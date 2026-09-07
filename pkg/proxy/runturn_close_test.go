package proxy

// runTURN's forwarder toward the relay writes through pion's client into the
// control socket with no deadline of its own. On a TCP relay that stopped
// taking bytes it sits in Write; runTURN sits in wg.Wait behind it; the
// deadline defer meant for the deallocate can never run, and the session
// above restarts without waiting — leaking the goroutine, the socket and the
// pion client until the kernel fails the write (user's review, 2026-09-07).
// The write is bounded at the cancel instead, in the AfterFunc that already
// frees the reads. Exercised on the REAL stack: a pion TURN server on
// loopback TCP behind a tap that stops reading, runTURN fed through the same
// AsyncPacketPipe the DTLS session uses.

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/turn/v5"
)

// loopbackTURN is a pion TURN server on loopback TCP that knows one
// long-term credential (u / pw in realm okcdn.ru).
func loopbackTURN(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == "u" {
				return "u", key, true
			}
			return "", nil, false
		},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener:              ln,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// stallingTap forwards a TCP connection to the TURN server; once `stall` is
// closed it stops READING from the client, so the client's send buffer fills
// and its next write blocks — a relay that stopped taking bytes.
type stallingTap struct {
	ln    net.Listener
	to    string
	stall chan struct{}
	mu    sync.Mutex
	conns []net.Conn
}

func newStallingTap(t *testing.T, to string) *stallingTap {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tap := &stallingTap{ln: ln, to: to, stall: make(chan struct{})}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *stallingTap) serve() {
	for {
		c, err := tap.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp4", tap.to)
		if err != nil {
			_ = c.Close()
			return
		}
		tap.mu.Lock()
		tap.conns = append(tap.conns, c, up)
		tap.mu.Unlock()
		go func() { _, _ = io.Copy(c, up) }() // server → client, always
		go func() {                           // client → server, until the stall
			buf := make([]byte, 64<<10)
			for {
				select {
				case <-tap.stall:
					return // stop reading: the client backs up into its own send buffer
				default:
				}
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := up.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
	}
}

func (tap *stallingTap) close() {
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.conns {
		_ = c.Close()
	}
}

func waitUntil(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// runTURN returns within the budget after a cancel even when its forwarder
// is stuck in a relay write. Sabotage seen red: the SetWriteDeadline dropped
// from the cancel AfterFunc (runTURN never returns — the test's guard
// fires and the tap has to close the socket to free it).
func TestRunTURNReturnsWhenTheRelayWriteIsStuck(t *testing.T) {
	tap := newStallingTap(t, loopbackTURN(t))
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- p.runTURN(ctx, tap.ln.Addr().String(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0)
	}()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })

	// A few packets BEFORE the stall: the first write waits for the relay's
	// answer to CreatePermission (the channel bind is asynchronous).
	pkt := make([]byte, 1200)
	for i := 0; i < 5; i++ {
		_, _ = conn1.WriteTo(pkt, peer)
	}
	waitUntil(t, "the first packets to reach the relay", 5*time.Second, func() bool { return p.connTxBytes[0].Load() >= 5*1200 })

	close(tap.stall)            // the relay stops taking bytes
	for i := 0; i < 6000; i++ { // ~7 MB; a stalled receiver's window stops the autotuning, ~0.55 MB is absorbed
		_, _ = conn1.WriteTo(pkt, peer)
	}
	waitUntil(t, "the forwarder to stop making progress", 5*time.Second, func() bool {
		a := p.connTxBytes[0].Load()
		time.Sleep(150 * time.Millisecond)
		return p.connTxBytes[0].Load() == a
	})
	if sent := p.connTxBytes[0].Load(); sent >= 6005*1200 {
		t.Fatalf("fixture: the whole flood (%d bytes) was absorbed — nothing is stuck in a write", sent)
	}
	select {
	case err := <-done:
		t.Fatalf("runTURN returned before the cancel: %v", err)
	default:
	}

	t0 := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(2*relayCloseWriteBudget + 2*time.Second):
		t.Fatal("runTURN did not return after the cancel: the forwarder sits in a relay write nothing bounds")
	}
	if took := time.Since(t0); took > 2*relayCloseWriteBudget+500*time.Millisecond {
		t.Fatalf("runTURN took %s after the cancel — more than the stuck write plus the deallocate under their budgets", took)
	}
}
