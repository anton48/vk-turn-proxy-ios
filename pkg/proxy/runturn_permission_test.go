package proxy

// A relay that takes the allocation and then answers NOTHING. The forwarder
// toward the relay sits in CreatePermission's transaction — pion asks for
// the permission on the first packet to the peer and waits for the answer —
// and until build 394 a cancel freed it only when pion's next retransmit
// WRITE failed the deadline the cancel had set: the rtx ladder 200 → 400 →
// 800 → 1600 ms, 1.1–2.1 s after the cancel (Sep 6 §63's "narrower window").
// The SRTP path had it wider: setupSRTPSession's explicit CreatePermission
// had no cancel wiring at all, so a cancel there waited out pion's whole
// ladder, 7.8 s. pion's Client.Close closes the transaction map and nothing
// else (the socket stays ours, the deallocate still goes out), and a closed
// transaction returns errTransactionClosed at once — so the cancel closes
// the client. The tap below goes silent exactly when the permission is
// asked. Sabotage seen red: client.Close dropped from runTURN's cancel
// AfterFunc (the return 1.1 s after the cancel); setupSRTPSession's
// AfterFunc dropped (the 3-s guard).

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

// permissionMutingTap forwards a TCP connection to the TURN server both ways
// until it sees a CreatePermission request go out (STUN type 0x0008 at the
// head of a client → server chunk); from then on everything the server
// answers is dropped — a relay that stays silent from the permission on.
type permissionMutingTap struct {
	ln       net.Listener
	to       string
	muted    atomic.Bool
	requests atomic.Int32 // CreatePermission requests seen
	mu       sync.Mutex
	conns    []net.Conn
}

func newPermissionMutingTap(t *testing.T, to string) *permissionMutingTap {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tap := &permissionMutingTap{ln: ln, to: to}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *permissionMutingTap) addr() string { return tap.ln.Addr().String() }

func (tap *permissionMutingTap) serve() {
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
		go func() { // client → server, always; a CreatePermission request mutes the relay
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if n >= 20 && buf[0] == 0x00 && buf[1] == 0x08 {
					tap.requests.Add(1)
					tap.muted.Store(true)
				}
				if n > 0 {
					if _, werr := up.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		go func() { // server → client, until muted
			buf := make([]byte, 64<<10)
			for {
				n, err := up.Read(buf)
				if n > 0 && !tap.muted.Load() {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func (tap *permissionMutingTap) close() {
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.conns {
		_ = c.Close()
	}
}

// runTURN: the first packet's permission is asked, the relay says nothing,
// the cancel lands while pion's ladder runs — runTURN returns at once.
func TestRunTURNReturnsWhenTheRelayGoesSilentAtCreatePermission(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t))
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0)
	}()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })

	_, _ = conn1.WriteTo(make([]byte, 100), peer) // the first packet: its permission is asked
	waitUntil(t, "the CreatePermission request to reach the relay", 5*time.Second, func() bool { return tap.requests.Load() >= 1 })
	time.Sleep(300 * time.Millisecond) // past pion's first retransmit: the ladder is running
	if sent := p.connTxBytes[0].Load(); sent != 0 {
		t.Fatalf("fixture: %d bytes went through — the forwarder is not waiting in CreatePermission", sent)
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
	case <-time.After(3 * time.Second):
		t.Fatal("runTURN did not return after the cancel: the forwarder waits out pion's retransmit ladder in CreatePermission's transaction")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget {
		t.Fatalf("runTURN took %s after the cancel, want under the %s budget — the transaction wait is not bounded by the cancel", took, relayCloseWriteBudget)
	}
}

// setupSRTPSession: its explicit CreatePermission right after the
// allocation, the relay silent from there — the cancel ends it at once.
func TestSetupSRTPSessionReturnsWhenTheRelayGoesSilentAtCreatePermission(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t))
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.setupSRTPSession(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, 0, 0)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	waitUntil(t, "the CreatePermission request to reach the relay", 5*time.Second, func() bool { return tap.requests.Load() >= 1 })
	time.Sleep(300 * time.Millisecond) // past pion's first retransmit: the ladder is running
	select {
	case err := <-done:
		t.Fatalf("setupSRTPSession returned before the cancel: %v", err)
	default:
	}

	t0 := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setupSRTPSession succeeded against a relay that never answered the permission")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setupSRTPSession did not return after the cancel: CreatePermission waits out pion's retransmit ladder")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget {
		t.Fatalf("setupSRTPSession took %s after the cancel, want under the %s budget", took, relayCloseWriteBudget)
	}
}
