package proxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A phone, 2026-11-20: the user's own relay was restarted under a live WRAP-A
// tunnel. Eleven of the thirty sessions sent a datagram in the second nobody
// listened at the relay's address; the host refused it, the refusal came back
// to the session's connected socket — and pion's client ENDED its read loop
// there ("Failed to read: … connection refused. Exiting loop"). A pion client
// never reads again behind that: the relay's 400 to the next permission
// refresh, which ended the other nineteen sessions at once, went unheard, and
// the eleven stood deaf for eight minutes, to the stop — nothing in WRAP-A
// ends a connection that hears nothing while the tunnel as a whole does.
//
// The reader's end is said by pion in one Debug line, which the session's
// logger hears: a session whose reader has ended is ended at once.

// relayFront stands between a session and the stand's relay, so that the
// relay's ADDRESS can stop listening for a moment — as while a relay process
// is restarted — without the relay losing anything. One client a stand.
type relayFront struct {
	t     *testing.T
	addr  string
	up    *net.UDPConn
	mu    sync.Mutex
	front net.PacketConn
	down  bool
	from  net.Addr
}

func newRelayFront(t *testing.T, relay string) *relayFront {
	t.Helper()
	front, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ra, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	f := &relayFront{t: t, addr: front.LocalAddr().String(), up: up, front: front}
	t.Cleanup(func() {
		f.mu.Lock()
		_ = f.front.Close()
		f.mu.Unlock()
		_ = up.Close()
	})
	go f.pump(front)
	go func() { // relay → client
		buf := make([]byte, 2048)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			f.mu.Lock()
			front, from := f.front, f.from
			f.mu.Unlock()
			if from != nil {
				_, _ = front.WriteTo(buf[:n], from)
			}
		}
	}()
	return f
}

// pump: client → relay, for as long as this front socket lives.
func (f *relayFront) pump(front net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := front.ReadFrom(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.from = from
		f.mu.Unlock()
		_, _ = f.up.Write(buf[:n])
	}
}

// stop: nobody listens at the address — a datagram sent to it is refused.
func (f *relayFront) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.front.Close()
	f.down = true
}

// start: the address listens again.
func (f *relayFront) start() {
	f.t.Helper()
	var front net.PacketConn
	var err error
	for i := 0; i < 100; i++ {
		if front, err = net.ListenPacket("udp4", f.addr); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		f.t.Fatalf("fixture: the front's address did not come back: %v", err)
	}
	f.mu.Lock()
	f.front, f.down = front, false
	f.mu.Unlock()
	go f.pump(front)
}

const readerEndedLine = "the relay socket's reader has ENDED"

// Through the session functions, every kind that has a relay leg: the relay's
// address refuses one datagram of an established session; the session ends at
// once and says why.
func TestASessionWhoseRelayReaderEndedIsEndedAtOnce(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  Config
		tcp  bool // the relay leg over TCP: the relay resets the connection
		peer func(t *testing.T, p *Proxy) *net.UDPAddr
		run  func(p *Proxy, ctx context.Context, ready chan struct{}) error
		up   string // the line that says the session is established
	}{
		{"direct", Config{}, false, func(t *testing.T, _ *Proxy) *net.UDPAddr { return newUDPPeer(t).addr },
			func(p *Proxy, ctx context.Context, ready chan struct{}) error {
				s := false
				return p.runDirectSession(ctx, "", ready, &s, 0)
			}, "TURN relay allocated"},
		{"WRAP-A", Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand"}, false,
			func(t *testing.T, p *Proxy) *net.UDPAddr { return wrapAPeer(t, p.wrapAKey, wrapAConfig()) },
			func(p *Proxy, ctx context.Context, ready chan struct{}) error {
				s := false
				return p.runWrapASession(ctx, "", ready, &s, 0)
			}, "WRAP-A+TURN session established"},
		{"DTLS", Config{UseDTLS: true}, false, func(t *testing.T, _ *Proxy) *net.UDPAddr { return dtlsPeer(t) },
			func(p *Proxy, ctx context.Context, ready chan struct{}) error {
				s := false
				return p.runDTLSSession(ctx, "", ready, &s, 0)
			}, ""},
		// The SRTP session's UDP socket is UNCONNECTED — a refusal never comes
		// back to it. Its reader ends over TCP, the production leg, when the
		// relay resets the connection.
		{"SRTP over TCP", Config{UseSrtp: true}, true, func(t *testing.T, _ *Proxy) *net.UDPAddr { return srtpPeer(t) },
			func(p *Proxy, ctx context.Context, ready chan struct{}) error {
				s := false
				return p.runSRTPSession(ctx, "", ready, &s, 0)
			}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var front *relayFront
			var relay *laggingRelay
			addr := ""
			if c.tcp {
				relay = newLaggingRelay(t, 1, 0, func(string) bool { return true }, false)
				addr = relay.addr
			} else {
				front = newRelayFront(t, permissionRelay(t, true))
				addr = front.addr
			}
			cfg := c.cfg
			cfg.UseUDP, cfg.NumConns, cfg.PeerAddr = !c.tcp, 1, "127.0.0.1:9"
			cfg.SeededTURN = &TURNCreds{Username: futureUser("reader"), Password: "pw", Address: addr, Addresses: []string{addr}}
			p := NewProxy(cfg)
			p.peer = c.peer(t, p)
			t.Cleanup(p.cancel)
			logged := captureLog(t)
			ready := make(chan struct{}, 1)
			done, stop := startSession(t, func(ctx context.Context) error { return c.run(p, ctx, ready) })
			if c.up != "" {
				waitUntil(t, "the session is established", 15*time.Second, func() bool { return strings.Contains(logged(), c.up) })
			} else {
				select {
				case <-ready:
				case <-done:
					t.Fatalf("fixture: the session ended before it was established: %v", stop())
				case <-time.After(15 * time.Second):
					t.Fatal("fixture: the session was not established")
				}
			}
			if c.tcp {
				if n := relay.drop(1, true); n != 1 {
					t.Fatalf("fixture: the relay reset %d connection(s), want 1", n)
				}
				waitUntil(t, "pion's reader ends on the reset", 5*time.Second, func() bool { return strings.Contains(logged(), "Exiting loop") })
			} else {
				// Nobody listens at the relay's address; the session's next datagram
				// is refused, and the listener is back a moment later.
				front.stop()
				waitUntil(t, "pion's reader ends on the refused datagram", 5*time.Second, func() bool {
					_ = p.SendPacket([]byte("into the gap"))
					return strings.Contains(logged(), "Exiting loop")
				})
				front.start()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("pion's reader ended and the session stands — deaf to everything the relay says from now on, until some other rule finds it")
			}
			_ = stop()
			if n := strings.Count(logged(), readerEndedLine); n != 1 {
				t.Fatalf("the reader's end was said %d time(s), want once", n)
			}
		})
	}
}

// The rule itself, on the session's ear.
func TestTheSessionsEarHearsItsReaderEnd(t *testing.T) {
	ear := func() (*allocLife, *atomic.Int32) {
		var gave gaveBack
		kills := &atomic.Int32{}
		gave.watch(func() { kills.Add(1) }, 7, true)
		return gave.lifeOf(), kills
	}
	settle := func(l *allocLife) { l.wait(); l.newEar(); l.fresh() } // joins what was begun; the next client's ear, the next allocation's life
	const refused = "Failed to read: read udp 192.0.2.1:50000->192.0.2.2:3478: read: connection refused. Exiting loop"
	for _, c := range []struct {
		name  string
		line  string
		kills int32
	}{
		{"a refused datagram", refused, 1},
		{"any other read error", "Failed to read: read udp 192.0.2.1:50000->192.0.2.2:3478: read: network is down. Exiting loop", 1},
		{"an inbound message it could not handle", "Failed to handle inbound message: unexpected EOF. Exiting loop", 1},
		{"our own close of the socket", "Failed to read: read udp 192.0.2.1:50000->192.0.2.2:3478: use of closed network connection. Exiting loop", 0},
		{"a read that failed and went on", "Failed to read: something", 0},
		{"another line that ends so", "Refresh done. Exiting loop", 0},
		{"a lifetime", "Updated lifetime: 600 seconds", 0},
	} {
		l, kills := ear()
		logged := captureLog(t)
		l.heardDebug(c.line)
		settle(l)
		if kills.Load() != c.kills {
			t.Errorf("%s: the session was ended %d time(s), want %d", c.name, kills.Load(), c.kills)
		}
		if n := int32(strings.Count(logged(), "proxy: [conn 7] "+readerEndedLine)); n != c.kills {
			t.Errorf("%s: the end was said %d time(s), want %d", c.name, n, c.kills)
		}
	}
	// Which read error it was is said by its kind.
	l, _ := ear()
	logged := captureLog(t)
	l.heardDebug(refused)
	settle(l)
	if !strings.Contains(logged(), "connection refused: nobody was listening at the relay's address") {
		t.Error("a refused datagram is not named as one")
	}
	l, _ = ear()
	logged = captureLog(t)
	l.heardDebug("Failed to handle inbound message: unexpected EOF. Exiting loop")
	settle(l)
	if !strings.Contains(logged(), readerEndedLine+" (an inbound message it could not handle)") {
		t.Error("an inbound message pion could not handle is not named as one")
	}
	// A session nobody armed (a set-up run by itself) has nothing to end: the
	// reader's end is said, and nothing traps.
	var bare gaveBack
	logged = captureLog(t)
	trapped := func() (trapped bool) {
		defer func() { trapped = recover() != nil }()
		bare.lifeOf().heardDebug(refused)
		return false
	}()
	if trapped || strings.Count(logged(), readerEndedLine) != 1 {
		t.Errorf("a reader's end on a session with nothing to end it: trapped %v, said %d time(s) — want said once", trapped, strings.Count(logged(), readerEndedLine))
	}
	// A session that is ending already is not ended again…
	l, kills := ear()
	l.wait()
	l.heardDebug(refused)
	if kills.Load() != 0 {
		t.Error("a reader's end heard behind the session's own teardown ended it again")
	}
	// …and the direct session's NEXT relay leg has an ear of its own.
	l, kills = ear()
	l.heardDebug(refused)
	settle(l)
	l.heardDebug(refused)
	settle(l)
	if kills.Load() != 2 {
		t.Errorf("two relay legs lost their readers and the session was ended %d time(s), want twice", kills.Load())
	}
	var none *allocLife
	none.heardDebug(refused) // no bookkeeping: nothing to end, nothing to trap on
}
