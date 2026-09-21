package proxy

// Build 428 (N3) — the deallocate, confirmed, over a UDP relay leg (dealloc.go).
// The stands run the REAL stack: a pion TURN server on loopback UDP that holds
// ONE allocation per credential (the quota, in its smallest form), behind a tap
// that can delay, drop or mute the deallocates. "Did the restart outrun its own
// deallocate" is then a fact the relay states: the Allocate that follows a
// teardown at once is accepted — or refused with 486.

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// udpQuotaTURN is a pion TURN server on loopback UDP that knows one long-term
// credential (u / pw in realm okcdn.ru) and refuses an Allocate with 486 while
// it holds `quota` allocations.
func udpQuotaTURN(t *testing.T, quota int) (string, *turn.Server) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	var srvRef atomic.Pointer[turn.Server]
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == "u" {
				return "u", key, true
			}
			return "", nil, false
		},
		QuotaHandler: func(string, string, net.Addr) bool {
			s := srvRef.Load()
			return s == nil || s.AllocationCount() < quota
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srvRef.Store(srv)
	t.Cleanup(func() { // as loopbackTURN: the server goes only after its allocations have
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
	})
	return pc.LocalAddr().String(), srv
}

// deallocTap forwards datagrams between the clients and the relay — every
// client socket gets an upstream socket of its own, so the relay sees distinct
// 5-tuples — and handles the DEALLOCATES (a Refresh request with LIFETIME 0) as
// told: delayed, the first few dropped, or all of them muted.
type deallocTap struct {
	t        *testing.T
	ln       *net.UDPConn
	relay    *net.UDPAddr
	delay    time.Duration
	dropNext atomic.Int32
	mute     atomic.Bool
	seen     atomic.Int32 // deallocates that reached the tap
	passed   atomic.Int32 // … and were handed on to the relay

	mu  sync.Mutex
	ups map[string]*net.UDPConn
}

func newDeallocTap(t *testing.T, relay string, delay time.Duration) *deallocTap {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tap := &deallocTap{t: t, ln: ln, relay: ra, delay: delay, ups: map[string]*net.UDPConn{}}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *deallocTap) addr() string { return tap.ln.LocalAddr().String() }

func isDeallocate(b []byte) bool {
	if !stun.IsMessage(b) {
		return false
	}
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() != nil || m.Type.Method != stun.MethodRefresh || m.Type.Class != stun.ClassRequest {
		return false
	}
	v, err := m.Get(stun.AttrLifetime)
	return err == nil && len(v) == 4 && v[0]|v[1]|v[2]|v[3] == 0
}

func (tap *deallocTap) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := tap.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		tap.mu.Lock()
		up := tap.ups[from.String()]
		if up == nil {
			if up, err = net.DialUDP("udp4", nil, tap.relay); err != nil {
				tap.mu.Unlock()
				return
			}
			tap.ups[from.String()] = up
			go func(up *net.UDPConn, to *net.UDPAddr) { // the relay's answers, back to that client
				b := make([]byte, 2048)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					_, _ = tap.ln.WriteToUDP(b[:n], to)
				}
			}(up, from)
		}
		tap.mu.Unlock()
		if !isDeallocate(pkt) {
			_, _ = up.Write(pkt)
			continue
		}
		tap.seen.Add(1)
		switch {
		case tap.mute.Load():
		case tap.dropNext.Load() > 0:
			tap.dropNext.Add(-1)
		case tap.delay > 0:
			go func() { time.Sleep(tap.delay); tap.passed.Add(1); _, _ = up.Write(pkt) }()
		default:
			tap.passed.Add(1)
			_, _ = up.Write(pkt)
		}
	}
}

func (tap *deallocTap) close() {
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.ups {
		_ = c.Close()
	}
}

// allocateNow is the re-dial: a fresh socket, a fresh client, one Allocate
// through the tap — what runConnection does the moment a session has returned.
// It reports whether the relay ACCEPTED it, and gives the allocation back.
func allocateNow(t *testing.T, tap *deallocTap) (accepted bool, err error) {
	t.Helper()
	ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	tc, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: tap.addr(), Conn: ctl, Username: "u", Password: "pw", Realm: "okcdn.ru"})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if err := tc.Listen(); err != nil {
		t.Fatal(err)
	}
	relayConn, err := tc.Allocate()
	if err != nil {
		return false, err
	}
	// Give it back, confirmed — so that the stand's server is empty again for whatever follows.
	_, _, _ = boundedDeallocate(func(req *stun.Message) (*stun.Message, error) {
		res, err := tc.PerformTransaction(req, tc.TURNServerAddr(), false)
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}, tc.Close, "u", "pw", 2*time.Second)
	_ = relayConn.Close()
	return true, nil
}

func udpProxy() *Proxy {
	return &Proxy{config: Config{UseUDP: true}, peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
		connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
}

// THE DEFECT, as the field showed it (2026-09-20, 423 over UDP: 22 of 22): a
// session ends, its connection re-dials at once, and on an identity at its
// quota the new Allocate reaches the relay before the old allocation's
// deallocate has taken effect — refused with 486, the slot benched over our own
// ghost. Here the deallocate is 150 ms on its way; the session function must not
// return — and its restart not begin — before the relay has answered it.
func TestARestartDoesNotOutrunItsOwnDeallocate(t *testing.T) {
	t.Run("runTURN — the DTLS family's allocation", func(t *testing.T) {
		relay, srv := udpQuotaTURN(t, 1)
		tap := newDeallocTap(t, relay, 150*time.Millisecond)
		p := udpProxy()
		conn1, conn2 := connutil.AsyncPacketPipe()
		defer conn1.Close()
		defer conn2.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0) }()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
		if ok, err := allocateNow(t, tap); ok || err == nil {
			t.Fatalf("fixture: a second Allocate was accepted while the first allocation stands — the quota of 1 is not enforced")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runTURN did not return after the cancel")
		}
		if ok, err := allocateNow(t, tap); !ok { // the restart, at once
			t.Fatalf("the re-dial right behind the session's end was REFUSED (%v): the session returned before the relay had answered its deallocate (deallocates seen by the tap %d, handed on %d)", err, tap.seen.Load(), tap.passed.Load())
		}
	})
	t.Run("setupSRTPSession — the abort of a setup whose handshake never completes", func(t *testing.T) {
		relay, srv := udpQuotaTURN(t, 1)
		tap := newDeallocTap(t, relay, 150*time.Millisecond)
		p := udpProxy()
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
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
		time.Sleep(50 * time.Millisecond) // into the handshake toward a peer that never answers
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("setupSRTPSession succeeded against a silent peer")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("setupSRTPSession did not return after the cancel")
		}
		if ok, err := allocateNow(t, tap); !ok {
			t.Fatalf("the re-dial right behind the aborted setup was REFUSED (%v): abortSetup returned before the relay had answered its deallocate", err)
		}
	})
	t.Run("srtpSessionConn.Close — the live SRTP session's teardown", func(t *testing.T) {
		relay, srv := udpQuotaTURN(t, 1)
		tap := newDeallocTap(t, relay, 150*time.Millisecond)
		p := udpProxy()
		ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		tc, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: tap.addr(), Conn: ctl, Username: "u", Password: "pw", Realm: "okcdn.ru"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tc.Listen(); err != nil {
			t.Fatal(err)
		}
		relayConn, err := tc.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
		above, _ := net.Pipe() // stands in for the SRTP wrapper above the relay conn
		creds := &TURNCreds{Username: "u", Password: "pw"}
		sess := &srtpSessionConn{Conn: above, relayConn: relayConn, tc: tc, ctlConn: ctl, release: func() { p.releaseAllocation(tc, creds, 0) }}
		_ = sess.Close()
		if ok, err := allocateNow(t, tap); !ok {
			t.Fatalf("the re-dial right behind Close was REFUSED (%v): Close returned before the relay had answered the deallocate", err)
		}
		if n := p.dealloc.confirmed.Load(); n != 1 {
			t.Errorf("confirmed deallocates counted: %d, want 1", n)
		}
	})
}

// A deallocate that is LOST is sent again — the transaction layer's
// retransmission, which the fire-and-forget form never lived to see: the client
// and the socket were closed right behind the one datagram, and the allocation
// held its seat until it expired.
func TestALostDeallocateIsSentAgain(t *testing.T) {
	relay, srv := udpQuotaTURN(t, 1)
	tap := newDeallocTap(t, relay, 0)
	p := udpProxy()
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0) }()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
	tap.dropNext.Store(1) // the first deallocate datagram never reaches the relay
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runTURN did not return after the cancel")
	}
	if ok, err := allocateNow(t, tap); !ok {
		t.Fatalf("the re-dial was REFUSED (%v): the lost deallocate was never repeated — the allocation holds its seat until it expires (deallocates seen by the tap: %d)", err, tap.seen.Load())
	}
	if n := tap.seen.Load(); n < 2 {
		t.Errorf("the tap saw %d deallocate datagram(s), want the lost one AND its repeat", n)
	}
}

// A relay that never answers — a dead path — must not hold a teardown: after the
// budget it goes on as it always did, and SAYS what it leaves behind. The
// control: that allocation really does still hold its seat.
func TestAnUnansweredDeallocateIsBoundedAndCounted(t *testing.T) {
	b := deallocConfirmBudget
	deallocConfirmBudget = 120 * time.Millisecond
	t.Cleanup(func() { deallocConfirmBudget = b })
	relay, srv := udpQuotaTURN(t, 1)
	tap := newDeallocTap(t, relay, 0)
	p := udpProxy()
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0) }()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
	tap.mute.Store(true) // no deallocate gets through from here on
	t0 := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runTURN did not return: an unanswered deallocate holds the teardown")
	}
	if took := time.Since(t0); took > time.Second {
		t.Errorf("the teardown took %s over a relay that never answers, want it bounded by the %s budget", took, deallocConfirmBudget)
	}
	if c, u := p.dealloc.confirmed.Load(), p.dealloc.unconfirmed.Load(); c != 0 || u != 1 {
		t.Errorf("counted %d confirmed and %d not confirmed, want 0 and 1", c, u)
	}
	if ok, _ := allocateNow(t, tap); ok {
		t.Error("fixture: the re-dial was accepted although no deallocate reached the relay")
	}
	tap.mute.Store(false) // let the stand's cleanup release what is left (pion's allocation lives 10 min otherwise)
	srvFree(t, srv, tap)
}

// srvFree empties the stand's server of an allocation its owner could not give back.
func srvFree(t *testing.T, srv *turn.Server, tap *deallocTap) {
	t.Helper()
	_ = tap
	deadline := time.Now().Add(200 * time.Millisecond)
	for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// The rule itself, against a relay that answers as the book says.
func TestConfirmDeallocateReadsTheRelaysAnswer(t *testing.T) {
	answer := func(req *stun.Message, class stun.MessageClass, code stun.ErrorCode, withNonce bool) *stun.Message {
		setters := []stun.Setter{stun.NewTransactionIDSetter(req.TransactionID), stun.NewType(stun.MethodRefresh, class)}
		if class == stun.ClassErrorResponse {
			setters = append(setters, stun.ErrorCodeAttribute{Code: code})
			if withNonce {
				setters = append(setters, stun.NewRealm("okcdn.ru"), stun.NewNonce("n-"+time.Now().Format("150405.000000")))
			}
		}
		m, err := stun.Build(setters...)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	authed := func(req *stun.Message) bool {
		return req.Contains(stun.AttrMessageIntegrity) && req.Contains(stun.AttrNonce)
	}
	zeroLifetime := func(req *stun.Message) bool {
		v, err := req.Get(stun.AttrLifetime)
		return err == nil && len(v) == 4 && v[0]|v[1]|v[2]|v[3] == 0
	}
	for _, c := range []struct {
		what   string
		script []func(*stun.Message) (*stun.Message, error)
		want   deallocVerdict
		code   int
	}{
		{"the challenge, then the release", []func(*stun.Message) (*stun.Message, error){
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeUnauthorized, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassSuccessResponse, 0, false), nil
			},
		}, deallocConfirmed, 0},
		{"a stale nonce is owed one more try", []func(*stun.Message) (*stun.Message, error){
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeUnauthorized, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeStaleNonce, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassSuccessResponse, 0, false), nil
			},
		}, deallocConfirmed, 0},
		{"437: the relay holds no allocation for this socket", []func(*stun.Message) (*stun.Message, error){
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeUnauthorized, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeAllocMismatch, false), nil
			},
		}, deallocGone, 437},
		{"a challenge that carries no nonce cannot be answered", []func(*stun.Message) (*stun.Message, error){
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeUnauthorized, false), nil
			},
		}, deallocRefused, 401},
		{"nothing comes back", []func(*stun.Message) (*stun.Message, error){
			func(*stun.Message) (*stun.Message, error) { return nil, errors.New("all retransmissions failed") },
		}, deallocUnanswered, 0},
		{"stale upon stale: three requests and no more", []func(*stun.Message) (*stun.Message, error){
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeUnauthorized, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeStaleNonce, true), nil
			},
			func(r *stun.Message) (*stun.Message, error) {
				return answer(r, stun.ClassErrorResponse, stun.CodeStaleNonce, true), nil
			},
		}, deallocRefused, 438},
	} {
		step := 0
		v, code, _ := confirmDeallocate(func(req *stun.Message) (*stun.Message, error) {
			if !zeroLifetime(req) {
				t.Errorf("%s: request %d asks for a lifetime other than 0 — that is a refresh, not a deallocate", c.what, step+1)
			}
			if step > 0 && !authed(req) {
				t.Errorf("%s: request %d carries no credentials although the relay has challenged", c.what, step+1)
			}
			if step >= len(c.script) {
				t.Fatalf("%s: a request too many (%d)", c.what, step+1)
			}
			f := c.script[step]
			step++
			return f(req)
		}, "u", "pw")
		if v != c.want || code != c.code {
			t.Errorf("%s: verdict %d code %d, want %d and %d", c.what, v, code, c.want, c.code)
		}
		if step != len(c.script) {
			t.Errorf("%s: %d request(s) made, want %d", c.what, step, len(c.script))
		}
	}
}

// The budget: a round trip that never returns is ABORTED when it runs out, and
// the goroutine behind it is joined before the teardown goes on.
func TestTheDeallocatesBudgetAbortsAndJoins(t *testing.T) {
	released := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	var aborted, joined atomic.Bool
	type out struct {
		v   deallocVerdict
		err error
	}
	res := make(chan out, 1)
	t0 := time.Now()
	go func() {
		v, _, err := boundedDeallocate(func(*stun.Message) (*stun.Message, error) {
			<-released                        // pion's WaitForResult, until the transaction map is closed
			time.Sleep(30 * time.Millisecond) // … and the goroutine takes its time to unwind
			joined.Store(true)
			return nil, errors.New("transaction closed")
		}, func() { aborted.Store(true); release() }, "u", "pw", 60*time.Millisecond)
		res <- out{v, err}
	}()
	var o out
	select {
	case o = <-res:
	case <-time.After(2 * time.Second):
		release() // the guard: free the stand, and fail
		t.Fatal("boundedDeallocate did not return: the budget ran out and the pending round trip was not aborted")
	}
	wasJoined := joined.Load() // read at once: a teardown that went on without the join finds it false
	if o.v != deallocUnanswered || o.err == nil {
		t.Errorf("verdict %d err %v, want unanswered with the reason", o.v, o.err)
	}
	if !aborted.Load() {
		t.Error("the pending round trip was not aborted when the budget ran out")
	}
	if !wasJoined {
		t.Error("boundedDeallocate returned while its goroutine was still running — nothing may be left running behind a teardown")
	}
	if took := time.Since(t0); took < 60*time.Millisecond {
		t.Errorf("returned after %s, before the 60ms budget", took)
	}
}

// Where it is wired, and where it is not. Every teardown that gives an
// allocation back runs the confirmed deallocate BEFORE its relay conn is closed
// and AFTER a live write budget is on the socket — and only over UDP.
func TestEveryTeardownConfirmsItsDeallocateOverUDPOnly(t *testing.T) {
	b, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	src := stripComments(string(b))
	if n := strings.Count(src, "p.releaseAllocation("); n != 2 {
		t.Errorf("proxy.go calls p.releaseAllocation %d times, want 2: runTURN's defer and setupSRTPSession's closure", n)
	}
	for _, guarded := range []string{
		`if p\.config\.UseUDP \{\s*defer p\.releaseAllocation\(client, creds, connIdx\)\s*\}`,
		`if p\.config\.UseUDP \{\s*release = func\(\) \{ p\.releaseAllocation\(tc, creds, connIdx\) \}\s*\}`,
	} {
		if !regexp.MustCompile(guarded).MatchString(src) {
			t.Errorf("proxy.go lacks /%s/ — the confirmed deallocate is for a UDP relay leg only", guarded)
		}
	}
	order := func(where, body string, want ...string) {
		at := -1
		for _, w := range want {
			i := strings.Index(body, w)
			if i < 0 {
				t.Errorf("%s: %q not found", where, w)
				return
			}
			if i < at {
				t.Errorf("%s: %q comes too early — want the order %v", where, w, want)
				return
			}
			at = i
		}
	}
	// runTURN: defers run last-in first-out — the budget, then the confirmed deallocate, then relayConn.Close.
	if i := strings.Index(src, "func (p *Proxy) runTURN("); i < 0 {
		t.Fatal("runTURN not found")
	} else {
		order("runTURN's defers", src[i:], "defer relayConn.Close()", "defer p.releaseAllocation(client, creds, connIdx)", "turnConn.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))")
	}
	a := strings.Index(src, "abortSetup := func() {")
	if a < 0 {
		t.Fatal("abortSetup not found")
	}
	order("abortSetup", src[a:a+strings.Index(src[a:], "\n\t}\n")], "quiesce()", "SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))", "release()", "relayConn.Close()", "tc.Close()", "ctlConn.Close()")
	c := strings.Index(src, "func (s *srtpSessionConn) Close() error {")
	if c < 0 {
		t.Fatal("srtpSessionConn.Close not found")
	}
	order("srtpSessionConn.Close", src[c:c+strings.Index(src[c:], "\n}\n")], "s.ctlConn.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))", "s.Conn.Close()", "s.release()", "s.relayConn.Close()", "s.tc.Close()", "s.ctlConn.Close()")
	if !strings.Contains(src, "release:   release,") {
		t.Error("setupSRTPSession does not hand its release to the session it returns — the live session's Close would give the allocation back unconfirmed")
	}
}

// …and over TCP nothing of it runs: no request of ours beside pion's own deallocate.
func TestOverTCPTheTeardownSendsNoRequestOfItsOwn(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), false, false)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0) }()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runTURN did not return after the cancel")
	}
	waitUntil(t, "pion's deallocate", 2*time.Second, func() bool { return tap.refreshes.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := tap.refreshes.Load(); n != 1 {
		t.Errorf("%d Refresh requests reached the TCP relay at the teardown, want pion's one", n)
	}
	if c, u := p.dealloc.confirmed.Load(), p.dealloc.unconfirmed.Load(); c != 0 || u != 0 {
		t.Errorf("the confirmed deallocate ran over TCP (%d confirmed, %d not)", c, u)
	}
}
