package proxy

// Build 429 — a session returns AFTER its relay leg is torn down (relayjoin.go).
// The stands run the session functions THEMSELVES — runDTLSSession,
// runWrapASession, runDirectSession, the three that start runTURN in a goroutine
// of its own — with a credential taken from the pool, over the real stack: a pion
// TURN server on loopback UDP that holds ONE allocation per credential, behind
// the tap that holds every deallocate 150 ms, and a real pion DTLS server as the
// peer. What the session did with its relay leg is then stated by the relay (the
// re-dial at once: accepted, or refused with 486) and by the pool (was the lease
// still out while the deallocate was on its way?).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// dtlsPeer is the far end of the DTLS family's session: a real pion DTLS server
// on loopback UDP that completes the handshake and reads whatever comes.
func dtlsPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func(c net.Conn) {
				if dc, ok := c.(*dtls.Conn); ok {
					hs, done := context.WithTimeout(ctx, 5*time.Second)
					err := dc.HandshakeContext(hs)
					done()
					if err != nil {
						return
					}
				}
				buf := make([]byte, 2048)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.UDPAddr)
}

// silentPeer is a peer that takes every datagram and answers none: a handshake
// toward it never completes.
func silentPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr)
}

// relayJoinStand is one session function under test, its credential in the
// pool's slot 0 and the relay leg over UDP through the tap.
type relayJoinStand struct {
	p    *Proxy
	tap  *deallocTap
	user string

	leasesAtPass []int32 // the pool's leases still out, each time the tap hands a deallocate on
	mu           sync.Mutex
}

func newRelayJoinStand(t *testing.T, cfg Config, peer *net.UDPAddr) (*relayJoinStand, func() int) {
	t.Helper()
	user := fmt.Sprintf("%d:stand", time.Now().Add(8*time.Hour).Unix()) // the pool's shape: an expiry in front
	relay, srv := udpQuotaTURNFor(t, 1, func(u string) bool { return u == user })
	s := &relayJoinStand{tap: newDeallocTap(t, relay, 150*time.Millisecond), user: user}
	cfg.UseUDP = true
	cfg.NumConns = 1
	cfg.PeerAddr = peer.String()
	cfg.SeededTURN = &TURNCreds{Username: user, Password: "pw", Address: s.tap.addr(), Addresses: []string{s.tap.addr()}}
	s.p = NewProxy(cfg)
	s.p.peer = peer // Start would resolve it; the stand runs one session function, not the proxy
	t.Cleanup(s.p.cancel)
	s.tap.onPass = func() {
		s.mu.Lock()
		s.leasesAtPass = append(s.leasesAtPass, int32(s.leases()))
		s.mu.Unlock()
	}
	return s, srv.AllocationCount
}

func (s *relayJoinStand) leases() int {
	s.p.credPool.mu.Lock()
	defer s.p.credPool.mu.Unlock()
	return s.p.credPool.liveLeasesLocked()
}

// verdict is read the moment the session function has returned — where
// runConnection re-dials.
func (s *relayJoinStand) verdict(t *testing.T, what string, returned time.Duration) {
	t.Helper()
	confirmed := s.p.dealloc.confirmed.Load()  // at the return, before anything else
	ok, err := allocateNowAs(t, s.tap, s.user) // the re-dial, at once
	if confirmed != 1 {
		t.Errorf("%s returned %s after its end with %d deallocate(s) confirmed by the relay, want 1: the session does not wait for its relay leg's teardown", what, returned.Round(10*time.Microsecond), confirmed)
	}
	if !ok {
		t.Errorf("%s: the re-dial right behind the session's return was REFUSED (%v) — the restart outran the session's own deallocate (deallocates seen by the tap %d, handed on %d)", what, err, s.tap.seen.Load(), s.tap.passed.Load())
	}
	// Our two deallocates — the challenge's and the authenticated one — reach the
	// relay 150 ms after they were written: was the credential still held then?
	var at []int32
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		s.mu.Lock()
		at = append([]int32(nil), s.leasesAtPass...)
		s.mu.Unlock()
		if len(at) >= 2 || time.Now().After(deadline) {
			break
		}
	}
	if len(at) < 2 {
		t.Errorf("%s: fixture: the tap handed %d deallocate(s) on, want the challenge's and the authenticated one", what, len(at))
	}
	for i, n := range at {
		if i < 2 && n != 1 { // ours: the challenge's and the authenticated one; pion's own follows the release
			t.Errorf("%s: %d lease(s) out while deallocate %d was on its way to the relay, want 1: the credential was given back before the relay had answered", what, n, i+1)
		}
	}
	if n := s.leases(); n != 0 {
		t.Errorf("%s: %d lease(s) still out after the session has returned, want 0", what, n)
	}
}

func TestASessionReturnsOnlyAfterItsRelayLegIsTornDown(t *testing.T) {
	t.Run("runDTLSSession — an established session is ended (a kill, a restart by request)", func(t *testing.T) {
		s, allocations := newRelayJoinStand(t, Config{UseDTLS: true}, dtlsPeer(t))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready, signaled := make(chan struct{}, 1), false
		done := make(chan error, 1)
		go func() { done <- s.p.runDTLSSession(ctx, "", ready, &signaled, 0) }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("fixture: the session ended before it was established: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("fixture: no DTLS session over the stand's relay")
		}
		if ok, _ := allocateNowAs(t, s.tap, s.user); ok || allocations() != 1 {
			t.Fatalf("fixture: a second Allocate was accepted while the session's allocation stands (allocations %d) — the quota of 1 is not enforced", allocations())
		}
		t0 := time.Now()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runDTLSSession did not return after the cancel")
		}
		s.verdict(t, "runDTLSSession", time.Since(t0))
	})
	t.Run("runDTLSSession — an early exit: the handshake never completes", func(t *testing.T) {
		s, allocations := newRelayJoinStand(t, Config{UseDTLS: true}, silentPeer(t))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signaled := false
		done := make(chan error, 1)
		go func() { done <- s.p.runDTLSSession(ctx, "", nil, &signaled, 0) }()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return allocations() == 1 })
		time.Sleep(50 * time.Millisecond) // into the handshake toward a peer that never answers
		t0 := time.Now()
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("fixture: a DTLS session came up against a silent peer")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("runDTLSSession did not return after the cancel")
		}
		s.verdict(t, "runDTLSSession (early exit)", time.Since(t0))
	})
	t.Run("runWrapASession — an early exit: the handshake never completes", func(t *testing.T) {
		s, allocations := newRelayJoinStand(t, Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand"}, silentPeer(t))
		if !s.p.config.UseWrapA {
			t.Fatal("fixture: NewProxy switched WRAP-A off")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signaled := false
		done := make(chan error, 1)
		go func() { done <- s.p.runWrapASession(ctx, "", nil, &signaled, 0) }()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return allocations() == 1 })
		time.Sleep(50 * time.Millisecond)
		t0 := time.Now()
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("fixture: a WRAP-A session came up against a silent peer")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("runWrapASession did not return after the cancel")
		}
		s.verdict(t, "runWrapASession (early exit)", time.Since(t0))
	})
	t.Run("runWrapASession — an early return that nobody cancelled: the WRAP-A layer cannot be built", func(t *testing.T) {
		s, _ := newRelayJoinStand(t, Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand"}, silentPeer(t))
		s.p.wrapAKey = s.p.wrapAKey[:1] // the session returns right behind the relay leg's start, its context alive
		signaled := false
		t0 := time.Now()
		if err := s.p.runWrapASession(context.Background(), "", nil, &signaled, 0); err == nil {
			t.Fatal("fixture: the WRAP-A session did not fail at its init")
		}
		s.verdict(t, "runWrapASession (init failure)", time.Since(t0))
		if n := s.p.dealloc.legsLeft.Load(); n != 0 {
			t.Errorf("the session returned WITHOUT its relay leg (%d): nobody ended the leg of a session that returned by itself", n)
		}
	})
	t.Run("runDirectSession — the session IS the relay leg", func(t *testing.T) {
		s, allocations := newRelayJoinStand(t, Config{}, silentPeer(t))
		if !s.p.directMode() {
			t.Fatal("fixture: not the direct transport")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signaled := false
		done := make(chan error, 1)
		go func() { done <- s.p.runDirectSession(ctx, "", nil, &signaled, 0) }()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return allocations() == 1 })
		t0 := time.Now()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runDirectSession did not return after the cancel")
		}
		s.verdict(t, "runDirectSession", time.Since(t0))
	})
}

// The wait is BOUNDED: a relay leg that outlasts relayJoinBudget is left behind —
// said and counted — and ends by itself. The control first: a teardown that takes
// its whole confirm budget (no deallocate gets through) is inside the join's
// budget and IS waited for, with the budgets as shipped.
func TestASessionsWaitForItsRelayLegIsBounded(t *testing.T) {
	run := func(t *testing.T) (s *relayJoinStand, returned time.Duration) {
		t.Helper()
		s, allocations := newRelayJoinStand(t, Config{}, silentPeer(t))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signaled := false
		done := make(chan error, 1)
		go func() { done <- s.p.runDirectSession(ctx, "", nil, &signaled, 0) }()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return allocations() == 1 })
		s.tap.mute.Store(true) // the relay never hears the deallocate: the leg's teardown takes its whole confirm budget
		t0 := time.Now()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runDirectSession did not return: the wait for its relay leg is not bounded")
		}
		return s, time.Since(t0)
	}
	t.Run("the control: a teardown that takes its whole confirm budget is waited for", func(t *testing.T) {
		s, returned := run(t)
		if u, left := s.p.dealloc.unconfirmed.Load(), s.p.dealloc.legsLeft.Load(); u != 1 || left != 0 {
			t.Errorf("at the session's return: %d deallocate(s) reported NOT confirmed, %d relay leg(s) left behind, want 1 and 0 — relayJoinBudget (%s) must cover a teardown that spends its whole confirm budget (%s)", u, left, relayJoinBudget, deallocConfirmBudget)
		}
		if returned < deallocConfirmBudget {
			t.Errorf("the session returned after %s, before the %s its relay leg's teardown takes", returned, deallocConfirmBudget)
		}
	})
	t.Run("a relay leg that outlasts the budget is left behind, said and counted", func(t *testing.T) {
		j, d := relayJoinBudget, deallocConfirmBudget
		relayJoinBudget, deallocConfirmBudget = 120*time.Millisecond, 700*time.Millisecond
		t.Cleanup(func() { relayJoinBudget, deallocConfirmBudget = j, d })
		s, returned := run(t)
		if returned < 120*time.Millisecond || returned > 500*time.Millisecond {
			t.Errorf("the session returned after %s, want the 120ms budget and not the 700ms its relay leg's teardown takes", returned)
		}
		if n := s.p.dealloc.legsLeft.Load(); n != 1 {
			t.Errorf("%d relay leg(s) counted as left behind, want 1", n)
		}
		if u := s.p.dealloc.unconfirmed.Load(); u != 0 {
			t.Errorf("fixture: the leg's teardown had ended (%d reported) when the session returned", u)
		}
		waitUntil(t, "the relay leg to end by itself", 3*time.Second, func() bool { return s.p.dealloc.unconfirmed.Load() == 1 })
	})
}

// relayLeg's own rules.
func TestARelayLegJoinsWhatWasStartedAndStartsNothingBehindAJoin(t *testing.T) {
	joinIn := func(l *relayLeg, budget time.Duration) <-chan bool {
		ch := make(chan bool, 1)
		go func() { ch <- l.join(budget) }()
		return ch
	}
	t.Run("nothing running: at once", func(t *testing.T) {
		var l relayLeg
		t0 := time.Now()
		if !l.join(time.Second) || time.Since(t0) > 200*time.Millisecond {
			t.Errorf("join of an idle leg: not at once (%s)", time.Since(t0))
		}
		if l.start() {
			t.Error("a run was started behind the join")
		}
	})
	t.Run("a run is waited for until it has ENDED", func(t *testing.T) {
		var l relayLeg
		if !l.start() {
			t.Fatal("start refused before any join")
		}
		joined := joinIn(&l, 5*time.Second)
		select {
		case <-joined:
			t.Fatal("join returned while the run was still running")
		case <-time.After(60 * time.Millisecond):
		}
		if l.start() {
			t.Error("a run was started while the session was joining")
		}
		l.done()
		select {
		case ok := <-joined:
			if !ok {
				t.Error("join reported a run left behind although it had ended")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("join did not return after the run had ended")
		}
	})
	t.Run("the budget: a run that does not end is left behind", func(t *testing.T) {
		var l relayLeg
		l.start()
		t0 := time.Now()
		select {
		case ok := <-joinIn(&l, 60*time.Millisecond):
			if ok {
				t.Error("join reported the leg ended while its run was still running")
			}
		case <-time.After(2 * time.Second): // the guard: a join without a budget would hold the stand for ever
			l.done()
			t.Fatal("join did not give up when its budget ran out")
		}
		if took := time.Since(t0); took < 60*time.Millisecond || took > time.Second {
			t.Errorf("join gave up after %s, want the 60ms budget", took)
		}
		l.done() // the run ends by itself, later — and must find nothing to trip over
		if !l.join(time.Second) {
			t.Error("a second join after the run's end did not see it ended")
		}
	})
	t.Run("one run after another — the direct session's reconnect — and the join waits for the one running", func(t *testing.T) {
		var l relayLeg
		l.start()
		l.done()
		if !l.start() {
			t.Fatal("the next run was refused although no join had begun")
		}
		joined := joinIn(&l, 5*time.Second)
		select {
		case <-joined:
			t.Fatal("join returned while the second run was still running")
		case <-time.After(60 * time.Millisecond):
		}
		l.done()
		if !<-joined {
			t.Error("join reported a run left behind although both had ended")
		}
	})
	t.Run("starts and ends from many goroutines against one join", func(t *testing.T) {
		var l relayLeg
		var wg sync.WaitGroup
		var tripped atomic.Value
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { // a run that ends twice over one join closes a closed channel
					if r := recover(); r != nil {
						tripped.Store(fmt.Sprint(r))
					}
				}()
				for j := 0; j < 200; j++ {
					if !l.start() {
						return
					}
					l.done()
				}
			}()
		}
		ok := l.join(5 * time.Second)
		wg.Wait()
		if r := tripped.Load(); r != nil {
			t.Errorf("a run's end panicked: %v", r)
		}
		if !ok {
			t.Error("join gave up although every run ended at once")
		}
		if l.start() {
			t.Error("a run was started behind the join")
		}
		l.mu.Lock()
		n := l.running
		l.mu.Unlock()
		if n != 0 {
			t.Errorf("%d run(s) still counted after all of them ended", n)
		}
	})
}

// Where it is wired. runTURN is started from ONE place, through the session's
// relay leg; and every session that starts it defers the join right behind the
// first start — after the credential's release was registered (so that the join
// runs before it) and before anything that can return.
func TestEverySessionJoinsItsRelayLegBeforeItGivesItsCredentialBack(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return stripComments(string(b))
	}
	src, join := read("proxy.go"), read("relayjoin.go")
	if n := strings.Count(src, "p.runTURN("); n != 0 {
		t.Errorf("proxy.go starts runTURN itself %d time(s), want 0: a relay leg started outside goRunTURN is joined by nobody", n)
	}
	if n := strings.Count(join, "p.runTURN("); n != 1 {
		t.Errorf("relayjoin.go calls runTURN %d time(s), want goRunTURN's one", n)
	}
	body := func(src, fn string) string {
		i := strings.Index(src, "func (p *Proxy) "+fn+"(")
		if i < 0 {
			t.Fatalf("%s not found", fn)
		}
		rest := src[i+1:]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	// goRunTURN: the leg has ended only when runTURN has returned AND the session was told.
	g := body(join, "goRunTURN")
	if at := regexp.MustCompile(`go func\(\) \{\s*defer leg\.done\(\)`).FindStringIndex(g); at == nil {
		t.Error("goRunTURN: the run's end is not reported by a defer at the top of its goroutine — a leg reported ended before runTURN's teardown is joined too early")
	}
	if !regexp.MustCompile(`if !leg\.start\(\) \{\s*return nil, false\s*\}`).MatchString(g) {
		t.Error("goRunTURN starts a run without asking the leg — a run could be started behind a join")
	}
	// joinRelayLeg: the cancel comes first — a session that returned by itself has cancelled nothing.
	j := body(join, "joinRelayLeg")
	if c, w := strings.Index(j, "cancel()"), strings.Index(j, "leg.join("); c < 0 || w < 0 || c > w {
		t.Error("joinRelayLeg does not cancel the session's context BEFORE it waits — the relay leg of a session that returned by itself would run on")
	}
	sessions := 0
	for _, fn := range []string{"runDTLSSession", "runWrapASession", "runDirectSession", "runSRTPSession", "runConnection"} {
		b := body(src, fn)
		starts := strings.Count(b, "p.goRunTURN(")
		if starts == 0 {
			continue
		}
		sessions++
		first := strings.Index(b, "p.goRunTURN(")
		joinAt := strings.Index(b, "defer p.joinRelayLeg(&leg, connCancel, connIdx)")
		release := strings.Index(b, "p.credPool.release(currentSlot, currentCreds)")
		switch {
		case strings.Count(b, "defer p.joinRelayLeg(") != 1 || joinAt < 0:
			t.Errorf("%s starts a relay leg and does not defer joinRelayLeg(&leg, connCancel, connIdx) exactly once", fn)
		case release < 0 || release > joinAt:
			t.Errorf("%s: the join is not registered BEHIND the credential's release — defers run last-in first-out, the credential would be given back before the relay leg is torn down", fn)
		case joinAt < first:
			t.Errorf("%s: the join is registered before the relay leg's first start", fn)
		case regexp.MustCompile(`\breturn\b`).MatchString(b[first:joinAt]):
			t.Errorf("%s: a return stands between the relay leg's start and its join — that way out leaves the leg behind", fn)
		}
		if strings.Count(b, "&leg") != starts+1 {
			t.Errorf("%s: %d use(s) of &leg for %d start(s) and one join — every start and the join go through the session's ONE leg", fn, strings.Count(b, "&leg"), starts)
		}
	}
	if sessions != 3 {
		t.Errorf("%d session function(s) start a relay leg, want the three: the DTLS family, WRAP-A, direct", sessions)
	}
}
