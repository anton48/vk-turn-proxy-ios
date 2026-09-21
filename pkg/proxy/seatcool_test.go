package proxy

// Build 430 — the relay's second (seatcool.go). The VK relay answers a deallocate
// at once and keeps the seat on the identity's quota for a second more (measured
// on a stand, 2026-09-21: refused 206 of 206 up to 990 ms behind the deallocate,
// accepted 52 of 52 from 1 000 ms). The end-to-end stands run the PRODUCTION
// session — runSRTPSession through runConnection, ten of them on one identity —
// against a relay whose quota lags its answers the same way, behind the tap that
// sees the deallocates pass.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy/srtpwrap"
	"github.com/pion/turn/v5"
)

// shortSecond shrinks the relay's second for a test.
func shortSecond(t *testing.T, cool, grace time.Duration) {
	t.Helper()
	c, g := seatCoolFor, seatLagGrace
	seatCoolFor, seatLagGrace = cool, grace
	t.Cleanup(func() { seatCoolFor, seatLagGrace = c, g })
}

func slotSaturated(cp *credPool, slot int) bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return time.Now().Before(cp.pool[slot].saturatedUntil)
}

// fullSlot0 is a lease pool whose slot 0 holds one credential with ten leases out.
func fullSlot0(t *testing.T, mints *atomic.Int32) (*credPool, *TURNCreds) {
	t.Helper()
	cp := leasePool(t, mints)
	creds := &TURNCreds{Username: fmt.Sprintf("%d:full", time.Now().Add(8*time.Hour).Unix()), Password: "p", Address: leaseTestRelay, Addresses: []string{leaseTestRelay}}
	cp.mu.Lock()
	cp.pool[0] = credPoolEntry{addr: leaseTestRelay, creds: creds, ts: time.Now().Add(-time.Hour), allocated: 10}
	seatHolders(cp, 0, connsPerSlot)
	cp.mu.Unlock()
	return cp, creds
}

// B, on the pool alone: a seat whose session gave its allocation back stays
// COUNTED for the relay's second — the connection that re-dials is seated
// elsewhere, not on the seat the relay still holds — and is let go by itself when
// the second is over. The control: a lease that gave nothing back is released at
// once, as it always was.
func TestASeatGivenBackStaysCountedForTheRelaysSecond(t *testing.T) {
	shortSecond(t, 150*time.Millisecond, 400*time.Millisecond)
	t.Run("counted while the relay holds it, let go after", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.releaseGivenBack(0, creds, time.Now())
		if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != connsPerSlot {
			t.Fatalf("right behind the give-back: active %d, leases out %d, want %d and %d — the seat the relay still holds is handed out again", active, live, connsPerSlot, connsPerSlot)
		}
		_, _, slot, err := cp.get(0, false) // the connection's own re-dial, at once
		if err != nil {
			t.Fatalf("the re-dial: %v", err)
		}
		if slot == 0 {
			t.Error("the re-dial was seated on slot 0 — on the seat its own session gave back a moment ago: the relay refuses that Allocate with 486")
		}
		waitUntil(t, "the seat to be let go", 2*time.Second, func() bool { a, _, _ := leaseCounts(cp, 0); return a == connsPerSlot-1 })
	})
	t.Run("a parked connection is woken when the second is over", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		cp := newCredPool(ctx, 12, 2*time.Minute, "", func(bool, int) (string, *TURNCreds, error) {
			return "", nil, errors.New("the stand mints nothing")
		})
		creds := &TURNCreds{Username: fmt.Sprintf("%d:only", time.Now().Add(8*time.Hour).Unix()), Password: "p", Address: leaseTestRelay, Addresses: []string{leaseTestRelay}}
		cp.mu.Lock()
		for len(cp.pool) < cp.size {
			cp.pool = append(cp.pool, credPoolEntry{})
		}
		cp.pool[0] = credPoolEntry{addr: leaseTestRelay, creds: creds, ts: time.Now().Add(-time.Hour), allocated: 10}
		seatHolders(cp, 0, connsPerSlot)
		cp.mu.Unlock()
		wake := cp.slotAvailableChannel()
		t0 := time.Now()
		cp.releaseGivenBack(0, creds, t0)
		if _, _, slot, err := cp.get(0, false); err == nil {
			t.Fatalf("the re-dial was seated (slot %d) although the only identity is full by the relay's count", slot)
		}
		select {
		case <-wake:
		case <-time.After(2 * time.Second):
			t.Fatal("nobody was woken when the seat was let go")
		}
		if took := time.Since(t0); took < 150*time.Millisecond {
			t.Errorf("woken %s after the give-back, inside the relay's second (150ms here)", took)
		}
		if _, _, slot, err := cp.get(0, false); err != nil || slot != 0 {
			t.Errorf("after the second: slot %d, %v — want the seat on slot 0", slot, err)
		}
	})
	t.Run("a give-back older than the second holds nothing", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.releaseGivenBack(0, creds, time.Now().Add(-time.Second))
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("active %d, want %d at once", active, connsPerSlot-1)
		}
	})
	t.Run("the control: a lease that gave nothing back is released at once", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		p := &Proxy{credPool: cp}
		var gave gaveBack // nothing noted: no allocation was made, or the relay holds none
		p.releaseLease(0, creds, &gave)
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("active %d, want %d: a seat nobody holds was cooled", active, connsPerSlot-1)
		}
		gave.note(time.Now())
		p.releaseLease(0, creds, &gave)
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("active %d, want %d: a lease whose allocation WAS given back must stay counted", active, connsPerSlot-1)
		}
		if _, again := gave.take(); again {
			t.Error("the note was not taken: the next lease of this session would be cooled by it")
		}
	})
}

// C, on the pool alone: a 486 right behind a seat this side gave back on that
// credential is the relay's second — nothing is benched, the breaker's freshness
// test does not see it, the total does, and whoever parks is woken. The controls:
// the same 486 with no give-back behind it, and one after the grace, bench the
// slot as they always did.
func TestA486BehindOurOwnGiveBackIsTheRelaysSecond(t *testing.T) {
	shortSecond(t, 150*time.Millisecond, 400*time.Millisecond)
	t.Run("the relay's second: not benched, counted, a wake", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.mu.Lock()
		cp.noteGiveBackLocked(0, creds, time.Now()) // the note alone — no seat cooling here, so that the wake below can only be this rule's own
		cp.mu.Unlock()
		wake := cp.slotAvailableChannel()
		if cd := cp.markSaturated(0, creds); cd != 0 {
			t.Errorf("cooldown %s, want 0: the slot was benched over the relay's own second", cd)
		}
		if slotSaturated(cp, 0) {
			t.Error("slot 0 is marked VK-saturated")
		}
		cp.mu.Lock()
		total, lag := cp.quota.refusals, cp.seat.lagRefusals
		cp.mu.Unlock()
		if total != 1 || lag != 1 {
			t.Errorf("refusals in the total %d, read as the relay's second %d, want 1 and 1", total, lag)
		}
		select {
		case <-wake:
		case <-time.After(2 * time.Second):
			t.Error("no wake when the second was over: whoever parked on the refusal sleeps out its retry delay")
		}
	})
	t.Run("the control: no give-back behind it — benched", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		if cd := cp.markSaturated(0, creds); cd != vkActiveAllocationsCooldown || !slotSaturated(cp, 0) {
			t.Errorf("cooldown %s, saturated %v — a 486 nothing of ours explains must bench the slot (%s)", cd, slotSaturated(cp, 0), vkActiveAllocationsCooldown)
		}
	})
	t.Run("the control: a give-back older than the grace — benched", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.releaseGivenBack(0, creds, time.Now().Add(-401*time.Millisecond))
		if cd := cp.markSaturated(0, creds); cd == 0 || !slotSaturated(cp, 0) {
			t.Errorf("cooldown %s, saturated %v — a give-back 401ms old (grace 400ms) explains no refusal", cd, slotSaturated(cp, 0))
		}
	})
	t.Run("another identity's give-back on the same slot number explains nothing", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		other := &TURNCreds{Username: fmt.Sprintf("%d:other", time.Now().Add(8*time.Hour).Unix()), Password: "p"}
		cp.mu.Lock()
		cp.noteGiveBackLocked(0, other, time.Now())
		cp.mu.Unlock()
		if cd := cp.markSaturated(0, creds); cd == 0 {
			t.Error("a give-back of ANOTHER identity was taken for this one's: the quota is per identity")
		}
	})
	t.Run("the same identity's give-back on another slot explains nothing", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.mu.Lock()
		cp.noteGiveBackLocked(1, creds, time.Now())
		cp.mu.Unlock()
		if cd := cp.markSaturated(0, creds); cd == 0 {
			t.Error("a give-back on ANOTHER slot was taken for this one's")
		}
	})
	t.Run("the latest give-back stands, old notes are dropped, and a note is aged by the wall clock", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		gone := &TURNCreds{Username: fmt.Sprintf("%d:gone", time.Now().Add(8*time.Hour).Unix()), Password: "p"}
		now := time.Now()
		cp.mu.Lock()
		cp.noteGiveBackLocked(3, gone, now.Add(-2*time.Minute))
		cp.noteGiveBackLocked(0, creds, now)
		cp.noteGiveBackLocked(0, creds, now.Add(-300*time.Millisecond)) // an older one, heard of later — a leg left behind
		_, kept := cp.gaveBackAt[leaseKeyOf(3, gone)]
		at := cp.gaveBackAt[leaseKeyOf(0, creds)]
		cp.mu.Unlock()
		if kept {
			t.Error("a note two minutes old is still kept: one entry per credential ever given back, for ever")
		}
		if !at.Equal(now) {
			t.Errorf("the note reads %s behind the latest give-back, want that one", now.Sub(at))
		}
		cp.mu.Lock()
		delete(cp.gaveBackAt, leaseKeyOf(0, creds))
		cp.mu.Unlock()
		cp.releaseGivenBack(0, creds, time.Now()) // a time WITH a monotonic reading, as csqtt's lease hands in
		cp.mu.Lock()
		at, noted := cp.gaveBackAt[leaseKeyOf(0, creds)]
		cp.mu.Unlock()
		if !noted {
			t.Fatal("releaseGivenBack noted no give-back: a 486 behind it explains nothing to the pool")
		}
		if at != at.Round(0) {
			t.Error("the note carries a monotonic reading: a freeze of the process would stop the relay's second, which runs in real time")
		}
	})
	t.Run("the breaker's freshness test does not see it", func(t *testing.T) {
		var mints atomic.Int32
		cp := leasePool(t, &mints)
		fresh := &TURNCreds{Username: fmt.Sprintf("%d:fresh", time.Now().Add(8*time.Hour).Unix()), Password: "p", Address: leaseTestRelay}
		cp.mu.Lock()
		cp.pool[0] = credPoolEntry{addr: leaseTestRelay, creds: fresh, ts: time.Now()} // a fresh credential, nothing ever accepted on it
		seatHolders(cp, 0, 2)
		cp.mu.Unlock()
		for i := 0; i < quotaRefusalTrip+1; i++ {
			cp.releaseGivenBack(0, fresh, time.Now())
			cp.markSaturated(0, fresh)
		}
		if _, paused := cp.quotaSnapshot(); paused != 0 {
			t.Errorf("minting paused for %s: the relay's second was read as the relay refusing fresh credentials", paused)
		}
	})
}

// The numbers as shipped, against the measurement: the relay let a seat go
// 1 000 ms behind its deallocate and not 990 ms behind it. The pool's second has
// to outlast that with a margin; the grace has to outlast the pool's second by
// the round trips of the Allocate that drew the 486.
func TestThePoolsSecondOutlastsTheRelays(t *testing.T) {
	if seatCoolFor < 1100*time.Millisecond || seatCoolFor > 2*time.Second {
		t.Errorf("seatCoolFor = %s, want 1.1–2 s: the relay holds a deallocated seat for 1.0 s (refused at 990 ms, accepted at 1 000 ms — 2026-09-21)", seatCoolFor)
	}
	if seatLagGrace < seatCoolFor+500*time.Millisecond {
		t.Errorf("seatLagGrace = %s, want at least seatCoolFor (%s) + 500 ms", seatLagGrace, seatCoolFor)
	}
}

// returnAllocation notes a give-back unless the relay is KNOWN to hold no seat
// for this session: over UDP its own word (437), over TCP a deallocate that
// could not even be written — the connection is gone.
func TestReturnAllocationNotesWhatTheRelayStillHolds(t *testing.T) {
	for _, c := range []struct {
		what     string
		release  func() deallocVerdict
		closeErr error
		noted    bool
	}{
		{"UDP: confirmed", func() deallocVerdict { return deallocConfirmed }, nil, true},
		{"UDP: 437 — the relay holds nothing for this socket", func() deallocVerdict { return deallocGone }, nil, false},
		{"UDP: unanswered — cannot tell", func() deallocVerdict { return deallocUnanswered }, errors.New("closed"), true},
		{"UDP: refused — cannot tell", func() deallocVerdict { return deallocRefused }, nil, true},
		{"TCP: the deallocate was written", nil, nil, true},
		{"TCP: the write failed — the connection is gone, and its seat with it", nil, errors.New("write: broken pipe"), false},
	} {
		var gave gaveBack
		order := ""
		release := c.release
		if release != nil {
			inner := release
			release = func() deallocVerdict { order += "release "; return inner() }
		}
		err := returnAllocation(closerFunc(func() error { order += "close"; return c.closeErr }), release, &gave)
		if _, noted := gave.take(); noted != c.noted {
			t.Errorf("%s: a give-back noted = %v, want %v", c.what, noted, c.noted)
		}
		if !errors.Is(err, c.closeErr) {
			t.Errorf("%s: returned %v, want the relay conn's close error %v", c.what, err, c.closeErr)
		}
		if want := map[bool]string{true: "release close", false: "close"}[c.release != nil]; order != want {
			t.Errorf("%s: order %q, want %q — the confirmed deallocate comes before the relay conn is closed", c.what, order, want)
		}
	}
	returnAllocation(closerFunc(func() error { return nil }), nil, nil) // a caller with no note to take (a test's direct runTURN) must not trip it
}

// …at the one teardown the stands above do not pass through: the ABORT of an SRTP
// setup whose allocation was made. (The live session's Close is the killed
// session of the end-to-end stand below; runTURN's is the relay leg of
// relayjoin_test.go.) The control: a setup that never got an allocation notes
// nothing — its lease goes back at once.
func TestAnAbortedSetupNotesTheAllocationItGaveBack(t *testing.T) {
	t.Run("the allocation was made, the handshake never completes", func(t *testing.T) {
		relay, srv := udpQuotaTURN(t, 1)
		tap := newDeallocTap(t, relay, 0)
		p := udpProxy()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var gave gaveBack
		done := make(chan error, 1)
		go func() {
			c, err := p.setupSRTPSession(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, 0, 0, &gave)
			if c != nil {
				_ = c.Close()
			}
			done <- err
		}()
		waitUntil(t, "the allocation", 5*time.Second, func() bool { return srv.AllocationCount() == 1 })
		time.Sleep(50 * time.Millisecond) // into the handshake toward a peer that never answers
		before := time.Now()
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("fixture: setupSRTPSession succeeded against a silent peer")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("setupSRTPSession did not return after the cancel")
		}
		at, noted := gave.take()
		if !noted {
			t.Fatal("the aborted setup gave its allocation back and noted nothing: its lease is released at once, and the seat the relay still holds is handed out again")
		}
		if at.Before(before.Add(-time.Millisecond)) || at.After(time.Now()) {
			t.Errorf("the note reads %s, want a moment between the cancel and the return", at.Sub(before))
		}
	})
	t.Run("the control: no allocation was made — nothing is noted", func(t *testing.T) {
		relay, _ := udpQuotaTURNFor(t, 1, func(string) bool { return false }) // the relay knows no such user: the Allocate is refused
		p := udpProxy()
		var gave gaveBack
		c, err := p.setupSRTPSession(context.Background(), relay, &TURNCreds{Username: "u", Password: "pw"}, 0, 0, &gave)
		if err == nil {
			_ = c.Close()
			t.Fatal("fixture: the setup succeeded with credentials the relay does not know")
		}
		if _, noted := gave.take(); noted {
			t.Error("a setup that never had an allocation noted a give-back: a seat nobody holds would be cooled")
		}
	})
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// ---- end to end ------------------------------------------------------------

// laggingRelay is a pion TURN server on loopback UDP that answers a deallocate
// at once and keeps the seat on the quota for `lag` more — the VK relay's shape —
// behind the tap, which sees the authenticated deallocates pass. It counts the
// Allocates it refused.
type laggingRelay struct {
	tap     *deallocTap
	srv     *turn.Server
	refused atomic.Int32

	mu    sync.Mutex
	freed map[string]time.Time // client socket → when its authenticated deallocate passed
}

func newLaggingRelay(t *testing.T, quota int, lag time.Duration, known func(string) bool) *laggingRelay {
	t.Helper()
	lr := &laggingRelay{freed: map[string]time.Time{}}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var srvRef atomic.Pointer[turn.Server]
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if known(ra.Username) {
				return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
			}
			return "", nil, false
		},
		QuotaHandler: func(string, string, net.Addr) bool {
			s := srvRef.Load()
			if s == nil {
				return true
			}
			held := 0
			lr.mu.Lock()
			for _, at := range lr.freed {
				if time.Since(at) < lag {
					held++
				}
			}
			lr.mu.Unlock()
			if s.AllocationCount()+held < quota {
				return true
			}
			lr.refused.Add(1)
			return false
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
	lr.srv = srv
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
	})
	lr.tap = newDeallocTap(t, pc.LocalAddr().String(), 0)
	lr.tap.onDealloc = func(from string, authenticated bool) {
		if !authenticated {
			return
		}
		lr.mu.Lock()
		if _, seen := lr.freed[from]; !seen {
			lr.freed[from] = time.Now()
		}
		lr.mu.Unlock()
	}
	return lr
}

// srtpPeer is the far end of the production session: the repo's own SRTP server
// side on loopback, accepting and reading whatever comes.
func srtpPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	srv, err := srtpwrap.Listen(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = srv.Close() })
	go func() {
		for {
			c, err := srv.Accept(ctx)
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return srv.Addr().(*net.UDPAddr)
}

// tenOnOneIdentity runs ten PRODUCTION connections — runConnection →
// runSRTPSession, over UDP — on ONE identity whose quota of ten the lagging relay
// enforces; the pool can mint nothing else. kill ends one connection's session
// the way a wake probe's verdict does: the session's own context, not the
// connection's — so runConnection re-dials at once.
type tenOnOneIdentity struct {
	p     *Proxy
	relay *laggingRelay
	mu    sync.Mutex
	kills map[int]context.CancelFunc
}

func newTenOnOneIdentity(t *testing.T, lag time.Duration) *tenOnOneIdentity {
	t.Helper()
	user := fmt.Sprintf("%d:stand", time.Now().Add(8*time.Hour).Unix())
	s := &tenOnOneIdentity{relay: newLaggingRelay(t, connsPerSlot, lag, func(u string) bool { return u == user }), kills: map[int]context.CancelFunc{}}
	peer := srtpPeer(t)
	creds := &TURNCreds{Username: user, Password: "pw", Address: s.relay.tap.addr(), Addresses: []string{s.relay.tap.addr()}}
	p := NewProxy(Config{UseSrtp: true, UseUDP: true, NumConns: connsPerSlot, PeerAddr: peer.String(), SeededTURN: creds})
	p.peer = peer
	p.credPool = newCredPool(p.ctx, poolSizeForNumConns(connsPerSlot), 0, "", func(bool, int) (string, *TURNCreds, error) {
		return "", nil, errors.New("the stand mints nothing: one identity is all there is")
	})
	p.credPool.setColdStartTarget(connsPerSlot)
	p.credPool.seedSlot(0, creds.Address, creds)
	p.sessionHook = func(ctx context.Context, connIdx int) error {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		s.mu.Lock()
		s.kills[connIdx] = cancel
		s.mu.Unlock()
		signaled := true
		return p.runSRTPSession(sctx, "", nil, &signaled, connIdx)
	}
	s.p = p
	var wg sync.WaitGroup
	t.Cleanup(func() { p.cancel(); wg.Wait() })
	for i := 0; i < connsPerSlot; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = p.runConnection(p.sessCtx, "", nil, i) }(i)
	}
	waitUntil(t, "ten sessions on the one identity", 15*time.Second, func() bool {
		return s.relay.srv.AllocationCount() == connsPerSlot && p.activeConns.Load() == int32(connsPerSlot)
	})
	if n := s.relay.refused.Load(); n != 0 {
		t.Fatalf("fixture: the relay refused %d Allocate(s) while the ten came up", n)
	}
	return s
}

// backWithin reports whether all ten are on the identity again within d — not
// fatal: a stand whose connection never comes back still has to say WHY.
func (s *tenOnOneIdentity) backWithin(d time.Duration) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if s.relay.srv.AllocationCount() == connsPerSlot {
			return true
		}
	}
	return false
}

func (s *tenOnOneIdentity) kill(connIdx int) {
	s.mu.Lock()
	cancel := s.kills[connIdx]
	s.mu.Unlock()
	cancel()
}

// THE DEFECT, as the field showed it on 428 (34 of 34): a session is killed on a
// full identity, its connection re-dials at once, and the Allocate reaches the
// relay inside the second it still holds the seat — 486, and a good slot benched
// for eleven minutes. With the seat counted through that second the re-dial
// PARKS (there is nowhere else to go here), is woken when the second is over,
// and is accepted: the relay refuses nothing.
func TestAKilledSessionsRedialIsNotRefusedOverTheRelaysSecond(t *testing.T) {
	shortSecond(t, 500*time.Millisecond, 1500*time.Millisecond)
	s := newTenOnOneIdentity(t, 300*time.Millisecond)
	s.kill(3)
	waitUntil(t, "the killed session to be gone", 5*time.Second, func() bool { return s.relay.srv.AllocationCount() == connsPerSlot-1 })
	back := s.backWithin(10 * time.Second)
	if n := s.relay.refused.Load(); n != 0 {
		t.Errorf("the relay REFUSED %d Allocate(s) — the re-dial reached it inside the second it still held the seat", n)
	}
	if slotSaturated(s.p.credPool, 0) {
		t.Error("slot 0 is benched as VK-saturated over the relay's own second")
	}
	if refusals, _ := s.p.credPool.quotaSnapshot(); refusals != 0 {
		t.Errorf("the pool was told of %d quota refusal(s), want none", refusals)
	}
	if !back {
		t.Error("the connection was not back on the identity within 10 s")
	}
}

// …and when the margin IS missed — here the pool's second is shorter than the
// relay's — the 486 that follows is read for what it is: the slot is not benched,
// and the connection is back as soon as the relay lets the seat go. (With the
// slot benched there is no way back on this stand: one identity is all it has.)
func TestA486InsideTheRelaysSecondDoesNotBenchTheSlot(t *testing.T) {
	shortSecond(t, 50*time.Millisecond, 3*time.Second)
	s := newTenOnOneIdentity(t, 600*time.Millisecond)
	s.kill(6)
	waitUntil(t, "the re-dial to be refused inside the relay's second", 5*time.Second, func() bool { return s.relay.refused.Load() >= 1 })
	back := s.backWithin(15 * time.Second)
	if slotSaturated(s.p.credPool, 0) {
		t.Error("slot 0 is benched as VK-saturated over a 486 inside the relay's own second")
	}
	if !back {
		t.Error("the connection was not back on the identity within 15 s")
	}
	s.p.credPool.mu.Lock()
	lag := s.p.credPool.seat.lagRefusals
	s.p.credPool.mu.Unlock()
	if lag < 1 {
		t.Errorf("%d refusal(s) read as the relay's second, want at least 1", lag)
	}
}

// Where it is wired. Every session gives its lease back through releaseLease,
// with the note its own teardown writes; an allocation is given back through
// returnAllocation at all three teardowns; a relay leg left behind is noted too.
func TestEverySessionReleasesItsLeaseBehindTheRelaysSecond(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return stripComments(string(b))
	}
	src, join := read("proxy.go"), read("relayjoin.go")
	body := func(src, fn string) string {
		i := strings.Index(src, fn)
		if i < 0 {
			t.Fatalf("%s not found", fn)
		}
		rest := src[i+1:]
		if j := strings.Index(rest, "\nfunc "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	for fn, note := range map[string]string{
		"func (p *Proxy) runDTLSSession(":   "&leg.gave",
		"func (p *Proxy) runWrapASession(":  "&leg.gave",
		"func (p *Proxy) runDirectSession(": "&leg.gave",
		"func (p *Proxy) runSRTPSession(":   "&gave",
	} {
		b := body(src, fn)
		if strings.Contains(b, "p.credPool.release(") {
			t.Errorf("%s releases its lease on the pool directly — a seat the relay still holds is handed out again; it goes through p.releaseLease", fn)
		}
		if n := strings.Count(b, "p.releaseLease(currentSlot, currentCreds, "+note+")"); n != 1 {
			t.Errorf("%s: %d deferred releaseLease(currentSlot, currentCreds, %s), want 1", fn, n, note)
		}
	}
	if b := body(src, "func (p *Proxy) runSRTPSession("); !strings.Contains(b, "p.setupSRTPSession(connCtx, turnAddr, creds, credSlot, connIdx, &gave)") {
		t.Error("runSRTPSession does not hand ITS note to setupSRTPSession — the teardown would write a note the lease never reads")
	}
	if b := body(src, "func (p *Proxy) runDirectSession("); !strings.Contains(b, "p.releaseLease(credSlot, currentCreds, &leg.gave)") {
		t.Error("runDirectSession's reconnect loop does not release the ended leg's lease through releaseLease")
	}
	if b := body(src, "func (p *Proxy) setupSRTPSession("); !regexp.MustCompile(`gave:\s+gave,`).MatchString(b) {
		t.Error("setupSRTPSession does not hand the note to the session it returns — the live session's Close would note nothing")
	}
	if n := strings.Count(src, "returnAllocation("); n != 3 {
		t.Errorf("proxy.go gives an allocation back through returnAllocation %d time(s), want 3: the live SRTP session's Close, the abort of its setup, runTURN's defer", n)
	}
	for _, direct := range []string{"relayConn.Close()", "s.relayConn.Close()"} {
		for _, fn := range []string{"func (p *Proxy) runTURN(", "func (p *Proxy) setupSRTPSession(", "func (s *srtpSessionConn) Close() error {"} {
			if strings.Contains(body(src, fn), direct) {
				t.Errorf("%s closes the relay conn itself (%s) — an allocation given back outside returnAllocation is noted by nobody", fn, direct)
			}
		}
	}
	if b := body(join, "func (p *Proxy) goRunTURN("); !strings.Contains(b, "&leg.gave)") {
		t.Error("goRunTURN does not hand the leg's note to runTURN")
	}
	if b := body(join, "func (p *Proxy) joinRelayLeg("); !strings.Contains(b, "leg.gave.note(") {
		t.Error("a relay leg left behind is not noted: its allocation is being given back about then, and the seat must stay counted")
	}
	bridge, err := os.ReadFile("../../WireGuardBridge/csqtt_bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	if b := stripComments(string(bridge)); !strings.Contains(b, "a.pool.ReleaseGivenBack(slot, creds, time.Now())") || !strings.Contains(b, "allocated.Load()") {
		t.Error("csqtt's lease does not go back behind the relay's second when it held an allocation")
	}
}
