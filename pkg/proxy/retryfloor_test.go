package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The floor's arithmetic: 250 ms doubling to an 8 s cap; nothing without a
// streak; void once a session came up AFTER the last failure — and only
// after; gone on a reset. Sabotages seen red: the cap dropped (k = 7 → 16 s);
// the void rule dropped; the void rule blind to order (a session-up BEFORE
// the failure voids it).
func TestRetryFloorTable(t *testing.T) {
	for _, c := range []struct {
		k    int
		want time.Duration
	}{
		{0, 0}, {1, 250 * time.Millisecond}, {2, 500 * time.Millisecond}, {3, time.Second}, {4, 2 * time.Second},
		{5, 4 * time.Second}, {6, 8 * time.Second}, {7, 8 * time.Second}, {40, 8 * time.Second}, {400, 8 * time.Second},
	} {
		if got := retryFloorFor(c.k); got != c.want {
			t.Errorf("retryFloorFor(%d) = %s, want %s", c.k, got, c.want)
		}
	}

	t0 := time.Unix(1_800_000_000, 0)
	var f retryFloor
	if h := f.hold(t0, time.Time{}); h != 0 {
		t.Fatalf("hold with no failure = %s, want 0", h)
	}
	f.noteNetworkFailure(t0)
	f.noteNetworkFailure(t0.Add(time.Second))
	f.noteNetworkFailure(t0.Add(2 * time.Second)) // k = 3: a 1 s floor from t0+2s
	last := t0.Add(2 * time.Second)
	for _, c := range []struct {
		name   string
		now    time.Time
		lastUp time.Time
		want   time.Duration
	}{
		{"at the failure", last, time.Time{}, time.Second},
		{"400 ms later", last.Add(400 * time.Millisecond), time.Time{}, 600 * time.Millisecond},
		{"after the floor", last.Add(time.Second), time.Time{}, 0},
		{"a session came up BEFORE the failure — no evidence about the network since", last.Add(100 * time.Millisecond), last.Add(-time.Millisecond), 900 * time.Millisecond},
		{"a session came up AFTER the failure — void", last.Add(100 * time.Millisecond), last.Add(50 * time.Millisecond), 0},
	} {
		if got := f.hold(c.now, c.lastUp); got != c.want {
			t.Errorf("%s: hold = %s, want %s", c.name, got, c.want)
		}
	}
	f.reset()
	if h := f.hold(last, time.Time{}); h != 0 || f.failures != 0 {
		t.Fatalf("after reset: hold %s, failures %d — want 0, 0", h, f.failures)
	}
}

// Network-class is what did NOT answer: the pool's parks, a captcha, a 486
// and a 401/403 are answers; a refused or unroutable dial, a timeout, a
// failed mint are not. Sabotage seen red: a park classed as the network's.
func TestNetworkClassIsDecidedByWhatAnswered(t *testing.T) {
	park := &poolParkError{msg: "credpool: no slot available (all saturated, cooling down, or fetching)"}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{park, false},
		{fmt.Errorf("session: %w", park), false},
		{&CaptchaRequiredError{}, false},
		{fmt.Errorf("SRTP setup: %w", errors.New("TURN allocate: Allocate error response (error 486: Allocation Quota Reached)")), false},
		{errors.New("DTLS failed: x (TURN error: TURN allocate: Allocate error response (error 401: Unauthorized))"), false},
		{errors.New("TURN allocate: Allocate error response (error 403: Forbidden)"), false},
		{errors.New("SRTP setup: TURN dial: dial tcp 95.163.34.180:19302: connect: no route to host"), true},
		{errors.New("SRTP setup: TURN dial: dial tcp 95.163.34.180:19302: connect: connection refused"), true},
		{errors.New("SRTP setup: TURN dial: dial tcp 95.163.34.180:19302: i/o timeout"), true},
		{errors.New("vk: step2 request failed: EOF"), true},
	} {
		if got := isNetworkClassFailure(c.err); got != c.want {
			t.Errorf("isNetworkClassFailure(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func signalledCh() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// waitRetry. A slot-available wake after a network-class failure is held back
// for the floor and no longer; the same wake after any other failure passes at
// once; the wait's own timer still wins when it is shorter; a session coming up
// anywhere releases a held wake at that moment; a stop ends the wait with the
// context's error. Sabotages seen red: the hold ignored (the wake passes at
// once); the session-up channel not selected (the held wake sits out its 8 s).
func TestWaitRetryHoldsASignalWakeUnderTheFloor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx}
	after := func(k int) *retryFloor {
		f := &retryFloor{}
		for i := 0; i < k; i++ {
			f.noteNetworkFailure(time.Now())
		}
		return f
	}

	start := time.Now()
	why, err := p.waitRetry(ctx, 7, 5*time.Second, signalledCh(), after(1), true)
	if el := time.Since(start); err != nil || why != retryWakeSignal || el < 240*time.Millisecond || el > 2*time.Second {
		t.Fatalf("a wake after ONE network-class failure: %v, %v after %s — want the signal, held ~250 ms", why, err, el.Round(time.Millisecond))
	}

	start = time.Now()
	why, err = p.waitRetry(ctx, 7, 5*time.Second, signalledCh(), after(6), false) // e.g. a park: no floor
	if el := time.Since(start); err != nil || why != retryWakeSignal || el > 100*time.Millisecond {
		t.Fatalf("a wake after a failure that is NOT the network's: %v, %v after %s — want the signal at once", why, err, el.Round(time.Millisecond))
	}

	start = time.Now()
	why, err = p.waitRetry(ctx, 7, 60*time.Millisecond, signalledCh(), after(6), true) // an 8 s floor, a 60 ms timer
	if el := time.Since(start); err != nil || why != retryWakeTimer || el > time.Second {
		t.Fatalf("the wait's own timer under a longer floor: %v, %v after %s — want the timer at ~60 ms", why, err, el.Round(time.Millisecond))
	}

	start = time.Now()
	go func() {
		time.Sleep(120 * time.Millisecond)
		p.noteSessionUp(33) // some OTHER connection's session came up: the network works
	}()
	why, err = p.waitRetry(ctx, 7, 30*time.Second, signalledCh(), after(6), true)
	if el := time.Since(start); err != nil || why != retryWakeSignal || el < 100*time.Millisecond || el > time.Second {
		t.Fatalf("a held wake when a session comes up elsewhere: %v, %v after %s — want the signal right after the ~120 ms mark, not at the 8 s floor", why, err, el.Round(time.Millisecond))
	}

	sess, stop := context.WithCancel(ctx)
	go func() { time.Sleep(50 * time.Millisecond); stop() }()
	start = time.Now()
	_, err = p.waitRetry(sess, 7, 30*time.Second, make(chan struct{}), after(6), true)
	if el := time.Since(start); !errors.Is(err, context.Canceled) || el > time.Second {
		t.Fatalf("a stop during the wait: %v after %s — want context.Canceled at once", err, el.Round(time.Millisecond))
	}
}

// THE HERD — the field's storm on a bare proxy. Forty connections restarted
// by a path change: their own slots are benched (the path-change marking), so
// all forty fall back onto the reserve slots by COMPACT-FILL — which packs
// them onto the fullest slot with room, i.e. keeps one slot at its cap. Each
// session takes its seat, fails at once the way a dial into a dead route does,
// and gives the seat back: a release from a full slot broadcasts
// slot-available, the waiters rush back in, compact-fill tops the slot up to
// its cap again, and the next release broadcasts again — before the floor,
// 69 dials per connection in 0.6 s on the phone. With the floor a connection
// dials at 0, ≥ 0.25 s and ≥ 0.75 s into the first second: at most three each.
// Exactly that here: 120 dials, run after run. Sabotages seen red: the failure
// never classed as the network's (floored stays false) — 231, 624, 828, 1 569
// and 2 773 dials in five runs, the last the phone's own figure; waitRetry
// ignoring the hold.
func TestAHerdOfInstantFailuresIsBoundedByTheFloor(t *testing.T) {
	const conns, slots = 40, 4
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 16, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
		return "", nil, fmt.Errorf("unexpected mint into slot %d", slot)
	})
	cp.setColdStartTarget(conns)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	for i := 0; i < 2*slots; i++ {
		cp.pool[i] = credPoolEntry{addr: leaseTestRelay, ts: time.Now(), creds: &TURNCreds{
			Username: fmt.Sprintf("%d:herd-%d", time.Now().Add(8*time.Hour).Unix(), i), Password: "p",
			Address: leaseTestRelay, Addresses: []string{leaseTestRelay}}}
		if i < slots { // the connections' own slots, benched by the path change
			cp.pool[i].saturatedUntil = time.Now().Add(10 * time.Minute)
		}
	}
	cp.mu.Unlock()

	var dials atomic.Int64
	p := &Proxy{ctx: ctx, credPool: cp}
	p.sessionHook = func(_ context.Context, connIdx int) error {
		_, creds, slot, err := p.resolveTURNAddr(connIdx, false)
		if err != nil {
			return err // a park: the pool's own answer, no floor
		}
		dials.Add(1)
		time.Sleep(time.Millisecond) // the seat is held for the length of a failing connect()
		p.credPool.release(slot, creds)
		return errors.New("SRTP setup: TURN dial: dial tcp 95.163.34.180:19302: connect: no route to host")
	}

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = p.runConnection(ctx, "", nil, i)
		}(i)
	}
	time.Sleep(time.Second)
	inFirstSecond := dials.Load()
	cancel()
	wg.Wait()
	t.Logf("%d dials in the first second from %d connections", inFirstSecond, conns)

	if inFirstSecond < conns {
		t.Fatalf("%d dials in the first second, want at least %d — not every connection even tried", inFirstSecond, conns)
	}
	if inFirstSecond > 3*conns {
		t.Fatalf("%d dials in the first second from %d connections whose dials fail at once — want at most %d (three apiece: at 0, 0.25 s and 0.75 s; the fourth is due at 1.75 s): the slot-available broadcasts are driving the herd again", inFirstSecond, conns, 3*conns)
	}
	if _, live, _ := leaseCounts(cp, 0); live != 0 {
		t.Fatalf("liveLeases = %d after every connection stopped, want 0", live)
	}
}

// A session that CAME UP ends the streak WHATEVER IT RETURNED (the user's review
// of build 409). runSRTPSession and runDTLSSession return nil after wg.Wait —
// also when an established session has dropped — and the reset sat under
// `err != nil`: the next iteration cannot see the previous one's stamp, so the
// streak survived a working session and the next failure's wake was held for
// seconds. Through runConnection, one connection, slot-available broadcast every
// 5 ms: two network-class failures (k = 2), a session that comes up and
// returns, then a failure — its wake must be held ~250 ms (k = 1), not ~1 s
// (k = 3). The arm whose session returns an ERROR was right before and must
// stay so. Sabotages seen red: the reset back under the error branch (the nil
// arm alone reddens: held 1 s); a failure after a session that came up still
// classed as the network's (the error arm reddens: its next attempt waits
// 250 ms instead of starting at once).
func TestASessionThatCameUpEndsTheStreakWhateverItReturned(t *testing.T) {
	for _, c := range []struct {
		name  string
		after error
	}{
		{"it returned nil, as the SRTP and DTLS sessions do after wg.Wait", nil},
		{"it returned an error", errors.New("SRTP: read tcp: connection reset by peer")},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
				return "", nil, fmt.Errorf("unexpected mint into slot %d", slot)
			})
			p := &Proxy{ctx: ctx, credPool: cp}
			var mu sync.Mutex
			var starts []time.Time
			p.sessionHook = func(hctx context.Context, connIdx int) error {
				mu.Lock()
				starts = append(starts, time.Now())
				n := len(starts)
				mu.Unlock()
				switch n {
				case 1, 2, 4:
					return errors.New("SRTP setup: TURN dial: dial tcp 95.163.34.180:19302: connect: no route to host")
				case 3:
					p.noteSessionUp(connIdx) // the session came up …
					return c.after           // … and ended
				default:
					<-hctx.Done()
					return hctx.Err()
				}
			}
			go func() { // every wait is signalled at once: only the floor holds a retry back
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-tick.C:
						cp.broadcastSlotAvailable()
					case <-ctx.Done():
						return
					}
				}
			}()
			done := make(chan struct{})
			go func() { defer close(done); _ = p.runConnection(ctx, "", nil, 0) }()
			deadline := time.After(6 * time.Second)
			for {
				mu.Lock()
				n := len(starts)
				mu.Unlock()
				if n >= 5 {
					break
				}
				select {
				case <-deadline:
					t.Fatalf("only %d attempts in 6 s", n)
				case <-time.After(5 * time.Millisecond):
				}
			}
			cancel()
			<-done
			mu.Lock()
			defer mu.Unlock()
			if g := starts[2].Sub(starts[1]); g < 450*time.Millisecond || g > 900*time.Millisecond {
				t.Fatalf("the gap after the SECOND failure = %s, want ~500 ms — the fixture is not exercising the floor", g.Round(time.Millisecond))
			}
			if g := starts[3].Sub(starts[2]); g > 200*time.Millisecond {
				t.Fatalf("the attempt after the session that came up started %s later, want at once — that iteration was no network failure", g.Round(time.Millisecond))
			}
			if g := starts[4].Sub(starts[3]); g < 200*time.Millisecond || g > 700*time.Millisecond {
				t.Fatalf("the wake after the first failure FOLLOWING a session that came up was held %s, want ~250 ms (a new streak, k = 1) — the streak of the two failures before that session was kept (k = 3 holds 1 s)", g.Round(time.Millisecond))
			}
		})
	}
}

// The wiring, by property: both retry waits go through waitRetry with the
// connection's floor and its classification; the streak ends on the
// connection's own session and on a restart by request, never on a signal
// wake; three transports stamp the session-up where their handshake over the
// relay has completed and the direct one at its allocation — never at its
// "session established" line, which precedes the allocation. Sabotages seen
// red: the retry delay back on a bare select over slotCh; a session-up stamp
// dropped; the direct line stamped; a signal wake resetting the streak.
func TestTheRetryWaitsConsultTheFloor(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	code := stripComments(string(src))
	rc := goFuncBody(t, "proxy.go", "func (p *Proxy) runConnection(")
	if n := strings.Count(rc, "p.waitRetry(sessCtx, "); n != 2 {
		t.Errorf("runConnection: %d waits through waitRetry, want 2 (the dormancy, the retry delay)", n)
	}
	if n := len(regexp.MustCompile(`p\.waitRetry\(sessCtx, connIdx, \w+, slotCh, &floor, floored\)`).FindAllString(rc, -1)); n != 2 {
		t.Errorf("runConnection: %d waits carry the connection's floor and its classification, want 2", n)
	}
	if strings.Contains(rc, "case <-slotCh") {
		t.Error("runConnection selects on the slot-available channel directly — a wake that bypasses the floor")
	}
	if n := strings.Count(rc, "floor.reset()"); n != 2 {
		t.Errorf("runConnection: %d floor resets, want 2 — the connection's own session, a restart by request", n)
	}
	if i := strings.Index(rc, "case retryWakeSignal:"); i < 0 || strings.Contains(rc[i:], "floor.reset()") {
		t.Error("runConnection: a signal wake resets the floor's streak (or the dormancy's signal arm is gone) — the streak ends on evidence that the network works, never on a wake")
	}
	if est, errBranch := strings.Index(rc, "established := p.ups.since(connIdx, start)"), strings.Index(rc, "if err != nil {"); est < 0 || errBranch < 0 || est > errBranch {
		t.Error("runConnection asks whether a session came up inside the error branch (or not at all) — a session that came up and returned nil would keep the streak")
	}
	if !strings.Contains(rc, "if established {\n\t\t\tfloor.reset()") || !strings.Contains(rc, "if !established && isNetworkClassFailure(err) {") {
		t.Error("runConnection: the streak's reset is conditioned on something besides the session having come up, or a failure after one still counts as the network's")
	}
	if !strings.Contains(rc, "p.ups.since(connIdx, start)") || !strings.Contains(rc, "isNetworkClassFailure(err)") {
		t.Error("runConnection does not classify the failure by what happened: no session in this iteration and no answer from the pool, VK or the relay")
	}
	hook, first := strings.Index(rc, "case p.sessionHook != nil:"), strings.Index(rc, "case p.config.UseWrapA:")
	if hook < 0 || first < 0 || hook > first {
		t.Error("runConnection's dispatch does not try the session hook first — the herd test's seam")
	}

	for _, lit := range []string{"DTLS+TURN session established", "WRAP-A+TURN session established", "SRTP+TURN session established"} {
		i := strings.Index(code, lit)
		if i < 0 {
			t.Fatalf("proxy.go no longer logs %q", lit)
		}
		if !strings.Contains(code[max(0, i-200):i], "p.noteSessionUp(connIdx)") {
			t.Errorf("%q is not preceded by the session-up stamp — the retry floor never learns that the network works", lit)
		}
	}
	direct := strings.Index(code, "direct TURN session established")
	if direct < 0 {
		t.Fatal("proxy.go no longer logs the direct session's line")
	}
	if strings.Contains(code[max(0, direct-300):direct], "noteSessionUp(") {
		t.Error("the direct session's \"established\" line carries the session-up stamp — that line precedes the allocation and is evidence of nothing")
	}
	turn := goFuncBody(t, "proxy.go", "func (p *Proxy) runTURN(")
	alloc, stamp := strings.Index(turn, "p.credPool.noteAllocated(slotIdx, creds)"), strings.Index(turn, "p.noteSessionUp(connIdx)")
	if alloc < 0 || stamp < alloc || !strings.Contains(turn[alloc:stamp], "if p.directMode() {") {
		t.Error("runTURN does not stamp the direct mode's session-up at its allocation (under directMode, after the allocation succeeded)")
	}
	if n := strings.Count(code, "p.noteSessionUp(connIdx)"); n != 4 {
		t.Errorf("proxy.go: %d session-up stamps, want 4 — three handshakes and the direct mode's allocation", n)
	}
}
