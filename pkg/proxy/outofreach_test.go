package proxy

// Build 432 — the allocation out of reach (outofreach.go). MEASURED on a stand
// (2026-09-21): a 5-tuple with no allocation is answered 400 to CreatePermission
// and ChannelBind and 437 to Refresh; the field of the same day showed such
// allocations still COUNTED on the identity's quota — the mapping had changed
// under the socket. The end-to-end stand runs the PRODUCTION session against a
// relay that answers the way the VK relay was measured to, behind a tap that can
// change one client's mapping.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy/srtpwrap"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// captureLog collects what the package says while a test runs.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(b)
	}))
	t.Cleanup(func() { log.SetOutput(prev) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// ---- the pool ---------------------------------------------------------------

// thawAtCleanup lets a test that leaves a seat HELD end clean: before the test
// returns the wall clock jumps a day ahead — as across a freeze — and the held
// seat is seen to be let go, so that no step of it runs beside the next test.
func thawAtCleanup(t *testing.T, cp *credPool, slot, want int) {
	t.Helper()
	clock := wallClock
	var thawed atomic.Bool
	wallClock = func() time.Time {
		if thawed.Load() {
			return time.Now().Add(24 * time.Hour).Round(0)
		}
		return time.Now().Round(0)
	}
	t.Cleanup(func() {
		thawed.Store(true)
		waitUntil(t, "the held seat to be let go before the test ends", 2*time.Second, func() bool { a, _, _ := leaseCounts(cp, slot); return a <= want })
		wallClock = clock
	})
}

// A seat whose allocation is OUT OF REACH stays counted until that allocation
// can have expired — by the WALL clock — and is let go then; one whose time has
// run out already is let go at once; and no give-back is noted for it: a 486
// behind a held seat is not the relay's second.
func TestASeatOutOfReachStaysCountedUntilItsAllocationCanHaveExpired(t *testing.T) {
	step := seatHoldStep
	seatHoldStep = 20 * time.Millisecond // a long wait is cut into steps: here every step is seen
	t.Cleanup(func() { seatHoldStep = step })
	t.Run("counted until then, let go then, and whoever parked is woken", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		wake := cp.slotAvailableChannel()
		t0 := time.Now()
		cp.holdSeatUntil(0, creds, t0.Add(150*time.Millisecond))
		if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != connsPerSlot {
			t.Fatalf("right behind the hold: active %d, leases out %d, want %d and %d — a seat the relay may still hold is handed out again", active, live, connsPerSlot, connsPerSlot)
		}
		select {
		case <-wake:
		case <-time.After(2 * time.Second):
			t.Fatal("nobody was woken when the seat was let go")
		}
		if took := time.Since(t0); took < 150*time.Millisecond {
			t.Errorf("let go %s after the hold began, ahead of its time (150ms)", took)
		}
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("active %d after the hold, want %d", active, connsPerSlot-1)
		}
	})
	t.Run("a time that has run out by the wall clock: at once", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		cp.holdSeatUntil(0, creds, time.Now().Add(-time.Second))
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("active %d, want %d at once: the allocation has expired, nothing holds the seat", active, connsPerSlot-1)
		}
	})
	t.Run("across a freeze: the wall clock runs ahead of the timers', and the next step sees it", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		var thawed atomic.Bool
		clock := wallClock
		wallClock = func() time.Time {
			if thawed.Load() {
				return time.Now().Add(2 * time.Hour).Round(0) // the process slept two hours: its timers did not
			}
			return time.Now().Round(0)
		}
		t.Cleanup(func() { wallClock = clock })
		cp.releaseAt(0, creds, time.Now().Add(time.Hour))
		time.Sleep(100 * time.Millisecond) // five steps: each looked, none let go
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot {
			t.Fatalf("active %d, want %d: a step let the seat go an hour ahead of its time", active, connsPerSlot)
		}
		thawed.Store(true)
		waitUntil(t, "the seat to be let go within a step of the thaw", time.Second, func() bool { a, _, _ := leaseCounts(cp, 0); return a == connsPerSlot-1 })
	})
	t.Run("a pool whose context has ended counts for nobody: the steps stop with it", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		ctx, cancel := context.WithCancel(context.Background())
		cp.ctx = ctx
		var thawed atomic.Bool
		clock := wallClock
		wallClock = func() time.Time {
			if thawed.Load() {
				return time.Now().Add(24 * time.Hour).Round(0)
			}
			return time.Now().Round(0)
		}
		cp.releaseAt(0, creds, time.Now().Add(time.Hour))
		cancel()
		time.Sleep(60 * time.Millisecond) // the step that finds the context ended is the last one
		thawed.Store(true)
		time.Sleep(100 * time.Millisecond)
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot {
			t.Errorf("active %d, want %d: a held seat went on stepping behind its pool's end", active, connsPerSlot)
		}
		wallClock = clock
	})
	t.Run("no give-back is noted: a 486 behind a held seat benches the slot", func(t *testing.T) {
		shortSecond(t, 150*time.Millisecond, 400*time.Millisecond)
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		thawAtCleanup(t, cp, 0, connsPerSlot-1)
		cp.holdSeatUntil(0, creds, time.Now().Add(time.Minute))
		if cd := cp.markSaturated(0, creds); cd == 0 || !slotSaturated(cp, 0) {
			t.Errorf("cooldown %s, saturated %v — a held seat is no give-back: the 486 behind it is not the relay's second", cd, slotSaturated(cp, 0))
		}
	})
	t.Run("releaseLease: a hold outlasts the second, and both notes are taken", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		thawAtCleanup(t, cp, 0, connsPerSlot-1)
		p := &Proxy{credPool: cp}
		var gave gaveBack
		gave.note(time.Now())
		gave.life.granted(time.Minute)
		gave.noteOutOfReach(time.Now())
		p.releaseLease(0, creds, &gave)
		time.Sleep(60 * time.Millisecond)
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot {
			t.Errorf("active %d, want %d: the lease went back by the second although its allocation is out of reach for a minute", active, connsPerSlot)
		}
		if _, again := gave.take(); again {
			t.Error("the give-back's note was left behind: the session's next lease would be cooled by it")
		}
		if _, again := gave.takeHold(); again {
			t.Error("the hold's note was left behind")
		}
	})
}

// ---- what the session hears -------------------------------------------------

// pion's lines are the only place a refresh's outcome is heard. The lifetime the
// relay granted is stamped on the wall clock; a permission refresh answered 400
// ends the session — once — and nothing else does.
func TestAllocLifeHearsWhatPionSays(t *testing.T) {
	const refused = "Fail to refresh permissions: CreatePermission error response (error 400: Bad Request)"
	t.Run("the lifetime, at the Allocate and at every refresh", func(t *testing.T) {
		var l allocLife
		now := time.Now()
		if got := l.expiry(now); got.Sub(now) != assumedAllocLifetime {
			t.Errorf("nothing heard: expiry %s from now, want the assumed lifetime %s", got.Sub(now), assumedAllocLifetime)
		}
		l.heardDebug("Initial lifetime: 600 seconds")
		if d := time.Until(l.expiry(now)); d < 599*time.Second || d > 601*time.Second+lifeSlack {
			t.Errorf("Initial lifetime: 600 seconds → expires in %s", d)
		}
		l.heardDebug("Updated lifetime: 3600 seconds")
		if d := time.Until(l.expiry(now)); d < 3599*time.Second || d > 3601*time.Second+lifeSlack {
			t.Errorf("Updated lifetime: 3600 seconds → expires in %s", d)
		}
		for _, other := range []string{"Refresh timer 1 expired", "lifetime: 5 seconds", "Updated lifetime: 0 seconds", "Updated lifetime: x seconds",
			"Send refresh request (dontWait=true)", "Refresh request sent", "No permission to refresh"} {
			before := l.expiry(now)
			l.heardDebug(other)
			if got := l.expiry(now); !got.Equal(before) {
				t.Errorf("%q moved the expiry by %s", other, got.Sub(before))
			}
		}
		if at := l.expiry(now); at != at.Round(0) {
			t.Error("the expiry carries a monotonic reading: the relay's lifetime runs in real time")
		}
	})
	t.Run("a permission refresh answered 400 ends the session, once, through pion's logger", func(t *testing.T) {
		say := captureLog(t)
		var gave gaveBack
		var kills atomic.Int32
		gave.watch(func() { kills.Add(1) }, 7, false)
		lg := (&turnLoggerFactory{slot: 0, life: gave.lifeOf()}).NewLogger("turnc")
		lg.Debugf("Initial lifetime: %d seconds", 1200) // pion's own call, udp_conn.go
		if d := time.Until(gave.lifeOf().expiry(time.Now())); d < 1199*time.Second || d > 1201*time.Second+lifeSlack {
			t.Errorf("the lifetime pion said through its logger was not stamped: expires in %s, want 20m", d.Round(time.Second))
		}
		lg.Errorf("Fail to refresh permissions: %s", "CreatePermission error response (error 400: Bad Request)") // pion's own call, allocation.go
		waitUntil(t, "the session to be ended by pion's FIRST line for the failure", time.Second, func() bool { return kills.Load() == 1 })
		lg.Warnf("Failed to refresh permissions: %s", "CreatePermission error response (error 400: Bad Request)") // … and its second line for the same failure
		lg.Error(refused)
		gave.lifeOf().wait()
		if n := kills.Load(); n != 1 {
			t.Errorf("the session was ended %d time(s), want once", n)
		}
		if !gave.lifeOf().isGone() {
			t.Error("the socket is not marked as one the relay has disowned — an unanswered deallocate behind it would be read as a give-back")
		}
		out := say()
		if n := strings.Count(out, "[conn 7] the session is dead at the relay"); n != 1 {
			t.Errorf("said %d time(s) that the session is dead at the relay, want once:\n%s", n, out)
		}
		if n := strings.Count(out, "the relay has NO allocation for this connection"); n != 1 {
			t.Errorf("the mapping was said %d time(s), want once (over TCP: that the 5-tuple is the connection's)", n)
		}
	})
	t.Run("nothing else ends it", func(t *testing.T) {
		for _, msg := range []string{
			"Fail to refresh permissions: all retransmissions failed for ZZZZ",
			"Fail to refresh permissions: transaction closed",
			"Fail to refresh permissions: CreatePermission error response (error 401: Unauthorized)",
			"Fail to refresh permissions: write udp [::]:64000->1.2.3.4:40000: use of closed network connection", // a bare 400 is a port number as often as not
			"Failed to bind channel 16384: unexpected response type ChannelBind error response",
			"Failed to refresh allocation: error response (error 400: Bad Request)",
			"x Fail to refresh permissions: CreatePermission error response (error 400: Bad Request)",
		} {
			var gave gaveBack
			var kills atomic.Int32
			gave.watch(func() { kills.Add(1) }, 1, false)
			gave.lifeOf().heardError(msg)
			gave.lifeOf().wait()
			if kills.Load() != 0 || gave.lifeOf().isGone() {
				t.Errorf("%q ended the session", msg)
			}
		}
	})
	t.Run("nothing is begun behind the join, and a nil life is no bookkeeping", func(t *testing.T) {
		var gave gaveBack
		var kills atomic.Int32
		gave.watch(func() { kills.Add(1) }, 1, false)
		gave.lifeOf().wait()
		gave.lifeOf().heardError(refused)
		time.Sleep(30 * time.Millisecond)
		if kills.Load() != 0 {
			t.Error("a session that has been joined was ended once more")
		}
		gave.lifeOf().fresh() // the direct session's next allocation under the same note
		gave.lifeOf().heardError(refused)
		gave.lifeOf().wait()
		if kills.Load() != 1 {
			t.Errorf("after fresh(): ended %d time(s), want 1 — the next allocation's life starts clean", kills.Load())
		}
		var none *allocLife
		none.heardDebug("Initial lifetime: 600 seconds")
		none.heardError(refused)
		none.fresh()
		none.askMappingAtAllocate(nil)
		none.sayMapping("x")
		none.wait()
		(*gaveBack)(nil).noteOutOfReach(time.Now())
	})
}

// The three strings this build hears are pion's OWN — and an upgrade that rewords
// them would silence it without a sound. Read in the module's source.
func TestPionStillSaysWhatThisBuildListensFor(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/pion/turn/v5").Output()
	if err != nil {
		t.Fatalf("go list: %v — the pin on pion's wording cannot be checked", err)
	}
	dir := strings.TrimSpace(string(out))
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	alloc, conn := read("internal/client/allocation.go"), read("internal/client/udp_conn.go")
	for _, want := range []struct{ src, lit, why string }{
		{alloc, `a.log.Debugf("Updated lifetime: %d seconds"`, "the expiry is stamped from it at every refresh"},
		{conn, `conn.log.Debugf("Initial lifetime: %d seconds"`, "the expiry is stamped from it at the Allocate"},
		{alloc, `a.log.Errorf("Fail to refresh permissions: %s", err)`, "a permission refresh answered 400 ends the session"},
		{alloc, `a.log.Debugf("Send refresh request (dontWait=%v)", dontWait)`, "a refresh sent and not heard granted may have been granted: the bound of the allocation's life counts it"},
		{alloc, `a.log.Debug("` + pionRefreshAnswered + `")`, "the last moment a copy of that refresh can have left"},
		{alloc, `a.log.Warnf("` + pionRefreshFailed + `%s", err)`, "the same, for a refresh that came back with no answer"},
	} {
		if !strings.Contains(want.src, want.lit) {
			t.Errorf("pion no longer says %s — %s (outofreach.go)", want.lit, want.why)
		}
	}
	// …and WHERE pion says them is what they mean: the first before the transaction
	// goes out, the second behind its return — never the other way round.
	body := alloc[strings.Index(alloc, "func (a *allocation) refreshAllocation("):]
	body = body[:strings.Index(body, "\nfunc (a *allocation) refreshPermissions(")]
	sentAt, txAt, backAt := strings.Index(body, `"Send refresh request (dontWait=%v)"`), strings.Index(body, "a.client.PerformTransaction("), strings.Index(body, `"Refresh request sent, and waiting response"`)
	if sentAt < 0 || txAt < 0 || backAt < 0 || !(sentAt < txAt && txAt < backAt) {
		t.Errorf("pion's refresh no longer says \"Send refresh request\" BEFORE its transaction and \"…waiting response\" BEHIND it (at %d, %d, %d) — the moments outofreach.go takes from them mean something else now", sentAt, txAt, backAt)
	}
	if fmt.Sprintf("Send refresh request (dontWait=%v)", false) != pionRefreshSent || !strings.HasPrefix(fmt.Sprintf("Failed to refresh allocation: %s", "x"), pionRefreshFailed) {
		t.Error("the refresh lines listened for are not pion's")
	}
	for _, line := range []string{"Initial lifetime: 600 seconds", "Updated lifetime: 600 seconds"} {
		if !pionLifetimeLine.MatchString(line) {
			t.Errorf("%q is not matched", line)
		}
	}
	if !strings.HasPrefix(fmt.Sprintf("Fail to refresh permissions: %s", "x"), pionPermissionRefreshFailed) {
		t.Error("the prefix listened for is not pion's")
	}
}

// Where it is wired: the session tells its note who it is before its client
// exists; the life starts clean right before every Allocate and asks for the
// mapping right behind it; pion's logger is handed the life; and whatever asks
// the relay is JOINED behind the client's Close, at all three teardowns.
func TestEverySessionsAllocationLifeIsWiredAndJoined(t *testing.T) {
	b, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	src := stripComments(string(b))
	body := func(fn string) string {
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
		"func (p *Proxy) runDTLSSession(":   "leg.gave",
		"func (p *Proxy) runWrapASession(":  "leg.gave",
		"func (p *Proxy) runDirectSession(": "leg.gave",
		"func (p *Proxy) runSRTPSession(":   "gave",
	} {
		bd := body(fn)
		w := strings.Index(bd, note+".watch(connCancel, connIdx, p.config.UseUDP)")
		if w < 0 {
			t.Errorf("%s does not tell its note who it is — a session dead at the relay could not be ended, and its mapping would be asked about as over TCP", fn)
			continue
		}
		if first := strings.Index(bd, "p.setupSRTPSession("); first >= 0 && first < w {
			t.Errorf("%s: the note is told only after the client exists", fn)
		}
		if first := strings.Index(bd, "p.goRunTURN("); first >= 0 && first < w {
			t.Errorf("%s: the note is told only after the relay leg has started", fn)
		}
	}
	order := func(where, bd string, want ...string) {
		at := -1
		for _, w := range want {
			i := strings.Index(bd, w)
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
	run := body("func (p *Proxy) runTURN(")
	order("runTURN", run, "life: gave.lifeOf()}", "defer func() { client.Close(); gave.lifeOf().wait() }()", "gave.lifeOf().fresh()", "client.Allocate()", "gave.lifeOf().askMappingAtAllocate(client)")
	setup := body("func (p *Proxy) setupSRTPSession(")
	order("setupSRTPSession", setup, "life: gave.lifeOf()}", "gave.lifeOf().fresh()", "tc.Allocate()", "gave.lifeOf().askMappingAtAllocate(tc)")
	a := strings.Index(setup, "abortSetup := func() {")
	order("abortSetup", setup[a:a+strings.Index(setup[a:], "\n\t}\n")], "returnAllocation(relayConn, release, gave)", "tc.Close()", "gave.lifeOf().wait()", "ctlConn.Close()")
	order("srtpSessionConn.Close", body("func (s *srtpSessionConn) Close() error {"), "returnAllocation(s.relayConn, s.release, s.gave)", "s.tc.Close()", "s.gave.lifeOf().wait()", "s.ctlConn.Close()")
	if strings.Contains(run, "defer client.Close()") {
		t.Error("runTURN closes its client without joining what asks the relay on the allocation's behalf")
	}
}

// ---- end to end -------------------------------------------------------------

// vkLikeTap forwards datagrams between the clients and a pion relay — every
// client socket gets an upstream socket of its own: the MAPPING the relay knows
// it by — and can do to one client what a translator on the path does across a
// silence: give it ANOTHER mapping. From then on that client's packets reach the
// relay from a 5-tuple with no allocation, and are answered the way the VK relay
// was measured to answer them (2026-09-21): 400 to CreatePermission and
// ChannelBind, 437 to Refresh — the unauthenticated one already; a Binding is
// answered, from the new mapping; data goes nowhere. The allocation lives on at
// the relay under the old mapping, and holds its seat.
type vkLikeTap struct {
	ln    *net.UDPConn
	relay *net.UDPAddr

	mu       sync.Mutex
	order    []string // client sockets in the order they appeared
	ups      map[string]*net.UDPConn
	disowned map[string]bool
	ghosts   []*net.UDPConn // the mappings left behind: open, so that their allocations live on
	refusals atomic.Int32   // 400s and 437s the tap answered
	firstAt  atomic.Int64   // when it answered the first of them, unix ns

	loseFor     string // the client socket whose next refresh is GRANTED by the relay — and the answer lost, the mapping changed behind the request
	refreshes   map[string]int
	lostAt      atomic.Int64 // when that refresh passed, unix ns
	lostAnswers atomic.Int32 // what the relay sent to a mapping left behind: it reaches nobody
}

func newVKLikeTap(t *testing.T, relay string) *vkLikeTap {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tap := &vkLikeTap{ln: ln, relay: ra, ups: map[string]*net.UDPConn{}, disowned: map[string]bool{}, refreshes: map[string]int{}}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *vkLikeTap) addr() string { return tap.ln.LocalAddr().String() }

// upstream makes a client its mapping. Caller holds tap.mu.
func (tap *vkLikeTap) upstream(client *net.UDPAddr) (*net.UDPConn, error) {
	up, err := net.DialUDP("udp4", nil, tap.relay)
	if err != nil {
		return nil, err
	}
	tap.ups[client.String()] = up
	go func() { // the relay's answers, back to that client — while this IS its mapping
		b := make([]byte, 2048)
		for {
			n, err := up.Read(b)
			if err != nil {
				return
			}
			tap.mu.Lock()
			current := tap.ups[client.String()] == up
			tap.mu.Unlock()
			if !current { // a translator that has forgotten the flow lets nothing back in
				tap.lostAnswers.Add(1)
				continue
			}
			_, _ = tap.ln.WriteToUDP(b[:n], client)
		}
	}()
	return up, nil
}

// remap gives the n-th client socket (in order of appearance) another mapping.
func (tap *vkLikeTap) remap(t *testing.T, n int) {
	t.Helper()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	if n >= len(tap.order) {
		t.Fatalf("fixture: the tap has seen %d client socket(s), no #%d", len(tap.order), n)
	}
	if err := tap.remapLocked(tap.order[n]); err != nil {
		t.Fatal(err)
	}
}

// remapLocked leaves the client's mapping behind — open, so that its allocation
// lives on — and gives it another. Caller holds tap.mu.
func (tap *vkLikeTap) remapLocked(client string) error {
	tap.ghosts = append(tap.ghosts, tap.ups[client])
	addr, _ := net.ResolveUDPAddr("udp4", client)
	if _, err := tap.upstream(addr); err != nil {
		return err
	}
	tap.disowned[client] = true
	return nil
}

// loseNextRefreshAnswer arms what a review of build 432 described: the n-th
// client's NEXT allocation refresh reaches the relay and is GRANTED — and the
// mapping changes right behind the request, so that the answer reaches nobody and
// the retransmitted copies arrive from a 5-tuple with no allocation (437). It
// says how many refreshes of that client had passed before it was armed.
func (tap *vkLikeTap) loseNextRefreshAnswer(t *testing.T, n int) int {
	t.Helper()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	if n >= len(tap.order) {
		t.Fatalf("fixture: the tap has seen %d client socket(s), no #%d", len(tap.order), n)
	}
	tap.loseFor = tap.order[n]
	return tap.refreshes[tap.loseFor]
}

func (tap *vkLikeTap) clients() int {
	tap.mu.Lock()
	defer tap.mu.Unlock()
	return len(tap.order)
}

func (tap *vkLikeTap) serve() {
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
			if up, err = tap.upstream(from); err != nil {
				tap.mu.Unlock()
				return
			}
			tap.order = append(tap.order, from.String())
		}
		disowned := tap.disowned[from.String()]
		if !disowned && stun.IsMessage(pkt) {
			r := &stun.Message{Raw: pkt}
			if lt, err := refreshLifetime(r); err == nil && lt > 0 {
				tap.refreshes[from.String()]++
				if tap.loseFor == from.String() {
					tap.loseFor = ""
					_, _ = up.Write(pkt) // the relay gets it, and grants it …
					tap.lostAt.Store(time.Now().UnixNano())
					if err := tap.remapLocked(from.String()); err != nil { // … and its answer finds the mapping gone
						tap.mu.Unlock()
						return
					}
					tap.mu.Unlock()
					continue
				}
			}
		}
		tap.mu.Unlock()
		if !disowned {
			_, _ = up.Write(pkt)
			continue
		}
		m := &stun.Message{Raw: pkt}
		if !stun.IsMessage(pkt) || m.Decode() != nil || m.Type.Class != stun.ClassRequest {
			continue // data, indications: a relay forwards nothing for a 5-tuple it has no allocation for
		}
		refuse := func(code stun.ErrorCode, reason string) {
			res, err := stun.Build(stun.NewTransactionIDSetter(m.TransactionID), stun.NewType(m.Type.Method, stun.ClassErrorResponse),
				stun.ErrorCodeAttribute{Code: code, Reason: []byte(reason)}, stun.Fingerprint)
			if err == nil {
				tap.firstAt.CompareAndSwap(0, time.Now().UnixNano())
				tap.refusals.Add(1)
				_, _ = tap.ln.WriteToUDP(res.Raw, from)
			}
		}
		switch m.Type.Method {
		case stun.MethodCreatePermission, stun.MethodChannelBind:
			refuse(stun.CodeBadRequest, "Bad Request")
		case stun.MethodRefresh:
			refuse(stun.CodeAllocMismatch, "Invalid allocation")
		default: // a Binding needs no allocation; an Allocate would make one
			_, _ = up.Write(pkt)
		}
	}
}

// refreshLifetime is the LIFETIME a Refresh REQUEST asks for, in seconds (a
// deallocate asks for 0); an error for anything else.
func refreshLifetime(m *stun.Message) (uint32, error) {
	if err := m.Decode(); err != nil {
		return 0, err
	}
	if m.Type != stun.NewType(stun.MethodRefresh, stun.ClassRequest) {
		return 0, errors.New("not a Refresh request")
	}
	v, err := m.Get(stun.AttrLifetime)
	if err != nil || len(v) != 4 {
		return 0, errors.New("no LIFETIME")
	}
	return binary.BigEndian.Uint32(v), nil
}

func (tap *vkLikeTap) close() {
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.ups {
		_ = c.Close()
	}
	for _, c := range tap.ghosts {
		_ = c.Close()
	}
}

// outOfReachStand: a pion relay with the VK relay's quota — ten seats per
// IDENTITY, a seat given back counted for `lag` more — behind the tap; ten
// PRODUCTION connections on identity A (slot 0), conn 0 started first, so that
// the tap's client #0 is conn 0's socket; and a RESERVE identity B on slot 1, as
// production's grower keeps (a connection that finds every seat counted parks
// rather than mint, once the identities on hand cover the connections).
type outOfReachStand struct {
	p            *Proxy
	tap          *vkLikeTap
	userA, userB string
	refused      atomic.Int32 // Allocates the relay refused, identity A

	mu     sync.Mutex
	live   map[string]int
	freed  map[string][]time.Time
	kills  map[int]context.CancelFunc
	starts map[int]int // sessions begun, per connection
	minted atomic.Int32
}

// srtpEchoPeer is srtpPeer with the two habits of the production server that a
// long stand needs: it SENDS something down a new session (there: WireGuard's
// answer) and it ECHOES a probe ping. A session that has heard nothing at all is
// replaced by its own read timeout after thirty seconds — the very moment its
// first ping goes out, and long before pion refreshes a permission — and one
// whose pings go unanswered by the periodic detector.
func srtpEchoPeer(t *testing.T) *net.UDPAddr {
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
				if _, err := c.Write([]byte{4, 0, 0, 0}); err != nil { // the session's first downlink datagram
					return
				}
				buf := make([]byte, 2048)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if isProbePacket(buf[:n]) {
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
				}
			}(c)
		}
	}()
	return srv.Addr().(*net.UDPAddr)
}

func newOutOfReachStand(t *testing.T) *outOfReachStand { return newOutOfReachStandFor(t, 0) }

// newOutOfReachStandFor: the relay grants `lifetime` to an allocation and to
// every refresh of it (0: pion's ten minutes) — a client refreshes at half of it.
func newOutOfReachStandFor(t *testing.T, lifetime time.Duration) *outOfReachStand {
	t.Helper()
	const lag = 300 * time.Millisecond
	s := &outOfReachStand{live: map[string]int{}, freed: map[string][]time.Time{}, kills: map[int]context.CancelFunc{}, starts: map[int]int{}}
	s.userA = fmt.Sprintf("%d:identity-a", time.Now().Add(8*time.Hour).Unix())
	s.userB = fmt.Sprintf("%d:identity-b", time.Now().Add(8*time.Hour).Unix())
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:              "okcdn.ru",
		AllocationLifetime: lifetime,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
		},
		QuotaHandler: func(username, _ string, _ net.Addr) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			held := s.live[username]
			for _, at := range s.freed[username] {
				if time.Since(at) < lag {
					held++
				}
			}
			if held < connsPerSlot {
				return true
			}
			if username == s.userA {
				s.refused.Add(1)
			}
			return false
		},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(_, _ net.Addr, _, userID, _ string, _ net.Addr, _ int) {
				s.mu.Lock()
				s.live[userID]++
				s.mu.Unlock()
			},
			OnAllocationDeleted: func(_, _ net.Addr, _, userID, _ string) {
				s.mu.Lock()
				s.live[userID]--
				s.freed[userID] = append(s.freed[userID], time.Now())
				s.mu.Unlock()
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() }) // the ghost's allocation is still alive: nothing to wait for
	s.tap = newVKLikeTap(t, pc.LocalAddr().String())
	peer := srtpEchoPeer(t)
	credsA := &TURNCreds{Username: s.userA, Password: "pw", Address: s.tap.addr(), Addresses: []string{s.tap.addr()}}
	p := NewProxy(Config{UseSrtp: true, UseUDP: true, NumConns: connsPerSlot, PeerAddr: peer.String(), SeededTURN: credsA})
	p.peer = peer
	p.credPool = newCredPool(p.ctx, poolSizeForNumConns(connsPerSlot), 0, "", func(_ bool, slot int) (string, *TURNCreds, error) {
		n := s.minted.Add(1)
		user := fmt.Sprintf("%d:identity-%d-slot-%d", time.Now().Add(8*time.Hour).Unix(), n, slot)
		return s.tap.addr(), &TURNCreds{Username: user, Password: "pw", Address: s.tap.addr(), Addresses: []string{s.tap.addr()}}, nil
	})
	p.credPool.setColdStartTarget(connsPerSlot)
	p.credPool.seedSlot(0, credsA.Address, credsA)
	p.credPool.seedSlot(1, credsA.Address, &TURNCreds{Username: s.userB, Password: "pw", Address: s.tap.addr(), Addresses: []string{s.tap.addr()}})
	p.sessionHook = func(ctx context.Context, connIdx int) error {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		s.mu.Lock()
		s.kills[connIdx] = cancel
		s.starts[connIdx]++
		s.mu.Unlock()
		signaled := true
		return p.runSRTPSession(sctx, "", nil, &signaled, connIdx)
	}
	s.p = p
	var wg sync.WaitGroup
	t.Cleanup(func() { p.cancel(); wg.Wait() })
	start := func(i int) {
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.runConnection(p.sessCtx, "", nil, i) }()
	}
	start(0)
	waitUntil(t, "conn 0 alone on the identity", 10*time.Second, func() bool { return p.activeConns.Load() == 1 && s.tap.clients() == 1 })
	for i := 1; i < connsPerSlot; i++ {
		start(i)
	}
	waitUntil(t, "ten sessions on identity A", 15*time.Second, func() bool {
		return s.liveOn(s.userA) == connsPerSlot && p.activeConns.Load() == int32(connsPerSlot)
	})
	if s.refused.Load() != 0 || s.minted.Load() != 0 {
		t.Fatalf("fixture: %d refusal(s), %d mint(s) while the ten came up on the seeded identity", s.refused.Load(), s.minted.Load())
	}
	return s
}

func (s *outOfReachStand) liveOn(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live[user]
}

func (s *outOfReachStand) begun(connIdx int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts[connIdx]
}

func (s *outOfReachStand) kill(connIdx int) {
	s.mu.Lock()
	cancel := s.kills[connIdx]
	s.mu.Unlock()
	cancel()
}

// THE DEFECT, as the field showed it on 430 (2026-09-21, three refusals in one
// burst): a session whose mapping has changed is ended; its deallocate is
// answered 437; build 430 read that as "the relay holds nothing", gave the lease
// back at once, and the re-dial was seated on the identity — where the relay
// still counts the allocation that lives on under the old mapping: 486, and with
// no give-back beside it the slot benched for eleven minutes. Now the seat stays
// COUNTED until that allocation can have expired: the re-dial goes to another
// identity, the relay refuses nothing — and the session SAYS what its mapping did.
func TestASeatWhoseDeallocateWasAnswered437StaysCounted(t *testing.T) {
	assumed := assumedAllocLifetime
	assumedAllocLifetime = time.Minute // so that the ten minutes below can only be the lifetime the relay was HEARD to grant
	t.Cleanup(func() { assumedAllocLifetime = assumed })
	say := captureLog(t)
	s := newOutOfReachStand(t)
	s.tap.remap(t, 0) // conn 0's socket reaches the relay from another mapping from now on
	s.kill(0)
	waitUntil(t, "the tap to answer conn 0's deallocate like the VK relay", 5*time.Second, func() bool { return s.tap.refusals.Load() >= 1 })
	waitUntil(t, "conn 0 to be back", 10*time.Second, func() bool { return s.p.activeConns.Load() == int32(connsPerSlot) })
	if n := s.liveOn(s.userA); n != connsPerSlot {
		t.Fatalf("fixture: the relay holds %d allocation(s) of identity A, want %d — nine sessions and the one that lives on under the old mapping", n, connsPerSlot)
	}
	if n := s.refused.Load(); n != 0 {
		t.Errorf("the relay REFUSED %d Allocate(s) on identity A — the re-dial was seated on a seat the relay still holds", n)
	}
	if slotSaturated(s.p.credPool, 0) {
		t.Error("slot 0 is benched as VK-saturated — a good identity lost for eleven minutes over an allocation of our own that is out of reach")
	}
	if refusals, _ := s.p.credPool.quotaSnapshot(); refusals != 0 {
		t.Errorf("the pool was told of %d quota refusal(s), want none", refusals)
	}
	if active, live, _ := leaseCounts(s.p.credPool, 0); active != connsPerSlot || live != connsPerSlot+1 {
		t.Errorf("slot 0: active %d, leases out in the pool %d, want %d and %d — the seat out of reach stays counted beside conn 0's new lease on identity B", active, live, connsPerSlot, connsPerSlot+1)
	}
	if n := s.liveOn(s.userB); n != 1 {
		t.Errorf("identity B carries %d allocation(s), want 1 — conn 0 is back, yet not on the reserve identity", n)
	}
	out := say()
	line := regexp.MustCompile(`\[conn 0\] the relay has NO allocation for this socket \([^)]*\) — the mapping CHANGED: port (\d+) at the Allocate, port (\d+) now, the same address`).FindStringSubmatch(out)
	if line == nil {
		t.Errorf("the session did not say that its mapping CHANGED:\n%s", grepLines(out, "NO allocation|mapping"))
	} else if line[1] == line[2] {
		t.Errorf("the two ports said are the same (%s)", line[1])
	}
	if n := strings.Count(out, "the relay has NO allocation for this socket"); n != 1 {
		t.Errorf("the mapping was said %d time(s), want once", n)
	}
	if !regexp.MustCompile(`credpool: slot 0 keeps a seat counted for (9m5\ds|10m[0-2]s) more — its deallocate was answered 437`).MatchString(out) {
		t.Errorf("the pool did not say that it keeps the seat for the allocation's ten minutes:\n%s", grepLines(out, "keeps a seat"))
	}
}

// THE REVIEW OF 432: the lifetime the relay was last HEARD to grant is not the
// upper bound of the allocation's life. A refresh can reach the relay and be
// GRANTED while its answer is lost — the mapping changes right behind the request
// — and the retransmitted copies are then refused (437) and pion says nothing of
// it. Build 432 let such a seat go the moment the last CONFIRMED lifetime had run
// out by the clock, although the relay held the allocation for the refresh's
// lifetime more: the re-dial was seated on it, refused with 486, and the identity
// benched for eleven minutes. The reviewer's stand, on the production session: a
// relay that grants eight seconds, the refresh at four granted and its answer
// lost, the session ended behind the confirmed eight and ahead of the relay's
// twelve.
func TestARefreshGrantedWithItsAnswerLostStillHoldsTheSeat(t *testing.T) {
	const lifetime = 8 * time.Second
	slack := lifeSlack
	lifeSlack = 200 * time.Millisecond // the stand's window is seconds wide
	t.Cleanup(func() { lifeSlack = slack })
	say := captureLog(t)
	s := newOutOfReachStandFor(t, lifetime)
	if n := s.tap.loseNextRefreshAnswer(t, 0); n != 0 {
		t.Fatalf("fixture: %d refresh(es) of conn 0 had passed before the tap was armed — the stand came up too slowly for a lifetime of %s", n, lifetime)
	}
	waitUntil(t, "conn 0's refresh to reach the relay, its answer lost", lifetime, func() bool { return s.tap.lostAt.Load() != 0 })
	lost := time.Unix(0, s.tap.lostAt.Load())
	// The lifetime conn 0 last HEARD of is the Allocate's: it runs out half a
	// lifetime behind the refresh; the relay's runs a whole one from it.
	time.Sleep(time.Until(lost.Add(lifetime/2 + lifeSlack + 500*time.Millisecond)))
	if n := s.tap.lostAnswers.Load(); n < 1 {
		t.Fatalf("fixture: the tap dropped %d answer(s) — the refresh's answer reached conn 0, and its confirmed lifetime has not run out", n)
	}
	if n := s.liveOn(s.userA); n != connsPerSlot {
		t.Fatalf("fixture: the relay holds %d allocation(s) of identity A before the session is ended, want %d", n, connsPerSlot)
	}
	refusedBefore := s.tap.refusals.Load() // the retransmitted copies of the refresh, and the refresh after it
	if left := time.Until(lost.Add(lifetime)); left < 1500*time.Millisecond {
		t.Fatalf("fixture: the session is ended only %s ahead of the relay's own expiry — too late to tell a held seat from an expired one", left.Round(time.Millisecond))
	}
	s.kill(0) // its lease is settled, and its re-dial seated, within milliseconds of this
	waitUntil(t, "the tap to answer conn 0's deallocate like the VK relay", 5*time.Second, func() bool { return s.tap.refusals.Load() > refusedBefore })
	waitUntil(t, "conn 0 to be back", 10*time.Second, func() bool {
		return s.p.activeConns.Load() == int32(connsPerSlot) && s.begun(0) >= 2 && (s.liveOn(s.userB) == 1 || s.refused.Load() > 0)
	})
	if n := s.refused.Load(); n != 0 {
		t.Errorf("the relay REFUSED %d Allocate(s) on identity A — the seat was let go by the last CONFIRMED lifetime, and the refresh whose answer was lost had been granted", n)
	}
	if slotSaturated(s.p.credPool, 0) {
		t.Error("slot 0 is benched as VK-saturated — a good identity lost for eleven minutes over an allocation of our own")
	}
	if active, _, _ := leaseCounts(s.p.credPool, 0); active != connsPerSlot {
		t.Errorf("slot 0: active %d, want %d — the seat out of reach stays counted while a refresh that may have been granted keeps its allocation alive", active, connsPerSlot)
	}
	if n := s.liveOn(s.userB); n != 1 {
		t.Errorf("identity B carries %d allocation(s), want 1 — conn 0 is not back on the reserve identity", n)
	}
	if out := say(); !strings.Contains(out, "credpool: slot 0 keeps a seat counted for ") {
		t.Errorf("the pool did not say that it keeps the seat:\n%s", grepLines(out, "keeps a seat|NO allocation"))
	}
}

func grepLines(out, rx string) string {
	re := regexp.MustCompile(rx)
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if re.MatchString(l) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// …and the EARLIEST sign, through the real thing: pion's own permission refresh
// (every two minutes — which is why this one runs only when asked to:
// VKTP_SLOW=1, as tools/test.sh and the sabotage runner do), answered 400 by the
// relay-like tap, heard by the production logger — and the session is ended
// THERE. The peer answers pings, so that the session LIVES to that refresh (one
// that hears nothing is replaced by its own read timeout after thirty seconds);
// and the mapping changes only after conn 0 has heard two pongs, so that the
// periodic detector — two minutes without a pong — could not act before the
// test's wait is over: what replaces conn 0 in time is the refresh's answer, or
// nothing.
func TestAPermissionRefreshAnswered400EndsTheSessionAtOnce(t *testing.T) {
	if os.Getenv("VKTP_SLOW") == "" {
		t.Skip("pion refreshes a permission every 120 s: set VKTP_SLOW=1 (tools/test.sh and the sabotage runner do)")
	}
	say := captureLog(t)
	s := newOutOfReachStand(t)
	for deadline := time.Now().Add(75 * time.Second); s.p.lastPongSeq[0].Load() < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("fixture: conn 0 has not heard its second pong within 75 s (pong mark %d, in its session #%d) — a session that hears nothing of its peer is replaced by its read timeout, one whose pings go unanswered has no pong: either way it does not live to pion's refresh:\n%s",
				s.p.lastPongSeq[0].Load(), s.begun(0), grepLines(say(), "conn 0\\]|conn 0 on"))
		}
	}
	if n := s.begun(0); n != 1 {
		t.Fatalf("fixture: conn 0 is in its session #%d before the re-mapping — a session that does not live to pion's refresh shows nothing:\n%s", n, grepLines(say(), "conn 0\\]"))
	}
	s.tap.remap(t, 0)
	t0 := time.Now()
	waitUntil(t, "pion's permission refresh to be answered 400, and conn 0 to be replaced", 75*time.Second, func() bool {
		return s.tap.refusals.Load() >= 1 && s.liveOn(s.userB) == 1 && s.p.activeConns.Load() == int32(connsPerSlot)
	})
	back := time.Since(time.Unix(0, s.tap.firstAt.Load()))
	out := say()
	if !strings.Contains(out, "[conn 0] the session is dead at the relay (its permission refresh was answered 400)") {
		t.Errorf("conn 0 was replaced %s after the re-mapping, but not BY the refresh's answer:\n%s", time.Since(t0).Round(time.Second), grepLines(out, "conn 0\\]"))
	}
	if back > 5*time.Second {
		t.Errorf("conn 0 was back %s after the relay's first refusal — want at once, not when a detector has listened its time out", back.Round(time.Millisecond))
	}
	if !regexp.MustCompile(`\[conn 0\] the relay has NO allocation for this socket \(its permission refresh was answered 400\) — the mapping CHANGED`).MatchString(out) {
		t.Errorf("the mapping was not said at the refresh's answer:\n%s", grepLines(out, "NO allocation"))
	}
	if other := grepLines(out, "SRTP zombie detected|SRTP read timeout|no echo within"); other != "" {
		t.Errorf("another detector acted — the stand cannot say which of them ended conn 0:\n%s", other)
	}
	if n := s.begun(0); n != 2 {
		t.Errorf("conn 0 began %d session(s), want 2 — the one that died at the relay and the one that replaced it", n)
	}
	if n := s.refused.Load(); n != 0 || slotSaturated(s.p.credPool, 0) {
		t.Errorf("the relay refused %d Allocate(s) on identity A, slot 0 benched: %v — want none, not benched", n, slotSaturated(s.p.credPool, 0))
	}
	if active, _, _ := leaseCounts(s.p.credPool, 0); active != connsPerSlot {
		t.Errorf("slot 0: active %d, want %d — the seat out of reach stays counted", active, connsPerSlot)
	}
}

// A test that waits for a library's own timer skips itself unless VKTP_SLOW is
// set — and a test that only a human ever switches on is one the gate cannot
// see: tools/test.sh switches it on, ahead of its first suite.
func TestTheGateRunsTheSlowTests(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "tools", "test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	set, firstSuite := -1, -1
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if m := regexp.MustCompile(`^export VKTP_SLOW=(\S+)$`).FindStringSubmatch(l); m != nil && set < 0 {
			set = i
		}
		if strings.HasPrefix(l, "run ") && firstSuite < 0 {
			firstSuite = i
		}
	}
	if firstSuite < 0 {
		t.Fatal("tools/test.sh runs no suite that this scan can find")
	}
	if set < 0 || set > firstSuite {
		t.Errorf("tools/test.sh does not export a non-empty VKTP_SLOW ahead of its first suite (export at line %d, first suite at line %d) — the slow tests would run for nobody", set+1, firstSuite+1)
	}
}

var _ = errors.New
