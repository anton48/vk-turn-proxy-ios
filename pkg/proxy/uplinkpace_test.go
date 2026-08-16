package proxy

import (
	"bytes"
	"context"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Each of these was SEEN to fail under a sabotage that still COMPILES; the
// sabotage is named above the test.

func resetPace() {
	SetUplinkPace(PaceOff, 0, false)
	paceSummary()
	for i := range paceBuckets {
		paceBuckets[i].Store(nil)
	}
}

// 🚫 OFF IS BYTE-FOR-BYTE THE PRODUCTION BEHAVIOUR. The lever must not change
// anything by existing: no reservation, no bucket, no line in the log.
//
// SABOTAGE SEEN TO FAIL: drop the `!st.on()` half of pacesWriter's guard so an
// off pacer still reserves. Compiles; this test then sees a non-zero reserve.
func TestPaceOffReservesNothingAndSaysNothing(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p, cancel := paceTestProxy()
	defer cancel()

	if got := p.paceReserve(20); got.reserved != 0 || got.st != nil {
		t.Fatalf("with the pacer off nothing may be reserved, got %+v", got)
	}
	if s := paceSummary(); s != "" {
		t.Fatalf("the field must be absent when off, got %q", s)
	}
}

// 🚨 THE SELECTOR IS THE ARM'S CONTROL. With groupBOnly the synthetic's own
// writers must NEVER be paced — group A is the untouched in-run control for
// cross-talk, and pacing it would both spoil that control and change the
// synthetic's own level, which is the one thing the split arms hold fixed.
//
// SABOTAGE SEEN TO FAIL: make pacesWriter return true whenever the split is on,
// dropping the splitOwnsSynth test. Compiles; writer 3 is then paced.
func TestGroupBOnlyNeverPacesTheSyntheticsWriters(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB, true)

	st := paceNow()
	for _, idx := range []int{0, 7, 14} {
		if pacesWriter(st, idx) {
			t.Fatalf("writer %d serves the synthetic and must never be paced", idx)
		}
	}
	for _, idx := range []int{15, 22, 29} {
		if !pacesWriter(st, idx) {
			t.Fatalf("writer %d serves group B and must be paced", idx)
		}
	}
}

// 🚨 AND WITH THE SPLIT OFF, groupBOnly PACES NOTHING. "Group B" is only defined
// when the pool is split; the alternative reading — pace everything — would
// silently apply the treatment to the synthetic as well.
//
// SABOTAGE SEEN TO FAIL: return true instead of false when the split is off.
// Compiles; every writer is then paced by an arm that asked for group B.
func TestGroupBOnlyPacesNothingWhenTheSplitIsOff(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB, true)

	st := paceNow()
	for _, idx := range []int{0, 15, 29} {
		if pacesWriter(st, idx) {
			t.Fatalf("with the split off there is no group B; writer %d must not be paced", idx)
		}
	}
}

// 🎯 THE BUCKET'S ARITHMETIC, and the property that makes the long-run rate
// EXACT rather than merely bounded: tokens go NEGATIVE, so a packet that
// overdraws delays the next one by precisely its excess.
//
// SABOTAGE SEEN TO FAIL: clamp tokens at 0 instead of letting them go negative
// (`if b.tokens < 0 { b.tokens = 0 }`). Compiles; the debt is then forgiven and
// the second take reports no wait.
func TestTokensGoNegativeSoTheRateIsExact(t *testing.T) {
	b := &paceBucket{rate: 1000, burst: 1000, tokens: 1000, last: time.Now()}
	if w := b.take(1000); w != 0 {
		t.Fatalf("a full bucket must not make the first packet wait, got %v", w)
	}
	// The bucket is now empty; the next reservation must be charged in full.
	w := b.take(500)
	if w < 400*time.Millisecond || w > 600*time.Millisecond {
		t.Fatalf("500 counted bytes at 1000 B/s ≈ 500 ms of debt, got %v", w)
	}
}

// The refund is what keeps the reservation honest: reserving a maximum-size
// packet and charging a small one would otherwise throttle to the reservation
// rather than to the traffic.
//
// SABOTAGE SEEN TO FAIL: make refund a no-op body (`_ = cost`). Compiles; the
// bucket then never recovers the unused reservation and this test's second
// take waits.
func TestRefundReturnsTheUnusedReservation(t *testing.T) {
	b := &paceBucket{rate: 1000, burst: 2000, tokens: 2000, last: time.Now()}
	b.take(paceMaxCost)        // reserve big
	b.refund(paceMaxCost - 40) // ...but only 40 counted bytes were really sent
	b.mu.Lock()
	tok := b.tokens
	b.mu.Unlock()
	if tok < 2000-41 {
		t.Fatalf("after refunding all but 40 bytes the bucket should be nearly full, got %.0f of 2000", tok)
	}
}

// 🚨 A RATE CHANGE MUST REACH THE BUCKETS THAT ALREADY EXIST. Without the
// generation check a live arm would apply only to connections opened after it —
// i.e. to none, since the pool is up before the run starts, and the arm would
// silently be a control.
//
// SABOTAGE SEEN TO FAIL: build the bucket with `gen: 0` instead of `st.gen`.
// Compiles; the old bucket then satisfies the freshness test forever.
func TestARateChangeRebuildsTheBuckets(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	SetUplinkPace(200, 16, true)
	_ = p.paceReserve(20)
	first := paceBuckets[20].Load()
	if first == nil || first.rate != 200*1024 {
		t.Fatalf("the first bucket should carry the first rate, got %+v", first)
	}

	SetUplinkPace(100, 16, true)
	_ = p.paceReserve(20)
	second := paceBuckets[20].Load()
	if second == nil || second.rate != 100*1024 {
		t.Fatalf("a live rate change must rebuild the bucket; still %.0f B/s", second.rate)
	}
}

// 🚨 THE ARM'S VERDICT IS NOT THE TICK'S, AND CONFLATING THEM WAS THE DEFECT.
// `paceSummary` clears its counters on every memstats tick, so a zero there is a
// QUIET TEN SECONDS — one tick can read zero while the pacer worked in the
// others, and the tail after a switch is cleared silently because the state is
// already off. The arm-level verdict has its own accumulators and is printed
// ONCE, by the setter, at the moment the generation ends.
// *(User-caught, 2026-08-16, before the run.)*
//
// SABOTAGE SEEN TO FAIL: in SetUplinkPace, drop the `if wt == 0` branch and
// always print "ENGAGED". Compiles; a completely inert arm then certifies
// itself.
func TestTheArmVerdictShoutsWhenTheBucketNeverEmptied(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// A rate far above anything this sends: the bucket can never empty.
	SetUplinkPace(100000, 1024, true)
	for i := 0; i < 5; i++ {
		tk := p.paceReserve(20)
		p.paceSettle(tk, 1312)
	}
	// The TICK line must not pretend to be a verdict.
	if tick := paceSummary(); strings.Contains(tick, "TESTED NOTHING") {
		t.Fatalf("the per-tick line covers ten seconds and must not judge the arm: %q", tick)
	}
	SetUplinkPace(PaceOff, 0, true) // ends the generation → prints its verdict

	out := buf.String()
	if !strings.Contains(out, "PACE-ARMEND") {
		t.Fatalf("turning the pacer off must print the arm's own verdict, got %q", out)
	}
	if !strings.Contains(out, "NEVER WAITED") || !strings.Contains(out, "waited=0") {
		t.Fatalf("an arm whose bucket never emptied must say so on PACE-ARMEND: %q", out)
	}
	if !strings.Contains(out, "paced=5") {
		t.Fatalf("the arm's verdict must carry its own totals, not the last tick's: %q", out)
	}
}

// The mirror: a bucket that DOES empty certifies the arm as engaged, and the
// dose is reported as MEASURED writer-time beside what the bucket asked for.
//
// SABOTAGE SEEN TO FAIL: report `planned` in the `total=` field (pass plan
// twice). Compiles; a wait cut short by a live toggle is then overstated as
// writer-time, which is the quantity a dose is divided from.
func TestTheArmVerdictReportsMeasuredWaitAndEngagement(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// 1 KiB/s with a 1 KiB burst: the second full-size packet must wait.
	SetUplinkPace(1, 1, true)
	for i := 0; i < 3; i++ {
		tk := p.paceReserve(20)
		p.paceSettle(tk, 1312)
	}
	SetUplinkPace(PaceOff, 0, true)

	out := buf.String()
	if !strings.Contains(out, "ENGAGED") || strings.Contains(out, "NEVER WAITED") {
		t.Fatalf("a bucket this small must certify the arm as engaged: %q", out)
	}
	// 🚨 AND `total` MUST BE THE MEASURED TIME, NOT A COPY OF `planned`. Checking
	// only that both FIELDS exist is a test that cannot fail — it was, and the
	// sabotage that reports `planned` in both slots ran straight through it. A
	// real sleep always overshoots its request, so measured > planned strictly;
	// when the two are the same value they are the same variable.
	mt := regexp.MustCompile(`total=(\S+) planned=(\S+)`).FindStringSubmatch(out)
	if mt == nil {
		t.Fatalf("the arm's verdict must carry both total= and planned=: %q", out)
	}
	total, err1 := time.ParseDuration(mt[1])
	plan, err2 := time.ParseDuration(mt[2])
	if err1 != nil || err2 != nil {
		t.Fatalf("unparseable durations %q / %q", mt[1], mt[2])
	}
	if total <= plan {
		t.Fatalf("total (%v) must EXCEED planned (%v) — a real sleep overshoots its "+
			"request, and equality means `total` is just a copy of the bucket's ask "+
			"rather than measured writer-time", total, plan)
	}
}

// 🚨🚨 THE GENERATION BOUNDARY, AND IT IS A REAL RACE THE FIRST VERSION HAD. A
// writer counts its `waited` BEFORE it sleeps and files its time AFTER. With the
// counters in globals and the setter reading them before publishing the new
// state, a writer asleep across the switch produced `waited=1 total=0s` — and
// the time it filed a moment later was then wiped in the next off-gap. The
// verdict would have understated the dose, silently, in exactly the arms where
// the pacer worked hardest.
//
// ⇒ The counters belong to the STATE, the setter publishes FIRST and then drains
// on `inflight`. This test builds the interleave directly: a writer parked in a
// long wait, the pacer turned off underneath it.
//
// SABOTAGE SEEN TO FAIL: in SetUplinkPace, move `paceCur.Store(next)` back below
// the verdict block (publish last). Compiles; the sleeping writer then still
// reads the OLD state as current, never leaves its wait before the drain's
// deadline, and the verdict comes out `NOT FULLY DRAINED` with total=0s.
func TestAWaitStraddlingTheSwitchIsNotLostFromTheVerdict(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// 1 KiB/s with a 1 KiB burst: the first reservation drains the bucket and the
	// second must sleep for seconds — long enough to be interrupted on purpose.
	SetUplinkPace(1, 1, true)
	tk := p.paceReserve(20)
	p.paceSettle(tk, 1312)

	parked := make(chan struct{})
	go func() {
		close(parked)
		tk2 := p.paceReserve(20) // sleeps
		p.paceSettle(tk2, 1312)
	}()
	<-parked
	time.Sleep(150 * time.Millisecond) // it is now inside the wait

	SetUplinkPace(PaceOff, 0, true) // the switch lands mid-sleep

	out := buf.String()
	if !strings.Contains(out, "PACE-ARMEND") {
		t.Fatalf("no verdict was printed: %q", out)
	}
	if strings.Contains(out, "NOT FULLY DRAINED") {
		t.Fatalf("the setter gave up waiting for a writer it should have drained in one "+
			"slice: %q", out)
	}
	m := regexp.MustCompile(`waited=(\d+)\(.*?total=(\S+) `).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not read waited/total from %q", out)
	}
	if m[1] == "0" {
		t.Fatalf("the interrupted wait was counted as waited, so it must appear: %q", out)
	}
	total, err := time.ParseDuration(m[2])
	if err != nil {
		t.Fatalf("unparseable total %q", m[2])
	}
	// 🚨 THE POINT: a counted wait with zero time is the defect. The writer was
	// asleep for at least the 150 ms above before the switch.
	if total < 100*time.Millisecond {
		t.Fatalf("waited=%s but total=%v — the time filed after the switch was lost, "+
			"which is exactly the race this ordering exists to close: %q", m[1], total, out)
	}
}

// 🚨 THE RESERVATION HAPPENS BEFORE THE DEQUEUE — the whole correctness
// argument, and it is a property of the CALL SITE, not of this file. A writer
// that dequeues first and then waits holds a packet where work-stealing cannot
// see it: the run-20 pathology.
//
// SABOTAGE SEEN TO FAIL: move `reserved := p.paceReserve(connIdx)` below the
// `nextSendItem` call in proxy.go. Compiles; this scan then finds them in the
// wrong order.
func TestReservationPrecedesTheDequeue(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("reading proxy.go: %v", err)
	}
	s := string(src)
	// ⚠️ The scan follows the CALL, not a particular variable name: this guard
	// went red on correct code once already, when `reserved` became `ticket`
	// because the reservation started carrying its generation. Anchoring on the
	// call keeps it tight without being brittle about naming.
	res := strings.Index(s, "p.paceReserve(connIdx)")
	if res < 0 {
		t.Fatal("the SRTP writer no longer reserves at all — the pacer is unwired")
	}
	deq := strings.Index(s[res:], "p.nextSendItem(connCtx.Done(), connIdx)")
	if deq < 0 {
		t.Fatal("no dequeue follows the reservation")
	}
	// And the settle must follow the dequeue, or the true size is never charged.
	if !strings.Contains(s[res:res+deq+400], "p.paceSettle(ticket, len(item.buf))") {
		t.Fatal("the reservation is never settled with the real packet size — " +
			"the bucket would throttle to the maximum size rather than the traffic")
	}
}

func paceTestProxy() (*Proxy, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8), synthCh: make(chan sendItem, 8)}, cancel
}
