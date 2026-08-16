package proxy

import (
	"context"
	"os"
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

	if got := p.paceReserve(20); got != 0 {
		t.Fatalf("with the pacer off nothing may be reserved, got %v", got)
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
	p.paceReserve(20)
	first := paceBuckets[20].Load()
	if first == nil || first.rate != 200*1024 {
		t.Fatalf("the first bucket should carry the first rate, got %+v", first)
	}

	SetUplinkPace(100, 16, true)
	p.paceReserve(20)
	second := paceBuckets[20].Load()
	if second == nil || second.rate != 100*1024 {
		t.Fatalf("a live rate change must rebuild the bucket; still %.0f B/s", second.rate)
	}
}

// 🚨 THE ENGAGEMENT WITNESS, and the reason it exists: at the arm's own numbers
// the bucket is expected to act only on BURSTS, so `waited=0` is the difference
// between "pacing does nothing" and "this arm tested nothing". A knob believed
// on the strength of its configured value cost this project nine runs.
//
// SABOTAGE SEEN TO FAIL: drop the `if w == 0` note from paceSummary and leave
// `_ = w`. Compiles; a completely inert arm then prints as a normal one.
func TestPaceSummaryShoutsWhenItNeverEngaged(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	// A rate far above anything the test sends: the bucket can never empty.
	SetUplinkPace(100000, 1024, true)
	for i := 0; i < 5; i++ {
		r := p.paceReserve(20)
		p.paceSettle(20, r, 1312)
	}
	s := paceSummary()
	if !strings.Contains(s, "waited=0") || !strings.Contains(s, "NEVER WAITED") {
		t.Fatalf("an arm whose bucket never emptied must say so loudly, got %q", s)
	}
	if !strings.Contains(s, "paced=5") {
		t.Fatalf("the paced count is the other half of the witness: %q", s)
	}
}

// And the mirror: when the bucket DOES empty, the line reports the waits rather
// than staying silent about them.
//
// SABOTAGE SEEN TO FAIL: stop counting paceWaited (drop its Add(1)). Compiles;
// a genuinely throttled arm then reports waited=0 and reads as inert.
func TestPaceSummaryReportsRealWaits(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := paceTestProxy()
	defer cancel()

	// 1 KiB/s with a 1 KiB burst: the second full-size packet must wait.
	SetUplinkPace(1, 1, true)
	for i := 0; i < 3; i++ {
		r := p.paceReserve(20)
		p.paceSettle(20, r, 1312)
	}
	s := paceSummary()
	if strings.Contains(s, "waited=0") || strings.Contains(s, "NEVER WAITED") {
		t.Fatalf("a bucket this small must have made a writer wait, got %q", s)
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
	res := strings.Index(s, "reserved := p.paceReserve(connIdx)")
	if res < 0 {
		t.Fatal("the SRTP writer no longer reserves at all — the pacer is unwired")
	}
	deq := strings.Index(s[res:], "p.nextSendItem(connCtx.Done(), connIdx)")
	if deq < 0 {
		t.Fatal("no dequeue follows the reservation")
	}
	// And the settle must follow the dequeue, or the true size is never charged.
	if !strings.Contains(s[res:res+deq+400], "p.paceSettle(connIdx, reserved, len(item.buf))") {
		t.Fatal("the reservation is never settled with the real packet size — " +
			"the bucket would throttle to the maximum size rather than the traffic")
	}
}

func paceTestProxy() (*Proxy, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8), synthCh: make(chan sendItem, 8)}, cancel
}
