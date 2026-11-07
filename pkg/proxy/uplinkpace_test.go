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
	SetUplinkPace(PaceOff, 0)
	paceSummary()
	for i := range paceBuckets {
		paceBuckets[i].Store(nil)
		paceRelay[i].Store(nil) // the relays' paces too (2026-11-07) — a test's hand-outs must not pace the next test's writers
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

// 🚫 PRODUCTION HAS NO CONTROL GROUP: every writer is paced, or none is. On the
// diagnostic branch a `groupBOnly` selector kept the synthetic's own writers
// unpaced as an in-run control; shipping that flag would have meant shipping a
// value whose only correct setting is `false`.
//
// SABOTAGE SEEN TO FAIL: make pacesWriter return `connIdx >= 15` (a leftover of
// the split's group-B rule). Compiles; writer 3 is then silently unpaced.
func TestEveryWriterIsPaced(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p, cancel := paceTestProxy()
	defer cancel()

	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB)
	for _, idx := range []int{0, 3, 15, 29, 59} {
		tk := p.paceReserve(idx)
		if tk.reserved == 0 || tk.st == nil {
			t.Fatalf("writer %d was not paced; in production there is no unpaced group, "+
				"and an unwired writer looks exactly like a bucket that never had to wait", idx)
		}
		p.paceSettle(tk, 1312)
	}
}

// A connection index beyond the bucket table goes UNPACED rather than sharing
// another allocation's bucket — two allocations metered from one bucket would
// meter neither. The pool ceiling is 60 against a table of 64, so this is a
// guard, not a live path.
//
// SABOTAGE SEEN TO FAIL: drop the upper bound from pacesWriter. Compiles, then
// panics on the array index, which is the loud version of the same bug.
func TestAWriterBeyondTheTableIsNotPaced(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p, cancel := paceTestProxy()
	defer cancel()

	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB)
	if tk := p.paceReserve(paceMaxConns); tk.reserved != 0 || tk.st != nil {
		t.Fatalf("connIdx %d is outside the bucket table and must not be paced, got %+v",
			paceMaxConns, tk)
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
	p, cancel := paceTestProxy()
	defer cancel()

	SetUplinkPace(200, 16)
	_ = p.paceReserve(20)
	first := paceBuckets[20].Load()
	if first == nil || first.rate != 200*1024 {
		t.Fatalf("the first bucket should carry the first rate, got %+v", first)
	}

	SetUplinkPace(100, 16)
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
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// A rate far above anything this sends: the bucket can never empty.
	SetUplinkPace(100000, 1024)
	for i := 0; i < 5; i++ {
		tk := p.paceReserve(20)
		p.paceSettle(tk, 1312)
	}
	// The TICK line must not pretend to be a verdict.
	if tick := paceSummary(); strings.Contains(tick, "never had to hold anything back") {
		t.Fatalf("the per-tick line covers ten seconds and must not judge the arm: %q", tick)
	}
	SetUplinkPace(PaceOff, 0) // ends the generation → prints its verdict

	out := buf.String()
	if !strings.Contains(out, "uplink-pace END") {
		t.Fatalf("turning the pacer off must print the arm's own verdict, got %q", out)
	}
	if !strings.Contains(out, "never had to hold anything back") || !strings.Contains(out, "waited=0") {
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
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// 1 KiB/s with a 1 KiB burst: the second full-size packet must wait.
	SetUplinkPace(1, 1)
	for i := 0; i < 3; i++ {
		tk := p.paceReserve(20)
		p.paceSettle(tk, 1312)
	}
	SetUplinkPace(PaceOff, 0)

	out := buf.String()
	if !strings.Contains(out, "ENGAGED") || strings.Contains(out, "never had to hold anything back") {
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
	p, cancel := paceTestProxy()
	defer cancel()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// 1 KiB/s with a 1 KiB burst: the first reservation drains the bucket and the
	// second must sleep for seconds — long enough to be interrupted on purpose.
	SetUplinkPace(1, 1)
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

	SetUplinkPace(PaceOff, 0) // the switch lands mid-sleep

	out := buf.String()
	if !strings.Contains(out, "uplink-pace END") {
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
// SABOTAGE SEEN TO FAIL: move `ticket := p.paceReserve(connIdx)` inside the
// `case item := <-p.sendCh:` branch in proxy.go, which is where it reads most
// naturally. Compiles, runs, paces at the right rate — and strands packets.
// This scan then finds the reservation below its dequeue.
func TestReservationPrecedesTheDequeue(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("reading proxy.go: %v", err)
	}
	s := string(src)
	// 🚨 EVERY WRITER LOOP, NOT JUST THE ONE. The first version anchored on the
	// FIRST `p.paceReserve(connIdx)` it found, so it passed while three of the
	// four writers were unwired — and a mode whose writer has no bucket looks
	// exactly like a bucket that never had to wait (`waited=0` renders as "NEVER
	// WAITED"), which is the failure this project has paid for twice.
	// The dequeue is the anchor because there is exactly one per writer loop.
	const deqCall = "case item := <-p.sendCh:"
	deqs := strings.Count(s, deqCall)
	if deqs != 4 {
		t.Fatalf("expected 4 sendCh writer loops in proxy.go, found %d — if a writer "+
			"was added or removed, this guard must be re-derived, not relaxed", deqs)
	}
	if got := strings.Count(s, "p.paceReserve(connIdx)"); got != deqs {
		t.Fatalf("%d writer loops but %d reservations — a writer dequeues without a "+
			"bucket, and its mode would run unpaced with nothing in the log saying so",
			deqs, got)
	}
	// ...and in each loop the reserve precedes the dequeue and the settle follows it.
	for i, off := 0, 0; i < deqs; i++ {
		d := strings.Index(s[off:], deqCall)
		abs := off + d
		// the reservation must be the nearest one BEFORE this dequeue
		res := strings.LastIndex(s[:abs], "p.paceReserve(connIdx)")
		if res < 0 || abs-res > 900 {
			t.Fatalf("writer %d dequeues at byte %d with no reservation above it — "+
				"a writer that takes a packet and then finds no budget holds it where "+
				"work-stealing cannot see it (the run-20 pathology)", i+1, abs)
		}
		if !strings.Contains(s[abs:min(abs+700, len(s))], "p.paceSettle(ticket, len(item.buf))") {
			t.Fatalf("writer %d never settles with the real packet size — the bucket "+
				"would throttle to the maximum size rather than to the traffic", i+1)
		}
		off = abs + len(deqCall)
	}
}

// A fresh session must get a fresh bucket: `paceBuckets` is package-scope and keyed
// by connIdx, so without this a reconnecting connection inherits the token debt of
// the allocation that just died.
//
// SABOTAGE SEEN TO FAIL: delete the PaceResetConn call from the dispatch site.
func TestEverySessionAttemptResetsItsBucket(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("reading proxy.go: %v", err)
	}
	s := string(src)
	call := strings.Index(s, "PaceResetConn(connIdx)")
	if call < 0 {
		t.Fatal("no PaceResetConn call — a reconnecting connection would inherit the " +
			"dead allocation's token debt and lose its opening burst")
	}
	// It must sit ABOVE the mode switch, so it covers all four transports rather
	// than whichever one someone remembered.
	sw := strings.Index(s, "case p.config.UseWrapA:")
	if sw < 0 || call > sw || sw-call > 700 {
		t.Fatal("PaceResetConn is not immediately above the session-mode switch, so it " +
			"does not cover every transport mode")
	}
}

func TestPaceResetConnGivesBackTheBurst(t *testing.T) {
	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB)
	defer SetUplinkPace(PaceOff, 0)
	p, cancel := paceTestProxy()
	defer cancel()
	// Drain the bucket: enough reservations to exhaust a 16 KiB burst.
	for i := 0; i < 40; i++ {
		tk := p.paceReserve(7)
		p.paceSettle(tk, 1200)
	}
	drained := paceBuckets[7].Load()
	if drained == nil {
		t.Fatal("no bucket after draining it — the reservation never built one")
	}
	PaceResetConn(7)
	if paceBuckets[7].Load() != nil {
		t.Fatal("PaceResetConn did not discard the bucket, so the new allocation " +
			"would start with the dead one's debt")
	}
}

func paceTestProxy() (*Proxy, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8)}, cancel
}

// 2026-11-07, the user's design: the pace is the RELAY's, not the direction's
// — the override entry's fourth field (host:port:quota:pace, KiB/s; 0 = no
// pacer) replaces the app's toggle for the connections on that relay. The
// uplink bucket of a connection takes the rate of the relay it was handed at
// resolveTURNAddr; the toggle stays the default for relays without the field
// (VK's: the policer is theirs). Nov 4 §562 measured why: with the toggle on,
// the own relay's upload was 72 against 224 without — the pacer is its cost
// alone, while a mixed list (`O:0:0,$vkurls`) seats connections on both.
//
// SABOTAGE SEEN TO FAIL: paceFor ignores the relay's rate and returns the
// toggle's. Compiles; conn 4 then reserves nothing with the toggle off.
func TestARelaysPaceFieldPacesItsConnectionsAlone(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p, cancel := paceTestProxy()
	defer cancel()

	// The toggle OFF; the relay of conn 4 paced at 300: conn 4 reserves at
	// 300 KiB/s, conn 5 (a relay without the field) does not.
	setConnRelayPace(4, 300, true)
	tk := p.paceReserve(4)
	if tk.reserved == 0 || tk.st == nil {
		t.Fatal("a connection on a relay with a pace field was not paced while the toggle is off")
	}
	p.paceSettle(tk, 1312)
	if b := paceBuckets[4].Load(); b == nil || b.rate != 300*1024 {
		t.Fatalf("conn 4's bucket runs at %v, want the relay's 300 KiB/s", b)
	}
	if got := p.paceReserve(5); got.reserved != 0 {
		t.Fatalf("a connection on a relay without the field was paced with the toggle off: %+v", got)
	}

	// The toggle ON; the relay of conn 6 without a pacer (0): conn 6 is not
	// paced, conn 7 is, at the toggle's rate.
	SetUplinkPace(PaceDefaultKiB, PaceDefaultBurstKiB)
	setConnRelayPace(6, 0, true)
	if got := p.paceReserve(6); got.reserved != 0 {
		t.Fatalf("a connection on a relay with pace 0 was paced under the toggle: %+v", got)
	}
	tk = p.paceReserve(7)
	if tk.reserved == 0 {
		t.Fatal("a connection on a relay without the field was not paced under the toggle")
	}
	p.paceSettle(tk, 1312)
	if b := paceBuckets[7].Load(); b == nil || b.rate != PaceDefaultKiB*1024 {
		t.Fatalf("conn 7's bucket runs at %v, want the toggle's rate", b)
	}
	// Conn 4 under the toggle keeps the relay's rate, not the toggle's.
	tk = p.paceReserve(4)
	p.paceSettle(tk, 1312)
	if b := paceBuckets[4].Load(); b == nil || b.rate != 300*1024 {
		t.Fatalf("conn 4's bucket under the toggle runs at %v, want the relay's 300 KiB/s still", b)
	}
	// The bucket follows the rate it was built for, generation or no
	// generation: a hand-out that records another rate on the same index
	// (a session on another relay) rebuilds it.
	setConnRelayPace(4, 600, true)
	tk = p.paceReserve(4)
	p.paceSettle(tk, 1312)
	if b := paceBuckets[4].Load(); b == nil || b.rate != 600*1024 {
		t.Fatalf("conn 4's bucket after a hand-out at 600 runs at %v, want 600 KiB/s", b)
	}
	// A new session asks its relay again: the reset clears the rate with the bucket.
	PaceResetConn(4)
	if _, ok := connRelayPace(4); ok {
		t.Fatal("PaceResetConn left the previous session's relay pace standing")
	}
	if got := p.paceReserve(4); got.reserved == 0 {
		t.Fatal("after the reset, with the toggle on and no relay pace, conn 4 is not paced")
	}
}

// The hand-out is the ONE place a connection learns its relay (every
// transport's session function calls resolveTURNAddr), so it is where the
// relay's pace reaches the bucket. A relay without the field leaves the
// toggle in charge; the probe (connIdx -1) records nothing.
//
// SABOTAGE SEEN TO FAIL: resolveTURNAddr does not ask the pool for the
// relay's pace. Compiles; conn 3's pace is then unset after its hand-out.
func TestTheHandOutRecordsTheRelaysPace(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	list, err := ParseTURNServers(relayO + ":0:500," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	p := &Proxy{credPool: cp}
	addr, _, _, err := p.resolveTURNAddr(3, false)
	if err != nil || addr != relayO {
		t.Fatalf("the hand-out: %q %v, want %s", addr, err, relayO)
	}
	if kib, ok := connRelayPace(3); !ok || kib != 500 {
		t.Fatalf("conn 3's relay pace after the hand-out: %d %v, want 500", kib, ok)
	}
	// O marked: the next hand-out is VK's relay, which has no field.
	cp.health.markLocked(cp.health.record(relayO), time.Now())
	addr, _, _, err = p.resolveTURNAddr(8, false)
	if err != nil || addr == relayO {
		t.Fatalf("the hand-out with O marked: %q %v, want VK's relay", addr, err)
	}
	if _, ok := connRelayPace(8); ok {
		t.Fatal("a hand-out of VK's relay recorded a pace")
	}
	if _, _, _, err := p.resolveTURNAddr(-1, false); err != nil {
		t.Fatal(err)
	}
}

// A writer paced by its RELAY under an OFF toggle waits its full debt: the
// sleep's "turned off mid-wait" exit asks this connection's own rate, not the
// toggle (which is off throughout and would end every wait at its first slice).
//
// SABOTAGE SEEN TO FAIL: the sleep loop breaks on `!paceNow().on()`.
// Compiles; the second reserve then returns after one 10-ms slice.
func TestARelayPacedWriterWaitsUnderAnOffToggle(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p, cancel := paceTestProxy()
	defer cancel()

	setConnRelayPace(9, 20, true) // 20 KiB/s: one maximum-size packet is ≈75 ms of debt
	for i := 0; i < 14; i++ {     // the 16-KiB burst spent
		p.paceSettle(p.paceReserve(9), 1500)
	}
	t0 := time.Now()
	tk := p.paceReserve(9)
	if took := time.Since(t0); took < 40*time.Millisecond {
		t.Fatalf("a relay-paced writer in debt waited %s under an off toggle, want its debt (≈75 ms)", took)
	}
	p.paceSettle(tk, 1500)
}
