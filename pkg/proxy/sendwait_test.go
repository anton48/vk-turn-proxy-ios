package proxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The headline property: residence is what the PACKET waited, and the summary
// must say so with a denominator beside it.
func TestResidencePercentilesAndDenominator(t *testing.T) {
	s := &sendWaitStats{}
	feed := func(n int, d time.Duration) {
		for i := 0; i < n; i++ {
			s.observe(1, 1+int64(d))
		}
	}
	feed(90, 100*time.Microsecond) // bucket 0
	feed(9, 5100*time.Microsecond) // bucket 20 → 5ms
	feed(1, 100*time.Millisecond)  // bucket 400 → 100ms, and the max

	got := s.summary()
	want := " sendch-wait=0s/0s/5ms max=100ms over=100"
	if got != want {
		t.Fatalf("summary = %q\n           want %q", got, want)
	}
}

// 🚨 THE CONSISTENCY CHECK THIS PROJECT USES TO CATCH DENOMINATOR BUGS. A
// histogram normalised by a count collected somewhere else walks off its own end
// and reports the overflow bucket — that is how "p99 512 ms" once printed beside
// "max 31 ms". p50 ≤ p90 ≤ p99 ≤ max must hold for ANY input.
func TestPercentilesCanNeverExceedMax(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 100, 999} {
		s := &sendWaitStats{}
		for i := 0; i < n; i++ {
			// A spread that straddles bucket boundaries and repeats values.
			s.observe(1, 1+int64(i%37)*int64(time.Millisecond)/3)
		}
		line := s.summary()
		p50, p90, p99, max := parseWaitLine(t, line)
		if !(p50 <= p90 && p90 <= p99 && p99 <= max) {
			t.Fatalf("n=%d: %q violates p50 ≤ p90 ≤ p99 ≤ max "+
				"(%v/%v/%v max %v) — the percentiles are being normalised by "+
				"something other than the histogram's own sum", n, line, p50, p90, p99, max)
		}
	}
}

// An idle phone must print nothing rather than a row of zeroes that could later
// be quoted as "measured, and it was fine".
func TestSummaryIsSilentWithNoSamples(t *testing.T) {
	s := &sendWaitStats{}
	if got := s.summary(); got != "" {
		t.Fatalf("summary with no samples = %q, want empty", got)
	}
}

// Read-and-reset, the idiom of every other counter on this line: one burst must
// not mark every later interval.
func TestSummaryResetsTheInterval(t *testing.T) {
	s := &sendWaitStats{}
	s.observe(1, 1+int64(7*time.Millisecond))
	if got := s.summary(); !strings.Contains(got, "over=1") {
		t.Fatalf("first summary = %q, want one sample", got)
	}
	if got := s.summary(); got != "" {
		t.Fatalf("second summary = %q — the interval did not reset, so the next "+
			"line reports this interval's backlog again", got)
	}
}

// Beyond the last bucket the percentile is a BOUND, and must be printed as one.
// A number the bucket cannot support is how a diagnostic starts lying.
func TestOverflowIsPrintedAsABoundAndMaxStaysExact(t *testing.T) {
	s := &sendWaitStats{}
	s.observe(1, 1+int64(600*time.Millisecond))
	got := s.summary()
	if !strings.Contains(got, ">=512ms") {
		t.Fatalf("summary = %q, want the overflow bucket rendered as >=512ms", got)
	}
	if !strings.Contains(got, "max=600ms") {
		t.Fatalf("summary = %q, want the exact max preserved past the last bucket", got)
	}
}

// A clock step between the enqueue stamp and the dequeue read must not land in
// the overflow bucket, where it would read as exactly the pathology this
// instrument exists to find.
func TestNegativeIntervalIsZeroNotOverflow(t *testing.T) {
	s := &sendWaitStats{}
	s.observe(1_000_000, 1) // dequeue "before" enqueue
	got := s.summary()
	if strings.Contains(got, ">=") {
		t.Fatalf("summary = %q — a backwards clock was filed as a 512 ms wait", got)
	}
	if !strings.Contains(got, "max=0s") {
		t.Fatalf("summary = %q, want max=0s", got)
	}
}

// An unstamped item (a path that predates the instrument, or a zero value) must
// be skipped, not counted as a wait since the epoch.
func TestUnstampedItemsAreNotCounted(t *testing.T) {
	s := &sendWaitStats{}
	s.observe(0, int64(time.Now().UnixNano()))
	if got := s.summary(); got != "" {
		t.Fatalf("summary = %q — an unstamped packet was measured against the epoch", got)
	}
}

// The packet path may not pay for the diagnostic in garbage: this device runs
// under GOMEMLIMIT 35 MB with a ~50 MB jetsam ceiling and a GC-spiral history.
func TestObserveAllocatesNothing(t *testing.T) {
	s := &sendWaitStats{}
	if n := testing.AllocsPerRun(200, func() { s.observe(1, 1+int64(time.Millisecond)) }); n != 0 {
		t.Fatalf("observe allocates %v times per call, want 0", n)
	}
}

// SendPacket must stamp, or every residence below is measured from the epoch.
func TestSendPacketStampsTheEnqueueInstant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 4)}

	before := time.Now().UnixNano()
	if err := p.SendPacket([]byte{1, 2, 3}); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	item := <-p.sendCh
	after := time.Now().UnixNano()

	if item.at == 0 {
		t.Fatal("SendPacket enqueued an UNSTAMPED item — every residence measured " +
			"from it is silently dropped by observe()")
	}
	if item.at < before || item.at > after {
		t.Fatalf("stamp %d outside [%d,%d]", item.at, before, after)
	}
	if len(item.buf) != 3 || item.buf[2] != 3 {
		t.Fatalf("payload did not survive the struct: %v", item.buf)
	}
}

// 🚨 THE INSTRUMENT MUST ACTUALLY BE FED, AND THERE ARE FOUR PLACES THAT CAN
// FORGET. sendCh is drained by four independent session goroutines (DTLS, direct
// UDP, WRAP-A, SRTP), each behind a live connection that a unit test cannot
// stand up — so the guard is on the source: every read of the channel must price
// the wait it just served, within a few lines of taking it.
//
// This is the test that fails when a FIFTH transport is added and quietly ships
// uninstrumented. Validated by sabotage: delete any one observe call and it goes
// red, naming the line.
//
// ⚠️ UPDATED WHEN THE FOUR SITES STOPPED CALLING observe INLINE: they hand the
// packet to `p.writePacket`, which prices every packet it writes
// (writepacket.go). The property is unchanged, the indirection is new, so
// a site now satisfies this guard EITHER way. That widening is only safe because
// of the second half below, which follows the delegation into writepacket.go and
// checks the instrument is still fed there; without it, routing a transport
// through a writePacket that had lost its observe call would pass silently. Same
// brittleness as the `sockStats.register` scan window: a guard that scans for a
// call near a line goes red on correct code the moment the call moves, and the
// fix is to follow the code, never to delete the guard.
func TestEverySendChDequeueFeedsTheInstrument(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	// 🚨 STRIP `//` COMMENTS FIRST. This scan matches a literal that any comment
	// ABOUT the dequeue sites also contains — and it went red on exactly that:
	// the ownership note added with sendPktPool names "`case item := <-p.sendCh`
	// bodies" while explaining where a Put must NOT go. That is the fourth time
	// a source scan in this project has reddened on its own documentation, so
	// the fix is the systematic one rather than rewording the prose.
	// ⚠️ Naive by design: it also cuts inside a string literal containing `//`.
	// Nothing this scan looks for lives in one.
	var code strings.Builder
	for _, ln := range strings.Split(string(src), "\n") {
		if i := strings.Index(ln, "//"); i >= 0 {
			ln = ln[:i]
		}
		code.WriteString(ln)
		code.WriteString("\n")
	}
	lines := strings.Split(code.String(), "\n")
	sites := 0
	for i, ln := range lines {
		if !strings.Contains(ln, "<-p.sendCh") {
			continue
		}
		sites++
		fed := false
		// 🚨 WIDENED FROM 5 TO 8 LINES, DELIBERATELY, AND THE REASON IS ON THE
		// RECORD ABOVE: "the fix is to follow the code, never to delete the
		// guard". The uplink pacer's `paceSettle` now sits between the dequeue
		// and the write at every site, so the write moved one line further from
		// its `case`. The window is proximity, not arithmetic — what it enforces
		// is that a dequeue and its instrument stay in the same breath.
		for j := i; j < i+8 && j < len(lines); j++ {
			if strings.Contains(lines[j], "p.sendWait.observe(") ||
				strings.Contains(lines[j], "p.writePacket(") {
				fed = true
				break
			}
		}
		if !fed {
			t.Errorf("proxy.go:%d dequeues sendCh without calling p.sendWait.observe "+
				"or p.writePacket within 8 lines — that transport's packets are invisible "+
				"to the residence histogram:\n\t%s", i+1, strings.TrimSpace(ln))
		}
	}
	if sites < 4 {
		t.Fatalf("found %d sendCh dequeue sites, expected at least 4 (DTLS, direct, "+
			"WRAP-A, SRTP) — the scan is not finding them and this test is passing "+
			"vacuously", sites)
	}

	// Follow the delegation: whatever writePacket writes, it must also price.
	chunkSrc, err := os.ReadFile("writepacket.go")
	if err != nil {
		t.Fatalf("read writepacket.go: %v", err)
	}
	if !strings.Contains(string(chunkSrc), "p.sendWait.observe(") {
		t.Fatal("writePacket no longer calls p.sendWait.observe — every transport now " +
			"delegates to it, so this one deletion makes the residence histogram blind " +
			"for the whole uplink while the per-site scan above still passes")
	}
	if !strings.Contains(string(chunkSrc), "p.writeWait.observe(") {
		t.Fatal("writePacket no longer calls p.writeWait.observe — `conn-write` has gone " +
			"blind for every transport")
	}
}

// parseWaitLine pulls the four durations back out of a summary line.
func parseWaitLine(t *testing.T, line string) (p50, p90, p99, max time.Duration) {
	t.Helper()
	f := strings.Fields(line)
	if len(f) != 3 {
		t.Fatalf("unexpected summary shape: %q", line)
	}
	pcts := strings.Split(strings.TrimPrefix(f[0], "sendch-wait="), "/")
	if len(pcts) != 3 {
		t.Fatalf("unexpected percentile group: %q", f[0])
	}
	dur := func(s string) time.Duration {
		s = strings.TrimPrefix(s, ">=")
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return d
	}
	return dur(pcts[0]), dur(pcts[1]), dur(pcts[2]),
		dur(strings.TrimPrefix(f[1], "max="))
}
