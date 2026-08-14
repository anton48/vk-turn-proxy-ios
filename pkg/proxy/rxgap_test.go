package proxy

import (
	"context"
	"strings"
	"testing"
	"time"
)

const ms = int64(time.Millisecond)

// TestTheFirstArrivalIsNotAGap: with nothing to compare against, the first
// packet must not invent an interval — otherwise every reconnect would inject a
// spurious huge gap at exactly the moment the field is most likely to be read.
func TestTheFirstArrivalIsNotAGap(t *testing.T) {
	// 🚨 A REALISTIC UnixNano, and that is the point. An earlier version of this
	// test passed 1_000_000 (1 ms past the epoch), so dropping the `prev == 0`
	// guard produced a 1 ms gap that the histogram ignores anyway — the test
	// survived its own sabotage for a reason that had nothing to do with the
	// property. With a real timestamp, a missing guard yields a gap of ~58 years,
	// which lands in the idle counter and is loudly visible.
	var r rxGapStats
	r.observe(time.Now().UnixNano())
	if s := r.summary(); s != "" {
		t.Fatalf("one arrival produced %q, want no field at all", s)
	}
}

// TestGapBucketsAreCUMULATIVE — a 1.2 s gap is also a gap over 500 ms and over
// 250 ms. Reading `ge250` as "gaps between 250 and 500 ms" would understate the
// small buckets and make the distribution's shape unreadable.
func TestGapBucketsAreCumulative(t *testing.T) {
	var r rxGapStats
	base := int64(1_000_000_000)
	r.observe(base)
	r.observe(base + 1200*ms) // one gap of 1.2 s
	s := r.summary()
	for _, want := range []string{"ge250=1", "ge500=1", "ge1s=1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q lacks %q — the buckets must be cumulative", s, want)
		}
	}
}

func TestSmallGapsCountInNoBucket(t *testing.T) {
	var r rxGapStats
	base := int64(1_000_000_000)
	r.observe(base)
	r.observe(base + 5*ms)
	s := r.summary()
	for _, unwanted := range []string{"ge250=1", "ge500=1", "ge1s=1"} {
		if strings.Contains(s, unwanted) {
			t.Fatalf("a 5 ms gap landed in a bucket: %q", s)
		}
	}
}

// TestAnIdleTunnelDoesNotLookLikeAStall is the guard that keeps the field
// usable at all. Between two probe runs the tunnel is quiet for tens of
// seconds; counting that as one enormous "feedback gap" would put a catastrophic
// max and a ge1s hit into the tick that follows every single run.
func TestAnIdleTunnelDoesNotLookLikeAStall(t *testing.T) {
	var r rxGapStats
	base := int64(1_000_000_000)
	r.observe(base)
	r.observe(base + 30*1000*ms) // 30 s of silence between runs
	s := r.summary()
	if strings.Contains(s, "ge1s=1") {
		t.Fatalf("a 30 s idle period was counted as a feedback gap: %q", s)
	}
	if !strings.Contains(s, "idle=1") {
		t.Fatalf("the dropped idle gap was not reported: %q — a silent drop is "+
			"how an instrument stops being auditable", s)
	}
	if strings.Contains(s, "max=30") {
		t.Fatalf("the idle gap poisoned max: %q", s)
	}
}

// TestSummaryIsReadAndReset: the memstats line is per-interval, and a counter
// that accumulates across ticks would make every tick look worse than the last.
func TestSummaryIsReadAndReset(t *testing.T) {
	var r rxGapStats
	base := int64(1_000_000_000)
	r.observe(base)
	r.observe(base + 1200*ms)
	if s := r.summary(); !strings.Contains(s, "ge1s=1") {
		t.Fatalf("first read lost the gap: %q", s)
	}
	if s := r.summary(); s != "" {
		t.Fatalf("second read still reports %q — the interval was not cleared", s)
	}
}

// TestTheDownlinkPathFeedsTheCounter is the wiring test: it is not enough for
// rxGapStats to be correct, the arrival path has to call it. Two arrivals
// separated by real time must produce a measured gap.
func TestTheDownlinkPathFeedsTheCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 4)}

	if !p.enqueueRecv(ctx, []byte{1}) {
		t.Fatal("enqueueRecv failed")
	}
	time.Sleep(30 * time.Millisecond)
	if !p.enqueueRecv(ctx, []byte{2}) {
		t.Fatal("enqueueRecv failed")
	}
	s := p.rxGap.summary()
	if s == "" {
		t.Fatal("the downlink arrival path does not feed rxGap — the field would " +
			"read empty for a whole session and be taken as 'no gaps'")
	}
	if !strings.Contains(s, "rxgap=") {
		t.Fatalf("unexpected field shape: %q", s)
	}
}
