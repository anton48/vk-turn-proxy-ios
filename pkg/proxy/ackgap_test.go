package proxy

import (
	"strings"
	"testing"
	"time"
)

const gms = int64(time.Millisecond)

// TestGapsArePERFLOW is the whole reason this instrument exists: the aggregate
// version could not see one flow pausing while the others kept arriving, and it
// refuted only the pool-wide form of the hypothesis. Two flows interleaving must
// NOT hide a gap in one of them.
func TestGapsArePerFlow(t *testing.T) {
	var a ackGapStats
	base := time.Now().UnixNano()
	// flow A goes quiet for 400 ms; flow B keeps ticking every 50 ms throughout.
	a.observe(0xAAAA, base)
	for i := int64(1); i <= 8; i++ {
		a.observe(0xBBBB, base+i*50*gms)
	}
	a.observe(0xAAAA, base+400*gms)

	s := a.summary()
	if !strings.Contains(s, "ge250=1") {
		t.Fatalf("one flow's 400 ms pause was lost while another kept arriving: %q\n"+
			"that is precisely the blind spot this instrument was built to remove", s)
	}
}

func TestTheFirstAckOfAFlowIsNotAGap(t *testing.T) {
	var a ackGapStats
	a.observe(0xAAAA, time.Now().UnixNano())
	if s := a.summary(); s != "" {
		t.Fatalf("one ACK produced %q, want no field", s)
	}
}

func TestUnparseablePacketsAreIgnored(t *testing.T) {
	var a ackGapStats
	base := time.Now().UnixNano()
	a.observe(0, base)
	a.observe(0, base+400*gms)
	if s := a.summary(); s != "" {
		t.Fatalf("flowKey 0 (unparseable) was counted as a flow: %q", s)
	}
}

// TestBucketsAreCumulativeAndIdleIsDropped folds the two properties the
// aggregate version had to learn the hard way.
func TestBucketsAreCumulativeAndIdleIsDropped(t *testing.T) {
	var a ackGapStats
	base := time.Now().UnixNano()
	a.observe(1, base)
	a.observe(1, base+1200*gms) // 1.2 s: must count in all three buckets
	a.observe(2, base)
	a.observe(2, base+30*1000*gms) // 30 s: idle between runs, not a stall
	s := a.summary()
	for _, want := range []string{"ge250=1", "ge500=1", "ge1s=1", "idle=1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q lacks %q", s, want)
		}
	}
	if strings.Contains(s, "flows=2") {
		t.Fatalf("the idle flow was counted in the denominator: %q — the rate "+
			"would then be divided by flows that produced no gap", s)
	}
}

func TestSummaryIsReadAndResetAndEvictsQuietFlows(t *testing.T) {
	var a ackGapStats
	base := time.Now().UnixNano()
	a.observe(1, base)
	a.observe(1, base+300*gms)
	if s := a.summary(); !strings.Contains(s, "gaps=1") {
		t.Fatalf("first read lost the gap: %q", s)
	}
	if s := a.summary(); s != "" {
		t.Fatalf("second read still reports %q", s)
	}
	// a flow last seen 20 s ago must be forgotten, or a long session grows the
	// map without bound
	a.mu.Lock()
	a.last[99] = time.Now().UnixNano() - 20*1000*gms
	a.mu.Unlock()
	a.summary()
	a.mu.Lock()
	_, still := a.last[99]
	a.mu.Unlock()
	if still {
		t.Fatal("a flow quiet for 20 s was not evicted")
	}
}
