package proxy

import (
	"strings"
	"testing"
	"time"
)

// TestDuplicateAcksDoNotRESETTheClock is the whole correction this counter
// exists for. Duplicate ACKs arrive at full cadence while the cumulative
// acknowledgement stands still — the ARRIVAL counter sees a healthy stream, and
// the retransmission timer runs anyway. A 400 ms stall filled with dup-ACKs must
// therefore be reported as a 400 ms ADVANCE gap.
func TestDuplicateAcksDoNotResetTheClock(t *testing.T) {
	var a ackAdvStats
	base := time.Now().UnixNano()
	a.observe(1, 1000, base)
	for i := int64(1); i <= 8; i++ { // dup-ACKs every 50 ms, same ack number
		a.observe(1, 1000, base+i*50*gms)
	}
	a.observe(1, 2000, base+400*gms) // finally advances

	s := a.summary()
	if !strings.Contains(s, "ge371=1") {
		t.Fatalf("a 400 ms stall filled with duplicate ACKs was not reported as an "+
			"advance gap: %q\nthat is exactly the blind spot of the arrival counter", s)
	}
	if !strings.Contains(s, "dup=8") {
		t.Fatalf("the duplicate ACKs were not counted: %q", s)
	}
}

// TestSequenceWraparoundIsNotAREGRESSION: the ack field is 32 bits and wraps.
// A naive `>` would read the wrap as a 4 GB backwards jump and then treat every
// later ACK as a duplicate for the rest of the flow — the counter would go
// silent precisely on a long transfer.
func TestSequenceWraparoundIsNotARegression(t *testing.T) {
	var a ackAdvStats
	base := time.Now().UnixNano()
	a.observe(1, 0xFFFFFF00, base)
	a.observe(1, 0x00000100, base+300*gms) // wrapped, and genuinely forward
	s := a.summary()
	if strings.Contains(s, "dup=1") {
		t.Fatalf("a sequence wrap was counted as a duplicate: %q", s)
	}
	if !strings.Contains(s, "ge250=1") {
		t.Fatalf("the advance across the wrap was lost: %q", s)
	}
}

// TestBucketEdgeSitsONTheRTO — rule 9: the deciding threshold is the measured
// RTO (371 ms p50), so an edge must be AT it, not around it.
func TestBucketEdgeSitsOnTheRTO(t *testing.T) {
	var a ackAdvStats
	base := time.Now().UnixNano()
	a.observe(1, 100, base)
	a.observe(1, 200, base+380*gms) // just over the RTO
	a.observe(2, 100, base)
	a.observe(2, 200, base+300*gms) // over 250 but UNDER the RTO
	s := a.summary()
	if !strings.Contains(s, "ge250=2") {
		t.Fatalf("want both gaps in ge250: %q", s)
	}
	if !strings.Contains(s, "ge371=1") {
		t.Fatalf("only the 380 ms gap may cross the RTO edge: %q", s)
	}
	if !strings.Contains(s, "ge486=0") {
		t.Fatalf("neither gap reaches the p90 edge: %q", s)
	}
}

func TestAdvanceIsPerFlow(t *testing.T) {
	var a ackAdvStats
	base := time.Now().UnixNano()
	a.observe(0xAAAA, 100, base)
	for i := int64(1); i <= 8; i++ { // flow B advances happily throughout
		a.observe(0xBBBB, uint32(100+i*10), base+i*50*gms)
	}
	a.observe(0xBBBB, 100, base) // seed B's first observation last, harmless
	a.observe(0xAAAA, 200, base+400*gms)
	if s := a.summary(); !strings.Contains(s, "ge371=1") {
		t.Fatalf("one flow's stall was hidden by another flow advancing: %q", s)
	}
}

// TestFirstAckStartsTheClockRatherThanCountingAsAGap.
//
// 🚨 AN EARLIER VERSION OF THIS TEST WAS VACUOUS AND SURVIVED TWO SABOTAGES: it
// made ONE observation, so nothing could be recorded whatever the code did. The
// property only becomes testable with a SECOND acknowledgement — the first must
// start the clock, and the second must produce exactly one ordinary gap rather
// than a gap measured from the epoch.
func TestFirstAckStartsTheClockRatherThanCountingAsAGap(t *testing.T) {
	var a ackAdvStats
	base := time.Now().UnixNano()
	a.observe(1, 500, base)
	a.observe(1, 600, base+300*gms)
	s := a.summary()
	if !strings.Contains(s, "adv=1") {
		t.Fatalf("want exactly one advance: %q", s)
	}
	if !strings.Contains(s, "ge250=1") {
		t.Fatalf("the 300 ms gap was lost: %q", s)
	}
	if !strings.Contains(s, "idle=0") {
		t.Fatalf("the FIRST acknowledgement was measured from the epoch and landed "+
			"in the idle bucket: %q — the clock must start, not tick", s)
	}
}
