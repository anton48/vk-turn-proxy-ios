package main

import "testing"

func newSim(window uint64) *replaySim {
	return &replaySim{enabled: true, window: window}
}

// In-order delivery must never look late.
func TestReplaySimInOrder(t *testing.T) {
	s := newSim(8128)
	for i := uint64(1); i <= 10000; i++ {
		s.observe(i, "t")
	}
	if s.ooo != 0 || s.rejected != 0 || s.maxDisp != 0 {
		t.Fatalf("in-order stream flagged: ooo=%d rejected=%d maxDisp=%d",
			s.ooo, s.rejected, s.maxDisp)
	}
	if s.analysed != 10000 {
		t.Fatalf("analysed=%d, want 10000", s.analysed)
	}
}

// Reordering INSIDE the window is late but survives — this is the case the
// real tunnel is expected to be in, and the one that must not raise an alarm.
func TestReplaySimWithinWindowSurvives(t *testing.T) {
	s := newSim(8128)
	// Deliver 1..1000 with each packet displaced 100 behind the leader.
	for i := uint64(1); i <= 1000; i++ {
		s.observe(i + 100, "t") // advance the leader
		s.observe(i, "t")       // the straggler, exactly 100 behind
	}
	if s.rejected != 0 {
		t.Fatalf("rejected=%d, want 0 — displacement 100 is well inside 8128", s.rejected)
	}
	if s.ooo != 1000 {
		t.Fatalf("ooo=%d, want 1000", s.ooo)
	}
	if s.maxDisp != 100 {
		t.Fatalf("maxDisp=%d, want 100", s.maxDisp)
	}
}

// The boundary must match wireguard-go: it rejects when last-counter EXCEEDS
// windowSize, so a displacement of exactly the window is still accepted.
func TestReplaySimBoundaryIsExclusive(t *testing.T) {
	s := newSim(8128)
	s.observe(100000, "t")
	s.observe(100000 - 8128, "t") // displacement == window → accepted
	if s.rejected != 0 {
		t.Fatalf("displacement == window was rejected; boundary is off by one")
	}
	s.observe(100000 - 8129, "t") // displacement == window+1 → rejected
	if s.rejected != 1 {
		t.Fatalf("rejected=%d, want 1 for displacement window+1", s.rejected)
	}
}

// A path stalling long enough to fall out of the window is what the whole
// experiment is looking for; make sure it is actually detected.
func TestReplaySimDetectsFarStraggler(t *testing.T) {
	s := newSim(8128)
	for i := uint64(1); i <= 20000; i++ {
		s.observe(i, "t")
	}
	s.observe(1, "t") // 19999 behind
	if s.rejected != 1 {
		t.Fatalf("rejected=%d, want 1", s.rejected)
	}
	if s.maxDisp != 19999 {
		t.Fatalf("maxDisp=%d, want 19999", s.maxDisp)
	}
}

// Attribution is the control that separates a real path stall from a stall of
// this process, so it has to actually distinguish the two shapes.
func TestReplaySimAttribution(t *testing.T) {
	one := newSim(8128)
	for i := uint64(1); i <= 20000; i++ {
		one.observe(i, "pathA")
	}
	for i := uint64(1); i <= 5; i++ {
		one.observe(i, "pathA") // one path fell far behind
	}
	if len(one.perSrc) != 1 || one.perSrc["pathA"] != 5 {
		t.Fatalf("single-path stall not attributed to one source: %v", one.perSrc)
	}

	many := newSim(8128)
	for i := uint64(1); i <= 20000; i++ {
		many.observe(i, "pathA")
	}
	for i, src := range []string{"pathA", "pathB", "pathC"} {
		many.observe(uint64(i+1), src) // scattered → looks like OUR stall
	}
	if len(many.perSrc) != 3 {
		t.Fatalf("scattered rejections not attributed to 3 sources: %v", many.perSrc)
	}
}

// Percentile indexing must not panic on the degenerate sizes.
func TestReplaySimReportDoesNotPanic(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		s := newSim(8128)
		s.observe(1000, "t")
		for i := 0; i < n; i++ {
			s.observe(uint64(1000 - i - 1), "t")
		}
		s.report()
	}
}
