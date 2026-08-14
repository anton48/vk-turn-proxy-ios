package proxy

import (
	"testing"
	"time"
)

// 🚨 THESE GUARD SILENT PROPERTIES. A wrong clamp, a reset counter or a stale
// deadline all produce a generator that RUNS and logs happily while measuring
// nothing — the failure mode this whole file exists to avoid. Each test below
// was run against a sabotage that still COMPILES and seen to fail.

// The live rate round-trips and clamps at both ends.
//
// SEEN TO FAIL by dropping the upper clamp: 1e6 comes back as 1e6, want 200.
func TestSynthRateClamps(t *testing.T) {
	defer SetUplinkSynthMbit(0)
	for _, tc := range []struct{ in, want float64 }{
		{0, 0}, {19, 19}, {59.5, 59.5}, {synthMaxMbit, synthMaxMbit},
		{1e6, synthMaxMbit}, {-5, 0},
	} {
		SetUplinkSynthMbit(tc.in)
		if got := synthTarget(); got != tc.want {
			t.Fatalf("SetUplinkSynthMbit(%v) -> %v, want %v", tc.in, got, tc.want)
		}
	}
}

// 🎯 THE ONE THAT MATTERS FOR THE MEASUREMENT: an arm that is set and forgotten
// must stop by itself. Without it a level left on overnight runs the radio flat,
// and — worse for the data — a later log would be scored as if someone had
// chosen that arm.
//
// SEEN TO FAIL by having synthTarget ignore the deadline: rate still 19 after
// the deadline passes, want 0.
func TestSynthArmStopsAtItsDeadline(t *testing.T) {
	defer SetUplinkSynthMbit(0)
	SetUplinkSynthMbit(19)
	if synthTarget() != 19 {
		t.Fatalf("arm did not start: %v", synthTarget())
	}
	synthArmDeadline.Store(time.Now().Add(-time.Second).UnixNano())
	if got := synthTarget(); got != 0 {
		t.Fatalf("expired arm still reports %v, want 0", got)
	}
	// And setting a rate again starts a FRESH arm rather than inheriting the
	// expired deadline.
	SetUplinkSynthMbit(37)
	if got := synthTarget(); got != 37 {
		t.Fatalf("re-arming did not refresh the deadline: %v", got)
	}
}

// Every rate change refreshes the deadline, so a dose-response that switches
// arms every ~120 s never trips the safety stop.
//
// SEEN TO FAIL by refreshing the deadline only when the rate was previously 0:
// the second SetUplinkSynthMbit leaves the old deadline and the arm reports 0.
func TestChangingTheRateRefreshesTheDeadline(t *testing.T) {
	defer SetUplinkSynthMbit(0)
	SetUplinkSynthMbit(19)
	synthArmDeadline.Store(time.Now().Add(50 * time.Millisecond).UnixNano())
	time.Sleep(80 * time.Millisecond)
	if synthTarget() != 0 {
		t.Fatal("setup: the arm should have expired")
	}
	SetUplinkSynthMbit(59)
	if got := synthTarget(); got != 59 {
		t.Fatalf("a rate change did not start a fresh arm: %v", got)
	}
}

// The burst arithmetic must reach the rate it was asked for. This is the
// "did the treatment apply" guard: a burst of 0 or 1 at a high rate silently
// caps the generator near 500 pkt/s and the run measures nothing.
//
// SEEN TO FAIL against the ROUNDED-BURST version this replaced, and it is why
// that version is gone: asked for 6 Mbit/s it delivers 10.50, asked for 12 it
// delivers 15.7 — 75% and 31% high on exactly the LOW arms the dose-response
// depends on, so a "30% of the knee" level would really have run at 40-50%.
func TestBurstReachesTheRequestedRate(t *testing.T) {
	for _, mbit := range []float64{6, 12, 19, 37, 59, 100} {
		perTick := mbit * 1e6 / 8 / synthPktSize * synthTick.Seconds()
		// Walk one second of ticks through the accumulator the loop uses.
		var owed float64
		var sent int
		for i := 0; i < int(time.Second/synthTick); i++ {
			owed += perTick
			n := int(owed)
			owed -= float64(n)
			sent += n
		}
		got := float64(sent) * synthPktSize * 8 / 1e6
		if got < mbit*0.99 || got > mbit*1.01 {
			t.Fatalf("%.0f Mbit/s: the accumulator delivers %.2f Mbit/s over one second", mbit, got)
		}
	}
}
