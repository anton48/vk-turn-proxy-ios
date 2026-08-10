package proxy

import (
	"testing"
	"time"
)

// 🚨 The synthetic uplink's timeout is derived from this, and the first version
// guessed 90 s against a ramp that takes 106.8 — a device run wasted on a
// number that was wrong by construction. Pin the arithmetic.
func TestExpectedRampTimeMatchesTheStagger(t *testing.T) {
	for _, c := range []struct {
		n    int
		want time.Duration
	}{
		{1, 0},
		{10, 1800 * time.Millisecond},
		{30, 1800*time.Millisecond + 20*5*time.Second},  // 1m46.8s — the measured 30-conn ramp
		{60, 1800*time.Millisecond + 50*5*time.Second},  // 4m16.8s
	} {
		if got := expectedRampTime(c.n); got != c.want {
			t.Fatalf("expectedRampTime(%d) = %s, want %s", c.n, got, c.want)
		}
	}
	// The device observed the 30th conn up at t+1m47s. The formula must not be
	// LONGER than that, or the wait derived from it would be pessimistic.
	if d := expectedRampTime(30); d > 107*time.Second {
		t.Fatalf("expectedRampTime(30) = %s, above the 1m47s observed on device", d)
	}
}
