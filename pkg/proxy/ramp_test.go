package proxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

// 🚨 The synthetic uplink's timeout is derived from this, and the first version
// guessed 90 s against a ramp that took 106.8 — a device run wasted on a
// number that was wrong by construction. Pin the arithmetic to the constant
// that builds the start.
//
// Sabotage seen red: the bi-modal formula of d2a1a6a put back (n=30 → 1m46.8s).
func TestExpectedRampTimeMatchesTheStagger(t *testing.T) {
	for _, c := range []struct {
		n    int
		want time.Duration
	}{
		{0, 0},
		{1, 0},
		{2, connStartStagger},
		{10, connStartStagger},
		{30, connStartStagger},
		{60, connStartStagger},
	} {
		if got := expectedRampTime(c.n); got != c.want {
			t.Fatalf("expectedRampTime(%d) = %s, want %s", c.n, got, c.want)
		}
	}
	if connStartStagger > time.Second {
		t.Fatalf("connStartStagger = %s — the start is meant to be sub-second, the path-change restart's shape", connStartStagger)
	}
}

// Every connection after the bootstrap launches within connStartStagger — no
// burst tier, no 5 s tier: the ten-per-identity quota is the pool's business
// (connIdx/10 → slot), nothing refills, and the grower mints regardless of
// when the connections ask. The delays are random (thirty dials must not land
// in one instant) but bounded.
//
// Sabotage seen red: the bi-modal delays put back — conn 10 waits 6.8 s.
func TestConnStartDelayIsWithinTheStagger(t *testing.T) {
	if d := connStartDelay(0); d != 0 {
		t.Fatalf("conn 0 (the bootstrap) must launch at once, got %s", d)
	}
	var min, max time.Duration = connStartStagger, 0
	for round := 0; round < 20; round++ {
		for i := 1; i < 60; i++ {
			d := connStartDelay(i)
			if d < 0 || d >= connStartStagger {
				t.Fatalf("connStartDelay(%d) = %s, want within [0, %s)", i, d, connStartStagger)
			}
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}
	}
	// A spread, not a constant: 1180 draws from a one-second window.
	if max-min < connStartStagger/2 {
		t.Fatalf("delays span only %s (min %s, max %s) — the start must be spread over the window, not clumped", max-min, min, max)
	}
}

// readProxySource is the source scan's input: proxy.go as it is on disk (a
// build overlay cannot sabotage these — apply a sabotage to the tree).
func readProxySource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// The start loop launches every connection through connStartDelay — no
// inlined arithmetic, no tier constants. connStartDelay has exactly one caller;
// without this scan the loop could go back to d2a1a6a's bi-modal delays while
// the helper's own test stayed green.
//
// Sabotage seen red: the old bi-modal computation inlined in the loop.
func TestStartLoopLaunchesThroughConnStartDelay(t *testing.T) {
	src := readProxySource(t)
	i := strings.Index(src, "for i := 1; i < p.config.NumConns; i++ {")
	if i < 0 {
		t.Fatal("the start loop is gone from startConnections")
	}
	j := strings.Index(src[i:], "p.runConnection(")
	if j < 0 {
		t.Fatal("the start loop no longer calls runConnection")
	}
	window := src[i : i+j]
	if !strings.Contains(window, "delay := connStartDelay(connIdx)") {
		t.Fatal("the start loop does not take its delay from connStartDelay")
	}
	for _, forbidden := range []string{"rampSlow", "rampBurst", "5 * time.Second", "200 * time.Millisecond", "mathrand."} {
		if strings.Contains(window, forbidden) {
			t.Fatalf("the start loop computes its own delay again (%q in the loop body)", forbidden)
		}
	}
}

// The path-change re-dial and the start share one spread: the "by request"
// branch of runConnection sleeps exactly restartStagger() — the window is the
// branch itself, from its log line to the `continue` that ends it.
//
// Sabotage seen red: the branch's own mathrand.Intn(1000) put back; and
// `time.After(0)` with the name left in a comment.
func TestPathChangeRestartUsesTheSharedStagger(t *testing.T) {
	src := readProxySource(t)
	i := strings.Index(src, "by request (path change) — restarting now")
	if i < 0 {
		t.Fatal("the by-request restart log line is gone from proxy.go")
	}
	j := strings.Index(src[i:], "continue")
	if j < 0 {
		t.Fatal("the by-request branch no longer ends in continue")
	}
	window := src[i : i+j]
	if !strings.Contains(window, "case <-time.After(restartStagger()):") {
		t.Fatalf("the by-request branch does not sleep restartStagger() (window: %q)", window)
	}
	if strings.Contains(window, "mathrand.") {
		t.Fatal("the by-request restart branch has its own stagger again")
	}
	for i := 0; i < 1000; i++ {
		if d := restartStagger(); d < 0 || d >= connStartStagger {
			t.Fatalf("restartStagger() = %s, want within [0, %s)", d, connStartStagger)
		}
	}
}
