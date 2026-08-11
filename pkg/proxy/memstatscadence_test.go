package proxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

const (
	tNormal = 10 * time.Second
	tFast   = 1 * time.Second
	tWindow = 30 * time.Second
)

// The whole point of centralising the decision: the two reasons to be at 1 s
// must not be able to undo each other.
func TestMemstatsCadence(t *testing.T) {
	for _, c := range []struct {
		name           string
		forced, window bool
		want           time.Duration
	}{
		{"idle", false, false, tNormal},
		{"spike window only", false, true, tFast},
		{"switch only", true, false, tFast},
		// 🚨 THE REGRESSION THIS GUARDS. A spike inside a forced session used to
		// leave the ticker at 10 s when the spike's own 30 s window closed,
		// quietly coarsening a measurement that was still running.
		{"switch on, spike window CLOSES under it", true, false, tFast},
		{"switch on, spike window open", true, true, tFast},
	} {
		got, why := memstatsCadence(c.forced, c.window, tNormal, tFast, tWindow)
		if got != c.want {
			t.Errorf("%s: cadence = %v, want %v", c.name, got, c.want)
		}
		if got == tFast && why == "" {
			t.Errorf("%s: 1s cadence with no reason logged — a log that says the "+
				"cadence changed but not why costs a session to re-derive", c.name)
		}
		if got == tNormal && why != "" {
			t.Errorf("%s: normal cadence carries reason %q", c.name, why)
		}
	}
}

// The switch outranks the window, not the other way round: whoever asked for 1 s
// explicitly must not be overridden by a heuristic that fires on its own.
func TestForcedOutranksTheSpikeWindow(t *testing.T) {
	forced, _ := memstatsCadence(true, false, tNormal, tFast, tWindow)
	spike, _ := memstatsCadence(false, true, tNormal, tFast, tWindow)
	if forced != tFast || spike != tFast {
		t.Fatalf("either reason alone must give %v; got forced=%v spike=%v", tFast, forced, spike)
	}
	_, why := memstatsCadence(true, true, tNormal, tFast, tWindow)
	if why != "forced by the Diagnostics switch" {
		t.Fatalf("with both true the reason is %q — the log would blame the "+
			"spike heuristic for a cadence the user chose", why)
	}
}

// 🚨 THE REPORT THIS GUARDS. Switching off while an ALLOC-SPIKE window is open
// leaves the cadence at 1 s — correctly, the window is a separate mechanism — and
// on 2026-08-11 that was read as "turning it off does not work", because the log
// said nothing at all between "fast ticks = false" and the 1 s lines that
// followed. The note is the whole fix: silence there costs a reconstruction from
// the spike list and a stopwatch.
func TestSwitchingOffUnderAnOpenSpikeWindowExplainsItself(t *testing.T) {
	note := memstatsForcedNote(false, true, 13*time.Second)
	if note == "" {
		t.Fatal("switch off while the window holds the cadence produced NO log line — " +
			"that silence is exactly what got read as a broken switch")
	}
	for _, want := range []string{"OFF", "1s", "ALLOC-SPIKE", "13s"} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q does not mention %q — a reader has to know the "+
				"window exists and do the arithmetic, which is the failure being fixed",
				note, want)
		}
	}

	// The ordinary cases stay silent: a switch that moves the cadence is already
	// logged by the cadence line, and one that changes nothing says nothing.
	if got := memstatsForcedNote(false, false, 0); got != "" {
		t.Errorf("switch off with the cadence already normal logged %q, want silence", got)
	}
	if got := memstatsForcedNote(true, true, 5*time.Second); got == "" {
		t.Error("switch ON under an open window logged nothing — the log would not " +
			"record that the switch took effect at all")
	}
}

// A correct explainer that nothing calls is the same silence it was written to
// remove — and Go does not complain about an unused function. The loop lives
// behind a running tunnel, so the guard is on the source, as for the sendCh
// dequeue sites.
func TestTheExplainerIsActuallyWired(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	// 🚨 Count CALLS, not mentions. The first version of this test asked
	// `strings.Contains(src, "memstatsForcedNote(")`, which the function's own
	// declaration satisfies — so it passed with every call site deleted. It took
	// a sabotage run to notice, which is the whole argument for doing them.
	calls := strings.Count(string(src), "memstatsForcedNote(") -
		strings.Count(string(src), "func memstatsForcedNote(")
	if calls < 1 {
		t.Fatal("logMemStatsLoop never calls memstatsForcedNote — switching the " +
			"Diagnostics switch off under an open ALLOC-SPIKE window would again " +
			"produce 1s lines with nothing in the log to explain them")
	}
}

// The flag is process-global (the app and the extension are separate processes
// with their own copy of this library), so the setter must be the only state.
func TestSetMemstatsFastTicksRoundTrips(t *testing.T) {
	defer SetMemstatsFastTicks(false)

	SetMemstatsFastTicks(true)
	if !memstatsFastTicks.Load() {
		t.Fatal("SetMemstatsFastTicks(true) did not take")
	}
	if got, _ := memstatsCadence(memstatsFastTicks.Load(), false, tNormal, tFast, tWindow); got != tFast {
		t.Fatalf("cadence with the flag set = %v, want %v", got, tFast)
	}
	SetMemstatsFastTicks(false)
	if memstatsFastTicks.Load() {
		t.Fatal("SetMemstatsFastTicks(false) did not clear")
	}
}
