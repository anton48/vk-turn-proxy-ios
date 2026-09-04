// SPDX-License-Identifier: MIT

package csqtt

import (
	"testing"
	"time"
)

func TestNewIdentityIsMonotonicWithAFreshSalt(t *testing.T) {
	g1, s1 := NewIdentity(0)
	g2, s2 := NewIdentity(g1)
	if g2 <= g1 {
		t.Fatalf("generation did not advance: %d → %d", g1, g2)
	}
	far := g1 + 1_000_000
	if g3, _ := NewIdentity(far); g3 <= far {
		t.Fatalf("generation must exceed a prev ahead of the clock: %d ≤ %d", g3, far)
	}
	if len(s1) != 32 || len(s2) != 32 || s1 == s2 {
		t.Fatalf("salts: %q %q", s1, s2)
	}
}

func TestStartGateSpacesStartsFromTheEndOfThePreviousOne(t *testing.T) {
	g := newStartGate(100 * time.Millisecond)
	now := time.Unix(1_700_000_000, 0)
	var slept []time.Duration
	g.now = func() time.Time { return now }
	g.sleep = func(d time.Duration) { slept = append(slept, d); now = now.Add(d) }

	done := g.begin()                     // first start: no wait
	now = now.Add(130 * time.Millisecond) // a slow credential mint inside the start
	done()
	done = g.begin() // right after: the full spacing, measured from the END
	done()
	now = now.Add(40 * time.Millisecond)
	done = g.begin() // 40 ms after the previous end: the remaining 60
	done()
	now = now.Add(time.Second)
	done = g.begin() // long after: no wait
	done()
	want := []time.Duration{100 * time.Millisecond, 60 * time.Millisecond}
	if len(slept) != len(want) || slept[0] != want[0] || slept[1] != want[1] {
		t.Fatalf("sleeps %v, want %v", slept, want)
	}
}

// Two workers whose starts overlap must serialise: the second cannot begin
// while the first is still inside its start.
func TestStartGateHoldsTheSlotForTheWholeStart(t *testing.T) {
	g := newStartGate(0)
	inside := make(chan struct{})
	release := make(chan struct{})
	go func() {
		done := g.begin()
		close(inside)
		<-release
		done()
	}()
	<-inside
	second := make(chan struct{})
	go func() { done := g.begin(); done(); close(second) }()
	select {
	case <-second:
		t.Fatal("second start began while the first was still inside its start")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second start never began after the first finished")
	}
}

func TestLivenessVerdict(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	base := livenessInput{
		Now:      t0.Add(2 * time.Minute),
		PrevTick: t0.Add(2*time.Minute - livenessTick),
		ReadyAt:  t0,
		LastRx:   t0.Add(2 * time.Minute), // heard from just now
		AnyRx:    t0.Add(2 * time.Minute),
	}
	cases := []struct {
		name string
		mod  func(*livenessInput)
		want livenessAction
	}{
		{"fresh inbound → nothing", func(*livenessInput) {}, livenessNone},
		{"silent 31 s, others live → probe", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-31 * time.Second)
		}, livenessProbe},
		{"silent 31 s but probe already out → wait", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-31 * time.Second)
			in.ProbeSentAt = in.Now.Add(-time.Second)
		}, livenessNone},
		{"silent 29 s → not yet a probe", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-29 * time.Second)
		}, livenessNone},
		{"silent exactly 30 s → probe", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-30 * time.Second)
		}, livenessProbe},
		{"probe unanswered for 29 s → still waiting", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-60 * time.Second)
			in.ProbeSentAt = in.Now.Add(-29 * time.Second)
		}, livenessNone},
		{"probe unanswered for 30 s → restart", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-61 * time.Second)
			in.ProbeSentAt = in.Now.Add(-30 * time.Second)
		}, livenessRestart},
		{"everyone silent → the path, not the worker", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-61 * time.Second)
			in.ProbeSentAt = in.Now.Add(-30 * time.Second)
			in.AnyRx = in.Now.Add(-31 * time.Second)
		}, livenessNone},
		{"late tick → descheduled, reset, judge nothing", func(in *livenessInput) {
			in.LastRx = in.Now.Add(-61 * time.Second)
			in.ProbeSentAt = in.Now.Add(-30 * time.Second)
			in.PrevTick = in.Now.Add(-(livenessTick + descheduledSlack + time.Second))
		}, livenessResetAll},
		{"first tick ever is not a late tick", func(in *livenessInput) {
			in.PrevTick = time.Time{}
			in.LastRx = in.Now.Add(-31 * time.Second)
		}, livenessProbe},
		{"not ready → not judged", func(in *livenessInput) {
			in.ReadyAt = time.Time{}
			in.LastRx = in.Now.Add(-61 * time.Second)
		}, livenessNone},
		{"ready 10 s ago, silent since → grace", func(in *livenessInput) {
			in.ReadyAt = in.Now.Add(-10 * time.Second)
			in.LastRx = in.Now.Add(-61 * time.Second)
		}, livenessNone},
	}
	for _, c := range cases {
		in := base
		c.mod(&in)
		if got := livenessVerdict(in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// A panel restart empties the server: every worker must GETCONF again, not
// only the one that happened to read the notice.
func TestPanelRestartKicksEveryWorker(t *testing.T) {
	c := &Client{cfg: Config{Logf: func(string, ...any) {}}}
	for i := 0; i < 3; i++ {
		c.workers = append(c.workers, &worker{c: c, id: i + 1, kick: make(chan string, 1)})
	}
	c.workers[1].handleControl(PanelRestartNotice)
	for _, w := range c.workers {
		select {
		case <-w.kick:
		default:
			t.Fatalf("worker %d was not restarted after the panel notice", w.id)
		}
	}
}

// A long-lived session resets the restart delay; a run of short ones
// doubles it up to the cap. (Seen live: worker 3 restarted once by the
// liveness rule waited 2 s at the panel restart an hour later — without a
// reset the delay would only ever grow.)
func TestNextBackoffResetsAfterAHealthySession(t *testing.T) {
	if got := nextBackoff(restartBackoff, time.Second); got != 2*restartBackoff {
		t.Fatalf("short session: %v, want doubled", got)
	}
	if got := nextBackoff(16*restartBackoff, time.Second); got != maxBackoff {
		t.Fatalf("cap: %v, want %v", got, maxBackoff)
	}
	if got := nextBackoff(maxBackoff, time.Second); got != maxBackoff {
		t.Fatalf("at the cap: %v, want %v", got, maxBackoff)
	}
	// The threshold is 40 s, written as a literal on purpose: a fixture that
	// derives it from the constant relaxes with the constant.
	if got := nextBackoff(maxBackoff, 40*time.Second); got != restartBackoff {
		t.Fatalf("40 s session: %v, want the reset %v", got, restartBackoff)
	}
	if got := nextBackoff(4*restartBackoff, 39*time.Second); got != 8*restartBackoff {
		t.Fatalf("39 s session: %v, want doubled", got)
	}
}
