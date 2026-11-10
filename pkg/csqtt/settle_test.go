package csqtt

import (
	"testing"
	"time"
)

// Who is not yet known to be on the server that came back: whoever has really
// heard nothing later than settleWindow after the notice. Without a notice,
// nobody — a worker that never heard anything included.
func TestWhoIsSettlingBehindARestartNotice(t *testing.T) {
	c := &Client{cfg: Config{Logf: func(string, ...any) {}}}
	now := time.Now().UnixNano()
	if c.settling(now) || c.settling(0) {
		t.Fatal("without a restart notice somebody is settling")
	}
	c.panelRestart() // the notice is when the settle time starts
	at := c.noticeAt.Load()
	if at < now {
		t.Fatalf("the notice left no mark of its moment (%d)", at)
	}
	for _, row := range []struct {
		heard time.Duration // after the notice
		want  bool
	}{
		{-time.Minute, true}, // last heard before it: the server that is about to go
		{time.Second, true},
		{settleWindow - time.Millisecond, true},
		{settleWindow, false}, // later than the old server can have answered
		{time.Hour, false},
	} {
		if got := c.settling(at + int64(row.heard)); got != row.want {
			t.Errorf("last really heard %v after the notice: settling = %v, want %v", row.heard, got, row.want)
		}
	}
	if !c.settling(0) {
		t.Error("a worker that has heard nothing at all since the notice is not settling")
	}
}

// The per-worker rule behind a notice: the same checks in the same order, on
// shorter times.
func TestLivenessVerdictBehindARestartNotice(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0.Add(2 * time.Minute)
	base := livenessInput{Now: now, PrevTick: now.Add(-livenessTick), ReadyAt: t0, LastRx: now, AnyRx: now, Settling: true}
	probeOut := func(first, last time.Duration, live int) func(*livenessInput) {
		return func(in *livenessInput) {
			in.LastRx = now.Add(-first - 2*time.Second)
			in.ProbeSentAt, in.LastProbeAt, in.LiveProbes = now.Add(-first), now.Add(-last), live
		}
	}
	ordinary := func(mod func(*livenessInput)) func(*livenessInput) {
		return func(in *livenessInput) { mod(in); in.Settling = false }
	}
	silent := func(d time.Duration) func(*livenessInput) {
		return func(in *livenessInput) { in.LastRx = now.Add(-d) }
	}
	fresh := func(ready, quiet time.Duration) func(*livenessInput) {
		return func(in *livenessInput) { in.ReadyAt, in.LastRx = now.Add(-ready), now.Add(-quiet) }
	}
	cases := []struct {
		name string
		mod  func(*livenessInput)
		want livenessAction
	}{
		{"heard just now", func(*livenessInput) {}, livenessNone},
		{"silent 1.9 s", silent(1900 * time.Millisecond), livenessNone},
		{"silent 2 s: asked", silent(2 * time.Second), livenessProbe},
		{"silent 2 s without a notice: not yet", ordinary(silent(2 * time.Second)), livenessNone},
		{"ready 1.9 s ago: not judged yet", fresh(1900*time.Millisecond, 1900*time.Millisecond), livenessNone},
		{"ready 3 s ago and silent since: asked", fresh(3*time.Second, 3*time.Second), livenessProbe},
		{"ready 3 s ago without a notice: the ordinary grace", ordinary(fresh(3*time.Second, 3*time.Second)), livenessNone},
		{"two counted re-sends, 10 s after the first probe: given up on", probeOut(10*time.Second, 5*time.Second, 2), livenessRestart},
		{"the same without a notice: asked again", ordinary(probeOut(10*time.Second, 5*time.Second, 2)), livenessReprobe},
		{"two counted re-sends, 9 s after the first probe: asked again", probeOut(9*time.Second, 5*time.Second, 2), livenessReprobe},
		{"ONE counted re-send, however long: asked again", probeOut(25*time.Second, 5*time.Second, 1), livenessReprobe},
		{"the last send a second ago: nothing yet", probeOut(15*time.Second, time.Second, 2), livenessNone},
		{"a late tick judges nothing", func(in *livenessInput) {
			silent(20 * time.Second)(in)
			in.PrevTick = now.Add(-livenessTick - descheduledSlack - time.Second)
		}, livenessResetAll},
		{"nobody has heard anything for 30 s: the path, not the worker", func(in *livenessInput) {
			silent(40 * time.Second)(in)
			in.AnyRx = now.Add(-probeAfter)
		}, livenessNone},
		{"the probe has been answered: its state comes down", func(in *livenessInput) {
			probeOut(15*time.Second, 5*time.Second, 2)(in)
			in.Answered = true
		}, livenessAnswered},
	}
	for _, tc := range cases {
		in := base
		tc.mod(&in)
		if got := livenessVerdict(in); got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The deafness rule behind a notice: the same checks on shorter times — and
// the silence that starts a round stays above a tick.
func TestDeafVerdictBehindARestartNotice(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0.Add(10 * time.Minute)
	base := deafInput{Now: now, PrevTick: now.Add(-livenessTick), Judgeable: 3, AnyRx: now.Add(-time.Second), Settling: true}
	quiet := func(d time.Duration) func(*deafInput) { return func(in *deafInput) { in.AnyRx = now.Add(-d) } }
	round := func(listened time.Duration, wake bool) func(*deafInput) {
		return func(in *deafInput) {
			in.AnyRx, in.RoundOut, in.RoundIsWake, in.RoundListened = now.Add(-time.Minute), true, wake, listened
		}
	}
	ordinary := func(mod func(*deafInput)) func(*deafInput) {
		return func(in *deafInput) { mod(in); in.Settling = false }
	}
	cases := []struct {
		name string
		mod  func(*deafInput)
		want deafAction
	}{
		{"heard a second ago", func(*deafInput) {}, deafNone},
		{"silent a tick and a half: the answers of a tick ago keep it fresh", quiet(7500 * time.Millisecond), deafNone},
		{"silent 8 s: everybody is asked", quiet(8 * time.Second), deafProbeAll},
		{"silent 8 s without a notice: nothing", ordinary(quiet(8 * time.Second)), deafNone},
		{"the round listened to for 5 s: asked again", round(5*time.Second, false), deafAskAgain},
		{"the round listened to for 10 s: everybody replaced", round(10*time.Second, false), deafRestartAll},
		{"the same without a notice: asked again", ordinary(round(10*time.Second, false)), deafAskAgain},
		{"a wake round keeps its own five seconds", round(5*time.Second, true), deafRestartAll},
		{"… and is not judged before them", round(4*time.Second, true), deafNone},
		{"a late tick judges nothing", func(in *deafInput) {
			round(time.Minute, false)(in)
			in.PrevTick = now.Add(-livenessTick - descheduledSlack - time.Second)
		}, deafNone},
		{"nobody ready: nobody to be deaf", func(in *deafInput) {
			round(time.Minute, false)(in)
			in.Judgeable = 0
		}, deafNone},
		{"the round is answered", func(in *deafInput) {
			round(time.Minute, false)(in)
			in.RoundAnswered, in.AnyRx = true, now.Add(-time.Second)
		}, deafNone},
		{"a restart-all a moment ago holds the next", func(in *deafInput) {
			round(time.Minute, false)(in)
			in.LastRestartAll, in.Rounds = now.Add(-5*time.Second), 1
		}, deafHeld},
	}
	for _, tc := range cases {
		in := base
		tc.mod(&in)
		if got := deafVerdict(in); got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.name, got, tc.want)
		}
	}
}

// One worker was taken back by the server that went; the other is on the one
// that came back and hears. The dead one is asked at the first tick, asked
// again at the next two — each re-send with the client hearing before and
// after it — and given up on at the fourth: twenty seconds after its last
// word, not the minute the ordinary times add up to.
func TestAWorkerTakenBackBehindARestartNoticeIsFoundOutInSeconds(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	c.noticeAt.Store(time.Now().UnixNano()) // the server said it is restarting; both workers have asked again since
	c.Blackhole(2, true)                    // worker 2 asked the server that went: nothing it is sent arrives
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for s := 5; s <= 15; s += 5 {
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	if st := c.Stats(); st.Probes != 1 || st.Reprobes != 2 || st.LostWorkers != 0 {
		t.Fatalf("fifteen seconds in: %d first probe(s), %d re-send(s), %d worker(s) given up on — want 1, 2, 0", st.Probes, st.Reprobes, st.LostWorkers)
	}
	othersHear(c, at(20), 1)
	tick(t, c, at(20))
	if st := c.Stats(); st.LostWorkers != 1 || st.DeafAll != 0 {
		t.Fatalf("twenty seconds in: %d worker(s) given up on, %d restart-all(s) — want 1 and 0", st.LostWorkers, st.DeafAll)
	}
}

// Every worker was taken back: nobody hears anything. Eight seconds of that
// start a round, the round is asked again a tick later and judged at the
// next: everybody replaced twenty seconds after the last word, not sixty.
// The per-worker rule gives nobody up meanwhile — its re-sends count only
// while the client hears.
func TestWorkersAllTakenBackBehindARestartNoticeAreReplacedInSeconds(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	c.noticeAt.Store(time.Now().UnixNano())
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	step := func(s int) { c.monitorStep(start.Add(time.Duration(s) * time.Second)) }
	for s := 5; s <= 15; s += 5 {
		step(s)
		if st := c.Stats(); st.DeafAll != 0 || st.LostWorkers != 0 {
			t.Fatalf("%d s in: %d restart-all(s), %d worker(s) given up on — want none yet", s, st.DeafAll, st.LostWorkers)
		}
	}
	step(20)
	if st := c.Stats(); st.DeafAll != 1 || st.LostWorkers != 0 {
		t.Fatalf("twenty seconds in: %d restart-all(s), %d worker(s) given up on one by one — want 1 and 0", st.DeafAll, st.LostWorkers)
	}
}

// Past the settle time the ordinary times are back: a worker that goes
// silent then is not asked after two seconds.
func TestPastTheSettleTimeTheOrdinaryTimesAreBack(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	c.noticeAt.Store(time.Now().Add(-time.Minute).UnixNano()) // a restart a minute ago; both workers have heard the server since
	c.Blackhole(2, true)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	for s := 5; s <= 25; s += 5 {
		now := start.Add(time.Duration(s) * time.Second)
		othersHear(c, now, 1)
		tick(t, c, now)
	}
	if st := c.Stats(); st.Probes != 0 || st.LostWorkers != 0 || st.DeafAll != 0 {
		t.Fatalf("twenty-five seconds of one worker's silence a minute behind a restart: %d probe(s), %d given up on, %d restart-all(s) — want none", st.Probes, st.LostWorkers, st.DeafAll)
	}
}

// Who is settling is a FACT — the last REAL inbound — and no clock reset can
// settle anybody: a late tick restarts every silence clock at "now", long
// past the settle time, and a worker that has still heard nothing real since
// the notice keeps the short times.
func TestAClockResetSettlesNobody(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	c.noticeAt.Store(time.Now().UnixNano())
	c.Blackhole(2, true)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.monitorStep(at(60)) // a late tick: every clock restarts a minute on
	if n := c.resets.Load(); n != 1 {
		t.Fatalf("the fixture: the late tick was not read as one (resets %d)", n)
	}
	for s := 65; s <= 75; s += 5 {
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	othersHear(c, at(80), 1)
	tick(t, c, at(80))
	if st := c.Stats(); st.Probes != 1 || st.LostWorkers != 1 {
		t.Fatalf("twenty seconds behind the reset: %d first probe(s), %d worker(s) given up on — want 1 and 1: the reset settled a worker that heard nothing", st.Probes, st.LostWorkers)
	}
}

// On an idle tunnel the workers that hear are heard once a tick — as answers
// to probes. That silence of nearly a tick must not start a round: a round
// asks everybody afresh, a fresh ask replaces the dead worker's standing
// probe, and it would never be given up on.
func TestAnIdleTunnelsTickOfSilenceStartsNoRound(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	c.noticeAt.Store(time.Now().UnixNano())
	c.Blackhole(2, true)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	for s := 5; s <= 20; s += 5 {
		now := start.Add(time.Duration(s) * time.Second)
		c.anyRx.Store(now.Add(-4900 * time.Millisecond).UnixNano()) // the last anybody heard: the answers of a tick ago
		c.workers[0].lastRx.Store(now.UnixNano())
		tick(t, c, now)
	}
	if st := c.Stats(); st.LostWorkers != 1 || st.DeafAll != 0 {
		t.Fatalf("twenty seconds in: %d worker(s) given up on, %d restart-all(s) — want 1 and 0: a round kept asking the dead worker afresh", st.LostWorkers, st.DeafAll)
	}
}
