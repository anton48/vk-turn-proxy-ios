package speedtest

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	stgo "github.com/showwin/speedtest-go/speedtest"
	"time"
)

// TestEngineVersionNamesEveryForkDivergence closes the traceability loop from
// this side: FORK.md documents the divergences, and the number reported beside
// every result must name all of them.
//
// The other half lives in the fork: TestForkDivergesFromUpstreamExactlyHere
// fails on a divergence nobody wrote down. Together, a change to the
// methodology cannot reach a user's screen under an unchanged label.
//
// Seen RED by adding a sixth "## Divergence 6:" section to FORK.md.
// TestEngineVersionNamesEveryMethodRevision is the same loop as the fork's, for
// the half the fork guard cannot see.
//
// 🚨 IT EXISTS BECAUSE THE FORK REVISION ALONE WAS NOT ENOUGH. Builds 315-318
// reported one unchanging version while the wrapper changed what a thread is,
// what the connection count counts, and whether a phase was primed — four
// mutually incomparable methodologies under one label.
//
// Seen RED by adding a sixth "## Method 6" section to METHOD.md.
func TestEngineVersionNamesEveryMethodRevision(t *testing.T) {
	b, err := os.ReadFile("METHOD.md")
	if err != nil {
		t.Fatalf("read METHOD.md: %v", err)
	}
	found := regexp.MustCompile(`(?m)^## Method (\d+) `).FindAllStringSubmatch(string(b), -1)
	if len(found) == 0 {
		t.Fatal("no '## Method N ' sections found — the anchor is wrong and this check would " +
			"pass on any tree")
	}
	if len(found) != methodRevision {
		t.Errorf("METHOD.md documents %d method revisions but methodRevision is %d — bump the "+
			"constant, or the next run will be labelled as comparable with runs it is not",
			len(found), methodRevision)
	}
	for _, want := range []string{"+fork.", "vkturn-method."} {
		if !strings.Contains(EngineVersion, want) {
			t.Errorf("EngineVersion %q does not carry %q", EngineVersion, want)
		}
	}
	// The User-Agent must carry them too: a server operator's log, or a capture
	// read months later, is often the only surviving record of a run.
	for _, want := range []string{"fork.", "vkturn-speedtest/"} {
		if !strings.Contains(UserAgent, want) {
			t.Errorf("UserAgent %q does not carry %q", UserAgent, want)
		}
	}
}

func TestEngineVersionNamesEveryForkDivergence(t *testing.T) {
	const forkMD = "../../third_party/speedtest-go/FORK.md"
	b, err := os.ReadFile(forkMD)
	if err != nil {
		t.Fatalf("read %s: %v", forkMD, err)
	}
	found := regexp.MustCompile(`(?m)^## Divergence (\d+):`).FindAllStringSubmatch(string(b), -1)
	if len(found) == 0 {
		t.Fatal("no '## Divergence N:' sections found — the anchor is wrong and the check below " +
			"would pass on any tree")
	}
	if len(found) != forkRevision {
		t.Errorf("FORK.md documents %d divergences but forkRevision is %d — bump the constant "+
			"(EngineVersion is what traces a measurement to the methodology that produced it)",
			len(found), forkRevision)
	}
	if !strings.Contains(EngineVersion, "+fork.") {
		t.Errorf("EngineVersion %q does not name the fork revision", EngineVersion)
	}
}

func TestPlanRefusesConfigsTheCSurfaceCouldDeliver(t *testing.T) {
	// wgSpeedtestStart unmarshals arbitrary JSON, so these are reachable even
	// though the Swift screen constrains all three.
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"threads above the cap spawns that many workers", Config{Threads: 10000, DurationSec: 15}},
		{"an unknown direction measured NOTHING and reported done", Config{Threads: 4, Direction: "sideways", DurationSec: 15}},
		{"duration far above anything the UI offers", Config{Threads: 4, DurationSec: 100000}},
		{"duration below the engine's own floor", Config{Threads: 4, DurationSec: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := plan(tc.cfg); err == nil {
				t.Error("accepted")
			}
		})
	}

	t.Run("research extends the capture and disables early stop", func(t *testing.T) {
		p, err := plan(Config{Threads: 4, DurationSec: 15, Research: true})
		if err != nil {
			t.Fatal(err)
		}
		if p.capture != 20*time.Second {
			t.Errorf("capture %v, want 20s (15s window + 5s warm-up) — a warm-up discarded "+
				"without extending the capture shortens the window it was meant to protect", p.capture)
		}
		if p.earlyStop {
			t.Error("early stop still on: the fixed window is neither fixed nor a window")
		}
	})

	t.Run("standard mode keeps early stop", func(t *testing.T) {
		p, err := plan(Config{Threads: 4, DurationSec: 15})
		if err != nil {
			t.Fatal(err)
		}
		if !p.earlyStop || p.warmup != 0 || p.capture != 15*time.Second {
			t.Errorf("standard plan is %+v", p)
		}
	})
}

// TestRunPhaseDeliversTheWarmupSample must be run with -race.
//
// It covers two distinct defects in the same six lines:
//
//   - the sample used to be written into the enclosing function's NAMED RETURN
//     VALUES by the goroutine and read by the caller with only a closed channel
//     between them — a signal, not a happens-before edge. `-race` reports it.
//   - the obvious repair, a non-blocking `select/default` receive, compiles and
//     looks right and silently LOSES the sample whenever the goroutine has not
//     sent yet, which reads downstream as a run that had no warm-up.
//
// 🚨 THE TIMING IS THE TEST. With a phase much longer than the warm-up the
// goroutine has long since sent into the buffered channel, so a non-blocking
// receive finds the value and PASSES — I verified that, and an earlier version
// of this test was vacuous for exactly that reason. The phase must end AT the
// boundary, repeatedly, so the goroutine is still in flight when we read.
//
// The discriminator is `warmup`: the goroutine stamps it on every path, so a
// zero there means we read a zero value instead of the goroutine's sample.
//
// Seen RED under: the named-return version (DATA RACE), and the select/default
// receive (sample lost).
func TestRunPhaseDeliversTheWarmupSample(t *testing.T) {
	var counter atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				counter.Add(1000)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	defer close(stop)

	const warm = 30 * time.Millisecond
	for i := 0; i < 200; i++ {
		s, _, err := runPhase(context.Background(), warm, 0,
			func() (int64, int64) { return counter.Load(), 0 },
			// Ends AT the boundary: the goroutine is racing us to send.
			func(context.Context) error { time.Sleep(warm); return nil })
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if s.warmup != warm {
			t.Fatalf("iteration %d returned a zero sample (warmup=%v, want %v) — the goroutine's "+
				"value was dropped, so a research run would report the warm-up as measured data",
				i, s.warmup, warm)
		}
		if s.ok && (s.bytes <= 0 || s.at.IsZero()) {
			t.Fatalf("iteration %d: sample claims a boundary but is empty: %+v", i, s)
		}
	}
}

// A phase shorter than its own warm-up must not produce a rate.
func TestRunPhaseShorterThanItsWarmup(t *testing.T) {
	s, _, err := runPhase(context.Background(), 500*time.Millisecond, 0,
		func() (int64, int64) { return 0, 0 },
		func(context.Context) error { time.Sleep(20 * time.Millisecond); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if s.ok {
		t.Fatal("claims a warm-up boundary that never came")
	}
	start := time.Now().Add(-20 * time.Millisecond)
	p := applyWindow(Phase{Bytes: 1234, ActualSec: 0.02}, s, warmSample{}, start, time.Now(), 1234, 0, false, 8)
	if p.RawMbps != 0 {
		t.Errorf("stated %v Mbit/s from a 0.02s window", p.RawMbps)
	}
	if len(p.Warnings) == 0 {
		t.Error("no warning: a figure covering the warm-up is not the figure research mode promises")
	}
}

// The two halves must ADD UP to the whole, because the UI prints all three and
// must never have to subtract.
func TestWindowSplitSumsToActual(t *testing.T) {
	start := time.Now()
	warmAt := start.Add(5 * time.Second)
	end := start.Add(20 * time.Second)

	p := measure(1e6, 40e6, start, end, false)
	p = applyWindow(p, warmSample{warmup: 5 * time.Second, bytes: 10e6, at: warmAt, ok: true}, warmSample{}, start, end, 40e6, 0, false, 8)

	if got := p.WarmupSec + p.WindowSec; got < p.ActualSec-0.01 || got > p.ActualSec+0.01 {
		t.Errorf("warmup %.3f + window %.3f = %.3f, but actual is %.3f",
			p.WarmupSec, p.WindowSec, got, p.ActualSec)
	}
	// 30 MB over the 15 s window, not 40 MB over 20 s.
	if want := 30e6 * 8 / 15 / 1e6; p.RawMbps < want-0.5 || p.RawMbps > want+0.5 {
		t.Errorf("raw %.2f Mbit/s, want ~%.2f — the rate must cover the WINDOW, not the phase",
			p.RawMbps, want)
	}
}

func TestApplyConnStatsWarnsWhenThreadsDidNotBecomeConnections(t *testing.T) {
	p := applyConnStats(Phase{}, 1, 1, 8, true)
	if len(p.Warnings) == 0 {
		t.Error("8 threads on 1 connection passed without a word — that is the HTTP/2 state " +
			"every thread-count comparison was taken in before 2026-08-20")
	}
	if q := applyConnStats(Phase{}, 8, 8, 8, true); len(q.Warnings) != 0 {
		t.Errorf("healthy phase warned: %v", q.Warnings)
	}
}

// TestOneActivityAtATime guards the mutual exclusion the previous `running`
// bool did not provide.
//
// 🚨 READING A FLAG IS NOT TAKING A GUARD. Servers() used to read `running` and
// release the lock, so a fetch could begin in the instant before a run claimed
// it, a run could start while a fetch was in flight, and nothing stopped two
// fetches at once. Every one of those puts the engine's concurrent
// ping-every-server fan-out inside a measurement.
//
// Seen RED by replacing claim() with a read-then-set pair.
func TestOneActivityAtATime(t *testing.T) {
	defer release()

	if err := claim(runningTest); err != nil {
		t.Fatalf("claiming from idle: %v", err)
	}
	if err := claim(loadingServers); err == nil {
		t.Error("🚨 a server-list fetch was allowed DURING a run — it pings every server at once")
	}
	if err := claim(runningTest); err == nil {
		t.Error("a second run was allowed during the first")
	}
	release()

	// And the other direction, which the bool never covered at all.
	if err := claim(loadingServers); err != nil {
		t.Fatalf("claiming from idle: %v", err)
	}
	if err := claim(runningTest); err == nil {
		t.Error("🚨 a run was allowed while a server-list fetch was in flight")
	}
	if err := claim(loadingServers); err == nil {
		t.Error("two concurrent server-list fetches were allowed")
	}
}

// A refused Start must not leave the package busy, or the feature is dead for
// the life of the process.
func TestRefusedStartLeavesNoClaim(t *testing.T) {
	if err := Start(Config{Threads: 10000, DurationSec: 15}); err == nil {
		t.Fatal("an out-of-range config was accepted")
	}
	if err := claim(runningTest); err != nil {
		t.Fatalf("🚨 the package is still busy after a REFUSED start: %v", err)
	}
	release()
}

// TestEveryPhaseIsPrimedBeforeItCounts guards an ORDERING, and it is a source
// scan because run() needs a live server list to execute.
//
// The order is the whole point: priming must open a connection BEFORE the
// counter is reset, so the phase starts with a reusable connection and a clean
// count. Prime after the reset and the priming connection is counted as
// measurement; omit it and the phase cannot detect HTTP/2 at all
// (TestUnprimedPhaseCannotSeeHTTP2 measures that).
//
// 🚨 THE SABOTAGE FOR AN ORDERING GUARD IS A REORDERING, NOT A DELETION —
// deleting the prime call reddens the "exists" half for a different reason, and
// a red run for the wrong reason is how this project has fooled itself before.
// Both were run: swapping the two lines reddens the order check alone.
func TestEveryPhaseIsPrimedBeforeItCounts(t *testing.T) {
	src, err := os.ReadFile("speedtest.go")
	if err != nil {
		t.Fatalf("read speedtest.go: %v", err)
	}
	body := string(src)

	start := strings.Index(body, "for _, name := range order {")
	if start < 0 {
		t.Fatal("the phase loop was not found — this scan would pass vacuously; fix the anchor")
	}
	loop := body[start:]
	if end := strings.Index(loop, "\n\treturn nil"); end > 0 {
		loop = loop[:end]
	}

	prime := strings.Index(loop, "meas.prime(ctx,")
	reset := strings.Index(loop, "meas.conns.reset()")
	stats := strings.Index(loop, "meas.conns.stats()")

	if prime < 0 {
		t.Fatal("🚨 the phase does not prime a connection — an unprimed phase reads N connections " +
			"whatever the protocol, so the HTTP/2 guard is inert")
	}
	if reset < 0 || stats < 0 {
		t.Fatal("the counter is no longer reset or read inside the phase loop")
	}
	if prime > reset {
		t.Error("🚨 priming happens AFTER the counter is reset, so the primed connection is " +
			"counted as measurement capacity — the figure reads one too high")
	}
	if reset > stats {
		t.Error("the counter is read before it is reset")
	}
}

// TestIDLookupDoesNotCallEveryFailureNotFound exercises the RULE, not the
// network.
//
// 🚨 An earlier version of this test stood up an httptest.Server serving
// malformed XML, said in its comment that it tested a malformed response — and
// never used the server. What it actually exercised was a cancelled context.
// Dead scaffolding makes a test look more thorough than it is, and the comment
// made a claim the code did not support.
//
// The classification is a pure function now, so every outcome is reachable
// without a socket: only ErrServerNotFound may be reported as "no server with
// id", because only it says anything about whether the server exists.
//
// Seen RED by collapsing the switch back to `if err != nil || server == nil`.
func TestIDLookupDoesNotCallEveryFailureNotFound(t *testing.T) {
	notFound := "no server with id"

	for _, tc := range []struct {
		name       string
		err        error
		claimsGone bool
	}{
		{"the library says it is not there", stgo.ErrServerNotFound, true},
		{"a cancelled lookup", context.Canceled, false},
		{"a deadline", context.DeadlineExceeded, false},
		{"a malformed response", errors.New("XML syntax error on line 1"), false},
		{"a refused connection", errors.New("dial tcp: connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := idLookupError("31551", nil, tc.err)
			if err == nil {
				t.Fatal("reported success")
			}
			claims := strings.Contains(err.Error(), notFound)
			if claims != tc.claimsGone {
				t.Errorf("reported %q — claims the server does not exist: %v, want %v. "+
					"Only Ookla saying so supports that claim; anything else leaves the user "+
					"abandoning an id that is fine.", err, claims, tc.claimsGone)
			}
		})
	}

	// A successful lookup is not an error at all.
	if err := idLookupError("31551", &stgo.Server{ID: "31551"}, nil); err != nil {
		t.Errorf("a successful lookup was reported as %v", err)
	}
}

// TestWindowBytesMatchesTheRateItProduced: a logged line must be checkable by
// arithmetic in BOTH modes.
//
// 🚨 Bytes is the WHOLE phase and RawMbps covers the measurement window, so in
// research mode `Bytes / WindowSec` does not equal RawMbps — a reader doing the
// obvious check on a correct line concludes the tool is lying. WindowBytes is
// what the rate was actually computed from.
//
// Seen RED by leaving WindowBytes unset in applyWindow's research branch.
func TestWindowBytesMatchesTheRateItProduced(t *testing.T) {
	start := time.Now()
	warmAt := start.Add(5 * time.Second)
	end := start.Add(20 * time.Second)

	p := measure(1e6, 40e6, start, end, false)
	p = applyWindow(p, warmSample{warmup: 5 * time.Second, bytes: 10e6, at: warmAt, ok: true}, warmSample{},
		start, end, 40e6, 0, false, 8)

	if p.WindowBytes != 30e6 {
		t.Errorf("WindowBytes = %d, want 30000000 (40 MB total minus the 10 MB warm-up)", p.WindowBytes)
	}
	if p.Bytes == p.WindowBytes {
		t.Error("Bytes and WindowBytes are equal in a research run — one of them is wrong, " +
			"and the whole point is that they differ")
	}
	// The check a reader would do, on the right field.
	implied := float64(p.WindowBytes) * 8 / p.WindowSec / 1e6
	if implied < p.RawMbps-0.5 || implied > p.RawMbps+0.5 {
		t.Errorf("WindowBytes/WindowSec = %.2f but RawMbps = %.2f — the line cannot be verified "+
			"by the arithmetic it invites", implied, p.RawMbps)
	}

	// Outside research mode the two must agree, or the same check breaks there.
	q := measure(1e6, 40e6, start, end, false)
	q = applyWindow(q, warmSample{}, warmSample{}, start, end, 40e6, 0, false, 8)
	if q.WindowBytes != q.Bytes {
		t.Errorf("outside research mode WindowBytes (%d) must equal Bytes (%d)", q.WindowBytes, q.Bytes)
	}
}

// TestConfirmedRatioIsScopedToTheWindow.
//
// 🚨 The ratio exists to qualify the RATE, and the rate covers the measurement
// window — so a phase-scoped ratio qualifies a number that appears nowhere, and
// printed beside window figures it makes a CORRECT line fail its own arithmetic.
// Measured on a research run before this: reported 98.0% while the window bytes
// beside it implied 97.5%.
//
// Seen RED by computing the ratio from the phase totals instead.
func TestConfirmedRatioIsScopedToTheWindow(t *testing.T) {
	start := time.Now()
	warmAt := start.Add(5 * time.Second)
	end := start.Add(20 * time.Second)

	// ⚠️ THE FIXTURE IS CHOSEN SO THE TWO ANSWERS DIFFER. A first version used
	// 400/10 and 1000/25, where the window ratio 600/615 and the phase ratio
	// 1000/1025 are BOTH 40/41 — so the discriminating check could not
	// discriminate. The test caught it; the numbers below do not coincide.
	//
	// Warm-up: 400 MB confirmed with 20 MB outstanding.
	// Whole phase: 1000 MB confirmed with 25 MB outstanding.
	// ⇒ the window moved 600 MB and accumulated only 5 MB of backlog.
	p := measure(1e6, 1000e6, start, end, true)
	p = applyWindow(p, warmSample{warmup: 5 * time.Second, bytes: 400e6, backlog: 20e6,
		at: warmAt, ok: true}, warmSample{}, start, end, 1000e6, 25e6, true, 8)

	if p.WindowBytes != 600e6 {
		t.Fatalf("WindowBytes = %d, want 600000000", p.WindowBytes)
	}
	if p.BacklogBytes != 5e6 {
		t.Errorf("BacklogBytes = %d, want 5000000 — the backlog is a DELTA over the window, "+
			"not the phase's outstanding total", p.BacklogBytes)
	}
	want := 600.0 / 605.0
	if p.ConfirmedRatio < want-0.001 || p.ConfirmedRatio > want+0.001 {
		t.Errorf("ConfirmedRatio = %.4f, want %.4f — it must be derivable from the two byte "+
			"figures printed beside it, or a correct line fails its own check",
			p.ConfirmedRatio, want)
	}
	// The phase-scoped answer, which is what it used to report.
	phase := 1000.0 / 1025.0
	if p.ConfirmedRatio > phase-0.001 && p.ConfirmedRatio < phase+0.001 {
		t.Error("the ratio is still the PHASE's — it disagrees with the window bytes beside it")
	}

	// A server that caught up during the window must not produce a negative
	// backlog: it is a level, and a delta of a level can go either way.
	q := applyWindow(measure(1e6, 1000e6, start, end, true),
		warmSample{warmup: 5 * time.Second, bytes: 400e6, backlog: 40e6, at: warmAt, ok: true}, warmSample{},
		start, end, 1000e6, 25e6, true, 8)
	if q.BacklogBytes != 0 {
		t.Errorf("backlog = %d after the server caught up, want 0", q.BacklogBytes)
	}
}

// 🚨 DOWNLOAD HAS NOTHING TO CONFIRM, and for five method revisions it said it
// had confirmed everything. The ratio came out 1.0 by construction (no backlog
// exists on a GET), which reads as a verdict about the server.
func TestDownloadPublishesNoConfirmationFigure(t *testing.T) {
	start := time.Now()
	end := start.Add(15 * time.Second)
	p := applyWindow(measure(1e6, 400e6, start, end, false), warmSample{}, warmSample{},
		start, end, 400e6, 0, false, 32)

	if p.ConfirmedRatio != 0 {
		t.Errorf("ConfirmedRatio = %.3f on a DOWNLOAD — the field is upload-only and a "+
			"figure of 1.0 reads as 'the server accepted everything'", p.ConfirmedRatio)
	}
	if p.BacklogBytes != 0 {
		t.Errorf("BacklogBytes = %d on a download", p.BacklogBytes)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "confirmed") {
			t.Errorf("a download carries a confirmation warning: %q", w)
		}
	}
}

// 🚨 THE TAIL OF A NORMAL PHASE IS NOT REFUSAL. Every worker is mid-chunk when
// the capture time expires, so a backlog of threads×chunk is what a HEALTHY run
// produces — and the old rule called it a server refusing bytes on every
// 32-thread run we ever took.
func TestCancellationTailIsNotReportedAsRefusal(t *testing.T) {
	start := time.Now()
	end := start.Add(15 * time.Second)

	// The measured 32-thread shape: 452.8 MB in the window, 29.5 MB backlog —
	// a ratio of 93.9%, and every byte of that backlog explained by 32
	// cancelled chunks.
	p := applyWindow(measure(1e6, 452.8e6, start, end, true), warmSample{}, warmSample{},
		start, end, 452.8e6, 29.5e6, true, 32)

	if p.ConfirmedRatio > 0.95 {
		t.Fatalf("precondition failed: ratio %.3f is above the warning threshold, so this "+
			"fixture cannot exercise the rule at all", p.ConfirmedRatio)
	}
	if p.BacklogTailBytes != 32*uploadChunkBytes {
		t.Errorf("BacklogTailBytes = %d, want %d — the line cannot qualify its own backlog "+
			"without it", p.BacklogTailBytes, 32*uploadChunkBytes)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "confirmed by the server") {
			t.Errorf("warned about the cancellation tail: %q\n"+
				"backlog %.1f MB against a %.1f MB ceiling of in-flight chunks",
				w, 29.5, float64(32*uploadChunkBytes)/1e6)
		}
	}
}

// ...and the endpoint the field exists for must still be caught: the Frankfurt
// 307 host confirmed NOTHING while 45.8 MB piled up, which no tail explains.
//
// 🚨 THE FIXTURE IS EXACTLY ZERO CONFIRMED, and the first version of this test
// was not: it pushed 1 MB through, giving a ratio of 0.021, so it exercised a
// shape ADJACENT to the one its own comment claimed. That mattered — with
// `ConfirmedRatio > 0` as the presence test, the real Frankfurt case (0.000) was
// rendered as ABSENT and warned about nowhere, and this test could not see it.
func TestABrokenEndpointStillWarns(t *testing.T) {
	start := time.Now()
	end := start.Add(15 * time.Second)
	p := applyWindow(measure(1e6, 0, start, end, true), warmSample{}, warmSample{},
		start, end, 0, 45.8e6, true, 8)

	if p.ConfirmedRatio != 0 {
		t.Fatalf("precondition failed: ratio %.4f — this fixture must be the EXACT zero, "+
			"which is the value the old presence test could not represent", p.ConfirmedRatio)
	}
	if !p.ConfirmedKnown {
		t.Fatal("a measured zero is reported as UNKNOWN — the one case the field exists for " +
			"would print on no line and warn nowhere")
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "confirmed by the server") {
			found = true
			if !strings.Contains(w, "more backlog") {
				t.Errorf("the warning does not say how much is UNEXPLAINED: %q", w)
			}
		}
	}
	if !found {
		t.Error("45.8 MB of backlog against 8 workers is 5.7x what cancellation can explain, " +
			"and nothing warned — this is the case the field was added for")
	}
}

// 🚨 THE WINDOW MUST CLOSE ON ITS OWN TIMER. `run()` returns only once every
// blocked worker has unwound, so measuring to that moment puts the unwinding
// inside the window: research mode promised a fixed 30 s and produced arms of
// 33.6, 34.1 and 35.0 s in a palindrome whose whole design is that its arms are
// the same length (20.08/speedtest0).
func TestTheWindowClosesOnTimeAndCleanupIsReportedSeparately(t *testing.T) {
	start := time.Now()
	warmAt := start.Add(5 * time.Second)
	closeAt := start.Add(35 * time.Second) // warm-up + the requested 30s
	end := start.Add(38 * time.Second)     // workers took 3s more to let go

	p := measure(1e6, 1000e6, start, end, true)
	p = applyWindow(p,
		warmSample{warmup: 5 * time.Second, bytes: 100e6, backlog: 2e6, at: warmAt, ok: true},
		warmSample{bytes: 700e6, backlog: 5e6, at: closeAt, ok: true},
		start, end, 1000e6, 9e6, true, 8)

	if got := p.WindowSec; got < 29.99 || got > 30.01 {
		t.Errorf("WindowSec = %.2f, want 30.00 — the requested window, not the window plus "+
			"however long the engine took to stop", got)
	}
	if got := p.CleanupSec; got < 2.99 || got > 3.01 {
		t.Errorf("CleanupSec = %.2f, want 3.00", got)
	}
	if got := p.WarmupSec + p.WindowSec + p.CleanupSec; got < p.ActualSec-0.01 || got > p.ActualSec+0.01 {
		t.Errorf("warmup %.2f + window %.2f + cleanup %.2f = %.2f, but the phase took %.2f — "+
			"the three parts must still account for the whole", p.WarmupSec, p.WindowSec,
			p.CleanupSec, got, p.ActualSec)
	}
	// 🚨 The BYTES must come from the boundary too. Taking them at the end
	// counts everything the unwinding workers confirmed, which is exactly the
	// arithmetic that kept `raw` self-consistent while the experiment drifted.
	if p.WindowBytes != 600e6 {
		t.Errorf("WindowBytes = %d, want 600000000 (700 MB at the close minus the 100 MB "+
			"warm-up) — %d means the cleanup's bytes were counted", p.WindowBytes, p.WindowBytes)
	}
	if p.BacklogBytes != 3e6 {
		t.Errorf("BacklogBytes = %d, want 3000000 — the backlog is the window's too", p.BacklogBytes)
	}
}

// Standard mode promises no window — the duration is explicitly a ceiling — so
// there is nothing to enforce and nothing to report as cleanup.
func TestStandardModeHasNoCleanupToReport(t *testing.T) {
	start := time.Now()
	end := start.Add(20 * time.Second)
	p := applyWindow(measure(1e6, 400e6, start, end, false), warmSample{}, warmSample{},
		start, end, 400e6, 0, false, 8)
	if p.CleanupSec != 0 {
		t.Errorf("CleanupSec = %.2f in standard mode", p.CleanupSec)
	}
	if got := p.WindowSec; got < p.ActualSec-0.01 || got > p.ActualSec+0.01 {
		t.Errorf("WindowSec %.2f != ActualSec %.2f — with no promised window the phase's own "+
			"length is the honest answer", got, p.ActualSec)
	}
}

// And the boundary must actually FIRE while the phase is still running: the
// sample is taken by a timer inside runPhase, not by the caller afterwards.
func TestRunPhaseSamplesAtTheWindowBoundary(t *testing.T) {
	var counter int64
	stop := make(chan struct{})
	go func() { // a worker that keeps confirming bytes the whole time
		for {
			select {
			case <-stop:
				return
			default:
				atomic.AddInt64(&counter, 1_000_000)
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()
	defer close(stop)

	sample := func() (int64, int64) { return atomic.LoadInt64(&counter), 0 }
	warm, closed, err := runPhase(context.Background(), 50*time.Millisecond, 100*time.Millisecond,
		sample,
		func(context.Context) error {
			// The engine returns LATE — this is the unwinding the fix exists for.
			time.Sleep(400 * time.Millisecond)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !warm.ok || !closed.ok {
		t.Fatalf("warm.ok=%v closed.ok=%v — both boundaries must fire while the phase runs",
			warm.ok, closed.ok)
	}
	// The window is 100ms; the phase runs 400ms. The defect measures the phase
	// (~350ms from the warm-up boundary), so the bound has to exclude that and
	// admit ordinary scheduling jitter — not merely be "small", which is how the
	// first version of this check managed to demand < 60ms of a 100ms window.
	if d := closed.at.Sub(warm.at); d < 90*time.Millisecond || d > 200*time.Millisecond {
		t.Errorf("the window measured %v, want ~100ms — anything near 350ms means the close "+
			"sample was taken when the phase ENDED, not when the window closed", d)
	}
	if closed.bytes >= atomic.LoadInt64(&counter) {
		t.Error("the close sample carries the FINAL counter, so it was read after the phase " +
			"finished rather than at the boundary")
	}
}

// 🚨 THE PLAN MUST ASK FOR THE BOUNDARY, and that is a separate claim from the
// boundary working. Deleting the request left every other test in this file
// green, because they drive applyWindow and runPhase directly — the same shape
// as a guard that checks only the write half of a two-part hookup.
func TestOnlyResearchModeEnforcesAWindow(t *testing.T) {
	research, err := plan(Config{Threads: 8, Direction: "upload", DurationSec: 30, Research: true})
	if err != nil {
		t.Fatal(err)
	}
	if research.closeWindow() != 30*time.Second {
		t.Errorf("research mode enforces %v, want 30s — a fixed window that is not enforced is "+
			"just a longer ceiling", research.closeWindow())
	}
	standard, err := plan(Config{Threads: 8, Direction: "upload", DurationSec: 30})
	if err != nil {
		t.Fatal(err)
	}
	if standard.closeWindow() != 0 {
		t.Errorf("standard mode enforces %v — early stop means the duration is a CEILING and "+
			"the phase's own end is the honest answer", standard.closeWindow())
	}

	// And the value has to REACH runPhase: computed-and-not-passed is how the
	// first version of this fix stayed green under its own sabotage.
	src, err := os.ReadFile("speedtest.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "runPhase(ctx, pl.warmup, pl.closeWindow()") {
		t.Error("runPhase is not called with pl.closeWindow() — the plan can enforce whatever " +
			"it likes if the phase loop does not pass it")
	}
}
