package speedtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
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
		s, err := runPhase(context.Background(), warm,
			func() int64 { return counter.Load() },
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
	s, err := runPhase(context.Background(), 500*time.Millisecond,
		func() int64 { return 0 },
		func(context.Context) error { time.Sleep(20 * time.Millisecond); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if s.ok {
		t.Fatal("claims a warm-up boundary that never came")
	}
	start := time.Now().Add(-20 * time.Millisecond)
	p := applyWindow(Phase{Bytes: 1234, ActualSec: 0.02}, s, start, time.Now(), 1234)
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

	p := measure(1e6, 40e6, start, end, false, 0, 0)
	p = applyWindow(p, warmSample{warmup: 5 * time.Second, bytes: 10e6, at: warmAt, ok: true}, start, end, 40e6)

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

// TestIDLookupDoesNotCallEveryFailureNotFound.
//
// 🚨 "There is no server with id X" is a CLAIM about Ookla's database, and only
// one failure supports it. Collapsing a timeout or a malformed response into it
// tells a user with a perfectly good id that their server does not exist — and
// the reasonable reaction to that is to stop trying the id, which is the one
// thing they should keep doing.
//
// Seen RED by restoring `if err != nil || server == nil`.
func TestIDLookupDoesNotCallEveryFailureNotFound(t *testing.T) {
	// A server that answers everything with garbage: the XML decode fails, which
	// is emphatically not "no such id".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not xml"))
	}))
	defer srv.Close()

	// Point the library's advanced-server endpoint at it by using a context that
	// is already dead — the same class of failure, reached without patching a
	// package-level URL.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := FindServers(ctx, "31551")
	if err == nil {
		t.Fatal("a cancelled lookup reported success")
	}
	if strings.Contains(err.Error(), "no server with id") {
		t.Errorf("a cancelled lookup was reported as %q — that is a claim about Ookla's "+
			"database, and this failure says nothing about it", err)
	}
}
