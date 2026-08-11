package proxy

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN returns one packet per Read after a settable delay, so a test can
// stage either of the two worlds the instrument has to tell apart.
type fakeTUN struct {
	readDelay time.Duration
	size      int
	calls     atomic.Int64
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.calls.Add(1)
	time.Sleep(f.readDelay)
	sizes[0] = f.size
	return 1, nil
}
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (f *fakeTUN) File() *os.File                               { return nil }
func (f *fakeTUN) MTU() (int, error)                            { return 1280, nil }
func (f *fakeTUN) Name() (string, error)                        { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event                     { return nil }
func (f *fakeTUN) Close() error                                 { return nil }
func (f *fakeTUN) BatchSize() int                               { return 1 }

func resetTunStats() {
	tunReadNs.Store(0)
	tunGapNs.Store(0)
	tunReads.Store(0)
	tunReadPkts.Store(0)
	tunReadBytes.Store(0)
	tunLastRet.Store(0)
	tunLastSummary.Store(0)
	tunStalls.Store(0)
	tunStallNs.Store(0)
	tunStallMax.Store(0)
}

// 🎯🎯 THE TEST THAT JUSTIFIES THE FIELD, and the one to run before deleting it
// as redundant: it stages the exact arithmetic from tunStallNsThreshold's comment
// and shows the MEAN cannot see what the stall accounting can.
//
// A second in which the phone hands over a stream of packets and then stands
// still must look, in the mean, exactly like a second in which it did not stand
// still. If this ever stops being true the field is genuinely redundant; while it
// is true, the mean is the wrong instrument for the question "why does the sender
// wait" and this is the evidence.
func TestTheMeanCannotSeeAStallButTheStallCounterCan(t *testing.T) {
	const fast = 200

	run := func(stall time.Duration) (mean time.Duration, out string) {
		resetTunStats()
		f := &fakeTUN{readDelay: 0, size: 1280}
		d := WrapTUNForStats(f)
		bufs, sizes := [][]byte{make([]byte, 2048)}, make([]int, 1)
		tunReadSummary() // start the window
		for i := 0; i < fast; i++ {
			if _, err := d.Read(bufs, sizes, 0); err != nil {
				t.Fatal(err)
			}
		}
		if stall > 0 {
			f.readDelay = stall
			if _, err := d.Read(bufs, sizes, 0); err != nil {
				t.Fatal(err)
			}
			f.readDelay = 0
		}
		// Snapshot the mean before the summary clears the interval.
		reads := tunReads.Load()
		mean = time.Duration(tunReadNs.Load() / reads)
		return mean, tunReadSummary()
	}

	quiet, quietOut := run(0)
	stalled, stalledOut := run(60 * time.Millisecond)

	// The mean moves by the stall spread over every read — a few hundred µs on
	// 200 reads. That is the blindness, stated as an assertion.
	if stalled > 2*time.Millisecond {
		t.Fatalf("staging is wrong: the mean rose to %v, so the stall is NOT being "+
			"diluted and this test proves nothing about the mean's blindness", stalled)
	}
	t.Logf("mean wait per read: %v without a stall, %v with a 60 ms one", quiet, stalled)

	if strings.Contains(quietOut, "tun-stall=") {
		t.Errorf("an interval with no stall printed one: %q — a zero here would be "+
			"quotable later as \"measured, the phone never waited\"", quietOut)
	}
	if !strings.Contains(stalledOut, "tun-stall=1/") {
		t.Errorf("the 60 ms stall was not reported: %q", stalledOut)
	}
	// max must be the real duration, not a bucket edge: this is the number that
	// answers "how long did the device stand still".
	if !strings.Contains(stalledOut, "max=6") { // 60ms, rounded to ms
		t.Errorf("summary %q does not carry the stall's true length", stalledOut)
	}
}

// Ordinary inter-packet gaps must not be counted, or a loaded second reads as
// one long stall and the field becomes another restatement of the packet rate.
func TestShortWaitsAreNotStalls(t *testing.T) {
	resetTunStats()
	d := WrapTUNForStats(&fakeTUN{readDelay: 2 * time.Millisecond, size: 1280})
	bufs, sizes := [][]byte{make([]byte, 2048)}, make([]int, 1)
	tunReadSummary()
	for i := 0; i < 20; i++ {
		if _, err := d.Read(bufs, sizes, 0); err != nil {
			t.Fatal(err)
		}
	}
	if out := tunReadSummary(); strings.Contains(out, "tun-stall=") {
		t.Errorf("2 ms waits were counted as stalls: %q — the threshold is %v and "+
			"must stay well above the ordinary gap", out, time.Duration(tunStallNsThreshold))
	}
}

// 🎯 THE WHOLE POINT: the instrument must separate STARVED from SLOW. If it
// cannot, it answers nothing and should not be shipped — the sendCh depth
// counter looked fine for two days and could not make this same distinction.
func TestTunStatsSeparatesStarvedFromSlow(t *testing.T) {
	const iters = 40

	// STARVED: Read blocks a long time, the consumer does nothing between reads.
	resetTunStats()
	d := WrapTUNForStats(&fakeTUN{readDelay: 3 * time.Millisecond, size: 1280})
	bufs, sizes := [][]byte{make([]byte, 2048)}, make([]int, 1)
	tunReadSummary() // start the window
	for i := 0; i < iters; i++ {
		if _, err := d.Read(bufs, sizes, 0); err != nil {
			t.Fatal(err)
		}
	}
	starved := tunReadSummary()
	starvedPct := pctFrom(t, starved)
	if starvedPct < 80 {
		t.Fatalf("starved case reads %.1f%% inside Read, want >80: %s", starvedPct, starved)
	}

	// SLOW: Read returns at once, the consumer burns the time instead.
	resetTunStats()
	d = WrapTUNForStats(&fakeTUN{readDelay: 0, size: 1280})
	tunReadSummary()
	for i := 0; i < iters; i++ {
		if _, err := d.Read(bufs, sizes, 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Millisecond) // wireguard-go's own processing
	}
	slow := tunReadSummary()
	slowPct := pctFrom(t, slow)
	if slowPct > 20 {
		t.Fatalf("slow case reads %.1f%% inside Read, want <20: %s", slowPct, slow)
	}

	if starvedPct-slowPct < 50 {
		t.Fatalf("the two worlds differ by only %.1f points (%.1f vs %.1f) — the "+
			"instrument cannot tell them apart", starvedPct-slowPct, starvedPct, slowPct)
	}
}

// An interval with no reads must print NOTHING, not a row of zeroes: a zero
// share would read as "never waiting", i.e. the opposite of the truth.
func TestTunStatsSaysNothingWhenItMeasuredNothing(t *testing.T) {
	resetTunStats()
	if s := tunReadSummary(); s != "" {
		t.Fatalf("printed %q with no reads — a build without the wrapper would "+
			"look like a measurement", s)
	}
}

// The counters must reset per interval, or every line reports the whole session
// and a late regression is averaged away.
func TestTunStatsResetsEachInterval(t *testing.T) {
	resetTunStats()
	d := WrapTUNForStats(&fakeTUN{readDelay: time.Millisecond, size: 900})
	bufs, sizes := [][]byte{make([]byte, 2048)}, make([]int, 1)
	tunReadSummary()
	for i := 0; i < 5; i++ {
		_, _ = d.Read(bufs, sizes, 0)
	}
	if first := tunReadSummary(); first == "" {
		t.Fatal("no line after 5 reads")
	}
	if second := tunReadSummary(); second != "" {
		t.Fatalf("counters survived the dump: %q", second)
	}
}

func pctFrom(t *testing.T, line string) float64 {
	t.Helper()
	i := strings.Index(line, "tun-read=")
	if i < 0 {
		t.Fatalf("no tun-read= in %q", line)
	}
	rest := line[i+len("tun-read="):]
	j := strings.Index(rest, "%")
	if j < 0 {
		t.Fatalf("no %% in %q", line)
	}
	var v float64
	if _, err := fmt.Sscanf(rest[:j], "%f", &v); err != nil {
		t.Fatalf("parse %q: %v", rest[:j], err)
	}
	return v
}
