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
