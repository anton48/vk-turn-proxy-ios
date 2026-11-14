package csqtt25

import (
	"testing"
	"time"
)

// The wire clock measures the stretches in which no stream wrote or heard a
// datagram: a take says how many went out and came in since the take before,
// the longest stretch without one — the one still open included — and how many
// stretches of QuietFloor and more ENDED in it. A stretch belongs whole to
// the take it ends in; a take starts the next measure; a reading older than
// the one before it (two streams at once) ends no stretch.
func TestTheWireClockMeasuresTheStretchesWithoutADatagram(t *testing.T) {
	const s = int64(time.Second)
	var q wireClock
	q.begin(100 * s)
	q.note(101*s, true)     // 1 s behind the start
	q.note(105*s, false)    // 4 s: a quiet one
	q.note(105*s+s/2, true) // half a second
	if got, want := q.take(107*s), (WireQuiet{Span: 7 * time.Second, Out: 2, In: 1, Longest: 4 * time.Second, Quiet: 1}); got != want {
		t.Fatalf("the first take %+v, want %+v", got, want)
	}
	// Nothing in the next: the open stretch is its longest, and no quiet one has ended.
	if got, want := q.take(120*s), (WireQuiet{Span: 13 * time.Second, Longest: 14*time.Second + 500*time.Millisecond}); got != want {
		t.Fatalf("a take with no datagram in it %+v, want %+v", got, want)
	}
	// The datagram that ends it: the whole stretch is the take's it ended in.
	q.note(121*s, false)
	if got, want := q.take(122*s), (WireQuiet{Span: 2 * time.Second, In: 1, Longest: 15*time.Second + 500*time.Millisecond, Quiet: 1}); got != want {
		t.Fatalf("the take a long stretch ended in %+v, want %+v", got, want)
	}
	// And the take behind it starts anew: its longest is its own, not the long one's.
	q.note(122*s+200*int64(time.Millisecond), true)
	if got, want := q.take(122*s+400*int64(time.Millisecond)), (WireQuiet{Span: 400 * time.Millisecond, Out: 1, Longest: 1200 * time.Millisecond}); got != want {
		t.Fatalf("the take behind a long stretch %+v, want %+v", got, want)
	}

	// The floor: one nanosecond short is no quiet stretch, the floor itself is.
	var b wireClock
	b.begin(0)
	b.note(int64(QuietFloor)-1, true)
	b.note(2*int64(QuietFloor)-1, true)
	if got, want := b.take(2*int64(QuietFloor)), (WireQuiet{Span: 2 * QuietFloor, Out: 2, Longest: QuietFloor, Quiet: 1}); got != want {
		t.Fatalf("at the floor %+v, want %+v", got, want)
	}

	// Two streams that read the clock at once: the older reading, noted
	// second, ends no stretch and does not count as one of a negative length.
	var r wireClock
	r.begin(10 * s)
	r.note(12*s, true)
	r.note(11*s, false)
	if got, want := r.take(12*s), (WireQuiet{Span: 2 * time.Second, Out: 1, In: 1, Longest: 2 * time.Second}); got != want {
		t.Fatalf("an older reading behind a newer %+v, want %+v", got, want)
	}
}

// A client's own datagrams reach the clock both ways: what its streams write
// counts as out, what its ready streams hear from the server as in, and a
// take begins the next measure.
func TestAClientsDatagramsReachTheWireClockBothWays(t *testing.T) {
	srv := newFakeServer(t, "wire-pw")
	c, _, got := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })
	if first := c.WireQuiet(); first.Out == 0 || first.In == 0 || first.Span <= 0 || first.Span > 30*time.Second {
		t.Fatalf("the set-up's own stretch %+v: the asks and the server's answers of two streams are datagrams too, and the measure began with the client — moments ago", first)
	}
	const n = 20
	for i := 0; i < n; i++ {
		if err := c.Send(seqPkt(4444, i, 200)); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	eventually(t, "the echoes back", func() bool { return got.n() == n })
	q := c.WireQuiet()
	if q.Out < n || q.In < n {
		t.Fatalf("after %d packets out and their echoes: %+v — want at least %d each way", n, q, n)
	}
	if q.Span <= 0 || q.Longest > q.Span || q.Longest >= QuietFloor {
		t.Fatalf("the take %+v: the longest stretch is inside the span, and a busy stretch of this length has no quiet one", q)
	}
	if again := c.WireQuiet(); again.Out >= n || again.In >= n {
		t.Fatalf("the take behind it %+v still carries the %d datagrams of the one before: a take starts the next measure", again, n)
	}
}
