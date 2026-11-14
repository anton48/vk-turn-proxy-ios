package csqtt25

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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

// A reading that reaches the clock LATE — its stream read the time, was held
// up (a busy scheduler; a suspension of the process between the reading and
// the note), and another stream's later reading got there first — ends no
// stretch, and it must not move the latest datagram BACK: the stretch to the
// next datagram is measured from the latest one, not from the latecomer.
func TestALateReadingDoesNotMoveTheLatestDatagramBack(t *testing.T) {
	const s = int64(time.Second)
	var q wireClock
	q.begin(10 * s)
	q.note(12*s, true)
	q.note(11*s, false) // read before the one above, noted behind it
	q.note(14*s, true)  // two seconds behind the latest datagram, not three
	if got, want := q.take(14*s), (WireQuiet{Span: 4 * time.Second, Out: 2, In: 1, Longest: 2 * time.Second}); got != want {
		t.Fatalf("readings noted in the order 12 s, 11 s, 14 s: %+v, want %+v — the longest stretch is 12 → 14, and no quiet one", got, want)
	}
	// A take whose own reading is older than the latest datagram: the boundary
	// is that datagram, never before it — no stretch of a negative length, and
	// the next span does not begin before a datagram already handed out.
	q.note(20*s, true)
	if got, want := q.take(19*s), (WireQuiet{Span: 6 * time.Second, Out: 1, Longest: 6 * time.Second, Quiet: 1}); got != want {
		t.Fatalf("a take read at 19 s behind a datagram at 20 s: %+v, want %+v", got, want)
	}
	q.note(21*s, false)
	if got, want := q.take(22*s), (WireQuiet{Span: 2 * time.Second, In: 1, Longest: time.Second}); got != want {
		t.Fatalf("the take behind it: %+v, want %+v — its span begins at the datagram the take before ended on", got, want)
	}
}

// A take is ONE moment: whatever a datagram's note changes — the counts, the
// longest stretch, the quiet ones — is in a take whole or not at all. One
// writer with readings that only grow, every third stretch a quiet one, and a
// reader taking as fast as it can: no take may say «a quiet stretch ended
// here» with a longest stretch below the floor, and the takes together hand
// out every datagram and every quiet stretch exactly once.
func TestATakeIsOneMomentOfTheClock(t *testing.T) {
	const notes = 300000
	var q wireClock
	q.begin(0)
	var cur atomic.Int64
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		now := int64(0)
		for i := 0; i < notes; i++ {
			if i%3 == 2 {
				now += int64(QuietFloor)
			} else {
				now += int64(time.Millisecond)
			}
			cur.Store(now)
			q.note(now, true)
		}
	}()
	var out, quiet int64
	var torn int
	var first WireQuiet
	check := func(w WireQuiet) {
		out += w.Out
		quiet += w.Quiet
		if w.Quiet > 0 && w.Longest < QuietFloor {
			if torn == 0 {
				first = w
			}
			torn++
		}
	}
	for !stop.Load() {
		check(q.take(cur.Load()))
	}
	wg.Wait()
	check(q.take(cur.Load()))
	if torn != 0 {
		t.Fatalf("%d take(s) with a quiet stretch counted and a longest stretch below the floor — the first %+v: the take was put together across a datagram's note", torn, first)
	}
	if out != notes || quiet != notes/3 {
		t.Fatalf("the takes together: %d datagram(s) out and %d quiet stretch(es), want %d and %d — each handed out exactly once", out, quiet, notes, notes/3)
	}
}

// The two bodies that touch the clock's fields do it under its ONE lock, held
// to their end: a race test catches a torn take only now and then, so where
// the lock stands is pinned by the source.
func TestTheWireClocksNoteAndTakeHoldItsLock(t *testing.T) {
	src, err := os.ReadFile("wire.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"note", "take", "begin"} {
		m := regexp.MustCompile(`(?s)\nfunc \(q \*wireClock\) ` + fn + `\(.*?\n}\n`).Find(src)
		if m == nil {
			t.Fatalf("no body of wireClock.%s in wire.go", fn)
		}
		body := string(m)
		open := strings.Index(body, "{\n")
		if !strings.HasPrefix(body[open+2:], "\tq.mu.Lock()\n\tdefer q.mu.Unlock()\n") {
			t.Fatalf("wireClock.%s does not begin with the clock's lock held to its end:\n%s", fn, body)
		}
		if strings.Contains(body, "atomic.") || strings.Contains(body, ".Swap(") || strings.Contains(body, ".Load()") {
			t.Fatalf("wireClock.%s reads or writes a field past the lock (an atomic in its body)", fn)
		}
	}
}
