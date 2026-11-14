package csqtt25

// The RHYTHM of a client on the wire, for the log.
//
// The counters say how much a client spoke; what a phone's radio and its
// sleep see is WHEN. An idle client speaks all the same — every stream says
// it is alive every keepaliveEvery and is asked after probeAfter of silence —
// and thirty streams whose moments are spread leave no stretch of the wire
// without a datagram, where the same thirty in step leave one of seconds
// between two bursts. A night in which a phone did not sleep at all for four
// hours with nothing but this traffic in its log is why the measure is here.
//
// What is measured: every datagram a stream writes through its wrapper (send)
// and every authentic one a READY stream hears (receive). Not seen from here:
// a handshake's own datagrams and the relay client's (its refreshes).

import (
	"sync"
	"time"
)

// QuietFloor is how long the wire has to be without a datagram for the
// stretch to count as a quiet one: about what a phone was seen to take
// between a wake and its next sleep.
const QuietFloor = 3 * time.Second

// WireQuiet is one take of the measure (Client.WireQuiet).
type WireQuiet struct {
	Span    time.Duration // what was measured: since the take before this one, or the client's start
	Out, In int64         // datagrams written and heard in it
	Longest time.Duration // the longest stretch in it without a datagram either way — the one still open at the take included
	Quiet   int64         // stretches of QuietFloor and more that ENDED in it (the open one is the next take's)
}

// wireClock keeps the measure between two takes. Its readings are the
// streams' own (the wall clock's, unix nanoseconds), so a suspension of the
// process is a stretch like any other: the log says the suspensions beside it.
//
// 🚨 ONE lock over every field. A datagram's note changes several of them —
// a count, the latest datagram, the longest stretch, the quiet ones — and a
// take reads and clears them all: with each field an atomic of its own
// nothing raced by the race detector's lights, and a take could still fall
// between two halves of one note and hand out a quiet stretch with no
// longest one. What a take hands out is ONE moment of the clock. The lock is
// held for a few assignments and never across anything that waits.
type wireClock struct {
	mu      sync.Mutex
	since   int64 // when the stretch being measured began
	last    int64 // the latest datagram either way; the start until there is one. It only moves FORWARD.
	out, in int64
	longest int64 // the longest stretch that ENDED since the last take
	quiet   int64
}

// begin starts the measure: the first stretch runs from here.
func (q *wireClock) begin(now int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.since, q.last = now, now
}

// note is one datagram, out or in, read off the clock at now. The stretch it
// ends is the one since the latest datagram before it, whichever stream's
// that was.
//
// 🚨 The reading is taken by the stream BEFORE it gets here, and streams do
// not take turns: a reading can arrive behind a later one — by microseconds
// under a busy scheduler, by a whole sleep when the process was suspended
// between the reading and the note. Such a latecomer is counted as the
// datagram it is and ends no stretch; above all it does not move the latest
// datagram BACK — the next stretch would be measured from it and come out
// longer than the wire was quiet.
func (q *wireClock) note(now int64, out bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if out {
		q.out++
	} else {
		q.in++
	}
	if now <= q.last {
		return
	}
	gap := now - q.last
	q.last = now
	if gap > q.longest {
		q.longest = gap
	}
	if gap >= int64(QuietFloor) {
		q.quiet++
	}
}

// take hands out the measure since the take before and starts the next. A
// stretch belongs, whole, to the take it ENDS in; the one still open counts
// for this take's longest and is not yet a quiet one. The take's boundary is
// never before the latest datagram it hands out: a reading of its own that is
// older (taken before the lock) is moved up to that datagram, so no stretch
// has a negative length and the next span begins where this one ended.
func (q *wireClock) take(now int64) WireQuiet {
	q.mu.Lock()
	defer q.mu.Unlock()
	if now < q.last {
		now = q.last
	}
	r := WireQuiet{
		Span: time.Duration(now - q.since),
		Out:  q.out, In: q.in,
		Longest: time.Duration(q.longest),
		Quiet:   q.quiet,
	}
	if open := time.Duration(now - q.last); open > r.Longest {
		r.Longest = open
	}
	q.since, q.out, q.in, q.longest, q.quiet = now, 0, 0, 0, 0
	return r
}

// WireQuiet takes the rhythm on the wire since the take before this one (the
// client's start for the first): how many datagrams went out and came in, the
// longest stretch without one, how many stretches of QuietFloor and more.
// 🚨 A TAKE: it starts the next stretch, so it has ONE reader — whoever logs
// it at a steady pace. Stats stays a snapshot anyone may read.
func (c *Client) WireQuiet() WireQuiet {
	return c.wire.take(time.Now().UnixNano())
}
