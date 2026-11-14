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
	"sync/atomic"
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
type wireClock struct {
	since   atomic.Int64 // when the stretch being measured began
	last    atomic.Int64 // the latest datagram either way; the start until there is one
	out, in atomic.Int64
	longest atomic.Int64 // the longest stretch that ENDED since the last take
	quiet   atomic.Int64
}

// begin starts the measure: the first stretch runs from here.
func (q *wireClock) begin(now int64) {
	q.since.Store(now)
	q.last.Store(now)
}

// note is one datagram, out or in, at now. The stretch it ends is the one
// since the datagram before it, whichever stream's that was. Two streams that
// read the clock at once may get here in the other order — a reading older
// than the one before it gives a stretch of no length or less, which is
// neither the longest nor a quiet one.
func (q *wireClock) note(now int64, out bool) {
	if out {
		q.out.Add(1)
	} else {
		q.in.Add(1)
	}
	gap := now - q.last.Swap(now)
	for {
		cur := q.longest.Load()
		if gap <= cur || q.longest.CompareAndSwap(cur, gap) {
			break
		}
	}
	if gap >= int64(QuietFloor) {
		q.quiet.Add(1)
	}
}

// take hands out the measure since the take before and starts the next. A
// stretch belongs, whole, to the take it ENDS in; the one still open counts
// for this take's longest and is not yet a quiet one.
func (q *wireClock) take(now int64) WireQuiet {
	r := WireQuiet{
		Span: time.Duration(now - q.since.Swap(now)),
		Out:  q.out.Swap(0), In: q.in.Swap(0),
		Longest: time.Duration(q.longest.Swap(0)),
		Quiet:   q.quiet.Swap(0),
	}
	if open := time.Duration(now - q.last.Load()); open > r.Longest {
		r.Longest = open
	}
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
