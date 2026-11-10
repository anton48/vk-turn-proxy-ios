package csqtt25

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// A ready stream's liveness, for a process the system suspends.
//
// The console's first rule read a clock: a stream that had heard nothing for
// twenty seconds was asked, one that had heard nothing for sixty was replaced.
// On a phone the process is frozen for minutes at a time, and the clock goes
// on: at every thaw each stream had «heard nothing» for the whole sleep and
// was replaced — every allocation given back and dialled again at every wake,
// whether anything was wrong with it or not. The rules here are the ones
// pkg/csqtt came to for the same phone (builds 411–420), carried into this
// engine's own shape — one goroutine per stream, which reads the stream and
// judges it, so that nothing here needs a lock:
//
//   - SILENCE IS LISTENING. What counts toward a verdict is the time the
//     process was observed to run without the stream hearing anything: the
//     on-time gaps between the serve loop's ticks, added up. Never a
//     difference of two wall-clock readings.
//   - A TICK THAT COMES LATE IS A FREEZE, and a freeze is a boundary: nothing
//     heard or not heard before it says anything about the path now (the
//     allocation may have expired, the NAT mapping gone, the network changed).
//     The silence counted so far is dropped, and the stream is ASKED AFRESH,
//     at once.
//   - BEHIND A BOUNDARY THE VERDICT IS QUICK: the stream is asked again every
//     wakeAskEvery of listening — what is written in the first moments after a
//     thaw is often lost, the radio is not up yet — and replaced when
//     wakeDeafAfter of listening has brought nothing. The ordinary twenty and
//     sixty seconds are for a stream that fell silent while the process ran.
//   - A FREEZE INSIDE THAT WINDOW STARTS IT OVER: a phone asleep wakes for a
//     second or two at a time, and what was not heard across the next sleep
//     proves nothing either.
//   - WHAT WAS READ ACROSS A FREEZE IS NOT AN ANSWER. Datagrams that arrived
//     before or during the sleep wait in the socket and are read in the first
//     instant after it — before the late tick has been seen, or right behind
//     it. Neither ends the window: an answer to the ask comes a round trip
//     later, and the ask is repeated.
//   - THE CALLER'S WORD (Client.Wake — the app's wake hook) is the same
//     boundary without a late tick: every ready stream is asked at once.
//
// What this does not do, on purpose: judge the client as a whole. pkg/csqtt
// has a monitor that asks «does ANY worker hear» before it gives up on one,
// because its workers were judged on a probe sent once. Here a stream is
// judged on its own answers to its own repeated asks, by itself.

// The watch's clocks; variables so that a test can shorten them.
var (
	// freezeSlack: a tick this much later than serveTick means the process did
	// not run — suspended, not slow. A stretch shorter than that is counted as
	// listening: nothing on the path expires inside it.
	freezeSlack = 2 * time.Second
	// wakeDeafAfter: how much LISTENING behind a boundary, with the stream
	// asked again and again, makes its silence a verdict.
	wakeDeafAfter = 5 * time.Second
	// wakeAskEvery: the stream is asked again after every this much listening
	// while the window stands.
	wakeAskEvery = time.Second
	// wakeAnswerFloor: an inbound read sooner than this behind a boundary is
	// taken for one that waited in the socket through the freeze, not for the
	// answer to the ask that the boundary sent.
	wakeAnswerFloor = 250 * time.Millisecond
	// wakeMerge: the caller's word inside this much of a boundary already
	// seen is the same wake (the late tick and the app's hook come together).
	wakeMerge = 2 * time.Second
)

// serveNow is the serve loop's clock: WALL time, without the monotonic
// reading — a runtime whose monotonic clock stands still while the machine
// sleeps would hide the very gap this is read for.
var serveNow = func() time.Time { return time.Now().Round(0) }

type watchAction int

const (
	watchNone      watchAction = iota
	watchAsk                   // send READY
	watchFroze                 // a late tick: a boundary — say so once, and ask
	watchWoke                  // the caller's word: a boundary — ask
	watchDeaf                  // deafAfter of listening without a word: replace
	watchUnsettled             // the same behind a restart notice, on its short times
	watchWakeDeaf              // wakeDeafAfter of listening behind a boundary without a word: replace
)

// watchClocks is the rule's times as one stream's watch holds them: read off
// the package's clocks ONCE, when the stream becomes ready. The serve loop
// then touches nothing shared on its way through a datagram.
type watchClocks struct {
	late                     time.Duration // a tick later than this is a freeze: serveTick + freezeSlack
	ask, deaf                time.Duration // probeAfter, deafAfter
	settleAsk, settleDeaf    time.Duration
	wakeDeaf, wakeAsk        time.Duration
	answerFloor, merge, idle time.Duration    // wakeAnswerFloor, wakeMerge, keepaliveEvery
	now                      func() time.Time // serveNow
}

func currentWatchClocks() watchClocks {
	return watchClocks{
		late: serveTick + freezeSlack, ask: probeAfter, deaf: deafAfter,
		settleAsk: settleProbeAfter, settleDeaf: settleDeafAfter,
		wakeDeaf: wakeDeafAfter, wakeAsk: wakeAskEvery,
		answerFloor: wakeAnswerFloor, merge: wakeMerge, idle: keepaliveEvery,
		now: serveNow,
	}
}

// newStreamWatch starts a stream's watch now, with the wake epoch it has
// nothing to answer for.
func newStreamWatch(epoch uint64) streamWatch {
	clocks := currentWatchClocks()
	return streamWatch{watchClocks: clocks, prev: clocks.now(), epoch: epoch}
}

// streamWatch is one ready stream's liveness state. Its serve loop owns it:
// tick at every tick, heard at every authentic inbound.
type streamWatch struct {
	watchClocks
	prev    time.Time     // the previous tick
	epoch   uint64        // the client's wake epoch this watch has acted on
	quiet   time.Duration // LISTENING since the last inbound or the last boundary
	askedAt time.Duration // quiet at the latest ask of this silence; 0: not asked

	wake     bool          // a boundary's window stands
	since    time.Time     // … since this moment
	listened time.Duration // … with this much listening in it
	nextAsk  time.Duration // … and the next ask due at this much
}

// tick is the rule, pure. now is the serve clock, epoch the client's wake
// epoch, unsettled whether the stream's last real inbound is too early
// behind a restart notice to be the server that came back (Client.unsettled).
// gap is the late tick's length for watchFroze.
func (s *streamWatch) tick(now time.Time, epoch uint64, unsettled bool) (act watchAction, gap time.Duration) {
	step := now.Sub(s.prev)
	if step < 0 {
		step = 0 // the wall clock was set back: nothing was observed
	}
	s.prev = now
	froze := step > s.late
	woke := epoch != s.epoch
	s.epoch = epoch
	if woke && !froze && s.wake && now.Sub(s.since) < s.merge {
		woke = false // the same wake, already acted on
	}
	if froze || woke {
		s.quiet, s.askedAt = 0, 0
		s.wake, s.since, s.listened, s.nextAsk = true, now, 0, s.wakeAsk
		if froze {
			return watchFroze, step
		}
		return watchWoke, 0
	}
	if s.wake {
		s.listened += step
		if s.listened >= s.wakeDeaf {
			return watchWakeDeaf, 0
		}
		if s.listened >= s.nextAsk {
			s.nextAsk = s.listened + s.wakeAsk
			return watchAsk, 0
		}
		return watchNone, 0
	}
	s.quiet += step
	ask, give, gone := s.ask, s.deaf, watchDeaf
	if unsettled {
		ask, give, gone = s.settleAsk, s.settleDeaf, watchUnsettled
	}
	switch {
	case s.quiet >= give:
		return gone, 0
	case s.quiet >= ask && (s.askedAt == 0 || s.quiet-s.askedAt >= ask/2):
		s.askedAt = s.quiet
		return watchAsk, 0
	}
	return watchNone, 0
}

// heard takes one authentic inbound, read at now. One read across a freeze
// the loop has not seen yet — the gap to the previous tick says so — changes
// nothing: the late tick that follows makes the boundary. One read right
// behind a boundary ends the silence but not the window.
func (s *streamWatch) heard(now time.Time) {
	if now.Sub(s.prev) > s.late {
		return
	}
	s.quiet, s.askedAt = 0, 0
	if s.wake && now.Sub(s.since) >= s.answerFloor {
		s.wake = false
	}
}

// ─── a write the relay does not take, a write into a connection that is gone ──

// DefaultWriteBound is the bound the app puts on a stream's write. Above
// every wait a healthy relay makes a write take (a full buffer at the
// policer's knee frees room every few milliseconds; a retransmission timeout
// on the relay's TCP connection holds it for hundreds), far below the
// liveness rule's seconds — pkg/csqtt's number, for the same relay.
const DefaultWriteBound = time.Second

var (
	errStalled  = errors.New("the relay took no bytes within the write bound")
	errConnGone = errors.New("a write found the connection gone")
	errWakeDeaf = errors.New("the stream heard nothing behind a wake")
)

// connGone says whether a write's error means the CONNECTION is gone — a
// reset, a broken pipe, the kernel's own give-up, a closed socket — as
// opposed to a moment's refusal (ENOBUFS, EAGAIN), a route that is away for
// now (the path change's business) or the bound's own expiry (a stall, judged
// apart). Over a TCP relay leg a reset is noticed by the next WRITE and by
// nothing else.
func connGone(err error) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPIPE, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.ENOTCONN, syscall.ETIMEDOUT:
			return true
		}
	}
	return false
}

// causeOf is the innermost error's own words, for a log line that names the
// cause and no address.
func causeOf(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	if errors.Is(err, net.ErrClosed) {
		return net.ErrClosed.Error()
	}
	return err.Error()
}
