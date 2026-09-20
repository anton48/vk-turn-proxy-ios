package proxy

// The post-wake active probe — ONE body for both session kinds (DTLS and SRTP),
// and the two marks it reads (build 422).
//
// What it replaces, in each session's probe goroutine: one ping, then a poll
// of `lastPongSeq >= sentSeq` until a WALL-CLOCK deadline thirty seconds away,
// and a kill. Three things were wrong with that, each seen in the field:
//
//   - the thirty seconds ran through iOS freezes. On a night when the process
//     runs two seconds per wake the deadline passed while it was frozen, and
//     the loop left on the deadline without a last look at the mark: healthy
//     connections killed for what they could not hear (2026-09-19, all 532
//     kills of an overnight run);
//   - the ping was sent ONCE, inside the first three hundred milliseconds after
//     a thaw — exactly where the phone drops outbound datagrams while its radio
//     comes up. Over TCP the transport repeats it; over UDP a lost ping was a
//     healthy connection killed thirty seconds later (2026-09-20: 25 + 22 in
//     one run, every one of them a ping that never reached the router);
//   - and it was answered only by the pong of ITS OWN LAST ping. At a thaw the
//     overdue periodic tick has usually just sent a ping of its own; a
//     connection whose pong to THAT ping came back four milliseconds later was
//     killed all the same, because the wake's second ping had been lost.
//
// Now every quantity is a FACT or LISTENING — no wall-clock deadline:
//
//   - the probe remembers the seq of its FIRST ping and is answered by ANY pong
//     at or above it (the marks move only forward and start from zero with
//     each session — notePongSeq, resetProbeMarks);
//   - a ping the periodic tick sent a moment ago IS the probe's first ping:
//     nothing more goes into the thaw's burst;
//   - while nothing has answered it asks again every second of listening;
//   - a poll step that took far longer than its timer is a freeze: it is not
//     listening, and it is followed by a ping at once (a thaw is a new start);
//   - the verdict needs thirty seconds of LISTENING, comes only once the latest
//     ping has had its second, and the mark is read — the last look — before it.
//
// A connection that really does not answer — the process running, thirty
// seconds listened, nothing heard — is killed exactly as before.

import (
	"context"
	"fmt"
	"log"
	mathrand "math/rand"
	"time"
)

// Vars so that a test can shrink them; nothing else writes them.
var (
	wakeProbeWindow      = 30 * time.Second       // LISTENING without an answer before the verdict
	wakeProbeResendEvery = time.Second            // listening between two pings of one probe
	wakeProbePoll        = 100 * time.Millisecond // how often the mark is looked at
	wakeProbeFreezeStep  = time.Second            // a poll step longer than this was a freeze, not listening
	wakeProbeAdopt       = time.Second            // a ping sent this recently is the probe's first ping
	wakeProbeJitter      = 300 * time.Millisecond // the pool's probes are spread over this much
	wakeProbeClock       = time.Now
)

type wakeProbeVerdict int

const (
	wakeProbeWait   wakeProbeVerdict = iota // keep listening
	wakeProbeResend                         // ask again now
	wakeProbeEchoed                         // a pong of one of the probe's pings has arrived
	wakeProbeDead                           // thirty seconds of listening, asked to the last, nothing heard
)

// wakeProbeState is the probe's whole memory. `first` is a fact; `listened`
// and `sinceSend` are listening, added step by step where it is observed.
type wakeProbeState struct {
	first     uint64        // seq of the probe's first ping: a pong at or above it answers the probe
	listened  time.Duration // awake time spent waiting since that ping
	sinceSend time.Duration // of it, since the latest ping
	resends   int
	freezes   int
}

// step takes one poll step — how long it lasted and the pong mark read AFTER
// it — and says what to do. The mark is looked at first, so no verdict is
// ever reached past an answer that is already in.
func (s *wakeProbeState) step(took time.Duration, pongMark uint64) wakeProbeVerdict {
	if pongMark >= s.first {
		return wakeProbeEchoed
	}
	if took > wakeProbeFreezeStep {
		// The process did not run for most of this step: it heard nothing
		// because it could not. None of it counts, and whatever the path was
		// before the freeze, it is asked again now.
		s.freezes++
		s.resends++
		s.sinceSend = 0
		return wakeProbeResend
	}
	s.listened += took
	s.sinceSend += took
	if s.sinceSend < wakeProbeResendEvery {
		return wakeProbeWait
	}
	// The latest ping has had its second.
	if s.listened >= wakeProbeWindow {
		return wakeProbeDead
	}
	s.resends++
	s.sinceSend = 0
	return wakeProbeResend
}

// resetProbeMarks starts a session's probe bookkeeping from zero. The probe
// goroutine's seq restarts at zero with every session, and a mark left by the
// previous session on this connection index "answered" the new session's
// first probes before anything had been sent ("echo received in 0s
// (sentSeq=1)") — over dead allocations the probe then killed nothing.
// Called before the session's probe goroutine starts; the previous session's
// goroutines have been joined by then.
func (p *Proxy) resetProbeMarks(connIdx int) {
	if connIdx < 0 || connIdx >= len(p.lastPongSeq) {
		return
	}
	p.lastPongSeq[connIdx].Store(0)
	p.lastPingSeq[connIdx].Store(0)
}

// notePongSeq records a pong's seq. The mark only moves FORWARD: a late or
// repeated pong — the server may one day repeat its last echo as a keepalive —
// never takes back what a newer one has shown.
func (p *Proxy) notePongSeq(connIdx int, seq uint64) {
	if connIdx < 0 || connIdx >= len(p.lastPongSeq) {
		return
	}
	for {
		old := p.lastPongSeq[connIdx].Load()
		if seq <= old || p.lastPongSeq[connIdx].CompareAndSwap(old, seq) {
			return
		}
	}
}

// closedWakeCh stands in for the wake channel of a goroutine that has a wake
// pending: its select takes the wake case at once.
var closedWakeCh = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// wakeWatch is one probe goroutine's view of the wake signal (build 424).
// broadcastWake closes the wake channel and REPLACES it: that reaches a
// goroutine parked in its select, and no other. A goroutine in its tick branch
// at that instant re-read the channel after the swap and never saw the wake —
// and at a thaw the overdue tick fires on EVERY connection at once (with a
// line to log when the gap is long), while Swift's wake() is still on its way
// to WakeHealthCheck: on 2026-09-20 two wakes of twelve went unprobed on all
// thirty connections, and at one of them 27 connections dead at the server
// stood for 2 min 15 s with the phone awake, until the periodic detector.
// So the wake is a COUNTER as well — bumped under the lock before the swap —
// and the goroutine remembers the epoch it has served: a level, not an edge.
type wakeWatch struct {
	p      *Proxy
	served uint64
}

// newWakeWatch starts from the present: a wake that came before this session
// existed is not this session's to serve.
func (p *Proxy) newWakeWatch() *wakeWatch {
	return &wakeWatch{p: p, served: p.wakeEpoch.Load()}
}

// pending: a wake has been broadcast that this goroutine has not served. Asked
// right after the goroutine has read the wake channel, at the top of EVERY
// turn of its loop — a wake that came earlier is in the epoch, one that comes
// later closes the channel just read.
func (w *wakeWatch) pending() bool { return w.p.wakeEpoch.Load() != w.served }

// serve is the wake case of a session's probe goroutine — one body for both
// session kinds. probed = false when this wake needed no probe.
func (w *wakeWatch) serve(ctx context.Context, connIdx, credSlot int, label string, seq *uint64, lastPingAt *time.Time, send func(seq uint64, now time.Time) error) (alive, probed bool, err error) {
	epoch := w.p.wakeEpoch.Load()
	if !w.p.wakeProbeDue(connIdx) {
		w.served = epoch
		return true, false, nil
	}
	// Spread the pool's probes over 0–300 ms: forty Write + SRTP-encrypt bursts
	// in the same instant once pushed the extension over its memory limit
	// (2026-05-25).
	if jitter := mathrand.Int63n(int64(wakeProbeJitter)); jitter > 0 {
		select {
		case <-time.After(time.Duration(jitter)):
		case <-ctx.Done():
			return true, false, ctx.Err()
		}
	}
	alive, err = w.p.runWakeProbe(ctx, connIdx, credSlot, label, seq, lastPingAt, send)
	// The probe asks again at every thaw inside its wait: whatever woke the
	// phone while it ran has been served by it.
	w.served = w.p.wakeEpoch.Load()
	return alive, true, err
}

// wakeProbeDue: is this wake to be probed on this connection at all?
func (p *Proxy) wakeProbeDue(connIdx int) bool {
	if !p.serverProbeable.Load() {
		return false // the server does not echo: nothing to judge by
	}
	if connIdx < 0 || connIdx >= len(p.lastActiveProbeAt) {
		return false
	}
	if last := p.lastActiveProbeAt[connIdx].Load(); last > 0 && time.Since(time.Unix(last, 0)) < 30*time.Second {
		return false // probed less than thirty seconds ago
	}
	// A connection with data traffic in the last five seconds is skipped (the
	// probes' own bytes do not count — only the data path stamps these).
	if connIdx < len(p.lastTxAt) {
		recent := time.Now().UnixNano() - int64(5*time.Second)
		if p.lastTxAt[connIdx].Load() > recent || p.lastRxAt[connIdx].Load() > recent {
			return false
		}
	}
	return true
}

// echoAfter is the time an echo line reports: the listening INCLUDING the step
// that saw the pong — up to 423 that step was left out, and an answer inside
// the first poll step printed "in 0s", the old false echo's very wording. A
// frozen step is not listening and is not added.
func echoAfter(listened, took time.Duration) time.Duration {
	if took > wakeProbeFreezeStep {
		return listened
	}
	return listened + took
}

// runWakeProbe is the wake branch of a session's probe goroutine, from the
// moment it has decided to probe. seq is the goroutine's ping counter,
// lastPingAt the time of its latest ping (the periodic tick's included), send
// writes one ping. It returns alive = false when the connection is to be
// killed, and an error when the goroutine should simply end (a failed write,
// the connection's context done).
func (p *Proxy) runWakeProbe(ctx context.Context, connIdx, credSlot int, label string, seq *uint64, lastPingAt *time.Time, send func(seq uint64, now time.Time) error) (alive bool, err error) {
	now := wakeProbeClock()
	p.lastActiveProbeAt[connIdx].Store(now.Unix())
	// stepStart is where the current poll step began. A ping is SENT when its
	// write is over: the step — and with it the ping's second and the
	// listening — starts THERE, so the time a write takes is never part of a
	// step. Counted into the step (422 restarted the step's clock before the
	// write) it was the ping's listening — a slow write left the latest ping
	// less than its second before the verdict — and a write slower than
	// wakeProbeFreezeStep read as a freeze: nothing was ever listened, the
	// probe asked again at once, and an unanswered probe never ended.
	stepStart := now
	ping := func() error {
		*seq++
		if err := send(*seq, wakeProbeClock()); err != nil {
			return err
		}
		stepStart = wakeProbeClock()
		*lastPingAt = stepStart
		return nil
	}
	adopted := *seq > 0 && !lastPingAt.IsZero() && now.Sub(*lastPingAt) < wakeProbeAdopt
	if !adopted {
		if err := ping(); err != nil {
			return true, err
		}
	}
	st := wakeProbeState{first: *seq}
	timer := time.NewTimer(wakeProbePoll)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return true, ctx.Err()
		}
		now = wakeProbeClock()
		took := now.Sub(stepStart)
		stepStart = now
		switch st.step(took, p.lastPongSeq[connIdx].Load()) {
		case wakeProbeEchoed:
			detail := ""
			if adopted || st.resends > 0 || st.freezes > 0 {
				detail = wakeProbeDetail(adopted, &st)
			}
			log.Printf("proxy: [conn %d] %sactive probe (post-wake) echo received in %s (sentSeq=%d)%s",
				connIdx, label, echoAfter(st.listened, took).Round(10*time.Millisecond), *seq, detail)
			return true, nil
		case wakeProbeResend:
			if err := ping(); err != nil {
				return true, err
			}
		case wakeProbeDead:
			lastPongS := p.lastPongSeq[connIdx].Load()
			var sentSinceLastPong uint64
			if *seq >= lastPongS {
				sentSinceLastPong = *seq - lastPongS
			}
			log.Printf("proxy: [conn %d on slot %d] %sactive probe (post-wake) no echo within %s of listening (sentSeq=%d lastPongSeq=%d sentSinceLastPong=%d authErrorsOnSlot=%d%s), killing",
				connIdx, credSlot, label, wakeProbeWindow, *seq, lastPongS, sentSinceLastPong, p.credPool.authErrorCount(credSlot), wakeProbeDetail(adopted, &st))
			return false, nil
		}
		timer.Reset(wakeProbePoll)
	}
}

func wakeProbeDetail(adopted bool, st *wakeProbeState) string {
	first := "its own"
	if adopted {
		first = "the tick's"
	}
	return fmt.Sprintf(" — first ping %s (seq %d), sent again %d×, %d freeze(s) inside the wait", first, st.first, st.resends, st.freezes)
}
