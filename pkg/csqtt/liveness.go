// SPDX-License-Identifier: MIT

package csqtt

// The resilience rules, kept as values so fixtures can drive them: how
// starts are paced, when a silent worker is probed and when it is given up
// on, and how a reconnect names itself to the server.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// ─── identity ─────────────────────────────────────────────────────────────

// NewIdentity returns the (generation, salt) pair a NEW connection must
// carry. The server keys a device's epoch on the pair: a GETCONF with a
// different pair replaces every older session of the device, so a reconnect
// that reused the old pair would leave stale sessions standing (until the
// server's 10 h idle purge) and counted against stream repair. Generation
// is strictly greater than prev — the reference app persists a counter for
// exactly this — and never below the clock, so two devices restored from
// different backups still order.
func NewIdentity(prev uint64) (generation uint64, salt string) {
	generation = uint64(time.Now().Unix())
	if generation <= prev {
		generation = prev + 1
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A clock-derived salt is still unique per second per device; the
		// server only compares it for equality.
		binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(b[8:], generation)
	}
	return generation, hex.EncodeToString(b[:])
}

// ─── start pacing ─────────────────────────────────────────────────────────

// startGate spaces worker starts by at least `every`, across the whole
// client and across restarts. Sixteen workers losing the network together
// would otherwise re-dial as one burst — sixteen credential mints and
// sixteen allocations in the same instant, which is how a relay says 486.
//
// 🚨 The slot is held for the WHOLE step inside it and the spacing is
// measured from the END of the previous one. The first version stamped the
// moment a worker entered the start: workers queued behind a slow step then
// left it together, and the second eight allocations of a 16-worker run
// landed within 35 ms of each other (2026-09-04, live1) — paced on paper, a
// burst on the wire. Since 2026-09-06 the step inside is the ALLOCATION
// only: credentials are taken before the gate, because a pool that parks a
// worker (the app's cold-start cap, its path-change settle) would otherwise
// stall every other start behind that one worker.
type startGate struct {
	mu    sync.Mutex
	every time.Duration
	last  time.Time // when the previous start finished
	now   func() time.Time
	sleep func(time.Duration)
}

func newStartGate(every time.Duration) *startGate {
	return &startGate{every: every, now: time.Now, sleep: time.Sleep}
}

// begin blocks until this start may proceed — at least `every` after the
// previous start FINISHED — and holds the slot; the caller must call the
// returned func when its start is over (success or failure alike).
func (g *startGate) begin() (done func()) {
	g.mu.Lock()
	if !g.last.IsZero() {
		if d := g.every - g.now().Sub(g.last); d > 0 {
			g.sleep(d)
		}
	}
	return func() {
		g.last = g.now()
		g.mu.Unlock()
	}
}

// ─── liveness ─────────────────────────────────────────────────────────────

// Liveness timings. A silent worker is first PROBED (READY, which the
// server answers with READY_OK — the cheapest packet that elicits a reply),
// the probe is sent AGAIN for as long as it stays unanswered, and the worker
// is given up on only if re-sends made while the path DEMONSTRABLY worked —
// the client really received something just before and just after them —
// went unanswered too.
const (
	livenessTick   = 5 * time.Second
	probeAfter     = 30 * time.Second // silence before a probe
	deadAfterProbe = 30 * time.Second // silence after the FIRST probe before a restart
	readyGrace     = 20 * time.Second // a fresh worker is not judged yet

	// reprobeEvery: an unanswered probe is sent again this long after the last
	// send — at every on-time tick, in effect. A second short of the tick on
	// purpose: measured tick gaps run a fraction of a millisecond under
	// livenessTick, and a comparison with the tick itself would skip every
	// other one. Over the UDP relay leg a datagram is simply lost now and then
	// (≈1 % on that leg), and an idle worker hears nothing BUT the answer to
	// its own probe: a probe sent once made every such loss a restart.
	reprobeEvery = livenessTick - time.Second

	// liveProbesToGiveUp: a worker is given up on only after this many RE-SENDS
	// of its probe went unanswered WHILE THE PATH WORKED — see
	// probeState.confirmed for what that means (in the ordinary case five of
	// them are confirmed by the thirtieth second). 🚨 A probe sent
	// when nobody is known to hear — the deafness round's, the wake hook's —
	// proves nothing about the worker when it is lost: it may have gone into a
	// dead path. Field, 2026-09-19: a 70-second block of the relay leg; the
	// round's probes went into it, the path came back, and thirty-five seconds
	// after the round twelve HEALTHY workers were restarted on those probes'
	// word — their allocations alive, nine 486s on the way back in.
	liveProbesToGiveUp = 2

	// descheduledSlack: a monitor tick that arrives this much late means
	// the PROCESS was not running (suspended, swapped, stalled), not that
	// the network was silent. 🚨 Every timeout verdict must carry this:
	// an app extension resumed after minutes of suspension would otherwise
	// find every worker "dead" and tear down every allocation on wake.
	descheduledSlack = 5 * time.Second
)

// livenessInput is one worker's view at a monitor tick.
type livenessInput struct {
	Now         time.Time
	PrevTick    time.Time // when the monitor last ran; zero on the first tick
	ReadyAt     time.Time // when this worker became ready; zero if not ready
	LastRx      time.Time // last inbound on this worker
	ProbeSentAt time.Time // when the FIRST probe of the current silence was sent — by this rule, the wake hook or the deafness round; zero if none. Any inbound clears it: a probe that is out is an unanswered one
	LastProbeAt time.Time // when a probe of the current silence was last sent: the first one, or a re-send
	LiveProbes  int       // a FACT: re-sends of the probe that count against the worker — made while the path demonstrably worked (probeState.confirmed)
	Answered    bool      // a FACT: THIS worker's real-inbound count has moved since its first probe went out. 🚫 Not "LastRx is fresh": that is a clock, which a wake and a late tick reset — and the read loop stamps it BEFORE it clears the probe
	AnyRx       time.Time // last inbound on ANY worker of the client
}

// probeState is what is known about the probe that is out for a worker's
// current silence: ONE immutable value behind one pointer (nil: no probe out),
// replaced whole by whoever changes it. A reader never sees half of it; an
// answer that lands between a verdict and its execution fails the verdict's
// CompareAndSwap; a re-send cannot resurrect a probe the read loop has just
// cleared.
type probeState struct {
	firstAt int64  // unix nanos of the FIRST probe of the silence — the restart's clock; a re-send never moves it
	lastAt  int64  // unix nanos of the latest send
	rx      int64  // THIS worker's real-inbound count when the first probe went out: the probe is answered once it has moved
	seq     uint64 // the CLIENT's real-inbound count (Client.rxSeq) when the latest send went out

	resent      bool // the latest send was a re-send by the liveness rule — not a first probe: the wake hook's and the deafness round's go out blind, and the rule's own first one is not counted either
	heardBefore bool // … and the client had really received something since the send before it
	counted     int  // re-sends already counted against the worker
}

// confirmed is how many re-sends count against the worker as of now, given
// whether the client has really received anything SINCE the latest send. A
// re-send counts only if the client heard something in the tick BEFORE it went
// out AND in the tick AFTER: then the path worked around the moment it
// travelled, and its silence is the worker's. 🚨 Both are facts — the client's
// real-inbound count moving — and not the age of anyRx: a re-send made into a
// general blackout (nothing before it, nothing after) counts for nothing,
// however young the last inbound still looked when it went out. What this
// cannot exclude is a path that dies and revives in step with the ticks; two
// confirmed re-sends, and a witness asked beside each (askWitness), make that
// two coincidences.
func (st *probeState) confirmed(heardSince bool) int {
	if st.resent && st.heardBefore && heardSince {
		return st.counted + 1
	}
	return st.counted
}

// livenessAction is what the monitor should do for a worker.
type livenessAction int

const (
	livenessNone     livenessAction = iota
	livenessProbe                   // send READY, record ProbeSentAt
	livenessRestart                 // give up on the worker
	livenessResetAll                // the process was descheduled: reset every clock, judge nothing
	livenessReprobe                 // send READY again for the same silence: ProbeSentAt stays, LastProbeAt moves, LiveProbes grows
	livenessAnswered                // the probe that is out HAS been answered: no verdict — and its state comes down (the monitor, by CompareAndSwap)
)

// livenessVerdict is the rule, pure. Order of the checks is the rule:
//  1. a late tick means descheduled — reset, never judge;
//  2. a worker that is not ready, or ready for less than readyGrace, is not judged;
//  3. if NO worker has heard anything for probeAfter, the path is down, not
//     this worker — restarting workers one by one would only churn allocations;
//  4. a probe is out, whoever sent it. If it has been ANSWERED — the worker's
//     own inbound count has moved — there is no verdict: one on the old probe
//     fields would restart a worker that has just answered. And its state
//     COMES DOWN, by the monitor's own hand (livenessAnswered). 🚨 The read
//     loop clears a probe only on an inbound that arrives AFTER the state was
//     published; worker.probe reads the count and then publishes, and the read
//     loop does not take turns with it: an inbound counted — and the clearing
//     done — in between leaves a state born answered, after the only event
//     that would ever have cleared it. Merely passed over, such a state stands
//     for ever, and the worker is never asked again and never given up on,
//     however long it stays silent afterwards (while the others hear, the
//     deafness rule does not help either).
//     Otherwise restart once deadAfterProbe has passed since the FIRST probe
//     AND liveProbesToGiveUp re-sends made while the path demonstrably worked
//     have gone unanswered, the last send at least reprobeEvery ago; otherwise
//     send it again, reprobeEvery after the last send. 🚫 The restart's clock
//     is the first probe's: a re-send never moves it, or a dead worker would be
//     asked for ever. 🚫 Rule 3 above is NOT "the path works": it lets the rule
//     through while the OLD anyRx is younger than probeAfter, although nobody
//     may have received anything since (a general blackout's first half
//     minute) — which is why the re-sends are counted by facts, not by it;
//  5. no probe out: silence past probeAfter → probe.
func livenessVerdict(in livenessInput) livenessAction {
	if !in.PrevTick.IsZero() && in.Now.Sub(in.PrevTick) > livenessTick+descheduledSlack {
		return livenessResetAll
	}
	if in.ReadyAt.IsZero() || in.Now.Sub(in.ReadyAt) < readyGrace {
		return livenessNone
	}
	if in.Now.Sub(in.AnyRx) >= probeAfter {
		return livenessNone
	}
	if !in.ProbeSentAt.IsZero() {
		if in.Answered {
			return livenessAnswered
		}
		rested := in.Now.Sub(in.LastProbeAt) >= reprobeEvery
		if rested && in.LiveProbes >= liveProbesToGiveUp && in.Now.Sub(in.ProbeSentAt) >= deadAfterProbe {
			return livenessRestart
		}
		if rested {
			return livenessReprobe
		}
		return livenessNone
	}
	if in.Now.Sub(in.LastRx) < probeAfter {
		return livenessNone
	}
	return livenessProbe
}

// ─── deafness: NOBODY hears anything ────────────────────────────────────────

// Rule 3 above leaves a silent worker alone while NO worker hears anything —
// one worker's silence among deaf peers says nothing about that worker. But the
// rule has no exit of its own, and a cause common to every worker is not always
// "the path is down": an iOS freeze that outlasts the TURN allocations (field,
// 2026-09-18: 578 s) leaves every worker "ready" on an allocation the relay no
// longer has. Over a TCP relay leg that announces itself — the relay resets the
// connection, the read fails, the worker restarts. Over UDP NOTHING announces
// it: a UDP write never fails, the TURN library reports a refused refresh as a
// success, and every probe goes into the void — the tunnel stayed dead for
// three hours with thirty "ready" workers. So deafness is judged for the
// client as a whole: ask every ready worker at once, and when none answers,
// replace them all (a new identity, as a path change does). The relay dials of
// the restarted workers then tell "the path is down" from "the allocations
// were": nobody becomes ready on a dead path, and with nobody ready this rule
// rests — the workers' own dial backoff is the recovery there.
const (
	deafSpacing    = 30 * time.Second // the least time between two restart-alls, doubled per round …
	deafSpacingCap = 5 * time.Minute
	deafQuiet      = 10 * time.Minute // … of a run; a restart-all this long ago ends the run

	// liveWindow: a ready worker heard from within this is LIVE in the stats.
	// An idle healthy worker is probed after probeAfter of silence, at the next
	// tick, and answered an RTT later — so its silence peaks near 36 s.
	liveWindow = 45 * time.Second
)

// wakeDeafAfter: how much LISTENING after the WAKE hook's probe round makes
// total silence a verdict. The user has just picked the phone up, every ready
// worker was asked at once, and an answer takes ~100 ms in the field; the
// monitor's own round listens for deadAfterProbe like any probe.
//
// wakeListenStep: a wake round's listening is counted in steps this long by a
// watcher of its own (the monitor's five-second tick is too coarse for a
// five-second wait). A step that takes more than twice its length means the
// process did not run — see deafInput.RoundListened. Variables so a test need
// not wait them out.
var (
	wakeDeafAfter  = 5 * time.Second
	wakeListenStep = 250 * time.Millisecond

	// wakeAskAgainEvery: a wake round that stands unanswered is asked again
	// after every this much LISTENING (the monitor's round: at every on-time
	// tick). 🚨 A round's probes go out when nobody is known to hear — into
	// a Wi-Fi that is still joining after the wake, a radio still coming up, a
	// block of a minute — and may be lost WHOLE; when the path comes back onto
	// an idle tunnel nothing arrives by itself (a worker hears nothing but the
	// answers to its own probes, and the per-worker rule is held by its rule 3
	// while nobody has heard anything): asked once, such a round ended in a
	// restart of every worker over a path that was fine.
	wakeAskAgainEvery = time.Second
)

// deafInput is the client's view at a monitor tick or at the wake verdict.
//
// 🚨 Two kinds of thing are in it and they must not be mixed. AnyRx is a CLOCK:
// it restarts on every inbound AND on every clock reset (a wake, a late tick),
// so that frozen time is never counted as silence — it says how long the
// running process has heard nothing, and it is NEVER evidence that something
// was received. RoundAnswered is a FACT: real inbound counted by the read
// loops since the round's probes went out, which no reset can grant or take
// away. (Build 411 read the fact off the clocks: a reset that landed after the
// answers made an answered round read as unanswered, and every healthy worker
// was restarted.)
//
// 🚨 And a round's wait is LISTENING, not wall time: RoundListened is the time
// the running process has been observed to spend since the probes went out —
// the monitor adds its on-time tick gaps to a round of its own, a wake round's
// watcher its on-time steps. A freeze is not listening, and a round that
// predates a DETECTED freeze does not stand at all: what it did not hear while
// the process was frozen proves nothing about the path now, and a verdict
// needs a fresh ask. (Build 412 measured the wait from the round's wall-clock
// time and kept the round through a late tick: a probe, ninety frozen seconds,
// a late tick, and the next tick restarted everybody on the old deadline —
// without having asked anyone again.)
type deafInput struct {
	Now            time.Time
	PrevTick       time.Time     // the monitor's previous tick; zero when the caller is not the monitor
	Judgeable      int           // workers ready for at least readyGrace
	AnyRx          time.Time     // the silence CLOCK: last inbound on any worker, or the last clock reset
	RoundOut       bool          // a probe round stands
	RoundIsWake    bool          // … the wake hook's
	RoundAnswered  bool          // a real inbound arrived, on any worker, after that round's probes went out
	RoundListened  time.Duration // awake time observed since then — never wall time
	LastRestartAll time.Time     // zero if never
	Rounds         int           // restart-alls in the current run
}

type deafAction int

const (
	deafNone       deafAction = iota
	deafProbeAll              // total silence for probeAfter: ask every ready worker
	deafRestartAll            // the round went unanswered: replace every worker
	deafHeld                  // … but the previous restart-all is too recent
	deafAskAgain              // the monitor's round stands unanswered, its wait not over: send its probes again
)

// deafSpacingFor is the least time after restart-all number `rounds` of a run
// before the next one.
func deafSpacingFor(rounds int) time.Duration {
	if rounds <= 0 {
		return 0
	}
	d := deafSpacing
	for i := 1; i < rounds && d < deafSpacingCap; i++ {
		d *= 2
	}
	if d > deafSpacingCap {
		d = deafSpacingCap
	}
	return d
}

// deafVerdict is the rule, pure. Order of the checks is the rule:
//  1. a late tick means descheduled — never judge (the monitor resets the clocks);
//  2. with no worker ready past its grace there is nobody to be deaf: the
//     workers are dialling, and their own backoff is the recovery;
//  3. a probe round that stands UNANSWERED — no real inbound since its probes
//     went out, whatever the clocks were reset to meanwhile — is a verdict once
//     it has been LISTENED to for its wait, unless the last restart-all is too
//     recent; until then it is ASKED AGAIN — the monitor's round at every
//     on-time tick (here), the wake round by its watcher inside its window —
//     and so is a round whose verdict is held, at the monitor's ticks
//     (judgeDeaf). 🚫 Asking again never touches the round's listening: the
//     wait is the first ask's;
//  4. otherwise, total silence for probeAfter → ask everybody.
func deafVerdict(in deafInput) deafAction {
	if !in.PrevTick.IsZero() && in.Now.Sub(in.PrevTick) > livenessTick+descheduledSlack {
		return deafNone
	}
	if in.Judgeable == 0 {
		return deafNone
	}
	if in.RoundOut && !in.RoundAnswered {
		wait := deadAfterProbe
		if in.RoundIsWake {
			wait = wakeDeafAfter
		}
		if in.RoundListened < wait {
			if in.RoundIsWake {
				return deafNone // its watcher asks again, in steps of its own
			}
			return deafAskAgain
		}
		if !in.LastRestartAll.IsZero() && in.Now.Sub(in.LastRestartAll) < deafSpacingFor(in.Rounds) {
			return deafHeld
		}
		return deafRestartAll
	}
	if in.Now.Sub(in.AnyRx) >= probeAfter {
		return deafProbeAll
	}
	return deafNone
}
