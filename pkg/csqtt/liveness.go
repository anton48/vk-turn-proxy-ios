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
// 🚨 The slot is held for the WHOLE start (credentials AND allocation) and
// the spacing is measured from the END of the previous start. The first
// version stamped the moment a worker entered the start: workers queued
// behind a slow credential mint then left it together, and the second
// eight allocations of a 16-worker run landed within 35 ms of each other
// (2026-09-04, live1) — paced on paper, a burst on the wire.
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
// and only given up on if the probe too goes unanswered.
const (
	livenessTick   = 5 * time.Second
	probeAfter     = 30 * time.Second // silence before a probe
	deadAfterProbe = 30 * time.Second // silence after the probe before a restart
	readyGrace     = 20 * time.Second // a fresh worker is not judged yet

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
	ProbeSentAt time.Time // when a probe was sent for the current silence; zero if none
	AnyRx       time.Time // last inbound on ANY worker of the client
}

// livenessAction is what the monitor should do for a worker.
type livenessAction int

const (
	livenessNone     livenessAction = iota
	livenessProbe                   // send READY, record ProbeSentAt
	livenessRestart                 // give up on the worker
	livenessResetAll                // the process was descheduled: reset every clock, judge nothing
)

// livenessVerdict is the rule, pure. Order of the checks is the rule:
//  1. a late tick means descheduled — reset, never judge;
//  2. a worker that is not ready, or ready for less than readyGrace, is not judged;
//  3. if NO worker has heard anything for probeAfter, the path is down, not
//     this worker — restarting workers one by one would only churn allocations;
//  4. silence past probeAfter with no probe out → probe;
//  5. silence past deadAfterProbe after the probe → restart.
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
	if in.Now.Sub(in.LastRx) < probeAfter {
		return livenessNone
	}
	if in.ProbeSentAt.IsZero() {
		return livenessProbe
	}
	if in.Now.Sub(in.ProbeSentAt) >= deadAfterProbe {
		return livenessRestart
	}
	return livenessNone
}
