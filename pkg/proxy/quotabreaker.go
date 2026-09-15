package proxy

import (
	"log"
	"time"
)

// The relay-refusal breaker (build 389; Sep 6 §58's open item 1).
//
// A 486 ("Allocation Quota Reached") on a credential's FIRST allocation
// cannot be that identity's quota — a fresh identity has its ten allocations
// on the relay — so it says the relay, or the host behind it, refuses
// regardless of identity, and minting another one is waste. Until this
// breaker, a relay that refused everything turned a run of 486s into a run
// of MINTS: each 486 marked its slot saturated, the retry found no usable
// slot and minted a fresh VK identity, on every worker's every retry —
// bounded only by the cold-start cap and the per-worker backoff (at N=30
// with the backoffs at 30 s, one identity per second, 3600 an hour) — until
// VK rate-limited the minting with a captcha: terminal for csqtt, a WebView
// on native, and the relay was the problem all along. Native's "three short
// failures → dormancy" did not bound it either: every mint broadcasts, the
// broadcast wakes the dormant connection and resets its failure count.
//
// The breaker counts refusals that land within quotaFreshCredWindow of the
// slot's fill; quotaRefusalTrip of them within quotaRefusalWindow pause
// MINTING — get()'s Phase 2 and the grower's fills; existing usable slots
// are still handed out — for quotaPauseBase, doubled per trip within
// quotaLadderWindow up to quotaPauseMax. A timer broadcasts at the pause's
// end so parked connections retry at once, and the next trip needs two NEW
// fresh refusals. A 486 on an older credential — the ghost case, VK still
// holding allocations from before a switch — is a real quota and is NOT
// counted: a fresh identity is exactly its cure (the four-switch run of
// 2026-09-06 lived on those mints).
//
// 🚨 FRESH IS NOT ENOUGH: THE REFUSED HOLDER MUST BE ALONE ON THE SLOT. The
// first device run of this breaker (csqtt, 2026-09-15 21:34) showed the
// other 486 a fresh credential gets: ten workers seated on a slot minted
// 5 s earlier, nine allocations succeeded, the TENTH was refused — the
// identity's real quota, on a credential 5 s old. The relay accepted the
// next identity at once. Counted by age alone that is a fresh refusal, and
// two such in one post-switch herd would have paused minting for 30 s
// while the tunnel was recovering on exactly those mints. So a refusal
// counts only when the refused holder is the slot's only lease (active ==
// 1 at the mark, before its release): nobody else made it on that
// identity. That is the storm's shape on every path — csqtt's worker 1
// alone before TUNCONF, the native bootstrap's conn 0, and a herd whose
// ten dials all fail (the last failure marks with active == 1) — and not
// the tenth-allocation quota, whose nine successes still hold the slot.
// The archive agrees: 296 logs, 8 real 486s, one of them on a credential
// under a minute old — that tenth allocation, with nine holders.
const (
	// quotaFreshCredWindow: a 486 this soon after the slot was filled is a
	// refusal of a fresh identity, not a quota. Ten connections seat on a
	// fresh credential within a second of the mint; a genuine quota needs
	// ten successful allocations first.
	quotaFreshCredWindow = 60 * time.Second
	// quotaRefusalWindow / quotaRefusalTrip: two fresh refusals within a
	// minute trip the breaker. One could be a coincidence at the relay's
	// edge; two fresh identities refused back to back are the storm's
	// signature, and the second costs exactly one mint more than the first.
	quotaRefusalWindow = 60 * time.Second
	quotaRefusalTrip   = 2
	// quotaLadderWindow: trips within it double the pause — a relay that
	// keeps refusing across pauses is waited out with longer ones; after
	// ten quiet minutes the ladder starts over at the base.
	quotaLadderWindow = 10 * time.Minute
)

// Vars, not consts: the tests shrink the pauses to milliseconds.
var (
	quotaPauseBase = 30 * time.Second
	quotaPauseMax  = 5 * time.Minute
)

type quotaBreaker struct {
	refusals    int64       // every 486 the pool was told of, this session — both transports
	fresh       []time.Time // refusals on fresh credentials, trimmed to quotaRefusalWindow
	trips       []time.Time // when the breaker tripped, trimmed to quotaLadderWindow
	pausedUntil time.Time   // minting refused while now is before it
	timer       *time.Timer // broadcasts slot-available at the pause's end
}

// noteQuotaRefusalLocked records a 486 on slot. Called by markSaturated —
// the one place every 486 reaches the pool, native and csqtt alike — under
// cp.mu, with the pool's clock as `now` so the tests can drive it.
func (cp *credPool) noteQuotaRefusalLocked(slot int, now time.Time) {
	q := &cp.quota
	q.refusals++
	e := cp.pool[slot]
	if e.ts.IsZero() || now.Sub(e.ts) >= quotaFreshCredWindow {
		return // an older credential: a real quota, cured by a fresh identity
	}
	if e.active != 1 {
		return // others hold this identity — its allocations went through; the tenth-allocation quota, not a refusal
	}
	q.fresh = keepSince(append(q.fresh, now), now.Add(-quotaRefusalWindow))
	if len(q.fresh) < quotaRefusalTrip || now.Before(q.pausedUntil) {
		return
	}
	q.trips = keepSince(append(q.trips, now), now.Add(-quotaLadderWindow))
	pause := quotaPauseBase
	for i := 1; i < len(q.trips) && pause < quotaPauseMax; i++ {
		pause *= 2
	}
	if pause > quotaPauseMax {
		pause = quotaPauseMax
	}
	q.pausedUntil = now.Add(pause)
	q.fresh = nil
	if q.timer != nil {
		q.timer.Stop()
	}
	q.timer = time.AfterFunc(pause, cp.broadcastSlotAvailable)
	log.Printf("credpool: the relay refused %d fresh credentials within %s (486 on a credential's first allocation, slot %d last) — minting paused for %s (trip %d within %s); existing slots are still handed out",
		quotaRefusalTrip, quotaRefusalWindow, slot, pause.Round(time.Second), len(q.trips), quotaLadderWindow)
}

// mintPausedLocked reports whether minting is paused at `now` and for how
// much longer. Read by get()'s Phase 2 and by tryFill, under cp.mu.
func (cp *credPool) mintPausedLocked(now time.Time) (remaining time.Duration, paused bool) {
	if now.Before(cp.quota.pausedUntil) {
		return cp.quota.pausedUntil.Sub(now), true
	}
	return 0, false
}

// quotaSnapshot is the breaker's state for the stats: 486s seen this
// session and the pause left, if any.
func (cp *credPool) quotaSnapshot() (refusals int64, paused time.Duration) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	paused, _ = cp.mintPausedLocked(time.Now())
	return cp.quota.refusals, paused
}

// keepSince drops the timestamps at or before `since`; the slice is kept
// in order, so the survivors are a suffix.
func keepSince(ts []time.Time, since time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(since) {
		i++
	}
	return ts[i:]
}
