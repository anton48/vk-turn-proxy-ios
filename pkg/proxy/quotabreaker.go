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
// 🚨 FRESH IS NOT ENOUGH: NOTHING MAY HAVE SUCCEEDED ON THE CREDENTIAL. The
// first device run of this breaker (csqtt, 2026-09-15 21:34) showed the
// other 486 a fresh credential gets: ten workers seated on a slot minted
// 5 s earlier, nine allocations succeeded, the TENTH was refused — the
// identity's real quota, on a credential 5 s old; the relay accepted the
// next identity at once. Counted by age alone that is a fresh refusal, and
// two such in one post-switch herd would have paused minting for 30 s
// while the tunnel was recovering on exactly those mints. Build 390 keyed
// the distinction on the refused holder being ALONE on the slot (active ==
// 1) — wrong twice over (the user's review): a herd whose failures OVERLAP
// never shows active == 1 (two failures in flight see active == 2, the
// count ends at zero, twenty 486s and no pause), and "alone" is a proxy
// for what is actually meant. What is meant is SUCCESS: both transports
// tell the pool when an allocation went through (noteAllocated — native the
// moment Allocate() returns in runTURN and setupSRTPSession, csqtt through
// Credential.Allocated right after the relay dial), and a refusal counts
// only on a credential with NO success yet. The storm's
// shape has none on every path — csqtt's worker 1 before TUNCONF, the
// native bootstrap's conn 0, a herd whose ten dials all fail, overlapping
// or not — while the tenth-allocation quota has nine. The archive agrees:
// 296 logs, 8 real 486s, one of them on a credential under a minute old —
// that tenth allocation, after nine successes.
//
// 🚨 THE MARK IS THE ALLOCATION, NOT THE SESSION. Build 391 marked the slot
// at the four "session established" lines, and the user's control stand
// (build 391, a real local TURN accepting nine allocations per credential and
// refusing the tenth, the SRTP handshake delayed, production runSRTPSession)
// showed what that measures: session READINESS — the relay held 18
// allocations, the pool saw allocated 0,0, and the breaker paused minting
// for a plain quota; direct's line even precedes its allocation (a mark with
// nothing behind it), DTLS's and WRAP-A's follow their handshakes. The
// relay's answer to Allocate() IS the fact the breaker keys on; the
// permission, the handshake and the session above are not the relay's
// verdict on the identity. So the two native allocation sites mark the slot
// the moment Allocate() succeeds, and the source scan pins the mark there.
//
// 🚨 THE MARK NAMES THE CREDENTIAL, NOT THE SLOT. The slot number a session
// leased does not identify its credential once the relay's answer is late:
// between the lease and the answer the slot can be cleared and refilled —
// invalidate() on a Resume, invalidateEntry on another holder's 401/403, a
// Phase-2 replacement of an idle saturated slot — and a slot-keyed mark then
// certifies the NEW credential with the OLD one's success. The user's stand
// on build 392: the TURN answer held, the old session cancelled, the slot
// refilled, the answer released — 3/3 the new credential read allocated 1,
// so its own 486s would have passed as its quota with the breaker silent.
// The mark therefore carries the leased credential and counts only if the
// slot still holds that identity, checked under the lock. The identity is
// the username — what the relay keys its acceptance on, not our slot or our
// copy of it: the same credential fetched into the slot again IS the
// identity the relay accepted.
//
// 🚨 THE LADDER MUST NOT DECAY WHILE THE RELAY STILL REFUSES. A first cut
// kept a window of trips and doubled per trip inside it, so a refusal that
// outlasted the window LOST rungs: 30 → 60 → 120 → 240 → 300 → 120 (the
// user's model-time check) — the bound loosened exactly for the long
// outage it exists for. Each trip now doubles the PREVIOUS pause when it
// comes within quotaLadderWindow of the previous trip, and starts over at
// the base only after that long a quiet: 30 → 60 → 120 → 240 → 300 → 300 …
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
	refusals    int64         // every 486 the pool was told of, this session — both transports
	fresh       []time.Time   // refusals on fresh credentials with no success, trimmed to quotaRefusalWindow
	trips       int           // how many times the breaker tripped, this session (the log)
	lastTrip    time.Time     // when it last tripped — the ladder's clock
	lastPause   time.Duration // the pause that trip set — doubled by the next trip within the window
	pausedUntil time.Time     // minting refused while now is before it
	timer       *time.Timer   // broadcasts slot-available at the pause's end
}

// noteAllocated records a successful allocation on creds, the credential the
// caller leased from slot — the evidence that the relay accepts this
// identity, so a later 486 on it is its quota, not a refusal. Native calls it
// the moment Allocate() succeeds (runTURN, setupSRTPSession — before
// CreatePermission and any handshake); csqtt through Credential.Allocated
// right after the relay dial. The slot number alone does not name the
// credential (the doc block above): the mark is checked under the lock
// against the credential the slot holds NOW, and a late mark for one the
// slot no longer holds is dropped with a log line. Nil-safe: the transport
// helpers run in tests on a Proxy without a pool.
func (cp *credPool) noteAllocated(slot int, creds *TURNCreds) {
	if cp == nil || slot < 0 || creds == nil || creds.Username == "" {
		return
	}
	late := false
	cp.mu.Lock()
	if slot < cp.size && slot < len(cp.pool) {
		if now := cp.pool[slot].creds; now != nil && now.Username == creds.Username {
			cp.pool[slot].allocated++
		} else {
			late = true
		}
	}
	cp.mu.Unlock()
	if late {
		log.Printf("credpool: a late allocation success on slot %d names a credential the slot no longer holds — not counted (the slot was refilled while the relay's answer was in flight)", slot)
	}
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
	if e.allocated > 0 {
		return // this identity has been accepted before: its quota, not the relay's refusal
	}
	q.fresh = keepSince(append(q.fresh, now), now.Add(-quotaRefusalWindow))
	if len(q.fresh) < quotaRefusalTrip || now.Before(q.pausedUntil) {
		return
	}
	pause := quotaPauseBase
	if !q.lastTrip.IsZero() && now.Sub(q.lastTrip) < quotaLadderWindow {
		pause = q.lastPause * 2
		if pause > quotaPauseMax {
			pause = quotaPauseMax
		}
	}
	q.trips++
	q.lastTrip, q.lastPause = now, pause
	q.pausedUntil = now.Add(pause)
	q.fresh = nil
	if q.timer != nil {
		q.timer.Stop()
	}
	q.timer = time.AfterFunc(pause, cp.broadcastSlotAvailable)
	log.Printf("credpool: the relay refused %d fresh credentials within %s (486 with no allocation ever accepted on them, slot %d last) — minting paused for %s (trip %d); existing slots are still handed out",
		quotaRefusalTrip, quotaRefusalWindow, slot, pause.Round(time.Second), q.trips)
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
