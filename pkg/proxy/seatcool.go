package proxy

// The relay's second (build 430).
//
// MEASURED on a stand (2026-09-21, one relay host, RTT 13 ms): the VK relay
// answers a deallocate — Refresh(LIFETIME 0) — at once, with success and
// LIFETIME 0, and keeps the seat on the identity's quota for ONE SECOND more.
// An Allocate that reached it 990 ms behind the deallocate was refused with 486
// (206 of 206), one 1 000 ms behind it was accepted (52 of 52) — over UDP and
// over TCP, for one seat or for all ten of an identity at once. The relay's
// answer says nothing of it, so neither the confirmed deallocate (dealloc.go)
// nor the join of the relay leg (relayjoin.go) can see that second: in the field
// every re-dial that needed a seat given back 20–40 ms earlier was refused — 34
// of 34 — and each refusal benched a good slot for eleven minutes over a second
// of the relay's own.
//
// So:
//
//   - the pool goes on COUNTING a seat for seatCoolFor after the session that
//     held it gave its allocation back. The session notes WHEN (gaveBack — in
//     returnAllocation, the ONE body that gives an allocation back); its lease
//     goes through releaseLease, and the pool lets the seat go by a timer. The
//     session itself returns at once: a re-dial is sent to a slot that has room,
//     or parks until the seat is really free — instead of being refused;
//   - a 486 met on a credential that gave a seat back less than seatLagGrace ago
//     — the margin missed, or a give-back the pool heard of too late — is the
//     relay's second, NOT saturation (markSaturated asks relaysSecondLocked): the
//     slot is not benched, the freshness test of the refusal breaker does not
//     see it, and whoever parks meanwhile is woken when the second is over.
//
// 🚫 A lease whose session gave NO allocation back — none was made, or the relay
// is known to hold none (a 437; a TCP relay that had already dropped the
// connection: the deallocate's write fails) — is released at once: cooling it
// would hold seats nobody holds. When this side cannot tell (an unanswered
// deallocate, a relay leg left behind by its session) the seat is cooled: a
// second of a seat is cheaper than eleven minutes of a slot.

import (
	"io"
	"log"
	"sync/atomic"
	"time"
)

// seatCoolFor is how long the pool keeps counting a seat behind its give-back:
// the relay's second and a margin for what this side cannot see — the second
// runs from the deallocate's ARRIVAL, the note is taken at its answer (UDP) or
// its write (TCP), half a round trip either side. The re-dial's own round trips
// come on top. A var so that a test can shrink it; nothing else writes it.
var seatCoolFor = 1200 * time.Millisecond

// seatLagGrace is how long behind a give-back a 486 on that credential is read
// as the relay's second: the Allocate that drew it left up to seatCoolFor after
// the note if the margin was missed, and the refusal is a round trip old when
// it gets here.
var seatLagGrace = seatCoolFor + time.Second

// gaveBack is a SESSION's note of when its allocation was given back to the
// relay by a deallocate that, as far as this side can tell, reached it. The zero
// value says: nothing was given back. The latest note stands (the direct
// session gives back one allocation after another); take reads and clears it.
type gaveBack struct{ at atomic.Int64 } // unix nanoseconds

func (g *gaveBack) note(t time.Time) {
	if g != nil {
		g.at.Store(t.UnixNano())
	}
}

func (g *gaveBack) take() (time.Time, bool) {
	if g == nil {
		return time.Time{}, false
	}
	if ns := g.at.Swap(0); ns != 0 {
		return time.Unix(0, ns), true
	}
	return time.Time{}, false
}

// returnAllocation gives a session's allocation back to the relay — ONE body
// for every teardown that does (the live SRTP session's Close, the abort of an
// SRTP setup, runTURN's defer): over a UDP relay leg the deallocate the relay
// CONFIRMS (release; nil over TCP — dealloc.go), then the relay conn's own
// Close, which writes pion's fire-and-forget deallocate. It NOTES the moment for
// the pool unless the relay is known to hold no seat for this session: over UDP
// its own word (437), over TCP a deallocate that could not even be written —
// the connection is gone, and a relay drops the allocation of a connection it
// has lost at once. Called with a live write budget on the socket.
func returnAllocation(relayConn io.Closer, release func() deallocVerdict, gave *gaveBack) error {
	held := false
	if release != nil {
		held = release() != deallocGone
	}
	err := relayConn.Close()
	if release == nil {
		held = err == nil
	}
	if held {
		gave.note(time.Now())
	}
	return err
}

// releaseLease gives a session's lease back to the pool — the ONE way a session
// does: at once if it gave no allocation back, behind the relay's second if it
// did.
func (p *Proxy) releaseLease(slot int, creds *TURNCreds, gave *gaveBack) {
	if at, ok := gave.take(); ok {
		p.credPool.releaseGivenBack(slot, creds, at)
		return
	}
	p.credPool.release(slot, creds)
}

// seatStats counts what the relay's second cost and saved since the start.
type seatStats struct {
	cooled        int64     // leases released behind a give-back
	lagRefusals   int64     // 486s read as the relay's second
	lastCooledLog time.Time // the cooled line: one per burst
}

// releaseGivenBack releases a lease whose session gave its allocation back at
// `at`: the seat stays counted — in the entry and in the record of leases still
// out alike, so that no publish of the credential restarts the count — until
// at+seatCoolFor, and release does the rest.
func (cp *credPool) releaseGivenBack(slot int, creds *TURNCreds, at time.Time) {
	if cp == nil || slot < 0 || creds == nil {
		return
	}
	// The relay's second runs in REAL time: the wall clock, which a freeze of this
	// process does not stop — a note carries no monotonic reading, so that a
	// give-back is aged the same whoever took it (gaveBack keeps unix nanoseconds;
	// csqtt's lease hands in a time.Now()).
	at = at.Round(0)
	now := time.Now()
	wait := at.Add(seatCoolFor).Sub(now)
	cp.mu.Lock()
	cp.noteGiveBackLocked(slot, creds, at)
	cp.seat.cooled++
	say := wait > 0 && now.Sub(cp.seat.lastCooledLog) > 5*time.Second
	if say {
		cp.seat.lastCooledLog = now
	}
	cooled, lag := cp.seat.cooled, cp.seat.lagRefusals
	cp.mu.Unlock()
	if wait <= 0 {
		cp.release(slot, creds)
		return
	}
	if say {
		log.Printf("credpool: slot %d keeps a seat counted for %s more — the relay holds a seat for a second behind its deallocate (%d seat(s) cooled, %d refusal(s) read as that second, since the start)",
			slot, wait.Round(time.Millisecond), cooled, lag)
	}
	time.AfterFunc(wait, func() { cp.release(slot, creds) })
}

// noteGiveBackLocked remembers the latest give-back on (slot, credential) — what
// relaysSecondLocked reads. Old notes are dropped as new ones come. Caller
// holds cp.mu.
func (cp *credPool) noteGiveBackLocked(slot int, creds *TURNCreds, at time.Time) {
	if cp.gaveBackAt == nil {
		cp.gaveBackAt = make(map[leaseKey]time.Time)
	}
	for k, t := range cp.gaveBackAt {
		if at.Sub(t) > time.Minute {
			delete(cp.gaveBackAt, k)
		}
	}
	k := leaseKeyOf(slot, creds)
	if at.After(cp.gaveBackAt[k]) {
		cp.gaveBackAt[k] = at
	}
}

// relaysSecondLocked reports whether a 486 on (slot, creds) at `now` is
// explained by a seat this side gave back on that credential a moment ago, and
// when that second is surely over. Caller holds cp.mu.
func (cp *credPool) relaysSecondLocked(slot int, creds *TURNCreds, now time.Time) (over time.Time, ok bool) {
	at, noted := cp.gaveBackAt[leaseKeyOf(slot, creds)]
	if !noted || now.Sub(at) >= seatLagGrace {
		return time.Time{}, false
	}
	return at.Add(seatCoolFor), true
}

// noteRelaysSecondLocked books a 486 that was the relay's second: it IS a 486
// the pool was told of, so the session's total carries it; it says nothing
// about the credential's quota or the relay's will, so neither the slot's
// cooldown nor the breaker's freshness test sees it. Whoever parks meanwhile is
// woken when the second is over. Caller holds cp.mu.
func (cp *credPool) noteRelaysSecondLocked(slot int, over, now time.Time) {
	cp.quota.refusals++
	cp.seat.lagRefusals++
	wake := over.Sub(now)
	if wake < 250*time.Millisecond {
		wake = 250 * time.Millisecond
	}
	time.AfterFunc(wake, cp.broadcastSlotAvailable)
	log.Printf("credpool: a 486 on slot %d right behind our own give-back — the relay's second, not saturation: the slot is NOT benched, a wake in %s (%d such since the start)",
		slot, wake.Round(time.Millisecond), cp.seat.lagRefusals)
}
