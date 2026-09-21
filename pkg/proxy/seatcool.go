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

// gaveBack is a SESSION's note for the pool of what became of its allocation:
// WHEN it was given back to the relay by a deallocate that, as far as this side
// can tell, reached it (at — the relay's second runs from there), or UNTIL when
// an allocation the relay disowned for this socket may go on holding its seat
// (until — outofreach.go); and, for that, what the session learnt of the
// allocation's life meanwhile (life). The zero value says: nothing was given
// back, nothing is held. The latest note stands (the direct session gives back
// one allocation after another); take and takeHold read and clear.
type gaveBack struct {
	at    atomic.Int64 // unix nanoseconds
	until atomic.Int64 // unix nanoseconds, wall clock
	life  allocLife
}

// watch tells the note's life who its session is — before the session's client
// exists, never again.
func (g *gaveBack) watch(kill func(), connIdx int, udp bool) {
	g.life.kill, g.life.connIdx, g.life.udp = kill, connIdx, udp
}

// lifeOf is the note's allocLife, nil for a caller with no note.
func (g *gaveBack) lifeOf() *allocLife {
	if g == nil {
		return nil
	}
	return &g.life
}

// noteOutOfReach is the note of an allocation the relay has disowned for this
// socket (its deallocate answered 437): if it lives on under another mapping it
// holds its seat until it expires — so the seat stays counted until it CAN have
// expired. EXPIRED BY THE CLOCK already, nothing is noted: the 437 is honest,
// and the seat free at once.
func (g *gaveBack) noteOutOfReach(now time.Time) {
	if g == nil {
		return
	}
	if until := g.life.expiry(now); until.After(now) {
		g.until.Store(until.UnixNano())
	}
}

func (g *gaveBack) takeHold() (time.Time, bool) {
	if g == nil {
		return time.Time{}, false
	}
	if ns := g.until.Swap(0); ns != 0 {
		return time.Unix(0, ns), true
	}
	return time.Time{}, false
}

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
// Close, which writes pion's fire-and-forget deallocate. It NOTES for the pool
// what became of the seat:
//
//   - given back — confirmed, or as far as this side can tell (an unanswered or
//     refused deallocate over UDP, a deallocate that was written over TCP): the
//     moment, for the relay's second;
//   - over TCP a deallocate that could not even be written: nothing — the
//     connection is gone, and a relay drops the allocation of a connection it
//     has lost at once;
//   - 🚫 a 437 over UDP is NOT "the relay holds nothing" (430 read it so, and the
//     field refuted it the same day): it says that THIS SOCKET has no
//     allocation. If the mapping changed the allocation lives on, out of reach,
//     and holds its seat until it expires — noteOutOfReach; and the session says
//     what its mapping did (outofreach.go). The same for a deallocate left
//     unanswered on a socket the relay had already disowned.
//
// Called with a live write budget on the socket, and before the client's Close.
func returnAllocation(relayConn io.Closer, release func() deallocVerdict, gave *gaveBack) error {
	held, inReach := false, true
	if release != nil {
		switch release() {
		case deallocConfirmed:
			held = true
		case deallocGone:
			inReach = false
		default:
			held, inReach = true, !gave.lifeOf().isGone()
		}
	}
	if !inReach {
		gave.lifeOf().sayMapping("its deallocate was answered as for a socket with no allocation")
	}
	err := relayConn.Close()
	if release == nil {
		held = err == nil
	}
	switch {
	case !inReach:
		gave.noteOutOfReach(time.Now())
	case held:
		gave.note(time.Now())
	}
	return err
}

// releaseLease gives a session's lease back to the pool — the ONE way a session
// does: at once if it gave no allocation back, behind the relay's second if it
// did.
func (p *Proxy) releaseLease(slot int, creds *TURNCreds, gave *gaveBack) {
	if until, ok := gave.takeHold(); ok {
		gave.take() // an allocation out of reach outlasts any second
		p.credPool.holdSeatUntil(slot, creds, until)
		return
	}
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
	heldOut       int64     // leases kept counted for an allocation out of reach (outofreach.go)
	lastHeldLog   time.Time
}

// seatHoldStep is how often a held seat's release looks at the WALL clock: the
// relay's lifetime runs in real time, a timer's clock stops with the process —
// so a long wait is cut into steps, and a seat whose time ran out across a
// freeze is let go within one step of the thaw. A var for tests.
var seatHoldStep = 10 * time.Second

// wallClock is the clock a held seat is let go by. A var so that a test can let
// it run ahead of the timers', as it does across a freeze.
var wallClock = func() time.Time { return time.Now().Round(0) }

// holdSeatUntil releases a lease whose allocation is OUT OF REACH (its deallocate
// answered 437): the seat stays counted — the relay may hold it under another
// mapping — until `until`, the wall-clock moment the allocation can have expired
// at the latest. 🚫 No give-back is noted: a 486 behind it is not the relay's
// second, and benches the slot as any other.
func (cp *credPool) holdSeatUntil(slot int, creds *TURNCreds, until time.Time) {
	if cp == nil || slot < 0 || creds == nil {
		return
	}
	now := time.Now()
	cp.mu.Lock()
	cp.seat.heldOut++
	say := until.After(now) && now.Sub(cp.seat.lastHeldLog) > 5*time.Second
	if say {
		cp.seat.lastHeldLog = now
	}
	n := cp.seat.heldOut
	cp.mu.Unlock()
	if say {
		log.Printf("credpool: slot %d keeps a seat counted for %s more — its deallocate was answered 437: if the allocation lives on under another mapping it holds the seat until it expires (%d such seat(s) since the start)",
			slot, until.Sub(now).Round(time.Second), n)
	}
	cp.releaseAt(slot, creds, until.Round(0))
}

// releaseAt releases a lease at a WALL-clock moment (seatHoldStep). A pool whose
// context has ended counts for nobody: the steps stop with it.
func (cp *credPool) releaseAt(slot int, creds *TURNCreds, until time.Time) {
	if cp.ctx != nil && cp.ctx.Err() != nil {
		return
	}
	left := until.Sub(wallClock())
	if left <= 0 {
		cp.release(slot, creds)
		return
	}
	if left > seatHoldStep {
		left = seatHoldStep
	}
	time.AfterFunc(left, func() { cp.releaseAt(slot, creds, until) })
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
