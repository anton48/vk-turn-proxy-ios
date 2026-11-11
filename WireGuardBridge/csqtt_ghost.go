package main

// A csqtt lease whose allocation is OUT OF REACH — both generations.
//
// Over a UDP relay leg an allocation can outlive the stream that made it: the
// phone sleeps, the NAT in front of it forgets the socket's mapping, and at
// the wake the relay no longer knows the socket — the stream is replaced, its
// deallocate is answered 437 or not at all, and the allocation lives on at the
// relay under the OLD mapping, holding its seat on the identity's quota until
// it expires. A lease that went back to the pool behind the relay's second
// (seatcool.go) then let the next worker be seated on an identity the relay
// counted one higher than the pool: refused with 486, the slot benched.
//
// The rule (the user's, 2026-11-11):
//
//   - the relay's word on the deallocate is ASKED (csqtt.ConfirmDeallocate —
//     2.1.9's relay in pkg/csqtt, 2.5's in csqtt25_relay.go) and the stream's
//     end hands it to the lease (csqtt.Credential.OutOfReach);
//   - a seat whose deallocate was answered 437 or not at all stays COUNTED for
//     csqttGhostHold — a whole allocation lifetime from the close: the last
//     refresh may have been granted a moment before it, and this side keeps no
//     record of the grants (native reads them out of pion's log lines; here the
//     flat lifetime is the upper bound of all of them);
//   - UNLESS the process slept longer than an allocation lives at some point
//     since the allocation was made: no refresh was sent in such a sleep, so
//     whatever was granted before it ran out inside it — the 437 is honest, the
//     silence harmless, and the seat is free at once.
//
// Over TCP nothing of this applies (the close asks nothing: the connection's
// own close frees the allocation), and a lease that never held an allocation
// goes back at once as before.

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// csqttGhostHold is how long an out-of-reach seat stays counted: the lifetime
// the relay gives an allocation that asks for none (pion asks for none) — ten
// minutes. A constant: the watch's goroutine reads it, and nothing a running
// goroutine reads is a test's to change (a test shortens its own adapter's
// hold instead — csqttPoolAdapter.hold).
const csqttGhostHold = 10 * time.Minute

// csqttSleepStep is how often the sleep watch looks at the clock. A sleep is a
// gap between two looks; a refresh granted between the last look and the
// sleep's start is covered by asking for one step more than a lifetime.
const csqttSleepStep = 5 * time.Second

// csqttWallClock is the clock the watch and the hold go by: the WALL clock,
// which a sleeping process does not stop.
func csqttWallClock() time.Time { return time.Now().Round(0) }

// csqttSleepWatch remembers the latest sleep longer than an allocation lives.
// Its looks are the ticks of run and every question asked of it — a question
// right behind a thaw must not depend on the ticker having fired first.
//
// A sleep is seen as a GAP between two looks, and where inside the gap the
// process stopped and started again is not known. So what is kept is the look
// the gap BEGAN at: an allocation made by then was there before the sleep and
// did not survive it; one made later — in the last step before the sleep, or
// behind the thaw and ahead of the look that noticed — is not judged by it
// (the first is then held although it has expired: the safe side).
type csqttSleepWatch struct {
	last      atomic.Int64 // the previous look, unix nanoseconds (0 = none yet)
	longBegan atomic.Int64 // the look the latest gap ≥ a lifetime + a step began at (0 = none)
}

// look notes the clock: a gap since the previous look of a lifetime and a step
// or more is a sleep no allocation survived.
func (w *csqttSleepWatch) look(now time.Time) {
	n := now.UnixNano()
	prev := w.last.Swap(n)
	if prev != 0 && time.Duration(n-prev) >= csqttGhostHold+csqttSleepStep {
		w.longBegan.Store(prev)
	}
}

// outlived reports whether the process has slept longer than an allocation
// lives since an allocation made at `since` was there.
func (w *csqttSleepWatch) outlived(since, now time.Time) bool {
	if w == nil {
		return false
	}
	w.look(now)
	began := w.longBegan.Load()
	return began != 0 && since.UnixNano() <= began
}

// run looks at the clock every step (csqttSleepStep) until ctx ends. Without
// these looks a long AWAKE stretch between two questions would read as a
// sleep, and a live ghost's seat would be given away.
func (w *csqttSleepWatch) run(ctx context.Context, step time.Duration) {
	w.look(csqttWallClock())
	t := time.NewTicker(step)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.look(csqttWallClock())
		}
	}
}

// csqttSeatHolder is what the rule needs of the pool (proxy.CredPool).
type csqttSeatHolder[C any] interface {
	Release(slot int, creds C, addr string)
	ReleaseHeld(slot int, creds C, addr string, until time.Time, why string)
}

// csqttReleaseOutOfReach gives back a lease whose allocation the relay did not
// confirm released: held for `hold` from now, or free at once if the process
// has slept a lifetime through since the allocation was made (madeAt). now is
// the wall clock's reading.
func csqttReleaseOutOfReach[C any](pool csqttSeatHolder[C], sleep *csqttSleepWatch, workerID, slot int, creds C, addr string, madeAt, now time.Time, hold time.Duration, why string) {
	if sleep.outlived(madeAt, now) {
		log.Printf("csqtt: worker %d: %s, and the process has slept longer than an allocation lives since it was made — it has expired, the seat is free", workerID, why)
		pool.Release(slot, creds, addr)
		return
	}
	pool.ReleaseHeld(slot, creds, addr, now.Add(hold), why)
}
