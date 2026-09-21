package proxy

// A session returns AFTER its relay leg is torn down (build 429).
//
// runTURN — the relay leg of the DTLS family (DTLS, WRAP, WRAP-S), of WRAP-A and
// of the direct transport — runs in a goroutine of its own beside the session
// that started it, and the session used to wait for its OWN forwarders alone: it
// returned, gave its credential back to the pool, and its connection re-dialled
// while runTURN's deferred teardown was still under way — over UDP the
// deallocate the relay confirms (dealloc.go), a third of a second on the stand.
// 428's guarantee, "the restart FOLLOWS the relay's answer", held for runTURN
// and not for the session above it: the re-dial reached the relay first and was
// refused with 486, the credential already handed to the next holder. The SRTP
// session never had the gap — its Close tears the relay leg down synchronously,
// inside the session.
//
// So a session that has a relay leg of this kind
//
//   - starts it through its relayLeg — goRunTURN, the ONE place runTURN is
//     started from — and
//   - defers joinRelayLeg right behind the first start: whatever ends the
//     session — its forwarders, a kill, a cancel, an early return out of a
//     handshake or a provisioning that failed — the relay leg is cancelled and
//     WAITED for before the defers registered earlier run, the credential's
//     release first among them. The pool counts the seat as taken until the
//     relay has given it back, so neither this connection's re-dial nor a
//     restart-all's new generation can be seated ahead of the deallocate.
//
// Bounded, as every teardown here is. The relay leg's own teardown is — by the
// write budget on its socket and by the deallocate's confirm budget. But a leg
// that is still dialling, or inside its Allocate, when the session ends is not
// to be cut short: an allocation the relay makes meanwhile has to be given back
// by the leg that asked for it, and against a silent relay pion's ladder runs
// 7.8 s. A stop must not wait for that: after relayJoinBudget the session
// returns WITHOUT its relay leg and says so; the leg ends by itself, as it
// always did.

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// relayJoinBudget bounds a session's wait for its relay leg. What the wait
// spans: what is left of the leg's dial and Allocate when the session ended that
// early; the forwarders' unwinding at the cancel; and the leg's teardown — the
// confirmed deallocate (deallocConfirmBudget) and pion's own, written under
// relayCloseWriteBudget, which started before the confirm and so overlaps it.
// Twice the teardown's own bound. A var so that a test can shrink it; nothing
// else writes it.
var relayJoinBudget = 2 * relayCloseWriteBudget

// relayLeg is a session's hold on the runTURN goroutines it has started — one
// at a time for every transport; the direct session starts another when one has
// ended. The zero value is ready.
type relayLeg struct {
	mu      sync.Mutex
	running int           // started and not yet ended, teardown included
	joined  bool          // the session is ending: nothing is started behind a join
	idle    chan struct{} // made by a join that found a leg running; closed by the last one's end

	gave gaveBack // when the leg gave its allocation back — what the session releases its lease by (seatcool.go)
}

// start registers one more run; false once the session is ending.
func (l *relayLeg) start() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.joined {
		return false
	}
	l.running++
	return true
}

func (l *relayLeg) done() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running--
	if l.running == 0 && l.idle != nil {
		close(l.idle) // once: behind a join nothing is started, the count only falls
	}
}

// join waits until every run has ended or the budget runs out, and reports
// which. From its first statement on, start refuses.
func (l *relayLeg) join(budget time.Duration) bool {
	l.mu.Lock()
	l.joined = true
	if l.running == 0 {
		l.mu.Unlock()
		return true
	}
	if l.idle == nil {
		l.idle = make(chan struct{})
	}
	idle := l.idle
	l.mu.Unlock()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-idle:
		return true
	case <-timer.C:
		return false
	}
}

// goRunTURN starts a session's relay leg — the ONE place runTURN is started
// from. The leg has ENDED when runTURN has returned — its deferred teardown
// behind it — and the session has been told (the result on the channel, then
// after, if any: the DTLS family and WRAP-A cancel the session there, which has
// no transport without its relay). False, and nothing started, once the session
// is ending.
func (p *Proxy) goRunTURN(ctx context.Context, leg *relayLeg, turnAddr string, creds *TURNCreds, conn2 net.PacketConn, connIdx, slotIdx int, after func()) (<-chan error, bool) {
	if !leg.start() {
		return nil, false
	}
	ch := make(chan error, 1)
	go func() {
		defer leg.done()
		ch <- p.runTURN(ctx, turnAddr, creds, conn2, connIdx, slotIdx, &leg.gave)
		if after != nil {
			after()
		}
	}()
	return ch, true
}

// joinRelayLeg ends a session's relay leg and waits for its teardown — ONE body
// for every session that has one, deferred right behind the leg's first start,
// so that it runs BEFORE the credential's release registered above it and on
// EVERY way out of the session.
func (p *Proxy) joinRelayLeg(leg *relayLeg, cancel context.CancelFunc, connIdx int) {
	cancel() // the relay leg ends WITH its session, whatever ended the session
	start := time.Now()
	if leg.join(relayJoinBudget) {
		return
	}
	// The leg left behind is still giving its allocation back — about now, for all
	// this side can tell: the pool keeps the seat counted for the relay's second.
	leg.gave.note(time.Now())
	n := p.dealloc.legsLeft.Add(1)
	waited := time.Since(start)
	frozen := ""
	if waited > 2*relayJoinBudget {
		frozen = " — the process was frozen inside the wait"
	}
	log.Printf("proxy: [conn %d] the session returns WITHOUT its relay leg: not torn down %s after the session's end (budget %s%s) — the restart may outrun its deallocate (%d such since the start)",
		connIdx, waited.Round(time.Millisecond), relayJoinBudget, frozen, n)
}
