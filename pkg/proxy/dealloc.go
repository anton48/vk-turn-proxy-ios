package proxy

// The deallocate, CONFIRMED — over a UDP relay leg (build 428; N3).
//
// pion's relay conn gives its allocation back with ONE Refresh(LIFETIME 0)
// datagram and does not wait for the answer (UDPConn.Close: dontWait) — and our
// teardown closes the client and the socket right behind it, so nothing is
// retransmitted and no answer is ever read. Over TCP that is enough: the stream
// delivers the request, and the connection's own close frees the allocation.
// Over UDP it left two doors open, both seen in the field:
//
//   - THE RESTART OUTRAN ITS OWN DEALLOCATE. A killed session returns at once
//     and its connection re-dials within 1–10 ms; on an identity at its quota
//     (ten allocations per identity and relay) the new Allocate reached the
//     relay before the seat was free: refused with 486, and the slot benched
//     for eleven minutes over a quota error that was our own ghost (2026-09-20,
//     423 over UDP: 22 of 22 such re-dials refused; across the archive 83 % of
//     the attempts whose seat depended on a deallocate less than 20 ms old,
//     20 % of those 20–100 ms after it);
//   - a deallocate that was LOST, or refused for a stale nonce, was never
//     repeated: the allocation held its seat until it expired — up to ten
//     minutes (refusals 10–600 s after the kill).
//
// So before the allocation is closed the teardown asks the relay itself — a
// Refresh(0) of its own through the client's transaction layer, which
// retransmits it (RTO 200 ms) — and WAITS for the answer, under a budget. The
// session's teardown returns only then, and the restart, which begins once the
// session function has returned, FOLLOWS the relay's answer instead of racing a
// datagram — for the SRTP session because its Close is this teardown, for the
// sessions whose relay leg is runTURN in a goroutine of its own because they
// JOIN it before they return (relayjoin.go). pion's own fire-and-forget
// deallocate still goes out afterwards (the relay answers it with 437; nobody
// is listening by then).
//
// Bounded: on a dead path nothing answers and a stop must not hang — after
// deallocConfirmBudget the pending transaction is closed and the teardown goes
// on as it always did; what that leaves behind is said in the log. 🚫 Never
// over TCP: nothing is gained there, and a stuck write is what the teardown's
// write budget exists for.

import (
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// deallocConfirmBudget bounds the wait for the relay's answer: two round trips
// (the challenge, the request) and one retransmission of either (pion's RTO is
// 200 ms). A var so that a test can shrink it; nothing else writes it.
var deallocConfirmBudget = 500 * time.Millisecond

type deallocVerdict int

const (
	deallocConfirmed  deallocVerdict = iota // the relay answered: the allocation is released
	deallocGone                             // 437: the relay holds no allocation for this socket — released already, or the mapping has changed and it cannot be reached from here
	deallocRefused                          // another error answer
	deallocUnanswered                       // nothing came back within the budget, or the request could not be written
)

// stunRoundTrip performs ONE STUN transaction with the relay and returns its
// answer — pion's transaction layer in production (retransmissions included).
type stunRoundTrip func(req *stun.Message) (*stun.Message, error)

// confirmDeallocate asks the relay to release this socket's allocation and
// reads its answer. The client's nonce is pion's own and not exposed, so the
// first request carries no credentials and is answered with a 401 that does;
// a 438 (stale nonce) is owed one more try with the nonce it brings.
func confirmDeallocate(do stunRoundTrip, username, password string) (deallocVerdict, int, error) {
	var realm stun.Realm
	var nonce stun.Nonce
	auth, code := false, 0
	for try := 0; try < 3; try++ { // the challenge, the request, and one more for a stale nonce
		setters := []stun.Setter{
			stun.TransactionID,
			stun.NewType(stun.MethodRefresh, stun.ClassRequest),
			stun.RawAttribute{Type: stun.AttrLifetime, Value: []byte{0, 0, 0, 0}},
		}
		if auth {
			setters = append(setters, stun.NewUsername(username), realm, nonce,
				stun.NewLongTermIntegrity(username, realm.String(), password))
		}
		req, err := stun.Build(append(setters, stun.Fingerprint)...)
		if err != nil {
			return deallocUnanswered, 0, err
		}
		res, err := do(req)
		if err != nil {
			return deallocUnanswered, 0, err
		}
		if res == nil {
			return deallocUnanswered, 0, errors.New("no answer")
		}
		if res.Type.Class != stun.ClassErrorResponse {
			return deallocConfirmed, 0, nil
		}
		var ec stun.ErrorCodeAttribute
		_ = ec.GetFrom(res)
		code = int(ec.Code)
		switch ec.Code {
		case stun.CodeUnauthorized, stun.CodeStaleNonce:
			if realm.GetFrom(res) != nil || nonce.GetFrom(res) != nil {
				return deallocRefused, code, nil // a challenge without a realm or a nonce cannot be answered
			}
			auth = true
		case stun.CodeAllocMismatch:
			return deallocGone, code, nil
		default:
			return deallocRefused, code, nil
		}
	}
	return deallocRefused, code, nil
}

// boundedDeallocate runs confirmDeallocate under a budget. abort must make a
// pending round trip return at once (pion: closing the client's transaction
// map) — it is called when the budget runs out, and the goroutine is joined
// before this returns: nothing is left running behind a teardown.
func boundedDeallocate(do stunRoundTrip, abort func(), username, password string, budget time.Duration) (deallocVerdict, int, error) {
	type outcome struct {
		v    deallocVerdict
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		v, code, err := confirmDeallocate(do, username, password)
		done <- outcome{v, code, err}
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.v, o.code, o.err
	case <-timer.C:
		abort()
		<-done
		return deallocUnanswered, 0, fmt.Errorf("no answer within %s", budget)
	}
}

// deallocStats counts what became of the deallocates since the start — the
// observation a field control needs: a teardown that confirms leaves no other
// trace.
type deallocStats struct {
	confirmed, unconfirmed atomic.Int64
	lastSummaryAt          atomic.Int64 // unix nanoseconds
	legsLeft               atomic.Int64 // sessions that returned without their relay leg — relayjoin.go
}

// releaseAllocation is the confirmed deallocate of a session over a UDP relay
// leg — ONE body for every teardown that gives an allocation back (the SRTP
// session's Close, its setup's abort, runTURN's defers). Called BEFORE the
// relay conn is closed, with a live write budget already on the socket.
func (p *Proxy) releaseAllocation(tc *turn.Client, creds *TURNCreds, connIdx int) {
	start := time.Now()
	do := func(req *stun.Message) (*stun.Message, error) {
		res, err := tc.PerformTransaction(req, tc.TURNServerAddr(), false)
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	v, code, err := boundedDeallocate(do, tc.Close, creds.Username, creds.Password, deallocConfirmBudget)
	p.noteDeallocate(connIdx, v, code, err, time.Since(start))
}

// noteDeallocate counts the outcome and says it: every deallocate that was NOT
// confirmed gets its line; the confirmed ones one line per burst (a mass kill
// or a stop gives back forty at once).
func (p *Proxy) noteDeallocate(connIdx int, v deallocVerdict, code int, err error, took time.Duration) {
	if v == deallocConfirmed {
		n := p.dealloc.confirmed.Add(1)
		now := time.Now().UnixNano()
		if last := p.dealloc.lastSummaryAt.Load(); now-last > int64(5*time.Second) && p.dealloc.lastSummaryAt.CompareAndSwap(last, now) {
			log.Printf("proxy: [conn %d] deallocate confirmed by the relay in %s (%d confirmed, %d not, since the start)",
				connIdx, took.Round(time.Millisecond), n, p.dealloc.unconfirmed.Load())
		}
		return
	}
	n := p.dealloc.unconfirmed.Add(1)
	why := ""
	switch v {
	case deallocGone:
		why = "error 437 — the relay holds no allocation for this socket: released already, or the mapping has changed and it cannot be reached from here"
	case deallocRefused:
		why = fmt.Sprintf("error %d", code)
	default:
		why = fmt.Sprintf("%v", err)
	}
	log.Printf("proxy: [conn %d] deallocate NOT confirmed by the relay after %s (%s) — the allocation may hold its quota seat until it expires (%d confirmed, %d not, since the start)",
		connIdx, took.Round(time.Millisecond), why, p.dealloc.confirmed.Load(), n)
}
