// SPDX-License-Identifier: MIT

package csqtt

// The deallocate, CONFIRMED — over a UDP relay leg.
//
// pion's relayed conn gives its allocation back with ONE Refresh(LIFETIME 0)
// datagram and does not wait for the answer, and the close shuts the client
// and the socket right behind it. Over TCP that is enough: the stream delivers
// the request and the connection's own close frees the allocation. Over UDP
// nothing says whether the relay ever heard it — and when it did not, or the
// socket's mapping had changed and the relay no longer knows this socket (a
// 437), the allocation lives on at the relay and holds its seat on the
// identity's quota until it expires: a ghost. A lease that went straight back
// to the pool then seats the next worker on an identity the relay counts one
// higher than the pool does, and that worker's Allocate is refused with 486
// (seen in the field behind long sleeps over UDP: two ghosts, eight refusals,
// two workers out for more than two minutes).
//
// So before a UDP allocation is closed the relay is ASKED — a Refresh(0) of
// our own through the TURN client's transaction layer, which retransmits it —
// and its answer read, under a budget. What it said is kept on the Relay
// (Relay.Deallocate) and the worker tells its lease (Credential.OutOfReach):
// what to do with the seat is the POOL's to decide.
//
// 🚫 Never over TCP: nothing is gained there, and a stuck write is what the
// close's write budget exists for.
//
// This is a SECOND INSTANCE of pkg/proxy's confirmed deallocate (dealloc.go
// there: confirmDeallocate, boundedDeallocate) — this package imports nothing
// from pkg/proxy — kept in step BY HAND: the conversation with the relay is the
// same one, and a fix to either is read against the other. The bridge's own
// relay for csqtt 2.5 asks through ConfirmDeallocate too.

import (
	"errors"
	"fmt"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// DeallocateConfirmBudget bounds the wait for the relay's answer: two round
// trips (the challenge, the request) and one retransmission of either (pion's
// RTO is 200 ms). A var so that a test can shrink it; nothing else writes it.
var DeallocateConfirmBudget = 500 * time.Millisecond

// Deallocate is what the relay said to a confirmed deallocate.
type Deallocate int

const (
	DeallocateConfirmed  Deallocate = iota // the relay answered: the allocation is released
	DeallocateGone                         // 437: the relay holds no allocation for this socket — released already, or the mapping has changed and it cannot be reached from here
	DeallocateRefused                      // another error answer
	DeallocateUnanswered                   // nothing came back within the budget, or the request could not be written
	DeallocateNotAwaited                   // the deallocate was written and its answer NOT waited for — a dial that was ended (csqtt 2.5)
)

// UnreleasedError is a relay dial's failure BEHIND an allocation the relay had
// accepted, over a UDP leg, when the relay did not confirm that it released
// that allocation: the dial is over, and the allocation may live on at the
// relay. It reads as the failure it wraps — whoever reads a failed dial's text
// reads the same text — and carries what became of the deallocate, for the
// lease (Credential.OutOfReach).
type UnreleasedError struct {
	Err        error
	Deallocate Deallocate
}

func (e *UnreleasedError) Error() string { return e.Err.Error() }
func (e *UnreleasedError) Unwrap() error { return e.Err }

// OutOfReach reports whether the allocation may live on at the relay where
// this side cannot end it: the relay disowned it for this socket, said nothing
// at all, or was not waited for. A refusal with another error is an answer
// about the request, not about the allocation's whereabouts.
func (d Deallocate) OutOfReach() bool {
	return d == DeallocateGone || d == DeallocateUnanswered || d == DeallocateNotAwaited
}

// Why is the verdict in words, for a log line.
func (d Deallocate) Why() string {
	switch d {
	case DeallocateConfirmed:
		return "its deallocate was confirmed"
	case DeallocateGone:
		return "its deallocate was answered 437"
	case DeallocateRefused:
		return "its deallocate was refused"
	case DeallocateNotAwaited:
		return "its deallocate's answer was not waited for"
	default:
		return "its deallocate was not answered"
	}
}

// stunRoundTrip performs ONE STUN transaction with the relay and returns its
// answer — pion's transaction layer in production (retransmissions included).
type stunRoundTrip func(req *stun.Message) (*stun.Message, error)

// confirmDeallocate asks the relay to release this socket's allocation and
// reads its answer. The client's nonce is pion's own and not exposed, so the
// first request carries no credentials and is answered with a 401 that does;
// a 438 (stale nonce) is owed one more try with the nonce it brings.
func confirmDeallocate(do stunRoundTrip, username, password string) (Deallocate, int, error) {
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
			return DeallocateUnanswered, 0, err
		}
		res, err := do(req)
		if err != nil {
			return DeallocateUnanswered, 0, err
		}
		if res == nil {
			return DeallocateUnanswered, 0, errors.New("no answer")
		}
		if res.Type.Class != stun.ClassErrorResponse {
			return DeallocateConfirmed, 0, nil
		}
		var ec stun.ErrorCodeAttribute
		_ = ec.GetFrom(res)
		code = int(ec.Code)
		switch ec.Code {
		case stun.CodeUnauthorized, stun.CodeStaleNonce:
			if realm.GetFrom(res) != nil || nonce.GetFrom(res) != nil {
				return DeallocateRefused, code, nil // a challenge without a realm or a nonce cannot be answered
			}
			auth = true
		case stun.CodeAllocMismatch:
			return DeallocateGone, code, nil
		default:
			return DeallocateRefused, code, nil
		}
	}
	return DeallocateRefused, code, nil
}

// boundedDeallocate runs confirmDeallocate under a budget. abort must make a
// pending round trip return at once (pion: closing the client's transaction
// map) — it is called when the budget runs out, and the goroutine is joined
// before this returns: nothing is left running behind a close.
func boundedDeallocate(do stunRoundTrip, abort func(), username, password string, budget time.Duration) (Deallocate, int, error) {
	type outcome struct {
		v    Deallocate
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
		return DeallocateUnanswered, 0, fmt.Errorf("no answer within %s", budget)
	}
}

// ConfirmDeallocate asks the relay behind tc to release the allocation of tc's
// socket and returns what it said — within DeallocateConfirmBudget; a relay
// that says nothing by then is DeallocateUnanswered and tc is CLOSED (that is
// what ends the pending transaction). Call it before the relayed conn's own
// Close, with a write deadline already on the control socket, and only over a
// UDP leg.
func ConfirmDeallocate(tc *turn.Client, username, password string) Deallocate {
	do := func(req *stun.Message) (*stun.Message, error) {
		res, err := tc.PerformTransaction(req, tc.TURNServerAddr(), false)
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	v, _, _ := boundedDeallocate(do, tc.Close, username, password, DeallocateConfirmBudget)
	return v
}
