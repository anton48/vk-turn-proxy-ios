package main

// A csqtt 2.5 stream whose relay says it has NO ALLOCATION for the stream's socket.
//
// Behind a sleep on a UDP leg the socket's mapping can have changed (a carrier's
// NAT forgets it within minutes), or the allocation has simply run out: the relay
// then has no allocation for the address the stream's packets arrive from, and
// nothing the stream sends is forwarded any more. The engine finds such a stream
// by its SILENCE — asked at the wake, replaced when the wake's window ends, five
// seconds later (ten over TCP). But the relay has said so itself, and earlier:
// the TURN client's permission refresh, overdue behind the sleep, goes out at the
// thaw and is answered 400 within a round trip — what a socket WITHOUT an
// allocation is answered (measured on the relay; pkg/proxy/outofreach.go's
// header). The native session ends on that word at once; so does a 2.5 stream:
//
//   - the bridge's TURN client is given csqtt25RelayEar for its logger factory —
//     pion's lines are the only place a refresh's outcome is said. They go out
//     exactly as before, and each Warn / Error line is also heard;
//   - a line that is a permission refresh answered 400 (ONE predicate with the
//     native session: proxy.RelayHoldsNoAllocation) closes the stream's relay —
//     once, and never on pion's own goroutine, which calls from inside the client;
//   - the engine is told nothing new: its stream's socket ends, the session ends
//     as it does for any socket that is gone, and the worker dials again behind
//     its ordinary wait. The close is the ordinary close: over UDP it asks the
//     relay about the deallocate, hears 437, and the lease keeps the seat counted
//     (csqtt_ghost.go).
//
// 🚫 Only the permission refresh's 400: an allocation refresh the relay refuses is
// swallowed by pion without a word, and any other failed refresh — no answer on a
// path that is still coming back — says nothing about the allocation.
//
// pkg/csqtt (2.1.9) is not touched: its relay is its own, and its liveness rules
// find such a worker as they did.

import (
	"fmt"
	"sync/atomic"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// csqtt25RelayEar is the logger factory of one stream's TURN client.
type csqtt25RelayEar struct {
	inner logging.LoggerFactory        // where pion's lines go, as before: the default factory at Warn
	relay atomic.Pointer[csqtt25Relay] // set once the dial has its relay; a line before that names nothing to end
}

// csqtt25NewRelayEar makes the ear a dial hands its TURN client. Behind a
// variable for the tests.
var csqtt25NewRelayEar = func() *csqtt25RelayEar {
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelWarn
	return &csqtt25RelayEar{inner: lf}
}

func (e *csqtt25RelayEar) NewLogger(scope string) logging.LeveledLogger {
	return &csqtt25RelayLogger{LeveledLogger: e.inner.NewLogger(scope), ear: e}
}

// heard is every Warn / Error line of the client.
func (e *csqtt25RelayEar) heard(msg string) {
	if !proxy.RelayHoldsNoAllocation(msg) {
		return
	}
	if r := e.relay.Load(); r != nil {
		r.noAllocation()
	}
}

// csqtt25RelayLogger passes every line on and lets the ear hear the Warn and
// Error ones — the levels pion says a failed refresh at.
type csqtt25RelayLogger struct {
	logging.LeveledLogger
	ear *csqtt25RelayEar
}

func (l *csqtt25RelayLogger) Warn(msg string) {
	l.LeveledLogger.Warn(msg)
	l.ear.heard(msg)
}

func (l *csqtt25RelayLogger) Warnf(format string, args ...interface{}) {
	l.LeveledLogger.Warnf(format, args...)
	l.ear.heard(fmt.Sprintf(format, args...))
}

func (l *csqtt25RelayLogger) Error(msg string) {
	l.LeveledLogger.Error(msg)
	l.ear.heard(msg)
}

func (l *csqtt25RelayLogger) Errorf(format string, args ...interface{}) {
	l.LeveledLogger.Errorf(format, args...)
	l.ear.heard(fmt.Sprintf(format, args...))
}

// noAllocation is the relay's word that this socket has no allocation: the
// allocation is closed — the stream's reads and writes end with it. Once; not
// for a relay whose close is already under way (it ended for another reason —
// nothing is left to say); and on a goroutine of its own, for pion says the line
// from inside the client the close is about to end. Whoever closes the relay
// beside it — the stream's own end — waits for this close (Close's once).
func (r *csqtt25Relay) noAllocation() {
	if r.closing.Load() || !r.gone.CompareAndSwap(false, true) {
		return
	}
	go func() {
		if say := r.said.Load(); say != nil {
			(*say)()
		}
		r.Close()
	}()
}

// onNoAllocation registers what is put in the log when the relay says it has no
// allocation for this stream's socket — the dialer names the worker
// (csqtt25_bridge.go).
func (c csqtt25RelayConn) onNoAllocation(say func()) { c.r.said.Store(&say) }
