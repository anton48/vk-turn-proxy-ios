package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// SPLITTING THE POOL: the synthetic on one set of allocations, WireGuard on the
// other, so the two streams share the relay and the phone but NOT an allocation.
//
// 🎯 THE QUESTION, and it is the last fork left in the uplink-loss investigation.
// A paced synthetic that loses ~0 alone loses 0.5-2.7% the moment real TCP runs
// beside it, on both transports, and the loss is synchronised across allocations
// (83-99% of gap events coincide within 10 ms, against a permutation null of
// 5-21%). Two mechanisms explain that equally well and nothing separates them:
//
//	per-allocation  — each allocation has its own meter or buffer, and the
//	                  client's burst empties many of them at once;
//	above it        — one resource shared by all 30: the relay's egress, its
//	                  CPU, or the relay → server1 leg.
//
// A capture at server1 cannot tell them apart — three ways of asking "was the
// losing allocation the one bursting" bracket the proportional null, because the
// deciding quantity is only observable through a channel the drop itself
// corrupts. So the discrimination has to be built into the EXPERIMENT.
//
// 🚨 WHY NOT TWO RELAYS FIRST (user's correction, and it is right): splitting
// 15+15 across two relays changes TWO things at once — whether the streams share
// an ALLOCATION and whether they share a HOST. This flag changes only the first.
// If the synthetic goes clean here, the answer is per-allocation and two relays
// are unnecessary; if it still loses, the resource is above the allocation and
// the two-relay run is the next question, not the first.
//
// ⚡ AND NOTE WHAT A CLEAN RESULT WOULD ALSO EXCLUDE: the phone. The radio, the
// socket, this dispatcher and the air are shared no matter how the allocations
// are split, so if the loss disappears when only the allocations become disjoint,
// nothing on our side can be the cause.
//
// ⚠️ THE CONFOUND TO CONTROL WHEN SCORING: splitting halves each stream's
// fan-out, so per-allocation load and the reordering each stream sees both
// change. Hold the SYNTHETIC's per-allocation rate constant — 30 Mbit/s over 30
// connections and 15 Mbit/s over 15 are both ~1 Mbit/s per allocation — and
// compare against the ramp's measured "alone at that level" figure of 0.02-0.03%.
//
// 🚫 OFF IS BYTE-FOR-BYTE THE CURRENT BEHAVIOUR. At 0 the writer indirection
// below is not entered at all and every packet takes the shared channel exactly
// as it does today. This is a DIAGNOSTIC, like the retired chunk size: no UI, no
// backup field, driven only by the paired runner as an arm.

// UplinkSplitOff is the default: one shared queue, every writer serving it.
const UplinkSplitOff = 0

// splitState binds the mode to the channel that will announce its END.
//
// 🚨🚨 WHY ONE STRUCT AND NOT TWO VARIABLES — this is a LOST WAKE-UP, and the
// first version of this file had it. With the size in one atomic and the wake
// channel in another, a writer can interleave like this:
//
//  1. reads n = 15 and picks synthCh;
//  2. SetUplinkSplitN(0) stores the new size, installs a fresh channel and
//     closes the old one;
//  3. only NOW does the writer evaluate the wake channel — and gets the NEW,
//     still-open one;
//  4. it parks on {old synthCh, new wake} and misses the close that was meant
//     for it. synthCh will never be filled again and the new channel only closes
//     on the NEXT change, so it sleeps through the whole arm.
//
// The invariant that fixes it: **the state you read is bound to the wake that
// supersedes it.** One snapshot, loaded once, used for both the decision and the
// parking — so whichever side of the swap a reader lands on, the channel it
// holds is the one the NEXT change closes. *(User-caught, 2026-08-16, after the
// first fix closed only the half where the writer parks BEFORE the flip.)*
// splitMode says WHERE the two streams are put relative to each other. The three
// values are the three arms of the experiment, and they differ in exactly one
// thing each — which is the whole point.
type splitMode uint8

const (
	// splitOffMode: one shared pool, every writer serving everything. Production.
	splitOffMode splitMode = iota
	// splitDisjoint: the synthetic on group A, WireGuard on group B. The streams
	// share the relay and the phone but NOT an allocation.
	splitDisjoint
	// splitColocated: BOTH streams on group A; group B carries nothing.
	//
	// 🚨 THIS ARM EXISTS BECAUSE THE HISTORICAL "shared" ONE IS NOT A CONTROL FOR
	// THE SPLIT. Shared moves three things at once — whether TCP is on the
	// synthetic's allocations, the synthetic's fan-out (30 against 15) and its
	// rate (30 against 15 Mbit/s) — so "shared loses while split ≈ solo" could be
	// caused by the fan-out or the level rather than by the neighbour. Colocated
	// holds the synthetic's own conditions FIXED (same 15 allocations, same 15
	// Mbit/s, same everything) and changes only WHERE the neighbour is: nowhere
	// (solo), on my allocations (colocated), on the other fifteen (split).
	// *(User-caught, 2026-08-16.)*
	splitColocated
)

type splitState struct {
	n    int
	mode splitMode
	wake chan struct{}
}

// on reports whether any grouping is in force.
func (s *splitState) on() bool { return s.mode != splitOffMode && s.n > UplinkSplitOff }

var (
	splitCur   atomic.Pointer[splitState]
	splitSetMu sync.Mutex
)

func init() {
	splitCur.Store(&splitState{n: UplinkSplitOff, mode: splitOffMode, wake: make(chan struct{})})
}

// splitNow returns the current snapshot. Load it ONCE per decision and use both
// fields from that one value; re-reading either separately re-opens the race
// this type exists to close.
func splitNow() *splitState { return splitCur.Load() }

// SetUplinkSplitN applies the split to THIS process without a reconnect, so an
// arm costs no 107-second thirty-connection ramp. Clamped: a value that would
// leave either side without a writer is meaningless, and 0 is off.
//
// Swap FIRST, then close the superseded channel: every reader that lands after
// the swap gets the new mode, and every reader that landed before it holds a
// channel that is about to close.
func SetUplinkSplitN(n int) { SetUplinkSplit(n, false) }

// SetUplinkSplit applies the size AND the mode together — they are one decision,
// and applying them in two calls would make the tunnel pass through a state
// nobody asked for.
func SetUplinkSplit(n int, colocated bool) {
	splitSetMu.Lock()
	defer splitSetMu.Unlock()
	old := splitCur.Load()
	next := &splitState{n: ClampUplinkSplitN(n), mode: splitDisjoint, wake: make(chan struct{})}
	if next.n <= UplinkSplitOff {
		next.mode = splitOffMode
	} else if colocated {
		next.mode = splitColocated
	}
	splitCur.Store(next)
	close(old.wake)
}

// ClampUplinkSplitN keeps the split inside [0, 29]: at least one connection must
// remain on each side, and 0 means off.
func ClampUplinkSplitN(n int) int {
	if n <= UplinkSplitOff {
		return UplinkSplitOff
	}
	if n > 29 {
		return 29
	}
	return n
}

// uplinkSplit reports the split size, 0 when off. For callers that need only the
// size and never park — the summary line, and tests.
func uplinkSplit() int {
	st := splitNow()
	if !st.on() {
		return UplinkSplitOff
	}
	return st.n
}

// synthDepthHook lets the summary READ the synthetic queue's depth. Read-only on
// purpose: the transfer that used to live here is what destroyed packets, and
// what is wanted now is only the observation.
//
// 🚨 WHY THE DEPTH IS PRINTED AT ALL. With the split off, a packet left in that
// queue is served by the next writer to loop — the un-split closes the wake, so
// every writer loops immediately, which is what makes the transition lossless.
// If a non-zero depth were ever to SURVIVE an un-split, those packets would sit
// while the other arm sends thousands of newer counters, and past the receiver's
// 8128-counter window they arrive `stale` and the loss never recovers. That is
// not a footnote for the end of the run — it invalidates the arm on the spot, so
// it has to be on the line the run is read from.
var synthDepthHook atomic.Value // func() int

func synthQueueDepth() int {
	f, _ := synthDepthHook.Load().(func() int)
	if f == nil {
		return 0
	}
	return f()
}

// splitOwnsSynth says whether this writer serves the synthetic's group under a
// given split size. Takes the size as an argument rather than reading it, so the
// caller's snapshot is the only source of truth.
func splitOwnsSynth(connIdx, n int) bool { return connIdx >= 0 && connIdx < n }

// splitAdmits reports whether this writer may SEND the packet it has just
// dequeued, under the mode in force RIGHT NOW.
//
// 🚨 WHY A CHECK AFTER THE DEQUEUE AND NOT ONLY BEFORE IT. Go's `select` picks
// UNIFORMLY AT RANDOM among ready cases. When the split is armed while a writer
// is parked on the shared channel, the closed wake and a WireGuard packet can be
// ready at the same instant — and half the time the writer takes the packet and
// sends it under the OLD mode, onto an allocation that now belongs to the
// synthetic. It is a handful of packets per transition, but it is a hole in the
// guarantee AND it was invisible: the legacy branch never called the counter, so
// `wrong=` could not see it. *(User-caught, 2026-08-16.)*
//
// The epoch is therefore checked where it can be checked exactly — on the packet,
// after it is in hand.
func splitAdmits(connIdx int, item sendItem) bool {
	st := splitNow()
	if !st.on() {
		return true
	}
	if st.mode == splitColocated {
		// Both streams live on group A; group B may send nothing at all.
		return splitOwnsSynth(connIdx, st.n)
	}
	return splitOwnsSynth(connIdx, st.n) == item.synth
}

// requeueStale puts a packet that no longer belongs to this writer back on the
// queue its group now reads, WITHOUT blocking. Returns false when that queue is
// full — the caller then sends it anyway and counts a leak, because dropping it
// would be loss, and a visible leak beats an invented gap.
func (p *Proxy) requeueStale(item sendItem) bool {
	dst := p.sendCh
	if item.synth && splitNow().on() {
		dst = p.synthCh
	}
	select {
	case dst <- item:
		splitRequeued.Add(1)
		return true
	default:
		return false
	}
}

// splitLeftover counts packets taken out of the synthetic's queue by an ORDINARY
// writer after the split was turned off.
//
// 🚨 WHY THERE IS NO DRAIN FUNCTION ANY MORE, and this is the important part.
// The first version copied the leftovers into the shared queue with a timeout
// and dropped them if it expired — and the comment claiming "room is guaranteed"
// on the put-back was simply FALSE: the drain frees a slot in `synthCh` by taking
// the packet, a blocked producer takes that slot, the copy times out, and the
// put-back finds no room. The packet then vanished with no counter at all.
// *(User-caught, 2026-08-16.)*
//
// ⚠️ And waiting was not harmless either: while a leftover sits unserved the
// other arm sends thousands of NEWER sequence numbers, and once the receiver's
// 8128-counter window has passed it, the packet arrives `stale` and the loss is
// never recovered. So "it will fly when the split comes back" was not a rescue.
//
// ⇒ 🎯 THE FIX IS TO REMOVE THE TRANSFER, NOT TO PERFECT IT. With the split off,
// a synthetic packet is legal for ANY writer, so the ordinary dispatch path
// serves `synthCh` whenever it is non-empty. Nothing is copied, nothing is
// dropped, nothing waits on a timer, and the packets keep their order.
var (
	splitLeftover atomic.Int64
	splitRequeued atomic.Int64
	splitLeaked   atomic.Int64
	splitSynthToA atomic.Int64
	splitSynthToB atomic.Int64
	splitWGToA    atomic.Int64
	splitWGToB    atomic.Int64
)

// noteSplitDispatch counts, for every dispatched packet, WHICH KIND went to
// WHICH GROUP — not just how many of each kind there were.
//
// 🚨 THE CROSS TERMS ARE THE POINT. `synth→B` and `wg→A` must both be ZERO while
// the split is armed, and printing them is what turns "the code cannot do that"
// into "it did not do that on this run". A design guarantee that is never
// observed is exactly how a lever gets believed for nine runs while inert.
func noteSplitDispatch(synth, toA bool) {
	switch {
	case synth && toA:
		splitSynthToA.Add(1)
	case synth:
		splitSynthToB.Add(1)
	case toA:
		splitWGToA.Add(1)
	default:
		splitWGToB.Add(1)
	}
}

// SplitStatsAndReset reports every split counter and clears them ALL in one
// call.
//
// 🚨 It returns the requeue and leak counts rather than leaving them to the
// caller, because the first version cleared them here and read them afterwards —
// so the field printed 0 no matter what happened. A reset that runs before the
// read is the same silent zero this project has now shipped three times.
func SplitStatsAndReset() (synthA, synthB, wgA, wgB, requeued, leaked, leftover int64, n int) {
	return splitSynthToA.Swap(0), splitSynthToB.Swap(0),
		splitWGToA.Swap(0), splitWGToB.Swap(0),
		splitRequeued.Swap(0), splitLeaked.Swap(0), splitLeftover.Swap(0), uplinkSplit()
}

// splitSummary renders the engagement witness and CLEARS the interval. Empty
// when the split is off, so an ordinary run prints nothing.
//
// 🚨 READ IT BEFORE BELIEVING ANY RESULT FROM A SPLIT ARM. It answers the
// question that a knob's VALUE cannot: whether both groups actually carried
// traffic. A split armed while one side reads 0 tested nothing — the same
// failure as a chunk size that is live but inert on a shallow queue, which cost
// this project nine runs.
func splitSummary() string {
	synthA, synthB, wgA, wgB, requeued, leaked, leftover, n := SplitStatsAndReset()
	mode := splitNow().mode
	if n <= UplinkSplitOff {
		// 🚨 One exception to the silence: leftovers served by the ordinary path
		// AFTER an un-split. They are not an error — that is the design — but a
		// large number means the switch left a lot behind, and the reader should
		// see it rather than infer it.
		if depth := synthQueueDepth(); depth > 0 {
			return fmt.Sprintf(" split=0 leftover-sent=%d 🚨 leftover-QUEUED=%d — the split is "+
				"OFF and packets are still in the synthetic queue; they age past the receiver's "+
				"8128-counter window and become loss that never recovers. THIS ARM IS VOID",
				leftover, depth)
		}
		if leftover > 0 {
			return fmt.Sprintf(" split=0 leftover-sent=%d", leftover)
		}
		return ""
	}
	// A leak is a packet that WAS sent under the superseded mode, so it counts as
	// wrong; a requeue is the same event caught in time and costs nothing.
	// 🚨 WHICH CROSS TERMS ARE "WRONG" DEPENDS ON THE MODE, and getting that
	// backwards would either hide a leak or condemn a correct arm. Disjoint: the
	// synthetic must not reach B and WireGuard must not reach A. Colocated: BOTH
	// belong on A, so anything at all on B is the error.
	wrong := leaked
	if mode == splitColocated {
		wrong += synthB + wgB
	} else {
		wrong += synthB + wgA
	}
	note := ""
	if wrong > 0 {
		// 🚨 Not a statistic — a broken run. If a packet crossed groups the two
		// streams shared allocations after all, and the arm measured the very
		// thing it was built to remove.
		note = " 🚨 WRONG-GROUP — the split LEAKED and this arm is void"
	}
	name := "disjoint"
	if mode == splitColocated {
		name = "colocated"
	}
	return fmt.Sprintf(" split=%d/%s synth→A=%d synth→B=%d wg→A=%d wg→B=%d requeued=%d leaked=%d leftover=%d wrong=%d%s",
		n, name, synthA, synthB, wgA, wgB, requeued, leaked, leftover, wrong, note)
}
