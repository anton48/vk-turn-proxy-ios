package proxy

import (
	"fmt"
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

// uplinkSplitN is the number of connections reserved for the SYNTHETIC. Writers
// with index < N serve the synthetic queue and nothing else; writers with index
// >= N serve WireGuard and nothing else. Process-global for the same reason the
// chunk size is: the extension runs exactly one Proxy and the bridge holds no
// handle on it.
var uplinkSplitN atomic.Int64

// SetUplinkSplitN applies the split to THIS process without a reconnect, so an
// arm costs no 107-second thirty-connection ramp. Clamped: a value that would
// leave either side without a writer is meaningless, and 0 is off.
func SetUplinkSplitN(n int) { uplinkSplitN.Store(int64(ClampUplinkSplitN(n))) }

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

// uplinkSplit reports the split size, 0 when off.
func uplinkSplit() int { return int(uplinkSplitN.Load()) }

// splitOwnsSynth says whether this writer serves the synthetic's group.
//
// ⚠️ Connections are identified by their index in the pool, which is stable for
// the life of a connection. A reconnect renumbers, and an arm that straddles one
// has its groups redrawn — read `split=` on the memstats line, which prints how
// many packets each group actually carried, rather than assuming.
func splitOwnsSynth(connIdx int) bool { return connIdx >= 0 && connIdx < uplinkSplit() }

var (
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

// SplitStatsAndReset reports the four (kind × group) counts and clears them.
func SplitStatsAndReset() (synthA, synthB, wgA, wgB int64, n int) {
	return splitSynthToA.Swap(0), splitSynthToB.Swap(0),
		splitWGToA.Swap(0), splitWGToB.Swap(0), uplinkSplit()
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
	synthA, synthB, wgA, wgB, n := SplitStatsAndReset()
	if n <= UplinkSplitOff {
		return ""
	}
	wrong := synthB + wgA
	note := ""
	if wrong > 0 {
		// 🚨 Not a statistic — a broken run. If a packet crossed groups the two
		// streams shared allocations after all, and the arm measured the very
		// thing it was built to remove.
		note = " 🚨 WRONG-GROUP — the split LEAKED and this arm is void"
	}
	return fmt.Sprintf(" split=%d synth→A=%d synth→B=%d wg→A=%d wg→B=%d wrong=%d%s",
		n, synthA, synthB, wgA, wgB, wrong, note)
}
