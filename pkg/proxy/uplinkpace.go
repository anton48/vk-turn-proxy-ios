package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// A PER-ALLOCATION TOKEN BUCKET ON THE UPLINK — the client pacer, as a
// DIAGNOSTIC, and only because the measurement it was gated on has now been
// taken.
//
// 🚨 READ THIS BEFORE TOUCHING IT: THE CLIENT PACER WAS REFUTED FOUR TIMES.
// Every one of those refutations rested on the same premise — *"the client
// policer never fires; we sit at 21-30% of the allowance and 99.98% is
// delivered"* — and on the belief that what pacing would treat was reordering
// or the outer TCP window. Both are gone:
//
//   - 2026-08-14 measured the premise FALSE (p50 71% of the knee, >100%
//     instantaneously);
//   - 2026-08-16 (`16.08.2026/tcptest1`) measured WHERE the loss happens, and
//     it is PER-ALLOCATION: the same synthetic loses 0.0000% alone, 0.0003%
//     with the neighbour on the other fifteen allocations, and 1.9981% with it
//     on its own — while the neighbour, ALONE on its own group with nothing
//     beside it, loses 0.82-0.91% at a mean of 60% of the knee.
//
// ⇒ **The thing this treats is now named and measured**: allocation-local drops
// that arrive as CONSECUTIVE BLOCKS of 14-21 packets (20-28 KB cut in one go),
// on every allocation the burster touches and only those, at a mean well under
// the knee. That is a bucket running dry, and a bucket is what answers it.
// *(User's decision, 2026-08-16, on the strength of that run.)*
//
// 🎯 THE SHAPE IS THE SERVER'S, DELIBERATELY. `server/pacer.go` has run this
// design in production on the downlink for weeks: at 247 KiB/s delivery is
// 100.00%, byte-exact per connection, while at 260 it falls to 97.96% and
// throughput drops 9.4%. Same token bucket, same counted-bytes unit, same
// pre-dequeue reservation. Porting it rather than inventing one means the one
// unknown in the experiment is whether the UPLINK behaves like the downlink.
//
// 🚨 WHY THE RESERVATION HAPPENS BEFORE THE DEQUEUE, AND IT IS THE WHOLE
// CORRECTNESS ARGUMENT. A writer that takes a packet and THEN discovers it has
// no budget holds that packet inside its goroutine where work-stealing cannot
// see it — the run-20 pathology, and the same reason `writeChunk` writes each
// packet before taking the next. Reserving first means a writer without tokens
// sleeps while the packet is still in the shared queue, where any other writer
// may take it. Nothing is ever stranded.
//
// ⚠️ ONE KNOWN IMPRECISION, INHERITED AND BOUNDED: the reservation is for a
// MAXIMUM-size packet, so when the bucket is in debt the sleep is computed for
// `paceMaxCost` and the refund arrives too late to shorten it. The long-run
// rate stays exact — the refund credits the bucket, so the net debit per packet
// is its true cost — but one small packet can be delayed by up to
// `paceMaxCost/rate`, ~5 ms at 247 KiB/s. Reserving the true size would mean
// peeking at the queue, which reintroduces the coupling above.

const (
	// PaceOff is the default. Not pacing is the production behaviour and this
	// lever must not change it by existing.
	PaceOff = 0

	// paceWireOverhead is what VK counts per packet on top of the bytes we hand
	// it — measured at ~30 B → reference_throughput_limits §2c.
	paceWireOverhead = 30

	// paceMaxCost is the reservation taken before dequeuing: the largest packet
	// this writer can be handed. A WireGuard transport record over a 1280 B
	// inner MTU is 1312 B; the margin covers a larger MTU without re-deriving.
	paceMaxCost = 1500 + paceWireOverhead

	// PaceDefaultKiB is the arm's suggested rate, in KiB/s of COUNTED bytes per
	// allocation — the same 247 the server's downlink pacer ships, which is 95%
	// of the 260 KiB/s the packet-size sweep put the policer at.
	//
	// 🚨 IT IS A HYPOTHESIS ABOUT THE UPLINK, NOT A MEASUREMENT OF IT. The knee
	// is bracketed at 247-260 KiB/s and the return leg was measured to be
	// policed identically — but "identically policed" was established on the
	// RATE, never on the BUCKET DEPTH, which is what this lever actually acts
	// on. If the first arm does not engage, the number to move is the BURST.
	PaceDefaultKiB = 247

	// PaceDefaultBurstKiB is the bucket's capacity, and it is the parameter the
	// 2026-08-16 run points at.
	//
	// 🎯 WHERE 16 COMES FROM AND WHAT IT ASSUMES. The server pacer uses 16 KiB
	// and it works there. Independently, the losses measured on the uplink
	// arrive in blocks of 14-21 packets ≈ 20-28 KB — and the size of a CUT is
	// (burst that arrived) − (VK's own bucket), so those blocks bound VK's
	// depth from neither side on their own. 16 KiB is therefore a guess placed
	// deliberately BELOW the observed cuts: a bucket stricter than theirs holds
	// back before they drop, while a looser one passes exactly what they cut.
	// ⇒ If loss does not fall, the diagnosis is "our bucket is looser than
	// theirs" and the burst comes DOWN before the rate does.
	PaceDefaultBurstKiB = 16

	// paceMaxConns bounds the per-connection bucket table. The pool ceiling is
	// 60 (reference_throughput_limits §2h); this leaves room and keeps the
	// table a fixed array so a writer never allocates on the hot path.
	paceMaxConns = 64
)

// paceState binds the rate, the burst and the selector into ONE value.
//
// 🚨 SAME REASON AS `splitState`, AND IT IS A DEFECT THIS FILE'S SIBLING ALREADY
// SHIPPED: reading a rate from one atomic and a selector from another lets a
// live change land between them, so a writer paces group A at group B's rate
// for one packet. One pointer, loaded once.
type paceState struct {
	rate  float64 // counted bytes per second; 0 = off
	burst float64 // counted bytes
	// groupBOnly restricts pacing to the writers that do NOT serve the
	// synthetic — the arm's design, because the synthetic is already smooth and
	// pacing it would test nothing while changing its level.
	groupBOnly bool
	// gen increments on every change. A per-connection bucket built under an
	// older generation is rebuilt rather than reused, so a rate change actually
	// reaches the buckets instead of applying only to connections opened after
	// it.
	gen uint64
}

func (s *paceState) on() bool { return s.rate > 0 }

var (
	paceCur   atomic.Pointer[paceState]
	paceSetMu sync.Mutex
	// One bucket per connection index. Only that connection's own writer
	// touches its entry.
	paceBuckets [paceMaxConns]atomic.Pointer[paceBucket]

	paceAwaits   atomic.Int64 // reservations attempted
	paceWaited   atomic.Int64 // reservations that actually slept
	paceWaitNs   atomic.Int64 // total slept
	paceWaitMax  atomic.Int64 // longest single sleep
	paceBytes    atomic.Int64 // counted bytes charged
	paceCancels  atomic.Int64 // waits abandoned because the context ended
	paceSkippedA atomic.Int64 // packets that went unpaced because the writer serves group A
)

func init() {
	paceCur.Store(&paceState{})
}

func paceNow() *paceState { return paceCur.Load() }

// SetUplinkPace applies the pacer to THIS process without a reconnect, so an
// arm costs no 107-second thirty-connection ramp. kib is KiB/s of COUNTED bytes
// per allocation; 0 turns it off, which is the production default.
func SetUplinkPace(kib int, burstKiB int, groupBOnly bool) {
	paceSetMu.Lock()
	defer paceSetMu.Unlock()
	old := paceCur.Load()
	next := &paceState{gen: old.gen + 1, groupBOnly: groupBOnly}
	if kib > 0 {
		next.rate = float64(kib) * 1024
		if burstKiB <= 0 {
			burstKiB = PaceDefaultBurstKiB
		}
		next.burst = float64(burstKiB) * 1024
	}
	paceCur.Store(next)
}

// UplinkPaceRate reports the configured rate in KiB/s, 0 when off. For the
// summary line and for tests.
func UplinkPaceRate() int {
	st := paceNow()
	if !st.on() {
		return PaceOff
	}
	return int(st.rate / 1024)
}

// paceBucket is a token bucket over counted wire bytes, plus the generation it
// was built under.
type paceBucket struct {
	gen   uint64
	rate  float64
	burst float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newPaceBucket(st *paceState) *paceBucket {
	return &paceBucket{gen: st.gen, rate: st.rate, burst: st.burst,
		tokens: st.burst, last: time.Now()}
}

// take deducts cost and reports how long the caller must wait before the debt
// is paid off. Tokens are allowed to go NEGATIVE — that is the reservation, and
// it is what makes the long-run rate exact rather than merely bounded: a packet
// that overdraws delays the NEXT one by precisely its excess.
func (b *paceBucket) take(cost float64) time.Duration {
	if b.rate <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += b.rate * now.Sub(b.last).Seconds()
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	b.tokens -= cost
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// refund credits back the difference between the reservation and the true cost.
// It does NOT move `last`: the accrual since the last take is already counted.
func (b *paceBucket) refund(cost float64) {
	if cost <= 0 || b.rate <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += cost
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// pacesWriter reports whether this writer's packets are subject to the bucket.
//
// 🚨 THE SELECTOR IS THE ARM'S CONTROL. With `groupBOnly` the synthetic's own
// writers are never paced, so group A is an untouched in-run control for
// cross-talk: if A's loss moves, the pacer or the split is broken, not the path.
func pacesWriter(st *paceState, connIdx int) bool {
	if !st.on() || connIdx < 0 || connIdx >= paceMaxConns {
		return false
	}
	if !st.groupBOnly {
		return true
	}
	sp := splitNow()
	if !sp.on() {
		// Group B is only defined when the pool is split. Refusing to pace at
		// all is the safe reading: it cannot silently pace everything.
		return false
	}
	return !splitOwnsSynth(connIdx, sp.n)
}

// paceReserve is called BEFORE the dequeue. It returns the amount reserved, to
// be handed to paceSettle once the real packet size is known.
//
// 🚨 It must never hold a packet: at this point the writer has none.
func (p *Proxy) paceReserve(connIdx int) float64 {
	st := paceNow()
	if !pacesWriter(st, connIdx) {
		if st.on() {
			paceSkippedA.Add(1)
		}
		return 0
	}
	b := paceBuckets[connIdx].Load()
	if b == nil || b.gen != st.gen {
		b = newPaceBucket(st)
		paceBuckets[connIdx].Store(b)
	}
	wait := b.take(paceMaxCost)
	paceAwaits.Add(1)
	if wait <= 0 {
		return paceMaxCost
	}
	paceWaited.Add(1)
	paceWaitNs.Add(int64(wait))
	for {
		prev := paceWaitMax.Load()
		if int64(wait) <= prev || paceWaitMax.CompareAndSwap(prev, int64(wait)) {
			break
		}
	}
	// ⚠️ BOUNDED SLEEP, RE-LOOPED. A writer asleep on a long timer is a writer
	// that cannot notice the pacer being turned OFF, the split changing, or the
	// context ending — the parked-writer trap in a third place. Waking every
	// 10 ms costs nothing at these rates and makes a live toggle land within one
	// slice. *(reference_uplink_dispatcher §0.)*
	const slice = 10 * time.Millisecond
	left := wait
	for left > 0 {
		d := slice
		if left < d {
			d = left
		}
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-p.ctx.Done():
			t.Stop()
			paceCancels.Add(1)
			return paceMaxCost
		}
		t.Stop()
		if !paceNow().on() {
			// Turned off mid-wait: stop paying for a lever that is no longer
			// armed, rather than finishing a sleep nobody asked for.
			break
		}
		left -= d
	}
	return paceMaxCost
}

// paceSettle refunds the unused part of the reservation once the true size is
// known, and files the counted bytes actually charged.
func (p *Proxy) paceSettle(connIdx int, reserved float64, payloadBytes int) {
	if reserved <= 0 {
		return
	}
	actual := float64(payloadBytes + paceWireOverhead)
	if actual > reserved {
		actual = reserved
	}
	paceBytes.Add(int64(actual))
	if connIdx >= 0 && connIdx < paceMaxConns {
		if b := paceBuckets[connIdx].Load(); b != nil {
			b.refund(reserved - actual)
		}
	}
}

// paceSummary renders the engagement witness and CLEARS the interval. Empty
// when the pacer is off, so an ordinary run prints nothing.
//
// 🚨 READ IT BEFORE BELIEVING ANY RESULT FROM A PACED ARM, and expect the waits
// to be RARE. Group B's measured mean is ~152 KiB/s of counted bytes against a
// 247 KiB/s rate — 62% of it — so a bucket at this rate can only ever act on
// BURSTS, and `waited=` near zero means the arm tested nothing rather than that
// pacing does nothing. That distinction cost this project nine runs once.
func paceSummary() string {
	st := paceNow()
	n := paceAwaits.Swap(0)
	w := paceWaited.Swap(0)
	ns := paceWaitNs.Swap(0)
	mx := paceWaitMax.Swap(0)
	by := paceBytes.Swap(0)
	cx := paceCancels.Swap(0)
	sk := paceSkippedA.Swap(0)
	if !st.on() {
		return ""
	}
	share := 0.0
	if n > 0 {
		share = 100 * float64(w) / float64(n)
	}
	mean := time.Duration(0)
	if w > 0 {
		mean = time.Duration(ns / w)
	}
	note := ""
	if w == 0 {
		note = " 🚨 NEVER WAITED — the bucket never emptied, so this arm tested NOTHING;" +
			" lower the BURST before the rate (the losses are block-shaped, i.e. a depth)"
	}
	return fmt.Sprintf(" pace=%.0f/%.0fKiB paced=%d unpaced-A=%d waited=%d(%.1f%%) mean=%s max=%s bytes=%dKiB cancel=%d%s",
		st.rate/1024, st.burst/1024, n, sk, w, share,
		mean.Round(time.Microsecond), time.Duration(mx).Round(time.Microsecond),
		by/1024, cx, note)
}
