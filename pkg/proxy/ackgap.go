package proxy

import (
	"fmt"
	"sync"
	"time"
)

// ackgap — the gap between consecutive inbound ACKs OF ONE INNER FLOW, and the
// last instrument the upload hypothesis needs.
//
// WHERE THIS CAME FROM. The upload is limited by a SPURIOUS RTO: the receiver
// sees 0.88% of bytes arrive twice against the sender's ~1.8% retransmits (so
// half of them are unnecessary — the original had already landed), the
// original→duplicate interval is p50 1203 ms against an srtt of 120 ms, and cwnd
// p10 sits at 1.8 × MSS, the post-RTO collapse. A timer firing over a healthy
// data path means the sender stopped getting FEEDBACK.
//
// 🚫 THE AGGREGATE VERSION ALREADY RAN AND REFUTED THE POOL-WIDE FORM (build
// 262, other branch): under load, 81 of 292 seconds had a collapsed cwnd but
// only 13 ticks showed ANY feedback gap ≥250 ms, and just 36% of the collapses
// had one. Feedback does not stop for everybody at once.
//
// 🎯 WHAT IT COULD NOT SEE, and why this file exists: a gap in ONE flow's ACKs
// while the other flows keep the aggregate busy. The margin that matters is
// small — the probe measured `rto` at 371 / 486 / 632 ms against an srtt of
// ~120 ms, barely 3× — so ONE flow's ACKs pausing for ~370 ms is enough to fire
// its timer, and an aggregate counter can never resolve that.
//
// 🚨 AND THE THRESHOLD IS TAKEN FROM THE MEASUREMENT, NOT FROM FOLKLORE. The
// aggregate build set its deciding bucket at 1 s because "Darwin's minimum RTO
// is ~1 s" while the same build shipped the field that measures it; quoted at
// 1 s the session showed one hit, quoted at 250 ms it showed thirteen. The
// buckets here start at 250 ms for that reason.
//
// HOW TO READ IT. The question is a RATE, not an event: 28% of loaded seconds
// have some flow with a collapsed cwnd, so if per-flow ACK gaps at RTO scale
// occur far more rarely than that, they cannot be the mechanism. `flows=` is
// printed so the rate can be formed — gaps per flow-second — without guessing
// how many flows were live.
const (
	// ackGapIdleCapNs — beyond this a flow is IDLE, not stalled, and the gap is
	// dropped (counted separately). Between probe runs a flow simply stops, and
	// counting that as a feedback gap would put a hit into the tick after every
	// run — the trap the aggregate version documented and this one inherits.
	ackGapIdleCapNs = 5_000_000_000

	// ackGapForgetNs — a flow not seen for this long is evicted, so a long
	// session cannot grow the map without bound.
	ackGapForgetNs = 10_000_000_000
)

// ackGapStats tracks, per inner-flow key, when that flow's last ACK arrived.
//
// A mutex rather than atomics: the map makes lock-free awkward, the inbound
// sequential receiver is ONE goroutine per peer (so contention is nil), and the
// path carries ACKs at a few thousand a second — three orders below where a
// mutex would show up against the crypto already on that path.
type ackGapStats struct {
	mu    sync.Mutex
	last  map[uint64]int64
	seen  map[uint64]struct{} // flows that produced a gap this interval
	gaps  int64
	ge250 int64
	ge500 int64
	ge1s  int64
	idle  int64
	maxNs int64
}

// observe records one inbound ACK for flowKey at time now (UnixNano).
// flowKey 0 means the packet was unparseable and is ignored.
func (a *ackGapStats) observe(flowKey uint64, now int64) {
	if flowKey == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		a.last = make(map[uint64]int64, 64)
		a.seen = make(map[uint64]struct{}, 64)
	}
	prev, ok := a.last[flowKey]
	a.last[flowKey] = now
	if !ok || now <= prev {
		return // first ACK of this flow invents no interval
	}
	gap := now - prev
	if gap > ackGapIdleCapNs {
		a.idle++
		return
	}
	a.seen[flowKey] = struct{}{}
	a.gaps++
	if gap > a.maxNs {
		a.maxNs = gap
	}
	switch {
	case gap >= 1_000_000_000:
		a.ge1s++
		fallthrough
	case gap >= 500_000_000:
		a.ge500++
		fallthrough
	case gap >= 250_000_000:
		a.ge250++
	}
}

// summary renders the field group, CLEARS the interval and evicts flows that
// have gone quiet. Empty when no flow produced a gap, so an idle tunnel prints
// nothing that could be mistaken for a measurement.
func (a *ackGapStats) summary() string {
	now := time.Now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, t := range a.last {
		if now-t > ackGapForgetNs {
			delete(a.last, k)
		}
	}
	gaps, ge250, ge500, ge1s, idle, maxNs := a.gaps, a.ge250, a.ge500, a.ge1s, a.idle, a.maxNs
	flows := len(a.seen)
	a.gaps, a.ge250, a.ge500, a.ge1s, a.idle, a.maxNs = 0, 0, 0, 0, 0, 0
	a.seen = make(map[uint64]struct{}, 64)
	if gaps == 0 && idle == 0 {
		return ""
	}
	return fmt.Sprintf(" ackgap=flows=%d gaps=%d ge250=%d ge500=%d ge1s=%d idle=%d max=%s",
		flows, gaps, ge250, ge500, ge1s, idle,
		time.Duration(maxNs).Round(time.Millisecond))
}

// ObserveInboundAck is the proxy's end of conn.FlowReceiver: the patched
// wireguard-go calls it for every inbound PURE TCP ACK, just before the packet
// reaches the TUN, with the inner-flow key it hashed from the plaintext.
func (p *Proxy) ObserveInboundAck(flowKey uint64) {
	p.ackGap.observe(flowKey, time.Now().UnixNano())
}
