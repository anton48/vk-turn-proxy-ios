package proxy

import (
	"fmt"
	"sync/atomic"
)

// rxgap — the GAP between consecutive downlink packet arrivals, and the one
// instrument the upload question now turns on.
//
// WHY IT EXISTS. On 2026-08-14 the upload was measured to be limited by a
// SPURIOUS RTO, not by loss and not by lateness: the receiver sees 0.88% of
// bytes arrive TWICE against the sender's ~1.8% retransmits (so half the
// retransmits are provably unnecessary — the original had already landed), the
// original→duplicate interval is p50 1203 ms against an srtt of 120 ms (RTO
// scale with backoff, not RACK), and `cwnd` p10 sits at 1.8 × MSS, which is the
// post-RTO collapse. Throughput is the area under a sawtooth whose teeth are cut
// by a timer. The same signature is on record from 08-12 at 1329 ms.
//
// An RTO firing over a healthy data path means the sender STOPPED GETTING
// FEEDBACK. During an upload that feedback is the ACK stream, and it returns
// over this same thirty-connection fan-out.
//
// 🎯 THE SIMPLIFICATION THAT MAKES THIS CHEAP: during an upload the downlink
// carries essentially nothing BUT ACKs. So the gap between downlink packet
// arrivals at the extension IS the gap in feedback, and no inner-TCP parsing is
// needed — which matters, because the inner 5-tuple is ciphertext here just as
// it is on the way out.
//
// 🚨 WHAT THIS CAN AND CANNOT CONCLUDE, stated before the run so the null is not
// over-read. This is an AGGREGATE gap across all connections and all inner
// flows. A gap therefore means EVERY flow's feedback stopped at once, which is a
// statement about the tunnel rather than about one flow — the strong, useful
// direction. The converse does NOT hold: with F flows interleaved, one flow's
// ACKs can stop for a second while the other three keep the aggregate busy, and
// this field would show nothing. So:
//
//	gaps at RTO scale found      -> the return channel is the cause. Fix it.
//	no gaps, RTO still fires     -> NOT an exoneration of the return channel;
//	                                it rules out a POOL-WIDE stall only, and the
//	                                next step is per-flow, which needs the
//	                                plaintext side (the wireguard-go fork).
//
// ⚠️ AND THE THRESHOLDS ARE CHOSEN FROM THE MEASUREMENT, not from taste. Darwin's
// minimum RTO is ~1 s, and the observed original→duplicate median is 1203 ms, so
// the bucket that decides the hypothesis is `ge1s`. The smaller buckets are
// there to show the shape of the distribution rather than to be thresholded.
const (
	// rxGapIdleCapNs — a gap longer than this is treated as the tunnel having
	// been IDLE, not as a stall, and is dropped. Without it a single quiet
	// minute between runs would poison `max` and every bucket for the whole
	// session, and the field would read as catastrophic on a healthy link.
	rxGapIdleCapNs = 5_000_000_000 // 5 s
)

// rxGapStats accumulates the inter-arrival gap of downlink packets.
//
// It reuses sendWaitStats for the percentile histogram (same bucket geometry,
// 250 µs × 2048 = 512 ms plus an overflow bucket and an exact max) and adds the
// three counters the hypothesis actually names. Percentiles alone would not do:
// the interesting gaps are ~1 s, i.e. in the overflow bucket, where a percentile
// saturates and stops being readable.
type rxGapStats struct {
	last  atomic.Int64 // UnixNano of the previous arrival; 0 = nothing yet
	hist  sendWaitStats
	ge250 atomic.Int64 // gaps ≥ 250 ms
	ge500 atomic.Int64 // gaps ≥ 500 ms
	ge1s  atomic.Int64 // gaps ≥ 1 s — the one that decides the hypothesis
	idle  atomic.Int64 // gaps dropped as idle (> rxGapIdleCapNs)
}

// observe records one downlink arrival at time `now` (UnixNano).
//
// 🚨 Deliberately racy between concurrent readers, exactly like notePeak: this
// is a diagnostic on a path that carries thousands of packets a second, and a
// lost sample costs nothing while a lock would cost real throughput. Two readers
// landing in the same nanosecond can both compute a gap from the same
// predecessor; at the rates involved that is invisible in a percentile.
func (r *rxGapStats) observe(now int64) {
	prev := r.last.Swap(now)
	if prev == 0 || now <= prev {
		return
	}
	gap := now - prev
	if gap > rxGapIdleCapNs {
		r.idle.Add(1)
		return
	}
	r.hist.observe(prev, now)
	switch {
	case gap >= 1_000_000_000:
		r.ge1s.Add(1)
		fallthrough
	case gap >= 500_000_000:
		r.ge500.Add(1)
		fallthrough
	case gap >= 250_000_000:
		r.ge250.Add(1)
	}
}

// summary renders the field group and CLEARS the interval, in the read-and-reset
// idiom of the other memstats fields. Empty when nothing arrived, so an idle
// tunnel prints no row of zeroes that could later be mistaken for a measurement.
//
// ⚠️ Read it beside `tx-pkt`: the field only means "feedback gap" while an upload
// is actually running. On an idle tunnel the gaps are the keepalive cadence.
func (r *rxGapStats) summary() string {
	base := r.hist.summaryAs("rxgap")
	ge250 := r.ge250.Swap(0)
	ge500 := r.ge500.Swap(0)
	ge1s := r.ge1s.Swap(0)
	idle := r.idle.Swap(0)
	if base == "" && ge250 == 0 && idle == 0 {
		return ""
	}
	return fmt.Sprintf("%s ge250=%d ge500=%d ge1s=%d idle=%d",
		base, ge250, ge500, ge1s, idle)
}
