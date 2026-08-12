package proxy

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Uplink chunking — how many CONSECUTIVE WireGuard packets one writer hands to
// ONE relay connection before going back to compete for the shared sendCh.
//
// WHY IT EXISTS. The uplink fan-out is per-packet work-stealing: every
// connection's send goroutine blocks on the same sendCh and whichever one the
// runtime wakes takes the next packet. sendCh has a SINGLE producer
// (SendPacket ← TURNBind.Send ← wireguard-go's one RoutineSequentialSender),
// so the items in it are in strict nonce order — and that order is then
// scattered across N relay paths of unequal latency. WireGuard does not
// resequence on receive; it replay-checks and hands packets to the TUN in
// ARRIVAL order. So the scatter reaches the inner TCP receiver as reordering,
// and its sender reads reordering as loss. A chunk of K keeps K consecutive
// packets on ONE path, in order.
//
// 🚨 WHAT IT CAN AND CANNOT DO — read this before scoring a run.
// Only SAME-FLOW reordering costs throughput: a packet of inner flow A
// overtaking one of flow B produces no duplicate ACK anywhere. With F inner
// flows active, a flow's own consecutive packets sit roughly F apart in the
// nonce stream, so a chunk of K keeps them together only when K >= F. This is
// therefore aimed at the SPEEDTEST regime (8-16 flows) and is expected to do
// very little at `iperf3 -P 64`. A null there is not a refutation; a null at
// K >= F is.
//
// 🚨 DO NOT SCORE IT WITH `uplinkReorder` (server/main.go). That counter keys
// on the shared WireGuard counter at the merge point, so it is FLOW-BLIND:
// chunking removes mostly harmless CROSS-flow inversions and will drive it
// down whether or not throughput moves. Score with throughput, measured
// back-to-back against a naked control in the same minutes (this line has gone
// 75 → 363 Mbit/s in ~70 minutes), and with the hole-duration tail at the
// inner receiver.
//
// 🎯 THE TARGET IS A DURATION, NOT AN ORDERING. The inner TCP sender here is
// Darwin, measured to be RACK+SACK — time-based, not a 3-dup-ACK count (holes
// 13+ dup-ACKs deep but short-lived draw a retransmit fraction of 0.001). It
// therefore tolerates reordering up to about one RTT (reo_wnd <= SRTT, ~155 ms
// on this path) for free: those holes are closed by the delayed original with
// no retransmit and no congestion-window cut. What costs throughput is only
// the TAIL beyond that — 12.8% of holes at one flow, 23.3% at eight. So the
// goal is not "no reordering", it is "no hole longer than ~155 ms".
const (
	// UplinkChunkOff is K = 1: one packet per grab, the drain loop below never
	// runs, and the writer path is byte-for-byte what it was before chunking
	// existed. It is both the default and the off switch.
	UplinkChunkOff = 1

	// UplinkChunkMax bounds the setting. A chunk cannot outrun the relay it is
	// written to: the per-allocation policer is ~2.07 Mbit/s and the peer's
	// advertised window is ~42 KB, so past roughly one window's worth of
	// packets the write simply blocks and the chunk self-truncates. The bound
	// exists to keep a mistyped value from being interesting, not because 128
	// is a tuned maximum.
	UplinkChunkMax = 128
)

// ClampUplinkChunkK snaps a configured K into the supported range. The Swift
// side clamps the same value twice (at the stepper and again on backup import)
// and the two must agree, so the range lives in one place per language.
func ClampUplinkChunkK(k int) int {
	if k < UplinkChunkOff {
		return UplinkChunkOff
	}
	if k > UplinkChunkMax {
		return UplinkChunkMax
	}
	return k
}

// chunkStats records how many packets each chunk actually carried.
//
// Deliberately NOT the sendWait time histogram: the quantity is a small count
// in 1..K, and the question it exists to answer is "did the knob engage at
// all". A run configured with K=16 whose chunks all carried one packet tested
// nothing — the queue was never deep enough — which is the same trap as the
// pacer's "0 writes delayed" and the reason this prints even when the answer
// is boring. Read it BEFORE believing any null.
type chunkStats struct {
	chunks  atomic.Int64
	packets atomic.Int64
	maxSeen atomic.Int64
}

func (c *chunkStats) observe(n int) {
	if n <= 0 {
		return
	}
	c.chunks.Add(1)
	c.packets.Add(int64(n))
	noteMax64(&c.maxSeen, int64(n))
}

// summary renders the field group and CLEARS the interval, in the read-and-reset
// idiom of the other memstats fields. Returns "" when no chunk was written, so
// an idle tunnel prints no row of zeroes that could later be mistaken for a
// measurement.
//
// The denominator is the same counter the mean is taken over, and it is printed:
// this project has shipped three wrong-denominator statistics, every one of them
// by normalising with a count collected somewhere else.
func (c *chunkStats) summary() string {
	chunks := c.chunks.Swap(0)
	packets := c.packets.Swap(0)
	maxSeen := c.maxSeen.Swap(0)
	if chunks == 0 {
		return ""
	}
	return fmt.Sprintf(" chunk=%.2f/%d over=%d",
		float64(packets)/float64(chunks), maxSeen, chunks)
}

// writeChunk writes `first` to one connection and then, if chunking is enabled,
// up to K-1 further packets that are ALREADY queued on sendCh — to the SAME
// connection, in the order the producer enqueued them.
//
// 🚨 THE LOOP SHAPE IS THE DESIGN. It takes ONE packet at a time and WRITES IT
// BEFORE TAKING THE NEXT. The obvious alternative — grab K, then write K — is
// wrong here: packets grabbed but not yet written sit inside this goroutine
// where work-stealing cannot see them, so a connection that stalls mid-chunk
// strands K-1 packets another writer could have carried. That is the run-20
// pathology (a packet committed to a stalled connection is invisible to the
// scheduler) and chunking must not deepen it. Writing first bounds this
// goroutine's exposure to the ONE packet in flight — exactly what it was before
// chunking existed.
//
// Two properties follow, and both are wanted:
//
//   - A chunk SELF-TRUNCATES on a slow connection. `write` blocks while the
//     socket buffer is full, so a backed-up connection never reaches its K and
//     the traffic concentrates on connections that are keeping up.
//
//   - A chunk NEVER WAITS for packets. The drain is non-blocking: it takes what
//     the producer has already queued, and stops. So chunking adds no delay of
//     its own — which is what separates it from the two refuted levers, the
//     server resequencer (a hold timer, +275 ms of loaded latency) and the
//     client pacer (inter-packet spacing). Those are temporal; this is purely
//     spatial, a choice of WHICH path, never of WHEN.
//
// txConnIdx is the connection whose TX counters this call site maintains, or -1
// for the sites that never accounted for them (DTLS / direct / WRAP-A). Passing
// -1 there is what keeps K=1 byte-for-byte identical to the pre-chunking code:
// this helper must not quietly add accounting a site did not have.
func (p *Proxy) writeChunk(first sendItem, txConnIdx int, write func(pkt []byte, now time.Time) error) error {
	k := int(p.uplinkChunkK.Load())
	if k < UplinkChunkOff {
		k = UplinkChunkOff
	}

	item := first
	sent := 0
	for {
		// One clock read serves both the residence stamp and the write
		// deadline, as it did before this helper existed.
		now := time.Now()
		p.sendWait.observe(item.at, now.UnixNano())
		w0 := time.Now()
		err := write(item.buf, now)
		p.writeWait.observe(w0.UnixNano(), time.Now().UnixNano())
		sent++

		if err != nil {
			p.chunkStats.observe(sent)
			return err
		}

		if txConnIdx >= 0 && txConnIdx < len(p.connTxBytes) {
			p.connTxBytes[txConnIdx].Add(int64(len(item.buf)))
			p.lastTxAt[txConnIdx].Store(time.Now().UnixNano())
		}

		if sent >= k {
			p.chunkStats.observe(sent)
			return nil
		}

		select {
		case next := <-p.sendCh:
			item = next
		default:
			// Nothing already queued. End the chunk instead of waiting for
			// one — see the "never waits" property above.
			p.chunkStats.observe(sent)
			return nil
		}
	}
}
