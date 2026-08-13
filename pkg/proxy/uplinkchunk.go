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
// 🚫🚫 SWEPT AND CLOSED, 2026-08-12 — DO NOT RE-RUN THIS SWEEP, AND DO NOT
// RE-SURFACE THE SETTING. 14 arms (F = 8/16/32 inner flows x K = 1/2/4/8, plus
// F=8 x K=32/64), live-switched inside ~14 minutes so drift is excluded, moved
// throughput nothing and the reordering tail nothing.
//
// THE LEVER CANNOT ENGAGE, and that is the result — it is NOT "reordering does
// not matter". The mean chunk was 1.00/1.27/1.48/1.66 at K=1/2/4/8 and stuck at
// 1.86 at BOTH K=32 and K=64: raising K eightfold moved the real chunk size 12%.
// The reason is structural and lives two lines below in the drain: ~30 writer
// goroutines compete for a queue whose MEAN depth is only ~2.8 packets (Little's
// law, 2560 pkt/s x 1-2 ms residence), so a writer that finishes a write finds
// that the other 29 already took what was there. Filling a chunk of K needs
// roughly N*K packets queued at once — 240 at K=8, ~1900 at K=64 — against 2.8.
// (⚠️ `sendch-peak` reads ~180/256 and is a read-and-reset BURST peak, not depth.)
//
// Confirmed independently at the inner receiver: the HOLE RATE stayed flat at
// 18.1-19.2% of segments across the entire sweep, including the arms where the
// model below predicted 75% and 87.5% fewer holes. Holes never stopped forming.
// The only real effect was cosmetic — at K=32, 54.5% of holes close in under a
// millisecond against ~20% elsewhere, i.e. chunking does tidy immediate adjacent
// swaps, but never reaches the >155 ms tail that costs throughput.
//
// 🚨 AND THE THRESHOLD BELOW WAS WRONG BY A FACTOR when it was written as
// "K >= F" — the real condition is K > F, practically K >> F: the fraction of
// same-flow adjacent pairs a chunk protects is max(0, 1 - F/K), which is exactly
// ZERO at K = F (a flow's packets land at positions 0 and F, i.e. in adjacent
// chunks on different connections). 12 of the 14 arms therefore predicted 0% and
// could never have shown anything.
//
// The machinery is kept, inert at K=1, driven only by the undocumented
// `uplink_chunk_k` backup field (the idiom of UplinkSynthMbit) — so it can be
// re-driven cheaply IF the fan-out architecture ever changes. The Settings entry
// was removed with the result.
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

// uplinkChunkK is process-global, in the idiom of memstatsFastTicks, for the
// same reason and with the same shape: the extension runs exactly one Proxy, the
// bridge has no handle on it, and the value has to be settable on a tunnel that
// is ALREADY UP.
//
// 🚨 THE LIVE PATH IS THE POINT, and it is a measurement requirement rather than
// a convenience. Applying K through a reconnect re-ramps 30 connections over
// ~107 s, so each arm of a sweep would be separated by a ramp on a line that has
// been seen to move 75 → 363 Mbit/s inside 70 minutes — the arms would differ by
// drift as much as by K. Live switching allows K to change WITHIN one iperf run,
// against one state of the line and one set of connections, which is the
// cleanest pairing available here.
//
// The same value also rides ProxyConfig, so a reconnect keeps whatever the user
// chose.
//
// ⚠️ Reading the log across a switch: the change takes effect on the very next
// chunk, but a memstats tick can straddle it. Discard the tick that contains the
// switch rather than attributing it to either arm.
var uplinkChunkK atomic.Int64

// SetUplinkChunkK applies K to this process immediately, without a reconnect.
// Called by both ProxyConfig entry points and by the extension when the app
// sends `set_uplink_chunk_k:`. Zero (never configured) and anything below 1
// clamp to UplinkChunkOff, so the tunnel's behaviour is unchanged by default.
func SetUplinkChunkK(k int) { uplinkChunkK.Store(int64(ClampUplinkChunkK(k))) }

// ClampUplinkChunkK snaps a configured K into the supported range. The Swift
// side clamps the same value twice (at the picker and again on backup import)
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
	k := int(uplinkChunkK.Load())
	if k < UplinkChunkOff {
		k = UplinkChunkOff
	}
	// 🚫 CHUNKING AND THE FLOW-LOCAL PATH SET MUST NOT RUN TOGETHER, and this is
	// the enforcement rather than a note in a file nobody reads. Two reasons.
	// Mechanically, the drain below takes the next packet from the SHARED
	// sendCh, so with a flow set armed a chunk would pull other flows' spilled
	// packets onto this connection and quietly undo the stickiness it was
	// supposed to compose with. Experimentally, they aim at the same target by
	// different means, so an arm with both on could not attribute its result to
	// either — and this project has already paid for one confounded sweep.
	// Chunking is the retired lever, so it is the one that yields.
	if flowPathsK.Load() > FlowPathsOff {
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
			if k > UplinkChunkOff {
				p.chunkStats.observe(sent)
			}
			return err
		}

		if txConnIdx >= 0 && txConnIdx < len(p.connTxBytes) {
			p.connTxBytes[txConnIdx].Add(int64(len(item.buf)))
			p.lastTxAt[txConnIdx].Store(time.Now().UnixNano())
		}

		if sent >= k {
			// K=1 is the permanent default now that the experiment is closed, and
			// every chunk is trivially 1 — recording it would print
			// ` chunk=1.00/1 over=N` on every tick forever, which is noise, not a
			// measurement. Only a deliberately raised K reports.
			if k > UplinkChunkOff {
				p.chunkStats.observe(sent)
			}
			return nil
		}

		select {
		case next := <-p.sendCh:
			item = next
		default:
			// Nothing already queued. End the chunk instead of waiting for
			// one — see the "never waits" property above.
			if k > UplinkChunkOff {
				p.chunkStats.observe(sent)
			}
			return nil
		}
	}
}
