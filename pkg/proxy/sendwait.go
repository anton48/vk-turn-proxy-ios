package proxy

import (
	"fmt"
	"sync/atomic"
	"time"
)

// HOW LONG DOES A PACKET SIT IN sendCh? — the one thing depth and blocked time
// cannot answer.
//
// 🎯 WHY THIS EXISTS. On 2026-08-11 the phone's own offer (`tun-mbit`, build 227
// — bytes tun.Read returned, i.e. what the inner TCP handed to wireguard-go) was
// joined to server1's ΣUP on one time axis, totalled per burst bounded by quiet
// on both sides. delivered/offered came out at 1.01-1.02 in all five bursts,
// which is exactly WireGuard's 32 B header on ~1300: our transport carries every
// byte the phone hands it, and the dips are the inner TCP backing off. Two of the
// three sendCh statistics we already had agreed — `sendch-block` totals 0.03-0.09%
// of loaded time, and in a dip the server falls in the SAME second with nothing
// arriving late afterwards, so nothing was held inside us.
//
// ⚠️ ONE READING DID NOT FIT, AND IT IS THE REASON FOR THIS FILE. sendCh does NOT
// fill on the fastest seconds: the 33.0 Mbit/s tick sat at 66/256, while the seven
// ticks that reached 256/256 averaged 17.6 Mbit/s offered against 18.8 in the
// rest — on those seconds the DRAIN paused rather than the producer accelerating
// — and the next second's offer fell in 6 of 7, median −24% against −1%.
// 🚨 n=7, spread −96% to +19%, four of the seven following a high tick: that is
// the shape regression to the mean produces, and it was NOT a finding. It was a
// reason to measure.
//
// ✅ IT WAS MEASURED, AND THE LEAD IS DEAD — three ways, from one run with this
// instrument at a 1 s cadence (58 loaded ticks, 14 of them at 256/256):
//
//  1. MAGNITUDE. The mechanism needed the 102 ms below. Residence is p50 2.1 ms
//     and p99 12.1 ms in the FULL ticks, 1.0 / 7.9 elsewhere, and 19.5 ms at
//     worst in the entire run — against an RTT of ~155 ms.
//  2. DIRECTION. The same max bounds the DRAIN from below: a packet enqueued at
//     len == 256 waited at most max, so the writers cleared 256 packets inside
//     it — >=13155 pkt/s worst, median >=18803 = ~196 Mbit/s of plaintext, 6.6x
//     to 22x what the phone was offering in that same second. A full queue here
//     is a producer handing over a batch, not writers falling behind.
//  3. THE CORRELATION. Split the same ticks by LEVEL instead of by the queue and
//     the next second is -2% above the median offer against +22% below it;
//     inside the high half alone, groups matched at 16.8 vs 16.5 Mbit/s, full
//     gives -1% and not-full -4%. It was regression to the mean, as suspected.
//
// ⇒ Keep the instrument — it is what closed the question, and it is the only
// thing that can reopen it if the queue's behaviour ever changes. But do not
// re-propose sendCh as the cause of anything without a residence number that
// contradicts the ones above.
//
// THE MEASUREMENT. A queue can be full and harmless or full and destructive, and
// the two differ only in how long a packet WAITS in it:
//
//	residence stays sub-millisecond ⇒ burst absorption. The queue is deep because
//	                                  the producer is bursty, it drains at once,
//	                                  and it cannot be perturbing anything.
//	residence reaches tens of ms    ⇒ we add jitter at the scale the inner TCP's
//	                                  ACK clock and RTO live at — which would make
//	                                  US the trigger of the dips while still
//	                                  delivering every byte, the only way both can
//	                                  be true at once.
//
// The arithmetic that makes it worth measuring: 256 packets at the ~2500 pkt/s of
// a loaded second is **102 ms**.
//
// 🚨 THIS IS THE SAME MOVE AS BUILD 224, ON THE OPPOSITE QUESTION. There, depth
// could not distinguish "deep because the producer is bursty" from "deep because
// the drain is slow", and only WAITING could. Here, blocked time cannot
// distinguish "absorbed harmlessly" from "absorbed and delayed", and only
// residence can. They are different quantities and both are kept: blocked time is
// what the PRODUCER waits for room; residence is what the PACKET waits for a
// writer. A queue that never blocks its producer can still hold every packet for
// 100 ms.
//
// ⚠️ WHAT THIS CANNOT SEE, and it must be said whenever the number is quoted:
// residence ENDS AT THE DEQUEUE. The packet then goes into one of the 30 outer
// TCP connections, whose send buffers are a second queue we do not instrument.
// **This is a LOWER BOUND on the delay we add, not the total.** A sub-millisecond
// residence does not prove we add no queueing — it proves the shared queue is not
// where it happens.

// sendItem is a packet plus the instant it entered sendCh.
//
// 🚨 THE TIMESTAMP TRAVELS WITH THE PACKET, deliberately. The obvious cheap
// alternative — a parallel FIFO of timestamps, since a channel is in order — is
// wrong: several producers enqueue concurrently, and the order they reach the
// side structure is not the order they win the channel, so the pairing drifts
// under exactly the load being measured. The server's resequencer already paid
// for this once, with an arrival time kept in a map beside the packet.
type sendItem struct {
	// flow is the inner 5-tuple hash (0 = keepalive/handshake). Carried here
	// only so the writer can NAME the connection a flow's first packets went
	// out on — the measurement for "what happens to a packet after
	// conn.Write". → flowpaths.go
	flow uint64
	buf  []byte
	at   int64 // time.Now().UnixNano() at enqueue; 0 = unstamped, not measured
}

// Bucket geometry. 250 µs per bucket, 2048 of them = 512 ms, plus one overflow
// bucket. Linear rather than exponential on purpose: the claim under test names a
// scale (~100 ms) and the RTO that would follow it (200-400 ms), so a uniform
// quarter-millisecond resolution answers it directly instead of reporting a
// factor-of-two band. 512 ms covers the whole interesting range; anything beyond
// it is catastrophic rather than interesting, and `max` records it exactly.
const (
	sendWaitBucketNs = 250_000
	sendWaitBuckets  = 2048
)

type sendWaitStats struct {
	// hist[sendWaitBuckets] is the >= 512 ms overflow bucket.
	hist  [sendWaitBuckets + 1]atomic.Int64
	maxNs atomic.Int64

	// scratch is owned by summary() alone, which runs only on the memstats
	// goroutine. It exists so a per-tick read does not allocate 16 KB of
	// garbage on a device whose GOMEMLIMIT is 35 MB and whose GC history
	// includes a death spiral.
	scratch [sendWaitBuckets + 1]int64
}

// observe files one packet's residence.
//
// Both times are UnixNano. The caller passes the time.Now() it already needed for
// the write deadline, so the packet path gains no extra clock read — the enqueue
// stamp in SendPacket is the only one added.
func (s *sendWaitStats) observe(enqueuedAt, now int64) {
	if enqueuedAt == 0 {
		return
	}
	d := now - enqueuedAt
	if d < 0 {
		// The two reads can straddle a clock adjustment. Count it as zero
		// rather than let a negative land in the overflow bucket, where it
		// would read as the very pathology this instrument exists to find.
		d = 0
	}
	idx := d / sendWaitBucketNs
	if idx > sendWaitBuckets {
		idx = sendWaitBuckets
	}
	s.hist[idx].Add(1)
	noteMax64(&s.maxNs, d)
}

// noteMax64 is notePeak for a value that is already an int64.
func noteMax64(mark *atomic.Int64, v int64) {
	for {
		cur := mark.Load()
		if v <= cur || mark.CompareAndSwap(cur, v) {
			return
		}
	}
}

// summary renders one field group and CLEARS the interval, in the read-and-reset
// idiom of sendChPeak. Returns "" when nothing was dequeued, so an idle phone
// prints no row of zeroes that could later pass for a measurement.
//
// 🚨 THE DENOMINATOR IS THE HISTOGRAM'S OWN SUM, taken from the same swapped
// values the percentiles walk. This project has shipped three wrong-denominator
// statistics — one printed "p99 512 ms" beside "max 31 ms" — every time by
// normalising a histogram with a count collected somewhere else. Here the two
// cannot disagree by construction, and the count is printed so nobody has to
// guess what the percentiles are percentiles OF.
//
// ⚠️ Percentiles are the LOWER edge of their bucket; `max` is exact. Lower edges
// are what keep the p50 ≤ p90 ≤ p99 ≤ max check mechanical — with upper edges a
// single 300 µs sample would print p99 = 500 µs beside max = 300 µs, and this
// project uses exactly that impossibility to catch denominator bugs. So
// `p50=0s` means half the packets waited under 250 µs, which is the answer
// "burst absorption" looks like.
func (s *sendWaitStats) summary() string { return s.summaryAs("sendch-wait") }

// summaryAs is summary with the field name given, so the same histogram serves
// the two halves of the question: how long a packet waits FOR a writer
// (`sendch-wait`), and how long the writer then spends handing it to the socket
// (`conn-write`). They are different quantities and must not be added: the first
// ends where the second begins.
func (s *sendWaitStats) summaryAs(name string) string {
	var total int64
	for i := range s.hist {
		s.scratch[i] = s.hist[i].Swap(0)
		total += s.scratch[i]
	}
	maxNs := s.maxNs.Swap(0)
	if total == 0 {
		return ""
	}
	h := s.scratch[:]
	return fmt.Sprintf(" %s=%s/%s/%s max=%s over=%d", name,
		sendWaitEdge(rxHistPct(h, total, 0.50)),
		sendWaitEdge(rxHistPct(h, total, 0.90)),
		sendWaitEdge(rxHistPct(h, total, 0.99)),
		time.Duration(maxNs).Round(time.Microsecond),
		total)
}

// sendWaitEdge renders a bucket index as the lower edge of the range it covers,
// or ">=512ms" for the overflow bucket — never a number the bucket cannot
// support.
func sendWaitEdge(idx int) string {
	switch {
	case idx < 0:
		return "-"
	case idx >= sendWaitBuckets:
		return ">=" + time.Duration(sendWaitBuckets*sendWaitBucketNs).String()
	default:
		return time.Duration(int64(idx) * sendWaitBucketNs).String()
	}
}
