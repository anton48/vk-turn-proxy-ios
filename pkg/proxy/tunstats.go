package proxy

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// IS WIREGUARD-GO STARVED, OR SLOW? — the one question left about the uplink.
//
// 🎯 WHY THIS EXISTS. By 2026-08-10 the ~19-22 Mbit/s upload ceiling is known to
// sit ABOVE SendPacket (the in-app synthetic pushed 61.2 Mbit/s through the same
// 30 allocations with zero blocked sends) and to be BYTE-bound, not per-packet
// (alternating MTU 1000/1400 moved the packet rate 1.30x and the byte rate not
// at all). Reading wireguard-go then produced a NEGATIVE result: its two
// directions are structurally symmetric — NumCPU encryption AND decryption
// workers, QueueOutboundSize == QueueInboundSize == 1024, BatchSize 1 both ways,
// one ingress goroutine each, one sequential per-peer goroutine each — and the
// DOWNLINK moves 103 Mbit/s through that very shape on this very device. So the
// code does not explain 22 versus 103, and guessing from source is exhausted.
//
// THE MEASUREMENT. RoutineReadFromTUN is a loop: Read → process → Read. Time
// both halves and the ambiguity dissolves:
//
//	~100% inside Read   ⇒ wireguard-go is STARVED. iOS is not handing us packets
//	                      any faster, so the ceiling is above it — iOS's packet
//	                      flow, or the inner TCP that feeds it.
//	a real share OUTSIDE ⇒ wireguard-go is SLOW, and the gap is its own
//	                      processing: the peer lookup, staging, and the two
//	                      blocking channel sends in SendStagedPackets, which
//	                      stall when the encryption or outbound queues fill.
//
// 🚨 THIS IS THE SAME TRICK THAT SETTLED sendCh IN BUILD 224, and for the same
// reason. Depth could not distinguish "the queue is deep because the producer is
// bursty" from "the queue is deep because the drain is slow"; only WAITING could.
// Here, likewise, a packet rate cannot distinguish starved from slow.
//
// ⚠️ MEMORY SAYS "DO NOT BUILD THE tun.Device WRAPPER", and that verdict was
// right FOR ITS QUESTION: the wrapper was proposed to test per-packet cost, and
// per-packet cost has since been refuted twice. This wrapper does not measure
// that. It measures where the loop's time goes, which nothing has done.
//
// ⚠️ THE FRACTION IS MEANINGLESS AT IDLE. With no traffic, Read blocks forever
// and reads 100% — starved, trivially and uninterestingly. Only loaded intervals
// say anything, which is why the packet and byte rates are printed beside it:
// a reader can see at a glance whether the interval carried any load at all.
type statsTUN struct {
	tun.Device
}

// 🚨🚨 AND THE SHARE IS THE WRONG SHAPE FOR THE NEXT QUESTION — build 237.
//
// `tun-read=99.0%/333µs` says wireguard-go waits ~99% of its loop and that the
// MEAN wait per read is 333 µs. At 2948 pkt/s the mean inter-packet interval is
// 339 µs, so that second number is just 1/rate: it repeats the packet rate and
// carries nothing else.
//
// The question it therefore cannot answer is the one that matters by 2026-08-11:
// **does the phone STOP for hundreds of milliseconds?** Work the arithmetic. Say
// the phone hands over 3000 packets in 800 ms and then stands still for 200 ms.
// Reads = 3000; total wait ≈ 792 + 200 = 992 ms; mean = 331 µs — the SAME number
// as a second with no stall at all. A fifth of the interval is invisible.
//
// 🚨 That is this project's own recurring error, third instance: an average over
// a window that mixes phases (sendCh depth vs blocked time, build 223 → 224; the
// 60 s conn-stats share; the `late`-vs-depth trap). Percentiles do not rescue it
// either — one 200 ms stall among 3000 reads is the 99.97th percentile, so even
// p99 would be the ordinary inter-packet gap.
//
// ⇒ What answers it is STALL ACCOUNTING: how many waits exceeded a threshold far
// above the normal gap, how much of the interval they consumed, and the longest
// one. That is directly comparable to the DEAD TIME measured at the inner
// receiver on server2 (8.3% of flow-time at 8 flows rising to 25.6% at 64), and
// it is measured HERE, on the phone, at the sender — the position the 08-11
// `bytes_in_flight` reading was retracted for getting wrong.
//
// ⚠️ THE THRESHOLD IS A COMPROMISE AND MUST BE READ WITH tun-pps BESIDE IT. At
// 3000 pkt/s the ordinary gap is 333 µs and 20 ms is sixty times that; at 100
// pkt/s the ordinary gap is 10 ms and the counter starts catching normal
// behaviour. So this field means what it says only on LOADED intervals — the
// same caveat the share above carries, and the reason the rates print next to it.
const tunStallNsThreshold = 20 * 1_000_000 // 20 ms

// Counters are package-level and read-and-reset by the memstats tick, in the
// idiom of sendChPeak. There is exactly one TUN per extension process.
var (
	tunReadNs      atomic.Int64 // time INSIDE Read — waiting for iOS
	tunGapNs       atomic.Int64 // time BETWEEN Reads — wireguard-go's own work
	tunReads       atomic.Int64 // Read calls
	tunReadPkts    atomic.Int64 // packets returned
	tunReadBytes   atomic.Int64 // bytes returned
	tunLastRet     atomic.Int64 // when the previous Read returned, unix nanos
	tunLastSummary atomic.Int64 // when the dump last ran, so the window is its own

	// Stall accounting: waits longer than tunStallNsThreshold, i.e. the phone
	// having nothing for us for a time the inner TCP's ACK clock would notice.
	tunStalls   atomic.Int64 // how many
	tunStallNs  atomic.Int64 // how long in total
	tunStallMax atomic.Int64 // the longest single one
)

// WrapTUNForStats times the uplink read loop. The wrapper is transparent:
// everything except Read is the underlying device's own method, so nothing about
// the data path changes.
func WrapTUNForStats(d tun.Device) tun.Device { return &statsTUN{Device: d} }

func (t *statsTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	start := time.Now()
	// The gap is the time since the PREVIOUS Read returned — i.e. everything
	// wireguard-go did with the last packet before coming back for the next one.
	// ⚠️ Skipped on the first call, where there is no previous return and the
	// "gap" would be the whole time since process start.
	if prev := tunLastRet.Load(); prev != 0 {
		if gap := start.UnixNano() - prev; gap > 0 {
			tunGapNs.Add(gap)
		}
	}

	n, err := t.Device.Read(bufs, sizes, offset)

	end := time.Now()
	waited := end.Sub(start).Nanoseconds()
	tunReadNs.Add(waited)
	tunReads.Add(1)
	// A wait far longer than the packet interval is the phone standing still.
	// Counted separately from the mean above because the mean cannot see it —
	// see the arithmetic on tunStallNsThreshold.
	if waited >= tunStallNsThreshold {
		tunStalls.Add(1)
		tunStallNs.Add(waited)
		noteMax64(&tunStallMax, waited)
	}
	tunLastRet.Store(end.UnixNano())
	if n > 0 {
		tunReadPkts.Add(int64(n))
		var b int64
		for i := 0; i < n && i < len(sizes); i++ {
			b += int64(sizes[i])
		}
		tunReadBytes.Add(b)
	}
	return n, err
}

// tunReadSummary renders one field group for the memstats tick and resets the
// window. Returns "" when the wrapper is not installed, so an un-wrapped build
// prints nothing rather than a row of zeroes that could pass for a measurement.
//
// ⚠️ It measures its OWN window from the previous call rather than taking the
// tick interval as an argument: the memstats loop switches between 10 s and 1 s
// cadences on an alloc spike, and a rate divided by the wrong interval is the
// wrong-window error this project has made repeatedly.
func tunReadSummary() string {
	now := time.Now()
	prevSummary := tunLastSummary.Swap(now.UnixNano())
	window := time.Duration(0)
	if prevSummary != 0 {
		window = time.Duration(now.UnixNano() - prevSummary)
	}
	reads := tunReads.Swap(0)
	if reads == 0 {
		return ""
	}
	readNs := tunReadNs.Swap(0)
	gapNs := tunGapNs.Swap(0)
	pkts := tunReadPkts.Swap(0)
	bytes := tunReadBytes.Swap(0)

	total := readNs + gapNs
	share := 0.0
	if total > 0 {
		share = 100 * float64(readNs) / float64(total)
	}
	perRead := time.Duration(0)
	perGap := time.Duration(0)
	if reads > 0 {
		perRead = time.Duration(readNs / reads)
		perGap = time.Duration(gapNs / reads)
	}
	rate := 0.0
	pps := 0.0
	if window > 0 {
		rate = float64(bytes) * 8 / window.Seconds() / 1e6
		pps = float64(pkts) / window.Seconds()
	}
	// 🚨 The SHARE is the answer and the rates are what make it readable: at idle
	// the share is trivially ~100% because Read blocks on nothing arriving, so a
	// share without a load figure beside it says nothing at all.
	return fmt.Sprintf(" tun-read=%.1f%%/%s tun-gap=%s tun-pps=%.0f tun-mbit=%.1f%s",
		share, perRead.Round(time.Microsecond), perGap.Round(time.Microsecond), pps, rate,
		tunStallSummary(window))
}

// tunStallSummary renders the stall group and clears it, or "" when the phone
// never stood still — an interval with no stalls must print NOTHING rather than
// a row of zeroes, because "0" here is the finding and it has to be visibly
// absent rather than quietly typed.
//
// 🚨 THE SHARE IS COMPUTED AGAINST THE SUMMARY'S OWN WINDOW, the same one the
// rates use, and NOT against a tick interval passed in from outside. The memstats
// cadence switches between 10 s and 1 s, and a duration divided by the wrong
// interval is the wrong-window error this file's header already warns about.
//
// ⚠️ Read it as "the phone had nothing for us for this long, in chunks", i.e. the
// sender-side twin of the DEAD TIME measured at the inner receiver. It does NOT
// say why: a stalled sender and an iOS scheduler that simply did not run us look
// identical from here. What it does settle is WHERE — above the extension.
func tunStallSummary(window time.Duration) string {
	n := tunStalls.Swap(0)
	ns := tunStallNs.Swap(0)
	maxNs := tunStallMax.Swap(0)
	if n == 0 {
		return ""
	}
	share := 0.0
	if window > 0 {
		share = 100 * float64(ns) / float64(window.Nanoseconds())
	}
	return fmt.Sprintf(" tun-stall=%d/%s/%.0f%% max=%s",
		n, time.Duration(ns).Round(time.Millisecond), share,
		time.Duration(maxNs).Round(time.Millisecond))
}

// File is delegated explicitly rather than embedded-only so the compiler pins
// the interface: a future wireguard-go that widens tun.Device fails to build
// here instead of silently losing the instrumentation.
func (t *statsTUN) File() *os.File { return t.Device.File() }
