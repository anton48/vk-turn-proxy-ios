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
	tunReadNs.Add(end.Sub(start).Nanoseconds())
	tunReads.Add(1)
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
	return fmt.Sprintf(" tun-read=%.1f%%/%s tun-gap=%s tun-pps=%.0f tun-mbit=%.1f",
		share, perRead.Round(time.Microsecond), perGap.Round(time.Microsecond), pps, rate)
}

// File is delegated explicitly rather than embedded-only so the compiler pins
// the interface: a future wireguard-go that widens tun.Device fails to build
// here instead of silently losing the instrumentation.
func (t *statsTUN) File() *os.File { return t.Device.File() }
