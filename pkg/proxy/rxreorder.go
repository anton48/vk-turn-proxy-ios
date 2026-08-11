package proxy

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// DOWNLINK reorder measurement — how badly OUR OWN 30 connections shuffle the
// return path, measured on the phone, at the point where they merge.
//
// WHY THIS EXISTS, AND WHAT IT DECIDES.
//
// Upload sits at ~19-22 Mbit/s while download runs at 103 through the SAME 30
// connections, the same relay and the same RTT spread. Our code is symmetric
// between the directions, so a 5x asymmetry has a cause we have not found. Two
// asymmetries are known and NEITHER is in our code:
//
//  1. the DOWNLINK is PACED per connection (server/pacer.go, 247 KiB/s of
//     counted bytes); the uplink is not paced at all;
//  2. the SENDER differs — it is always the sender that reacts to reordering,
//     because it is the one seeing the duplicate ACKs. Uploading, the sender is
//     Darwin on this phone. Downloading, it is whatever is at the far end.
//
// 🚨 AND (2) IS WEAKER THAN IT WAS WRITTEN DOWN AS. It used to say "downloading,
// the sender is Linux with RACK and adaptive tcp_reordering". That is wrong for
// our own measurements: the iperf3 runs were against our FreeBSD box, whose
// default stack is NOT RACK and has no Linux-style reordering auto-tuning. So
// the download sender is, if anything, LESS reorder-tolerant than Darwin — and
// download still does 103. Which makes it much more likely that the operative
// asymmetry is (1), and much more important to measure the thing below.
//
// server/reorder.go measures the UPLINK, at server1, where the connections
// merge. It has no counterpart on this side, so everything we know about the
// downlink is that 84-86% of its ACKs are displaced — and ACKs are the
// back-channel, not the stream. This is the missing half:
//
//   - downlink as disordered as the uplink, yet 103 Mbit/s  =>  disorder is not
//     what limits upload at all, and the difference is the sender's stack;
//   - downlink arrives near-ordered  =>  something preserves order on the way
//     down that the uplink lacks — pacing being the obvious candidate — and the
//     client-side pacer becomes live again for a MEASURED reason.
//
// This is deliberately a LINE-FOR-LINE port of server/reorder.go. The two
// numbers only mean something next to each other, so the two instruments must
// not differ in how they count.
//
// WHY WIREGUARD'S COUNTER AND NOT A CAPTURE. On the wire everything is inside
// SRTP+DTLS+WireGuard and a capture would need three decryptors. But a
// WireGuard TRANSPORT message carries its 64-bit counter IN THE CLEAR — it is
// the AEAD nonce, so it has to be readable — and the counter is strictly
// increasing at the sender by construction, which makes displacement EXACT
// rather than heuristic.
//
//	byte 0     : message type, 4 = transport data
//	bytes 1-3  : reserved
//	bytes 4-7  : receiver index (LE) — on an INBOUND packet this is the index
//	             WE assigned, so it is a stable per-keypair discriminator here
//	             exactly as it is on the server
//	bytes 8-15 : counter (LE)        — strictly increasing per keypair
//
// ⚠️ REKEY IS NOT REORDERING. WireGuard rotates keypairs roughly every 2 minutes
// and the counter restarts at 0. Keying state by RECEIVER INDEX makes that a
// new sequence rather than a 4-billion-packet backwards jump; the keypair count
// is reported so an implausible statistic can be checked against it.
//
// ⚠️ The probe sentinel (0xff 'P' 'N' 'G') and the group hello (0xff 'G' 'R' 'P')
// are outside WireGuard's 1..4 message-type range, so the type check drops them.

const (
	rxWGMsgTypeTransport = 4
	rxWGTransportHdrLen  = 16 // type(1) + reserved(3) + receiver(4) + counter(8)

	// Displacement is exact below this and lands in one overflow bucket above.
	// 🚨 On the server this SATURATED at 1024 during the synthetic run (p50 =
	// p90 = 1024 is a FLOOR, not a value) — so read maxDepth and the overflow
	// bucket before quoting a percentile, and treat p90 == 1024 as "unmeasured".
	rxReorderDepthBuckets = 1024
	// Lateness in whole milliseconds, same shape.
	rxReorderLateBuckets = 512

	// Duplicate-detection window, in packets. Deliberately the same 8128 as
	// wireguard-go's own replay window (replay.windowSize = 127*64): a duplicate
	// too old for WireGuard to reject is also too old for us to care about.
	// Costs 1016 B of bitmap per live keypair.
	rxReorderDupWindow = 8128

	// Keypairs with no traffic for this long are dropped, so a long session does
	// not accumulate state for dead keypairs. Deliberately short: the only way
	// junk indices leave the map is by going idle, and a live keypair sends
	// continuously, so a minute is generous for the real ones and quick for the
	// rest.
	rxReorderPeerIdle = 60 * time.Second

	// 🚨 HARD CAP ON TRACKED KEYPAIRS, AND IT IS A MEMORY-SAFETY BOUND, NOT A
	// TUNING KNOB. observe() runs BEFORE WireGuard has authenticated anything —
	// the receiver index is four bytes of unvalidated network input — so without
	// a cap any party that can put packets on our relay sockets mints one 1016 B
	// bitmap per novel index. Measured: 50 000 indices = 56 MB of heap, against
	// GOMEMLIMIT 35 MB and a ~50 MB jetsam ceiling; roughly 30 000 of them, a
	// few seconds of traffic, kills the extension. A real session holds about
	// three live keypairs, so 64 is generous and the worst case is ~70 KB.
	// Refusals are counted and printed — if that number is not zero, something
	// is injecting and the whole reading is suspect.
	rxReorderMaxPeers = 64
)

// rxPeerSeq tracks one keypair's counter sequence.
type rxPeerSeq struct {
	max uint64 // highest counter seen
	// maxAt is when `max` was seen, and `late` is measured against it.
	//
	// 🚨 SO `late` IS NOT "HOW LONG A MISSING PACKET TAKES TO ARRIVE." It is the
	// time since the NEWEST counter arrived, which under a continuous stream is
	// just an inter-arrival gap. Sizing anything from it is the mistake that
	// produced "25-40 ms should catch nearly everything" when 30 ms turned out
	// to be the worst working hold there is. The quantity that describes the
	// spread is DEPTH. Report `late` as what it is.
	maxAt time.Time
	seen  []uint64  // bitmap ring over (max-rxReorderDupWindow, max]
	last  time.Time // for idle pruning
}

func newRxPeerSeq(now time.Time) *rxPeerSeq {
	return &rxPeerSeq{seen: make([]uint64, rxReorderDupWindow/64), last: now}
}

// mark records counter c in the ring and reports whether it was already there.
// Counters more than rxReorderDupWindow behind the maximum cannot be answered
// and return stale=true.
func (p *rxPeerSeq) mark(c uint64) (dup bool, stale bool) {
	if c > p.max {
		// Advancing: clear the bits the window slides over, so a counter from a
		// previous lap cannot masquerade as a duplicate.
		gap := c - p.max
		if gap >= rxReorderDupWindow {
			for i := range p.seen {
				p.seen[i] = 0
			}
		} else {
			for x := p.max + 1; x <= c; x++ {
				idx := x % rxReorderDupWindow
				p.seen[idx/64] &^= 1 << (idx % 64)
			}
		}
		idx := c % rxReorderDupWindow
		p.seen[idx/64] |= 1 << (idx % 64)
		return false, false
	}
	if p.max-c >= rxReorderDupWindow {
		return false, true
	}
	idx := c % rxReorderDupWindow
	if p.seen[idx/64]&(1<<(idx%64)) != 0 {
		return true, false
	}
	p.seen[idx/64] |= 1 << (idx % 64)
	return false, false
}

type rxReorderStats struct {
	mu    sync.Mutex
	peers map[uint32]*rxPeerSeq

	total     int64 // transport packets observed
	displaced int64 // counter below the maximum, and genuinely not a duplicate
	dup       int64 // counter seen before — duplication, NOT reordering
	stale     int64 // too far behind to classify
	rekeys    int64 // new receiver index, i.e. a fresh keypair
	refused   int64 // new index rejected because the map is at rxReorderMaxPeers

	depth    [rxReorderDepthBuckets + 1]int64
	late     [rxReorderLateBuckets + 1]int64
	maxDepth uint64
	maxLate  time.Duration
}

// downlinkReorder is measured in ReceivePacket, at the single point where
// packets leave recvCh on their way into wireguard-go.
//
// 🚨 IT WAS FIRST WRITTEN AT THE PRODUCER SIDE OF recvCh AND THAT WAS WRONG, in
// the one direction that mattered. Up to 30 inbound goroutines enter
// enqueueRecv, take the instrument's lock, release it, and only then race for
// the channel — so the order recorded there is the order they ARRIVED, not the
// order they WON. Measured against the sequence the consumer actually
// delivered: ~0.6% out-of-order reported against ~5.8% real, about 10x under,
// every run, always low. Under-reporting disorder is exactly what would have
// produced the false conclusion "the downlink arrives near-ordered, so pacing
// preserves order" — one of the two outcomes this file exists to choose
// between. An instrument that errs toward one of your hypotheses is worse than
// no instrument.
//
// ReceivePacket is single-threaded by construction (turnbind returns exactly
// one conn.ReceiveFunc, and wireguard-go runs one RoutineReceiveIncoming per
// receive func), so this point is both correct and free of the 30-way lock
// contention the producer side had.
//
// ⚠️ This therefore measures the ORDER WIREGUARD GETS. It does not separate the
// path's disorder from any our own queueing adds; doing that needs a second
// instance at the producer side and a second 64-keypair map, which is not worth
// the phone's memory until there is a question that needs it.
//
// Read only by the memstats tick: ONE consumer, because the counters are
// read-and-reset and two readers would steal from each other.
var downlinkReorder = &rxReorderStats{peers: map[uint32]*rxPeerSeq{}}

// rxReorderEnabled gates the whole thing so a run can be done without it as a
// control. On by default: the cost is one mutex, one map lookup and a few bit
// operations per DOWNLINK packet, and nothing at all per uplink packet.
var rxReorderEnabled = true

// observeRx is the call-site helper. It reads the clock only when there is
// something to record, so a disabled instrument, a handshake and a sentinel all
// cost one comparison and no time.Now() on the receive hot path.
func (s *rxReorderStats) observeRx(pkt []byte) {
	if !rxReorderEnabled || len(pkt) < rxWGTransportHdrLen || pkt[0] != rxWGMsgTypeTransport {
		return
	}
	s.observe(pkt, time.Now())
}

// observe records one packet on its way from a connection to WireGuard. Takes
// the clock as a parameter so tests can drive it deterministically; production
// calls arrive through observeRx. Handshake messages carry no counter and are
// ignored; so are short buffers, which cannot be transport messages at all.
func (s *rxReorderStats) observe(pkt []byte, now time.Time) {
	if !rxReorderEnabled || len(pkt) < rxWGTransportHdrLen || pkt[0] != rxWGMsgTypeTransport {
		return
	}
	idx := binary.LittleEndian.Uint32(pkt[4:8])
	ctr := binary.LittleEndian.Uint64(pkt[8:16])

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.peers[idx]
	if p == nil {
		if len(s.peers) >= rxReorderMaxPeers {
			// Refuse rather than allocate. See rxReorderMaxPeers: the index is
			// unauthenticated input and the bitmap is 1 KB.
			s.refused++
			return
		}
		p = newRxPeerSeq(now)
		p.max, p.maxAt = ctr, now
		s.peers[idx] = p
		s.rekeys++
		s.total++
		_, _ = p.mark(ctr)
		return
	}
	p.last = now
	s.total++

	dup, stale := p.mark(ctr)
	switch {
	case dup:
		// A duplicate is duplication, not reordering. Counting it as displaced
		// is exactly the conflation that made tshark report 47% where the truth
		// was 1.24%.
		s.dup++
		return
	case stale:
		s.stale++
		return
	}
	if ctr > p.max {
		p.max, p.maxAt = ctr, now
		return
	}

	d := p.max - ctr
	s.displaced++
	if d > s.maxDepth {
		s.maxDepth = d
	}
	if d > rxReorderDepthBuckets {
		s.depth[rxReorderDepthBuckets]++
	} else {
		s.depth[d]++
	}

	late := now.Sub(p.maxAt)
	if late > s.maxLate {
		s.maxLate = late
	}
	ms := int(late / time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	if ms > rxReorderLateBuckets {
		ms = rxReorderLateBuckets
	}
	s.late[ms]++
}

// rxHistPct returns the value at the given fraction of a histogram, or -1 when
// the histogram is empty.
//
// ⚠️ Nearest-rank, with the rank ROUNDED UP. Truncating instead puts p50 of
// three samples on the smallest of them, and a diagnostic that lies on small
// intervals is worse than none — short intervals are exactly what a burst gets.
func rxHistPct(h []int64, total int64, frac float64) int {
	if total == 0 {
		return -1
	}
	want := int64(math.Ceil(frac * float64(total)))
	if want < 1 {
		want = 1
	}
	var seen int64
	for i, c := range h {
		seen += c
		if seen >= want {
			return i
		}
	}
	return len(h) - 1
}

// dumpAndReset writes one summary line and clears the interval counters. The
// per-keypair sequence state is NOT cleared — it is the running sequence, not a
// statistic — except for keypairs that have gone idle.
//
// Called by the memstats tick only. Silent when no transport packet arrived in
// the interval, so an idle phone does not fill the log.
func (s *rxReorderStats) dumpAndReset(now time.Time) {
	if !rxReorderEnabled {
		return
	}
	s.mu.Lock()
	line := s.summaryLocked()
	s.total, s.displaced, s.dup, s.stale, s.rekeys, s.refused = 0, 0, 0, 0, 0, 0
	s.maxDepth, s.maxLate = 0, 0
	for i := range s.depth {
		s.depth[i] = 0
	}
	for i := range s.late {
		s.late[i] = 0
	}
	for idx, p := range s.peers {
		if now.Sub(p.last) > rxReorderPeerIdle {
			delete(s.peers, idx)
		}
	}
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
}

// summaryLocked builds the report. Caller holds s.mu.
//
// The field order and names match server/reorder.go's line exactly, so the two
// can be diffed by eye and by script.
func (s *rxReorderStats) summaryLocked() string {
	// refused is in the condition on purpose: a flood of novel receiver indices
	// is refused WITHOUT being counted in total, so keying the line on total
	// alone would make the one situation we most need to see the silent one.
	if s.total == 0 && s.refused == 0 {
		return ""
	}
	share := 100 * float64(s.displaced) / float64(s.total)
	dh, lh := s.depth[:], s.late[:]
	return fmt.Sprintf(
		"proxy: reorder(downlink): %d pkts, %.1f%% out-of-order, depth p50/p90/p99/max %d/%d/%d/%d, late p50/p90/p99 %d/%d/%d ms (max %s), dup %d, stale %d, keypairs %d, refused %d",
		s.total, share,
		rxHistPct(dh, s.displaced, 0.50), rxHistPct(dh, s.displaced, 0.90), rxHistPct(dh, s.displaced, 0.99), s.maxDepth,
		rxHistPct(lh, s.displaced, 0.50), rxHistPct(lh, s.displaced, 0.90), rxHistPct(lh, s.displaced, 0.99),
		s.maxLate.Round(time.Millisecond),
		s.dup, s.stale, s.rekeys, s.refused)
}
