package proxy

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// wgTransportPkt builds a minimal WireGuard transport message.
func wgTransportPkt(idx uint32, ctr uint64) []byte {
	b := make([]byte, 32)
	b[0] = rxWGMsgTypeTransport
	binary.LittleEndian.PutUint32(b[4:8], idx)
	binary.LittleEndian.PutUint64(b[8:16], ctr)
	return b
}

func freshRx() *rxReorderStats {
	return &rxReorderStats{peers: map[uint32]*rxPeerSeq{}}
}

func TestInOrderStreamShowsNoDisorder(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint64(0); i < 100; i++ {
		s.observe(wgTransportPkt(7, i), now.Add(time.Duration(i)*time.Millisecond))
	}
	if s.total != 100 {
		t.Fatalf("total = %d, want 100", s.total)
	}
	if s.displaced != 0 || s.dup != 0 || s.stale != 0 {
		t.Fatalf("a strictly increasing stream reported displaced=%d dup=%d stale=%d, want all 0",
			s.displaced, s.dup, s.stale)
	}
}

// Depth is the distance BELOW the high-water mark, not the distance from the
// previous packet. Getting that backwards would make every late packet read as
// depth 1.
func TestDisplacementDepthIsDistanceBelowTheHighWaterMark(t *testing.T) {
	s, now := freshRx(), time.Now()
	// 3 is SKIPPED on the way up: a counter that already arrived and comes
	// again is a duplicate, not a late packet, and the bitmap says so.
	for i := uint64(0); i <= 9; i++ {
		if i == 3 {
			continue
		}
		s.observe(wgTransportPkt(7, i), now)
	}
	s.observe(wgTransportPkt(7, 3), now.Add(20*time.Millisecond)) // max is 9

	if s.dup != 0 {
		t.Fatalf("a genuinely missing counter was reported as %d duplicate(s)", s.dup)
	}
	if s.displaced != 1 {
		t.Fatalf("displaced = %d, want 1", s.displaced)
	}
	if s.maxDepth != 6 {
		t.Fatalf("maxDepth = %d, want 6 (9-3)", s.maxDepth)
	}
	if s.depth[6] != 1 {
		t.Fatalf("depth[6] = %d, want 1; histogram put it elsewhere", s.depth[6])
	}
	// Both ends bounded: a lower bound alone would also pass for a zero clock.
	if s.maxLate < 15*time.Millisecond || s.maxLate > 25*time.Millisecond {
		t.Fatalf("maxLate = %v, want ~20ms", s.maxLate)
	}
}

// Counting a duplicate as displaced is the exact conflation that made tshark
// report 47% reordering where the truth was 1.24%.
func TestADuplicateIsCountedAsDuplicationNotReordering(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint64(0); i <= 5; i++ {
		s.observe(wgTransportPkt(7, i), now)
	}
	s.observe(wgTransportPkt(7, 5), now)

	if s.dup != 1 {
		t.Fatalf("dup = %d, want 1", s.dup)
	}
	if s.displaced != 0 {
		t.Fatalf("a duplicate was counted as %d displaced packet(s)", s.displaced)
	}
}

// A rekey restarts the counter at 0. Keyed by receiver index that is a new
// sequence; keyed by anything else it is a four-billion-packet backwards jump
// that would swamp every statistic in the interval.
func TestRekeyStartsANewSequenceInsteadOfAHugeBackwardsJump(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint64(1000); i <= 1005; i++ {
		s.observe(wgTransportPkt(1, i), now)
	}
	for i := uint64(0); i <= 5; i++ {
		s.observe(wgTransportPkt(2, i), now)
	}
	if s.displaced != 0 {
		t.Fatalf("a rekey produced %d displaced packets, want 0", s.displaced)
	}
	if s.rekeys != 2 {
		t.Fatalf("keypairs = %d, want 2", s.rekeys)
	}
	if s.maxDepth != 0 {
		t.Fatalf("maxDepth = %d after a rekey, want 0", s.maxDepth)
	}
}

// The probe sentinel and the group hello both start with 0xff, handshakes are
// types 1-3, and anything shorter than the header cannot be transport at all.
func TestNonTransportPacketsAreIgnored(t *testing.T) {
	s, now := freshRx(), time.Now()
	s.observe([]byte{0xff, 'P', 'N', 'G', 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, now)
	s.observe([]byte{0xff, 'G', 'R', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, now)
	handshake := wgTransportPkt(7, 1)
	handshake[0] = 1
	s.observe(handshake, now)
	s.observe([]byte{4, 0, 0, 0}, now) // too short for a header

	if s.total != 0 {
		t.Fatalf("total = %d, want 0 — a non-transport packet entered the statistics", s.total)
	}
}

// Truncating the rank puts the median of three samples on the smallest of them.
func TestPercentileRoundsUpSoTheMedianIsNotTheSmallest(t *testing.T) {
	h := make([]int64, 64)
	h[5], h[20], h[40] = 1, 1, 1

	if got := rxHistPct(h, 3, 0.50); got != 20 {
		t.Fatalf("p50 of {5,20,40} = %d, want 20", got)
	}
	if got := rxHistPct(h, 3, 0.99); got != 40 {
		t.Fatalf("p99 of {5,20,40} = %d, want 40", got)
	}
	if got := rxHistPct(h, 0, 0.50); got != -1 {
		t.Fatalf("p50 of an empty histogram = %d, want -1", got)
	}
}

// The interval counters reset; the per-keypair SEQUENCE must not, or every
// interval boundary would look like a fresh keypair and hide real displacement.
func TestDumpResetsCountersButKeepsTheSequence(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint64(0); i <= 9; i++ {
		if i == 3 { // left missing, to be delivered late after the dump
			continue
		}
		s.observe(wgTransportPkt(7, i), now)
	}
	s.dumpAndReset(now)

	if s.total != 0 || s.displaced != 0 || s.maxDepth != 0 {
		t.Fatalf("after dump: total=%d displaced=%d maxDepth=%d, want all 0",
			s.total, s.displaced, s.maxDepth)
	}
	// The sequence survived: 3 is still below the old high-water mark of 9.
	s.observe(wgTransportPkt(7, 3), now)
	if s.displaced != 1 || s.maxDepth != 6 {
		t.Fatalf("sequence state was lost across the dump: displaced=%d maxDepth=%d, want 1 and 6",
			s.displaced, s.maxDepth)
	}
	if s.rekeys != 0 {
		t.Fatalf("the surviving keypair was recounted as %d new keypair(s)", s.rekeys)
	}
}

func TestSummaryIsSilentWhenNothingArrived(t *testing.T) {
	s := freshRx()
	if line := s.summaryLocked(); line != "" {
		t.Fatalf("an empty interval produced a line: %q", line)
	}
	s.observe(wgTransportPkt(7, 1), time.Now())
	line := s.summaryLocked()
	if !strings.Contains(line, "reorder(downlink)") || !strings.Contains(line, "keypairs 1") {
		t.Fatalf("summary line is missing its identifying fields: %q", line)
	}
}

// 🚨 THE ONE THAT CATCHES SABOTAGE. Every test above drives observe() directly,
// so all of them stay green if the call is removed from the receive path and
// the instrument silently measures nothing — precisely the failure this project
// has shipped before. This test goes through ReceivePacket, which is also the
// only correct observation point: see the comment on downlinkReorder.
func TestTheInstrumentIsFedByReceivePacket(t *testing.T) {
	saved := downlinkReorder
	downlinkReorder = freshRx()
	defer func() { downlinkReorder = saved }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 4)}

	for i := uint64(0); i <= 3; i++ {
		if !p.enqueueRecv(ctx, wgTransportPkt(9, i)) {
			t.Fatal("enqueueRecv failed with room available")
		}
	}
	// Queued but not yet consumed: nothing may have been recorded, because the
	// producer side is deliberately NOT the observation point.
	downlinkReorder.mu.Lock()
	queuedTotal := downlinkReorder.total
	downlinkReorder.mu.Unlock()
	if queuedTotal != 0 {
		t.Fatalf("%d packets were recorded before ReceivePacket drained them — "+
			"the instrument is back on the producer side, where it under-reports "+
			"disorder about tenfold", queuedTotal)
	}

	buf := make([]byte, 64)
	for i := 0; i < 4; i++ {
		if _, err := p.ReceivePacket(buf); err != nil {
			t.Fatalf("ReceivePacket: %v", err)
		}
	}
	downlinkReorder.mu.Lock()
	total := downlinkReorder.total
	downlinkReorder.mu.Unlock()
	if total != 4 {
		t.Fatalf("the receive path fed the instrument %d packets, want 4 — "+
			"observeRx is not being called from ReceivePacket", total)
	}
}

// 🚨 THE MEMORY-SAFETY BOUND. The receiver index is unauthenticated network
// input and each novel one costs a 1 KB bitmap; without a cap ~30 000 of them
// exceed the extension's jetsam budget. Bound BOTH ends: the map must stop
// growing, and the refusals must be visible rather than silent.
func TestNovelKeypairsAreCappedAndCounted(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint32(0); i < rxReorderMaxPeers*4; i++ {
		s.observe(wgTransportPkt(i, 1), now)
	}
	if len(s.peers) != rxReorderMaxPeers {
		t.Fatalf("peers = %d, want the cap of %d — the map is unbounded and a "+
			"flood of forged receiver indices will kill the extension",
			len(s.peers), rxReorderMaxPeers)
	}
	want := int64(rxReorderMaxPeers * 3)
	if s.refused != want {
		t.Fatalf("refused = %d, want %d", s.refused, want)
	}
	// A refusal must not be laundered into the traffic statistics.
	if s.total != int64(rxReorderMaxPeers) {
		t.Fatalf("total = %d, want %d — refused packets were counted as observed",
			s.total, rxReorderMaxPeers)
	}
	// And it must not be silent: the line is emitted on refusals alone.
	if line := s.summaryLocked(); !strings.Contains(line, "refused ") {
		t.Fatalf("refusals are invisible in the summary: %q", line)
	}
}

// A flood that is refused outright leaves total == 0. The line must still be
// emitted, or the one situation that most needs seeing is the silent one.
func TestASilentFloodStillProducesALine(t *testing.T) {
	s, now := freshRx(), time.Now()
	for i := uint32(0); i < rxReorderMaxPeers; i++ {
		s.observe(wgTransportPkt(i, 1), now)
	}
	s.total = 0 // as if the real traffic sat in an earlier interval
	s.observe(wgTransportPkt(999999, 1), now)

	if s.refused == 0 {
		t.Fatal("the flood was not refused")
	}
	if line := s.summaryLocked(); line == "" {
		t.Fatal("a refusal-only interval produced no line at all")
	}
}

// Disabling must make it inert, so a control run really is a control.
func TestDisabledInstrumentRecordsNothing(t *testing.T) {
	s := freshRx()
	rxReorderEnabled = false
	defer func() { rxReorderEnabled = true }()

	s.observeRx(wgTransportPkt(7, 1))
	if s.total != 0 {
		t.Fatalf("total = %d while disabled, want 0", s.total)
	}
}
