package csqtt25

import (
	"encoding/binary"
	"testing"
	"time"
)

// pkt4 is an IPv4 packet of n bytes for a flow; sport tells flows apart.
func pkt4(proto byte, sport uint16, n int) []byte {
	if n < 28 {
		n = 28
	}
	p := make([]byte, n)
	p[0] = 0x45
	p[9] = proto
	copy(p[12:16], []byte{198, 51, 100, 2})
	copy(p[16:20], []byte{203, 0, 113, 9})
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], 443)
	return p
}

func all(int) bool { return true }

// A TCP flow stays on ONE stream for a burst and moves only at its end:
// inside a burst the server sees the flow's packets in order, and it puts
// nothing back in order itself.
func TestAFlowMovesOnlyAtABurstsEnd(t *testing.T) {
	if FlowBurst != 16*1024 {
		t.Fatalf("a burst is %d bytes; both ends of the wire use 16 KiB", FlowBurst)
	}
	d := NewDispatcher(6)
	now := time.Unix(1000, 0)
	pkt := pkt4(6, 4000, 1200)
	cost := len(pkt) + pathOverheadPerDatagram
	perBurst := FlowBurst / cost
	var runs []int
	last, run := -1, 0
	for i := 0; i < perBurst*5; i++ {
		now = now.Add(time.Millisecond)
		idx, ok := d.Pick(pkt, 1, all, now)
		if !ok {
			t.Fatal("no stream")
		}
		if idx != last {
			if run > 0 {
				runs = append(runs, run)
			}
			last, run = idx, 0
		}
		run++
	}
	if len(runs) < 3 {
		t.Fatalf("the flow moved %d time(s) in five bursts' worth of packets", len(runs))
	}
	for i, r := range runs {
		if r < perBurst-1 || r > perBurst+1 {
			t.Fatalf("run %d on one stream was %d packets, a burst is %d", i, r, perBurst)
		}
	}
}

// Two flows are told apart and each keeps its own stream; a packet that is
// not IP has no flow and is simply balanced.
func TestFlowsAreKeptApart(t *testing.T) {
	d := NewDispatcher(4)
	now := time.Unix(1000, 0)
	a, b := pkt4(6, 1111, 600), pkt4(6, 2222, 600)
	ia, _ := d.Pick(a, 1, all, now)
	ib, _ := d.Pick(b, 1, all, now)
	if ia == ib {
		t.Fatal("two new flows were put on one stream while others stood idle")
	}
	for i := 0; i < 8; i++ {
		now = now.Add(time.Millisecond)
		if x, _ := d.Pick(a, 1, all, now); x != ia {
			t.Fatal("flow A left its stream inside its burst")
		}
		if x, _ := d.Pick(b, 1, all, now); x != ib {
			t.Fatal("flow B left its stream inside its burst")
		}
	}
	seen := map[int]bool{}
	for i := 0; i < 8; i++ {
		x, ok := d.Pick([]byte{0xff, 0xff, 0xff, 0xff}, 1, all, now)
		if !ok {
			t.Fatal("no stream for a packet without a flow")
		}
		seen[x] = true
	}
	// They go where the balance is highest: the two streams the flows left idle.
	if len(seen) != 2 || seen[ia] || seen[ib] {
		t.Fatalf("packets without a flow went to streams %v; the flows hold %d and %d", seen, ia, ib)
	}
	if _, ok := flowOf([]byte{0x45, 0, 0}); ok {
		t.Fatal("a truncated header has a flow")
	}
	// A later IP fragment has no transport header: what stands where the
	// ports would be is payload, and two such fragments are one flow.
	f1, f2 := pkt4(17, 1111, 600), pkt4(17, 2222, 600)
	binary.BigEndian.PutUint16(f1[6:8], 185)
	binary.BigEndian.PutUint16(f2[6:8], 185)
	k1, _ := flowOf(f1)
	k2, _ := flowOf(f2)
	if k1 != k2 || k1.sport != 0 || k1.dport != 0 {
		t.Fatal("a later IP fragment was given ports")
	}
}

// A small-UDP flow is pinned: it stays on its stream past a burst's worth of
// bytes, for as long as small packets keep coming within the second.
func TestASmallUDPFlowIsPinned(t *testing.T) {
	d := NewDispatcher(6)
	now := time.Unix(1000, 0)
	first, _ := d.Pick(pkt4(17, 5000, 120), 1, all, now)
	sent := 0
	for i := 0; i < 400; i++ { // 64 packets a second, small and 1200-byte alternating
		now = now.Add(15625 * time.Microsecond)
		n := 1200
		if i%2 == 0 {
			n = 120
		}
		idx, _ := d.Pick(pkt4(17, 5000, n), 1, all, now)
		if idx != first {
			t.Fatalf("the pinned flow moved after %d bytes (packet %d)", sent, i)
		}
		sent += n
	}
	if sent < 3*FlowBurst {
		t.Fatalf("the fixture sent only %d bytes", sent)
	}
	// Left alone for more than the sticky second, a large packet may move it.
	now = now.Add(2 * time.Second)
	moved := false
	for i := 0; i < 40 && !moved; i++ {
		now = now.Add(time.Millisecond)
		idx, _ := d.Pick(pkt4(17, 5000, 1200), 1, all, now)
		moved = idx != first
	}
	if !moved {
		t.Fatal("the flow stayed pinned with no small packet for two seconds and two bursts of large ones")
	}
}

// A flow that carries more than one stream takes loses its pin although
// small packets keep coming (a QUIC-like upload held on one stream ran at
// that stream's rate).
func TestABulkUDPFlowLosesItsPin(t *testing.T) {
	d := NewDispatcher(6)
	now := time.Unix(1000, 0)
	used := map[int]bool{}
	for i := 1; i < 4000; i++ { // ≈20 Mbit/s of 1300-byte packets, a small one every 200 ms
		now = now.Add(520 * time.Microsecond)
		n := 1300
		if i%385 == 0 {
			n = 100
		}
		idx, _ := d.Pick(pkt4(17, 6000, n), 1, all, now)
		if i > 400 {
			used[idx] = true
		}
	}
	if len(used) < 4 {
		t.Fatalf("a bulk UDP flow with small packets in it used %d stream(s) of 6", len(used))
	}
}

// A stream that cannot send is passed over — for a new flow and for one
// already on it — and with none usable there is no stream.
func TestAnUnusableStreamIsPassedOver(t *testing.T) {
	d := NewDispatcher(3)
	now := time.Unix(1000, 0)
	pkt := pkt4(6, 7000, 500)
	idx, _ := d.Pick(pkt, 1, all, now)
	down := idx
	alive := func(i int) bool { return i != down }
	for i := 0; i < 50; i++ {
		now = now.Add(time.Millisecond)
		got, ok := d.Pick(pkt, 1, alive, now)
		if !ok || got == down {
			t.Fatalf("pick %d went to the stream that cannot send", i)
		}
		if g2, _ := d.Pick(pkt4(6, uint16(8000+i), 500), 1, alive, now); g2 == down {
			t.Fatal("a new flow was put on the stream that cannot send")
		}
	}
	if _, ok := d.Pick(pkt, 1, func(int) bool { return false }, now); ok {
		t.Fatal("a stream was picked with none usable")
	}
	if _, ok := NewDispatcher(0).Pick(pkt, 1, all, now); ok {
		t.Fatal("a stream was picked out of none")
	}
}

// A bulk flow's bursts are spread: with every stream idle the next burst
// goes to the stream with the most tokens, so no stream is left out.
func TestBurstsAreSpreadOverTheStreams(t *testing.T) {
	d := NewDispatcher(5)
	now := time.Unix(1000, 0)
	used := map[int]int{}
	pkt := pkt4(6, 9000, 1200)
	for i := 0; i < 2000; i++ {
		now = now.Add(2 * time.Millisecond)
		idx, _ := d.Pick(pkt, 1, all, now)
		used[idx]++
	}
	if len(used) != 5 {
		t.Fatalf("a long flow used %d stream(s) of 5", len(used))
	}
	for i, n := range used {
		if n < 2000/5/3 {
			t.Fatalf("stream %d carried %d of 2000 packets", i, n)
		}
	}
}

// A resize forgets the flows (the indices mean other streams) and the
// table does not grow without bound.
func TestResizeAndTheFlowTablesBound(t *testing.T) {
	d := NewDispatcher(4)
	now := time.Unix(1000, 0)
	for i := 0; i < 3000; i++ {
		d.Pick(pkt4(6, uint16(i), 100), 1, all, now)
	}
	if n := len(d.flows); n > flowTableMax {
		t.Fatalf("%d flows in the table, the bound is %d", n, flowTableMax)
	}
	d.Resize(2)
	if len(d.flows) != 0 || len(d.tokens) != 2 {
		t.Fatal("a resize kept the flows of the old streams")
	}
	for i := 0; i < 20; i++ {
		if idx, ok := d.Pick(pkt4(6, 42, 100), 1, all, now); !ok || idx > 1 {
			t.Fatalf("after the resize a pick went to stream %d", idx)
		}
	}
	// Idle flows leave the table.
	e := NewDispatcher(2)
	for i := 0; i < 500; i++ {
		e.Pick(pkt4(6, uint16(i), 100), 1, all, now)
	}
	later := now.Add(flowIdleTTL + time.Second)
	for i := 0; i < flowEvictEach+10; i++ {
		e.Pick(pkt4(6, 60000, 100), 1, all, later)
	}
	if n := len(e.flows); n != 1 {
		t.Fatalf("%d flows left after the idle ones should have gone", n)
	}
}

// A fragmented packet is charged for every datagram it travels as.
func TestAFragmentedPacketIsChargedForItsDatagrams(t *testing.T) {
	d := NewDispatcher(1)
	now := time.Unix(1000, 0)
	pkt := pkt4(6, 1, 1400)
	d.Pick(pkt, 2, all, now)
	if got, want := d.tokens[0], streamCapacity-float64(1400+2*pathOverheadPerDatagram); got != want {
		t.Fatalf("tokens after a two-datagram packet: %v, want %v", got, want)
	}
	for i := 0; i < 100; i++ {
		d.Pick(pkt, 2, all, now)
	}
	if d.tokens[0] != streamFloor {
		t.Fatalf("the balance fell to %v, below its floor", d.tokens[0])
	}
}

// A flow that begins with a small UDP packet is pinned from that packet on.
func TestASmallFirstPacketPinsTheFlow(t *testing.T) {
	d := NewDispatcher(6)
	now := time.Unix(1000, 0)
	first, _ := d.Pick(pkt4(17, 5100, 100), 1, all, now)
	for i := 0; i < 20; i++ { // 25 kB of large packets inside the second, no small one among them
		now = now.Add(10 * time.Millisecond)
		if idx, _ := d.Pick(pkt4(17, 5100, 1200), 1, all, now); idx != first {
			t.Fatalf("the flow moved at packet %d although it began with a small one", i)
		}
	}
}

// Once a flow has carried more than a stream takes it is bulk for two
// seconds: small packets in a quieter stretch do not pin it back at once.
func TestABulkFlowStaysBulkForItsHold(t *testing.T) {
	d := NewDispatcher(6)
	now := time.Unix(1000, 0)
	for i := 0; i < 300; i++ { // ≈20 Mbit/s for 150 ms: well above one stream
		now = now.Add(500 * time.Microsecond)
		d.Pick(pkt4(17, 5200, 1300), 1, all, now)
	}
	used := map[int]bool{}
	for i := 0; i < 40; i++ { // then a quiet second: 40 packets, small and large alternating
		now = now.Add(25 * time.Millisecond)
		n := 1200
		if i%2 == 0 {
			n = 100
		}
		idx, _ := d.Pick(pkt4(17, 5200, n), 1, all, now)
		if i >= 12 { // past the window that was still full of the heavy stretch
			used[idx] = true
		}
	}
	if len(used) < 2 {
		t.Fatal("small packets pinned the flow back inside its bulk hold")
	}
}

// With every stream's balance at the floor new flows still spread: equal
// balances are told apart by where the last choice left off.
func TestNewFlowsSpreadWhenEveryBalanceIsEqual(t *testing.T) {
	d := NewDispatcher(4)
	now := time.Unix(1000, 0)
	for i := 0; i < 200; i++ { // no time passes: every balance falls to the floor
		d.Pick(pkt4(6, uint16(20000+i), 1400), 1, all, now)
	}
	got := map[int]int{}
	for i := 0; i < 400; i++ {
		idx, _ := d.Pick(pkt4(6, uint16(30000+i), 1400), 1, all, now)
		got[idx]++
	}
	for s := 0; s < 4; s++ {
		if got[s] < 50 {
			t.Fatalf("stream %d took %d of 400 new flows with every balance equal", s, got[s])
		}
	}
}

// A stream's balance comes back with time: one that was run down is taken
// again once it has rested.
func TestABalanceComesBackWithTime(t *testing.T) {
	d := NewDispatcher(2)
	now := time.Unix(1000, 0)
	only0 := func(i int) bool { return i == 0 }
	for i := 0; i < 50; i++ {
		d.Pick([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}, 20, only0, now) // run stream 0 down to the floor
	}
	now = now.Add(time.Second) // far more than the bucket's worth
	got := map[int]int{}
	for i := 0; i < 6; i++ {
		idx, _ := d.Pick(pkt4(6, uint16(40000+i), 1400), 1, all, now)
		got[idx]++
	}
	if got[0] < 2 {
		t.Fatalf("a rested stream took %d of 6 new flows", got[0])
	}
}

// IPv6 flows are told apart by their ports as IPv4 ones are.
func TestIPv6Flows(t *testing.T) {
	mk := func(sport uint16) []byte {
		p := make([]byte, 80)
		p[0] = 0x60
		p[6] = 6
		p[8], p[24] = 0x20, 0x20
		p[23], p[39] = 1, 2
		binary.BigEndian.PutUint16(p[40:42], sport)
		binary.BigEndian.PutUint16(p[42:44], 443)
		return p
	}
	a, ok := flowOf(mk(1111))
	if !ok || !a.v6 || a.proto != 6 || a.sport != 1111 || a.dport != 443 || a.src[15] != 1 || a.dst[15] != 2 {
		t.Fatalf("an IPv6 flow read as %+v (%v)", a, ok)
	}
	if b, _ := flowOf(mk(2222)); a == b {
		t.Fatal("two IPv6 flows with different ports are one")
	}
	if _, ok := flowOf(mk(1)[:39]); ok {
		t.Fatal("a truncated IPv6 header has a flow")
	}
}
