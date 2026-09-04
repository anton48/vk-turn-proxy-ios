// SPDX-License-Identifier: MIT

package csqtt

import "testing"

func ipv4UDPPorts(payloadLen int, sport, dport uint16) []byte {
	p := ipv4UDP(payloadLen)
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	return p
}

func TestClassifyByLengthAndKind(t *testing.T) {
	if got := Classify(ipv4TCP(100, 0x18, 1, 2)); got != ClassSmall {
		t.Fatalf("140 B TCP data → %v, want Small", got)
	}
	// The boundaries themselves: 164 is the last Small, 1000 the first Bulk.
	if got := Classify(ipv4TCP(124, 0x18, 1, 2)); got != ClassSmall {
		t.Fatalf("164 B → %v, want Small", got)
	}
	if got := Classify(ipv4TCP(125, 0x18, 1, 2)); got != ClassMedium {
		t.Fatalf("165 B → %v, want Medium", got)
	}
	if got := Classify(ipv4TCP(959, 0x18, 1, 2)); got != ClassMedium {
		t.Fatalf("999 B → %v, want Medium", got)
	}
	if got := Classify(ipv4TCP(960, 0x18, 1, 2)); got != ClassBulk {
		t.Fatalf("1000 B → %v, want Bulk", got)
	}
	if got := Classify(ipv4TCP(300, 0x18, 1, 2)); got != ClassMedium {
		t.Fatalf("340 B TCP data → %v, want Medium", got)
	}
	if got := Classify(ipv4TCP(1260, 0x18, 1, 2)); got != ClassBulk {
		t.Fatalf("1300 B TCP data → %v, want Bulk", got)
	}
	// Control-like packets are Small whatever their length.
	if got := Classify(ipv4TCP(0, 0x10, 1, 2)); got != ClassSmall {
		t.Fatalf("bare ACK → %v, want Small", got)
	}
	if got := Classify(ipv4UDPPorts(600, 40000, 53)); got != ClassSmall {
		t.Fatalf("628 B DNS → %v, want Small", got)
	}
	if got := Classify(ipv4UDPPorts(600, 53, 40000)); got != ClassSmall {
		t.Fatalf("628 B DNS reply → %v, want Small", got)
	}
	if got := Classify(ipv4UDPPorts(600, 40000, 443)); got != ClassMedium {
		t.Fatalf("628 B QUIC → %v, want Medium", got)
	}
	icmp := ipv4UDP(500)
	icmp[9] = 1
	if got := Classify(icmp); got != ClassSmall {
		t.Fatalf("528 B ICMP → %v, want Small", got)
	}
	if got := Classify(ipv4UDPPorts(1200, 40000, 443)); got != ClassBulk {
		t.Fatalf("1228 B UDP → %v, want Bulk", got)
	}
}

// One class hands a worker a whole chunk, then moves on; classes do not
// share a cursor, so a bulk run never displaces small packets.
func TestStriperChunksPerClassIndependently(t *testing.T) {
	s := NewStriper(3)
	all := func(int) bool { return true }
	var bulk []int
	for i := 0; i < 2*DefaultChunks[ClassBulk]+1; i++ {
		bulk = append(bulk, s.Pick(ClassBulk, all))
	}
	for i, w := range bulk {
		want := (i/DefaultChunks[ClassBulk] + 1) % 3
		if w != want {
			t.Fatalf("bulk pick %d → worker %d, want %d", i, w, want)
		}
	}
	// Small cursor is untouched by the bulk run: its first chunk goes to
	// worker 1 (cursor starts at 0 with nothing remaining → advances).
	for i := 0; i < DefaultChunks[ClassSmall]; i++ {
		if w := s.Pick(ClassSmall, all); w != 1 {
			t.Fatalf("small pick %d → worker %d, want 1", i, w)
		}
	}
	if w := s.Pick(ClassSmall, all); w != 2 {
		t.Fatalf("small chunk did not advance: %d", w)
	}
}

func TestStriperSkipsDeadWorkers(t *testing.T) {
	s := NewStriper(4)
	dead1 := func(w int) bool { return w != 1 }
	seen := map[int]int{}
	for i := 0; i < 4*DefaultChunks[ClassMedium]; i++ {
		seen[s.Pick(ClassMedium, dead1)]++
	}
	if seen[1] != 0 {
		t.Fatalf("dead worker 1 was picked %d times", seen[1])
	}
	if seen[0] == 0 || seen[2] == 0 || seen[3] == 0 {
		t.Fatalf("live workers not all used: %v", seen)
	}
	// A worker dying mid-chunk hands the rest of the chunk over.
	s = NewStriper(2)
	all := func(int) bool { return true }
	first := s.Pick(ClassBulk, all)
	only := func(w int) bool { return w != first }
	if w := s.Pick(ClassBulk, only); w == first {
		t.Fatal("kept sending to a worker that died mid-chunk")
	}
	if w := s.Pick(ClassBulk, func(int) bool { return false }); w != -1 {
		t.Fatalf("no live worker must return -1, got %d", w)
	}
}

func TestStriperSetChunksTakesEffect(t *testing.T) {
	s := NewStriper(3)
	s.SetChunks([3]int{1, 0, 2}) // small 1, medium unchanged, bulk 2
	all := func(int) bool { return true }
	if a, b := s.Pick(ClassSmall, all), s.Pick(ClassSmall, all); a == b {
		t.Fatalf("small chunk 1 must alternate workers, got %d %d", a, b)
	}
	if a, b, c := s.Pick(ClassBulk, all), s.Pick(ClassBulk, all), s.Pick(ClassBulk, all); a != b || b == c {
		t.Fatalf("bulk chunk 2: got %d %d %d", a, b, c)
	}
	picks := map[int]bool{}
	for i := 0; i < DefaultChunks[ClassMedium]; i++ {
		picks[s.Pick(ClassMedium, all)] = true
	}
	if len(picks) != 1 {
		t.Fatalf("medium chunk must stay at the default %d, saw %d workers", DefaultChunks[ClassMedium], len(picks))
	}
}

func TestStriperResizeClampsCursors(t *testing.T) {
	s := NewStriper(4)
	all := func(int) bool { return true }
	for i := 0; i < 3*DefaultChunks[ClassSmall]; i++ {
		s.Pick(ClassSmall, all) // cursor now on worker 3
	}
	s.Resize(2)
	if w := s.Pick(ClassSmall, all); w < 0 || w > 1 {
		t.Fatalf("after Resize(2) picked worker %d", w)
	}
}

// The duplicate never rides the worker that carried the original, only a
// ready one, and it rotates so the copies spread across the pool.
func TestSecondWorkerIsAnotherReadyWorker(t *testing.T) {
	c := &Client{workers: make([]*worker, 4)}
	for i := range c.workers {
		c.workers[i] = &worker{id: i + 1}
	}
	for _, w := range c.workers {
		w.ready.Store(true)
	}
	c.workers[2].ready.Store(false)
	seen := map[int]int{}
	for i := 0; i < 12; i++ {
		w2 := c.secondWorker(0)
		if w2 == 0 {
			t.Fatal("duplicate sent through the same worker as the original")
		}
		if w2 == 2 {
			t.Fatal("duplicate sent through a worker that is not ready")
		}
		seen[w2]++
	}
	if seen[1] == 0 || seen[3] == 0 {
		t.Fatalf("copies did not rotate over the ready workers: %v", seen)
	}
	c.workers[1].ready.Store(false)
	c.workers[3].ready.Store(false)
	if w2 := c.secondWorker(0); w2 != -1 {
		t.Fatalf("with no other ready worker expected -1, got %d", w2)
	}
}

// The bulk default is a MEASURED number (tcp9, 2026-09-04): 64 beat 32 by
// 20–25 % at 4–8 flows and 128 turned down. Anyone moving it should be
// moving it with a palindrome in hand, so the value is pinned here.
func TestBulkChunkDefaultIsTheMeasuredOne(t *testing.T) {
	if DefaultChunks != [numClasses]int{4, 16, 64} {
		t.Fatalf("DefaultChunks = %v; 4/16/64 is the measured default", DefaultChunks)
	}
}
