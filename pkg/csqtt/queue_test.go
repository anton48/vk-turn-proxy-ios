// SPDX-License-Identifier: MIT

package csqtt

// The bounded write queue (queue.go): a stuck relay holds its own queue and
// nothing else; a full queue drops, never waits and never moves a packet to
// another worker; what was queued under a session that ended is not written
// through its replacement; the packet is copied at the enqueue; the writers
// end with the client; and with the queue off the old synchronous write is
// what runs.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
)

// gatedConn is a relay socket whose WriteTo can be made to block — the shape
// of a TCP relay that stopped taking bytes, its socket buffer full. A writer
// that enters the block announces itself on entered; unblock lets it through
// to the real write, Close fails it, as closing a real socket does. Every
// payload the real write took is kept, so a test can see what went out.
type gatedConn struct {
	net.PacketConn
	block   atomic.Bool
	closed  atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	written [][]byte
}

func newGatedConn(pc net.PacketConn) *gatedConn {
	return &gatedConn{PacketConn: pc, entered: make(chan struct{}, 256), release: make(chan struct{})}
}

func (g *gatedConn) WriteTo(p []byte, to net.Addr) (int, error) {
	if g.block.Load() {
		select {
		case g.entered <- struct{}{}:
		default:
		}
		<-g.release
		if g.closed.Load() {
			return 0, errors.New("gated relay: closed while the write was blocked")
		}
	}
	g.mu.Lock()
	g.written = append(g.written, append([]byte(nil), p...))
	g.mu.Unlock()
	return g.PacketConn.WriteTo(p, to)
}

func (g *gatedConn) unblock() {
	g.block.Store(false)
	g.once.Do(func() { close(g.release) })
}

func (g *gatedConn) Close() error {
	g.closed.Store(true)
	g.once.Do(func() { close(g.release) })
	return g.PacketConn.Close()
}

func (g *gatedConn) wires() [][]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]byte(nil), g.written...)
}

// gatedRelays replaces DialRelay with loopback relays that can be gated, in
// dial order: with N workers the first N dials are workers 1..N (Dial starts
// worker 1 alone and the rest after its TUNCONF), and a restarted worker's
// new allocation is the next dial.
type gatedRelays struct {
	mu    sync.Mutex
	conns []*gatedConn
}

func installGatedRelays(t *testing.T) *gatedRelays {
	t.Helper()
	g := &gatedRelays{}
	prev := dialRelay
	dialRelay = func(_ TURNCredentials, _ *net.UDPAddr, _ string, _ logging.LogLevel, allocated func()) (*Relay, error) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		gc := newGatedConn(uc)
		g.mu.Lock()
		g.conns = append(g.conns, gc)
		g.mu.Unlock()
		if allocated != nil {
			allocated()
		}
		return &Relay{Conn: gc, Local: gc.LocalAddr(), close: func() { gc.Close() }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
	return g
}

func (g *gatedRelays) conn(i int) *gatedConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i < len(g.conns) {
		return g.conns[i]
	}
	return nil
}

func (g *gatedRelays) dials() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.conns)
}

// bulkPacket is an IPv4/UDP packet of n bytes (class Bulk from 1000), with
// a tag in its payload so that echoes can be told apart. Unframed: the
// fake server echoes data as it came.
func bulkPacket(n int, tag byte) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	pkt[9] = 17
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 40001)
	for i := 28; i < n; i++ {
		pkt[i] = tag
	}
	return pkt
}

// readEchoes reads what the fake server echoed until `want` says it has seen
// enough or the deadline passes.
func readEchoes(t *testing.T, c *Client, d time.Duration, want func(p []byte) bool) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for {
		p, err := c.ReadPacket(ctx)
		if err != nil {
			return false
		}
		if want(p) {
			return true
		}
	}
}

// writeWithin is WritePacket with a deadline: on a path that writes
// synchronously behind a blocked relay the call never returns, and a test
// must say so rather than hang.
func writeWithin(t *testing.T, c *Client, pkt []byte, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.WritePacket(pkt) }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatal("WritePacket did not return: the caller stood behind a blocked relay")
		return nil
	}
}

func writeLoopGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "(*worker).writeLoop(")
}

// ONE relay that stopped taking bytes must not hold the TUN pump — the one
// caller of WritePacket — and with it every other worker. Before the queue,
// WritePacket wrote synchronously under w.mu and the pump stood behind the
// blocked write until the liveness rule restarted that worker.
func TestAStuckRelayHoldsOnlyItsOwnQueue(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteQueue = DefaultWriteQueue
	c := dialReady(t, cfg)
	defer c.Close()
	stuck := relays.conn(1) // worker 2's relay
	stuck.block.Store(true)

	pkt := bulkPacket(1200, 0x11)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 400; i++ {
			_ = c.WritePacket(pkt) // a full queue refuses; a refusal is not a wait
		}
	}()
	select {
	case <-stuck.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no packet reached the stuck relay's writer — the stall was never provoked")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("one stuck relay held the TUN pump: WritePacket did not return")
	}
	if !readEchoes(t, c, 3*time.Second, func(p []byte) bool { return bytes.Equal(p, pkt) }) {
		t.Fatal("the healthy relay stopped delivering while its neighbour was stuck")
	}
	st := c.Stats()
	if st.Workers[1].Queued > DefaultWriteQueue || st.Queued > 2*DefaultWriteQueue {
		t.Fatalf("a queue past its depth: %+v", st.Workers)
	}
	t0 := time.Now()
	c.Close()
	if took := time.Since(t0); took > closeDisconnectBudget+closeJoinBudget+time.Second {
		t.Fatalf("Close took %s behind a stuck writer", took)
	}
}

// A full queue DROPS the packet and says so — never waits (the wait is what
// held the whole uplink), never grows past its depth.
func TestAFullQueueDropsInsteadOfWaitingAndSaysSo(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteQueue = 8
	c := dialReady(t, cfg)
	defer c.Close()
	stuck := relays.conn(0)
	stuck.block.Store(true)

	pkt := bulkPacket(1200, 0x22)
	n := 2 * DefaultChunks[ClassBulk] // past the first chunk's end: the second must find the queue without room where it begins
	type outcome struct{ accepted, refused, other int }
	res := make(chan outcome, 1)
	go func() {
		var o outcome
		for i := 0; i < n; i++ {
			switch err := c.WritePacket(pkt); {
			case err == nil:
				o.accepted++
			case errors.Is(err, errQueueFull):
				o.refused++
			default:
				o.other++
			}
		}
		res <- o
	}()
	var o outcome
	select {
	case o = <-res:
	case <-time.After(3 * time.Second):
		t.Fatal("WritePacket waited on a full queue")
	}
	// One packet is in the blocked write, the depth are queued, the rest are
	// refused — inside the first chunk by the queue, and where the second
	// chunk begins by the striper finding no room (a refusal, not "no worker").
	if o.other != 0 || o.accepted > cfg.WriteQueue+1 || o.refused < n-cfg.WriteQueue-1 {
		t.Fatalf("%d packets into a stuck worker with a queue of %d: accepted %d, refused %d, other %d", n, cfg.WriteQueue, o.accepted, o.refused, o.other)
	}
	st := c.Stats()
	if st.QueueFull != int64(o.refused) {
		t.Fatalf("QueueFull %d, refused %d — every refusal is counted", st.QueueFull, o.refused)
	}
	if st.Workers[0].Queued > cfg.WriteQueue {
		t.Fatalf("queued %d > depth %d", st.Workers[0].Queued, cfg.WriteQueue)
	}
}

// Where a chunk BEGINS, a worker whose queue has no room is passed over —
// as a dead one is; INSIDE a chunk the room is not asked, so the chunk stays
// on its worker (the queue drops what it cannot take; the schedule never
// moves a flow's packets onto another allocation). And PickRoom with no room
// predicate is Pick, to the packet.
func TestNoRoomIsPassedOverWhereAChunkBeginsAndNeverInsideOne(t *testing.T) {
	all := func(int) bool { return true }
	bulk := DefaultChunks[ClassBulk]

	// Worker 1 has no room: every chunk boundary picks worker 0.
	s := NewStriper(2)
	noRoom := map[int]bool{1: true}
	room := func(i int) bool { return !noRoom[i] }
	for i := 0; i < 3*bulk; i++ {
		if w := s.PickRoom(ClassBulk, all, room); w != 0 {
			t.Fatalf("pick %d went to worker %d, whose queue has no room, at a chunk boundary", i, w)
		}
	}

	// Mid-chunk the room is not asked: a chunk on worker 1, its room gone ten
	// packets in — the chunk stays; the NEXT chunk goes to worker 0.
	s = NewStriper(2)
	noRoom = map[int]bool{}
	first := s.PickRoom(ClassBulk, all, room)
	for i := 1; i < 10; i++ {
		s.PickRoom(ClassBulk, all, room)
	}
	noRoom[first] = true
	for i := 10; i < bulk; i++ {
		if w := s.PickRoom(ClassBulk, all, room); w != first {
			t.Fatalf("pick %d of the chunk moved to worker %d when worker %d's queue lost its room mid-chunk", i, w, first)
		}
	}
	if w := s.PickRoom(ClassBulk, all, room); w == first {
		t.Fatalf("the next chunk began on worker %d, whose queue has no room", first)
	}

	// A DEAD worker mid-chunk still hands the rest to a live one, as before.
	s = NewStriper(2)
	noRoom = map[int]bool{}
	first = s.PickRoom(ClassBulk, all, room)
	alive := func(i int) bool { return i != first }
	if w := s.PickRoom(ClassBulk, alive, room); w == first {
		t.Fatal("a dead worker kept its chunk")
	}

	// No room predicate: the schedule is Pick's exactly.
	a, b := NewStriper(3), NewStriper(3)
	for i := 0; i < 1000; i++ {
		class := PacketClass(i % int(numClasses))
		al := func(w int) bool { return w != (i/7)%3 }
		if a.Pick(class, al) != b.PickRoom(class, al, nil) {
			t.Fatalf("PickRoom without a room predicate differs from Pick at pick %d", i)
		}
	}
}

// The room a chunk needs where it begins is the chunk, or half the queue
// when the chunk is larger; and the queue is at least the bulk chunk deep,
// so a chunk that starts on an empty queue fits whole.
func TestTheRoomAChunkNeedsIsBoundedByHalfTheQueue(t *testing.T) {
	for _, tc := range []struct{ chunk, depth, want int }{
		{4, 64, 4}, {16, 64, 16}, {64, 64, 32}, {64, 8, 4}, {1, 2, 1},
	} {
		if got := queueRoom(tc.chunk, tc.depth); got != tc.want {
			t.Errorf("queueRoom(%d, %d) = %d, want %d", tc.chunk, tc.depth, got, tc.want)
		}
	}
	if DefaultWriteQueue < DefaultChunks[ClassBulk] {
		t.Fatalf("DefaultWriteQueue %d < the bulk chunk %d: a bulk chunk could never start on a queue with room for it", DefaultWriteQueue, DefaultChunks[ClassBulk])
	}
}

// A worker whose queue has no room for a chunk is passed over where the
// next chunks begin: worker 2's writer is held (its queue fills to one slot
// short of the depth), and from then on every chunk begins on worker 1 —
// nothing more is handed to worker 2, nothing more is refused there. The
// room a bulk chunk needs is half the queue, not one slot.
func TestAWorkerWithAFullQueueIsPassedOverWhereAChunkBegins(t *testing.T) {
	srv := newFakeServer(t)
	installGatedRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteQueue = DefaultWriteQueue
	held := make(chan struct{})
	release := make(chan struct{})
	var holds atomic.Int32
	hook := func(w *worker) {
		if w.id == 2 && holds.Add(1) == 1 { // worker 2's writer, on its first packet
			close(held)
			<-release
		}
	}
	writeLoopTook.Store(&hook)
	t.Cleanup(func() { writeLoopTook.Store(nil); close(release) })
	c := dialReady(t, cfg)
	defer c.Close()

	pkt := bulkPacket(1200, 0x33)
	bulk := DefaultChunks[ClassBulk]
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5*bulk; i++ { // the first chunk lands on worker 2 and fills its queue but one slot; the next four must not
			_ = c.WritePacket(pkt)
		}
	}()
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("worker 2's writer never took a packet: the first chunk did not land there")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("WritePacket did not return")
	}
	w2 := c.Stats().Workers[1]
	if w2.Queued != DefaultWriteQueue-1 {
		t.Fatalf("worker 2 holds %d, want %d: the first chunk did not fill its queue to one slot short", w2.Queued, DefaultWriteQueue-1)
	}
	if w2.QueueFull != 0 {
		t.Fatalf("%d packets were handed to worker 2 and refused after its queue had no room for a chunk: a boundary began a chunk there", w2.QueueFull)
	}
}

// What was queued under a session is never written through its replacement.
// The writer that holds a packet of the old session across the restart is the
// case: descheduled (an iOS freeze in the middle of a restart), it wakes with
// the new allocation installed — and the packet, seconds or minutes old, is
// dropped as stale, never written to the new relay.
func TestAQueuedPacketNeverGoesOutThroughAReplacementAllocation(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteQueue = DefaultWriteQueue
	held := make(chan struct{})
	release := make(chan struct{})
	var holds atomic.Int32
	hook := func(*worker) {
		if holds.Add(1) == 1 { // the first packet the writer takes: held across the restart
			close(held)
			<-release
		}
	}
	writeLoopTook.Store(&hook)
	t.Cleanup(func() { writeLoopTook.Store(nil) })
	c := dialReady(t, cfg)
	defer c.Close()

	p1, p3 := bulkPacket(1200, 0x41), bulkPacket(1200, 0x43)
	if err := c.WritePacket(p1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("the writer did not take the packet")
	}
	c.workers[0].restart("test: the relay is dead")
	waitFor(t, "the worker on a new allocation", func() bool {
		st := c.Stats()
		return relays.dials() == 2 && st.Restarts == 1 && st.Ready == 1
	})
	close(release) // the writer wakes with the old packet in hand and the new relay installed
	if err := c.WritePacket(p3); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	if !readEchoes(t, c, 3*time.Second, func(p []byte) bool { return bytes.Equal(p, p3) }) {
		t.Fatal("the packet queued under the new session did not go out")
	}
	key, err := DeriveKey(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	second := relays.conn(1)
	sawP3 := false
	for _, wire := range second.wires() {
		if !IsRTP(wire) {
			continue
		}
		plain, _, err := cipher.Unwrap(ModeAudio, wire)
		if err != nil {
			continue
		}
		if bytes.Equal(plain, p1) {
			t.Fatal("a packet queued under the dead allocation went out through its replacement")
		}
		if bytes.Equal(plain, p3) {
			sawP3 = true
		}
	}
	if !sawP3 {
		t.Fatal("the new allocation carried no data — the check saw nothing")
	}
	if st := c.Stats(); st.QueueStale != 1 || st.WriteErrs != 0 {
		t.Fatalf("stale %d (want 1: the old session's packet), write errors %d (want 0)", st.QueueStale, st.WriteErrs)
	}
}

// The queue holds a COPY: the TUN pump reuses its read buffer, the CQF1 frame
// lives in the worker's frameBuf, and a queued packet must not change under
// the queue's feet.
func TestTheQueueCopiesThePacket(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteQueue = DefaultWriteQueue
	c := dialReady(t, cfg)
	defer c.Close()
	gate := relays.conn(0)
	gate.block.Store(true)

	p1 := bulkPacket(1200, 0x51)
	p2 := bulkPacket(1200, 0x52)
	original := append([]byte(nil), p2...)
	if err := writeWithin(t, c, p1, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the writer did not enter the blocked write")
	}
	if err := writeWithin(t, c, p2, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 28; i < len(p2); i++ { // the caller reuses its buffer
		p2[i] = 0xee
	}
	gate.unblock()
	if !readEchoes(t, c, 3*time.Second, func(p []byte) bool { return bytes.Equal(p, original) }) {
		t.Fatal("the queued packet went out with the caller's later bytes: the queue aliased the caller's buffer")
	}
}

// The writers end with the client — a writer blocked in a relay's write is
// freed by the relay's close and leaves — and Close stays inside its budget.
func TestCloseEndsTheWritersEvenBehindAStuckRelay(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteQueue = DefaultWriteQueue
	c := dialReady(t, cfg)
	if got := writeLoopGoroutines(); got != 2 {
		t.Fatalf("%d writer goroutine(s) for 2 workers", got)
	}
	stuck := relays.conn(1)
	stuck.block.Store(true)
	pkt := bulkPacket(1200, 0x61)
	for i := 0; i < 2*DefaultChunks[ClassBulk]; i++ {
		_ = c.WritePacket(pkt)
	}
	select {
	case <-stuck.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the writer did not enter the blocked write")
	}
	t0 := time.Now()
	c.Close()
	if took := time.Since(t0); took > closeDisconnectBudget+closeJoinBudget+time.Second {
		t.Fatalf("Close took %s", took)
	}
	deadline := time.After(2 * time.Second)
	for writeLoopGoroutines() != 0 {
		select {
		case <-deadline:
			t.Fatalf("%d writer goroutine(s) still running after Close", writeLoopGoroutines())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if st := c.Stats(); st.WriteErrs < 1 {
		t.Fatal("the blocked write that the close failed was not counted")
	}
}

// With the queue OFF — WriteQueue 0, the default — nothing changes: the
// write is synchronous, a relay that stops taking bytes holds WritePacket,
// and no writer goroutine exists. The rollback is the old path, to the byte.
func TestWithTheQueueOffWritePacketWaitsForTheRelay(t *testing.T) {
	srv := newFakeServer(t)
	relays := installGatedRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	if cfg.WriteQueue != 0 {
		t.Fatal("the test's config is not the default")
	}
	c := dialReady(t, cfg)
	defer c.Close()
	if got := writeLoopGoroutines(); got != 0 {
		t.Fatalf("%d writer goroutine(s) with the queue off", got)
	}
	gate := relays.conn(0)
	gate.block.Store(true)
	pkt := bulkPacket(1200, 0x71)
	done := make(chan error, 1)
	go func() { done <- c.WritePacket(pkt) }()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the write did not reach the relay")
	}
	select {
	case err := <-done:
		t.Fatalf("with the queue off WritePacket returned (%v) while the relay held the write", err)
	case <-time.After(300 * time.Millisecond):
	}
	gate.unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the write failed once the relay took it: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WritePacket did not return once the relay took the write")
	}
	if st := c.Stats(); st.Queued != 0 || st.QueueFull != 0 {
		t.Fatalf("queue counters moved with the queue off: %+v", st)
	}
}
