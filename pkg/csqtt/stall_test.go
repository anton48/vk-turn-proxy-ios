// SPDX-License-Identifier: MIT

package csqtt

// The bounded relay write (stall.go). The TUN pump writes IN ORDER across the
// workers: a later chunk never overtakes an earlier one on its way out, which is
// what the csqtt server's 12-ms CQF1 gap window lives on — build 437's write
// queue let worker B's chunk leave while worker A's writer held the chunk
// before it, and a writer delayed 30 ms lost 64 of 65 packets after reassembly
// (the user's review, 2026-09-23, 3 of 3). A relay that takes no bytes within
// the bound is a STALL: the packet is dropped and counted, the worker is not
// ready at once and restarted, the caller is free. A plain write error is not
// a stall. The deadline is cleared behind every write and restored for a close
// under way. With the bound off the write waits as long as the relay makes it.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// writeRecord is what left through every relay of a test, in the order the
// writes ENDED — each with the moment it began and the moment it ended.
type writeRecord struct {
	mu     sync.Mutex
	writes []recordedWrite
}

type recordedWrite struct {
	conn       int // the dial's index
	start, end time.Time
	wire       []byte
	idx        uint32 // filled in by decoded: the packet's index
}

func (r *writeRecord) add(conn int, start, end time.Time, wire []byte) {
	r.mu.Lock()
	r.writes = append(r.writes, recordedWrite{conn: conn, start: start, end: end, wire: append([]byte(nil), wire...)})
	r.mu.Unlock()
}

// decoded returns the test's TCP packets (tcpPacket) among the writes, decrypted
// and sorted by their index; control writes and keepalives are left out.
func (r *writeRecord) decoded(t *testing.T) []recordedWrite {
	t.Helper()
	key, err := DeriveKey(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	all := append([]recordedWrite(nil), r.writes...)
	r.mu.Unlock()
	var out []recordedWrite
	for _, w := range all {
		if !IsRTP(w.wire) {
			continue
		}
		plain, _, err := cipher.Unwrap(ModeAudio, w.wire)
		if err != nil {
			continue
		}
		idx, ok := tcpIndex(FramePayload(plain))
		if !ok {
			continue
		}
		w.idx = idx
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].idx < out[j].idx })
	return out
}

// stallConn is a relay socket that does what a TCP relay's does: a write can be
// DELAYED (a relay slow to take bytes), BLOCKED until the test releases it, the
// conn is closed or a write deadline passes (a relay taking none), or FAILED
// once with a plain error. It honours SetWriteDeadline as a real socket does — a
// deadline set before or during a blocked write ends it, an expired one fails
// the next write at once — serialises its writers as a socket's fd lock does (a
// second write waits for the first to return, and only then reads the deadline
// as it stands), and records every write into the test's record.
type stallConn struct {
	net.PacketConn
	id  int
	rec *writeRecord
	wmu sync.Mutex // one write at a time, as net.Conn's fd lock: the second reads the deadline the first left behind

	delayFirst time.Duration // the first write sleeps this long before the real write
	delayEach  time.Duration // every write sleeps this long
	firstDone  atomic.Bool
	block      atomic.Bool
	failNext   atomic.Bool
	failErr    error         // what the next failed write returns; nil = a plain error
	entered    chan struct{} // a write that blocked announces itself
	release    chan struct{}
	closed     chan struct{}
	relOnce    sync.Once
	closeOnce  sync.Once

	dmu             sync.Mutex
	deadline        time.Time
	deadlineChanged chan struct{}
	deadlineSets    int // SetWriteDeadline calls with a non-zero time
	deadlineClears  int // … with the zero time
}

func newStallConn(pc net.PacketConn, id int, rec *writeRecord) *stallConn {
	return &stallConn{PacketConn: pc, id: id, rec: rec,
		entered: make(chan struct{}, 256), release: make(chan struct{}), closed: make(chan struct{}),
		deadlineChanged: make(chan struct{})}
}

func (s *stallConn) SetWriteDeadline(t time.Time) error {
	s.dmu.Lock()
	s.deadline = t
	if t.IsZero() {
		s.deadlineClears++
	} else {
		s.deadlineSets++
	}
	close(s.deadlineChanged)
	s.deadlineChanged = make(chan struct{})
	s.dmu.Unlock()
	return nil
}

func (s *stallConn) deadlines() (deadline time.Time, sets, clears int) {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.deadline, s.deadlineSets, s.deadlineClears
}

// wait is the blocked write's wait: released, closed or timed out.
func (s *stallConn) wait() error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	for {
		s.dmu.Lock()
		deadline, changed := s.deadline, s.deadlineChanged
		s.dmu.Unlock()
		var expire <-chan time.Time
		if !deadline.IsZero() {
			expire = time.After(time.Until(deadline))
		}
		select {
		case <-s.release:
			return nil
		case <-s.closed:
			return net.ErrClosed
		case <-expire:
			return os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

func (s *stallConn) WriteTo(p []byte, to net.Addr) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	start := time.Now()
	if s.failNext.CompareAndSwap(true, false) {
		if s.failErr != nil {
			return 0, s.failErr
		}
		return 0, errors.New("stall fixture: a plain write error")
	}
	if d := s.delayEach; d > 0 {
		time.Sleep(d)
	}
	if s.delayFirst > 0 && s.firstDone.CompareAndSwap(false, true) {
		time.Sleep(s.delayFirst)
	}
	if s.block.Load() {
		if err := s.wait(); err != nil {
			return 0, err
		}
	} else if dl, _, _ := s.deadlines(); !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded // an expired deadline fails the write at once, as a socket's does
	}
	n, err := s.PacketConn.WriteTo(p, to)
	s.rec.add(s.id, start, time.Now(), p)
	return n, err
}

func (s *stallConn) unblock() {
	s.block.Store(false)
	s.relOnce.Do(func() { close(s.release) })
}

func (s *stallConn) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return s.PacketConn.Close()
}

// stallRelays replaces DialRelay with loopback relays over stallConns, in dial
// order: with N workers the first N dials are workers 1..N (Dial starts worker
// 1 alone and the rest after its TUNCONF), and a restarted worker's new
// allocation is the next dial. The relay's close is the production one over
// the fixture: the deallocate through the control socket under its budget, then
// the socket.
type stallRelays struct {
	mu    sync.Mutex
	conns []*stallConn
	rec   *writeRecord
}

func installStallRelays(t *testing.T) *stallRelays {
	t.Helper()
	g := &stallRelays{rec: &writeRecord{}}
	prev := dialRelay
	dialRelay = func(_ TURNCredentials, _ *net.UDPAddr, _ string, _ logging.LogLevel, allocated func()) (*Relay, error) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		g.mu.Lock()
		sc := newStallConn(uc, len(g.conns), g.rec)
		g.conns = append(g.conns, sc)
		g.mu.Unlock()
		if allocated != nil {
			allocated()
		}
		return &Relay{Conn: sc, Local: sc.LocalAddr(), ctl: sc, close: func() { closeRelayBounded(sc, deallocating{sc}, nil) }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
	return g
}

func (g *stallRelays) nth(i int) *stallConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i < len(g.conns) {
		return g.conns[i]
	}
	return nil
}

func (g *stallRelays) dials() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.conns)
}

// tcpPacket is an IPv4/TCP segment of n bytes (class Bulk from 1000) carrying
// payload — so it is CQF1-framed — all of one flow, with its index at the start
// of the payload and a tag behind it. The fake server echoes data as it came.
func tcpPacket(n int, idx uint32) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 0, 0, 2})
	copy(pkt[16:20], []byte{10, 0, 0, 3})
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	pkt[32] = 5 << 4 // data offset 20
	pkt[33] = 0x18   // PSH|ACK
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	binary.BigEndian.PutUint32(pkt[40:44], idx)
	for i := 44; i < n; i++ {
		pkt[i] = 0x5a
	}
	return pkt
}

// tcpIndex reads the index a tcpPacket carries; false for anything else.
func tcpIndex(pkt []byte) (uint32, bool) {
	if len(pkt) < 45 || pkt[0] != 0x45 || pkt[9] != 6 || pkt[44] != 0x5a {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[40:44]), true
}

// writeWithin is WritePacket with a deadline: on a path that writes without a
// bound behind a blocked relay the call never returns, and a test must say so
// rather than hang.
func writeWithin(t *testing.T, c *Client, pkt []byte, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.WritePacket(pkt) }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("WritePacket did not return within %s: the caller stood behind a relay's write", d)
		return nil
	}
}

// readIndices reads what the fake server echoed — through the client's own
// reassembler, which applies the server's rule (a 12-ms gap window) — until
// `want` distinct packets have come back or the deadline passes.
func readIndices(t *testing.T, c *Client, want int, d time.Duration) map[uint32]bool {
	t.Helper()
	got := map[uint32]bool{}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for len(got) < want {
		p, err := c.ReadPacket(ctx)
		if err != nil {
			break
		}
		if idx, ok := tcpIndex(p); ok {
			got[idx] = true
		}
	}
	return got
}

// The pump's order IS the wire's order: a packet's write begins only after the
// write of the packet dispatched before it has ended, across workers — chunk
// k+1 on worker B never leaves while chunk k is still being written to worker
// A. The first-picked worker's relay is slow to take every packet; nothing may
// overtake it. Sabotage seen red: the write made asynchronous (returning before
// the relay took the bytes).
func TestChunksLeaveInTheOrderTheyAreDispatched(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	relays.nth(1).delayEach = time.Millisecond // worker 2 (the striper's first pick) is slow to take each packet

	n := 3 * DefaultChunks[ClassBulk]
	for i := 0; i < n; i++ {
		if err := writeWithin(t, c, tcpPacket(1200, uint32(i)), 3*time.Second); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	writes := relays.rec.decoded(t)
	if len(writes) != n {
		t.Fatalf("%d of %d packets went out", len(writes), n)
	}
	used := map[int]bool{}
	for i, w := range writes {
		used[w.conn] = true
		if uint32(i) != w.idx {
			t.Fatalf("packet %d missing from the wire (found %d)", i, w.idx)
		}
		if i > 0 && w.start.Before(writes[i-1].end) {
			t.Fatalf("packet %d (worker %d) began its write %s before packet %d (worker %d) had left: a later packet overtook an earlier one",
				w.idx, w.conn+1, writes[i-1].end.Sub(w.start), writes[i-1].idx, writes[i-1].conn+1)
		}
	}
	if len(used) != 2 {
		t.Fatalf("fixture: the chunks landed on %d worker(s), want both", len(used))
	}
}

// The user's stand (the review of 437): two workers, the production chunks,
// CQF1 framing, ONE writer 30 ms late with the first packet of its chunk — and
// the 65th packet, the next chunk's first, on the other worker. Through the
// reassembler — the client's own applies the server's 12-ms gap window to the
// echoes, which come back in the order the writes went out — every packet is
// delivered. With 437's queue worker 1's packet left at once, the window
// released it 12 ms later, and the chunk behind it was dropped as backward: 1
// of 65, 3 of 3.
func TestALaterChunkNeverOvertakesAnEarlierOneThroughCQF1(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	relays.nth(1).delayFirst = 30 * time.Millisecond // worker 2 takes the chunk's first packet 30 ms late

	n := DefaultChunks[ClassBulk] + 1
	for i := 0; i < n; i++ {
		if err := writeWithin(t, c, tcpPacket(1200, uint32(i)), 3*time.Second); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	got := readIndices(t, c, n, 2*time.Second)
	onSlow := 0
	for _, w := range relays.rec.decoded(t) {
		if w.conn == 1 {
			onSlow++
		}
	}
	if onSlow < n-1 {
		t.Fatalf("fixture: %d of the chunk's %d packets went through the delayed relay", onSlow, n-1)
	}
	if len(got) != n {
		t.Fatalf("%d of %d packets delivered after reassembly: a later chunk overtook the delayed one and the 12-ms gap window dropped it", len(got), n)
	}
}

// A relay that takes no bytes within the bound is a STALL: the caller is back
// within the bound with errWriteStalled, the packet is counted against that
// worker, the worker is not ready AT ONCE — the very next packet goes to its
// neighbour without a second wait — and it is restarted onto a fresh
// allocation. Sabotages seen red: no deadline set (the write never returns);
// the verdict not marking the worker (the next packet stalls on it again); no
// restart (no third dial); the stall not counted.
func TestAWriteTheRelayDoesNotTakeIsAStall(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteStall = 200 * time.Millisecond
	c := dialReady(t, cfg)
	defer c.Close()
	stuck := relays.nth(1) // worker 2, the striper's first pick
	stuck.block.Store(true)

	t0 := time.Now()
	err := writeWithin(t, c, tcpPacket(1200, 1), cfg.WriteStall+3*time.Second)
	took := time.Since(t0)
	if !errors.Is(err, errWriteStalled) {
		t.Fatalf("WritePacket returned %v after %s, want the stall", err, took)
	}
	if took < cfg.WriteStall/2 || took > cfg.WriteStall+time.Second {
		t.Fatalf("the stall was judged after %s, the bound is %s", took, cfg.WriteStall)
	}
	if c.workers[1].ready.Load() {
		t.Fatal("the stalled worker still reads ready: the next chunk would begin on it and stall again")
	}
	t1 := time.Now()
	if err := writeWithin(t, c, tcpPacket(1200, 2), 3*time.Second); err != nil {
		t.Fatalf("the packet after the stall: %v", err)
	}
	if d := time.Since(t1); d > cfg.WriteStall/2 {
		t.Fatalf("the packet after the stall took %s: it waited on the stalled relay again", d)
	}
	// A second packet 20 ms behind the first: the flow's sequence has a hole
	// where the dropped packet was, and the reassembler — the server's and
	// the client's alike — releases a gap only when the NEXT packet of the
	// flow arrives after the 12-ms window (frame.go: no timer of its own).
	time.Sleep(20 * time.Millisecond)
	if err := writeWithin(t, c, tcpPacket(1200, 3), 3*time.Second); err != nil {
		t.Fatalf("the second packet after the stall: %v", err)
	}
	if got := readIndices(t, c, 2, 2*time.Second); !got[2] || !got[3] {
		t.Fatalf("the packets after the stall were not delivered through the healthy worker: %v", got)
	}
	waitFor(t, "the stalled worker on a fresh allocation", func() bool {
		st := c.Stats()
		return relays.dials() == 3 && st.Restarts == 1 && st.Ready == 2
	})
	st := c.Stats()
	if st.WriteStalls != 1 || st.Workers[1].Stalls != 1 || st.Workers[0].Stalls != 0 {
		t.Fatalf("stalls: client %d, worker 2 %d, worker 1 %d — want 1, 1, 0", st.WriteStalls, st.Workers[1].Stalls, st.Workers[0].Stalls)
	}
}

// The deadline is set for the write and CLEARED behind it: pion's own writes on
// the control socket — the refreshes, the deallocate — must never meet a
// deadline that has passed. Every bounded write sets one and clears it, and a
// write made long after the last one succeeds. Sabotage seen red: the clear
// dropped (the write after the bound fails at once on the expired deadline).
func TestTheWriteDeadlineIsClearedBehindEveryWrite(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = 100 * time.Millisecond
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	if err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	dl, sets, clears := sc.deadlines()
	if sets == 0 {
		t.Fatal("a bounded write set no deadline")
	}
	if !dl.IsZero() || clears != sets {
		t.Fatalf("after the write the deadline stands at %v (%d set, %d cleared): pion's next write on this socket would meet it", dl, sets, clears)
	}
	time.Sleep(2 * cfg.WriteStall)
	if err := writeWithin(t, c, tcpPacket(1200, 2), 3*time.Second); err != nil {
		t.Fatalf("a write %s after the previous one failed: %v — an expired deadline was left on the socket", 2*cfg.WriteStall, err)
	}
	if st := c.Stats(); st.WriteStalls != 0 {
		t.Fatalf("stalls %d on a relay that took every byte", st.WriteStalls)
	}
}

// A write that ends while the relay's Close is under way restores the close's
// own deadline: the close set relayCloseWriteBudget first, the write's clear
// would wipe it, and the deallocate the close writes would then wait for ever
// on the stuck socket — the teardown, the liveness restart and Client.Close
// behind it. Sabotage seen red: the restore dropped (Close never returns).
func TestAWriteEndingUnderTheRelaysCloseKeepsTheCloseBounded(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.block.Store(true)
	written := make(chan error, 1)
	go func() { written <- c.WritePacket(tcpPacket(1200, 1)) }()
	select {
	case <-sc.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the write did not reach the relay")
	}
	relay := c.workers[0].relayRef.Load()
	closed := make(chan struct{})
	t0 := time.Now()
	go func() { relay.Close(); close(closed) }() // as the liveness restart and Client.Close do, from outside the write
	select {
	case <-written:
	case <-time.After(DefaultWriteStall + 2*time.Second):
		t.Fatal("the blocked write did not end under the close's deadline")
	}
	select {
	case <-closed:
	case <-time.After(relayCloseWriteBudget + DefaultWriteStall + 2*time.Second):
		t.Fatal("Relay.Close did not return: the write that ended under it cleared the close's deadline and the deallocate waits for ever")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget+DefaultWriteStall+time.Second {
		t.Fatalf("Relay.Close took %s", took)
	}
}

// A write that FAILS at once — a closed socket, ENOBUFS on a UDP socket — is not
// a stall: the error goes back to the caller as before, nothing is counted, the
// worker stays ready and is not restarted. Sabotage seen red: every write error
// read as a stall.
func TestAPlainWriteErrorIsNotAStall(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = 200 * time.Millisecond
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.failNext.Store(true)
	err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second)
	if err == nil || errors.Is(err, errWriteStalled) {
		t.Fatalf("WritePacket returned %v, want the plain error", err)
	}
	time.Sleep(2 * cfg.WriteStall)
	st := c.Stats()
	if st.WriteStalls != 0 || st.Ready != 1 || st.Restarts != 0 || relays.dials() != 1 {
		t.Fatalf("after a plain write error: stalls %d, ready %d, restarts %d, dials %d", st.WriteStalls, st.Ready, st.Restarts, relays.dials())
	}
}

// With the bound OFF — WriteStall 0, the package's default — nothing changes:
// no deadline is ever set, a relay that stops taking bytes holds WritePacket,
// and the counters stay at zero. The rollback is the old path, to the byte.
func TestWithTheBoundOffAWriteWaitsForTheRelay(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	if cfg.WriteStall != 0 {
		t.Fatal("the test's config is not the default")
	}
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.block.Store(true)
	done := make(chan error, 1)
	go func() { done <- c.WritePacket(tcpPacket(1200, 1)) }()
	select {
	case <-sc.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the write did not reach the relay")
	}
	select {
	case err := <-done:
		t.Fatalf("with the bound off WritePacket returned (%v) while the relay held the write", err)
	case <-time.After(300 * time.Millisecond):
	}
	sc.unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the write failed once the relay took it: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WritePacket did not return once the relay took the write")
	}
	if _, sets, _ := sc.deadlines(); sets != 0 {
		t.Fatalf("%d deadline(s) set with the bound off", sets)
	}
	if st := c.Stats(); st.WriteStalls != 0 || st.Workers[0].Stalls != 0 {
		t.Fatalf("stall counters moved with the bound off: %+v", st)
	}
}

// The bound sits above the deallocate's own budget and far below the liveness
// rule's silence: a stall is judged before the rule even asks.
func TestTheWriteBoundSitsBetweenTheCloseBudgetAndTheLivenessRule(t *testing.T) {
	if DefaultWriteStall <= relayCloseWriteBudget || DefaultWriteStall >= probeAfter {
		t.Fatalf("DefaultWriteStall %s: want above the close budget %s and below probeAfter %s", DefaultWriteStall, relayCloseWriteBudget, probeAfter)
	}
}

// ─── the real stack ────────────────────────────────────────────────────────

// loopbackTURN is a pion TURN server on loopback TCP that knows one long-term
// credential (u / pw in realm okcdn.ru). The server is closed only after its
// connections have released their allocations (pkg/proxy's fixture and its
// reason: pion/turn v5.0.2's Manager.Close races a permission's timer).
func loopbackTURN(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == "u" {
				return "u", key, true
			}
			return "", nil, false
		},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener:              ln,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n := srv.AllocationCount(); n != 0 {
			t.Errorf("loopbackTURN: %d allocation(s) still held as the server closes", n)
		}
		_ = srv.Close()
	})
	return ln.Addr().String()
}

// stallingTap forwards a TCP connection to the TURN server; once `stall` is
// closed it stops READING from the client, so the client's send buffer fills
// and its next write blocks — a relay that stopped taking bytes.
type stallingTap struct {
	ln    net.Listener
	to    string
	stall chan struct{}
	mu    sync.Mutex
	conns []net.Conn
}

func newStallingTap(t *testing.T, to string) *stallingTap {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tap := &stallingTap{ln: ln, to: to, stall: make(chan struct{})}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *stallingTap) serve() {
	for {
		c, err := tap.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp4", tap.to)
		if err != nil {
			_ = c.Close()
			return
		}
		tap.mu.Lock()
		tap.conns = append(tap.conns, c, up)
		tap.mu.Unlock()
		go func() { _, _ = io.Copy(c, up) }() // server → client, always
		go func() {                           // client → server, until the stall
			buf := make([]byte, 64<<10)
			for {
				select {
				case <-tap.stall:
					return
				default:
				}
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := up.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
	}
}

func (tap *stallingTap) close() {
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.conns {
		_ = c.Close()
	}
}

// On the production transport — a real pion allocation over TCP — the bound
// reaches the socket through pion's STUNConn and the timeout comes back
// through pion's write path as the stall: a relay that stops taking bytes ends
// the write at the bound, and the relay's Close still returns within its
// budgets afterwards. Sabotage seen red: DialRelay keeping no control socket on
// the Relay (the deadline lands on pion's stub and the write never returns).
func TestAStallReachesThroughPionOnTheTCPTransport(t *testing.T) {
	tap := newStallingTap(t, loopbackTURN(t))
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	relay, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: tap.ln.Addr().String()}, peer, "tcp", logging.LogLevelError, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	pkt := make([]byte, 1200)
	for i := 0; i < 5; i++ { // before the stall: the first write waits for the permission and the channel bind
		if err := relay.write(pkt, peer, 0); err != nil {
			t.Fatalf("write %d before the stall: %v", i, err)
		}
	}
	close(tap.stall) // the relay stops taking bytes
	const bound = 500 * time.Millisecond
	type outcome struct {
		err  error
		took time.Duration
		n    int
	}
	res := make(chan outcome, 1)
	go func() {
		var o outcome
		for o.n = 0; o.n < 40000; o.n++ { // ~48 MB, far past what the loopback absorbs
			t0 := time.Now()
			o.err = relay.write(pkt, peer, bound)
			o.took = time.Since(t0)
			if o.err != nil {
				break
			}
		}
		res <- o
	}()
	var o outcome
	select {
	case o = <-res:
	case <-time.After(bound + 10*time.Second):
		t.Fatal("the write into the stalled relay never returned: the bound did not reach the socket")
	}
	if !errors.Is(o.err, errWriteStalled) {
		t.Fatalf("after %d writes: %v (took %s), want the stall", o.n, o.err, o.took)
	}
	if o.took < bound/2 || o.took > bound+3*time.Second {
		t.Fatalf("the stall was judged after %s, the bound is %s", o.took, bound)
	}
	t0 := time.Now()
	relay.Close()
	if took := time.Since(t0); took > relayCloseWriteBudget+bound+2*time.Second {
		t.Fatalf("Relay.Close took %s behind the stalled write", took)
	}
}

// ─── the dead write (build 439) ────────────────────────────────────────────

// opErr wraps an errno the way the net package reports a socket's error:
// OpError → SyscallError → Errno.
func opErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "tcp", Err: &os.SyscallError{Syscall: op, Err: errno}}
}

// What ends a session and what does not: a reset, a broken pipe, the
// kernel's give-up and a closed socket are the connection gone; a moment's
// refusal (ENOBUFS, EAGAIN), a route that is away for now (the path-change
// hook's business), the bound's own timeout (a stall) and a plain error are
// not.
func TestConnGoneTellsADeadConnectionFromAMomentsRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		gone bool
	}{
		{"EPIPE", opErr("write", syscall.EPIPE), true},
		{"ECONNRESET", opErr("write", syscall.ECONNRESET), true},
		{"ECONNABORTED", opErr("write", syscall.ECONNABORTED), true},
		{"ENOTCONN", opErr("write", syscall.ENOTCONN), true},
		{"ETIMEDOUT", opErr("write", syscall.ETIMEDOUT), true},
		{"a closed socket", &net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}, true},
		{"a closed pipe", io.ErrClosedPipe, true},
		{"ENOBUFS", opErr("sendto", syscall.ENOBUFS), false},
		{"EAGAIN", opErr("write", syscall.EAGAIN), false},
		{"EHOSTUNREACH", opErr("write", syscall.EHOSTUNREACH), false},
		{"ENETUNREACH", opErr("write", syscall.ENETUNREACH), false},
		{"ENETDOWN", opErr("write", syscall.ENETDOWN), false},
		{"the bound's timeout", &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}, false},
		{"a plain error", errors.New("stall fixture: a plain write error"), false},
		{"nil", nil, false},
	} {
		if got := connGone(tc.err); got != tc.gone {
			t.Errorf("connGone(%s) = %v, want %v", tc.name, got, tc.gone)
		}
	}
}

// A write that finds the connection gone — a broken pipe, a reset — ENDS THE
// SESSION: the caller hears the write's own error (not a stall), the worker
// is not ready at once (the next packet goes to its neighbour without a
// wait), the write is counted, and the session ends with a FAILURE — the
// re-dial comes after the failure backoff, never at once. Before 439 the
// error went back to the bridge as a count and nothing else: the worker
// stayed ready and the striper fed the dead socket until the keepalive
// noticed, up to ten seconds later. Sabotages seen red: the verdict not
// consulted; the worker left ready; the session not ended; the counters
// dropped; the restart asked at once instead of failed.
func TestAWriteThatFindsTheConnectionGoneEndsTheSession(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	gone := relays.nth(1) // worker 2, the striper's first pick
	gone.failErr = opErr("write", syscall.EPIPE)
	gone.failNext.Store(true)

	t0 := time.Now()
	err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second)
	if err == nil || errors.Is(err, errWriteStalled) {
		t.Fatalf("WritePacket returned %v, want the write's own error", err)
	}
	if c.workers[1].ready.Load() {
		t.Fatal("the worker whose connection is gone still reads ready: the striper would feed the dead socket on")
	}
	t1 := time.Now()
	if err := writeWithin(t, c, tcpPacket(1200, 2), 3*time.Second); err != nil {
		t.Fatalf("the packet after the dead write: %v", err)
	}
	if d := time.Since(t1); d > 200*time.Millisecond {
		t.Fatalf("the packet after the dead write took %s", d)
	}
	waitFor(t, "the worker on a fresh allocation", func() bool {
		st := c.Stats()
		return relays.dials() == 3 && st.Restarts == 1 && st.Ready == 2
	})
	if took := time.Since(t0); took < restartBackoff {
		t.Fatalf("the worker re-dialled %s after the dead write: an asked restart, not a failure under its backoff", took)
	}
	st := c.Stats()
	if st.DeadWrites != 1 || st.Workers[1].DeadWrites != 1 || st.Workers[0].DeadWrites != 0 || st.WriteStalls != 0 {
		t.Fatalf("dead writes: client %d, worker 2 %d, worker 1 %d; stalls %d — want 1, 1, 0, 0", st.DeadWrites, st.Workers[1].DeadWrites, st.Workers[0].DeadWrites, st.WriteStalls)
	}
}

// A moment's refusal — ENOBUFS on a UDP socket, EAGAIN — is neither a stall
// nor the connection gone: the error goes back to the caller, the worker
// stays ready, nothing is counted, nothing restarts. Sabotage seen red: every
// errno read as the connection gone.
func TestAMomentsRefusalDoesNotEndTheSession(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.failErr = opErr("sendto", syscall.ENOBUFS)
	sc.failNext.Store(true)
	if err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second); err == nil {
		t.Fatal("the refused write returned no error")
	}
	time.Sleep(300 * time.Millisecond)
	st := c.Stats()
	if st.DeadWrites != 0 || st.WriteStalls != 0 || st.Ready != 1 || st.Restarts != 0 || relays.dials() != 1 || !c.workers[0].ready.Load() {
		t.Fatalf("after a moment's refusal: dead writes %d, stalls %d, ready %d, restarts %d, dials %d", st.DeadWrites, st.WriteStalls, st.Ready, st.Restarts, relays.dials())
	}
}

// The relay's OWN close — the teardown's, Client.Close's, the liveness
// restart's — fails a write under way with "closed": that is the close
// itself, not a dead connection found by the write; nothing is counted and
// no second ending is asked for. Sabotage seen red: the closing check dropped.
func TestTheRelaysOwnCloseIsNotADeadWrite(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	relay := c.workers[0].relayRef.Load()
	relay.closing.Store(true) // a Close under way, as Relay.Close marks it before anything else
	sc.failErr = &net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}
	sc.failNext.Store(true)
	if err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second); err == nil {
		t.Fatal("the write on the closing relay returned no error")
	}
	if st := c.Stats(); st.DeadWrites != 0 || st.Workers[0].DeadWrites != 0 {
		t.Fatalf("the relay's own close was counted as a dead write: %d", st.DeadWrites)
	}
	select {
	case err := <-c.workers[0].dead:
		t.Fatalf("the relay's own close asked the session to end: %v", err)
	default:
	}
}

// A PROBE's write that finds the connection gone ends the session too: the
// probe's error is otherwise dropped on the floor, and on the TCP transport a
// reset is noticed by a write and by nothing else. Sabotage seen red: the
// verdict reached from the pump's path alone.
func TestAProbesWriteThatFindsTheConnectionGoneEndsTheSession(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.failErr = opErr("write", syscall.ECONNRESET)
	sc.failNext.Store(true)
	c.WakeHealthCheck() // the probe's write, on its own goroutine
	waitFor(t, "the worker on a fresh allocation after the probe's dead write", func() bool {
		st := c.Stats()
		return relays.dials() == 2 && st.Restarts == 1 && st.Ready == 1
	})
	if st := c.Stats(); st.DeadWrites != 1 {
		t.Fatalf("dead writes %d, want 1", st.DeadWrites)
	}
}

// A dead-write signal left over from a session that has ended — a probe's
// write racing the teardown — must not end the NEXT session at its first
// step: the session drains the signal when it starts, as it drains an old
// kick. Sabotage seen red: the drain dropped (the fresh session ends at once).
func TestAStaleDeadSignalDoesNotEndTheNextSession(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	// The next session waits 300 ms in Creds — before its drain — so that the
	// stale signal lands in the window it is meant for: after the old serve
	// loop's exit and before the new session looks.
	var acquires atomic.Int32
	l := &lease{delay: func(int) time.Duration {
		if acquires.Add(1) >= 2 {
			return 300 * time.Millisecond
		}
		return 0
	}}
	cfg := testConfig(srv, 1, l.creds)
	c := dialReady(t, cfg)
	defer c.Close()
	w := c.workers[0]
	w.restart("test: an asked restart")
	waitFor(t, "the old session's teardown", func() bool { return !w.ready.Load() })
	select {
	case w.dead <- errors.New("stale: from the session that has ended"):
	default:
		t.Fatal("fixture: the dead channel was not empty")
	}
	waitFor(t, "the worker on a fresh allocation", func() bool {
		st := c.Stats()
		return relays.dials() == 2 && st.Restarts == 1 && st.Ready == 1
	})
	time.Sleep(1500 * time.Millisecond)
	if st := c.Stats(); st.Restarts != 1 || st.Ready != 1 || relays.dials() != 2 {
		t.Fatalf("the stale signal ended the fresh session: restarts %d, ready %d, dials %d", st.Restarts, st.Ready, relays.dials())
	}
}

// THE SOCKET'S WORD (the user's review of 439, 2026-09-23). Under the bound
// Relay.write re-labels the socket's error: the deadline's own expiry becomes
// errWriteStalled. net.Error's Timeout() is NOT the deadline's own word — a
// syscall.Errno answers it for ETIMEDOUT (the kernel's own give-up on the
// connection: a dead write) and for EAGAIN (a moment's refusal: nothing) as
// well — and 439 took it for one: under the bound ETIMEDOUT was a STALL (an
// asked restart at once, no failure backoff — a fresh allocation ≈4.5 ms
// after the error on the reviewer's stand; DeadWrites 0, WriteStalls 1) and
// EAGAIN restarted a worker that had nothing wrong with it; and the errno was
// formatted away (%v), so nothing downstream could tell. The isolated
// connGone table cannot see any of this: the error is re-labelled before it
// gets there. The tests below go through WritePacket with the bound ON, and
// through Relay.write row by row.

// The kernel's own give-up under the bound is a dead write — the caller hears
// ETIMEDOUT itself, the worker is not ready at once, the session ends with a
// failure and the re-dial waits the failure backoff — not a stall. Sabotages
// seen red: the deadline's word taken from net.Error's Timeout() again (439's
// isTimeout); the word looked for at the top level only.
func TestAKernelTimeoutUnderTheBoundIsADeadWriteNotAStall(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	gone := relays.nth(1) // worker 2, the striper's first pick
	gone.failErr = opErr("write", syscall.ETIMEDOUT)
	gone.failNext.Store(true)

	t0 := time.Now()
	err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second)
	if err == nil || errors.Is(err, errWriteStalled) || !errors.Is(err, syscall.ETIMEDOUT) {
		t.Fatalf("WritePacket returned %v, want the kernel's own ETIMEDOUT and not the stall", err)
	}
	if c.workers[1].ready.Load() {
		t.Fatal("the worker whose connection timed out still reads ready: the striper would feed the dead socket on")
	}
	t1 := time.Now()
	if err := writeWithin(t, c, tcpPacket(1200, 2), 3*time.Second); err != nil {
		t.Fatalf("the packet after the dead write: %v", err)
	}
	if d := time.Since(t1); d > 200*time.Millisecond {
		t.Fatalf("the packet after the dead write took %s", d)
	}
	waitFor(t, "the worker on a fresh allocation", func() bool {
		st := c.Stats()
		return relays.dials() == 3 && st.Restarts == 1 && st.Ready == 2
	})
	if took := time.Since(t0); took < restartBackoff {
		t.Fatalf("the worker re-dialled %s after the kernel's timeout: an asked restart — a stall's — not a failure under its backoff", took)
	}
	st := c.Stats()
	if st.DeadWrites != 1 || st.Workers[1].DeadWrites != 1 || st.WriteStalls != 0 || st.Workers[1].Stalls != 0 {
		t.Fatalf("dead writes %d (worker 2: %d), stalls %d (worker 2: %d) — want 1, 1, 0, 0", st.DeadWrites, st.Workers[1].DeadWrites, st.WriteStalls, st.Workers[1].Stalls)
	}
}

// A moment's refusal under the bound is neither a stall nor a dead write: the
// packet is dropped, the caller hears the socket's own EAGAIN, the worker
// stays ready and nothing restarts.
func TestAMomentsRefusalUnderTheBoundIsNeitherAStallNorADeadWrite(t *testing.T) {
	srv := newFakeServer(t)
	relays := installStallRelays(t)
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.WriteStall = DefaultWriteStall
	c := dialReady(t, cfg)
	defer c.Close()
	sc := relays.nth(0)
	sc.failErr = opErr("write", syscall.EAGAIN)
	sc.failNext.Store(true)
	err := writeWithin(t, c, tcpPacket(1200, 1), 3*time.Second)
	if err == nil || errors.Is(err, errWriteStalled) || !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("the refused write returned %v, want the socket's own EAGAIN and not the stall", err)
	}
	time.Sleep(300 * time.Millisecond)
	st := c.Stats()
	if st.DeadWrites != 0 || st.WriteStalls != 0 || st.Ready != 1 || st.Restarts != 0 || relays.dials() != 1 || !c.workers[0].ready.Load() {
		t.Fatalf("after a moment's refusal under the bound: dead writes %d, stalls %d, ready %d, restarts %d, dials %d", st.DeadWrites, st.WriteStalls, st.Ready, st.Restarts, relays.dials())
	}
}

// Relay.write's re-labelling, row by row: the stall is the deadline's own
// word — os.ErrDeadlineExceeded, bare or as the net package wraps it — and no
// other, and the stall KEEPS the socket's error inside (errors.Is sees it);
// the kernel's ETIMEDOUT, EAGAIN, EPIPE, ECONNRESET and a plain error come
// back as they are, whatever the bound; with the bound off nothing is
// re-labelled at all. Sabotages seen red: Timeout() as the word; the word at
// the top level only; the socket's error formatted away (%v) or dropped.
func TestTheStallIsTheDeadlinesOwnWordAndKeepsIt(t *testing.T) {
	deadlineWrapped := &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}
	plain := errors.New("stall fixture: a plain write error")
	rows := []struct {
		name      string
		fail      error // what the socket answers; nil with block = the deadline passes
		block     bool
		bound     time.Duration
		wantStall bool
		wantIs    error // the socket's own error, still inside
		wantGone  bool
	}{
		{"the deadline passes on a blocked write", nil, true, 50 * time.Millisecond, true, os.ErrDeadlineExceeded, false},
		{"the deadline's own word, bare", os.ErrDeadlineExceeded, false, time.Second, true, os.ErrDeadlineExceeded, false},
		{"the deadline's own word as the net package wraps it", deadlineWrapped, false, time.Second, true, os.ErrDeadlineExceeded, false},
		{"ETIMEDOUT, the kernel's own give-up", opErr("write", syscall.ETIMEDOUT), false, time.Second, false, syscall.ETIMEDOUT, true},
		{"EAGAIN, a moment's refusal", opErr("write", syscall.EAGAIN), false, time.Second, false, syscall.EAGAIN, false},
		{"EPIPE", opErr("write", syscall.EPIPE), false, time.Second, false, syscall.EPIPE, true},
		{"ECONNRESET", opErr("write", syscall.ECONNRESET), false, time.Second, false, syscall.ECONNRESET, true},
		{"a plain error", plain, false, time.Second, false, plain, false},
		{"ETIMEDOUT with the bound off", opErr("write", syscall.ETIMEDOUT), false, 0, false, syscall.ETIMEDOUT, true},
		{"the deadline's word with the bound off", deadlineWrapped, false, 0, false, os.ErrDeadlineExceeded, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			sc := newStallConn(uc, 0, &writeRecord{})
			defer sc.Close()
			r := &Relay{Conn: sc, Local: sc.LocalAddr(), ctl: sc}
			if row.fail != nil {
				sc.failErr = row.fail
				sc.failNext.Store(true)
			}
			sc.block.Store(row.block)
			err = r.write([]byte("x"), uc.LocalAddr(), row.bound)
			if err == nil {
				t.Fatal("the write returned no error")
			}
			if got := errors.Is(err, errWriteStalled); got != row.wantStall {
				t.Fatalf("a stall: %v, want %v (%v)", got, row.wantStall, err)
			}
			if !errors.Is(err, row.wantIs) {
				t.Fatalf("the socket's own word is gone: %v does not carry %v", err, row.wantIs)
			}
			if got := connGone(err); got != row.wantGone {
				t.Fatalf("connGone: %v, want %v (%v)", got, row.wantGone, err)
			}
		})
	}
}
