// SPDX-License-Identifier: MIT

package csqtt

// The worker's life against a fake csqtt server on UDP loopback — just
// enough of WIRE-3 for the lifecycle (GETCONF → TUNCONF, READY → READY_OK,
// DISCONNECT → OK:disconnected, data echoed back) with the relay replaced
// by a plain socket. What these check is the client's contract with the
// app: the credential lease, credentials outside the start gate, the
// identity on a path change, probes on wake, a bounded stop, the stats.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
)

const testPassword = "wire-password"

type getconfSeen struct {
	gen    string
	salt   string
	worker string
}

type fakeServer struct {
	t        *testing.T
	conn     *net.UDPConn
	Addr     *net.UDPAddr
	cipher   *Cipher
	wrapper  *Wrapper
	mu       sync.Mutex
	getconf  []getconfSeen
	readies  int
	discons  int
	withhold map[string]int // worker id → GETCONFs still to leave unanswered
	closed   chan struct{}
}

// withholdTUNCONF leaves the next n GETCONFs of a worker unanswered, so the
// worker sits in its GETCONF schedule.
func (s *fakeServer) withholdTUNCONF(worker string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.withhold == nil {
		s.withhold = map[string]int{}
	}
	s.withhold[worker] = n
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	key, err := DeriveKey(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := NewWrapper(cipher, ModeAudio)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, conn: conn, Addr: conn.LocalAddr().(*net.UDPAddr), cipher: cipher, wrapper: wrapper, closed: make(chan struct{})}
	go s.loop()
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) Close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
		s.conn.Close()
	}
}

func (s *fakeServer) reply(to net.Addr, plain string) {
	s.mu.Lock()
	wire, err := s.wrapper.Wrap(nil, []byte(plain))
	s.mu.Unlock()
	if err == nil {
		_, _ = s.conn.WriteTo(wire, to)
	}
}

func (s *fakeServer) loop() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		wire := buf[:n]
		if !IsRTP(wire) {
			continue
		}
		plain, _, err := s.cipher.Unwrap(ModeAudio, wire)
		if err != nil {
			continue
		}
		switch p := string(plain); {
		case strings.HasPrefix(p, "GETCONF:"):
			f := strings.Split(strings.TrimPrefix(p, "GETCONF:"), "|")
			answer := true
			if len(f) >= 6 {
				s.mu.Lock()
				s.getconf = append(s.getconf, getconfSeen{gen: f[3], salt: f[4], worker: f[5]})
				if s.withhold[f[5]] > 0 {
					s.withhold[f[5]]--
					answer = false
				}
				s.mu.Unlock()
			}
			if answer {
				s.reply(from, "TUNCONF:10.66.67.3:77.88.8.8:9000:stream-v2")
			}
		case p == ReadyRequest:
			s.mu.Lock()
			s.readies++
			s.mu.Unlock()
			s.reply(from, ReadyOK)
		case strings.HasPrefix(p, "DISCONNECT:"):
			s.mu.Lock()
			s.discons++
			s.mu.Unlock()
			s.reply(from, DisconnectedResponse)
		case IsIdleKeepalive(plain):
		default: // data: echo it back
			s.mu.Lock()
			wire, err := s.wrapper.Wrap(nil, plain)
			s.mu.Unlock()
			if err == nil {
				_, _ = s.conn.WriteTo(wire, from)
			}
		}
	}
}

func (s *fakeServer) counts() (getconfs, readies, discons int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.getconf), s.readies, s.discons
}

func (s *fakeServer) seen() []getconfSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]getconfSeen(nil), s.getconf...)
}

// loopbackRelay replaces DialRelay: a plain UDP socket toward the fake
// server. `hook` sees each dial (worker id from the credential's username)
// and may fail it.
func loopbackRelay(t *testing.T, hook func(creds TURNCredentials) error) {
	t.Helper()
	prev := dialRelay
	dialRelay = func(creds TURNCredentials, _ *net.UDPAddr, _ string, _ logging.LogLevel) (*Relay, error) {
		if hook != nil {
			if err := hook(creds); err != nil {
				return nil, err
			}
		}
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		return &Relay{Conn: uc, Local: uc.LocalAddr(), close: func() { uc.Close() }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
}

// lease counts what the pool would see: acquires, releases, live leases.
type lease struct {
	mu       sync.Mutex
	acquires int
	releases int
	delay    func(workerID int) time.Duration // optional slow mint
}

func (l *lease) creds(ctx context.Context, workerID int) (Credential, error) {
	if l.delay != nil {
		if d := l.delay(workerID); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return Credential{}, ctx.Err()
			}
		}
	}
	l.mu.Lock()
	l.acquires++
	l.mu.Unlock()
	return Credential{
		TURNCredentials: TURNCredentials{Username: "u", Password: "p", Address: "127.0.0.1:19302"},
		Release: func() {
			l.mu.Lock()
			l.releases++
			l.mu.Unlock()
		},
	}, nil
}

func (l *lease) get() (acquires, releases int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acquires, l.releases
}

func testConfig(srv *fakeServer, workers int, creds func(context.Context, int) (Credential, error)) Config {
	gen, salt := NewIdentity(0)
	return Config{
		Server: srv.Addr, Password: testPassword, DeviceID: "test-device",
		Generation: gen, Salt: salt, Workers: workers, Creds: creds,
		StartPacing: 5 * time.Millisecond, TURNLogLevel: logging.LogLevelError,
	}
}

func dialReady(t *testing.T, cfg Config) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	waitFor(t, "every worker ready", func() bool { return c.Stats().Ready == cfg.Workers })
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// Every successful Creds is released exactly once — when the session ends
// (a path change, Close) or at once when the allocation fails — and a
// failed Creds releases nothing. Sabotage seen red: the deferred release
// dropped (releases stay at zero).
func TestCredentialLeaseReleasedExactlyOncePerAcquire(t *testing.T) {
	srv := newFakeServer(t)
	var dials atomic.Int32
	loopbackRelay(t, func(TURNCredentials) error {
		if dials.Add(1) == 2 {
			return errors.New("relay allocate: injected failure") // the second allocation never comes up
		}
		return nil
	})
	l := &lease{}
	c := dialReady(t, testConfig(srv, 3, l.creds))

	acq, rel := l.get()
	if acq < 4 || rel != acq-3 {
		t.Fatalf("after start: acquires %d releases %d — want 3 live leases and every failed allocation released", acq, rel)
	}
	before, _, _ := srv.counts()
	c.OnPathChange()
	waitFor(t, "every worker re-announced after the path change", func() bool {
		g, _, _ := srv.counts()
		return g >= before+3 && c.Stats().Ready == 3
	})
	acq, rel = l.get()
	if rel != acq-3 {
		t.Fatalf("after the path change: acquires %d releases %d — the old sessions' leases must be released, the three live ones held", acq, rel)
	}
	c.Close()
	acq, rel = l.get()
	if rel != acq {
		t.Fatalf("after Close: acquires %d releases %d — every lease must be released", acq, rel)
	}
}

// Credentials are taken OUTSIDE the start gate: two workers whose mints
// take 300 ms each mint in parallel and then allocate 5 ms apart, so the
// third allocation lands well under 600 ms after the first. Sabotage seen
// red: the gate taken before Creds (the mints serialize behind the gate,
// the third allocation lands at 600 ms or later).
func TestCredentialsAreTakenOutsideTheStartGate(t *testing.T) {
	srv := newFakeServer(t)
	var mu sync.Mutex
	dialAt := map[int]time.Time{}
	var n int
	loopbackRelay(t, func(TURNCredentials) error {
		mu.Lock()
		n++
		dialAt[n] = time.Now()
		mu.Unlock()
		return nil
	})
	l := &lease{delay: func(id int) time.Duration {
		if id >= 2 {
			return 300 * time.Millisecond
		}
		return 0
	}}
	c := dialReady(t, testConfig(srv, 3, l.creds))
	defer c.Close()
	mu.Lock()
	gap := dialAt[3].Sub(dialAt[1])
	mu.Unlock()
	if gap >= 500*time.Millisecond {
		t.Fatalf("third allocation %s after the first — the slow mints serialized behind the start gate", gap)
	}
}

// A path change replaces the identity ONCE for the whole client: every
// worker re-announces under a strictly greater generation and a fresh salt,
// all under the same new pair. Sabotage seen red: OnPathChange restarting
// the workers without NewIdentity (the generation does not move).
func TestPathChangeCarriesANewIdentity(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	c := dialReady(t, cfg)
	defer c.Close()
	first := srv.seen()
	t0 := time.Now()
	c.OnPathChange()
	waitFor(t, "two GETCONFs under the new identity", func() bool { g, _, _ := srv.counts(); return g >= len(first)+2 })
	// A restart we asked for re-dials at once: no failure backoff (which
	// would put the first re-announce a second or more out). Sabotage seen
	// red: the kicked session treated as a failure (backoff applied).
	if took := time.Since(t0); took > 500*time.Millisecond {
		t.Fatalf("re-announce after the path change took %s — the restart paid a failure backoff", took)
	}
	after := srv.seen()[len(first):]
	oldGen, oldSalt := first[0].gen, first[0].salt
	workers := map[string]bool{}
	for _, g := range after {
		if g.gen <= oldGen || g.salt == oldSalt || g.gen != after[0].gen || g.salt != after[0].salt {
			t.Fatalf("GETCONF after the path change: gen %s salt %s (was gen %s salt %s) — want one new pair for every worker", g.gen, g.salt, oldGen, oldSalt)
		}
		workers[g.worker] = true
	}
	if len(workers) != 2 {
		t.Fatalf("workers that re-announced: %v, want both", workers)
	}
	if st := c.Stats(); st.PathChanges != 1 || st.Generation <= cfg.Generation {
		t.Fatalf("stats after the path change: %+v", st)
	}
}

// A wake probes every ready worker at once (READY, answered READY_OK).
// Sabotage seen red: WakeHealthCheck resetting the clocks without sending.
func TestWakeHealthCheckProbesEveryReadyWorker(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	_, readiesBefore, _ := srv.counts()
	c.WakeHealthCheck()
	waitFor(t, "a READY from every worker after the wake", func() bool { _, r, _ := srv.counts(); return r >= readiesBefore+2 })
	if st := c.Stats(); st.Probes != 2 {
		t.Fatalf("probes counted after the wake: %d, want 2", st.Probes)
	}
}

// blockableConn is a relay socket whose writes can be made to hang, as a
// full TCP buffer toward a relay would. A hung write returns when the test
// unblocks it, when the conn is closed, or when a write deadline set BEFORE
// OR DURING the hang passes — as a real socket's does.
type blockableConn struct {
	net.PacketConn
	block                atomic.Bool
	unblock              chan struct{}
	closed               chan struct{}
	entered              chan struct{} // closed once a write has blocked
	closeOnce, enterOnce sync.Once

	dmu             sync.Mutex
	deadline        time.Time
	deadlineChanged chan struct{} // closed and replaced on every SetWriteDeadline
}

func newBlockableConn(pc net.PacketConn) *blockableConn {
	return &blockableConn{PacketConn: pc, unblock: make(chan struct{}), closed: make(chan struct{}), entered: make(chan struct{}),
		deadlineChanged: make(chan struct{})}
}

func (b *blockableConn) SetWriteDeadline(t time.Time) error {
	b.dmu.Lock()
	b.deadline = t
	close(b.deadlineChanged)
	b.deadlineChanged = make(chan struct{})
	b.dmu.Unlock()
	return nil
}

func (b *blockableConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if !b.block.Load() {
		return b.PacketConn.WriteTo(p, a)
	}
	b.enterOnce.Do(func() { close(b.entered) })
	for {
		b.dmu.Lock()
		deadline, changed := b.deadline, b.deadlineChanged
		b.dmu.Unlock()
		var expire <-chan time.Time
		if !deadline.IsZero() {
			expire = time.After(time.Until(deadline))
		}
		select {
		case <-b.unblock:
			return 0, net.ErrClosed
		case <-b.closed:
			return 0, net.ErrClosed
		case <-expire:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		}
	}
}

func (b *blockableConn) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return b.PacketConn.Close()
}

// deallocating is pion's relay conn as Close sees it: Close WRITES the
// deallocate through the control socket before anything else.
type deallocating struct{ ctl net.PacketConn }

func (d deallocating) Close() error {
	_, err := d.ctl.WriteTo([]byte("deallocate"), nil)
	return err
}

// blockableRelays replaces DialRelay: every dial gets a fresh blockableConn,
// kept in order of dialing.
type blockableRelays struct {
	mu    sync.Mutex
	conns []*blockableConn
}

func installBlockableRelays(t *testing.T) *blockableRelays {
	t.Helper()
	r := &blockableRelays{}
	prev := dialRelay
	dialRelay = func(TURNCredentials, *net.UDPAddr, string, logging.LogLevel) (*Relay, error) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		bc := newBlockableConn(uc)
		r.mu.Lock()
		r.conns = append(r.conns, bc)
		r.mu.Unlock()
		// The production close order over the fake: the deallocate write
		// through the (blockable) control socket, then the socket.
		return &Relay{Conn: bc, Local: uc.LocalAddr(), close: func() { closeRelayBounded(bc, deallocating{bc}, nil) }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
	return r
}

func (r *blockableRelays) nth(i int) *blockableConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.conns) {
		return nil
	}
	return r.conns[i]
}

// A relay's own Close is bounded when the deallocate pion writes on it
// blocks (a TCP relay that stopped taking bytes): the write deadline goes
// on the control socket we own, and the close returns within the budget
// instead of hanging behind the write — the session teardown, the liveness
// restart and Client.Close all sit behind this one call. Sabotage seen red:
// the deadline dropped from closeRelayBounded (Close never returns).
func TestRelayCloseIsBoundedWhenTheDeallocateBlocks(t *testing.T) {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	bc := newBlockableConn(uc)
	bc.block.Store(true)
	r := &Relay{Conn: bc, Local: uc.LocalAddr(), close: func() { closeRelayBounded(bc, deallocating{bc}, nil) }}
	done := make(chan struct{})
	t0 := time.Now()
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(relayCloseWriteBudget + 2*time.Second):
		t.Fatal("Relay.Close did not return: the deallocate write hung the close")
	}
	if took := time.Since(t0); took < relayCloseWriteBudget/2 {
		t.Fatalf("Relay.Close returned in %s — it did not even try the deallocate under its deadline", took)
	}
}

// With EVERY session stuck in its own keepalive write (the idle worker on a
// dead TCP relay — the production shape), Close still returns within its
// budgets: a session blocked in a write cannot reach its own teardown, so
// Close's closeRelay is what frees each one, and it runs them concurrently
// — each costs the deallocate's deadline, and eight in a row would be four
// seconds, past the join budget. Sabotage seen red: the relays closed one
// after another. (With idle sessions the sabotage stays green: each session
// closes its own relay in its teardown the moment the ctx ends, which is why
// this test parks them in a write first.)
func TestCloseIsBoundedWhenEveryRelayIsStuck(t *testing.T) {
	srv := newFakeServer(t)
	relays := installBlockableRelays(t)
	prevKeepalive := keepaliveEvery
	keepaliveEvery = 20 * time.Millisecond
	defer func() { keepaliveEvery = prevKeepalive }()
	const workers = 8
	c := dialReady(t, testConfig(srv, workers, (&lease{}).creds))
	for i := 0; i < workers; i++ {
		relays.nth(i).block.Store(true)
	}
	for i := 0; i < workers; i++ {
		<-relays.nth(i).entered // every session is now inside a keepalive write
	}
	done := make(chan struct{})
	t0 := time.Now()
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeDisconnectBudget + closeJoinBudget + time.Second):
		t.Fatal("Close did not return with every relay stuck")
	}
	if took := time.Since(t0); took > closeDisconnectBudget+closeJoinBudget {
		t.Fatalf("Close took %s — the relays were closed one after another, not within the join budget", took)
	}
}

// Close returns within its budget even when a write to the relay hangs:
// DISCONNECT is best-effort, the relays are closed (their own deallocate
// write under its deadline), the join is bounded. Sabotage seen red: the
// join budget dropped (Close waits for the hung goroutine for ever).
func TestCloseIsBoundedWhenAWriteBlocks(t *testing.T) {
	srv := newFakeServer(t)
	relays := installBlockableRelays(t)
	c := dialReady(t, testConfig(srv, 1, (&lease{}).creds))
	bc := relays.nth(0)
	bc.block.Store(true)
	defer close(bc.unblock)

	done := make(chan struct{})
	t0 := time.Now()
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeDisconnectBudget + closeJoinBudget + 2*time.Second):
		t.Fatal("Close did not return: a hung relay write held the stop")
	}
	if took := time.Since(t0); took < closeDisconnectBudget {
		t.Fatalf("Close returned in %s — it did not even try the DISCONNECT budget", took)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("the client is not stopped after Close")
	}
}

// Stats carry what the app shows: bytes both ways, ready and total workers,
// the allocation RTT. Sabotage seen red: TxBytes not counted.
func TestStatsCarryBytesAndReady(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 1, (&lease{}).creds))
	defer c.Close()

	pkt := make([]byte, 100) // a minimal IPv4/UDP packet: no CQF1 frame, class Small
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 17
	if err := c.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	echo, err := c.ReadPacket(ctx)
	if err != nil || !bytes.Equal(echo, pkt) {
		t.Fatalf("echo through the fake server: err %v, %d bytes", err, len(echo))
	}
	st := c.Stats()
	if st.TxBytes < int64(len(pkt)) || st.RxBytes < int64(len(pkt)) || st.Ready != 1 || st.Total != 1 || st.AllocateRTT <= 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// A kick that arrives while the worker waits in its GETCONF schedule is
// honoured there, and no GETCONF after a path change carries the old pair.
// The server keys the epoch on the pair ALONE — a different pair replaces
// the device's sessions whatever its generation — so a retry under a pair
// the client has already replaced, landing after a neighbour announced the
// new one, rolls every worker back to a dead epoch. iOS delivers a path
// change as a cascade of 2–3 events ~500 ms apart, so a worker still in
// GETCONF from the first event is the norm. Sabotage seen red: the kick
// case dropped from the GETCONF wait (worker 2 waits out the 750 ms and
// retries under the old pair).
func TestKickDuringGetconfIsHonoured(t *testing.T) {
	srv := newFakeServer(t)
	srv.withholdTUNCONF("2", 1) // worker 2's first GETCONF goes unanswered: it sits in its 750 ms wait
	loopbackRelay(t, nil)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	waitFor(t, "worker 2's first GETCONF at the server", func() bool {
		for _, g := range srv.seen() {
			if g.worker == "2" {
				return true
			}
		}
		return false
	})
	before := srv.seen()
	old := before[0]
	t0 := time.Now()
	c.OnPathChange()
	waitFor(t, "both workers ready under the new identity", func() bool { return c.Stats().Ready == 2 })
	if took := time.Since(t0); took > 500*time.Millisecond {
		t.Fatalf("workers ready %s after the path change — worker 2 waited out its GETCONF schedule before noticing the kick", took)
	}
	time.Sleep(200 * time.Millisecond) // room for a stale retry to show up
	for _, g := range srv.seen()[len(before):] {
		if g.gen == old.gen || g.salt == old.salt {
			t.Fatalf("GETCONF from worker %s under the OLD pair (gen %s) after the path change — an epoch rollback at the server", g.worker, g.gen)
		}
	}
}

// A kick during the failure backoff re-dials at once — the path changed, so
// the failure being backed off from is moot — and is consumed by that
// re-dial: left in its buffer through the sleep it would restart the next
// session the moment it was ready (an extra allocation and lease for
// nothing). Sabotage seen red: the kick case dropped from the backoff wait
// (ready only after the 2 s backoff, then a second GETCONF from worker 2).
func TestKickDuringFailureBackoffRedialsAtOnceAndOnce(t *testing.T) {
	srv := newFakeServer(t)
	failed := make(chan struct{})
	var dials atomic.Int32
	loopbackRelay(t, func(TURNCredentials) error {
		if dials.Add(1) == 2 { // worker 2's first allocation
			close(failed)
			return errors.New("relay allocate: injected failure")
		}
		return nil
	})
	cfg := testConfig(srv, 2, (&lease{}).creds)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	<-failed
	waitFor(t, "worker 2 in its backoff", func() bool { return c.Stats().Restarts == 1 })
	before, _, _ := srv.counts()
	t0 := time.Now()
	c.OnPathChange()
	waitFor(t, "both workers ready", func() bool { return c.Stats().Ready == 2 })
	if took := time.Since(t0); took > 500*time.Millisecond {
		t.Fatalf("workers ready %s after the path change — the kick waited out worker 2's backoff", took)
	}
	time.Sleep(300 * time.Millisecond) // room for the extra cycle to show up
	n := 0
	for _, g := range srv.seen()[before:] {
		if g.worker == "2" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("GETCONFs from worker 2 after the path change: %d, want exactly 1 — the kick was not consumed by the re-dial", n)
	}
}

// A kick older than the allocation is answered by the session that starts:
// a worker parked in Creds (the pool's cold-start cap, its path-change
// settle) when the path changes reads the new identity anyway, and its
// GETCONF is the re-announce — the buffered kick must cost neither a second
// allocation (and lease) nor a second GETCONF. Sabotage seen red: the drain
// before the dial dropped (worker 2 allocates twice — the buffered kick is
// found by the GETCONF wait's own check and the first allocation is thrown
// away).
func TestKickOlderThanTheAllocationIsAnsweredByIt(t *testing.T) {
	srv := newFakeServer(t)
	var dials2 atomic.Int32
	loopbackRelay(t, func(creds TURNCredentials) error {
		if creds.Username == "2" {
			dials2.Add(1)
		}
		return nil
	})
	parked := make(chan struct{})
	release := make(chan struct{})
	var parks atomic.Int32
	l := &lease{}
	creds := func(ctx context.Context, id int) (Credential, error) {
		if id == 2 && parks.Add(1) == 1 { // worker 2's first mint parks until the test releases it
			close(parked)
			select {
			case <-release:
			case <-ctx.Done():
				return Credential{}, ctx.Err()
			}
		}
		cr, err := l.creds(ctx, id)
		cr.Username = strconv.Itoa(id) // so the relay hook can tell the workers apart
		return cr, err
	}
	cfg := testConfig(srv, 2, creds)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	<-parked
	c.OnPathChange() // worker 1 re-announces; worker 2's kick waits in its buffer
	close(release)
	waitFor(t, "both workers ready", func() bool { return c.Stats().Ready == 2 })
	time.Sleep(300 * time.Millisecond) // room for the extra cycle to show up
	n := 0
	for _, g := range srv.seen() {
		if g.worker == "2" {
			n++
			if g.gen == strconv.FormatUint(cfg.Generation, 10) || g.salt == cfg.Salt {
				t.Fatalf("worker 2 announced under the OLD pair (gen %s) after the path change", g.gen)
			}
		}
	}
	if n != 1 {
		t.Fatalf("GETCONFs from worker 2: %d, want exactly 1 — a kick older than its allocation restarted the session", n)
	}
	if d := dials2.Load(); d != 1 {
		t.Fatalf("allocations for worker 2: %d, want exactly 1 — a kick older than its allocation threw the allocation away", d)
	}
}

// WakeHealthCheck never waits for a relay write: on the TCP transport a full
// buffer toward a relay that stopped taking bytes blocks WriteTo, and the
// wake hook runs on the extension's wake/path callback. The probe mark is
// set before the send, so a write that never completes is an unanswered
// probe and the liveness rule restarts the worker. The monitor's own probe
// takes the same path (blocked there, it would arrive late at its next
// tick and read the stall as a deschedule — wiping the mark that would
// have caught it). Sabotage seen red: the probe sent synchronously (the
// wake returns only when the write is released).
func TestWakeHealthCheckDoesNotWaitForABlockedWrite(t *testing.T) {
	srv := newFakeServer(t)
	relays := installBlockableRelays(t)
	c := dialReady(t, testConfig(srv, 1, (&lease{}).creds))
	defer c.Close()
	bc := relays.nth(0)
	bc.block.Store(true)
	defer close(bc.unblock)
	done := make(chan struct{})
	go func() { c.WakeHealthCheck(); close(done) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("WakeHealthCheck did not return: a blocked relay write held the wake hook")
	}
	<-bc.entered // the probe is in the write, marked
	if st := c.Stats(); st.Probes != 1 {
		t.Fatalf("probes marked by the wake: %d, want 1", st.Probes)
	}
}

// A session's teardown closes the relay BEFORE taking the worker lock: a
// writer blocked in WriteTo (a probe, the TUN pump) holds that lock, and the
// close is what frees it. Otherwise restarting a worker whose relay stopped
// taking bytes — the liveness verdict's whole purpose — waits behind the
// very write it is meant to end. Sabotage seen red: the lock taken before
// the close in the deferred teardown (the kicked worker never comes back).
func TestSessionTeardownFreesABlockedWriter(t *testing.T) {
	srv := newFakeServer(t)
	relays := installBlockableRelays(t)
	c := dialReady(t, testConfig(srv, 1, (&lease{}).creds))
	defer c.Close()
	first := relays.nth(0)
	first.block.Store(true)
	c.WakeHealthCheck()
	<-first.entered // the probe now sits in WriteTo holding the worker's lock
	before := c.Stats().Restarts
	c.workers[0].restart("test: the relay stopped taking bytes")
	waitFor(t, "the worker back on a fresh relay", func() bool {
		st := c.Stats()
		return st.Restarts == before+1 && st.Ready == 1 && relays.nth(1) != nil
	})
}

// A refused allocation reaches the lease BEFORE the release, with the
// relay's error, and the worker's next attempt asks the pool again: the
// pool is what decides that a 486 means "another credential next time" —
// a worker that only released handed the same exhausted credential back to
// itself for ever (the user's review, 2026-09-06: two 486s, one mint, zero
// saturated slots). Sabotage seen red: the Failed call dropped from
// session() (the lease sees "released" first and never the error).
func TestRefusedAllocationReachesTheLeaseBeforeRelease(t *testing.T) {
	srv := newFakeServer(t)
	quota := errors.New("turn allocate: Allocate error response (error 486: Allocation Quota Reached)")
	loopbackRelay(t, func(creds TURNCredentials) error {
		if creds.Username == "exhausted" {
			return quota
		}
		return nil
	})
	var mu sync.Mutex
	var events []string
	handed := 0
	creds := func(ctx context.Context, workerID int) (Credential, error) {
		mu.Lock()
		handed++
		name := "fresh"
		if handed == 1 {
			name = "exhausted"
		}
		mu.Unlock()
		return Credential{
			TURNCredentials: TURNCredentials{Username: name, Password: "p", Address: "127.0.0.1:19302"},
			Failed: func(err error) {
				mu.Lock()
				events = append(events, "failed: "+err.Error())
				mu.Unlock()
			},
			Release: func() {
				mu.Lock()
				events = append(events, "released")
				mu.Unlock()
			},
		}, nil
	}
	c := dialReady(t, testConfig(srv, 1, creds))
	defer c.Close()

	mu.Lock()
	defer mu.Unlock()
	want := []string{"failed: " + quota.Error(), "released"}
	if handed != 2 || len(events) != 2 || events[0] != want[0] || events[1] != want[1] {
		t.Fatalf("handed %d credentials, lease saw %q — want 2 handed and %q (the refusal first, with the relay's error, then the release)", handed, events, want)
	}
}

// longReady makes every worker look ready for a minute: the deafness rule does
// not judge a worker inside its readyGrace.
func longReady(c *Client) {
	for _, w := range c.workers {
		w.readyAt.Store(time.Now().Add(-time.Minute).UnixNano())
	}
}

// quickWake shortens the wake round's wait and its watcher's step.
func quickWake(t *testing.T) {
	t.Helper()
	oldAfter, oldStep, oldAsk := wakeDeafAfter, wakeListenStep, wakeAskAgainEvery
	wakeDeafAfter, wakeListenStep, wakeAskAgainEvery = 150*time.Millisecond, 20*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() { wakeDeafAfter, wakeListenStep, wakeAskAgainEvery = oldAfter, oldStep, oldAsk })
}

func deafen(c *Client) {
	for i := range c.workers {
		c.Blackhole(i+1, true)
	}
}

// oneNewPairForAll: the GETCONFs after `first` carry ONE identity, newer than
// the first one, from every worker.
func oneNewPairForAll(t *testing.T, srv *fakeServer, first []getconfSeen, workers int) {
	t.Helper()
	after := srv.seen()[len(first):]
	seen := map[string]bool{}
	for _, g := range after {
		if g.gen <= first[0].gen || g.salt == first[0].salt || g.gen != after[0].gen || g.salt != after[0].salt {
			t.Fatalf("a GETCONF after the restart-all: gen %s salt %s (was gen %s) — want ONE new pair for every worker: the server keys the epoch on the pair, and the old sessions must go", g.gen, g.salt, first[0].gen)
		}
		seen[g.worker] = true
	}
	if len(seen) != workers {
		t.Fatalf("workers that re-announced: %v, want all %d", seen, workers)
	}
}

// The monitor's side of deafness, driven tick by tick with the test's own
// clock: every worker ready and deaf (the blackhole fault: the relay path is
// dead from our side, nothing fails) — after thirty seconds of total silence
// every ready worker is asked AT ONCE, and thirty seconds after an unanswered
// round every worker is replaced under ONE new identity. Until the fix the
// per-worker rule alone sat here for ever. Sabotages seen red: the monitor
// never consulting the deafness rule; the restart-all keeping the old identity;
// a probe round at every tick instead of one per silence.
func TestAllDeafWorkersAreAskedAtOnceAndThenReplacedTogether(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	_, readies0, _ := srv.counts()
	deafen(c)
	start := time.Now() // the silence is counted from here, to the tick
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	step := func(from, to int) {
		for s := from; s <= to; s += 5 {
			c.monitorStep(start.Add(time.Duration(s) * time.Second))
		}
	}

	step(5, 25)
	if st := c.Stats(); st.Probes != 0 || st.DeafAll != 0 {
		t.Fatalf("twenty-five seconds of silence already acted: %+v", st)
	}
	step(30, 30) // thirty seconds of total silence: the round
	waitFor(t, "a READY from both workers — the round", func() bool { _, r, _ := srv.counts(); return r >= readies0+2 })
	step(35, 55) // the answers are blackholed: still total silence, and the round is out
	if st := c.Stats(); st.Probes != 2 || st.DeafAll != 0 {
		t.Fatalf("twenty-five seconds after the round: probes %d (want 2 — ONE round, not one per tick), restart-alls %d (want 0)", st.Probes, st.DeafAll)
	}
	step(60, 60) // thirty seconds after the unanswered round
	if st := c.Stats(); st.DeafAll != 1 {
		t.Fatalf("restart-alls thirty seconds after an unanswered round: %d, want 1", st.DeafAll)
	}
	waitFor(t, "both workers back under the new identity", func() bool { g, _, _ := srv.counts(); return g >= len(first)+2 })
	oneNewPairForAll(t, srv, first, 2)
	waitFor(t, "both workers ready again", func() bool { return c.Stats().Ready == 2 })
	if st := c.Stats(); st.LostWorkers != 0 || st.PathChanges != 0 {
		t.Fatalf("the restart-all was booked as something else: %+v", st)
	}
}

// Build 419 — the deafness round's own probes were sent ONCE. A round that goes
// whole into a dead path (a block of a minute, a Wi-Fi that is still joining)
// is lost whole; when the path comes back onto a COMPLETELY idle tunnel nothing
// arrives by itself — an idle worker hears nothing but the answers to its own
// probes, the per-worker rule is held by rule 3 for as long as nobody has heard
// anything — and thirty seconds of listening later the round counted as
// unanswered: every worker replaced over a path that had been fine for a while
// (over UDP with the old allocations alive: a quota refusal per worker on the
// way back). A round that stands unanswered is asked AGAIN at every tick of its
// wait; its clock — the listening — is not touched by that. Sabotage seen red:
// the round never asked again (418).
func TestARoundLostInADeadPathIsAskedAgainSoAPathThatReturnedGetsNoVerdict(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	_, readies0, _ := srv.counts()
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for s := 5; s <= 40; s += 5 { // +30: the round, into the dead path; +35, +40: still dead
		c.monitorStep(at(s))
		waitFor(t, "this tick's sends to leave", func() bool { return !c.workers[0].probing.Load() && !c.workers[1].probing.Load() })
	}
	waitFor(t, "the round's READYs at the server", func() bool { _, r, _ := srv.counts(); return r >= readies0+2 })
	time.Sleep(100 * time.Millisecond) // their answers arrive and are DROPPED while the path is still dead
	undeafen(c)                        // the path is back — and the tunnel is idle: nothing comes by itself
	heard := c.rxSeq.Load()
	for s := 45; s <= 75; s += 5 { // the verdict of a round sent once falls at +60
		c.monitorStep(at(s))
		waitFor(t, "this tick's sends to leave", func() bool { return !c.workers[0].probing.Load() && !c.workers[1].probing.Load() })
		time.Sleep(20 * time.Millisecond) // an answer, if anybody was asked
	}
	g, _, _ := srv.counts()
	if st := c.Stats(); st.DeafAll != 0 || st.LostWorkers != 0 || g != len(first) || c.rxSeq.Load() == heard {
		t.Fatalf("a round lost whole into a dead path, the path back for thirty seconds before its verdict: restart-alls %d (want 0), given up on %d (want 0), %d new GETCONF(s) (want 0), heard anything after the path returned: %v (want true — somebody has to ASK: an idle tunnel says nothing by itself)",
			st.DeafAll, st.LostWorkers, g-len(first), c.rxSeq.Load() != heard)
	}
}

// The wake round's side: its probes go out the instant the process unfreezes —
// into a Wi-Fi that is still joining, a radio still coming up. Lost whole, with
// the path back a moment later and the tunnel idle, the round counted as
// unanswered at wakeDeafAfter and every worker was replaced. Its watcher asks
// again after every wakeAskAgainEvery of listening. Sabotage seen red: the
// watcher never asking again.
func TestAWakeRoundLostInADeadPathIsAskedAgainInsideItsWindow(t *testing.T) {
	quickWake(t)

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	_, readies0, _ := srv.counts()
	deafen(c)
	c.WakeHealthCheck() // the round: into the dead path
	waitFor(t, "the round's READYs at the server", func() bool { _, r, _ := srv.counts(); return r >= readies0+2 })
	time.Sleep(wakeAskAgainEvery / 4) // their answers arrive and are dropped while the path is still dead
	undeafen(c)                       // the path is back well inside the window; the tunnel is idle
	time.Sleep(3 * wakeDeafAfter)
	g, _, _ := srv.counts()
	if st := c.Stats(); st.DeafAll != 0 || g != len(first) || st.RoundAsks == 0 {
		t.Fatalf("a wake round lost into a path that came back inside its window: restart-alls %d (want 0), %d new GETCONF(s) (want 0), the round asked again %d time(s) (want > 0)", st.DeafAll, g-len(first), st.RoundAsks)
	}
}

// A HELD round keeps asking. The hold — the spacing between two restart-alls —
// can last minutes; a path that comes back in them onto an idle tunnel must not
// find, at the hold's end, a verdict on probes nobody repeated. Sabotage seen
// red: a held round not asked again.
func TestAHeldRoundKeepsAskingSoAPathThatReturnedGetsNoVerdictAtTheHoldsEnd(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	deafen(c)
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.deafMu.Lock()
	c.deafRounds = 3 // the third restart-all of a run was a moment ago: the next is held for deafSpacingFor(3) = 120 s
	c.deafMu.Unlock()
	c.lastDeafAll.Store(start.UnixNano())
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	step := func(s int) {
		c.monitorStep(at(s))
		waitFor(t, "this tick's sends to leave", func() bool { return !c.workers[0].probing.Load() && !c.workers[1].probing.Load() })
	}
	for s := 5; s <= 70; s += 5 { // +30 the round; +60 its verdict is due — and HELD; +65, +70: held
		step(s)
	}
	time.Sleep(100 * time.Millisecond)
	if st := c.Stats(); st.DeafAll != 0 {
		t.Fatalf("the fixture: a restart-all inside the hold (%d)", st.DeafAll)
	}
	undeafen(c) // the path is back, the tunnel idle, fifty seconds of hold to go
	heard := c.rxSeq.Load()
	step(75)
	waitFor(t, "the held round, asked again, to be answered", func() bool { return c.rxSeq.Load() > heard })
	for s := 80; s <= 130; s += 5 { // the hold ends at +120
		c.anyRx.Store(at(s - 1).UnixNano()) // the answers, in the monitor's time
		step(s)
	}
	g, _, _ := srv.counts()
	if st := c.Stats(); st.DeafAll != 0 || g != len(first) {
		t.Fatalf("a held round, the path back fifty seconds before the hold's end: restart-alls %d (want 0), %d new GETCONF(s) (want 0)", st.DeafAll, g-len(first))
	}
}

// … and a held WAKE round is asked again too — by the monitor's tick: its
// watcher asks inside the round's window only (every quarter of a second of a
// hold that can last minutes would be a flood). Sabotage seen red: the monitor's
// tick asking for its own rounds alone.
func TestAHeldWakeRoundIsAskedAgainByTheMonitorsTick(t *testing.T) {
	quickWake(t)

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	deafen(c)
	c.deafMu.Lock()
	c.deafRounds = 3 // held for deafSpacingFor(3) = 120 s after the restart-all of a moment ago
	c.deafMu.Unlock()
	c.lastDeafAll.Store(time.Now().UnixNano())
	c.WakeHealthCheck()
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	time.Sleep(3 * wakeDeafAfter) // the window is over, the verdict due — and held
	if st := c.Stats(); st.DeafAll != 0 {
		t.Fatalf("the fixture: a restart-all inside the hold (%d)", st.DeafAll)
	}
	step := func(s int) {
		c.monitorStep(at(s))
		waitFor(t, "this tick's sends to leave", func() bool { return !c.workers[0].probing.Load() && !c.workers[1].probing.Load() })
	}
	for s := 5; s <= 30; s += 5 { // the path stays dead; past +30 the per-worker rule is held by its rule 3 — nobody has heard anything
		step(s)
	}
	time.Sleep(100 * time.Millisecond)
	undeafen(c) // the path is back, the tunnel idle, the hold has a minute and a half to go
	heard := c.rxSeq.Load()
	step(35) // nobody but the held round's own asking is left to ask
	waitFor(t, "the held wake round, asked again by the monitor's tick, to be answered", func() bool { return c.rxSeq.Load() > heard })
	g, _, _ := srv.counts()
	if st := c.Stats(); st.DeafAll != 0 || g != len(first) {
		t.Fatalf("a held wake round, the path back inside the hold: restart-alls %d (want 0), %d new GETCONF(s) (want 0)", st.DeafAll, g-len(first))
	}
}

// A round's re-sends go out in a SILENCE — nobody has heard anything — and count
// against nobody, exactly as the per-worker rule's re-sends into a blackout do
// not: whether a re-send counts is the FACT of the client hearing before it and
// after it (probeState.confirmed), whoever sent it. A worker that really is dead
// goes two confirmed re-sends after the path returned, not one tick sooner.
// Sabotage seen red: the round's re-sends marked as made while the client heard.
func TestARoundsResendsIntoASilenceAreNotEvidenceAgainstAWorker(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	for s := 5; s <= 45; s += 5 { // +30 the round; +35, +40, +45: asked again, into the silence
		c.monitorStep(at(s))
		waitFor(t, "this tick's sends to leave", func() bool { return !c.workers[0].probing.Load() && !c.workers[1].probing.Load() })
	}
	time.Sleep(100 * time.Millisecond)
	c.Blackhole(1, false) // the path is back; worker 2 stays dead
	heard := c.rxSeq.Load()
	c.monitorStep(at(50)) // the round asked again: worker 1 answers — the round is answered
	waitFor(t, "worker 1 hears again", func() bool { return c.rxSeq.Load() > heard })
	for s := 55; s <= 65; s += 5 { // +55: worker 2 asked again, the first re-send made while the path works; +60: confirmed (1); +65: two → it goes
		othersHear(c, at(s-2), 1)
		tick(t, c, at(s))
		if st := c.Stats(); s < 65 && st.LostWorkers != 0 {
			t.Fatalf("+%d s: worker 2 given up on — but only %d re-send(s) had been made while the path worked; the round's, made into the silence, count for nothing", s, (s-55)/5)
		}
	}
	if st := c.Stats(); st.LostWorkers != 1 || st.DeafAll != 0 {
		t.Fatalf("+65 s: given up on %d worker(s) (want 1 — the dead one, after two confirmed re-sends), restart-alls %d (want 0)", st.LostWorkers, st.DeafAll)
	}
}

// A FIRST probe never counts against a worker, whatever is heard after it: the
// wake hook's and the round's go out when nobody is known to hear, and the
// rule's own is not a re-send. (Until the round was asked again, a scenario
// test carried this — the round's first probe, thirty seconds old when the
// path returned; now the round's re-sends replace that state long before, and
// the scenario cannot see the first probe's marking any more. The property is
// pinned where it is made.) Sabotage seen red: a first probe published as a
// re-send made while the client heard.
func TestAFirstProbeNeverCountsWhateverIsHeardAfterIt(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	w := c.workers[1]
	c.Blackhole(2, true) // its answer never comes: the state stays to be looked at
	w.probe(time.Now().UnixNano())
	st := w.probeSt.Load()
	if st == nil {
		t.Fatal("no probe state published")
	}
	if n := st.confirmed(true); n != 0 {
		t.Fatalf("a first probe, the client hearing right after it, counts as %d confirmed re-send(s) — want 0: it was sent when nobody was known to hear", n)
	}
}

// One line per tick that sends probes again, split by the fact the counting
// rests on — the client hearing since the send before, or not. The stop line's
// total cannot say which (the field run of 2026-09-19: "+28 sent again" over a
// run with a block in it). Sabotages seen red: no line; every re-send reported
// as made while the path worked.
func TestATickThatSendsProbesAgainSaysSoAndSaysIntoWhat(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	var mu sync.Mutex
	var lines []string
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.Logf = func(f string, a ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	c := dialReady(t, cfg)
	defer c.Close()
	longReady(c)
	said := func(what string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range lines {
			if strings.Contains(l, what) {
				n++
			}
		}
		return n
	}
	c.Blackhole(2, true) // worker 2 is dead; worker 1 hears
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	for s := 5; s <= 35; s += 5 { // +30: the first probe (and a witness, which answers); +35: sent again — the client HAS heard since
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	if n := said("liveness — 1 unanswered probe(s) sent again: 1 with the client hearing since the send before (the path works), 0 into silence"); n != 1 {
		t.Fatalf("a probe sent again while the witness answered: %d line(s) saying so, want 1; the log: %q", n, lines)
	}
	othersHear(c, at(37), 1) // the witness's last answer, in the monitor's time (the read loop stamped the real clock) …
	deafen(c)                // … and now a blackout: rule 3 still lets the rule through, and nothing is heard any more
	tick(t, c, at(40))
	if n := said("liveness — 1 unanswered probe(s) sent again: 0 with the client hearing since the send before (the path works), 1 into silence"); n != 0 {
		// +40's re-send still had the +35 witness's answer before it: it is +45's that goes out into silence
		t.Fatalf("the fixture: +40's re-send was made after the witness's last answer — it is not the silent one (%d)", n)
	}
	tick(t, c, at(45))
	if n := said("liveness — 1 unanswered probe(s) sent again: 0 with the client hearing since the send before (the path works), 1 into silence"); n != 1 {
		t.Fatalf("a probe sent again into a blackout: %d line(s) saying so, want 1; the log: %q", n, lines)
	}
}

// othersHear makes the client look, at the monitor's synthetic `now`, the way
// it looks while the path works: some worker has just heard something, and the
// workers named have too (a test's real inbound is stamped with the REAL clock,
// which the synthetic one has run ahead of).
func othersHear(c *Client, now time.Time, live ...int) {
	c.anyRx.Store(now.UnixNano())
	for _, id := range live {
		c.workers[id-1].lastRx.Store(now.UnixNano())
	}
}

// Build 415 — the field case of 2026-09-19 (a 70-second block of the relay leg,
// csqtt over UDP): the deafness round's probes went INTO the dead path, the path
// came back, the round was answered by whoever heard first — and thirty-five
// seconds after the round the per-worker rule restarted twelve HEALTHY workers
// on the word of those lost probes (their allocations alive: nine 486s on the
// re-dial). A probe sent when nobody is known to hear proves nothing; the rule
// now asks AGAIN, while others hear, before it gives a worker up. Sabotages
// seen red: the rule never asking again; a restart on a probe that was not sent
// while others heard.
func TestAProbeLostInADeadPathIsAskedAgainBeforeTheWorkerIsGivenUpOn(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	_, readiesAtStart, _ := srv.counts()
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for s := 5; s <= 30; s += 5 { // thirty seconds of total silence: the round, into the dead path
		c.monitorStep(at(s))
	}
	// The test's thirty seconds are microseconds: let the round's two answers
	// arrive and be DROPPED while the path is still dead — lifted first, the
	// fault would let them through, and the probes would not be lost at all.
	waitFor(t, "the round's READYs at the server", func() bool { _, r, _ := srv.counts(); return r >= readiesAtStart+2 })
	time.Sleep(100 * time.Millisecond)
	if st := c.Stats(); st.Probes != 2 || st.Reprobes != 0 {
		t.Fatalf("the round: probes %d (want 2), sent again %d (want 0 — nobody hears, so nobody is asked again)", st.Probes, st.Reprobes)
	}
	for s := 35; s <= 55; s += 5 {
		c.monitorStep(at(s))
	}
	// The path comes back — LATE, as in the field: by the next tick the round's
	// probes are thirty seconds old. Worker 1 hears (it asks, and is answered: a REAL
	// inbound, which answers the round); worker 2 is healthy too but hears
	// nothing by itself — an idle worker's only inbound is the answer to its
	// own probe, and its probe is long lost.
	undeafen(c)
	heard := c.rxSeq.Load()
	c.workers[0].probe(time.Now().UnixNano())
	waitFor(t, "worker 1 hears again", func() bool { return c.rxSeq.Load() > heard })
	_, readies0, _ := srv.counts()
	othersHear(c, at(60), 1)
	tick(t, c, at(60)) // thirty seconds after the round's probe to worker 2 — the tick that restarted it in the field
	waitFor(t, "worker 2 asked AGAIN, and answered", func() bool {
		_, r, _ := srv.counts()
		return r > readies0 && !probeOut(c.workers[1])
	})
	for s := 65; s <= 90; s += 5 {
		othersHear(c, at(s), 1, 2) // both hear now
		tick(t, c, at(s))
	}
	g, _, _ := srv.counts()
	if st := c.Stats(); st.LostWorkers != 0 || st.DeafAll != 0 || g != len(first) || st.Reprobes == 0 {
		t.Fatalf("a HEALTHY worker whose probe had gone into a dead path: given up on %d time(s) (want 0), restart-alls %d, %d new GETCONF(s), asked again %d time(s) (want > 0)",
			st.LostWorkers, st.DeafAll, g-len(first), st.Reprobes)
	}
}

// The other side: a worker that is really dead is still given up on — thirty
// seconds after its FIRST probe, exactly as before, having been asked at every
// tick in between; and after a dead path came back, a dead worker is asked
// twice more, while others hear, before it goes. Sabotages seen red: a re-send
// moving the restart's clock (the worker is asked for ever); re-sends not
// counted (never given up on); the round's own probe counted as one of them
// (given up on a tick early, on ONE re-send).
func TestADeadWorkerIsStillGivenUpOnThirtySecondsAfterItsFirstProbe(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	c.Blackhole(2, true) // worker 2 is dead: nothing it is sent arrives
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	_, readies0, _ := srv.counts()
	for s := 5; s <= 55; s += 5 { // the first probe at +30 s of silence, then one more at every tick: +35 … +55 — and a witness beside each
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	_, readies, _ := srv.counts()
	if st := c.Stats(); st.Probes != 1 || st.Reprobes != 5 || st.Witnesses != 6 || readies != readies0+12 || st.LostWorkers != 0 {
		t.Fatalf("twenty-five seconds after the first probe: probes %d (want 1), sent again %d (want 5), witnesses asked %d (want 6), READYs at the server %d (want 12), given up on %d (want 0 — not before the thirty seconds)",
			st.Probes, st.Reprobes, st.Witnesses, readies-readies0, st.LostWorkers)
	}
	othersHear(c, at(60), 1)
	tick(t, c, at(60))
	if st := c.Stats(); st.LostWorkers != 1 {
		t.Fatalf("thirty seconds after the FIRST probe: given up on %d worker(s), want 1 — the re-sends were made while the witness answered; and a re-send must not move the restart's clock", st.LostWorkers)
	}
}

func TestAfterADeadPathADeadWorkerGetsTwoLiveProbesBeforeItGoes(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for s := 5; s <= 55; s += 5 { // the round at +30, into the dead path
		c.monitorStep(at(s))
	}
	c.Blackhole(1, false) // the path is back — late — for worker 1; worker 2 stays dead
	heard := c.rxSeq.Load()
	c.workers[0].probe(time.Now().UnixNano())
	waitFor(t, "worker 1 hears again", func() bool { return c.rxSeq.Load() > heard })
	for s := 60; s <= 70; s += 5 { // +60: the round's probe is 30 s old — asked again; +65: that re-send confirmed (1), asked again; +70: confirmed (2) → it goes
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
		if s < 70 {
			if st := c.Stats(); st.LostWorkers != 0 {
				t.Fatalf("+%d s: worker 2 given up on — want two re-sends made while the path worked, and unanswered, first (the round's own probe went into a dead path and counts for nothing)", s)
			}
		}
	}
	if st := c.Stats(); st.LostWorkers != 1 || st.DeafAll != 0 {
		t.Fatalf("+70 s: given up on %d worker(s) (want 1 — the dead one, after two confirmed re-sends), restart-alls %d (want 0)", st.LostWorkers, st.DeafAll)
	}
}

// ripeProbe puts worker w where the rule gives it up: a probe out since
// `first`, asked again (last at `last`) often enough, while others heard.
func ripeProbe(c *Client, w *worker, first, last time.Time) {
	w.lastRx.Store(first.Add(-30 * time.Second).UnixNano())
	w.probeSt.Store(&probeState{firstAt: first.UnixNano(), lastAt: last.UnixNano(), rx: w.rx.Load(), seq: c.rxSeq.Load(),
		resent: true, heardBefore: true, counted: 4})
}

// probeOut: a probe stands for the worker's current silence.
func probeOut(w *worker) bool { return w.probeSt.Load() != nil }

// tick runs one monitor step at the synthetic `now` and then lets what it sent
// leave and be answered: the test's five seconds are microseconds, a worker has
// one send in flight, and the facts the rule counts are REAL inbound — a
// witness's READY_OK has to come back before the next tick can see it.
func tick(t *testing.T, c *Client, now time.Time) {
	t.Helper()
	w0, r0 := c.Stats().Witnesses, c.rxSeq.Load()
	c.monitorStep(now)
	waitFor(t, "this tick's sends to leave", func() bool {
		for _, w := range c.workers {
			if w.probing.Load() {
				return false
			}
		}
		return true
	})
	if c.Stats().Witnesses > w0 { // a witness was asked: if it can answer, let it
		deadline := time.Now().Add(150 * time.Millisecond)
		for c.rxSeq.Load() == r0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
}

// Build 416 — the review of 415, finding 1: rule 3 lets the rule through for as
// long as the OLD anyRx is younger than thirty seconds, although nobody has
// received anything since — so re-sends made INTO a general blackout were
// counted as "sent while others heard". The reviewer's stand: the first probe
// and five re-sends lost in a general silence, the path back just before the
// thirtieth second, one worker answers — and the healthy idle worker is given
// up on at once, without being asked again after the recovery (5 of 5).
// "Others hear" is a FACT — the client's real-inbound count moving around the
// send — never the age of a clock.
func TestResendsMadeIntoAGeneralBlackoutAreNotEvidenceAgainstAWorker(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano()) // worker 2: idle, silent from the start
	for s := 5; s <= 25; s += 5 {
		othersHear(c, at(s), 1)
		c.monitorStep(at(s))
	}
	// The blackout begins — for everybody — with anyRx 27 s into the run: the
	// clock stays "younger than thirty seconds" up to +55.
	othersHear(c, at(27), 1)
	deafen(c)
	for s := 30; s <= 55; s += 5 { // +30: worker 2's first probe; +35 … +55: five re-sends — every one of them into the blackout
		tick(t, c, at(s))
	}
	if st := c.Stats(); st.LostWorkers != 0 {
		t.Fatalf("given up on %d worker(s) INSIDE the blackout", st.LostWorkers)
	}
	time.Sleep(100 * time.Millisecond) // the blackholed answers arrive and are dropped while the path is still dead
	// The path is back just before the thirtieth second; worker 1 asks and is answered.
	undeafen(c)
	heard := c.rxSeq.Load()
	c.workers[0].probe(time.Now().UnixNano())
	waitFor(t, "worker 1 hears again", func() bool { return c.rxSeq.Load() > heard })
	othersHear(c, at(58), 1) // rule 3's clock, in the monitor's time
	tick(t, c, at(60))       // thirty seconds after worker 2's first probe
	waitFor(t, "worker 2 asked AGAIN after the recovery, and answered", func() bool { return !probeOut(c.workers[1]) })
	g, _, _ := srv.counts()
	if st := c.Stats(); st.LostWorkers != 0 || g != len(first) {
		t.Fatalf("a HEALTHY idle worker, every probe of which went into a general blackout: given up on %d time(s) (want 0 — it was never asked while the path worked), %d new GETCONF(s)", st.LostWorkers, g-len(first))
	}
}

// Finding 2: the read loop stamps a real inbound (lastRx, heardAt) BEFORE it
// clears the probe, and the monitor does not take turns with it: a verdict
// computed in that window saw the old probe fields — thirty seconds out, enough
// re-sends — and restarted a worker that had just ANSWERED (10 of 10 on the
// reviewer's stand with a pause before the clearing). Whether the probe was
// answered is a fact of its own — the worker's real-inbound count since the
// probe went out — and it voids the verdict whatever the other fields say.
func TestAnAnswerThatHasArrivedVoidsTheVerdictOnTheOldProbeFields(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	w2 := c.workers[1]
	ripeProbe(c, w2, at(0), at(25)) // out for thirty seconds at +30, asked again and again while others heard
	stamped, release := make(chan struct{}), make(chan struct{})
	hook := func(w *worker) {
		if w == w2 {
			close(stamped)
			<-release
		}
	}
	readLoopStamped.Store(&hook)
	verdicts := 0
	reached := func(_ *worker, a livenessAction) {
		if a == livenessRestart {
			verdicts++
		}
	}
	livenessVerdictReached.Store(&reached)
	t.Cleanup(func() { readLoopStamped.Store(nil); livenessVerdictReached.Store(nil) })
	defer close(release)
	w2.sendProbe() // … and NOW the answer comes: a real READY_OK, stamped — and the read loop held right before it clears the probe
	select {
	case <-stamped:
	case <-time.After(5 * time.Second):
		t.Fatal("the answer never reached the read loop")
	}
	c.lastTick.Store(at(25).UnixNano())
	othersHear(c, at(29), 1)
	c.monitorStep(at(30))
	g, _, _ := srv.counts()
	if st := c.Stats(); st.LostWorkers != 0 || g != len(first) || verdicts != 0 {
		t.Fatalf("a worker whose answer had ARRIVED (stamped, the probe not cleared yet): given up on %d time(s), %d new GETCONF(s), the restart verdict reached %d time(s) — want 0, 0, and 0: an answered probe is no verdict at all (the commit's last look is the second line of defence, not the first)",
			st.LostWorkers, g-len(first), verdicts)
	}
}

// … and the other half of the same seam: the verdict was reached on a probe
// that really was unanswered, and the answer reaches the read loop BEFORE it is
// carried out — counted, the probe not cleared yet (the read loop is held
// there). The restart is COMMITTED, as the deafness verdict is since 414: the
// probe's state comes down by CompareAndSwap from the one the verdict was
// reached on, and the worker's inbound count is read once more beside it — it
// is that last look that voids the verdict here.
func TestAnAnswerBetweenTheVerdictAndItsExecutionVoidsTheRestart(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	w2 := c.workers[1]
	ripeProbe(c, w2, at(0), at(25))
	stamped, release := make(chan struct{}), make(chan struct{})
	held := func(w *worker) {
		if w == w2 {
			close(stamped)
			<-release
		}
	}
	reached := 0
	hook := func(w *worker, a livenessAction) {
		if w != w2 || a != livenessRestart {
			return
		}
		reached++
		readLoopStamped.Store(&held)
		w2.sendProbe() // the answer comes now, between the verdict and the restart …
		select {
		case <-stamped: // … counted by the read loop, which is held before it clears the probe
		case <-time.After(5 * time.Second):
			t.Error("the late answer never reached the read loop")
		}
	}
	livenessVerdictReached.Store(&hook)
	t.Cleanup(func() { livenessVerdictReached.Store(nil); readLoopStamped.Store(nil) })
	defer close(release)
	c.lastTick.Store(at(25).UnixNano())
	othersHear(c, at(29), 1)
	c.monitorStep(at(30))
	g, _, _ := srv.counts()
	if st := c.Stats(); reached != 1 || st.LostWorkers != 0 || g != len(first) {
		t.Fatalf("the verdict was reached %d time(s) (want 1); the answer arrived before it was carried out, and it was carried out: given up on %d, %d new GETCONF(s)", reached, st.LostWorkers, g-len(first))
	}
}

// The commit's other clause: between the verdict and its execution the WAKE
// HOOK ran — a freeze boundary: whatever was observed before it means nothing,
// and the hook has put a fresh probe in the old one's place. No answer has
// arrived, so the last look at the inbound count says nothing; it is the
// CompareAndSwap that fails, and the restart is not carried out.
func TestAWakeBetweenTheVerdictAndItsExecutionVoidsTheRestart(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	w2 := c.workers[1]
	c.Blackhole(2, true) // nothing arrives for worker 2: only the hook's fresh probe can void the verdict
	ripeProbe(c, w2, at(0), at(25))
	reached := 0
	hook := func(w *worker, a livenessAction) {
		if w == w2 && a == livenessRestart {
			reached++
			c.WakeHealthCheck()
		}
	}
	livenessVerdictReached.Store(&hook)
	t.Cleanup(func() { livenessVerdictReached.Store(nil) })
	c.lastTick.Store(at(25).UnixNano())
	othersHear(c, at(29), 1)
	c.monitorStep(at(30))
	g, _, _ := srv.counts()
	if st := c.Stats(); reached != 1 || st.LostWorkers != 0 || g != len(first) {
		t.Fatalf("the verdict was reached %d time(s) (want 1); a WAKE came before it was carried out, and it was carried out: given up on %d, %d new GETCONF(s)", reached, st.LostWorkers, g-len(first))
	}
}

// After a general blackout a worker that really is dead still goes — but on
// re-sends made while the path WORKED: the five made into the blackout count
// for nothing, and neither does the last of them for having the recovery after
// it (nothing had been heard before it went out).
func TestAfterAGeneralBlackoutADeadWorkerGoesOnConfirmedResendsOnly(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.lastTick.Store(start.UnixNano())
	c.workers[1].lastRx.Store(start.UnixNano())
	for s := 5; s <= 25; s += 5 {
		othersHear(c, at(s), 1)
		c.monitorStep(at(s))
	}
	othersHear(c, at(27), 1)
	deafen(c)
	for s := 30; s <= 55; s += 5 { // the first probe and five re-sends, all into the blackout
		tick(t, c, at(s))
	}
	time.Sleep(100 * time.Millisecond)
	c.Blackhole(1, false) // the path is back; worker 2 stays dead
	heard := c.rxSeq.Load()
	c.workers[0].probe(time.Now().UnixNano())
	waitFor(t, "worker 1 hears again", func() bool { return c.rxSeq.Load() > heard })
	for s := 60; s <= 70; s += 5 { // +60: asked again, the first re-send made while the path works; +65: it is confirmed (1); +70: two → it goes
		othersHear(c, at(s-2), 1)
		tick(t, c, at(s))
		if st := c.Stats(); s < 70 && st.LostWorkers != 0 {
			t.Fatalf("+%d s: worker 2 given up on — but only %d re-send(s) had been made while the path worked; the ones made into the blackout count for nothing", s, (s-60)/5)
		}
	}
	if st := c.Stats(); st.LostWorkers != 1 {
		t.Fatalf("+70 s: given up on %d worker(s), want 1 — the dead one, after two confirmed re-sends", st.LostWorkers)
	}
}

// Build 417 — the review of 416: worker.probe reads the worker's inbound count
// and THEN publishes the probe's state, and the read loop — which does not take
// turns with it — can count an inbound AND clear the probe in between. The
// state is then born ANSWERED (the count has moved past its snapshot) after the
// only event that would ever have cleared it. The rule said "answered —
// nothing" at every tick: a worker that went silent right then was never asked
// again and never given up on, and with the other workers hearing the deafness
// rule does not help either (the reviewer's stand, a real packet and a
// controlled pause before the publication, 5 of 5; 180 s of model time: Probes
// 1 → 1, Reprobes 0 → 0, LostWorkers 0 → 0, the old state still standing). An
// answered state is TAKEN DOWN by the monitor, not just passed over.
//
// anInboundOutrunsTheProbesPublication arms that window for worker w: the first
// time a probe of w's has read its counts and not yet published, a REAL inbound
// arrives for w and is handled to the end, and then w goes silent for good —
// the probe that follows goes into a dead path. (The sentinel only makes the
// read loop's clearing observable: in the field there is nothing to clear at
// that moment, which is the point.)
func anInboundOutrunsTheProbesPublication(t *testing.T, c *Client, w *worker, id int) {
	t.Helper()
	var once sync.Once
	hook := func(x *worker) {
		if x != w {
			return
		}
		once.Do(func() {
			w.probeSt.Store(&probeState{})
			w.sendProbe() // a READY of its own: the server's READY_OK is the real inbound
			waitFor(t, "the inbound to be counted and the probe cleared, inside the probe's window", func() bool {
				return w.probeSt.Load() == nil && !w.probing.Load()
			})
			c.Blackhole(id, true)
		})
	}
	probeSnapshotTaken.Store(&hook)
	t.Cleanup(func() { probeSnapshotTaken.Store(nil) })
}

func TestAProbePublishedAfterItsAnswerDoesNotSwitchTheWorkersRecoveryOff(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	w2 := c.workers[1]
	c.lastTick.Store(start.UnixNano())
	w2.lastRx.Store(start.UnixNano()) // worker 2: idle, silent from the start
	anInboundOutrunsTheProbesPublication(t, c, w2, 2)
	for s := 5; s <= 30; s += 5 { // +30: worker 2's first probe — and inside it, between the counts and the publication, the inbound
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	w2.lastRx.Store(at(30).UnixNano()) // that inbound, in the monitor's time (the read loop stamped the real clock)
	if st := w2.probeSt.Load(); st == nil || st.rx == w2.rx.Load() {
		t.Fatalf("the fixture: the probe's state was to be published AFTER an inbound its snapshot had not seen (published: %v)", st != nil)
	}
	othersHear(c, at(35), 1)
	tick(t, c, at(35))
	standsAt35 := probeOut(w2)
	for s := 40; s <= 180; s += 5 { // silent since +30: asked afresh at +60, again at every tick, given up on at +90
		if c.Stats().LostWorkers != 0 {
			break
		}
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	if st := c.Stats(); standsAt35 || st.Probes != 2 || st.Reprobes != 5 || st.LostWorkers != 1 {
		t.Fatalf("a worker that went silent right after a probe published BEHIND its own answer, 180 s on: the answered state still standing a tick later: %v (want false — nobody else is left to clear it); probes %d (want 2 — asked afresh thirty seconds into the silence), sent again %d (want 5), given up on %d (want 1): its recovery was switched off",
			standsAt35, st.Probes, st.Reprobes, st.LostWorkers)
	}
}

// The same window in the WAKE HOOK's probe — where the field is most likely to
// meet it: at an unfreeze the read loops drain what the sockets had buffered at
// the very moment the hook probes every worker.
func TestAWakeProbePublishedAfterItsAnswerDoesNotSwitchTheWorkersRecoveryOffEither(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	w2 := c.workers[1]
	anInboundOutrunsTheProbesPublication(t, c, w2, 2)
	c.WakeHealthCheck()
	waitFor(t, "worker 1's wake probe to be answered", func() bool { return !probeOut(c.workers[0]) })
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	c.lastTick.Store(start.UnixNano())
	w2.lastRx.Store(start.UnixNano())
	if st := w2.probeSt.Load(); st == nil || st.rx == w2.rx.Load() {
		t.Fatalf("the fixture: the wake probe's state was to be published AFTER an inbound its snapshot had not seen (published: %v)", st != nil)
	}
	for s := 5; s <= 180; s += 5 { // +5: the answered state comes down; +30: asked afresh; +60: given up on
		if c.Stats().LostWorkers != 0 {
			break
		}
		othersHear(c, at(s), 1)
		tick(t, c, at(s))
	}
	if st := c.Stats(); st.Probes != 3 || st.Reprobes != 5 || st.LostWorkers != 1 || st.DeafAll != 0 {
		t.Fatalf("a worker that went silent right after a WAKE probe published behind its own answer, 180 s on: probes %d (want 3 — the wake's two and a fresh one thirty seconds into the silence), sent again %d (want 5), given up on %d (want 1), restart-alls %d (want 0)",
			st.Probes, st.Reprobes, st.LostWorkers, st.DeafAll)
	}
}

// … and the monitor's taking-down is the SECOND line, for the state nobody else
// can clear: an inbound still ends its probe AT ONCE, in the read loop — the
// worker is a witness again and out of suspicion that instant, not a tick
// later. (With the monitor able to take an answered state down, the read loop's
// clearing could be dropped and everything that WAITS for the probe to end
// would still pass a tick later: the sabotage "an answer does not end the
// probe" went green the moment the monitor's layer was added. This test sees
// which of the two acted.)
func TestAnInboundEndsItsProbeAtOnceNotTheMonitorATickLater(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	w2 := c.workers[1]
	var byMonitor atomic.Int32
	hook := func(w *worker, a livenessAction) {
		if w == w2 && a == livenessAnswered {
			byMonitor.Add(1)
		}
	}
	livenessVerdictReached.Store(&hook)
	t.Cleanup(func() { livenessVerdictReached.Store(nil) })
	rx0 := w2.rx.Load()
	w2.probe(time.Now().UnixNano())
	waitFor(t, "worker 2's answer to be counted", func() bool { return w2.rx.Load() > rx0 })
	for deadline := time.Now().Add(time.Second); probeOut(w2) && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond) // the clearing follows the count within the same read-loop iteration
	}
	if probeOut(w2) || byMonitor.Load() != 0 {
		t.Fatalf("a second after its answer was counted: the probe still out: %v, taken down by the monitor %d time(s) — want false and 0: the inbound itself ends the probe, in the read loop", probeOut(w2), byMonitor.Load())
	}
}

// The taking-down is a CompareAndSwap from the state that was looked at: the
// wake hook does not take turns with the monitor, and a fresh probe it has put
// in the answered one's place between the look and the removal is a wake's —
// a freeze boundary's — and must stand. (Removed by a plain clearing, worker 2
// would lose its wake probe, and a dead worker found by a wake would wait the
// monitor's thirty seconds of silence instead.)
func TestAWakeBetweenFindingAProbeAnsweredAndTakingItDownKeepsTheFreshProbe(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	w2 := c.workers[1]
	c.Blackhole(2, true) // nothing arrives for worker 2: the hook's fresh probe stays out, to be looked at
	born := &probeState{firstAt: at(0).UnixNano(), lastAt: at(0).UnixNano(), rx: w2.rx.Load() - 1, seq: c.rxSeq.Load()}
	w2.probeSt.Store(born) // a state born answered: the count had moved before it was published
	reached := 0
	hook := func(w *worker, a livenessAction) {
		if w == w2 && a == livenessAnswered {
			reached++
			c.WakeHealthCheck()
		}
	}
	livenessVerdictReached.Store(&hook)
	t.Cleanup(func() { livenessVerdictReached.Store(nil) })
	c.lastTick.Store(at(0).UnixNano())
	othersHear(c, at(5), 1)
	c.monitorStep(at(5))
	if st := w2.probeSt.Load(); reached != 1 || st == nil || st == born {
		t.Fatalf("the probe was found answered %d time(s) (want 1); a WAKE put a fresh probe in its place before it was taken down — and what stands afterwards: a probe %v, the answered one itself %v (want the wake's fresh probe: true, false)",
			reached, st != nil, st == born)
	}
}

// The wake's side: the hook's probes are a round with a watcher of its own,
// and wakeDeafAfter of LISTENING without one real inbound is the verdict — the
// user has the phone in hand. The control is a healthy client: its probes are
// answered and nothing restarts. Sabotages seen red: the wake hook not starting
// the watcher; the wake round made to wait like the monitor's.
func TestTheWakeVerdictReplacesDeafWorkersWithinSeconds(t *testing.T) {
	quickWake(t)

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()

	c.WakeHealthCheck() // healthy: READY_OK comes back
	time.Sleep(3 * wakeDeafAfter)
	if g, _, _ := srv.counts(); g != len(first) || c.Stats().DeafAll != 0 {
		t.Fatalf("a HEALTHY client was restarted after its wake: %d new GETCONF(s), %d restart-all(s)", g-len(first), c.Stats().DeafAll)
	}

	deafen(c)
	t0 := time.Now()
	c.WakeHealthCheck()
	waitFor(t, "both workers back under the new identity", func() bool { g, _, _ := srv.counts(); return g >= len(first)+2 })
	if took := time.Since(t0); took > 2*time.Second {
		t.Fatalf("the restart-all came %s after the wake", took.Round(10*time.Millisecond))
	}
	oneNewPairForAll(t, srv, first, 2)
	if st := c.Stats(); st.DeafAll != 1 {
		t.Fatalf("restart-alls after one deaf wake: %d, want 1", st.DeafAll)
	}
}

// An unfreeze runs the monitor's LATE tick and the wake hook side by side, and
// the late tick's clock reset may land AFTER the hook's probe round — before
// the answers or after them. Whether the round was answered is a fact the read
// loops counted; the reset must neither grant it nor take it away.
//
// This half: DEAF workers. The reset restarts the silence clock after the
// round went out; read off the clocks, that would look like an answer and the
// wake verdict would be lost exactly when it is needed. Nor may the tick DROP
// the round as one that predates the freeze: it was published after this tick
// read its mark. Sabotages seen red: "answered" read off the silence clock; the
// late tick dropping whatever round stands.
func TestALateTickDoesNotVoidTheWakeRoundThatBeatIt(t *testing.T) {
	quickWake(t)
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	now := time.Now()
	c.lastTick.Store(now.Add(-10 * time.Minute).UnixNano()) // the monitor last ran before the freeze
	prevBeforeHook := nanosTime(c.lastTick.Load())
	c.WakeHealthCheck()                         // the hook first: clocks reset, a round out, the tick mark moved …
	c.lastTick.Store(prevBeforeHook.UnixNano()) // … but this tick had read its mark BEFORE the hook moved it
	c.monitorStep(time.Now())                   // late by ten minutes: every clock restarts
	if st := c.Stats(); st.Descheduled != 1 {
		t.Fatalf("the fixture's tick was not late: descheduled %d", st.Descheduled)
	}
	if c.round.Load() == nil {
		t.Fatal("the late tick dropped the round the wake hook had just published — it is FRESH: sent after the unfreeze, after this tick read its mark")
	}
	waitFor(t, "the restart-all once the fresh round has gone unanswered", func() bool { return c.Stats().DeafAll == 1 })
}

// The other half, the user's review of 411: HEALTHY workers. The hook's round
// is ANSWERED, and then the late tick's reset lands (it had read its tick mark
// before the hook moved it). 411 re-stamped the round on that reset, the answer
// was forgotten, and wakeDeafAfter later every healthy worker was restarted —
// 3 of 3 on the reviewer's stand with the real timer. The round's real watcher
// runs here too. Sabotages seen red: the reset re-stamping the round; a real inbound not
// counted.
func TestALateTickDoesNotUnanswerTheWakeRound(t *testing.T) {
	quickWake(t)

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()

	c.lastTick.Store(time.Now().Add(-10 * time.Minute).UnixNano()) // the monitor last ran before the freeze
	prevBeforeHook := c.lastTick.Load()
	heard := c.rxSeq.Load()
	c.WakeHealthCheck() // the hook first: a round goes out …
	waitFor(t, "the round's answers", func() bool { return c.rxSeq.Load() >= heard+2 })
	c.lastTick.Store(prevBeforeHook) // … and the late tick, which had read its mark BEFORE the hook moved it,
	c.monitorStep(time.Now())        // resets every clock AFTER the answers came
	if st := c.Stats(); st.Descheduled != 1 {
		t.Fatalf("the fixture's tick was not late: descheduled %d", st.Descheduled)
	}
	time.Sleep(3 * wakeDeafAfter)                              // the round's watcher has listened its fill by now
	c.monitorStep(time.Now().Add(wakeDeafAfter + time.Second)) // … and the monitor has looked once more
	if g, _, _ := srv.counts(); g != len(first) || c.Stats().DeafAll != 0 {
		t.Fatalf("HEALTHY workers whose round was answered were restarted: %d new GETCONF(s), %d restart-all(s) — a clock reset un-answered the round",
			g-len(first), c.Stats().DeafAll)
	}
}

// A round sent BEFORE a freeze proves nothing after it (the user's review of
// 412): the path may have changed while the process was frozen, and a verdict
// needs a fresh ask. 412 kept the round through the late tick and measured its
// wait in wall time, so: a probe, ninety frozen seconds, a late tick, the next
// tick five seconds on — every worker restarted on the OLD deadline with
// Probes 2 → 2, nobody having been asked again. Now the late tick drops the
// round, the wait is LISTENING (awake time the monitor's on-time ticks add up),
// and the restart comes only after a fresh round went unanswered. Sabotages
// seen red: the late tick keeping the pre-freeze round; the monitor's ticks not
// adding up the listening.
func TestARoundSentBeforeAFreezeIsDroppedNotJudged(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	at := func(s int) { c.monitorStep(start.Add(time.Duration(s) * time.Second)) }

	for s := 5; s <= 35; s += 5 { // the round at thirty seconds of silence, five seconds of listening after it
		at(s)
	}
	if st := c.Stats(); st.Probes != 2 || c.round.Load() == nil {
		t.Fatalf("before the freeze: probes %d (want 2), a round standing: %v", st.Probes, c.round.Load() != nil)
	}
	at(35 + 90) // ninety seconds frozen: this tick is late
	if st := c.Stats(); st.Descheduled != 1 || st.DeafAll != 0 || c.round.Load() != nil {
		t.Fatalf("the late tick: descheduled %d (want 1), restart-alls %d (want 0), the pre-freeze round still standing: %v (want dropped)",
			st.Descheduled, st.DeafAll, c.round.Load() != nil)
	}
	for s := 130; s <= 150; s += 5 { // the next ticks are on time — and have nothing to judge
		at(s)
		if st := c.Stats(); st.DeafAll != 0 || st.Probes != 2 {
			t.Fatalf("%d s after the freeze: restart-alls %d, probes %d — every worker restarted (or asked) on a round that predates the freeze", s-125, st.DeafAll, st.Probes)
		}
	}
	at(155) // thirty seconds of silence since the reset: the FRESH ask
	if st := c.Stats(); st.Probes != 4 || st.DeafAll != 0 {
		t.Fatalf("thirty seconds after the freeze: probes %d (want 4 — a fresh round), restart-alls %d (want 0)", st.Probes, st.DeafAll)
	}
	for s := 160; s <= 180; s += 5 {
		at(s)
	}
	if st := c.Stats(); st.DeafAll != 0 {
		t.Fatalf("restarted after %d s of listening to the fresh round", 180-155)
	}
	at(185) // thirty seconds of listening to the fresh round, not one answer
	if st := c.Stats(); st.DeafAll != 1 || st.Probes != 4 {
		t.Fatalf("after the fresh round went unanswered: restart-alls %d (want 1), probes %d", st.DeafAll, st.Probes)
	}
	waitFor(t, "both workers back under the new identity", func() bool { g, _, _ := srv.counts(); return g >= len(first)+2 })
}

// The same for the WAKE hook's round when the process resumes WITHOUT a new
// wake: the hook moved the tick mark when it published, so at the late tick the
// round is at or before the mark — it predates the freeze, and goes.
func TestAWakeRoundSentBeforeAFreezeIsDroppedToo(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	c.WakeHealthCheck() // default timings: its watcher needs five seconds, the test is over long before
	if c.round.Load() == nil {
		t.Fatal("the wake hook published no round")
	}
	c.monitorStep(time.Now().Add(90 * time.Second)) // resumed with no new wake: a late tick
	if st := c.Stats(); st.Descheduled != 1 || st.DeafAll != 0 || c.round.Load() != nil {
		t.Fatalf("the late tick after a freeze with no new wake: descheduled %d, restart-alls %d, the old wake round standing: %v (want dropped)",
			st.Descheduled, st.DeafAll, c.round.Load() != nil)
	}
}

// A wake round's listening is its WATCHER's to count, in short steps that notice
// a freeze. The monitor's tick must not add its five-second gap to it: the
// monitor takes a gap of up to ten seconds for "on time", so a freeze of a few
// seconds would pass as listening — and one tick alone would fill the wake
// round's whole wait. Sabotage seen red: the monitor adding its gap to a wake
// round.
func TestTheMonitorsTickIsNotAWakeRoundsListening(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	c.WakeHealthCheck()                            // default timings: the watcher has counted next to nothing yet
	c.monitorStep(time.Now().Add(6 * time.Second)) // an on-time tick, six seconds "later"
	if st := c.Stats(); st.DeafAll != 0 {
		t.Fatalf("restart-alls right after a wake: %d — the monitor's tick gap was counted as the wake round's listening", st.DeafAll)
	}
	if r := c.round.Load(); r == nil || time.Duration(r.listened.Load()) > time.Second {
		t.Fatalf("the wake round after an on-time monitor tick: %+v — want it standing, with only its watcher's steps counted", r)
	}
}

// A wake round's five seconds are LISTENING, counted by its watcher in short
// steps. A step that takes ninety seconds is a freeze: the round predates it
// and is dropped — not judged on what it did not hear while nobody listened.
// The next wake asks again, and that round's verdict stands. Sabotage seen red:
// a frozen step counted as listening.
func TestAFreezeInsideTheWakeWindowDropsTheRound(t *testing.T) {
	quickWake(t)
	realSleep := wakeListenSleep
	var steps atomic.Int32
	wakeListenSleep = func(ctx context.Context, d time.Duration) time.Duration {
		took := realSleep(ctx, d)
		if steps.Add(1) == 2 {
			return 90 * time.Second // the process was frozen inside this step
		}
		return took
	}
	defer func() { wakeListenSleep = realSleep }()

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	c.WakeHealthCheck()
	waitFor(t, "the watcher to drop the round that predates the freeze", func() bool { return c.round.Load() == nil })
	time.Sleep(3 * wakeDeafAfter)
	if st := c.Stats(); st.DeafAll != 0 {
		t.Fatalf("restart-alls on a round that was frozen through: %d, want 0", st.DeafAll)
	}
	c.WakeHealthCheck() // the next wake asks again; no step of this round is frozen
	waitFor(t, "the restart-all after the fresh wake round went unanswered", func() bool { return c.Stats().DeafAll == 1 })
}

// A round is dropped, replaced by the monitor's, or cleared by a verdict ONLY
// by CompareAndSwap from the round that was looked at: the wake hook publishes
// from its own callback at any moment, and a Store would take a fresh round
// with it. The one Store is the hook's — a wake is a freeze boundary, and
// whatever stood before it is meant to go. A race cannot be pinned by running
// it; the form is pinned here. Sabotages seen red: the late tick's drop as a
// Store(nil); the wake hook publishing its round after its probes.
func TestARoundIsOnlyEverTakenDownByCompareAndSwap(t *testing.T) {
	raw, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if n := strings.Count(src, "c.round.Store("); n != 1 || !strings.Contains(src, "c.round.Store(r) // a wake is a freeze boundary") {
		t.Fatalf("c.round.Store( appears %d time(s) — want exactly one, the wake hook's publication", n)
	}
	// … and the hook publishes BEFORE its probes go out: judgeDeaf does not take
	// turns with it, and a verdict on the older round must fail its commit from
	// the first moment of the wake — not only once the probes are on their way.
	hook := src[strings.Index(src, "func (c *Client) WakeHealthCheck() {"):]
	hook = hook[:strings.Index(hook, "\n}\n")]
	if pub, probe := strings.Index(hook, "c.round.Store(r)"), strings.Index(hook, "w.probe(ns)"); pub < 0 || probe < 0 || pub > probe {
		t.Fatalf("the wake hook publishes its round at %d and probes at %d — want the publication first", pub, probe)
	}
	for _, fn := range []string{"func (c *Client) dropRoundBefore(", "func (c *Client) listenTo(", "func (c *Client) judgeDeaf("} {
		from := strings.Index(src, fn)
		if from < 0 {
			t.Fatalf("%s… is not where the scan expects it", fn)
		}
		body := src[from:]
		if end := strings.Index(body, "\n}\n"); end >= 0 {
			body = body[:end] // the scope ends at the function's closing brace
		}
		if !strings.Contains(body, "c.round.CompareAndSwap(r, ") {
			t.Fatalf("%s… takes a round down without CompareAndSwap from the round it looked at", fn)
		}
	}
}

// driveToTheVerdict deafens every worker and drives the monitor, tick by tick
// with the test's clock, up to the tick at which the verdict on the monitor's
// own round falls due (sixty seconds in); it returns that tick as a func.
func driveToTheVerdict(c *Client) (verdictTick func()) {
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	for s := 5; s <= 55; s += 5 {
		c.monitorStep(start.Add(time.Duration(s) * time.Second))
	}
	return func() { c.monitorStep(start.Add(60 * time.Second)) }
}

func undeafen(c *Client) {
	for i := range c.workers {
		c.Blackhole(i+1, false)
	}
}

// A verdict belongs to the round it was reached on (the user's review of 413).
// The wake hook is not serialized with judgeDeaf: between the verdict and its
// execution it can publish a FRESH round — a wake is a freeze boundary — which
// healthy workers then answer. 413 took the old round down with a
// CompareAndSwap and ignored its answer: the fresh round survived, and the
// identity was changed and every worker restarted all the same (the reviewer's
// stand with a controlled pause before the execution: 5 of 5). Now the
// CompareAndSwap COMMITS the verdict, before anything else is changed.
//
// First half: the fresh round is ANSWERED — nothing may happen. Second half, on
// a new client: the fresh round is published and stays unanswered — the OLD
// verdict is void all the same (this is what pins the CompareAndSwap's own
// check: no answer arrives to void it by other means), and the fresh round's
// own listening ends in a restart-all of its own: truly silent workers are
// still replaced. Sabotage seen red: the verdict carried out although its round
// was replaced.
func TestAVerdictOnAReplacedRoundIsNotCarriedOut(t *testing.T) {
	defer func() { deafVerdictReached = nil }() // after the Closes below: nobody reads it any more
	quickWake(t)

	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	gen := c.Stats().Generation
	verdictTick := driveToTheVerdict(c)
	reached := 0
	deafVerdictReached = func(a deafAction) {
		if a != deafRestartAll {
			return
		}
		if reached++; reached > 1 {
			return
		}
		undeafen(c) // the path is back …
		heard := c.rxSeq.Load()
		c.WakeHealthCheck() // … a wake publishes a fresh round …
		waitFor(t, "real answers to the fresh round", func() bool { return c.rxSeq.Load() >= heard+2 })
	}
	verdictTick()
	if reached != 1 {
		t.Fatalf("the fixture never reached a restart-all verdict (%d)", reached)
	}
	time.Sleep(3 * wakeDeafAfter)
	st := c.Stats()
	if g, _, _ := srv.counts(); st.DeafAll != 0 || st.Generation != gen || g != len(first) {
		t.Fatalf("a verdict reached on a round that a wake had REPLACED — and whose replacement was answered — was carried out: restart-alls %d, generation %d → %d, %d new GETCONF(s)",
			st.DeafAll, gen, st.Generation, g-len(first))
	}

	srv2 := newFakeServer(t)
	c2 := dialReady(t, testConfig(srv2, 2, (&lease{}).creds))
	defer c2.Close()
	longReady(c2)
	verdictTick2 := driveToTheVerdict(c2)
	reached = 0
	var fresh *probeRound
	deafVerdictReached = func(a deafAction) {
		if a != deafRestartAll {
			return
		}
		if reached++; reached > 1 {
			return
		}
		c2.WakeHealthCheck() // a wake — and the workers are still deaf
		fresh = c2.round.Load()
	}
	probesBefore := c2.Stats().Probes
	verdictTick2()
	if st := c2.Stats(); st.DeafAll != 0 || c2.round.Load() != fresh || fresh == nil || !fresh.wake {
		t.Fatalf("right after the old verdict: restart-alls %d (want 0 — its round was replaced by a wake's), the fresh wake round standing: %v",
			st.DeafAll, c2.round.Load() == fresh && fresh != nil)
	}
	waitFor(t, "the fresh round's OWN verdict: truly silent workers are still replaced", func() bool { return c2.Stats().DeafAll == 1 })
	if st := c2.Stats(); st.Probes != probesBefore+2 {
		t.Fatalf("probes %d → %d: the restart-all must rest on the fresh round's two probes", probesBefore, st.Probes)
	}
}

// … and the facts are read once more at the moment of commitment: a real
// inbound that arrives between the verdict and its execution — with no new
// round published — voids it too. Sabotage seen red: the last look dropped.
func TestAnAnswerAtTheLastInstantVoidsTheVerdict(t *testing.T) {
	defer func() { deafVerdictReached = nil }()
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	first := srv.seen()
	verdictTick := driveToTheVerdict(c)
	reached := 0
	deafVerdictReached = func(a deafAction) {
		if a != deafRestartAll {
			return
		}
		if reached++; reached > 1 {
			return
		}
		undeafen(c)
		heard := c.rxSeq.Load()
		c.workers[0].probe(time.Now().UnixNano()) // one worker asks, and is answered: a real inbound, no new round
		waitFor(t, "the late answer", func() bool { return c.rxSeq.Load() > heard })
	}
	verdictTick()
	if g, _, _ := srv.counts(); reached != 1 || c.Stats().DeafAll != 0 || g != len(first) {
		t.Fatalf("reached %d; an answer had arrived before the verdict was carried out, and it was carried out: restart-alls %d, %d new GETCONF(s)",
			reached, c.Stats().DeafAll, g-len(first))
	}
}

// The same commitment for the monitor's own round: when the wake hook has just
// asked everybody, the monitor's round is not published and its probes are not
// sent — the hook's round stands, with its two probes and no more. Sabotage
// seen red: the monitor probing whether or not its round was published.
func TestTheMonitorDoesNotAskAgainWhenTheWakeHookJustDid(t *testing.T) {
	defer func() { deafVerdictReached = nil }()
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	deafen(c)
	start := time.Now()
	c.lastTick.Store(start.UnixNano())
	c.anyRx.Store(start.UnixNano())
	for s := 5; s <= 25; s += 5 {
		c.monitorStep(start.Add(time.Duration(s) * time.Second))
	}
	reached := 0
	deafVerdictReached = func(a deafAction) {
		if a == deafProbeAll {
			if reached++; reached == 1 {
				c.WakeHealthCheck() // default timings: its watcher's verdict is seconds away, the test is over before
			}
		}
	}
	c.monitorStep(start.Add(30 * time.Second)) // thirty seconds of silence: the monitor wants to ask — the hook just did
	r := c.round.Load()
	if st := c.Stats(); reached != 1 || st.Probes != 2 || r == nil || !r.wake {
		t.Fatalf("reached %d; probes %d (want 2 — the wake hook's round and no second one), the standing round is the hook's: %v",
			reached, st.Probes, r != nil && r.wake)
	}
}

// What the app shows as connections is LIVE, not ready: a worker that reached
// READY_OK once stays ready until something restarts it, and the field screen
// read 30/30 over a dead tunnel. Sabotage seen red: Live counted as Ready.
func TestStatsCountAsLiveOnlyWorkersHeardFromLately(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	if st := c.Stats(); st.Ready != 2 || st.Live != 2 {
		t.Fatalf("two fresh workers: ready %d, live %d — want 2 and 2", st.Ready, st.Live)
	}
	c.workers[0].heardAt.Store(time.Now().Add(-liveWindow - time.Second).UnixNano())
	if st := c.Stats(); st.Ready != 2 || st.Live != 1 {
		t.Fatalf("one worker unheard for longer than the window: ready %d, live %d — want 2 and 1", st.Ready, st.Live)
	}
}

// LIVE is counted from REAL reception (the user's review of 411). The liveness
// clocks restart on a wake and on a late tick without a single packet having
// arrived; read from them, a clock reset alone made two fully deaf workers
// "live" again — Live 0 → 2 with RxBytes unchanged — and the screen showed
// connections until the (never coming) answers. The stats have a stamp of their
// own that only the read loop writes. Sabotages seen red: the wake hook
// stamping it; the late tick's reset stamping it; Live read from the liveness
// clock.
func TestNoClockResetMakesADeafWorkerLive(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	longReady(c)
	longAgo := time.Now().Add(-liveWindow - time.Minute).UnixNano()
	age := func() {
		for _, w := range c.workers {
			w.heardAt.Store(longAgo)
		}
	}

	deafen(c)
	age()
	before := c.Stats()
	if before.Ready != 2 || before.Live != 0 {
		t.Fatalf("two deaf workers unheard for minutes: ready %d, live %d — want 2 and 0", before.Ready, before.Live)
	}
	c.WakeHealthCheck() // clocks reset, probes out — and nothing comes back
	c.lastTick.Store(time.Now().Add(-10 * time.Minute).UnixNano())
	c.monitorStep(time.Now()) // a late tick: clocks reset again
	time.Sleep(50 * time.Millisecond)
	if st := c.Stats(); st.Live != 0 || st.RxBytes != before.RxBytes || st.Descheduled != 1 {
		t.Fatalf("after a wake and a late tick, with not a byte received (rx %d → %d): live %d, want 0 (descheduled %d)",
			before.RxBytes, st.RxBytes, st.Live, st.Descheduled)
	}
	for _, ws := range c.Stats().Workers {
		if time.Since(ws.LastRx) < liveWindow {
			t.Fatalf("worker %d reports its last inbound %s ago — a clock reset, not a packet", ws.ID, time.Since(ws.LastRx).Round(time.Millisecond))
		}
	}
}

// … and a REAL answer does: a healthy client unheard for minutes (a freeze) is
// live again as soon as its wake probes are answered.
func TestARealAnswerMakesAWorkerLiveAgain(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	c := dialReady(t, testConfig(srv, 2, (&lease{}).creds))
	defer c.Close()
	for _, w := range c.workers {
		w.heardAt.Store(time.Now().Add(-liveWindow - time.Minute).UnixNano())
	}
	if st := c.Stats(); st.Live != 0 {
		t.Fatalf("unheard for minutes: live %d, want 0", st.Live)
	}
	c.WakeHealthCheck()
	waitFor(t, "both workers live again on their READY_OK", func() bool { return c.Stats().Live == 2 })
}
