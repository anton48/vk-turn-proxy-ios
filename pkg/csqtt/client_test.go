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
