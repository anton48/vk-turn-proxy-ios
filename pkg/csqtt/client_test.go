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
	t       *testing.T
	conn    *net.UDPConn
	Addr    *net.UDPAddr
	cipher  *Cipher
	wrapper *Wrapper
	mu      sync.Mutex
	getconf []getconfSeen
	readies int
	discons int
	closed  chan struct{}
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
			if len(f) >= 6 {
				s.mu.Lock()
				s.getconf = append(s.getconf, getconfSeen{gen: f[3], salt: f[4], worker: f[5]})
				s.mu.Unlock()
			}
			s.reply(from, "TUNCONF:10.66.67.3:77.88.8.8:9000:stream-v2")
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
// full TCP buffer toward a relay would.
type blockableConn struct {
	net.PacketConn
	block   atomic.Bool
	unblock chan struct{}
}

func (b *blockableConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if b.block.Load() {
		<-b.unblock
		return 0, net.ErrClosed
	}
	return b.PacketConn.WriteTo(p, a)
}

// Close returns within its budget even when a write to the relay hangs:
// DISCONNECT is best-effort, the relays are closed, the join is bounded.
// Sabotage seen red: the join budget dropped (Close waits for the hung
// goroutine for ever).
func TestCloseIsBoundedWhenAWriteBlocks(t *testing.T) {
	srv := newFakeServer(t)
	bc := &blockableConn{unblock: make(chan struct{})}
	prev := dialRelay
	dialRelay = func(TURNCredentials, *net.UDPAddr, string, logging.LogLevel) (*Relay, error) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		bc.PacketConn = uc
		return &Relay{Conn: bc, Local: uc.LocalAddr(), close: func() { uc.Close() }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
	c := dialReady(t, testConfig(srv, 1, (&lease{}).creds))
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
