package csqtt25

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
)

// fakeServer is the server's side of the wire as this package's reference
// describes it, on a loopback socket: a first datagram is tried under the
// password-derived keys, a DTLS record is ignored (so a handshake times
// out), and the control strings are answered.
type fakeServer struct {
	t        *testing.T
	sock     *net.UDPConn
	password string

	mu          sync.Mutex
	sessions    map[string]*fakeSession
	limit       int          // the password's worker limit; 0 = none
	sayWorkers  bool         // TUNCONF carries workers=
	deny        string       // every GETCONF is answered DENIED:<this>
	noconf      bool         // every GETCONF is answered NOCONF: the password is right, the server has no address for it
	denyFirst   int          // …only the first so many
	denyAbove   int          // worker ids above this get DENIED:invalid_worker_count; 0 = off
	muteWorkers bool         // GETWORKERS is not answered: the count is learnt from the refusals alone
	mute        map[int]bool // worker ids the server neither hears nor answers once they are ready
	dropGetconf map[int]bool // worker ids whose GETCONF gets no answer: they stay in their set-up
	echo        bool         // a data packet goes back down the stream it came up
	getconfs    map[int]int  // GETCONF datagrams by worker id
	readys      map[int]int  // READY datagrams by worker id
	unanswered  map[int]int  // GETCONF datagrams it left without an answer (dropGetconf), by worker id
	keepalives  map[int]int
	data        []fakeData
	disconnects []string
	workersAsks int
	dtlsSeen    int
	idents      map[int]string // the identity of each worker's latest GETCONF: generation|salt
}

type fakeSession struct {
	addr   *net.UDPAddr
	worker int
	ready  bool
	send   *Wrapper
	recv   *Cipher
	reasm  *Reassembler
	salt   string
}

type fakeData struct {
	worker int
	pkt    []byte
}

func newFakeServer(t *testing.T, password string) *fakeServer {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, sock: sock, password: password, sessions: map[string]*fakeSession{}, sayWorkers: true,
		mute: map[int]bool{}, dropGetconf: map[int]bool{}, getconfs: map[int]int{}, unanswered: map[int]int{}, readys: map[int]int{}, keepalives: map[int]int{}, idents: map[int]string{}, echo: true}
	t.Cleanup(func() { sock.Close() })
	go s.loop()
	return s
}

func (s *fakeServer) set(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

func (s *fakeServer) reply(ses *fakeSession, plain string, times int) {
	for i := 0; i < times; i++ {
		wire, err := ses.send.Wrap(nil, []byte(plain))
		if err == nil {
			_, _ = s.sock.WriteToUDP(wire, ses.addr)
		}
	}
}

// down sends one IP packet to the client through a session, as fragments
// when it is large.
func (s *fakeServer) down(ses *fakeSession, pkt []byte) {
	parts := [][]byte{pkt}
	if len(pkt) > WholeMax {
		parts = Fragment(uint16(len(s.data)+1), pkt)
	}
	for _, p := range parts {
		if wire, err := ses.send.Wrap(nil, p); err == nil {
			_, _ = s.sock.WriteToUDP(wire, ses.addr)
		}
	}
}

func (s *fakeServer) loop() {
	buf := make([]byte, 4096)
	wrap, _ := WrapKey(s.password)
	keys := WrapKeys(wrap)
	for {
		n, addr, err := s.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		wire := append([]byte(nil), buf[:n]...)
		s.mu.Lock()
		if IsDTLS(wire) {
			s.dtlsSeen++
			s.mu.Unlock()
			continue
		}
		ses := s.sessions[addr.String()]
		if ses == nil {
			recv, _ := NewCipher(keys.Client)
			plain, _, err := recv.Unwrap(append([]byte(nil), wire...))
			if err != nil || !bytes.HasPrefix(plain, []byte("GETCONF:")) {
				s.mu.Unlock()
				continue // silence for keys that do not open
			}
			sendC, _ := NewCipher(keys.Server)
			w, _ := NewWrapper(sendC, ModeUnified)
			ses = &fakeSession{addr: addr, send: w, recv: recv, reasm: NewReassembler()}
			s.sessions[addr.String()] = ses
		}
		plain, _, err := ses.recv.Unwrap(wire)
		if err != nil {
			s.mu.Unlock()
			continue
		}
		s.handle(ses, plain)
		s.mu.Unlock()
	}
}

// handle runs under s.mu.
func (s *fakeServer) handle(ses *fakeSession, plain []byte) {
	text := string(plain)
	if ses.ready && s.mute[ses.worker] {
		if text == ReadyRequest {
			s.readys[ses.worker]++
		}
		return
	}
	switch {
	case strings.HasPrefix(text, "GETCONF:"):
		f := strings.Split(strings.TrimPrefix(text, "GETCONF:"), "|")
		if len(f) != 6 || f[1] != s.password {
			return
		}
		if id, _ := strconv.Atoi(f[4]); s.dropGetconf[id] {
			s.unanswered[id]++
			return
		}
		ses.worker, _ = strconv.Atoi(f[4])
		ses.salt = f[3]
		s.idents[ses.worker] = f[2] + "|" + f[3]
		asked, _ := strconv.Atoi(f[5])
		s.getconfs[ses.worker]++
		total := 0
		for _, n := range s.getconfs {
			total += n
		}
		if s.noconf {
			s.reply(ses, NoConfigResponse, 1)
			return
		}
		switch {
		case s.deny != "" && (s.denyFirst == 0 || total <= s.denyFirst):
			s.reply(ses, "DENIED:"+s.deny, 1)
			return
		case s.denyAbove > 0 && ses.worker > s.denyAbove:
			s.reply(ses, "DENIED:invalid_worker_count", 1)
			return
		}
		agreed := asked
		if s.limit > 0 {
			agreed = s.limit
		}
		conf := "TUNCONF:198.51.100.2:192.0.2.53:" + f[0] + ":stream-v1"
		if s.sayWorkers {
			conf += ":workers=" + strconv.Itoa(agreed)
		}
		s.reply(ses, conf, 2) // the server says it twice
	case text == ReadyRequest:
		ses.ready = true
		s.readys[ses.worker]++
		s.reply(ses, ReadyOK, 1)
	case strings.HasPrefix(text, "GETWORKERS:"):
		s.workersAsks++
		if s.muteWorkers {
			return
		}
		_, count, _ := strings.Cut(strings.TrimPrefix(text, "GETWORKERS:"), "|")
		asked, _ := strconv.Atoi(count)
		agreed := asked
		if s.limit > 0 && agreed > s.limit {
			agreed = s.limit
		}
		s.reply(ses, fmt.Sprintf("TUNWORKERS:%d:%d", agreed, s.limit), 1)
	case strings.HasPrefix(text, "DISCONNECT:"):
		s.disconnects = append(s.disconnects, strings.TrimPrefix(text, "DISCONNECT:"))
		s.reply(ses, DisconnectedResponse, 1)
	case IsIdleKeepalive(plain):
		s.keepalives[ses.worker]++
	default:
		if IsFragment(plain) {
			whole, done := ses.reasm.Push(plain, time.Now())
			if !done {
				return
			}
			plain = whole
		}
		pkt := append([]byte(nil), plain...)
		s.data = append(s.data, fakeData{worker: ses.worker, pkt: pkt})
		if s.echo {
			s.down(ses, pkt)
		}
	}
}

func (s *fakeServer) session(worker int) *fakeSession {
	var found *fakeSession
	for _, ses := range s.sessions {
		if ses.worker == worker && ses.ready {
			found = ses
		}
	}
	return found
}

// knowsReady says whether the server holds a ready session of the worker —
// what say and repair need to reach it.
func (s *fakeServer) knowsReady(worker int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session(worker) != nil
}

// identities is the identity each worker last asked under.
func (s *fakeServer) identities() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]string, len(s.idents))
	for id, v := range s.idents {
		out[id] = v
	}
	return out
}

// say sends an arbitrary plaintext down worker `via`'s stream.
func (s *fakeServer) say(via int, plain []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ses := s.session(via); ses != nil {
		if wire, err := ses.send.Wrap(nil, plain); err == nil {
			_, _ = s.sock.WriteToUDP(wire, ses.addr)
		}
	}
}

// repair sends a STREAM_REPAIR notice naming ids through worker `via`.
func (s *fakeServer) repair(via int, seq uint64, ids ...int) {
	p := append([]byte(nil), streamRepairPrefix...)
	p = binary.BigEndian.AppendUint64(p, seq)
	p = binary.BigEndian.AppendUint16(p, 8)
	p = append(p, byte(len(ids)))
	for _, id := range ids {
		p = binary.BigEndian.AppendUint16(p, uint16(id))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ses := s.session(via); ses != nil {
		if wire, err := ses.send.Wrap(nil, p); err == nil {
			_, _ = s.sock.WriteToUDP(wire, ses.addr)
		}
	}
}

// dialer hands every worker a loopback socket to the fake server and counts.
type dialer struct {
	refuse map[int]int // worker → how many of its next dials fail by themselves
	server net.Addr
	mu     sync.Mutex
	dials  map[int]int
	times  map[int][]time.Time
	closes int
	gates  []*gateConn                             // every socket handed out, when gated is set
	gated  bool                                    // hand out sockets whose writes can be parked
	parkAt bool                                    // …parked from their first write
	hang   map[int]chan bool                       // a dial for this worker blocks until its channel is closed, whatever the context says
	hold   func(workerID, nth int) <-chan struct{} // a worker's nth dial waits for the channel this names and then goes on
	began  map[int]int                             // dials begun, the ones still waiting among them
	deaf   bool                                    // a held dial does not hear its context: let go, it comes back WITH its socket
}

// gateConn is a socket whose writes can be made to park, as a write into a
// full buffer does; a parked write ends when the socket is closed — or, as a
// real socket's does, when the write deadline set before it passes. Its
// writes can also be made to fail with an error of the caller's choosing.
type gateConn struct {
	net.PacketConn
	stuck    atomic.Bool
	parked   atomic.Int32
	released chan struct{}
	once     sync.Once
	deadline atomic.Int64          // the write deadline, unix nanos; 0: none
	sets     atomic.Int32          // SetWriteDeadline calls
	fail     atomic.Pointer[error] // every write fails with this
}

func (g *gateConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if e := g.fail.Load(); e != nil {
		return 0, *e
	}
	if g.stuck.Load() {
		g.parked.Add(1)
		var expired <-chan time.Time
		if dl := g.deadline.Load(); dl != 0 {
			expired = time.After(time.Until(time.Unix(0, dl)))
		}
		select {
		case <-g.released:
			return 0, net.ErrClosed
		case <-expired:
			return 0, &net.OpError{Op: "write", Net: "udp", Err: os.ErrDeadlineExceeded}
		}
	}
	return g.PacketConn.WriteTo(p, a)
}

func (g *gateConn) SetWriteDeadline(t time.Time) error {
	g.sets.Add(1)
	if t.IsZero() {
		g.deadline.Store(0)
	} else {
		g.deadline.Store(t.UnixNano())
	}
	return nil
}

func (g *gateConn) Close() error {
	g.once.Do(func() { close(g.released) })
	return g.PacketConn.Close()
}

func (d *dialer) dial(ctx context.Context, workerID int) (net.PacketConn, net.Addr, func(), error) {
	d.mu.Lock()
	wait := d.hang[workerID]
	if d.began == nil {
		d.began = map[int]int{}
	}
	d.began[workerID]++
	if d.refuse[workerID] > 0 { // this dial fails by itself, at once
		d.refuse[workerID]--
		d.mu.Unlock()
		return nil, nil, nil, errors.New("the relay said no")
	}
	var held <-chan struct{}
	if d.hold != nil {
		held = d.hold(workerID, d.began[workerID])
	}
	deaf := d.deaf
	d.mu.Unlock()
	if held != nil && deaf {
		<-held // the dial that had its answer as it was being ended: it returns a stream all the same
	} else if held != nil {
		select {
		case <-held:
		case <-ctx.Done(): // a held dial is one that waits for its far side: it ends with its context
			return nil, nil, nil, ctx.Err()
		}
	}
	if wait != nil {
		<-wait
		return nil, nil, nil, errors.New("the dial that ignored the stop ended")
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, nil, err
	}
	var conn net.PacketConn = udp
	d.mu.Lock()
	if d.gated {
		g := &gateConn{PacketConn: udp, released: make(chan struct{})}
		g.stuck.Store(d.parkAt)
		d.gates = append(d.gates, g)
		conn = g
	}
	d.dials[workerID]++
	if d.times == nil {
		d.times = map[int][]time.Time{}
	}
	d.times[workerID] = append(d.times[workerID], time.Now())
	d.mu.Unlock()
	return conn, d.server, func() {
		d.mu.Lock()
		d.closes++
		d.mu.Unlock()
		conn.Close()
	}, nil
}

func (d *dialer) count(workerID int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[workerID]
}

// begun is how many dials the worker has started, a held one among them.
func (d *dialer) begun(workerID int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.began[workerID]
}

func (d *dialer) setHold(f func(workerID, nth int) <-chan struct{}) {
	d.mu.Lock()
	d.hold = f
	d.mu.Unlock()
}

// quickClocks shortens the client's clocks for a test.
func quickClocks(t *testing.T) {
	t.Helper()
	old := []any{getconfWaits, keepaliveEvery, probeAfter, deafAfter, serveTick, backoffBase, backoffMax, heldAfter, disconnectWait, handshakeTimeout, stopWait}
	stopWait = 500 * time.Millisecond
	getconfWaits = []time.Duration{150 * time.Millisecond, 150 * time.Millisecond}
	keepaliveEvery, probeAfter, deafAfter = 10*time.Second, 20*time.Second, 60*time.Second
	serveTick, backoffBase, backoffMax, heldAfter = 20*time.Millisecond, 30*time.Millisecond, 100*time.Millisecond, 10*time.Second
	disconnectWait, handshakeTimeout = 300*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		getconfWaits = old[0].([]time.Duration)
		keepaliveEvery, probeAfter, deafAfter = old[1].(time.Duration), old[2].(time.Duration), old[3].(time.Duration)
		serveTick, backoffBase, backoffMax, heldAfter = old[4].(time.Duration), old[5].(time.Duration), old[6].(time.Duration), old[7].(time.Duration)
		disconnectWait, handshakeTimeout = old[8].(time.Duration), old[9].(time.Duration)
		stopWait = old[10].(time.Duration)
	})
}

type delivered struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (d *delivered) take(p []byte) {
	d.mu.Lock()
	d.pkts = append(d.pkts, append([]byte(nil), p...))
	d.mu.Unlock()
}

func (d *delivered) n() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pkts)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

func startClient(t *testing.T, srv *fakeServer, workers int, keys KeyMode) (*Client, *dialer, *delivered) {
	t.Helper()
	return startClientCfg(t, srv, workers, keys, nil)
}

// startClientCfg is startClient with a hand on the config.
func startClientCfg(t *testing.T, srv *fakeServer, workers int, keys KeyMode, tweak func(*ClientConfig)) (*Client, *dialer, *delivered) {
	t.Helper()
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	got := &delivered{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := ClientConfig{Password: srv.password, Workers: workers, Keys: keys, Dial: d.dial, Deliver: got.take}
	if tweak != nil {
		tweak(&cfg)
	}
	c, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(c.Close)
	return c, d, got
}

// seqPkt is a packet of a flow that carries its number in its payload.
func seqPkt(sport uint16, seq, n int) []byte {
	p := pkt4(6, sport, n)
	binary.BigEndian.PutUint32(p[24:28], uint32(seq))
	return p
}

// N workers come up under ONE identity, a flow's packets reach the server in
// the order they were sent and on one stream inside a burst, the echoes come
// back to Deliver, and a packet above 1280 bytes travels as fragments on one
// stream in both directions.
func TestTheClientBringsUpItsWorkersAndCarriesPackets(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-engine")
	c, d, got := startClient(t, srv, 4, KeysWrap)
	eventually(t, "four workers ready", func() bool { return c.Stats().Ready == 4 })
	if conf := c.Config(); conf.TunnelIP != "198.51.100.2" || conf.Stream != "stream-v1" || conf.Workers != 4 {
		t.Fatalf("configuration %+v", conf)
	}
	srv.mu.Lock()
	for id := 1; id <= 4; id++ {
		if d.count(id) != 1 {
			t.Fatalf("worker %d dialled %d times", id, d.count(id))
		}
		if srv.getconfs[id] != 2 {
			t.Fatalf("worker %d asked for its configuration %d time(s); the request goes out twice", id, srv.getconfs[id])
		}
		if srv.readys[id] != 1 {
			t.Fatalf("worker %d said READY %d time(s)", id, srv.readys[id])
		}
	}
	if srv.dtlsSeen != 0 {
		t.Fatalf("with password-derived keys asked for, %d DTLS record(s) were sent", srv.dtlsSeen)
	}
	srv.mu.Unlock()
	const n = 40
	for i := 0; i < n; i++ { // 40 × 266 bytes: inside one burst
		if err := c.Send(seqPkt(5555, i, 200)); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	eventually(t, "the flow at the server", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.data) == n })
	srv.mu.Lock()
	first := srv.data[0].worker
	for i, dp := range srv.data {
		if dp.worker != first {
			t.Fatalf("packet %d of the flow came through worker %d, the flow began on %d", i, dp.worker, first)
		}
		if seq := int(binary.BigEndian.Uint32(dp.pkt[24:28])); seq != i {
			t.Fatalf("packet %d at the server carries number %d", i, seq)
		}
	}
	salts := map[string]bool{}
	for _, ses := range srv.sessions {
		salts[ses.salt] = true
	}
	srv.mu.Unlock()
	if len(salts) != 1 {
		t.Fatalf("the four workers announced %d identities", len(salts))
	}
	eventually(t, "the echoes delivered", func() bool { return got.n() == n })

	big := seqPkt(6666, 7, 1400)
	if err := c.Send(big); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the large packet back", func() bool { return got.n() == n+1 })
	got.mu.Lock()
	back := got.pkts[n]
	got.mu.Unlock()
	if !bytes.Equal(back, big) {
		t.Fatal("the large packet came back changed")
	}
	if st := c.Stats(); st.FragsTx != 2 || st.FragsRx != 2 || st.TxPackets < n+2 || st.RxPackets != n+1 || st.AuthFailures != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// A long flow moves between streams, and on every stream its packets stay
// in the order they were sent.
func TestALongFlowMovesAndStaysOrderedOnEveryStream(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-bursts")
	srv.set(func() { srv.echo = false })
	c, _, _ := startClient(t, srv, 4, KeysWrap)
	eventually(t, "four workers ready", func() bool { return c.Stats().Ready == 4 })
	const n = 120 // 120 × 1266 bytes ≈ nine bursts
	for i := 0; i < n; i++ {
		if err := c.Send(seqPkt(7777, i, 1200)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the flow at the server", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.data) == n })
	srv.mu.Lock()
	defer srv.mu.Unlock()
	last := map[int]int{}
	used := map[int]bool{}
	for _, dp := range srv.data {
		seq := int(binary.BigEndian.Uint32(dp.pkt[24:28]))
		if prev, ok := last[dp.worker]; ok && seq <= prev {
			t.Fatalf("worker %d carried packet %d after packet %d", dp.worker, seq, prev)
		}
		last[dp.worker] = seq
		used[dp.worker] = true
	}
	if len(used) < 3 {
		t.Fatalf("nine bursts of one flow used %d stream(s) of 4", len(used))
	}
}

// The server's worker count is followed: a limit below what was asked parks
// the workers above it before they dial.
func TestTheClientFollowsTheAgreedWorkerCount(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-limit")
	srv.set(func() { srv.limit = 3 })
	c, d, _ := startClient(t, srv, 6, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	time.Sleep(300 * time.Millisecond)
	st := c.Stats()
	if st.Ready != 3 || st.Target != 3 || st.Workers != 6 {
		t.Fatalf("stats %+v", st)
	}
	for id := 4; id <= 6; id++ {
		if d.count(id) != 0 {
			t.Fatalf("worker %d, above the agreed count, dialled %d time(s)", id, d.count(id))
		}
	}
	srv.mu.Lock()
	asks := srv.workersAsks
	srv.mu.Unlock()
	if asks != 1 {
		t.Fatalf("GETWORKERS was sent %d time(s), by more than worker 1 or not at all", asks)
	}
	// Packets go only through the workers that are left.
	for i := 0; i < 30; i++ {
		_ = c.Send(seqPkt(uint16(9000+i), i, 100))
	}
	eventually(t, "thirty flows at the server", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.data) == 30 })
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, dp := range srv.data {
		if dp.worker > 3 {
			t.Fatalf("a packet went through worker %d", dp.worker)
		}
	}
}

// A worker the server refuses for its number is parked, not asked again and
// again; the ones below it carry on.
//
// The server here says no count at all — neither in its configuration nor to
// GETWORKERS: the refusals are all the client has. (A server that refused
// worker 3 and then answered GETWORKERS with four would raise the count back
// behind the refusals whenever its answer came last, and the refused workers
// would dial once more: the fake did, and under load that order came up.)
func TestAWorkerRefusedForItsNumberIsParked(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-above")
	srv.set(func() { srv.sayWorkers, srv.denyAbove, srv.muteWorkers = false, 2, true })
	c, d, _ := startClient(t, srv, 4, KeysWrap)
	eventually(t, "the count settles at two", func() bool { st := c.Stats(); return st.Ready == 2 && st.Target == 2 })
	time.Sleep(400 * time.Millisecond)
	if n := d.count(3) + d.count(4); n > 2 {
		t.Fatalf("the refused workers dialled %d times in all", n)
	}
	if st := c.Stats(); st.Ready != 2 {
		t.Fatalf("stats %+v", st)
	}
}

// A denial that asking again cannot change ends the client, and Dial says
// which; one that may pass is asked again.
func TestDenials(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-denied")
	srv.set(func() { srv.deny = "expired" })
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 2, Keys: KeysWrap, Dial: d.dial})
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Reason != "expired" {
		t.Fatalf("Dial under DENIED:expired returned %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if d.count(1) != 1 || d.count(2) != 0 {
		t.Fatalf("after a fatal denial the workers dialled %d and %d time(s)", d.count(1), d.count(2))
	}

	busy := newFakeServer(t, "pw-busy")
	busy.set(func() { busy.deny, busy.denyFirst = "server_busy", 2 })
	c, d2, _ := startClient(t, busy, 1, KeysWrap)
	eventually(t, "ready after the busy answers", func() bool { return c.Stats().Ready == 1 })
	if d2.count(1) < 2 {
		t.Fatalf("worker 1 came up on dial %d although its first was refused", d2.count(1))
	}
}

// A stream that falls silent is asked, and replaced when it stays silent; an
// idle stream that answers is left alone.
func TestASilentStreamIsAskedAndReplaced(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 150*time.Millisecond, 500*time.Millisecond
	srv := newFakeServer(t, "pw-silent")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	srv.set(func() { srv.mute[2] = true })
	eventually(t, "worker 2 dialled again", func() bool { return d.count(2) >= 2 })
	srv.mu.Lock()
	asked := srv.readys[2]
	srv.mu.Unlock()
	if asked < 2 {
		t.Fatalf("the silent stream was replaced after %d READY in all — it was never asked", asked)
	}
	if d.count(1) != 1 {
		t.Fatalf("the idle stream that answers was replaced (%d dials)", d.count(1))
	}
	if st := c.Stats(); st.Probes == 0 {
		t.Fatalf("stats %+v", st)
	}
}

// A repair notice restarts the ready worker it names, once.
func TestARepairNoticeRestartsTheWorkerItNames(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-repair")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	srv.repair(1, 5, 2)
	eventually(t, "worker 2 dialled again", func() bool { return d.count(2) == 2 })
	eventually(t, "three workers ready again", func() bool { return c.Stats().Ready == 3 })
	srv.repair(1, 5, 2) // the same notice, repeated
	srv.repair(1, 4, 3) // an older one
	srv.repair(1, 6, 7) // a newer one, about a worker this client does not have
	time.Sleep(300 * time.Millisecond)
	if d.count(1) != 1 || d.count(2) != 2 || d.count(3) != 1 {
		t.Fatalf("dials after a repeated and an old notice: %d %d %d", d.count(1), d.count(2), d.count(3))
	}
	if st := c.Stats(); st.Repairs != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// An idle stream says it is there; Close tells the server under the
// session's own salt and gives every socket back.
func TestKeepalivesAndClose(t *testing.T) {
	quickClocks(t)
	keepaliveEvery = 80 * time.Millisecond
	srv := newFakeServer(t, "pw-close")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	eventually(t, "keepalives from both", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.keepalives[1] >= 2 && srv.keepalives[2] >= 2
	})
	srv.mu.Lock()
	var salt string
	for _, ses := range srv.sessions {
		salt = ses.salt
	}
	srv.mu.Unlock()
	c.Close()
	srv.mu.Lock()
	said := append([]string(nil), srv.disconnects...)
	srv.mu.Unlock()
	if len(said) == 0 || said[0] != srv.password+"|"+salt {
		t.Fatalf("DISCONNECT at the server: %d, not under the session's password and salt", len(said))
	}
	d.mu.Lock()
	dials, closes := 0, d.closes
	for _, n := range d.dials {
		dials += n
	}
	d.mu.Unlock()
	if dials != closes {
		t.Fatalf("%d sockets dialled, %d given back", dials, closes)
	}
	if err := c.Send(seqPkt(1, 1, 100)); !errors.Is(err, ErrNoStream) {
		t.Fatalf("Send after Close: %v", err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done is open after Close")
	}
}

// In auto mode a server that does not answer the handshake is reached with
// password-derived keys; in dtls mode it is not reached at all.
func TestAutoFallsBackAndDTLSDoesNot(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-auto")
	c, _, _ := startClient(t, srv, 2, KeysAuto)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	if st := c.Stats(); st.Fallbacks != 2 || st.Handshakes != 0 {
		t.Fatalf("stats %+v", st)
	}
	srv.mu.Lock()
	seen := srv.dtlsSeen
	srv.mu.Unlock()
	if seen == 0 {
		t.Fatal("auto mode sent no ClientHello before it fell back")
	}

	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if _, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 1, Keys: KeysDTLS, Dial: d.dial}); err == nil {
		t.Fatal("dtls mode reached a server that answers no handshake")
	}
}

func TestParseStreamRepair(t *testing.T) {
	p := append([]byte(nil), streamRepairPrefix...)
	p = binary.BigEndian.AppendUint64(p, 9)
	p = binary.BigEndian.AppendUint16(p, 36)
	p = append(p, 2)
	p = binary.BigEndian.AppendUint16(p, 14)
	p = binary.BigEndian.AppendUint16(p, 28)
	cmd, ok := ParseStreamRepair(p)
	if !ok || cmd.Sequence != 9 || cmd.Desired != 36 || len(cmd.Workers) != 2 || cmd.Workers[0] != 14 || cmd.Workers[1] != 28 {
		t.Fatalf("%+v %v", cmd, ok)
	}
	if _, ok := ParseStreamAlive(p); ok {
		t.Fatal("a repair notice parsed as an alive one")
	}
	bad := func(mut func([]byte)) (taken bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("a malformed notice was sliced: %v", r)
				taken = true
			}
		}()
		q := append([]byte(nil), p...)
		mut(q)
		_, ok := ParseStreamRepair(q)
		return ok
	}
	n := len(streamRepairPrefix)
	if bad(func(q []byte) { binary.BigEndian.PutUint64(q[n:], 0) }) {
		t.Fatal("sequence 0 taken")
	}
	if bad(func(q []byte) { binary.BigEndian.PutUint16(q[n+8:], 101) }) {
		t.Fatal("a count above the most workers taken")
	}
	if bad(func(q []byte) { q[n+10] = 3 }) {
		t.Fatal("a count that disagrees with the length taken")
	}
	if bad(func(q []byte) { binary.BigEndian.PutUint16(q[n+11:], 37) }) {
		t.Fatal("a worker id above the desired count taken")
	}
	if bad(func(q []byte) { binary.BigEndian.PutUint16(q[n+11:], 0) }) {
		t.Fatal("worker id 0 taken")
	}
	if _, ok := ParseStreamRepair(p[:n+10]); ok {
		t.Fatal("a short notice taken")
	}
}

// What is not an IP packet never reaches Deliver — a control string whose
// first byte reads as an IP version least of all.
func TestOnlyIPPacketsAreDelivered(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-deliver")
	c, _, got := startClient(t, srv, 1, KeysWrap)
	eventually(t, "the worker ready", func() bool { return c.Stats().Ready == 1 })
	time.Sleep(100 * time.Millisecond) // the second TUNCONF, READY_OK, TUNWORKERS
	for _, p := range [][]byte{
		[]byte("OK:disconnected"),    // 'O' = 0x4f: version 4
		[]byte("DENIED:server_busy"), // 'D' = 0x44
		[]byte("NOCONF"),             // 'N' = 0x4e
		[]byte("ROUTING:START:3"),
		{0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		{0xff, 0xff, 0xff, 0xff},
	} {
		srv.say(1, p)
	}
	time.Sleep(200 * time.Millisecond)
	if n := got.n(); n != 0 {
		t.Fatalf("%d thing(s) that are not IP packets were delivered", n)
	}
	srv.say(1, seqPkt(1, 1, 60))
	eventually(t, "an IP packet delivered", func() bool { return got.n() == 1 })
}

// A worker still in its set-up is neither restarted by a repair notice nor
// given packets.
func TestAWorkerInItsSetUpIsLeftAlone(t *testing.T) {
	quickClocks(t)
	getconfWaits = []time.Duration{2 * time.Second}
	srv := newFakeServer(t, "pw-setup")
	srv.set(func() { srv.echo = false })
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	srv.set(func() { srv.dropGetconf[2] = true })
	srv.repair(1, 1, 2)
	eventually(t, "worker 2 back in its set-up", func() bool { return d.count(2) == 2 && c.Stats().Ready == 1 })
	srv.repair(1, 2, 2) // names a worker that is not ready
	for i := 0; i < 30; i++ {
		if err := c.Send(seqPkt(uint16(3000+i), i, 100)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "thirty flows at the server", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.data) == 30 })
	time.Sleep(200 * time.Millisecond)
	if st := c.Stats(); st.Repairs != 1 {
		t.Fatalf("a notice about a worker in its set-up was acted on: %+v", st)
	}
	if d.count(2) != 2 {
		t.Fatalf("worker 2 dialled %d times", d.count(2))
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, dp := range srv.data {
		if dp.worker != 1 {
			t.Fatalf("a packet went through the stream of worker %d, which is not ready", dp.worker)
		}
	}
}

// A repair notice left over from a session that ended meanwhile is not about
// the next one.
func TestAStaleRepairDoesNotEndTheNextSession(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-stale")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	w := c.workers[1]
	w.kick <- errRepair // ends the session
	eventually(t, "worker 2 between sessions", func() bool { return !w.ready.Load() })
	w.end(errRepair) // left behind while nobody listens
	eventually(t, "worker 2 ready again", func() bool { return w.ready.Load() })
	time.Sleep(300 * time.Millisecond)
	if d.count(2) != 2 || !w.ready.Load() {
		t.Fatalf("worker 2 dialled %d times: the stale notice ended its new session", d.count(2))
	}
}

// A lower count that the server says AFTER the workers are up parks the
// ones above it.
func TestALaterLowerCountParksTheWorkersAboveIt(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-shrink")
	c, d, _ := startClient(t, srv, 5, KeysWrap)
	eventually(t, "five workers ready", func() bool { return c.Stats().Ready == 5 })
	srv.say(1, []byte("TUNWORKERS:2:2"))
	eventually(t, "the count settles at two", func() bool { st := c.Stats(); return st.Target == 2 && st.Ready == 2 })
	time.Sleep(300 * time.Millisecond)
	if st := c.Stats(); st.Ready != 2 {
		t.Fatalf("stats %+v", st)
	}
	for id := 3; id <= 5; id++ {
		if d.count(id) != 1 {
			t.Fatalf("parked worker %d dialled %d times", id, d.count(id))
		}
	}
}

// The agreed count's bounds, and a refusal that can only lower it.
func TestTheAgreedCountsBounds(t *testing.T) {
	c := &Client{cfg: ClientConfig{Workers: 4, Logf: func(string, ...any) {}}, target: 4}
	c.lowerTarget(2)
	c.lowerTarget(3) // the higher worker's refusal, arriving second
	if got := c.targetNow(); got != 2 {
		t.Fatalf("a later refusal of a higher worker moved the count to %d", got)
	}
	c.setTarget(3) // the server's own word may raise it
	if got := c.targetNow(); got != 3 {
		t.Fatalf("the server's count was not followed up: %d", got)
	}
	c.setTarget(99)
	if got := c.targetNow(); got != 4 {
		t.Fatalf("the count went above what was asked: %d", got)
	}
	c.setTarget(0)
	if got := c.targetNow(); got != 1 {
		t.Fatalf("the count went below one: %d", got)
	}
}

// The wait before a new session grows while sessions fail and starts over
// after one that held.
func TestTheBackOffGrowsAndASessionThatHeldEndsIt(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax, heldAfter = 40*time.Millisecond, 5*time.Second, 50*time.Millisecond

	// Failing at once, again and again: every wait longer than the one before.
	busy := newFakeServer(t, "pw-grow")
	busy.set(func() { busy.deny, busy.denyFirst = "server_busy", 8 })
	c, d, _ := startClient(t, busy, 1, KeysWrap)
	eventually(t, "ready after the busy answers", func() bool { return c.Stats().Ready == 1 })
	d.mu.Lock()
	times := append([]time.Time(nil), d.times[1]...)
	d.mu.Unlock()
	if len(times) < 4 {
		t.Fatalf("the fixture: only %d dials", len(times))
	}
	first, third := times[1].Sub(times[0]), times[3].Sub(times[2])
	if third < first*2 {
		t.Fatalf("the waits did not grow: %s, then %s two failures later", first, third)
	}

	// Ended six times, each after it had held: every wait is the first one.
	srv := newFakeServer(t, "pw-held")
	c2, d2, _ := startClient(t, srv, 2, KeysWrap)
	began := time.Now()
	for k := 0; k < 6; k++ {
		eventually(t, "two workers ready", func() bool { return c2.Stats().Ready == 2 })
		time.Sleep(70 * time.Millisecond) // longer than heldAfter
		srv.repair(1, uint64(k+1), 2)
		eventually(t, "worker 2 dialled again", func() bool { return d2.count(2) == k+2 })
	}
	if took := time.Since(began); took > 1500*time.Millisecond {
		t.Fatalf("six sessions that held were followed by waits that kept growing: %s in all", took)
	}
}

// within runs f and fails the test when f has not returned in time; the
// test itself never waits on what it is checking.
func within(t *testing.T, limit time.Duration, what string, f func()) time.Duration {
	t.Helper()
	done := make(chan struct{})
	began := time.Now()
	go func() { f(); close(done) }()
	select {
	case <-done:
		return time.Since(began)
	case <-time.After(limit):
		t.Fatalf("%s did not return within %s", what, limit)
		return 0
	}
}

// A write parked in a stream's socket does not hold the stop: Close has ONE
// budget for telling the server and one for the workers to end, and the
// stop itself releases every socket.
func TestCloseIsBoundedWhenAWriteIsParked(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-parked")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}, gated: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 2, Keys: KeysWrap, Dial: d.dial})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	d.mu.Lock()
	gates := append([]*gateConn(nil), d.gates...)
	d.mu.Unlock()
	t.Cleanup(func() { // whatever happens, let every parked goroutine go
		for _, g := range gates {
			g.Close()
		}
	})
	for _, g := range gates {
		g.stuck.Store(true)
	}
	for i := 0; i < 2; i++ { // one writer parked in each stream, holding the stream's lock
		go func(i int) { _ = c.Send(seqPkt(uint16(100+i), i, 100)) }(i)
	}
	eventually(t, "a write parked in each socket", func() bool { return gates[0].parked.Load() > 0 && gates[1].parked.Load() > 0 })
	took := within(t, 4*time.Second, "Close with a write parked in every stream", c.Close)
	if limit := disconnectWait + stopWait + 300*time.Millisecond; took > limit {
		t.Fatalf("Close took %s; its budgets add up to %s", took, limit)
	}
	eventually(t, "every socket given back", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.closes == 2
	})
}

// Dial's deadline holds although the first write of the first stream is
// parked.
func TestDialsDeadlineHoldsWhenTheFirstWriteIsParked(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-parked-dial")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}, gated: true, parkAt: true}
	t.Cleanup(func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, g := range d.gates {
			g.Close()
		}
	})
	var err error
	took := within(t, 4*time.Second, "Dial with its first write parked", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err = Dial(ctx, ClientConfig{Password: srv.password, Workers: 2, Keys: KeysWrap, Dial: d.dial})
	})
	if err == nil {
		t.Fatal("Dial returned a client although nothing was ever written")
	}
	if limit := 200*time.Millisecond + stopWait + 300*time.Millisecond; took > limit {
		t.Fatalf("Dial returned after %s; its deadline and the stop's budget add up to %s", took, limit)
	}
	eventually(t, "the socket of the parked write given back", func() bool {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.dials[1] == 1 && d.closes == 1
	})
}

// Close does not wait for a dial that ignores the stop.
func TestCloseDoesNotWaitForADialThatIgnoresTheStop(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-hung-dial")
	never := make(chan bool)
	t.Cleanup(func() { close(never) })
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}, hang: map[int]chan bool{2: never}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 2, Keys: KeysWrap, Dial: d.dial})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "worker 1 ready", func() bool { return c.Stats().Ready == 1 })
	took := within(t, 4*time.Second, "Close beside a dial that never returns", c.Close)
	if limit := disconnectWait + stopWait + 300*time.Millisecond; took > limit {
		t.Fatalf("Close took %s; its budgets add up to %s", took, limit)
	}
}

// sayWhere sends a plaintext down every stream the predicate picks.
func (s *fakeServer) sayWhere(plain []byte, pick func(*fakeSession) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ses := range s.sessions {
		if !pick(ses) {
			continue
		}
		if wire, err := ses.send.Wrap(nil, plain); err == nil {
			_, _ = s.sock.WriteToUDP(wire, ses.addr)
		}
	}
}

// announceRestart is the server saying, on every stream it has heard from,
// that it is about to restart. It goes on answering until forget — the real
// one does for three quarters of a second.
func (s *fakeServer) announceRestart() {
	s.sayWhere(panelRestartNotice, func(*fakeSession) bool { return true })
}

// forget is the server that came back: it knows none of the old streams.
func (s *fakeServer) forget() {
	s.mu.Lock()
	s.sessions = map[string]*fakeSession{}
	s.mu.Unlock()
}

// restartPanel is the server restarting with nothing between the two: it
// says so on every stream and then knows none of them.
func (s *fakeServer) restartPanel() {
	s.announceRestart()
	s.forget()
}

// The server's restart notice starts every worker over at once: the server
// that comes back knows none of the old streams, and waiting to find that
// out by their silence costs a minute.
func TestAPanelRestartStartsEveryWorkerOver(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-panel")
	c, d, got := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	srv.restartPanel()
	eventually(t, "every worker dialled again", func() bool { return d.count(1) == 2 && d.count(2) == 2 && d.count(3) == 2 })
	eventually(t, "three workers ready again", func() bool { return c.Stats().Ready == 3 })
	if st := c.Stats(); st.PanelRestarts != 1 {
		t.Fatalf("one restart, said on three streams, was counted %d time(s)", st.PanelRestarts)
	}
	select {
	case <-c.Done():
		t.Fatal("the client ended at the server's restart")
	default:
	}
	// The same restart, said again a moment later, is the same restart.
	c.panelRestart()
	time.Sleep(200 * time.Millisecond)
	if st := c.Stats(); st.PanelRestarts != 1 || d.count(1) != 2 {
		t.Fatalf("a repeated notice started the workers over again: %+v, worker 1 dialled %d times", st, d.count(1))
	}
	// And the tunnel carries packets again.
	if err := c.Send(seqPkt(4242, 1, 100)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a packet through the restarted server", func() bool { return got.n() == 1 })
}

func TestIsPanelRestartIsExact(t *testing.T) {
	if !IsPanelRestart(panelRestartNotice) {
		t.Fatal("the notice itself")
	}
	off := append([]byte(nil), panelRestartNotice...)
	off[len(off)-1] ^= 1
	if IsPanelRestart(off) || IsPanelRestart(panelRestartNotice[:len(panelRestartNotice)-1]) || IsPanelRestart(append(append([]byte(nil), panelRestartNotice...), 0)) {
		t.Fatal("something else read as the restart notice")
	}
}

// registered says which of the workers the server holds a ready stream of.
func (s *fakeServer) registered(ids ...int) map[int]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int]bool{}
	for _, id := range ids {
		out[id] = s.session(id) != nil
	}
	return out
}

// A restart notice that comes while a worker is still setting its stream up
// is about that stream too. The server that says it is restarting goes on
// answering for a moment, so the set-up completes — against a server that
// is about to forget it; the worker must start over like the ready ones,
// or it stays ready here on a stream the server that came back never heard
// of, and everything the dispatcher hands it is lost.
func TestARestartNoticeReachesAWorkerInItsSetUp(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "restart-in-set-up")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })

	across := make(chan struct{}) // worker 3's second dial: in flight across the notice
	behind := make(chan struct{}) // every dial behind the notice: until the server is back
	var acrossOnce, behindOnce sync.Once
	letAcross := func() { acrossOnce.Do(func() { close(across) }) }
	letBehind := func() { behindOnce.Do(func() { close(behind) }) }
	t.Cleanup(func() { letAcross(); letBehind() })
	d.setHold(func(workerID, nth int) <-chan struct{} {
		switch {
		case workerID == 3 && nth == 2:
			return across
		case nth >= 2:
			return behind
		}
		return nil
	})

	w3 := c.workers[2]
	w3.kick <- errRepair // its session ends and the next one waits inside its dial
	eventually(t, "worker 3 inside its second dial", func() bool { return d.begun(3) == 2 })
	srv.announceRestart()
	eventually(t, "the restart notice heard", func() bool { return c.Stats().PanelRestarts == 1 })
	letAcross()
	// The set-up the notice overlapped is over one of two ways: the worker
	// dials again, or the old server has been told READY once more.
	eventually(t, "worker 3 past the set-up the notice overlapped", func() bool {
		srv.mu.Lock()
		readys := srv.readys[3]
		srv.mu.Unlock()
		return d.begun(3) == 3 || readys >= 2
	})
	srv.forget()
	letBehind()

	deadline := time.Now().Add(3 * time.Second)
	for {
		reg := srv.registered(1, 2, 3)
		if reg[1] && reg[2] && reg[3] && c.Stats().Ready == 3 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the restart: worker 3 dialled %d times (3 = it started over), ready here: %v, known to the server that came back: %v (workers 1, 2: %v, %v)",
				d.begun(3), w3.ready.Load(), reg[3], reg[1], reg[2])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// inItsWait brings worker 2 into a configuration wait that nothing answers.
func inItsWait(t *testing.T, srv *fakeServer, c *Client, d *dialer) {
	t.Helper()
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	srv.set(func() { srv.dropGetconf[2] = true })
	c.workers[1].kick <- errRepair
	eventually(t, "worker 2 waiting for a configuration", func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.unanswered[2] >= 1
	})
	srv.set(func() { srv.dropGetconf[2] = false }) // the next ask is answered
}

// A notice that finds a worker waiting for its configuration ends the wait
// there and then: sitting the wait out — seconds on the real schedule —
// only to start over is time the tunnel is short of a stream.
func TestARestartNoticeEndsAConfigurationWaitAtOnce(t *testing.T) {
	quickClocks(t)
	getconfWaits = []time.Duration{3 * time.Second}
	srv := newFakeServer(t, "restart-in-the-wait")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	inItsWait(t, srv, c, d)
	if d.count(2) != 2 {
		t.Fatalf("the fixture: worker 2 dialled %d times before the notice, want 2", d.count(2))
	}
	said := time.Now()
	srv.say(1, panelRestartNotice) // heard on worker 1's stream alone
	eventually(t, "worker 2 dialling again", func() bool { return d.count(2) == 3 })
	if took := time.Since(said); took > time.Second {
		t.Fatalf("worker 2 dialled again %v after the notice: it sat its configuration wait out", took.Round(10*time.Millisecond))
	}
	eventually(t, "both workers ready again", func() bool { return c.Stats().Ready == 2 })
}

// The notice may come down the very stream that is still being set up — the
// only one there is while the first worker dials, and every one when all of
// them start over together. It is the same notice.
func TestARestartNoticeOnAStreamInItsSetUpIsHeard(t *testing.T) {
	quickClocks(t)
	getconfWaits = []time.Duration{3 * time.Second}
	srv := newFakeServer(t, "restart-on-its-own-stream")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	inItsWait(t, srv, c, d)
	said := time.Now()
	srv.sayWhere(panelRestartNotice, func(ses *fakeSession) bool { return !ses.ready }) // worker 2's new stream alone
	eventually(t, "both workers dialling again", func() bool { return d.count(1) == 2 && d.count(2) == 3 })
	if took := time.Since(said); took > time.Second {
		t.Fatalf("the workers dialled again %v after the notice: it was not the notice that moved them", took.Round(10*time.Millisecond))
	}
	if st := c.Stats(); st.PanelRestarts != 1 {
		t.Fatalf("server restarts counted: %d, want 1", st.PanelRestarts)
	}
	eventually(t, "both workers ready again", func() bool { return c.Stats().Ready == 2 })
}

// settleClocks shortens the clocks of the rule for streams set up around a
// server restart.
func settleClocks(t *testing.T, settle, ask, give time.Duration) {
	t.Helper()
	a, b, c := restartSettle, settleProbeAfter, settleDeafAfter
	restartSettle, settleProbeAfter, settleDeafAfter = settle, ask, give
	t.Cleanup(func() { restartSettle, settleProbeAfter, settleDeafAfter = a, b, c })
}

// Which streams are not yet known to be on the server that came back.
func TestWhichStreamsAreUnsettledBehindARestartNotice(t *testing.T) {
	settleClocks(t, 15*time.Second, 2*time.Second, 5*time.Second)
	at := time.Now()
	c := &Client{}
	if c.unsettled(at) {
		t.Fatal("without a restart notice a stream is unsettled")
	}
	c.panelAt = at
	for _, row := range []struct {
		heard time.Duration // after the notice
		want  bool
	}{
		{-time.Second, true}, // heard before the notice: the server that is about to go
		{time.Second, true},
		{15*time.Second - time.Millisecond, true},
		{15 * time.Second, false}, // later than the old server can have answered
		{time.Hour, false},
	} {
		if got := c.unsettled(at.Add(row.heard)); got != row.want {
			t.Errorf("a stream last heard %v after the notice: unsettled = %v, want %v", row.heard, got, row.want)
		}
	}
}

// Starting over on the notice is right only if the server is gone by the
// time a worker asks again — and it answers until it is. A stream it takes
// back behind its own notice is forgotten with it: ready here, unknown to
// the server that came back. Such a stream is found out by a short silence,
// not by the minute an ordinary one is given; and once a stream has heard
// the server later than the old one can have answered, it is an ordinary
// stream again.
func TestAStreamTakenBackByTheServerThatIsAboutToGoIsFoundOutSoon(t *testing.T) {
	quickClocks(t)
	settleClocks(t, 1500*time.Millisecond, 60*time.Millisecond, 250*time.Millisecond)
	srv := newFakeServer(t, "restart-slow-to-go")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })

	said := time.Now()
	srv.announceRestart() // …and it goes on answering
	eventually(t, "both workers taken back by the server that is about to go", func() bool {
		srv.mu.Lock()
		r1, r2 := srv.readys[1], srv.readys[2]
		srv.mu.Unlock()
		return d.count(1) == 2 && d.count(2) == 2 && r1 >= 2 && r2 >= 2 && c.Stats().Ready == 2
	})
	srv.forget() // the server that came back knows neither
	went := time.Now()
	for {
		reg := srv.registered(1, 2)
		if reg[1] && reg[2] && c.Stats().Ready == 2 {
			break
		}
		if time.Since(went) > 2*time.Second {
			t.Fatalf("%v after the old server went: workers 1, 2 dialled %d, %d times (3 = found out), ready here: %d, known to the server that came back: %v, %v",
				time.Since(went).Round(10*time.Millisecond), d.count(1), d.count(2), c.Stats().Ready, reg[1], reg[2])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := c.Stats(); st.Unsettled != 2 {
		t.Fatalf("streams replaced for their silence behind the notice: %d, want 2 (which rule found them out?)", st.Unsettled)
	}

	// Past the settle time the streams have heard the server that came back:
	// the asking stops and nobody is replaced.
	for time.Since(said) < restartSettle+300*time.Millisecond {
		time.Sleep(20 * time.Millisecond)
	}
	asked := c.Stats().Probes
	time.Sleep(400 * time.Millisecond)
	st := c.Stats()
	if st.Probes != asked {
		t.Fatalf("settled streams were asked %d more times in 400 ms", st.Probes-asked)
	}
	if st.Unsettled != 2 || st.Ready != 2 || d.count(1) != 3 || d.count(2) != 3 {
		t.Fatalf("a stream on the server that came back was not left alone: replaced %d, ready %d, dials %d and %d", st.Unsettled, st.Ready, d.count(1), d.count(2))
	}
}
