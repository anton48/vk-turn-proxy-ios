// SPDX-License-Identifier: MIT

package csqtt

// Client: N workers over VK TURN to one csqtt server, presenting the same
// two calls the app's packet flow needs — WritePacket (from the TUN) and
// ReadPacket (to the TUN). Everything between is this file: striping,
// CQF1 framing and reassembly, the control plane, keepalives, and the
// server's REPAIR requests.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
)

// Config is everything a Client needs; Creds is the one thing the package
// does not do itself.
type Config struct {
	Server   *net.UDPAddr
	Password string

	// Identity shared by every worker. A new (Generation, Salt) pair makes
	// the server drop every older session of this DeviceID.
	DeviceID   string
	Generation uint64
	Salt       string

	Workers int    // 1..MaxWorkers
	Chunks  [3]int // per-class striping chunks; zero keeps DefaultChunks

	// DuplicateTCP (EXPERIMENT) sends a second copy of every CQF1-framed
	// packet through a different worker. The server keys reassembly on
	// (sender, flow, sequence), so whichever copy lands first is delivered
	// and the other is dropped as a duplicate — a lever against the ~1 %
	// random loss of the relay leg, at the price of doubled TCP-data bytes
	// on the uplink. Unframed packets are never duplicated: the server would
	// hand both copies to its TUN.
	DuplicateTCP bool
	Mode         Mode   // ModeAudio unless told otherwise
	Revision     string // WireRevision unless told otherwise
	LocalPort    string // echoed by the server; "9000" unless told otherwise

	// Creds mints a relay credential for a worker. Called with a worker id
	// (1-based) each time that worker (re)starts; the pool policy is the
	// caller's.
	Creds func(ctx context.Context, workerID int) (TURNCredentials, error)

	TURNTransport string           // "udp" or "tcp"
	TURNLogLevel  logging.LogLevel // pion verbosity

	// StartPacing spaces worker starts (the reference client uses 100 ms).
	StartPacing time.Duration

	Logf func(format string, args ...any)
}

func (c *Config) defaults() {
	if c.Mode != ModeVideo {
		c.Mode = ModeAudio
	}
	if c.Revision == "" {
		c.Revision = WireRevision
	}
	if c.LocalPort == "" {
		c.LocalPort = "9000"
	}
	if c.TURNTransport == "" {
		c.TURNTransport = "udp"
	}
	if c.TURNLogLevel == 0 {
		c.TURNLogLevel = logging.LogLevelWarn
	}
	if c.StartPacing == 0 {
		c.StartPacing = 100 * time.Millisecond
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.Workers < 1 {
		c.Workers = 1
	}
	if c.Workers > MaxWorkers {
		c.Workers = MaxWorkers
	}
}

// Client is a running tunnel. Create with Dial, use WritePacket/ReadPacket,
// end with Close.
type Client struct {
	cfg  Config
	ctx  context.Context
	stop context.CancelFunc

	workers []*worker
	striper *Striper
	seq     *Sequencer

	reasmMu sync.Mutex
	reasm   *Reassembler[[]byte]

	out chan []byte

	confMu   sync.Mutex
	conf     ConfigResponse
	confOnce chan struct{} // closed when the first TUNCONF arrives
	confSet  bool

	fatal   atomic.Pointer[error]
	wg      sync.WaitGroup
	closing atomic.Bool

	// counters
	dropped     atomic.Int64 // out queue full
	noWorker    atomic.Int64 // WritePacket with nothing alive
	framedTx    atomic.Int64
	dupTx       atomic.Int64 // second copies sent (DuplicateTCP)
	reassembled atomic.Int64
	repairs     atomic.Int64

	dupCursor int // rotates the worker that carries the copy
}

// Dial starts worker 1 and returns once it has a TUNCONF; the other workers
// come up in the background, paced. A DENIED anywhere is fatal for the
// whole client, because the server would refuse every worker the same way.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	cfg.defaults()
	if cfg.Server == nil || cfg.Password == "" || cfg.DeviceID == "" || cfg.Creds == nil {
		return nil, errors.New("csqtt: Server, Password, DeviceID and Creds are required")
	}
	key, err := DeriveKey(cfg.Password)
	if err != nil {
		return nil, err
	}
	cipher, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg:      cfg,
		ctx:      cctx,
		stop:     cancel,
		striper:  NewStriper(cfg.Workers),
		seq:      NewSequencer(0),
		reasm:    NewReassembler[[]byte](),
		out:      make(chan []byte, 1024),
		confOnce: make(chan struct{}),
	}
	c.striper.SetChunks(cfg.Chunks)
	c.workers = make([]*worker, cfg.Workers)
	for i := range c.workers {
		c.workers[i] = newWorker(c, i+1, cipher)
	}

	// Worker 1 first, alone: its TUNCONF is what the caller waits for, and
	// its DENIED is what stops everything before N−1 more relays are burnt.
	c.wg.Add(1)
	go c.workers[0].run()
	select {
	case <-c.confOnce:
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	case <-cctx.Done():
		err := c.Err()
		if err == nil {
			err = errors.New("csqtt: client stopped before TUNCONF")
		}
		return nil, err
	}
	for i := 1; i < len(c.workers); i++ {
		c.wg.Add(1)
		go c.workers[i].run()
		select {
		case <-time.After(cfg.StartPacing):
		case <-cctx.Done():
			return c, nil
		}
	}
	return c, nil
}

// Config is the latest TUNCONF (the first one, or a pushed update).
func (c *Client) Config() ConfigResponse {
	c.confMu.Lock()
	defer c.confMu.Unlock()
	return c.conf
}

// Err is the fatal error that stopped the client, if any.
func (c *Client) Err() error {
	if p := c.fatal.Load(); p != nil {
		return *p
	}
	return nil
}

// Done is closed when the client has stopped for any reason.
func (c *Client) Done() <-chan struct{} { return c.ctx.Done() }

// WritePacket takes one IP packet from the TUN and sends it through a
// worker chosen by class. TCP packets are CQF1-framed when the server
// asked for frames. Not safe for concurrent use — one TUN reader.
func (c *Client) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	w := c.striper.Pick(Classify(pkt), c.alive)
	if w < 0 {
		c.noWorker.Add(1)
		return errNoWorker
	}
	wk := c.workers[w]
	if c.Config().FramesData() {
		if framed, ok := c.seq.Frame(wk.frameBuf, pkt); ok {
			c.framedTx.Add(1)
			err := wk.send(framed)
			if c.cfg.DuplicateTCP {
				if w2 := c.secondWorker(w); w2 >= 0 {
					if c.workers[w2].send(framed) == nil {
						c.dupTx.Add(1)
					}
				}
			}
			return err
		}
	}
	return wk.send(pkt)
}

var errNoWorker = errors.New("csqtt: no worker is ready")

// secondWorker picks a ready worker other than first for the duplicate,
// rotating so the copies spread over the pool; -1 when none qualifies.
func (c *Client) secondWorker(first int) int {
	n := len(c.workers)
	for i := 0; i < n; i++ {
		c.dupCursor = (c.dupCursor + 1) % n
		w := c.dupCursor
		if w != first && c.alive(w) {
			return w
		}
	}
	return -1
}

// ReadPacket returns the next IP packet for the TUN, or ctx's error, or the
// client's fatal error once it has stopped.
func (c *Client) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-c.out:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		if err := c.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("csqtt: client closed")
	}
}

// Close tells the server to drop this (device, salt) and releases every
// relay. Safe to call more than once.
func (c *Client) Close() error {
	if !c.closing.CompareAndSwap(false, true) {
		return nil
	}
	req := []byte(DisconnectRequest(c.cfg.DeviceID, c.cfg.Salt))
	for _, w := range c.workers {
		if w.ready.Load() {
			_ = w.send(req)
			break
		}
	}
	c.stop()
	c.wg.Wait()
	return nil
}

func (c *Client) alive(i int) bool { return c.workers[i].ready.Load() }

func (c *Client) fail(err error) {
	if c.fatal.CompareAndSwap(nil, &err) {
		c.cfg.Logf("csqtt: fatal: %v", err)
		c.stop()
	}
}

func (c *Client) setConfig(conf ConfigResponse) {
	c.confMu.Lock()
	changed := c.confSet && conf.Raw != c.conf.Raw
	c.conf = conf
	first := !c.confSet
	c.confSet = true
	c.confMu.Unlock()
	if first {
		close(c.confOnce)
	} else if changed {
		c.cfg.Logf("csqtt: TUNCONF updated: %s", conf.Raw)
	}
}

// deliver hands an inbound IP packet to the TUN side, through the
// reassembler when it carries a frame.
func (c *Client) deliver(plain []byte) {
	h, payload, framed := DecodeFrame(plain)
	if !framed {
		c.enqueue(append([]byte(nil), plain...))
		return
	}
	pkt := append([]byte(nil), payload...)
	var released [][]byte
	c.reasmMu.Lock()
	c.reasm.Push(h, pkt, &released)
	c.reasmMu.Unlock()
	if len(released) > 0 {
		c.reassembled.Add(int64(len(released)))
	}
	for _, p := range released {
		c.enqueue(p)
	}
}

func (c *Client) enqueue(p []byte) {
	select {
	case c.out <- p:
	default:
		c.dropped.Add(1)
	}
}

// repair restarts the workers the server says it has not seen.
func (c *Client) repair(cmd StreamCommand) {
	c.repairs.Add(1)
	for _, id := range cmd.WorkerIDs {
		if int(id) >= 1 && int(id) <= len(c.workers) {
			c.workers[id-1].restart(fmt.Sprintf("server REPAIR seq=%d", cmd.Sequence))
		}
	}
}

// ─── stats ────────────────────────────────────────────────────────────────

// WorkerStats is one worker's counters.
type WorkerStats struct {
	ID       int
	Ready    bool
	Relay    string
	TxPkts   int64
	RxPkts   int64
	Restarts int64
	LastRx   time.Time
}

// Stats is a snapshot of the client.
type Stats struct {
	Workers     []WorkerStats
	Dropped     int64 // inbound packets the TUN side did not take in time
	NoWorker    int64 // outbound packets with no ready worker
	FramedTx    int64
	DupTx       int64
	Reassembled int64
	Repairs     int64
}

// Stats snapshots the counters.
func (c *Client) Stats() Stats {
	s := Stats{
		Dropped:     c.dropped.Load(),
		NoWorker:    c.noWorker.Load(),
		FramedTx:    c.framedTx.Load(),
		DupTx:       c.dupTx.Load(),
		Reassembled: c.reassembled.Load(),
		Repairs:     c.repairs.Load(),
	}
	for _, w := range c.workers {
		s.Workers = append(s.Workers, w.stats())
	}
	return s
}

// ─── worker ───────────────────────────────────────────────────────────────

const (
	keepaliveEvery = 10 * time.Second
	readyWait      = 3 * time.Second
	restartBackoff = time.Second
	maxBackoff     = 30 * time.Second
)

var getconfSchedule = []time.Duration{750 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second}

type worker struct {
	c      *Client
	id     int
	cipher *Cipher

	mu       sync.Mutex // guards wrapper, relay and wireBuf
	wrapper  *Wrapper
	relay    *Relay
	wireBuf  []byte
	frameBuf []byte

	ready    atomic.Bool
	tx, rx   atomic.Int64
	restarts atomic.Int64
	lastRx   atomic.Int64 // unix nanos
	lastTx   atomic.Int64
	relayStr atomic.Pointer[string]

	kick chan string // restart requests with a reason
}

func newWorker(c *Client, id int, cipher *Cipher) *worker {
	return &worker{
		c: c, id: id, cipher: cipher,
		wireBuf: make([]byte, 0, 2048), frameBuf: make([]byte, 0, 2048),
		kick: make(chan string, 1),
	}
}

func (w *worker) stats() WorkerStats {
	s := WorkerStats{ID: w.id, Ready: w.ready.Load(), TxPkts: w.tx.Load(), RxPkts: w.rx.Load(), Restarts: w.restarts.Load()}
	if ns := w.lastRx.Load(); ns != 0 {
		s.LastRx = time.Unix(0, ns)
	}
	if p := w.relayStr.Load(); p != nil {
		s.Relay = *p
	}
	return s
}

// restart asks the run loop to tear the session down and dial again.
func (w *worker) restart(reason string) {
	select {
	case w.kick <- reason:
	default:
	}
}

// run is the worker's life: dial, handshake, serve, and on any failure
// back off and dial again until the client stops.
func (w *worker) run() {
	defer w.c.wg.Done()
	backoff := restartBackoff
	for w.c.ctx.Err() == nil {
		err := w.session()
		if w.c.ctx.Err() != nil {
			return
		}
		var denied *DeniedError
		if errors.As(err, &denied) || errors.Is(err, ErrNoConfig) {
			w.c.fail(fmt.Errorf("worker %d: %w", w.id, err))
			return
		}
		w.restarts.Add(1)
		w.c.cfg.Logf("csqtt: worker %d: %v — restarting in %s", w.id, err, backoff)
		select {
		case <-time.After(backoff):
		case <-w.c.ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// session is one allocation's lifetime. It returns why it ended.
func (w *worker) session() error {
	ctx := w.c.ctx
	creds, err := w.c.cfg.Creds(ctx, w.id)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	relay, err := DialRelay(creds, w.c.cfg.Server, w.c.cfg.TURNTransport, w.c.cfg.TURNLogLevel)
	if err != nil {
		return err
	}
	wrapper, err := NewWrapper(w.cipher, w.c.cfg.Mode)
	if err != nil {
		relay.Close()
		return err
	}
	w.mu.Lock()
	w.relay, w.wrapper = relay, wrapper
	w.mu.Unlock()
	rs := relay.Conn.LocalAddr().String()
	w.relayStr.Store(&rs)
	defer func() {
		w.ready.Store(false)
		w.mu.Lock()
		w.relay, w.wrapper = nil, nil
		w.mu.Unlock()
		relay.Close()
	}()
	w.c.cfg.Logf("csqtt: worker %d: relay %s via %s", w.id, rs, creds.Address)

	// The read loop feeds the control channel and delivers data; it ends
	// when the relay is closed.
	control := make(chan []byte, 64)
	readErr := make(chan error, 1)
	go w.readLoop(relay.Conn, control, readErr)

	// GETCONF with the reference schedule.
	req := []byte(ConfigRequest(w.c.cfg.LocalPort, w.c.cfg.DeviceID, w.c.cfg.Password,
		w.c.cfg.Generation, w.c.cfg.Salt, w.id, w.c.cfg.Workers, w.c.cfg.Revision))
	var conf ConfigResponse
	got := false
attempts:
	for _, wait := range getconfSchedule {
		if err := w.send(req); err != nil {
			return fmt.Errorf("GETCONF send: %w", err)
		}
		deadline := time.After(wait)
		for {
			select {
			case p := <-control:
				if !IsConfigResponse(p) {
					continue
				}
				conf, err = ParseConfigResponse(p)
				if err != nil {
					return err
				}
				got = true
				break attempts
			case err := <-readErr:
				return fmt.Errorf("relay read: %w", err)
			case <-deadline:
				continue attempts
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if !got {
		return errors.New("no TUNCONF (wrong password is silence)")
	}
	w.c.setConfig(conf)
	if err := w.send([]byte(ReadyRequest)); err != nil {
		return fmt.Errorf("READY send: %w", err)
	}
	w.ready.Store(true)
	w.c.cfg.Logf("csqtt: worker %d: ready (%s)", w.id, conf.Raw)

	// Serve: keepalives when idle, control messages as they come, until the
	// read loop dies, the client stops, or someone asks for a restart.
	tick := time.NewTicker(keepaliveEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case reason := <-w.kick:
			return errors.New(reason)
		case err := <-readErr:
			return fmt.Errorf("relay read: %w", err)
		case p := <-control:
			w.handleControl(p)
		case <-tick.C:
			if time.Since(time.Unix(0, w.lastTx.Load())) >= keepaliveEvery {
				if err := w.send(IdleKeepalive); err != nil {
					return fmt.Errorf("keepalive: %w", err)
				}
			}
		}
	}
}

func (w *worker) handleControl(p []byte) {
	switch {
	case IsPanelRestart(p):
		w.c.cfg.Logf("csqtt: worker %d: server is restarting", w.id)
		w.restart("panel restart")
	case IsConfigResponse(p):
		if conf, err := ParseConfigResponse(p); err == nil {
			w.c.setConfig(conf) // a pushed TUNCONF (DNS change)
		} else {
			w.c.fail(fmt.Errorf("worker %d: %w", w.id, err))
		}
	case len(p) > 0 && p[0] == 0xff:
		if cmd, ok := ParseStreamRepair(p); ok {
			w.c.cfg.Logf("csqtt: server REPAIR seq=%d restart=%v", cmd.Sequence, cmd.WorkerIDs)
			w.c.repair(cmd)
		}
		// ALIVE notices and keepalives need no action.
	}
}

// send wraps and writes one plaintext. Safe for concurrent callers.
func (w *worker) send(plain []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.relay == nil || w.wrapper == nil {
		return errNoWorker
	}
	wire, err := w.wrapper.Wrap(w.wireBuf, plain)
	if err != nil {
		return err
	}
	if _, err := w.relay.Conn.WriteTo(wire, w.c.cfg.Server); err != nil {
		return err
	}
	w.tx.Add(1)
	w.lastTx.Store(time.Now().UnixNano())
	return nil
}

// readLoop unwraps every datagram from the relay: control to the channel,
// data to the client. It ends with the relay.
func (w *worker) readLoop(conn net.PacketConn, control chan<- []byte, readErr chan<- error) {
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			readErr <- err
			return
		}
		wire := buf[:n]
		if !IsRTP(wire) {
			continue
		}
		plain, _, err := w.cipher.Unwrap(w.c.cfg.Mode, wire)
		if err != nil {
			continue
		}
		w.rx.Add(1)
		w.lastRx.Store(time.Now().UnixNano())
		if IsIdleKeepalive(plain) {
			continue
		}
		if IsControl(plain) {
			cp := append([]byte(nil), plain...)
			select {
			case control <- cp:
			default:
			}
			continue
		}
		w.c.deliver(plain)
	}
}
