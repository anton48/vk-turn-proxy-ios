package csqtt25

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The client: N streams ("workers") to one server under one identity, an
// uplink dispatcher over them, and whatever comes down handed to Deliver.
//
// It restarts a stream that fails, asks a silent one whether it is alive and
// replaces it when it is not, follows the worker count the server agrees to
// and its repair notices. A stream's silence is judged as LISTENING, with a
// freeze of the process as a boundary (liveness.go), and a write the relay
// does not take is bounded (ClientConfig.WriteBound): a phone suspends the
// process for minutes at a time, and a relay that stops taking bytes must
// cost its own stream and nothing else.

// DialFunc opens one stream's socket to the server: a PacketConn whose
// datagrams to peer reach the server (a TURN allocation in production).
// closeConn releases it and must end a write parked in conn; the client
// calls it exactly once per dial — at the session's end or at the client's
// stop, from another goroutine than the one writing. A dial should return
// when ctx is done; one that does not delays nothing but its own worker.
//
// With ClientConfig.WriteBound set, conn's SetWriteDeadline has to be REAL: a
// WriteTo the far side has not taken by the deadline returns
// os.ErrDeadlineExceeded. (A TURN library's relayed conn commonly ignores a
// deadline — it belongs on the socket under it.)
type DialFunc func(ctx context.Context, workerID int) (conn net.PacketConn, peer net.Addr, closeConn func(), err error)

// KeyMode is where a stream's keys come from.
type KeyMode int

const (
	KeysAuto KeyMode = iota // a DTLS handshake, password-derived keys if it fails (the reference's default)
	KeysDTLS                // a DTLS handshake or nothing
	KeysWrap                // password-derived keys, no handshake
)

// ParseKeyMode accepts the reference client's names.
func ParseKeyMode(s string) (KeyMode, error) {
	switch s {
	case "auto", "":
		return KeysAuto, nil
	case "dtls", "dtls-srtp":
		return KeysDTLS, nil
	case "wrap", "wrap-srtp":
		return KeysWrap, nil
	}
	return 0, errors.New("csqtt25: unknown key mode " + s)
}

// ClientConfig is what a client is made of.
type ClientConfig struct {
	Password string
	Workers  int // streams asked for, 1..MaxWorkers; the server may agree to fewer
	Mode     Mode
	Keys     KeyMode
	Dial     DialFunc
	// Deliver takes one whole IP packet from the server. It is called from
	// the streams' read loops — concurrently across streams — and owns the
	// slice.
	Deliver   func(pkt []byte)
	Logf      func(format string, args ...any)
	LocalPort string // echoed by the server; "9000" when empty
	// WriteBound is how long a stream's socket may take over ONE datagram. A
	// write it has not taken by then is a stall: the datagram is dropped, the
	// stream is not ready from that moment and is replaced — the caller of Send
	// waited the bound once, not until somebody noticed. 0: no bound.
	WriteBound time.Duration
}

// The client's clocks; variables so that a test can shorten them.
var (
	getconfWaits   = []time.Duration{400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3000 * time.Millisecond}
	keepaliveEvery = 10 * time.Second // an idle stream says so this often
	probeAfter     = 20 * time.Second // a stream that heard nothing this long is asked (READY)
	deafAfter      = 60 * time.Second // …and replaced when it heard nothing this long
	serveTick      = time.Second
	backoffBase    = time.Second
	backoffMax     = 15 * time.Second
	heldAfter      = 30 * time.Second       // a session that stayed ready this long ends the run of failures
	disconnectWait = 700 * time.Millisecond // Close: telling the server and hearing its answer, in all
	stopWait       = 2 * time.Second        // Close: the workers' end once every socket is released
	panelWindow    = 15 * time.Second       // the server's restart notices inside this are one restart
	// A server that says it is restarting goes on answering until it is gone,
	// so a stream can be set up on it behind the notice. Until a stream has
	// heard something later than restartSettle after the notice it is not
	// known to be on the server that came back, and its silence is short.
	restartSettle    = 15 * time.Second
	settleProbeAfter = 2 * time.Second // such a stream is asked (READY) after this much silence
	settleDeafAfter  = 5 * time.Second // …and replaced after this much
	// A ready stream counts as live while it has heard something this lately
	// (an idle one is asked after probeAfter, so a healthy one always has).
	liveWindow = 45 * time.Second
)

// ErrNoStream is Send's answer when no stream can carry a packet now.
var ErrNoStream = errors.New("csqtt25: no stream is ready")

var (
	errParked       = errors.New("csqtt25: the worker is above the agreed count")
	errRepair       = errors.New("csqtt25: the server asked for this worker again")
	errPanelRestart = errors.New("csqtt25: the server is restarting")
	errUnsettled    = errors.New("silent behind the server's restart notice: a stream of the server that went")
	errPathChange   = errors.New("the path changed")
	errDeaf         = errors.New("csqtt25: the stream heard nothing")
)

// Stats is a snapshot of the client's counters.
type Stats struct {
	Workers, Target, Ready                 int
	Live                                   int // of the ready ones, heard from within liveWindow: what a screen shows as connections
	TxPackets, TxBytes, RxPackets, RxBytes int64
	FragsTx, FragsRx                       int64
	Sessions, Restarts                     int64 // sessions that reached READY; sessions that ended
	AuthFailures, NoStream                 int64
	Probes, Repairs, Handshakes, Fallbacks int64
	Unsettled                              int64 // streams replaced for their silence behind a restart notice
	PanelRestarts                          int64
	PathChanges                            int64
	WriteStalls, DeadWrites                int64 // writes the relay did not take within the bound; writes that found the connection gone
	Freezes, Wakes                         int64 // late ticks taken for a suspension of the process (one per suspension); the caller's wake words
	WakeDeaf                               int64 // streams replaced for their silence behind a freeze or a wake
}

// Client is a running csqtt 2.5 client.
type Client struct {
	cfg  ClientConfig
	gen  uint64
	salt string

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	workers []*worker

	mu        sync.Mutex // guards gen, salt, disp, target, conf, repairSeq, panelAt, fatal, rallyAt, rallyFrom, frozeAt
	disp      *Dispatcher
	target    int
	conf      ConfigResponse
	repairSeq uint64
	panelAt   time.Time // the last restart notice acted on
	// rallyAt is when every worker was last started together — the start, a
	// path change, a restart notice — and rallyFrom its name; zero once the
	// client has said that all the agreed workers are ready (rallied).
	rallyAt   time.Time
	rallyFrom string
	frozeAt   time.Time // when a freeze was last said (froze): the streams see one suspension a tick apart
	fatal     error

	confOnce     chan struct{} // closed with the first TUNCONF
	confClosed   sync.Once
	done         chan struct{} // closed when the client is over: a fatal denial, or Close
	doneClosed   sync.Once
	disconnected chan struct{}
	fragID       atomic.Uint32

	txPackets, txBytes, rxPackets, rxBytes atomic.Int64
	fragsTx, fragsRx                       atomic.Int64
	sessions, restarts                     atomic.Int64
	authFailures, noStream                 atomic.Int64
	probes, repairs, handshakes, fallbacks atomic.Int64
	panelRestarts                          atomic.Int64
	pathChanges                            atomic.Int64
	unsettledN                             atomic.Int64
	writeStalls, deadWrites                atomic.Int64
	freezes, wakes, wakeDeaf               atomic.Int64
	wakeEpoch                              atomic.Uint64 // moved by Wake; every serve loop compares its own copy at each pass (a level, not an edge)
}

type worker struct {
	c  *Client
	id int

	mu      sync.Mutex // guards conn, peer, wrapper, wireBuf: one sender at a time
	conn    net.PacketConn
	peer    net.Addr
	wrapper *Wrapper
	wireBuf []byte

	ready  atomic.Bool
	lastTx atomic.Int64
	lastRx atomic.Int64
	kick   chan error    // the server wants this worker's session over: the reason
	wake   chan struct{} // the agreed count changed
	reasm  *Reassembler  // the read loop's alone
	nudge  chan struct{} // the caller's wake word: look at the wake epoch now, not at the next tick
	// closing: this session's socket is being given back (its end, or the
	// stop). A write that fails from here on failed because of the close.
	closing atomic.Bool
	// saying: one control datagram of the serve loop's — an ask, a keepalive —
	// is in its write (say).
	saying atomic.Bool
}

// Dial starts worker 1 and returns once the server has answered it with a
// configuration; the other workers start behind it. ctx bounds only that
// wait.
func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Password == "" || cfg.Dial == nil {
		return nil, errors.New("csqtt25: Password and Dial are required")
	}
	if cfg.Workers < 1 || cfg.Workers > MaxWorkers {
		return nil, fmt.Errorf("csqtt25: Workers must be 1..%d", MaxWorkers)
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Deliver == nil {
		cfg.Deliver = func([]byte) {}
	}
	if cfg.LocalPort == "" {
		cfg.LocalPort = "9000"
	}
	var salt [8]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	c := &Client{
		cfg: cfg, gen: uint64(time.Now().UnixMilli()), salt: hex.EncodeToString(salt[:]),
		disp: NewDispatcher(cfg.Workers), target: cfg.Workers,
		confOnce: make(chan struct{}), done: make(chan struct{}), disconnected: make(chan struct{}, 1),
		rallyAt: time.Now(), rallyFrom: "the start",
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	for id := 1; id <= cfg.Workers; id++ {
		c.workers = append(c.workers, &worker{c: c, id: id, kick: make(chan error, 1), wake: make(chan struct{}, 1), nudge: make(chan struct{}, 1)})
	}
	c.start(c.workers[0])
	select {
	case <-c.confOnce:
	case <-c.done:
		err := c.Err()
		c.Close()
		return nil, err
	case <-ctx.Done():
		c.Close()
		return nil, fmt.Errorf("csqtt25: no configuration from the server: %w", ctx.Err())
	}
	for _, w := range c.workers[1:] {
		c.start(w)
	}
	return c, nil
}

func (c *Client) start(w *worker) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		w.run()
	}()
}

// Config is the latest configuration the server sent.
func (c *Client) Config() ConfigResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conf
}

// Done is closed when the client is over; Err says why (nil after Close).
func (c *Client) Done() <-chan struct{} { return c.done }

// Err is the denial that ended the client, if one did.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fatal
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.fatal == nil {
		c.fatal = err
	}
	c.mu.Unlock()
	c.doneClosed.Do(func() { close(c.done) })
	c.cancel()
}

func (c *Client) targetNow() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target
}

// setTarget follows the count the server agreed to: never above what was
// asked, never below one.
func (c *Client) setTarget(agreed int) { c.moveTarget(agreed, false) }

// lowerTarget takes a refusal of one worker's number as a count: it can only
// lower what stands (two refused workers answer in any order — the higher
// one's must not raise what the lower one's set).
func (c *Client) lowerTarget(to int) { c.moveTarget(to, true) }

func (c *Client) moveTarget(agreed int, onlyDown bool) {
	if agreed < 1 {
		agreed = 1
	}
	if agreed > c.cfg.Workers {
		agreed = c.cfg.Workers
	}
	c.mu.Lock()
	changed := c.target != agreed && !(onlyDown && agreed > c.target)
	if changed {
		c.target = agreed
	}
	c.mu.Unlock()
	if !changed {
		return
	}
	defer c.rallied()
	c.cfg.Logf("csqtt25: the server agrees to %d worker(s) of the %d asked", agreed, c.cfg.Workers)
	for _, w := range c.workers {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

func (c *Client) setConfig(conf ConfigResponse) {
	c.mu.Lock()
	changed := c.conf.Raw != conf.Raw
	c.conf = conf
	c.mu.Unlock()
	if conf.Workers > 0 {
		c.setTarget(conf.Workers)
	}
	if changed {
		c.cfg.Logf("csqtt25: configuration: tunnel %s, stream %q, workers=%d", conf.TunnelIP, conf.Stream, conf.Workers)
	}
	c.confClosed.Do(func() { close(c.confOnce) })
}

// repair restarts the READY workers a repair notice names: the server does
// not see them although they think they are up. A notice is acted on once.
func (c *Client) repair(cmd StreamCommand) {
	c.mu.Lock()
	fresh := cmd.Sequence > c.repairSeq
	if fresh {
		c.repairSeq = cmd.Sequence
	}
	c.mu.Unlock()
	if !fresh {
		return
	}
	named := make(map[int]bool, len(cmd.Workers))
	for _, id := range cmd.Workers {
		named[id] = true
	}
	for _, w := range c.workers {
		if named[w.id] && w.ready.Load() {
			c.repairs.Add(1)
			w.end(errRepair)
		}
	}
}

// panelRestart acts on the server's notice that it is restarting: the
// server that comes back holds none of these sessions, so every worker
// starts over now — left to their silence they would be found out a worker
// at a time, deafAfter later; one caught in its set-up starts over too (its
// answer may have been the old server's last). The identity stays: the server is
// empty, and a new one is for a new connection. The notice comes on every
// stream and more than once; the copies inside panelWindow are one restart.
func (c *Client) panelRestart() {
	now := time.Now()
	c.mu.Lock()
	repeat := !c.panelAt.IsZero() && now.Sub(c.panelAt) < panelWindow
	if !repeat {
		c.panelAt = now
		c.rallyAt, c.rallyFrom = now, "the server's restart notice"
	}
	c.mu.Unlock()
	if repeat {
		return
	}
	c.panelRestarts.Add(1)
	c.cfg.Logf("csqtt25: the server says it is restarting — every worker starts over")
	for _, w := range c.workers {
		w.end(errPanelRestart)
	}
}

// rallied says, once per start-of-all, that every worker the server agreed to
// is ready and how long that took. It is asked wherever the answer can turn
// true: a worker has become ready, or the agreed count has come down to the
// ones that already are. It is what gives a log its figure for «the tunnel
// whole again» — the counters come a minute later.
func (c *Client) rallied() {
	c.mu.Lock()
	if c.rallyAt.IsZero() {
		c.mu.Unlock()
		return
	}
	ready := 0
	for _, w := range c.workers {
		if w.ready.Load() {
			ready++
		}
	}
	if ready < c.target {
		c.mu.Unlock()
		return
	}
	target, took, from := c.target, time.Since(c.rallyAt), c.rallyFrom
	c.rallyAt = time.Time{}
	c.mu.Unlock()
	asked := ""
	if target != c.cfg.Workers {
		asked = fmt.Sprintf(" (%d asked)", c.cfg.Workers)
	}
	c.cfg.Logf("csqtt25: all %d agreed workers ready%s, %v after %s", target, asked, took.Round(time.Millisecond), from)
}

// identity is the pair the client asks under now.
func (c *Client) identity() (gen uint64, salt string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen, c.salt
}

// OnPathChange is the caller's word that the network under the streams has
// changed — another interface, another address: every stream's socket is on
// a path that is gone. The client takes a NEW identity (the server replaces
// a password's older sessions when a later pair arrives, so it stops sending
// into the dead streams with the first worker that registers) and every
// worker starts over at once: this is an asked restart, not a failure — it
// neither waits nor lengthens the next wait (run), and it ends the wait of a
// worker that is between sessions. A worker in its set-up dialled on the old
// path and starts over too.
func (c *Client) OnPathChange() {
	var salt [8]byte
	_, _ = rand.Read(salt[:])
	c.mu.Lock()
	gen := uint64(time.Now().UnixMilli())
	if gen <= c.gen {
		gen = c.gen + 1
	}
	c.gen, c.salt = gen, hex.EncodeToString(salt[:])
	c.rallyAt, c.rallyFrom = time.Now(), "the path change"
	c.mu.Unlock()
	c.pathChanges.Add(1)
	c.cfg.Logf("csqtt25: the path changed: a new identity, every worker starts over")
	for _, w := range c.workers {
		w.endNow(errPathChange)
	}
}

// Wake is the caller's word that the process may just have been suspended —
// the app's wake hook; on a phone it comes with every wake of the device and
// every change of the path's state. It is a freeze boundary for every ready
// stream (liveness.go): each is asked at once, again while it stays silent,
// and replaced after wakeDeafAfter of listening without a word. It never
// waits: it moves an epoch and nudges the serve loops, which act on the
// epoch — a nudge that finds its channel full is not lost, the loop compares
// the epoch at its next tick anyway.
func (c *Client) Wake() {
	c.wakeEpoch.Add(1)
	c.wakes.Add(1)
	ready := 0
	for _, w := range c.workers {
		if w.ready.Load() {
			ready++
		}
		select {
		case w.nudge <- struct{}{}:
		default:
		}
	}
	c.cfg.Logf("csqtt25: wake — %d ready stream(s) asked afresh", ready)
}

// froze says, once per suspension, that a serve loop's tick came late: every
// stream sees the same gap, a tick apart (late: the gap that makes a tick late).
func (c *Client) froze(gap, late time.Duration) {
	now := time.Now()
	c.mu.Lock()
	said := !c.frozeAt.IsZero() && now.Sub(c.frozeAt) < late
	if !said {
		c.frozeAt = now
	}
	c.mu.Unlock()
	if said {
		return
	}
	c.freezes.Add(1)
	c.cfg.Logf("csqtt25: the process did not run for %s — what was heard before it counts for nothing, every ready stream is asked afresh", gap.Round(100*time.Millisecond))
}

// unsettled says whether a stream last heard at `heard` may still be one of
// the server that said it was restarting. The restart on the notice is
// right only if that server is gone when a worker asks again, and nothing
// says when it goes: a worker whose back-off ran out behind the notice, or
// every worker when the server is slow to stop, is taken back by it and
// then forgotten with it. What tells such a stream from one on the server
// that came back is an answer later than the old server can have given.
func (c *Client) unsettled(heard time.Time) bool {
	c.mu.Lock()
	at := c.panelAt
	c.mu.Unlock()
	return heard.Before(at.Add(restartSettle))
}

// Send hands one IP packet to the server: whole up to WholeMax bytes, as
// fragments on one stream above it. Callers send one at a time (the order of
// a flow's packets is the order of the calls).
func (c *Client) Send(pkt []byte) error {
	datagrams := 1
	if len(pkt) > WholeMax {
		datagrams = (len(pkt) + FragMax - 1) / FragMax
	}
	c.mu.Lock()
	idx, ok := c.disp.Pick(pkt, datagrams, func(i int) bool { return c.workers[i].ready.Load() }, time.Now())
	c.mu.Unlock()
	if !ok {
		c.noStream.Add(1)
		return ErrNoStream
	}
	w := c.workers[idx]
	if datagrams == 1 {
		return w.send(pkt)
	}
	frags := Fragment(uint16(c.fragID.Add(1)), pkt)
	if frags == nil {
		return errors.New("csqtt25: the packet is too large to travel")
	}
	for _, f := range frags {
		if err := w.send(f); err != nil {
			return err
		}
		c.fragsTx.Add(1)
	}
	return nil
}

// Stats is a snapshot of the counters.
func (c *Client) Stats() Stats {
	s := Stats{
		Workers: len(c.workers), Target: c.targetNow(),
		TxPackets: c.txPackets.Load(), TxBytes: c.txBytes.Load(), RxPackets: c.rxPackets.Load(), RxBytes: c.rxBytes.Load(),
		FragsTx: c.fragsTx.Load(), FragsRx: c.fragsRx.Load(), Sessions: c.sessions.Load(), Restarts: c.restarts.Load(),
		AuthFailures: c.authFailures.Load(), NoStream: c.noStream.Load(),
		Probes: c.probes.Load(), Repairs: c.repairs.Load(), Handshakes: c.handshakes.Load(), Fallbacks: c.fallbacks.Load(),
		PanelRestarts: c.panelRestarts.Load(),
		PathChanges:   c.pathChanges.Load(),
		Unsettled:     c.unsettledN.Load(),
		WriteStalls:   c.writeStalls.Load(),
		DeadWrites:    c.deadWrites.Load(),
		Freezes:       c.freezes.Load(),
		Wakes:         c.wakes.Load(),
		WakeDeaf:      c.wakeDeaf.Load(),
	}
	now := time.Now().UnixNano()
	for _, w := range c.workers {
		if w.ready.Load() {
			s.Ready++
			if now-w.lastRx.Load() < int64(liveWindow) {
				s.Live++
			}
		}
	}
	return s
}

// Close stops the client within a bounded time, whatever its streams are
// doing. Telling the server (DISCONNECT through up to three ready streams)
// and hearing its answer have ONE budget, disconnectWait, and nothing in it
// is waited for beyond that — a write parked in a stream's socket holds
// that stream's lock, so the telling is done beside Close, not by it. Then
// the stop releases every stream's socket by itself (session) and the
// workers get stopWait to end; one still inside a dial that ignores the
// stop ends with its dial. Safe to call more than once.
func (c *Client) Close() {
	_, salt := c.identity()
	req := []byte(DisconnectRequest(c.cfg.Password, salt))
	var tellers sync.WaitGroup
	asked := 0
	for _, w := range c.workers {
		if asked == 3 {
			break
		}
		if w.ready.Load() {
			asked++
			tellers.Add(1)
			go func(w *worker) {
				defer tellers.Done()
				_ = w.send(req)
			}(w)
		}
	}
	if asked > 0 {
		budget := time.NewTimer(disconnectWait)
		select {
		case <-c.disconnected:
		case <-budget.C:
		}
		budget.Stop()
	}
	c.doneClosed.Do(func() { close(c.done) })
	c.cancel()
	ended := make(chan struct{})
	go func() {
		tellers.Wait()
		c.wg.Wait()
		close(ended)
	}()
	stop := time.NewTimer(stopWait)
	defer stop.Stop()
	select {
	case <-ended:
	case <-stop.C:
		c.cfg.Logf("csqtt25: close: a worker is still inside its dial after %s — returning without it", stopWait)
	}
}

// end asks the worker's session to end for a reason of the server's.
func (w *worker) end(why error) {
	select {
	case w.kick <- why:
	default:
	}
}

// endNow is end for this side's own word: it takes the place of a notice
// that is still waiting (a worker in its set-up has not looked yet), so that
// the session ends for THIS reason.
func (w *worker) endNow(why error) {
	select {
	case <-w.kick:
	default:
	}
	w.end(why)
}

// ─── a worker ────────────────────────────────────────────────────────────

func (w *worker) send(plain []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		return ErrNoStream
	}
	wire, err := w.wrapper.Wrap(w.wireBuf, plain)
	if err != nil {
		return err
	}
	w.wireBuf = wire[:0]
	// The bound goes on and comes off around the ONE write: whatever else
	// writes to the socket under this conn (a TURN client's refreshes, its
	// deallocate) must never meet a deadline that has passed.
	bound := w.c.cfg.WriteBound
	if bound > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(bound))
	}
	_, err = w.conn.WriteTo(wire, w.peer)
	if bound > 0 {
		_ = w.conn.SetWriteDeadline(time.Time{})
	}
	if err != nil {
		w.failedWrite(err, bound)
		return err
	}
	w.lastTx.Store(time.Now().UnixNano())
	w.c.txPackets.Add(1)
	w.c.txBytes.Add(int64(len(plain)))
	return nil
}

// failedWrite is the verdict on a write's error, under w.mu from send —
// whoever wrote: the caller of Send, an ask, a keepalive. Two errors end the
// stream, and at once: the bound's own expiry (the relay took no bytes — a
// stall) and the connection gone (a reset, a broken pipe, the kernel's own
// give-up: over a TCP relay leg the next WRITE is the only thing that notices).
// The stream is not ready from this moment — the dispatcher gives it nothing
// more — and its session is told to end; the dial that follows waits the
// failure back-off like any other failure of the relay path. Anything else —
// a moment's refusal, a route that is away for now — is the caller's error
// and nothing more; and a write that failed because this session's socket is
// being given back failed because of the close.
//
// 🚫 The bound's expiry is os.ErrDeadlineExceeded and nothing else: a
// net.Error's Timeout() is also true of the kernel's ETIMEDOUT, which is the
// connection gone, and of EAGAIN, which is nothing.
func (w *worker) failedWrite(err error, bound time.Duration) {
	if w.closing.Load() {
		return
	}
	c := w.c
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		c.writeStalls.Add(1)
		w.ready.Store(false)
		c.cfg.Logf("csqtt25: worker %d: the relay took no bytes for %s — a stalled write, the stream is replaced", w.id, bound)
		w.end(errStalled)
	case connGone(err):
		c.deadWrites.Add(1)
		w.ready.Store(false)
		c.cfg.Logf("csqtt25: worker %d: the write found the connection gone (%s) — the stream is replaced", w.id, causeOf(err))
		w.end(errConnGone)
	}
}

// say writes one control datagram of the serve loop's — an ask, a keepalive —
// WITHOUT holding the loop: over a TCP relay leg a write into a full buffer
// waits, and a serve loop that waits with it reads no notice, hears no
// answer, and arrives late at its own next tick — which reads as a freeze.
// One at a time: a second one while the first is still in its write is not
// queued behind it (it would say the same thing). The write's own verdict is
// send's (failedWrite).
func (w *worker) say(p []byte) {
	if !w.saying.CompareAndSwap(false, true) {
		return
	}
	w.c.wg.Add(1) // from the serve loop, itself counted: never from zero
	go func() {
		defer w.c.wg.Done()
		defer w.saying.Store(false)
		_ = w.send(p)
	}()
}

func (w *worker) run() {
	c := w.c
	backoff := backoffBase
	for c.ctx.Err() == nil {
		if w.id > c.targetNow() {
			select {
			case <-c.ctx.Done():
				return
			case <-w.wake:
			}
			continue
		}
		readyAt, err := w.session()
		if c.ctx.Err() != nil {
			return
		}
		c.restarts.Add(1)
		// A session that HELD ends the run of failures behind it HOWEVER it
		// ended — asked here, before the exits part: the ones below that dial
		// again without waiting (a path change, a worker parked and let go
		// again) never reach the wait, and a reset that sat there left the
		// next failure with what the failures of long ago had grown.
		if !readyAt.IsZero() && time.Since(readyAt) >= heldAfter {
			backoff = backoffBase
		}
		var denied *DeniedError
		switch {
		case errors.Is(err, ErrNoConfig):
			// The password is right and the server has no address for it: no
			// retry changes that, and whoever started the client must hear it.
			c.cfg.Logf("csqtt25: worker %d: %v — stopping the client", w.id, err)
			c.fail(err)
			return
		case errors.As(err, &denied) && denied.Fatal():
			c.cfg.Logf("csqtt25: worker %d: %v — the client stops", w.id, err)
			c.fail(err)
			return
		case errors.As(err, &denied) && denied.Reason == "invalid_worker_count":
			// The server holds fewer streams than this worker's number.
			c.lowerTarget(w.id - 1)
			continue
		case errors.Is(err, errParked):
			continue
		}
		if errors.Is(err, errPathChange) {
			c.cfg.Logf("csqtt25: worker %d: session ended (%v), again now", w.id, err)
			continue
		}
		c.cfg.Logf("csqtt25: worker %d: session ended (%v), again in %s", w.id, err, backoff)
		t := time.NewTimer(backoff)
	waiting:
		for {
			select {
			case <-c.ctx.Done():
				t.Stop()
				return
			case <-t.C:
				break waiting
			case why := <-w.kick:
				// Nothing to end between sessions — but a path change ends the
				// wait: it was earned on the path that is gone. Any other notice
				// is older than the session that follows, as session's own look
				// would find it.
				if errors.Is(why, errPathChange) {
					t.Stop()
					break waiting
				}
			}
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// session is one stream from its dial to its end. readyAt is when it
// reached READY (zero if it never did).
func (w *worker) session() (readyAt time.Time, err error) {
	c := w.c
	// A notice older than this session's dial is answered by the session
	// that starts now: whoever asked wanted a fresh one. From the dial on a
	// notice names THIS session and is kept — through the dial and the
	// handshake into the configuration wait and the serve loop. A server
	// that says it is restarting still answers for a moment, and a stream
	// set up in that moment is one the server that comes back never heard
	// of: dropped here, the notice would leave it ready on this side alone.
	select {
	case <-w.kick:
	default:
	}
	conn, peer, closeConn, err := c.cfg.Dial(c.ctx, w.id)
	if err != nil {
		return readyAt, fmt.Errorf("dial: %w", err)
	}
	// The socket is given back once — by this session's end or by the stop,
	// whichever is first. The stop does it BY ITSELF: a write parked in the
	// socket keeps this goroutine from ever reaching its own close, and it
	// is the close that ends the write.
	w.closing.Store(false)
	var once sync.Once
	release := func() {
		once.Do(func() {
			w.closing.Store(true) // before the close: a write it ends must know why it ended (failedWrite)
			closeConn()
		})
	}
	defer release()
	defer context.AfterFunc(c.ctx, release)()
	split := NewSplitter(conn, peer)

	var keys Keys
	switch c.cfg.Keys {
	case KeysWrap:
		wrap, err := WrapKey(c.cfg.Password)
		if err != nil {
			return readyAt, err
		}
		keys = WrapKeys(wrap)
		split.Seal()
	default:
		keys, err = Handshake(c.ctx, split)
		if err == nil {
			c.handshakes.Add(1)
			break
		}
		if c.cfg.Keys == KeysDTLS || c.ctx.Err() != nil {
			return readyAt, err
		}
		c.fallbacks.Add(1)
		c.cfg.Logf("csqtt25: worker %d: no DTLS handshake (%v) — password-derived keys", w.id, err)
		wrap, werr := WrapKey(c.cfg.Password)
		if werr != nil {
			return readyAt, werr
		}
		keys = WrapKeys(wrap)
	}
	sendC, err := NewCipher(keys.Client)
	if err != nil {
		return readyAt, err
	}
	recvC, err := NewCipher(keys.Server)
	if err != nil {
		return readyAt, err
	}
	wrapper, err := NewWrapper(sendC, c.cfg.Mode)
	if err != nil {
		return readyAt, err
	}
	w.mu.Lock()
	w.conn, w.peer, w.wrapper = conn, peer, wrapper
	w.mu.Unlock()
	w.reasm = NewReassembler()
	defer func() {
		w.ready.Store(false)
		// The socket goes FIRST, the lock after: a write parked in the socket
		// holds the lock, and only the close ends it — taken in the other
		// order, a session whose relay had stopped taking bytes could not end
		// on anybody's word until that write came back by itself.
		release()
		w.mu.Lock()
		w.conn = nil
		w.mu.Unlock()
	}()

	media := split.Media()
	conf, err := w.getconf(media, recvC)
	if err != nil {
		return readyAt, err
	}
	c.setConfig(conf)
	if err := w.send([]byte(ReadyRequest)); err != nil {
		return readyAt, fmt.Errorf("READY: %w", err)
	}
	readyAt = time.Now()
	w.lastRx.Store(readyAt.UnixNano())
	w.ready.Store(true)
	c.sessions.Add(1)
	c.rallied()
	if w.id == 1 {
		_ = w.send([]byte(WorkersRequest(c.cfg.Password, c.cfg.Workers)))
	}

	tick := time.NewTicker(serveTick)
	defer tick.Stop()
	watch := newStreamWatch(c.wakeEpoch.Load())
	for {
		select {
		case <-c.ctx.Done():
			return readyAt, c.ctx.Err()
		case why := <-w.kick:
			return readyAt, why
		case wire, ok := <-media:
			if !ok {
				return readyAt, errors.New("the stream's socket closed")
			}
			if w.receive(wire, recvC) {
				watch.heard(watch.now())
			}
			continue
		case <-w.nudge: // the wake word: a pass now — it finds the epoch moved, or it is a short tick
		case <-tick.C:
		}
		if w.id > c.targetNow() {
			return readyAt, errParked
		}
		// The rule (liveness.go). Every write it asks for goes through say: the
		// loop never waits in a socket.
		epoch := c.wakeEpoch.Load()
		act, gap := watch.tick(watch.now(), epoch, c.unsettled(time.Unix(0, w.lastRx.Load())))
		if seen := c.wakeEpoch.Load(); act.ends() && seen != epoch {
			// The wake word was said while this verdict was being reached. A
			// verdict is about the time before the epoch it was reached under:
			// it is carried out only if that is still the epoch — looked at
			// again HERE, behind the rule and in front of the session's end.
			// Otherwise the word opens its own window, under the epoch just
			// seen, and the stream is asked.
			watch.void(watch.now(), seen)
			act = watchWoke
		}
		switch act {
		case watchFroze:
			c.froze(gap, watch.late)
			c.probes.Add(1)
			w.say([]byte(ReadyRequest))
		case watchWoke, watchAsk:
			c.probes.Add(1)
			w.say([]byte(ReadyRequest))
		case watchDeaf:
			return readyAt, errDeaf
		case watchUnsettled:
			c.unsettledN.Add(1)
			return readyAt, errUnsettled
		case watchWakeDeaf:
			c.wakeDeaf.Add(1)
			return readyAt, errWakeDeaf
		default:
			if time.Since(time.Unix(0, w.lastTx.Load())) >= watch.idle {
				w.say(IdleKeepalive)
			}
		}
	}
}

// getconf asks for the configuration on the reference's schedule: the
// request twice, then a wait, four times over.
func (w *worker) getconf(media <-chan []byte, recvC *Cipher) (ConfigResponse, error) {
	c := w.c
	gen, salt := c.identity()
	req := []byte(ConfigRequest(c.cfg.LocalPort, c.cfg.Password, gen, salt, w.id, c.cfg.Workers))
	for _, wait := range getconfWaits {
		for i := 0; i < 2; i++ {
			if err := w.send(req); err != nil {
				return ConfigResponse{}, fmt.Errorf("GETCONF: %w", err)
			}
		}
		deadline := time.NewTimer(wait)
	waiting:
		for {
			select {
			case <-c.ctx.Done():
				deadline.Stop()
				return ConfigResponse{}, c.ctx.Err()
			case <-deadline.C:
				break waiting
			case why := <-w.kick:
				deadline.Stop()
				return ConfigResponse{}, why
			case wire, ok := <-media:
				if !ok {
					deadline.Stop()
					return ConfigResponse{}, errors.New("the stream's socket closed")
				}
				if !IsRTP(wire) {
					continue
				}
				plain, _, err := recvC.Unwrap(wire)
				if err != nil {
					c.authFailures.Add(1)
					continue
				}
				if IsPanelRestart(plain) {
					// Said down a stream that is not ready yet — the only one
					// there is while the first worker dials. The same notice:
					// every worker starts over, this one through its own kick.
					c.panelRestart()
					continue
				}
				if !IsConfigResponse(plain) {
					continue
				}
				deadline.Stop()
				return ParseConfigResponse(plain)
			}
		}
	}
	return ConfigResponse{}, errors.New("no answer to GETCONF (a server gives silence to keys it cannot use)")
}

// receive handles one datagram of a ready stream and says whether it was the
// server's: it opened under the stream's key.
func (w *worker) receive(wire []byte, recvC *Cipher) bool {
	if !IsRTP(wire) {
		return false
	}
	plain, _, err := recvC.Unwrap(wire)
	if err != nil {
		w.c.authFailures.Add(1)
		return false
	}
	w.lastRx.Store(time.Now().UnixNano())
	w.take(plain)
	return true
}

// take handles one authentic plaintext of a ready stream.
func (w *worker) take(plain []byte) {
	c := w.c
	// Control first: several control strings begin with a byte that reads
	// as an IP version.
	if IsControl(plain) {
		switch {
		case IsConfigResponse(plain):
			if conf, err := ParseConfigResponse(plain); err == nil {
				c.setConfig(conf)
			}
		case string(plain) == DisconnectedResponse:
			select {
			case c.disconnected <- struct{}{}:
			default:
			}
		case IsPanelRestart(plain):
			c.panelRestart()
		default:
			if agreed, _, ok := ParseWorkers(plain); ok {
				c.setTarget(agreed)
			} else if cmd, ok := ParseStreamRepair(plain); ok {
				c.repair(cmd)
			}
		}
		return
	}
	if IsFragment(plain) {
		c.fragsRx.Add(1)
		whole, done := w.reasm.Push(plain, time.Now())
		if !done {
			return
		}
		plain = whole
	}
	if len(plain) == 0 || (plain[0]>>4 != 4 && plain[0]>>4 != 6) {
		return
	}
	c.rxPackets.Add(1)
	c.rxBytes.Add(int64(len(plain)))
	c.cfg.Deliver(plain)
}
