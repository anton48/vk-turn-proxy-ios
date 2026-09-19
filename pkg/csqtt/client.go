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

	// Creds mints a relay credential for a worker. Called with the worker id
	// (1-BASED — a pool indexed from 0 maps worker k to k−1) each time that
	// worker (re)starts, BEFORE the start gate, so a pool that parks the
	// caller (cold-start cap, path-change settle) stalls only this worker;
	// ctx ends the wait. The pool policy is the caller's. The Release in the
	// result is called exactly once — when the allocation obtained with the
	// credential is gone, or at once when the allocation failed; Failed, if
	// set, is called first with DialRelay's error whenever the allocation
	// failed, so the pool can act on a refusal — a 486 must move this worker
	// to another credential, and a pool that only hears Release cannot.
	Creds func(ctx context.Context, workerID int) (Credential, error)

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

	gate     *startGate
	anyRx    atomic.Int64 // last inbound on any worker, unix nanos
	probes   atomic.Int64 // liveness probes marked
	reprobes atomic.Int64 // unanswered probes sent again — by the liveness rule, and by a round that is asked again
	roundAsk atomic.Int64 // times a standing, unanswered probe round was asked again (each time: every ready worker)
	witness  atomic.Int64 // READYs to a worker known to be alive, asked beside them (askWitness)
	resets   atomic.Int64 // monitor ticks found late (descheduled)
	lostToL  atomic.Int64 // workers restarted by the liveness verdict
	lastTick atomic.Int64 // the monitor's previous tick (or a WakeHealthCheck), unix nanos

	// deafness (see deafVerdict): judged for the client as a whole, by the
	// monitor's tick and by the wake verdict — deafMu makes the two take turns,
	// so one silence is answered by one restart-all.
	deafMu sync.Mutex
	// rxSeq counts REAL inbound datagrams on every worker and nothing else — no
	// clock reset touches it. "Was the round answered" is read from it; the
	// clocks (anyRx, a worker's lastRx) restart on a wake and on a late tick and
	// prove nothing about reception.
	rxSeq        atomic.Uint64
	round        atomic.Pointer[probeRound] // the probe round that stands; nil if none
	listenMu     sync.Mutex                 // starting a wake round's watcher vs Close: no Add after the Wait began
	listeners    sync.WaitGroup             // the wake rounds' watchers, joined by Close
	lastDeafAll  atomic.Int64               // the last restart-all, unix nanos
	deafRounds   int                        // restart-alls in the current run (under deafMu)
	deafRestarts atomic.Int64               // restart-alls, ever
	heldSaid     bool                       // the spacing's hold was logged for this round (under deafMu)

	// identity is the (generation, salt) pair every worker's GETCONF carries.
	// OnPathChange replaces it ONCE for the whole client — the server's
	// epoch rule then drops every session of the old pair — and every worker
	// re-announces under the new one. A REPAIR or a panel restart keeps it.
	identMu     sync.Mutex
	gen         uint64
	salt        string
	pathChanges atomic.Int64
	allocRTT    atomic.Int64 // the last relay allocation, nanoseconds
}

// Credential is what Creds returns: the relay credential and the two calls
// the pool wants back. Release is called exactly once per successful Creds
// — when the allocation obtained with it is gone (the session ended for any
// reason, including Close), or at once when the allocation never came up.
// Failed is called at most once, BEFORE that Release, with DialRelay's
// error whenever the allocation did not come up — the relay refused it,
// never answered, or a step around it failed (the local socket, the TCP
// dial, the permission). The POOL decides what the error means: a 486
// (quota) marks the slot so the next Creds hands out another credential,
// a 401/403 invalidates it, anything else changes nothing. A worker that
// only released handed the same exhausted credential back to itself on
// every retry (the user's review, 2026-09-06: two 486s, one mint, zero
// saturated slots). nil callbacks mean no bookkeeping (a manual
// credential).
type Credential struct {
	TURNCredentials
	Release func()
	Failed  func(err error)
	// Allocated, when set, is called once the relay ACCEPTED the allocation
	// — the pool's evidence that this identity works, so a later 486 on it
	// is its quota rather than the relay refusing everything (the pool's
	// relay-refusal breaker keys on that). Called before READY.
	Allocated func()
}

// dialRelay is DialRelay, replaceable by tests with a loopback relay.
var dialRelay = DialRelay

// identity is the pair the next GETCONF must carry.
func (c *Client) identity() (uint64, string) {
	c.identMu.Lock()
	defer c.identMu.Unlock()
	return c.gen, c.salt
}

// OnPathChange is the app's path-change hook: the network underneath every
// allocation changed, so the whole session is replaced under a NEW
// identity (one pair for all workers) and every worker restarts. Each old
// session's credential is released as it ends; the new starts acquire
// afresh, so the pool's own path-change marking spreads them.
func (c *Client) OnPathChange() {
	c.identMu.Lock()
	c.gen, c.salt = NewIdentity(c.gen)
	gen := c.gen
	c.identMu.Unlock()
	c.pathChanges.Add(1)
	c.cfg.Logf("csqtt: path change — new identity gen=%d, restarting every worker", gen)
	c.restartAll("path change")
}

// WakeHealthCheck is the app's wake hook. The process may have been
// suspended for any length of time, so nothing observed before now means
// anything: every clock restarts here (as a late monitor tick does), and
// every ready worker is probed at once — a dead one is then given up on
// deadAfterProbe later instead of probeAfter+deadAfterProbe. The monitor's
// tick mark moves too, so the tick that follows does not read the wake gap
// as a deschedule and wipe the probes. The hook never waits for a relay
// write (see worker.probe): it runs on the extension's wake/path callback.
func (c *Client) WakeHealthCheck() {
	ns := time.Now().UnixNano()
	// A wake is a freeze boundary, and it is PUBLISHED as one before anything
	// else happens: from this Store on, a verdict that judgeDeaf — which does
	// not take turns with this hook — reached on an older round can no longer
	// be committed (its CompareAndSwap fails). Published after the probes, the
	// window would be theirs: asked again, not yet answered, and restarted on
	// the old round's word. The count is read first: whatever arrives from here
	// on answers the round.
	r := &probeRound{at: ns, wake: true, rxSeq: c.rxSeq.Load()}
	c.round.Store(r) // a wake is a freeze boundary: whatever round stood before it is replaced
	c.anyRx.Store(ns)
	probed := 0
	for _, w := range c.workers {
		w.lastRx.Store(ns)
		w.clearProbe()
		if w.ready.Load() {
			w.probe(ns)
			probed++
		}
	}
	c.lastTick.Store(ns)
	c.cfg.Logf("csqtt: wake — clocks reset, %d ready worker(s) probed", probed)
	if probed == 0 {
		c.round.CompareAndSwap(r, nil) // nobody was asked: there is no round to listen to
		return
	}
	// The probes just sent are the ROUND: if NO worker hears anything in
	// wakeDeafAfter of listening, every allocation died in the freeze (or the
	// path did) and waiting for the monitor's thirty seconds serves nobody.
	c.listenMu.Lock()
	if !c.closing.Load() {
		c.listeners.Add(1)
		go func() {
			defer c.listeners.Done()
			c.listenTo(r)
		}()
	}
	c.listenMu.Unlock()
}

// probeRound is one round of probes to every ready worker: when it went out,
// who sent it, and the real-inbound count at that moment — the round is
// answered once the count has moved. Its identity never changes (one pointer:
// a reader never sees half of a newer round, and a drop is a CompareAndSwap
// that cannot take a newer round with it); only `listened` grows.
type probeRound struct {
	at       int64        // unix nanos: tells a round published AFTER a late tick read its mark from one that predates the freeze
	wake     bool         // the wake hook's: its listening is counted by listenTo, the monitor's by the monitor's ticks
	rxSeq    uint64       // Client.rxSeq when the probes went out
	listened atomic.Int64 // nanos of AWAKE time observed since — a freeze is never in it
}

// wakeListenSleep waits one step and says how long it really took; a test
// makes a step "take" ninety seconds to stand in for a freeze.
var wakeListenSleep = func(ctx context.Context, d time.Duration) time.Duration {
	t0 := time.Now()
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
	return time.Since(t0)
}

// listenTo is a wake round's watcher: it counts the round's LISTENING in short
// steps and asks for the verdict once there is wakeDeafAfter of it. It ends
// with the round — answered, replaced by a newer one, dropped, or judged. A
// step that took far longer than it should means the process was frozen in it:
// the round then predates a freeze and is dropped — never judged on what it
// did not hear while nobody was listening; the next wake, or the monitor's
// thirty seconds of silence, asks again.
func (c *Client) listenTo(r *probeRound) {
	nextAsk := wakeAskAgainEvery
	for {
		took := wakeListenSleep(c.ctx, wakeListenStep)
		if c.ctx.Err() != nil || c.round.Load() != r || c.rxSeq.Load() != r.rxSeq {
			return
		}
		if took > 2*wakeListenStep {
			c.round.CompareAndSwap(r, nil)
			return
		}
		listened := time.Duration(r.listened.Add(int64(took)))
		if listened >= wakeDeafAfter {
			c.judgeDeaf(time.Now(), time.Time{}) // held by the spacing, the round stands and is judged again next step — and asked again at the monitor's ticks, not here
		} else if listened >= nextAsk {
			nextAsk = listened + wakeAskAgainEvery
			c.askRoundAgain(r, listened, time.Now())
		}
	}
}

// askRoundAgain sends the probes of a round that stands unanswered AGAIN, to
// every ready worker whose probe is still out. The round's own record is not
// touched — its listening, and with it its verdict, is the first ask's. Each
// probe is sent again the way the liveness rule does it (worker.reprobe): by
// CompareAndSwap from the state that was read, and with the FACT of whether the
// client has heard anything since the send before — in a silence it has not,
// so these re-sends can never count against a worker.
func (c *Client) askRoundAgain(r *probeRound, listened time.Duration, at time.Time) {
	now := at.UnixNano()
	n := 0
	for _, w := range c.workers {
		if !w.ready.Load() {
			continue
		}
		if st := w.probeSt.Load(); st != nil && w.reprobe(st, now, c.rxSeq.Load() != st.seq) {
			n++
		}
	}
	c.roundAsk.Add(1)
	kind := "the round"
	if r.wake {
		kind = "the wake round"
	}
	c.cfg.Logf("csqtt: not one answer %s into %s — %d ready worker(s) asked again", listened.Round(100*time.Millisecond), kind, n)
}

// dropRoundBefore is the monitor's part of the same rule, at a late tick: a
// round sent before the freeze goes. One published AFTER this tick read its
// mark — the wake hook runs side by side with the late tick at an unfreeze —
// is fresh and stays; and the drop is a CompareAndSwap, so a round published
// between the look and the drop is not the one dropped.
func (c *Client) dropRoundBefore(mark time.Time) {
	if r := c.round.Load(); r != nil && r.at <= mark.UnixNano() {
		c.round.CompareAndSwap(r, nil)
	}
}

// deafVerdictReached is a test's window between a verdict and its execution:
// the wake hook is not serialized with judgeDeaf, and what it publishes in that
// window decides whether the verdict may still be carried out. nil in production.
var deafVerdictReached func(deafAction)

// judgeDeaf applies deafVerdict. prevTick is the monitor's previous tick, zero
// from a wake round's watcher (which notices a freeze by its own steps).
//
// 🚨 A verdict belongs to the ROUND it was reached on, and it is COMMITTED by
// taking that round down with a CompareAndSwap — before anything else is
// changed. The wake hook publishes from its own callback at any moment: if a
// fresher round stands by then, a wake has happened — a freeze boundary — and
// the old verdict is void; nothing is touched, the fresh round gets its own
// listening and its own verdict. (Build 413 ignored the CompareAndSwap's
// answer: the fresh round survived, and the healthy workers that had just
// answered it were restarted all the same.)
func (c *Client) judgeDeaf(now, prevTick time.Time) {
	c.deafMu.Lock()
	defer c.deafMu.Unlock()
	last := nanosTime(c.lastDeafAll.Load())
	if !last.IsZero() && now.Sub(last) >= deafQuiet {
		c.deafRounds = 0
	}
	in := deafInput{Now: now, PrevTick: prevTick, AnyRx: time.Unix(0, c.anyRx.Load()),
		LastRestartAll: last, Rounds: c.deafRounds}
	r := c.round.Load()
	if r != nil {
		in.RoundOut, in.RoundIsWake, in.RoundListened = true, r.wake, time.Duration(r.listened.Load())
		in.RoundAnswered = c.rxSeq.Load() != r.rxSeq // a FACT the read loops counted, not a comparison of clocks
	}
	for _, w := range c.workers {
		if at := w.readyAt.Load(); at != 0 && now.Sub(time.Unix(0, at)) >= readyGrace {
			in.Judgeable++
		}
	}
	action := deafVerdict(in)
	if deafVerdictReached != nil && action != deafNone {
		deafVerdictReached(action)
	}
	switch action {
	case deafProbeAll:
		// The round is published FIRST, over the round that was judged and no
		// other: if the wake hook has just asked everybody itself, its round
		// stands and this one is not sent. (The count is read before the probes
		// go out: no answer can precede its probe.)
		if !c.round.CompareAndSwap(r, &probeRound{at: now.UnixNano(), rxSeq: c.rxSeq.Load()}) {
			return
		}
		probed := 0
		for _, w := range c.workers {
			if w.ready.Load() {
				w.probe(now.UnixNano())
				probed++
			}
		}
		c.heldSaid = false
		c.cfg.Logf("csqtt: no worker has heard anything for %s — %d ready worker(s) probed at once", now.Sub(in.AnyRx).Round(time.Second), probed)
	case deafAskAgain:
		c.askRoundAgain(r, in.RoundListened, now)
	case deafHeld:
		if !c.heldSaid {
			c.heldSaid = true
			c.cfg.Logf("csqtt: deaf again — the restart of every worker is held until %s after the previous one (round %d of this run)",
				deafSpacingFor(in.Rounds), in.Rounds)
		}
		// A held round keeps asking — the hold can last minutes, and the path
		// may come back in them onto an idle tunnel. At the MONITOR's ticks,
		// whoever's round it is: a wake round's watcher asks inside its window
		// only, and comes here every quarter of a second while the hold lasts.
		if !prevTick.IsZero() {
			c.askRoundAgain(r, in.RoundListened, now)
		}
	case deafRestartAll:
		// COMMIT: the judged round comes down, by CompareAndSwap, and only if
		// that succeeds — and if not one real inbound has arrived up to this
		// very moment — is the verdict carried out. Otherwise nothing changes.
		if !c.round.CompareAndSwap(r, nil) || c.rxSeq.Load() != r.rxSeq {
			return
		}
		c.identMu.Lock()
		c.gen, c.salt = NewIdentity(c.gen)
		gen := c.gen
		c.identMu.Unlock()
		c.deafRounds++
		c.deafRestarts.Add(1)
		c.lastDeafAll.Store(now.UnixNano())
		c.heldSaid = false
		c.anyRx.Store(now.UnixNano()) // the silence that was judged ends here; the next one is counted afresh
		c.cfg.Logf("csqtt: DEAF — %d ready worker(s) and not one answer in %s of listening after the probe round: every allocation is presumed dead, new identity gen=%d, restarting every worker (round %d)",
			in.Judgeable, in.RoundListened.Round(100*time.Millisecond), gen, c.deafRounds)
		c.restartAll("deaf: no worker heard anything after a probe round")
	}
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
		gate:     newStartGate(cfg.StartPacing),
	}
	c.striper.SetChunks(cfg.Chunks)
	c.gen, c.salt = cfg.Generation, cfg.Salt
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
		go c.workers[i].run() // paced by the start gate inside session()
	}
	c.wg.Add(1)
	go c.monitor()
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
// Close stops the client within a bounded time: DISCONNECT is best-effort
// (a write that blocks — a full TCP buffer to the relay — must not hold the
// stop), then every relay is closed CONCURRENTLY and INSIDE the join budget
// — a relay's own close writes the deallocate under relayCloseWriteBudget,
// and thirty of those in a row would be fifteen seconds — then the
// goroutines are joined with the same budget; whatever is still stuck dies
// with the process, as Proxy.StopWithTimeout accepts.
func (c *Client) Close() error {
	if !c.closing.CompareAndSwap(false, true) {
		return nil
	}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		_, salt := c.identity()
		req := []byte(DisconnectRequest(c.cfg.DeviceID, salt))
		for _, w := range c.workers {
			if w.ready.Load() {
				_ = w.send(req)
				return
			}
		}
	}()
	select {
	case <-sent:
	case <-time.After(closeDisconnectBudget):
		c.cfg.Logf("csqtt: close: DISCONNECT did not go out within %s", closeDisconnectBudget)
	}
	c.stop()
	var closers sync.WaitGroup
	for _, w := range c.workers {
		closers.Add(1)
		go func(w *worker) {
			defer closers.Done()
			w.closeRelay()
		}(w)
	}
	c.listenMu.Lock() // closing is set: no watcher starts from here on, and one that raced us has added itself
	c.listenMu.Unlock()
	joined := make(chan struct{})
	go func() {
		closers.Wait()
		c.wg.Wait()
		c.listeners.Wait() // each ends within a step of the stop
		close(joined)
	}()
	select {
	case <-joined:
	case <-time.After(closeJoinBudget):
		c.cfg.Logf("csqtt: close: goroutines still running after %s — returning anyway", closeJoinBudget)
	}
	return nil
}

// The stop budgets: how long DISCONNECT may take to go out, and how long the
// goroutines may take to end after the relays are closed.
const (
	closeDisconnectBudget = 500 * time.Millisecond
	closeJoinBudget       = 2 * time.Second
)

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

// Blackhole is FAULT INJECTION for the stand: from now on worker id drops
// every inbound datagram of its current session, as if the relay had gone
// silent. The liveness rule is expected to probe it and then restart it;
// the restarted session is not blackholed. Not for production.
func (c *Client) Blackhole(workerID int, on bool) {
	if workerID >= 1 && workerID <= len(c.workers) {
		c.workers[workerID-1].blackhole.Store(on)
	}
}

// restartAll kicks every worker — the server restarted and holds no
// sessions, so each one has to GETCONF again (same identity: the server is
// empty, and a new pair is for a NEW connection, see NewIdentity).
func (c *Client) restartAll(reason string) {
	for _, w := range c.workers {
		w.restart(reason)
	}
}

// monitor runs the liveness rule every livenessTick.
func (c *Client) monitor() {
	defer c.wg.Done()
	tick := time.NewTicker(livenessTick)
	defer tick.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tick.C:
		}
		c.monitorStep(time.Now())
	}
}

// monitorStep is one tick of the monitor at `now`: the per-worker rule, the
// deschedule reset, then the client-wide deafness rule.
func (c *Client) monitorStep(now time.Time) {
	prev := nanosTime(c.lastTick.Load())
	anyRx := time.Unix(0, c.anyRx.Load())
	reset := false
	asked := false
	again, againHeard := 0, 0 // this tick's re-sends, and how many of them with the client hearing since the send before
	for _, w := range c.workers {
		in := livenessInput{Now: now, PrevTick: prev, AnyRx: anyRx,
			ReadyAt: nanosTime(w.readyAt.Load()), LastRx: nanosTime(w.lastRx.Load())}
		// The probe's state is ONE value, loaded once; the facts beside it are
		// read AFTER it — the read loop counts an inbound (w.rx) before anything
		// else, so an answer that has reached it is seen here whatever it has
		// or has not got round to yet.
		st := w.probeSt.Load()
		heardSince := false
		if st != nil {
			heardSince = c.rxSeq.Load() != st.seq
			in.ProbeSentAt, in.LastProbeAt = nanosTime(st.firstAt), nanosTime(st.lastAt)
			in.LiveProbes = st.confirmed(heardSince)
			in.Answered = w.rx.Load() != st.rx
		}
		switch livenessVerdict(in) {
		case livenessResetAll:
			reset = true
		case livenessProbe:
			w.probe(now.UnixNano())
			asked = true
		case livenessReprobe:
			if w.reprobe(st, now.UnixNano(), heardSince) {
				asked = true
				again++
				if heardSince {
					againHeard++
				}
			}
		case livenessAnswered:
			// The probe has been answered: its state comes down — here, and not
			// only in the read loop, which clears on an inbound and so cannot clear
			// a state PUBLISHED after the inbound that answers it (see worker.probe).
			// By CompareAndSwap from the state that was looked at: a fresh probe
			// the wake hook has put in its place meanwhile is not the one removed.
			if hook := livenessVerdictReached.Load(); hook != nil {
				(*hook)(w, livenessAnswered)
			}
			w.probeSt.CompareAndSwap(st, nil)
		case livenessRestart:
			if hook := livenessVerdictReached.Load(); hook != nil {
				(*hook)(w, livenessRestart)
			}
			// COMMIT, as for the deafness verdict: the probe's state comes down by
			// CompareAndSwap from the one the verdict was reached on, the worker's
			// inbound count is read once more beside it, and only then is anything
			// done. An answer that landed meanwhile — or a fresh probe from the
			// wake hook — voids the verdict.
			if !w.probeSt.CompareAndSwap(st, nil) || w.rx.Load() != st.rx {
				continue
			}
			c.lostToL.Add(1)
			w.restart("liveness: no inbound after a probe while other workers are live")
		}
	}
	if asked && !reset {
		c.askWitness()
	}
	if again > 0 {
		// One line per tick that sends probes again, split by the FACT the
		// counting rests on: a total alone cannot say whether the re-sends went
		// out while the path worked or into a silence (field, 2026-09-19: "+28
		// sent again" over a run with a block in it — unreadable).
		c.cfg.Logf("csqtt: liveness — %d unanswered probe(s) sent again: %d with the client hearing since the send before (the path works), %d into silence",
			again, againHeard, again-againHeard)
	}
	if reset {
		// The process was not running: nothing observed in that gap means
		// anything. Every clock starts over from now.
		c.resets.Add(1)
		c.cfg.Logf("csqtt: monitor tick %.0fs late — descheduled, clocks reset, no verdict", now.Sub(prev).Seconds())
		c.anyRx.Store(now.UnixNano())
		for _, w := range c.workers {
			w.lastRx.Store(now.UnixNano())
			w.clearProbe()
		}
		// 🚨 The probe ROUND is not a clock, and the reset above neither answers
		// nor un-answers one. But a round sent BEFORE this freeze goes: it
		// proves nothing now. A round the wake hook published while this late
		// tick was under way — the two run side by side at an unfreeze — is
		// fresh and stands as it is, whichever of the two ran first.
		c.dropRoundBefore(prev)
	} else {
		if r := c.round.Load(); r != nil && !r.wake && now.After(prev) {
			r.listened.Add(int64(now.Sub(prev))) // an on-time tick: the process ran, and listened, since the previous one
		}
		c.judgeDeaf(now, prev)
	}
	c.lastTick.Store(now.UnixNano())
}

func nanosTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
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

// Stats is a snapshot of the client. The first block is what the app's
// Stats carries (bytes, connections, RTT, reconnects); the rest is csqtt's own.
type Stats struct {
	TxBytes     int64         // plaintext bytes sent through the relays (IP packets + control)
	RxBytes     int64         // plaintext bytes received
	Ready       int           // workers with a session — READY_OK once, not restarted since
	Live        int           // … of them, heard from within liveWindow: what the app shows as connections
	Total       int           // workers configured
	Restarts    int64         // worker restarts, all reasons
	AllocateRTT time.Duration // the last relay allocation
	Generation  uint64
	PathChanges int64

	Workers     []WorkerStats
	Dropped     int64 // inbound packets the TUN side did not take in time
	NoWorker    int64 // outbound packets with no ready worker
	FramedTx    int64
	DupTx       int64
	Reassembled int64
	Repairs     int64
	Probes      int64 // liveness probes marked (the send is asynchronous)
	Reprobes    int64 // unanswered probes sent again — per worker, whoever sent them again
	RoundAsks   int64 // times a standing, unanswered probe ROUND was asked again
	Witnesses   int64 // READYs to a worker known to be alive, asked beside them
	Descheduled int64 // monitor ticks found late
	LostWorkers int64 // workers restarted by the liveness verdict
	DeafAll     int64 // restart-alls by the deafness verdict
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
		Probes:      c.probes.Load(),
		Reprobes:    c.reprobes.Load(),
		RoundAsks:   c.roundAsk.Load(),
		Witnesses:   c.witness.Load(),
		Descheduled: c.resets.Load(),
		LostWorkers: c.lostToL.Load(),
		DeafAll:     c.deafRestarts.Load(),
	}
	now := time.Now()
	s.AllocateRTT = time.Duration(c.allocRTT.Load())
	s.Generation, _ = c.identity()
	s.PathChanges = c.pathChanges.Load()
	s.Total = len(c.workers)
	for _, w := range c.workers {
		ws := w.stats()
		s.Workers = append(s.Workers, ws)
		s.TxBytes += w.txBytes.Load()
		s.RxBytes += w.rxBytes.Load()
		s.Restarts += ws.Restarts
		if ws.Ready {
			s.Ready++
			if !ws.LastRx.IsZero() && now.Sub(ws.LastRx) <= liveWindow {
				s.Live++
			}
		}
	}
	return s
}

// ─── worker ───────────────────────────────────────────────────────────────

const (
	readyWait      = 3 * time.Second
	restartBackoff = time.Second
	maxBackoff     = 30 * time.Second
)

// keepaliveEvery is the idle keepalive cadence (the reference client's 10 s).
// A variable so a test can park every session in its own keepalive write.
var keepaliveEvery = 10 * time.Second

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

	ready     atomic.Bool
	tx, rx    atomic.Int64
	txBytes   atomic.Int64
	rxBytes   atomic.Int64
	restarts  atomic.Int64
	lastRx    atomic.Int64 // the liveness CLOCK, unix nanos: last inbound OR the last clock reset (a wake, a late tick)
	heardAt   atomic.Int64 // the last REAL inbound, unix nanos — no reset touches it; what the stats report
	lastTx    atomic.Int64
	readyAt   atomic.Int64               // unix nanos; 0 while not ready
	blackhole atomic.Bool                // FAULT INJECTION: drop every inbound datagram of the current session
	probeSt   atomic.Pointer[probeState] // the probe that is out for the current silence; nil if none. Any inbound clears it
	probing   atomic.Bool                // a READY probe is in its write (at most one goroutine behind a blocked relay)
	relayStr  atomic.Pointer[string]
	relayRef  atomic.Pointer[Relay] // the live allocation, for closeRelay — no mutex, a blocked send holds mu

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
	if ns := w.heardAt.Load(); ns != 0 { // the real one: a clock reset must not make a deaf worker look heard-from
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

// probe marks a READY probe as sent at `now` and sends it WITHOUT holding
// the caller. On the TCP transport a full buffer toward a relay that
// stopped taking bytes blocks WriteTo, and the callers are the app's wake
// hook and the monitor: the first must return to the extension, the second
// must not arrive late at its own next tick and read the stall as a
// deschedule — which wipes every probe mark. The mark goes first, so a
// write that never completes is an unanswered probe: the liveness rule
// restarts the worker, and the teardown closes the relay, which frees the
// write. One probe in flight per worker — a second wake does not queue
// another goroutine behind the same blocked write.
//
// This is the FIRST probe of a silence, and it starts the restart's clock. As
// the wake hook and the deafness round send it, nobody is known to be hearing —
// such a probe may go into a dead path — so a first probe is never counted
// against the worker; what can count is the re-sends: see reprobe. It REPLACES
// whatever probe stood (a wake is a boundary; the round asks everybody afresh).
// The two counts are read before the send: no answer can precede its probe.
// 🚨 But an inbound CAN land between the reading of the counts and the
// publication — the read loop does not take turns with this function — and it
// has then done all it will ever do about this probe (counted, cleared what
// stood) BEFORE the state exists: the state is born answered with nobody left
// to clear it. The monitor takes an answered state down itself
// (livenessAnswered); that, not the read loop, is what ends such a probe.
func (w *worker) probe(now int64) {
	st := &probeState{firstAt: now, lastAt: now, rx: w.rx.Load(), seq: w.c.rxSeq.Load()}
	if hook := probeSnapshotTaken.Load(); hook != nil {
		(*hook)(w)
	}
	w.probeSt.Store(st)
	w.c.probes.Add(1)
	w.sendProbe()
}

// probeSnapshotTaken is a test's window INSIDE worker.probe, between the
// reading of the two counts and the publication of the probe's state — nil in
// production. The read loop does not take turns with probe: an inbound can be
// counted, and the probe cleared, in exactly that window.
var probeSnapshotTaken atomic.Pointer[func(*worker)]

// reprobe sends the unanswered probe AGAIN — the liveness rule's doing alone.
// The new state takes the old one's place by CompareAndSwap: if the read loop
// has cleared the probe meanwhile (the answer came), or the wake hook or the
// round has put a fresh one there, theirs stands and nothing is sent. 🚫 The
// first probe's time and the worker's inbound count at that time are carried
// over untouched: the restart's clock is the first probe's, and "answered" is
// asked of the whole silence. Whether this re-send will count against the
// worker is decided by facts — heardSince now (the client really received
// something since the send before), and again at the next tick
// (probeState.confirmed). A probe whose write is still blocked is a probe all
// the same: the mark goes first — a relay that takes no bytes is no answer.
func (w *worker) reprobe(st *probeState, now int64, heardSince bool) bool {
	next := &probeState{firstAt: st.firstAt, lastAt: now, rx: st.rx, seq: w.c.rxSeq.Load(),
		resent: true, heardBefore: heardSince, counted: st.confirmed(heardSince)}
	if !w.probeSt.CompareAndSwap(st, next) {
		return false
	}
	w.c.reprobes.Add(1)
	w.sendProbe()
	return true
}

// readLoopStamped is a test's window INSIDE the read loop, between the stamps
// of a real inbound and the clearing of the probe — nil in production. The
// monitor does not take turns with the read loop, and a verdict must hold in
// that window too.
var readLoopStamped atomic.Pointer[func(*worker)]

// clearProbe: the silence is over — an inbound arrived — or whatever was
// observed of it means nothing any more (a wake, a late tick, the session's end).
func (w *worker) clearProbe() {
	w.probeSt.Store(nil)
}

// livenessVerdictReached is a test's window between a verdict of the liveness
// rule that changes the probe's state — a restart, an answered probe taken down
// — and its execution; nil in production.
var livenessVerdictReached atomic.Pointer[func(*worker, livenessAction)]

// askWitness sends ONE READY to the worker most likely to be alive — ready, no
// probe out, the most recently heard from — at every tick at which the liveness
// rule has asked a silent worker anything. Its answer is the
// FACT the rule's evidence rests on: on an idle tunnel a worker hears nothing
// but the answers to its own probes, and after a wake or a deafness round every
// worker's cycle runs in step — half a minute can pass without one inbound
// while the path is perfectly well; the re-sends to a dead worker would then
// never be confirmed (probeState.confirmed), and it would stay. The witness
// keeps no probe state: it is not under suspicion, and a lost answer of its
// costs nothing but a tick of evidence.
func (c *Client) askWitness() {
	var best *worker
	var bestAt int64
	for _, w := range c.workers {
		if !w.ready.Load() || w.probeSt.Load() != nil { // a worker with a probe out is itself under suspicion — and may be the very one being asked
			continue
		}
		if h := w.heardAt.Load(); best == nil || h > bestAt {
			best, bestAt = w, h
		}
	}
	if best != nil {
		c.witness.Add(1)
		best.sendProbe()
	}
}

func (w *worker) sendProbe() {
	if !w.probing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer w.probing.Store(false)
		_ = w.send([]byte(ReadyRequest))
	}()
}

// closeRelay ends the current allocation from outside the session (Close):
// the read loop and any blocked write fail at once. Relay.Close is
// idempotent, so the session's own deferred close is harmless afterwards.
func (w *worker) closeRelay() {
	if r := w.relayRef.Load(); r != nil {
		r.Close()
	}
}

// run is the worker's life: dial, handshake, serve, and on any failure
// back off and dial again until the client stops.
func (w *worker) run() {
	defer w.c.wg.Done()
	backoff := restartBackoff
	for w.c.ctx.Err() == nil {
		started := time.Now()
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
		// A restart WE asked for (path change, panel restart, REPAIR, the
		// liveness verdict) is not a failure of the path: re-dial at once —
		// the start gate spaces the allocations — and leave the backoff
		// where it was. Only a session that ended on its own backs off.
		var asked *restartRequest
		if errors.As(err, &asked) {
			w.c.cfg.Logf("csqtt: worker %d: restarting now (%s)", w.id, asked.reason)
			continue
		}
		backoff = nextBackoff(backoff, time.Since(started))
		w.c.cfg.Logf("csqtt: worker %d: %v — restarting in %s", w.id, err, backoff)
		select {
		case <-time.After(backoff):
		case reason := <-w.kick:
			// The path changed (or the server asked) while we were backing
			// off from a failure this makes moot: re-dial now. The kick is
			// consumed here — left in its buffer through the sleep, it would
			// restart the next session the moment it was ready.
			w.c.cfg.Logf("csqtt: worker %d: restarting now (%s) — backoff cut short", w.id, reason)
		case <-w.c.ctx.Done():
			return
		}
	}
}

// restartRequest is how a session reports that it ended because someone
// asked (worker.restart), as opposed to failing.
type restartRequest struct{ reason string }

func (r *restartRequest) Error() string { return "restart requested: " + r.reason }

// healthySession is how long a session must have lived for its end to
// count as a fresh failure rather than the next in a run of them.
const healthySession = 2 * readyGrace

// nextBackoff is the restart delay after a session that lived `lived`:
// a session that held for healthySession resets the run — the delay starts
// over at restartBackoff — while a short-lived one doubles it up to
// maxBackoff. Without the reset a worker restarted a few times over a day
// (a panel restart, a liveness verdict, a relay refresh failing once) would
// wait the full maxBackoff for every later blip, for ever.
func nextBackoff(prev, lived time.Duration) time.Duration {
	if lived >= healthySession {
		return restartBackoff
	}
	next := prev * 2
	if next > maxBackoff {
		next = maxBackoff
	}
	return next
}

// session is one allocation's lifetime. It returns why it ended.
func (w *worker) session() error {
	ctx := w.c.ctx
	// The credential first, OUTSIDE the start gate: a pool may park this
	// worker (cold-start cap, path-change settle) and a park inside the gate
	// would stall every other start. The lease is released exactly once,
	// whatever ends the session — or right here if the allocation fails.
	cred, err := w.c.cfg.Creds(ctx, w.id)
	if err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	released := false
	release := func() {
		if cred.Release != nil && !released {
			released = true
			cred.Release()
		}
	}
	defer release()
	// One allocation at a time, spaced from the end of the previous one —
	// first starts and restarts alike. Credentials that finished together
	// still allocate 100 ms apart.
	startDone := w.c.gate.begin()
	if ctx.Err() != nil {
		startDone()
		return ctx.Err()
	}
	// A kick older than this allocation is answered by the session that
	// starts now: whatever asked (REPAIR, a panel restart, a path change
	// while the pool parked us in Creds) wanted a fresh GETCONF, and this is
	// one under the current identity. From here on a kick names THIS
	// allocation and is honoured — in the GETCONF wait and the serve loop.
	select {
	case <-w.kick:
	default:
	}
	t0 := time.Now()
	relay, err := dialRelay(cred.TURNCredentials, w.c.cfg.Server, w.c.cfg.TURNTransport, w.c.cfg.TURNLogLevel)
	startDone()
	if err != nil {
		// The relay refused or never answered: the lease hears it BEFORE
		// the deferred release, while the pool still counts this worker on
		// the slot — a 486 must not come back to this worker as the same
		// credential on the next attempt.
		if cred.Failed != nil {
			cred.Failed(err)
		}
		return err
	}
	w.c.allocRTT.Store(int64(time.Since(t0)))
	if cred.Allocated != nil {
		cred.Allocated()
	}
	creds := cred.TURNCredentials
	wrapper, err := NewWrapper(w.cipher, w.c.cfg.Mode)
	if err != nil {
		relay.Close()
		return err
	}
	w.blackhole.Store(false) // a fresh allocation is a fresh path; an injected fault does not follow it
	w.mu.Lock()
	w.relay, w.wrapper = relay, wrapper
	w.mu.Unlock()
	w.relayRef.Store(relay)
	rs := relay.Conn.LocalAddr().String()
	w.relayStr.Store(&rs)
	defer func() {
		w.ready.Store(false)
		w.readyAt.Store(0)
		w.clearProbe()
		// The relay FIRST: a writer blocked in WriteTo (a probe, the TUN
		// pump) holds w.mu, and the close is what frees it — a restart of a
		// worker whose relay stopped taking bytes must not wait behind the
		// write it is meant to end. Then the fields, under the lock.
		relay.Close()
		w.mu.Lock()
		w.relay, w.wrapper = nil, nil
		w.mu.Unlock()
		w.relayRef.Store(nil)
	}()
	w.c.cfg.Logf("csqtt: worker %d: relay %s via %s", w.id, rs, creds.Address)

	// The read loop feeds the control channel and delivers data; it ends
	// when the relay is closed.
	control := make(chan []byte, 64)
	readErr := make(chan error, 1)
	go w.readLoop(relay.Conn, control, readErr)

	// GETCONF with the reference schedule. The identity is read for EVERY
	// attempt and a kick ends the wait: the server keys the epoch on the
	// pair alone — a different pair replaces the device's sessions whatever
	// its generation — so a retry under a pair the client has already
	// replaced, landing after a neighbour announced the new one, would roll
	// every worker back to a dead epoch. iOS delivers a path change as a
	// cascade of 2–3 events ~500 ms apart; a worker still in this loop from
	// the first event is the norm. (A kick that lands between identity()
	// and the write can still put one stale GETCONF on the wire — the
	// select then restarts the worker; that window is microseconds where
	// the old one was the whole schedule.)
	var conf ConfigResponse
	got := false
attempts:
	for _, wait := range getconfSchedule {
		select {
		case reason := <-w.kick:
			return &restartRequest{reason: reason}
		default:
		}
		gen, salt := w.c.identity()
		req := []byte(ConfigRequest(w.c.cfg.LocalPort, w.c.cfg.DeviceID, w.c.cfg.Password,
			gen, salt, w.id, w.c.cfg.Workers, w.c.cfg.Revision))
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
			case reason := <-w.kick:
				return &restartRequest{reason: reason}
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
	w.readyAt.Store(time.Now().UnixNano())
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
			return &restartRequest{reason: reason}
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
		w.c.cfg.Logf("csqtt: worker %d: server is restarting — restarting every worker", w.id)
		w.c.restartAll("panel restart")
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
	w.txBytes.Add(int64(len(plain)))
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
		if w.blackhole.Load() {
			continue // the fault: the relay path is dead from our point of view
		}
		if !IsRTP(wire) {
			continue
		}
		plain, _, err := w.cipher.Unwrap(w.c.cfg.Mode, wire)
		if err != nil {
			continue
		}
		w.rx.Add(1)
		w.rxBytes.Add(int64(len(plain)))
		now := time.Now().UnixNano()
		w.lastRx.Store(now)
		w.heardAt.Store(now)
		if hook := readLoopStamped.Load(); hook != nil {
			(*hook)(w)
		}
		w.clearProbe() // any inbound answers the probe
		w.c.anyRx.Store(now)
		w.c.rxSeq.Add(1)
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
