package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	neturl "net/url"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Config holds proxy configuration.
type Config struct {
	PeerAddr      string        // vk-turn-proxy server address (host:port)
	TurnServer    string        // override TURN server host (optional)
	TurnPort      string        // override TURN port (optional)
	VKLink        string        // VK call invite link or link ID
	UseDTLS       bool          // true = DTLS obfuscation (default mode)
	UseUDP        bool          // true = UDP to TURN, false = TCP
	NumConns         int           // number of concurrent connections (default 1)
	CredPoolTTL      time.Duration // per-entry freshness in the cred pool; <=0 → default 10m
	CredPoolCooldown time.Duration // post-failure cooldown per slot in the cred pool; <=0 → default 2m
	CaptchaSolver    CaptchaSolver // called when VK requires captcha (may be nil)
	// SeededTURN, if non-nil, pre-populates credPool slot 0 with these
	// credentials so the first conn establishes immediately without
	// hitting VK's API. Used by the pre-bootstrap captcha flow.
	SeededTURN *TURNCreds
}

// Stats holds live tunnel statistics.
type Stats struct {
	TxBytes          int64   `json:"tx_bytes"`
	RxBytes          int64   `json:"rx_bytes"`
	ActiveConns      int32   `json:"active_conns"`
	TotalConns       int32   `json:"total_conns"`
	TurnRTTms        float64 `json:"turn_rtt_ms"`                 // last TURN Allocate RTT
	DTLSHandshakeMs  float64 `json:"dtls_handshake_ms"`           // last DTLS handshake time
	LastHandshakeSec int64   `json:"last_handshake_sec"`          // seconds since last WG handshake
	Reconnects       int64   `json:"reconnects"`                  // total TURN reconnects
	CaptchaImageURL  string  `json:"captcha_image_url,omitempty"` // non-empty when captcha is pending
	CaptchaSID       string  `json:"captcha_sid,omitempty"`       // captcha_sid for the pending captcha
}

// Proxy manages the DTLS+TURN tunnel to the peer server.
type Proxy struct {
	config Config
	ctx    context.Context // global lifetime (wgTurnOn → wgTurnOff)
	cancel context.CancelFunc

	peer   *net.UDPAddr
	linkID string

	// For packet I/O from the WireGuard side
	sendCh chan []byte
	recvCh chan []byte

	wg sync.WaitGroup

	started atomic.Bool

	// Active session context (cancelled on Pause, recreated on Resume)
	sessMu     sync.Mutex
	sessCtx    context.Context
	sessCancel context.CancelFunc

	// TURN server IP discovered after connecting to VK
	turnServerIP atomic.Value // stores string

	// Captcha handling: when VK requires captcha, the image URL is stored here
	// and the solver blocks until an answer is provided via SolveCaptcha().
	captchaImageURL    atomic.Value // stores string (empty = no captcha pending)
	captchaCh          chan string  // buffered channel for captcha answers
	lastCaptchaSID     atomic.Value // stores string: captcha_sid from last CaptchaRequiredError
	lastCaptchaKey     atomic.Value // stores string: success_token from captchaNotRobot.check
	lastCaptchaTs      atomic.Value // stores float64: captcha_ts from error response
	lastCaptchaAttempt atomic.Value // stores float64: captcha_attempt from error response
	lastCaptchaToken1  atomic.Value // stores string: step1 access_token to reuse on retry

	// Pool of independent TURN credentials, one per connection index.
	// Each slot has its own per-entry TTL (10 minutes). When a conn's own
	// cred is stale it refetches; when that refetch hits captcha or a 403
	// it falls back to round-robin over any other fresh slot, so a single
	// slot's trouble does not tear down the whole tunnel. See creds.go.
	credPool *credPool

	// Watchdog: last time a packet was received (unix seconds).
	// Used to detect dead tunnels after iOS freeze/thaw.
	lastRecvTime atomic.Int64

	// Pion silent-degradation detector. The pion TURN client logs Errorf when
	// CreatePermission refresh fails and Warnf when ChannelBind refresh fails.
	// Neither failure tears down the underlying allocation, so a partial loss
	// (e.g. 8 of 10 clients lose permissions on the server side) is invisible
	// at the application layer: stats keep showing conns 10/10, lastRecvTime
	// stays fresh thanks to the surviving connections, throughput drops by 80%.
	// We count these failures here and the watchdog forces a full reconnect
	// once they accumulate past a threshold while persisting for some time.
	pionTransientErrors atomic.Int64 // cumulative since last ForceReconnect
	firstPionErrorTime  atomic.Int64 // unix seconds, 0 = no errors yet

	// Guard against multiple concurrent waitCaptchaAndRestart goroutines.
	// Only one should be running at a time; extras just compete on captchaCh.
	captchaWaiterActive atomic.Bool

	// Last time RefreshCaptchaURL was called (= user is looking at captcha WebView).
	// Used to suppress periodic probes while user is actively trying to solve captcha.
	// Probes create new VK sessions that invalidate the current one, causing
	// "Attempt limit reached" errors in the WebView.
	lastRefreshCaptchaTime atomic.Int64 // unix seconds

	// Stats
	txBytes     atomic.Int64
	rxBytes     atomic.Int64
	activeConns atomic.Int32
	totalConns  atomic.Int32
	turnRTTns   atomic.Int64 // nanoseconds
	dtlsHSns    atomic.Int64 // nanoseconds
	reconnects  atomic.Int64

	// Per-conn liveness probe. Detects "zombie" conns where the TURN
	// allocation appears alive (NAT keepalive Binding to VK succeeds,
	// pion's Refresh succeeds) but actual data path is broken — typically
	// after iOS network handover where VK's relay is still pointing at
	// the old NAT mapping.
	//
	// Mechanism: each conn periodically writes a sentinel packet through
	// its DTLS pipe. The patched server (vk-turn-proxy-server with
	// matching support) recognizes the magic bytes and echoes the
	// packet back. An unpatched server forwards the bytes to WireGuard
	// which drops them (first byte 0xff doesn't match WG message types
	// 1..4) — no echo, no harm.
	//
	// On the client side, ANY received pong sets serverProbeable to
	// true. From that point on, every conn's lastPongTime is checked
	// for staleness; stale conns are killed via connCancel and the
	// reconnect loop rebuilds them with fresh TURN allocations.
	//
	// Backward compat: with an old server, no pongs ever arrive,
	// serverProbeable stays false, no kills happen — behaviour is
	// identical to pre-probe code modulo a steady ~1-3 kbps of probe
	// traffic that the server silently drops.
	serverProbeable atomic.Bool
	lastPongTimes   []atomic.Int64 // per conn, indexed by connIdx; Unix seconds

	// Bootstrap-ready signaling. Fires exactly once per proxy lifetime, when
	// either (a) the first conn establishes a live DTLS+TURN session (signaled
	// with nil from runConnection), or (b) Start() hits a fatal non-captcha
	// error before any conn comes up. Captcha-pending does NOT signal — the
	// caller waits up to timeout for the user to solve and the first conn to
	// come up after Resume(). Used by bridge's wgWaitBootstrapReady so Swift
	// can defer setTunnelNetworkSettings until VK bootstrap is actually done.
	bootstrapDoneCh   chan error
	bootstrapDoneOnce sync.Once
}

// NewProxy creates a new proxy instance.
func NewProxy(cfg Config) *Proxy {
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	// Fresh global session — clear any leftover pion-degradation counters.
	// (atomic.Int64 zero values are fine for a brand-new struct, but explicit
	//  for clarity in case Proxy is ever pooled in the future.)
	ctx, cancel := context.WithCancel(context.Background())
	sessCtx, sessCancel := context.WithCancel(ctx)
	p := &Proxy{
		config:          cfg,
		ctx:             ctx,
		cancel:          cancel,
		sendCh:          make(chan []byte, 256),
		recvCh:          make(chan []byte, 256),
		sessCtx:         sessCtx,
		sessCancel:      sessCancel,
		captchaCh:       make(chan string, 1),
		bootstrapDoneCh: make(chan error, 1),
		lastPongTimes:   make([]atomic.Int64, cfg.NumConns),
	}
	// If no external solver provided, use the built-in channel-based solver
	// that waits for SolveCaptcha() to be called (e.g. from iOS UI).
	if p.config.CaptchaSolver == nil {
		p.config.CaptchaSolver = p.waitForCaptchaAnswer
	}
	// Build the cred pool with a closure that does the VK API work and
	// parses the TURN host:port. Pool size = max(2, ceil(NumConns/3)) —
	// enough insurance slots to keep the tunnel alive through mid-session
	// captcha without the full per-conn PoW cost of a size=NumConns pool.
	// TTL/cooldown come from Config; newCredPool falls back to defaults
	// (10m TTL, 2m cooldown) if <= 0.
	p.credPool = newCredPool(poolSizeForNumConns(cfg.NumConns), cfg.CredPoolTTL, cfg.CredPoolCooldown, p.fetchFreshCreds)

	// Seed slot 0 with pre-fetched TURN creds (from main app's pre-bootstrap
	// captcha flow). The first conn's get() returns these without an API
	// call, dodging the .connecting-window captcha deadlock.
	if cfg.SeededTURN != nil {
		// Build TURN host:port the same way fetchFreshCreds would,
		// honoring TurnServer/TurnPort overrides if set.
		turnHost, turnPort, err := net.SplitHostPort(cfg.SeededTURN.Address)
		if err == nil {
			if cfg.TurnServer != "" {
				turnHost = cfg.TurnServer
			}
			if cfg.TurnPort != "" {
				turnPort = cfg.TurnPort
			}
			addr := net.JoinHostPort(turnHost, turnPort)
			p.credPool.seedSlot(0, addr, cfg.SeededTURN)
			p.turnServerIP.Store(turnHost)
		} else {
			log.Printf("NewProxy: SeededTURN address %q is not host:port (%v) — ignoring", cfg.SeededTURN.Address, err)
		}
	}

	return p
}

// signalBootstrapDone fires the bootstrap-ready channel exactly once per
// proxy lifetime. Safe to call from any goroutine, any number of times —
// only the first call is observable. err=nil means "first conn has a live
// DTLS+TURN session and is ready to carry traffic". Non-nil err is a fatal
// failure before any conn came up. Captcha-pending should NOT signal (the
// user may still solve it and a conn will come up via Resume()).
func (p *Proxy) signalBootstrapDone(err error) {
	p.bootstrapDoneOnce.Do(func() {
		p.bootstrapDoneCh <- err
	})
}

// WaitBootstrap blocks until bootstrap is ready, a fatal error occurred,
// the proxy was stopped, or the timeout expired. Multiple callers share the
// same signal — the channel value is replayed back so later waiters get it
// too. Returns nil on ready, an error otherwise.
func (p *Proxy) WaitBootstrap(timeout time.Duration) error {
	select {
	case err := <-p.bootstrapDoneCh:
		// Replay the signal so any future waiter also observes it.
		select {
		case p.bootstrapDoneCh <- err:
		default:
		}
		return err
	case <-time.After(timeout):
		return fmt.Errorf("bootstrap timeout after %s", timeout)
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// Start establishes the DTLS+TURN connection chain.
// It blocks until the first connection is established or an error occurs.
// Idempotent: subsequent calls after a successful start return nil without
// re-initializing. This lets turnbind.Open() safely call Start() even when
// the caller has already started the proxy via wgStartVKBootstrap.
func (p *Proxy) Start() error {
	if p.started.Swap(true) {
		return nil
	}

	// Limit Go scheduler threads to reduce CPU wakeups on iOS.
	// iOS Network Extensions are killed if they exceed 45000 wakeups/300s.
	// With 10 connections and ~50 goroutines, unrestricted GOMAXPROCS
	// causes ~1500 wakes/sec. Limiting to 2 threads keeps us well under.
	runtime.GOMAXPROCS(2)

	// Parse VK link ID
	linkID := p.config.VKLink
	if strings.Contains(linkID, "join/") {
		parts := strings.Split(linkID, "join/")
		linkID = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(linkID, "/?#"); idx != -1 {
		linkID = linkID[:idx]
	}
	p.linkID = linkID

	// Resolve peer address
	peer, err := net.ResolveUDPAddr("udp", p.config.PeerAddr)
	if err != nil {
		wrapped := fmt.Errorf("resolve peer: %w", err)
		p.signalBootstrapDone(wrapped)
		return wrapped
	}
	p.peer = peer

	// Start watchdog goroutine to detect dead tunnels after iOS freeze/thaw.
	// This is the primary self-healing mechanism — it doesn't rely on iOS
	// calling sleep()/wake() which is unreliable.
	go p.runWatchdog()

	// Background cred-pool grower: fills empty slots over time without
	// blocking conn startup. Conn 0 still does an inline fetch (needs at
	// least one cred to bootstrap). Conns 1-N use fallback to whichever
	// slots are fresh; the grower backfills pool[1..N-1] slowly so the
	// pool eventually reaches full insurance coverage.
	go p.growCredPool(p.ctx)

	err = p.startConnections()
	if err != nil {
		// Fatal failure before any conn came up — wake any bootstrap waiters
		// so they don't sit on the channel until timeout.
		p.signalBootstrapDone(err)
	}
	// Success (first conn ready) is signaled from runConnection itself, so
	// WaitBootstrap reflects reality even in the captcha-retry path where
	// startConnections returns nil while the first conn is still coming up.
	return err
}

// growCredPool runs a background loop that opportunistically fills
// empty/stale slots in the cred pool. Behaviour:
//   - Waits for bootstrap to be ready before starting (no point fetching
//     more creds while conn 0 is still trying to establish the first).
//   - Pauses while captcha is pending — adding another fetch would
//     pressure VK and potentially invalidate the current captcha session.
//   - Uses allowCaptchaBlock=false so a background fetch hitting captcha
//     records a cooldown instead of blocking on user input.
//   - Fast poll (2s) while there is work to do, slow poll (30s) when all
//     slots are full or on cooldown.
// Lifetime = p.ctx (stops on Proxy.Stop).
func (p *Proxy) growCredPool(ctx context.Context) {
	// Wait until the first conn has a live DTLS+TURN session. There's no
	// value in populating more slots before the tunnel actually works.
	if err := p.WaitBootstrap(2 * time.Minute); err != nil {
		log.Printf("credpool-grow: bootstrap did not succeed within 2m (%v), grower exiting", err)
		return
	}

	const (
		fastInterval = 2 * time.Second
		slowInterval = 30 * time.Second
	)
	interval := fastInterval

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		// Don't add VK pressure while captcha is pending.
		if v := p.captchaImageURL.Load(); v != nil {
			if s, _ := v.(string); s != "" {
				interval = slowInterval
				continue
			}
		}

		slot := p.credPool.pickSlotToFill()
		if slot < 0 {
			// Everything filled or on cooldown — idle poll.
			interval = slowInterval
			continue
		}

		// tryFill returns fast whether success or failure; it handles
		// cooldown bookkeeping internally.
		p.credPool.tryFill(slot, false)
		interval = fastInterval
	}
}

// startConnections launches all connection goroutines using the current session context.
func (p *Proxy) startConnections() error {
	p.sessMu.Lock()
	sessCtx := p.sessCtx
	p.sessMu.Unlock()

	// Spawns conn 0; returns nil on success (readyCh fired), the error
	// otherwise. Pulled out so the iOS-network-race retry below can re-
	// run it without code duplication.
	spawnConn0 := func() error {
		readyCh := make(chan struct{}, 1)
		errCh := make(chan error, 1)

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			err := p.runConnection(sessCtx, p.linkID, readyCh, 0)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}()

		select {
		case <-readyCh:
			return nil
		case err := <-errCh:
			return err
		case <-p.ctx.Done():
			return p.ctx.Err()
		}
	}

	// Bootstrap retry loop — conn 0's first DTLS+TURN handshake can fail
	// transiently for several network reasons:
	//   - iOS VPN policy applied mid-handshake (kernel closes the UDP
	//     socket under us; surfaces as "broken pipe" / "use of closed
	//     network connection"). The 1.5s settle delay in
	//     wgStartVKBootstrap isn't always enough.
	//   - WiFi handover / DHCP setup not finished when bootstrap begins.
	//   - Carrier-grade NAT mapping warmup on cellular reconnect.
	//   - Slow DNS or routing convergence on a fresh network.
	//
	// Up to 4 attempts × 15s DTLS handshake timeout + 3 backoffs × 10s
	// = ~90s total. Linear backoff (not exponential): each attempt has
	// the same cost, so spreading evenly is fine.
	//
	// Retry triggers on ANY error EXCEPT captcha — captcha needs a user
	// answer, retrying immediately just burns budget. Captcha-required
	// drops out of this loop and surfaces via the captcha-pending path
	// below.
	const maxBootstrapAttempts = 4
	const bootstrapBackoff = 10 * time.Second
	err := spawnConn0()
	for attempt := 1; err != nil && attempt < maxBootstrapAttempts; attempt++ {
		var captchaErr *CaptchaRequiredError
		if errors.As(err, &captchaErr) {
			break
		}
		log.Printf("proxy: bootstrap attempt %d/%d failed (%v), retrying conn 0 after %s",
			attempt, maxBootstrapAttempts, err, bootstrapBackoff)
		select {
		case <-time.After(bootstrapBackoff):
		case <-p.ctx.Done():
			return p.ctx.Err()
		}
		err = spawnConn0()
		if err == nil {
			log.Printf("proxy: bootstrap attempt %d/%d succeeded", attempt+1, maxBootstrapAttempts)
		}
	}

	if err != nil {
		// If captcha is required during initial connection, don't fail —
		// publish the captcha and wait for the user to solve it.
		var captchaErr *CaptchaRequiredError
		if errors.As(err, &captchaErr) {
			log.Printf("proxy: captcha required during startup, waiting for solution")
			p.captchaImageURL.Store(captchaErr.ImageURL)
			p.lastCaptchaSID.Store(captchaErr.SID)
			p.lastCaptchaTs.Store(captchaErr.CaptchaTs)
			p.lastCaptchaAttempt.Store(captchaErr.CaptchaAttempt)
			p.lastCaptchaToken1.Store(captchaErr.Token1)
			// Only spawn one waiter at a time — multiple goroutines
			// competing on captchaCh cause missed answers and orphaned waiters.
			if p.captchaWaiterActive.CompareAndSwap(false, true) {
				go p.waitCaptchaAndRestart()
			} else {
				log.Printf("proxy: waitCaptchaAndRestart already running, not spawning another")
			}
			return nil // tunnel "starts" in captcha-pending mode
		}
		return fmt.Errorf("first connection failed: %w", err)
	}

	// Bi-modal stagger: first burstSize conns launch 200ms apart to use
	// VK's initial allocation token bucket (~10 tokens immediately
	// available); the rest wait slowStagger between each to fit the
	// observed refill rate (~1 token / 20-30s).
	//
	// Empirically (vpn.wifi.18.log starting 20:16:55, NumConns=16): the
	// first 10 allocations succeeded in 2 seconds (200ms*9 stagger);
	// then conns 10-15 spent ~38s burning 15s DTLS handshake timeouts
	// against an empty bucket before any of them succeeded — pure waste
	// because they were retrying immediately on 486 instead of waiting
	// for a refill. With slowStagger=5s, conn 10 starts at ~7s (after
	// the burst window), which is close to when the next bucket token
	// becomes available; subsequent conns continue at 5s intervals.
	//
	// For NumConns ≤ burstSize, the slow branch is never taken and
	// behaviour matches the previous linear stagger (200ms × i).
	const burstSize = 10
	const burstStagger = 200 * time.Millisecond
	const slowStagger = 5 * time.Second
	for i := 1; i < p.config.NumConns; i++ {
		p.wg.Add(1)
		connIdx := i
		go func() {
			defer p.wg.Done()
			var delay time.Duration
			if connIdx < burstSize {
				delay = time.Duration(connIdx) * burstStagger
			} else {
				// Burst phase ends at (burstSize-1)*burstStagger after t=0.
				// Then each subsequent conn launches slowStagger after
				// the previous one.
				delay = time.Duration(burstSize-1)*burstStagger +
					time.Duration(connIdx-burstSize+1)*slowStagger
			}
			select {
			case <-time.After(delay):
			case <-sessCtx.Done():
				return
			}
			p.runConnection(sessCtx, p.linkID, nil, connIdx)
		}()
	}

	return nil
}

// waitCaptchaAndRestart waits for captcha answer, then restarts connections.
// After the user solves the captcha in the WebView, VK validates it server-side
// (tied to the captcha_sid). We simply restart connections — VK should
// accept the next request from this IP without another captcha.
func (p *Proxy) waitCaptchaAndRestart() {
	defer p.captchaWaiterActive.Store(false)

	// Drain any stale answer
	select {
	case <-p.captchaCh:
	default:
	}

	probeInterval := 2 * time.Minute

	for {
		select {
		case answer := <-p.captchaCh:
			p.captchaImageURL.Store("")
			if answer != "" {
				p.lastCaptchaKey.Store(answer)
				log.Printf("proxy: captcha answered (%d chars), restarting connections (will use stored captcha_sid + key)", len(answer))
			} else {
				log.Printf("proxy: VK no longer requires captcha, restarting connections normally")
			}
			p.Resume()
			return
		case <-time.After(probeInterval):
			// Periodic self-retry: check if VK cooled down while user was away.
			// Suppress if user is actively viewing captcha WebView.
			if lastRefresh := p.lastRefreshCaptchaTime.Load(); lastRefresh > 0 {
				if time.Since(time.Unix(lastRefresh, 0)) < 10*time.Minute {
					log.Printf("proxy: probe skipped — user is viewing WebView (last refresh %s ago)",
						time.Since(time.Unix(lastRefresh, 0)).Round(time.Second))
					continue
				}
			}
			log.Printf("proxy: probing if VK still requires captcha (interval was %s)...", probeInterval)
			// DON'T wholesale-invalidate the pool here. If a background fetcher
			// (or another path) has filled any slot, that's the strongest
			// signal VK has cooled down — preserve it for use, not discard it.
			// Invalidate would destroy creds other conns may be running on,
			// creating a self-amplifying decay loop. credPool.get below
			// returns cached cred if available, otherwise fetches with
			// allowCaptchaBlock=false (surfaces captcha as error w/o blocking).
			_, _, probeSlot, probeErr := p.resolveTURNAddr(-1, false)
			// Probe is non-consuming; release whatever slot got acquired so
			// it doesn't leak quota count for a cred we never used.
			if probeErr == nil {
				p.credPool.release(probeSlot)
				log.Printf("proxy: VK no longer requires captcha (probe succeeded), resuming")
				p.captchaImageURL.Store("")
				p.Resume()
				return
			}
			var probeCapErr *CaptchaRequiredError
			if errors.As(probeErr, &probeCapErr) {
				if probeCapErr.IsRateLimit {
					// VK returned ERROR_LIMIT — back off significantly.
					// Frequent probes only prolong the rate limit.
					probeInterval = 10 * time.Minute
					log.Printf("proxy: VK rate-limited (ERROR_LIMIT), backing off to %s", probeInterval)
				} else {
					// Regular captcha (not rate-limited) — keep shorter interval
					probeInterval = 2 * time.Minute
					log.Printf("proxy: VK still requires captcha, waiting %s", probeInterval)
				}
				p.captchaImageURL.Store(probeCapErr.ImageURL)
				p.lastCaptchaSID.Store(probeCapErr.SID)
				p.lastCaptchaTs.Store(probeCapErr.CaptchaTs)
				p.lastCaptchaAttempt.Store(probeCapErr.CaptchaAttempt)
				p.lastCaptchaToken1.Store(probeCapErr.Token1)
			} else {
				log.Printf("proxy: probe failed (non-captcha): %v, waiting %s", probeErr, probeInterval)
			}
		case <-p.ctx.Done():
			p.captchaImageURL.Store("")
			p.lastCaptchaSID.Store("")
			return
		}
	}
}

// Pause gracefully stops all connections (for sleep).
func (p *Proxy) Pause() {
	p.sessMu.Lock()
	if p.sessCancel != nil {
		p.sessCancel()
	}
	p.sessMu.Unlock()
	// Invalidate creds so Resume fetches fresh ones
	p.credPool.invalidate()
	log.Printf("proxy: Pause — all connections cancelled")
}

// Resume restarts all connections (for wake).
// Always cancels the old session first — iOS may call wake() without sleep(),
// or the process may have been frozen without any lifecycle callback.
func (p *Proxy) Resume() {
	// If captcha is pending, don't start new connections — there's already a
	// waitCaptchaAndRestart goroutine that will handle it when the user solves
	// the captcha. Starting new connections would just pile up goroutines that
	// all block on the same captcha, leading to 100s of accumulated goroutines
	// when iOS repeatedly wakes the extension during the night.
	if v := p.captchaImageURL.Load(); v != nil {
		if url, _ := v.(string); url != "" {
			log.Printf("proxy: Resume — captcha pending, skipping (will resume after captcha solved)")
			return
		}
	}

	p.sessMu.Lock()
	// Cancel any existing session to kill orphaned goroutines.
	// This is critical: iOS can freeze the process and unfreeze it
	// without calling sleep(). Old goroutines sit on dead sockets
	// with stale TURN allocations. We must kill them first.
	if p.sessCancel != nil {
		p.sessCancel()
	}
	p.sessCtx, p.sessCancel = context.WithCancel(p.ctx)
	p.sessMu.Unlock()
	// Invalidate creds — after sleep, TURN allocations expired
	p.credPool.invalidate()
	log.Printf("proxy: Resume — cancelled old session, starting fresh connections")
	go p.startConnections()
}

// ForceReconnect tears down all connections and starts fresh.
// Used by the watchdog when it detects a dead tunnel.
func (p *Proxy) ForceReconnect() {
	// Don't force reconnect while captcha is pending (same reason as Resume)
	if v := p.captchaImageURL.Load(); v != nil {
		if url, _ := v.(string); url != "" {
			log.Printf("proxy: ForceReconnect — captcha pending, skipping")
			return
		}
	}

	p.sessMu.Lock()
	if p.sessCancel != nil {
		p.sessCancel()
	}
	p.sessCtx, p.sessCancel = context.WithCancel(p.ctx)
	p.sessMu.Unlock()
	// DON'T wholesale-invalidate the pool here. The watchdog only knows
	// the tunnel is silent — it doesn't know whether the underlying TURN
	// creds are server-side stale. Most often the silence is from a
	// kernel-side socket kill (DHCP renewal, network handover) while
	// allocations remain valid on the TURN server. Keeping cached creds
	// lets the new bootstrap try a DTLS handshake with the existing slot 0
	// cred immediately, succeeding within ~100ms in the common case.
	//
	// If the cred IS actually stale, the new conn 0's TURN session goes
	// short-lived (<30s), the existing per-slot invalidateEntry path
	// drops just that slot, and bootstrap retry (4 × 15s + 10s backoffs,
	// see startConnections) gets a fresh fetch on the next attempt.
	// Either way we don't pay the cost of a fresh VK API call before
	// even trying to reconnect.
	// Clear the silent-degradation counters so the new session starts fresh.
	p.pionTransientErrors.Store(0)
	p.firstPionErrorTime.Store(0)
	// Reset the lastRecvTime clock so the new session gets a fair 2-minute
	// window before watchdog condition 1 can fire again. Otherwise, if the
	// old lastRecvTime is stale (which is exactly why condition 1 triggered
	// in the first place), the very next watchdog tick would see elapsed
	// still > 2 minutes and ForceReconnect the not-yet-built new session.
	p.lastRecvTime.Store(time.Now().Unix())
	p.reconnects.Add(1)
	log.Printf("proxy: ForceReconnect — watchdog triggered, starting fresh connections")
	go p.startConnections()
}

// WakeHealthCheck is called from Swift wake() whenever iOS resumes the
// Network Extension. It runs a fast-path variant of the watchdog's
// condition 3 with a lower threshold: if even 2 pion permission/binding
// errors have accumulated since the last ForceReconnect, we immediately
// tear down and rebuild everything, on the assumption that the user is
// about to use the network and we'd rather spend ~5 seconds reconnecting
// now than let them hit a broken tunnel.
//
// This complements the normal 30-second watchdog tick: the watchdog is
// tuned for slow-moving degradation over minutes, while wake() fires
// precisely when fast detection matters most. Without this hook, a
// degradation that started during sleep could take several more minutes
// of accumulated errors after wake before the normal watchdog triggers.
func (p *Proxy) WakeHealthCheck() {
	// Don't interfere with an in-progress captcha flow.
	if v := p.captchaImageURL.Load(); v != nil {
		if url, _ := v.(string); url != "" {
			return
		}
	}
	pionErrs := p.pionTransientErrors.Load()
	if pionErrs >= 5 {
		log.Printf("proxy: wake check — %d pion permission/binding errors accumulated, forcing urgent reconnect", pionErrs)
		p.ForceReconnect()
	}
}

// runWatchdog monitors tunnel health and forces reconnection when dead.
// iOS freezes Network Extension processes without calling sleep()/wake().
// After unfreeze, all TURN allocations are expired but goroutines sit on
// dead sockets. The watchdog detects this by tracking the last received packet.
//
// Three conditions trigger a full reconnect:
//  1. No packets for 2 min with active connections → dead tunnel
//  2. Active connections < half of expected for 5+ min → partial recovery stuck
//     (e.g., after Allocation Quota Reached, only 1-2 of 10 connections survive)
//  3. Pion permission/binding refresh failures persist past a threshold →
//     silent partial degradation (some clients still alive, but server-side
//     permissions are gone for the others; UI shows 10/10 with 0 reconnects
//     while throughput collapses to 1/N)
func (p *Proxy) runWatchdog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lowConnSince time.Time  // when we first noticed too few connections
	var zeroConnSince time.Time // when we first noticed zero connections

	for {
		select {
		case <-ticker.C:
			// Don't force reconnect while captcha is pending — a goroutine is
			// already waiting for the user to solve it. ForceReconnect would
			// cancel that wait and start a new cycle that hits the same captcha.
			if v := p.captchaImageURL.Load(); v != nil {
				if url, _ := v.(string); url != "" {
					continue // captcha pending, skip watchdog cycle
				}
			}

			lastRecv := p.lastRecvTime.Load()
			active := p.activeConns.Load()
			expected := int32(p.config.NumConns)

			// Condition 1: No packets despite active connections → dead tunnel
			if lastRecv > 0 && active > 0 {
				elapsed := time.Since(time.Unix(lastRecv, 0))
				if elapsed > 2*time.Minute {
					log.Printf("proxy: watchdog — no packets for %s with %d active conns, forcing reconnect",
						elapsed.Round(time.Second), active)
					lowConnSince = time.Time{} // reset
					p.ForceReconnect()
					continue
				}
			}

			// Condition 3: Silent partial degradation — pion is logging
			// permission or channel-binding refresh failures but the surviving
			// clients keep lastRecvTime fresh, so condition 1 never trips.
			// Trigger if we've accumulated enough errors AND they have been
			// persisting for at least 90 seconds (avoids reacting to a single
			// flaky cycle).
			//
			// Threshold 5 is tuned from observed vpn11.log: at 1 real VK
			// rejection per 2-min permission refresh cycle, threshold 10
			// took 16+ minutes to trigger (8 cycles to accumulate), leaving
			// the tunnel broken too long before recovery. Threshold 5 cuts
			// that to ~8 minutes, which is still slow enough to ignore a
			// single transient cycle but fast enough to actually matter.
			pionErrs := p.pionTransientErrors.Load()
			firstErr := p.firstPionErrorTime.Load()
			if pionErrs >= 5 && firstErr > 0 && time.Since(time.Unix(firstErr, 0)) > 90*time.Second {
				log.Printf("proxy: watchdog — %d pion permission/binding errors over %s, tunnel silently degraded, forcing reconnect",
					pionErrs, time.Since(time.Unix(firstErr, 0)).Round(time.Second))
				lowConnSince = time.Time{} // reset
				p.ForceReconnect()
				continue
			}

			// Condition 2: Too few active connections for too long.
			// After sleep/wake, Allocation Quota Reached kills most connections.
			// Dormant goroutines will eventually retry (30s-3min), but if the
			// situation persists, force a clean restart.
			if lastRecv > 0 && active > 0 && active < expected/2 {
				if lowConnSince.IsZero() {
					lowConnSince = time.Now()
				} else if time.Since(lowConnSince) > 5*time.Minute {
					log.Printf("proxy: watchdog — only %d/%d conns active for 5+ min, forcing reconnect",
						active, expected)
					lowConnSince = time.Time{}
					p.ForceReconnect()
					continue
				}
			} else {
				lowConnSince = time.Time{} // reset if healthy
			}

			// Condition 4: Zero active connections for too long.
			// Conditions 1 and 2 both require active>0, so a hard
			// bootstrap dead-end (e.g. ForceReconnect → all 4 retry
			// attempts hit cred-486 → "first connection failed" → no
			// more retries) leaves the watchdog mute and the tunnel
			// stays down indefinitely. Observed in vpn.lte.0.log on
			// 2026-04-29 at 09:05:52 — log just trails into background
			// captcha activity with 0 active conns and no recovery.
			//
			// 5-minute threshold is long enough that the initial
			// startup phase (typically 5-30s but can stretch to several
			// minutes if the cred pool needs to fetch through captcha)
			// finishes without us spuriously retrying it. After that,
			// firing every 5 minutes gives saturated slots time to
			// recover (10-minute markSaturated cooldown) between
			// attempts and gives the cred-pool grower a window to fill
			// new slots.
			if active == 0 {
				if zeroConnSince.IsZero() {
					zeroConnSince = time.Now()
				} else if time.Since(zeroConnSince) > 5*time.Minute {
					log.Printf("proxy: watchdog — 0 active conns for 5+ min, forcing reconnect")
					zeroConnSince = time.Time{}
					p.ForceReconnect()
					continue
				}
			} else {
				zeroConnSince = time.Time{}
			}
		case <-p.ctx.Done():
			return
		}
	}
}

// SendPacket sends a WireGuard packet through the tunnel.
func (p *Proxy) SendPacket(data []byte) error {
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case p.sendCh <- buf:
		p.txBytes.Add(int64(len(data)))
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// ReceivePacket receives a packet from the tunnel.
// Blocks until a packet arrives or context is cancelled.
func (p *Proxy) ReceivePacket(buf []byte) (int, error) {
	select {
	case pkt := <-p.recvCh:
		n := copy(buf, pkt)
		p.rxBytes.Add(int64(n))
		return n, nil
	case <-p.ctx.Done():
		return 0, p.ctx.Err()
	}
}

// GetStats returns current tunnel statistics.
func (p *Proxy) GetStats() Stats {
	var captchaURL string
	if v := p.captchaImageURL.Load(); v != nil {
		captchaURL = v.(string)
	}
	var captchaSID string
	if v := p.lastCaptchaSID.Load(); v != nil {
		captchaSID = v.(string)
	}
	return Stats{
		TxBytes:         p.txBytes.Load(),
		RxBytes:         p.rxBytes.Load(),
		ActiveConns:     p.activeConns.Load(),
		TotalConns:      p.totalConns.Load(),
		TurnRTTms:       float64(p.turnRTTns.Load()) / 1e6,
		DTLSHandshakeMs: float64(p.dtlsHSns.Load()) / 1e6,
		Reconnects:      p.reconnects.Load(),
		CaptchaImageURL: captchaURL,
		CaptchaSID:      captchaSID,
	}
}

// waitForCaptchaAnswer is the built-in CaptchaSolver that publishes the captcha
// image URL via stats and blocks until SolveCaptcha() is called.
func (p *Proxy) waitForCaptchaAnswer(imageURL string) (string, error) {
	log.Printf("proxy: captcha required, waiting for answer (image: %s)", imageURL)
	p.captchaImageURL.Store(imageURL)

	// Drain any stale answer
	select {
	case <-p.captchaCh:
	default:
	}

	select {
	case answer := <-p.captchaCh:
		p.captchaImageURL.Store("") // clear pending state
		log.Printf("proxy: captcha answer received")
		return answer, nil
	case <-p.ctx.Done():
		p.captchaImageURL.Store("")
		return "", p.ctx.Err()
	}
}

// SolveCaptcha provides the answer to a pending captcha challenge.
// Called from the iOS UI via the bridge.
func (p *Proxy) SolveCaptcha(answer string) {
	if answer != "" {
		p.lastCaptchaKey.Store(answer)
	}
	p.captchaImageURL.Store("")

	select {
	case p.captchaCh <- answer:
	default:
		log.Printf("proxy: SolveCaptcha called but no captcha pending")
	}

	// Schedule a forced Resume after a delay. This guarantees fresh connections
	// are started regardless of which goroutine consumed the captchaCh answer.
	// Without this, if the inline solver in getVKCreds wins the race (instead of
	// waitCaptchaAndRestart), Resume() is never called and connections stay dead.
	go func() {
		time.Sleep(15 * time.Second)
		// If no active connections after 15s, force reconnect
		if p.activeConns.Load() == 0 {
			log.Printf("proxy: SolveCaptcha — no active conns after 15s, forcing Resume()")
			p.Resume()
		}
	}()
}

// RefreshCaptchaURL makes a fresh step2 VK API call to get a new captcha URL.
// Called from Swift right before showing WebView, so the URL is guaranteed fresh.
// Returns the new redirect_uri or empty string on failure.
func (p *Proxy) RefreshCaptchaURL() string {
	log.Printf("proxy: refreshing captcha URL for WebView")
	// Mark that user is actively viewing the captcha WebView.
	// Periodic probes will be suppressed for 10 minutes to avoid
	// creating new VK sessions that invalidate the current one.
	p.lastRefreshCaptchaTime.Store(time.Now().Unix())

	linkID := p.linkID
	if linkID == "" {
		log.Printf("proxy: RefreshCaptchaURL: no linkID")
		return ""
	}

	// Pick a random client_id for the fresh request
	vc := vkCredentialsList[mathrand.Intn(len(vkCredentialsList))]
	ua := randomUserAgent()
	name := generateName()

	client := newHTTPClient()
	defer client.CloseIdleConnections()

	// Step 1: get anon token
	step1Data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", vc.ClientID, vc.ClientSecret, vc.ClientID)
	step1Resp, err := doSimplePost(client, step1Data, "https://login.vk.ru/?act=get_anonym_token", ua)
	if err != nil {
		log.Printf("proxy: RefreshCaptchaURL step1 failed: %v", err)
		return ""
	}
	token1, ok := extractNestedString(step1Resp, "data", "access_token")
	if !ok {
		log.Printf("proxy: RefreshCaptchaURL step1 parse failed")
		return ""
	}

	// Step 2: trigger captcha
	step2URL := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", vc.ClientID)
	step2Data := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s",
		linkID, neturl.QueryEscape(name), token1)
	step2Resp, err := doSimplePost(client, step2Data, step2URL, ua)
	if err != nil {
		log.Printf("proxy: RefreshCaptchaURL step2 failed: %v", err)
		return ""
	}

	sid, captchaURL, ts, attempt := extractCaptcha(step2Resp)
	if sid == "" {
		// Step2 returned no captcha, but this is NOT reliable — step2 is a simple
		// anonymous API call, while the actual GetVKCreds flow includes PoW check
		// which often triggers BOT+slider even when step2 didn't.
		// Do NOT unblock the captchaCh goroutine here — that causes a rapid
		// "cooled → retry → slider → freeze → cooled" ping-pong cycle with
		// multiple broken WebViews flashing on screen.
		// The goroutine has its own periodic retry (every 2 min) that will
		// detect when VK truly cools down by attempting the full credential flow.
		log.Printf("proxy: RefreshCaptchaURL: no captcha in step2 response (not reliable — goroutine will self-retry)")
		return ""
	}

	log.Printf("proxy: RefreshCaptchaURL: got fresh captcha sid=%s", sid)
	// Update stored captcha info
	p.captchaImageURL.Store(captchaURL)
	p.lastCaptchaSID.Store(sid)
	p.lastCaptchaTs.Store(ts)
	p.lastCaptchaAttempt.Store(attempt)
	p.lastCaptchaToken1.Store(token1)

	return captchaURL
}

// doSimplePost is a helper for RefreshCaptchaURL.
func doSimplePost(client *http.Client, data, url, ua string) (map[string]interface{}, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// extractNestedString extracts a string from nested maps.
func extractNestedString(m map[string]interface{}, keys ...string) (string, bool) {
	var cur interface{} = m
	for _, k := range keys {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur = mm[k]
	}
	s, ok := cur.(string)
	return s, ok
}

// TURNServerIP returns the TURN server IP discovered after connecting.
// Returns empty string if not yet connected.
func (p *Proxy) TURNServerIP() string {
	if v := p.turnServerIP.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Stop tears down all connections.
func (p *Proxy) Stop() {
	p.cancel()
	p.wg.Wait()
}

// runConnection runs a single connection slot with reconnection.
// Reconnects on failure until sessCtx is cancelled (Pause/Resume) or global ctx is done (Stop).
// After 3 consecutive short-lived failures, goes dormant for up to 3 minutes.
// This avoids hammering the TURN server (Allocation Quota Reached) while still
// recovering without relying on iOS sleep()/wake() which are unreliable.
func (p *Proxy) runConnection(sessCtx context.Context, linkID string, readyCh chan<- struct{}, connIdx int) error {
	signaled := false
	shortFailures := 0

	for {
		select {
		case <-sessCtx.Done():
			return sessCtx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		start := time.Now()
		var err error
		if p.config.UseDTLS {
			err = p.runDTLSSession(sessCtx, linkID, readyCh, &signaled, connIdx)
		} else {
			err = p.runDirectSession(sessCtx, linkID, readyCh, &signaled, connIdx)
		}
		if err != nil {
			duration := time.Since(start)
			log.Printf("proxy: [conn %d] session ended after %s: %s", connIdx, duration.Round(time.Second), err)
			if !signaled && readyCh != nil {
				return err
			}

			// If the session ended because of a captcha requirement and
			// it was already handled (solved or pending), don't count as failure.
			var captchaErr *CaptchaRequiredError
			if errors.As(err, &captchaErr) {
				log.Printf("proxy: session ended with captcha requirement, not counting as failure")
				shortFailures = 0
			} else if duration > 5*time.Minute {
				shortFailures = 0 // session was healthy
			} else {
				shortFailures++
			}

			// After 3 consecutive short-lived failures, go dormant for up to 3 minutes.
			// This prevents hammering the TURN server when Allocation Quota is reached.
			// Previously this waited forever for Resume(), but iOS doesn't reliably
			// call wake() — so we use a timeout and retry with staggered delay.
			if shortFailures >= 3 {
				// Stagger dormancy wake-up: random 30s-3min so all 10 connections
				// don't try to reconnect simultaneously (which causes Quota Reached).
				dormantDuration := time.Duration(30+mathrand.Intn(150)) * time.Second
				log.Printf("proxy: %d consecutive short failures, sleeping %s before retry", shortFailures, dormantDuration.Round(time.Second))
				select {
				case <-time.After(dormantDuration):
					shortFailures = 0 // reset after dormancy
					log.Printf("proxy: waking from dormancy, retrying connection")
					// DON'T wholesale-invalidate the pool here. This conn was
					// dormant, but other conns may have been running fine on
					// existing creds — wholesale-invalidate destroys them and
					// forces every conn to re-fetch (which often hits captcha).
					// If our retry uses a stale cred and gets a short-lived
					// session, the per-slot invalidateEntry path (line ~1228)
					// drops only that bad slot. Other conns keep their creds.
				case <-sessCtx.Done():
					return sessCtx.Err()
				case <-p.ctx.Done():
					return p.ctx.Err()
				}
				continue
			}

			// Staggered delay before reconnect: random 2-7s to avoid
			// all connections hitting TURN server at the same instant.
			delay := time.Duration(2000+mathrand.Intn(5000)) * time.Millisecond
			select {
			case <-time.After(delay):
			case <-sessCtx.Done():
				return sessCtx.Err()
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		}
	}
}

// resolveTURNAddr returns (addr, creds, credSlot, err) for the given
// connection slot. credSlot identifies which pool slot ultimately
// provided the cred — either connIdx itself (own or freshly-fetched)
// or another slot's index (fallback). Used by short-session detection
// to invalidate the correct slot, and by logging to show which cred
// each TURN session runs on.
//
// Delegates to credPool. allowCaptchaBlock gates whether the underlying
// fetcher may block a CaptchaSolver waiting on user input; when false,
// captcha surfaces as CaptchaRequiredError (which the pool may swallow
// via fallback).
func (p *Proxy) resolveTURNAddr(connIdx int, allowCaptchaBlock bool) (string, *TURNCreds, int, error) {
	return p.credPool.get(connIdx, allowCaptchaBlock)
}

// fetchFreshCreds is the pool's underlying VK fetcher. It wraps GetVKCreds
// with captcha-token bookkeeping and TURN host:port parsing. Serialized
// under credPool.mu, so only one fetch runs at a time — VK rate limiting
// makes real parallelism pointless anyway.
func (p *Proxy) fetchFreshCreds(allowCaptchaBlock bool) (string, *TURNCreds, error) {
	var solver CaptchaSolver
	if allowCaptchaBlock {
		solver = p.config.CaptchaSolver
	}

	// Consume any pre-solved captcha tokens (one-shot — the success_token
	// is only valid for the exact next step2 call).
	var solvedSID, solvedKey string
	var solvedTs, solvedAttempt float64
	if v := p.lastCaptchaSID.Load(); v != nil {
		solvedSID, _ = v.(string)
		if solvedSID != "" {
			p.lastCaptchaSID.Store("")
		}
	}
	if v := p.lastCaptchaKey.Load(); v != nil {
		solvedKey, _ = v.(string)
		if solvedKey != "" {
			p.lastCaptchaKey.Store("")
		}
	}
	if v := p.lastCaptchaTs.Load(); v != nil {
		solvedTs, _ = v.(float64)
	}
	if v := p.lastCaptchaAttempt.Load(); v != nil {
		solvedAttempt, _ = v.(float64)
	}
	var savedToken1 string
	if v := p.lastCaptchaToken1.Load(); v != nil {
		savedToken1, _ = v.(string)
		if savedToken1 != "" {
			p.lastCaptchaToken1.Store("")
		}
	}

	// solver=nil → CaptchaRequiredError surfaces instead of blocking.
	// savedClientID="" preserves existing mid-session behavior — proxy.go
	// doesn't track client_id on captcha-retry today (independent of the
	// pre-bootstrap captcha flow which does pin client_id strictly).
	creds, err := GetVKCreds(p.linkID, solver, solvedSID, solvedKey, solvedTs, solvedAttempt, savedToken1, "")
	if err != nil {
		return "", nil, fmt.Errorf("get VK creds: %w", err)
	}
	turnHost, turnPort, err := net.SplitHostPort(creds.Address)
	if err != nil {
		return "", nil, fmt.Errorf("parse TURN address: %w", err)
	}
	if p.config.TurnServer != "" {
		turnHost = p.config.TurnServer
	}
	if p.config.TurnPort != "" {
		turnPort = p.config.TurnPort
	}
	p.turnServerIP.Store(turnHost)
	return net.JoinHostPort(turnHost, turnPort), creds, nil
}

// runDTLSSession runs a long-lived DTLS session.
// DTLS stays alive while TURN reconnects underneath with fresh creds only on failure.
// Only returns when DTLS itself fails (then the caller restarts everything).
func (p *Proxy) runDTLSSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool, connIdx int) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	// Create AsyncPacketPipe: conn1 = DTLS transport, conn2 = TURN transport.
	// The same conn2 is reused across TURN reconnections (matching the original client).
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	// Get initial credentials and start first TURN relay. credSlot tells
	// us which pool slot actually provided the cred — may equal connIdx
	// (own slot / fresh fetch) or some other slot's index (fallback).
	// We track it so a short-lived session can invalidate the slot that
	// actually carried the bad cred, not this conn's nominal slot.
	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, *signaled)
	if err != nil {
		return err
	}
	// Each successful resolveTURNAddr increments cp.pool[credSlot].active
	// to enforce the per-cred quota (~10 simultaneous allocations on VK).
	// A defer pinned to currentSlot via closure releases the LATEST slot
	// at function exit — important because the reconnect loop below may
	// switch us to a different slot, and we need to release whatever
	// slot we're holding when this conn's session finally ends.
	currentSlot := credSlot
	defer func() { p.credPool.release(currentSlot) }()

	// Start TURN relay FIRST — DTLS handshake goes through it.
	// TURN runs until it fails naturally (no forced lifetime).
	// The pion/turn client handles allocation refresh automatically.
	//
	// spawnTURN shape: the goroutine writes the runTURN result to its
	// returned channel. cancelOnError=true is used during bootstrap so that
	// a fast TURN failure (e.g. 486 quota response in ~100ms) immediately
	// cancels connCtx and unblocks dialDTLS — without this, dialDTLS sat
	// for its full 15s timeout waiting for handshake bytes that would
	// never come, wasting ~14.5s per failed bootstrap attempt.
	//
	// In the reconnect loop below, subsequent runTURN spawns use
	// cancelOnError=false: the loop itself handles failure (chooses delay,
	// fetches fresh creds, re-spawns), and a connCancel from inside the
	// runTURN goroutine would kill the loop on the very first failure.
	spawnTURN := func(addr string, c *TURNCreds, cancelOnError bool) chan error {
		ch := make(chan error, 1)
		go func() {
			err := p.runTURN(connCtx, addr, c, conn2, connIdx)
			ch <- err
			if err != nil && cancelOnError {
				connCancel()
			}
		}()
		return ch
	}
	turnDone := spawnTURN(turnAddr, creds, true)

	// DTLS handshake — packets go through conn1 → conn2 → TURN relay → peer
	dtlsStart := time.Now()
	dtlsConn, err := dialDTLS(connCtx, conn1, p.peer)
	if err != nil {
		connCancel()
		select {
		case turnErr := <-turnDone:
			if turnErr != nil {
				// Bootstrap-path equivalent of the reconnect-loop's
				// markSaturated branch. Without this, a quota error during
				// the first allocation on this conn would surface as a
				// generic "DTLS failed" and the bootstrap retry loop in
				// startConnections would burn its 4-attempt budget retrying
				// the same saturated slot.
				if isQuotaError(turnErr) {
					p.credPool.markSaturated(credSlot, 10*time.Minute)
					log.Printf("proxy: [conn %d] bootstrap quota error on slot %d, marked VK-saturated for 10m",
						connIdx, credSlot)
				} else if isAuthError(turnErr) {
					p.credPool.invalidateEntry(credSlot)
					log.Printf("proxy: [conn %d] bootstrap auth error on slot %d, invalidated",
						connIdx, credSlot)
				}
				return fmt.Errorf("DTLS failed: %w (TURN error: %v)", err, turnErr)
			}
		default:
		}
		return fmt.Errorf("DTLS: %w", err)
	}
	defer dtlsConn.Close()

	// Close DTLS when context is cancelled to unblock Read() immediately.
	context.AfterFunc(connCtx, func() {
		dtlsConn.Close()
	})

	// Record DTLS handshake time
	p.dtlsHSns.Store(int64(time.Since(dtlsStart)))
	p.activeConns.Add(1)
	p.totalConns.Add(1)
	defer p.activeConns.Add(-1)

	// Signal ready
	if readyCh != nil && !*signaled {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	// Mark as signaled for ALL connection slots (not just slot 0).
	// This ensures that on reconnection, allowCaptchaBlock=true so the
	// captcha solver can block and wait for the user to solve the captcha
	// instead of immediately returning CaptchaRequiredError.
	*signaled = true

	// Signal proxy-lifetime bootstrap ready exactly once. Safe to call on
	// every successful reconnect — sync.Once drops all calls after the first.
	p.signalBootstrapDone(nil)

	log.Printf("proxy: [conn %d, cred %d] DTLS+TURN session established", connIdx, credSlot)

	// Reset this conn's last-pong time to "now" so the zombie watchdog
	// gives the conn a fresh probeStaleThreshold window before it
	// considers killing it. Without this, a re-established conn whose
	// previous incarnation died with stale lastPongTime would be
	// killed immediately on its first probe tick.
	if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
		p.lastPongTimes[connIdx].Store(time.Now().Unix())
	}

	// Liveness-probe sender. Periodically writes a sentinel packet
	// through this conn's DTLS pipe; the server echoes if it's
	// patched, drops to WireGuard if not (and WG drops it as malformed).
	// On the receive side the recv goroutine recognizes the magic
	// bytes and updates p.lastPongTimes[connIdx]. After any pong has
	// arrived (serverProbeable=true), each tick checks whether
	// lastPongTime is stale beyond probeStaleThreshold and if so
	// cancels connCtx, which propagates through wg.Wait below and
	// returns from runDTLSSession — runConnection then takes over and
	// rebuilds the conn with a fresh TURN allocation. See proxy
	// struct comment on serverProbeable / lastPongTimes for full
	// rationale.
	go func() {
		ticker := time.NewTicker(probeInterval)
		defer ticker.Stop()
		var seq uint64
		pingPkt := make([]byte, len(probePingMagic)+8)
		copy(pingPkt[0:len(probePingMagic)], probePingMagic)
		for {
			select {
			case <-ticker.C:
				seq++
				binary.BigEndian.PutUint64(pingPkt[len(probePingMagic):], seq)
				dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := dtlsConn.Write(pingPkt); err != nil {
					// Write failure means the conn is already broken.
					// Other goroutines (DTLS recv timeout, TURN reconnect
					// loop) will handle the actual teardown — we just
					// stop sending probes.
					return
				}
				// Zombie check — currently DETECT-ONLY, no kill.
				//
				// Reason for not killing: when a network handover (e.g.
				// WiFi→LTE) zombifies all 30 conns simultaneously, mass-
				// killing leads to a recovery storm:
				//   1. All 30 conns reconnect simultaneously
				//   2. Each tries ownSlot, gets 486 (cred quota saturated
				//      server-side by old NAT mapping's allocations,
				//      lifetime ~10 min)
				//   3. markSaturated → fallback → next slot also 486 →
				//      eventually all 4 cred slots VK-saturated
				//   4. Phase 2 → fresh fetch → captcha required
				//   5. Captcha WebView page is hosted on id.vk.ru, which
				//      is routed THROUGH the tunnel (iOS ignores
				//      excludedRoutes when includeAllNetworks=true — our
				//      vpn-routing-diag project verified this) — so with
				//      0 alive conns, the WebView request can't reach VK.
				//      User sees blank captcha, infinite stuck.
				//
				// Without kill: 30 conns stay "active" with high packet
				// loss (35%), tunnel is degraded but the user can still
				// see/fix it. Better UX than total deadlock.
				//
				// Re-enable when we have a captcha-during-broken-tunnel
				// recovery path — e.g., extension-side captcha rendering
				// + WKURLSchemeHandler bypass, or cancelTunnelWithError +
				// trigger pre-bootstrap from main app.
				if p.serverProbeable.Load() && connIdx >= 0 && connIdx < len(p.lastPongTimes) {
					lastPong := time.Unix(p.lastPongTimes[connIdx].Load(), 0)
					stale := time.Since(lastPong)
					if stale > probeStaleThreshold {
						log.Printf("proxy: [conn %d] zombie detected (no pong for %s) — kill disabled, see comment in proxy.go",
							connIdx, stale.Round(time.Second))
						// connCancel()  // NOT called — see comment above.
					}
				}
			case <-connCtx.Done():
				return
			}
		}
	}()

	// TURN reconnection loop in background.
	// Only reconnects when TURN actually fails (not proactively).
	// The same conn2 is reused — DTLS doesn't see the reconnection.
	go func() {
		defer connCancel() // if TURN loop gives up, kill DTLS too
		turnStart := time.Now()
		for {
			// Wait for current TURN to finish; capture err so the
			// invalidate / delay decisions below can branch on the
			// failure type instead of guessing from session duration.
			var turnErr error
			select {
			case turnErr = <-turnDone:
			case <-connCtx.Done():
				return
			}

			if connCtx.Err() != nil {
				return
			}

			turnAge := time.Since(turnStart)
			p.reconnects.Add(1)
			log.Printf("proxy: [conn %d] TURN session ended after %s (err=%v), reconnecting...",
				connIdx, turnAge.Round(time.Second), turnErr)

			// Decide whether to invalidate the cred slot.
			//
			// Previous heuristic was time-based (turnAge < 30s ⇒ assume
			// cred expired ⇒ invalidate). That conflated three cases:
			//   1. Auth error (401/403): cred truly stale → invalidate.
			//   2. 486 quota: cred fine, just too many parallel allocs
			//      on it. With NumConns > 10 (or even ~10 under
			//      reconnect storm), the 11th-Nth attempt always gets
			//      486 fast → time-based heuristic invalidated a
			//      working cred and killed the pool for the other 10
			//      conns. Observed: vpn.wifi.18.log at 20:28:17, where
			//      a single 486 from a redundant conn killed slot 5
			//      mid-session.
			//   3. Network blip / iOS socket race: cred unrelated.
			//
			// New: invalidate only on auth errors. Quota and network
			// errors keep the cred — caller's reconnect handles them
			// via the delay choice below.
			if isAuthError(turnErr) {
				p.credPool.invalidateEntry(credSlot)
				log.Printf("proxy: [conn %d] auth error (%v), invalidated cred slot %d",
					connIdx, turnErr, credSlot)
			} else if isQuotaError(turnErr) {
				// VK's allocation count for this cred is at 10 from prior
				// (possibly already-killed-on-our-side) allocations. The
				// cred is fine; VK just won't accept more on it for the
				// remainder of those allocations' TURN lifetime (~10 min).
				// Mark the slot saturated so subsequent get() calls steer
				// elsewhere instead of looping on the same cred. Without
				// this, ForceReconnect after a watchdog trip is a deadlock
				// (vpn.lte.0.log on 2026-04-29: 4 bootstrap attempts all
				// hit cred 0 → 486 → "first connection failed" → no more
				// retries since watchdog conditions all require active>0).
				p.credPool.markSaturated(credSlot, 10*time.Minute)
				log.Printf("proxy: [conn %d] quota error on slot %d, marked VK-saturated for 10m",
					connIdx, credSlot)
			}

			// Pause before reconnecting. 486 quota needs the longest
			// delay — VK's allocation token bucket refills slowly
			// (empirically ~30s for 1 token after the initial burst of
			// ~10), so 5s here gives a partial refill window before
			// the next attempt. Other short-lived failures keep the
			// existing 3s pause; normal reconnects after long sessions
			// just need 500ms.
			var delay time.Duration
			switch {
			case isQuotaError(turnErr):
				delay = 5 * time.Second
			case turnAge < 5*time.Second:
				delay = 3 * time.Second
			default:
				delay = 500 * time.Millisecond
			}
			select {
			case <-time.After(delay):
			case <-connCtx.Done():
				return
			}

			// Get fresh VK credentials and reconnect TURN.
			//
			// Retry budget is wide because mass-failure events (e.g. iOS DHCP
			// renewal kills all 10 sockets simultaneously, observed every ~2h
			// on routers with short lease) put every conn into reconnect at
			// once with an empty/cooldown pool. Pool grower runs in the
			// background at ~15% PoW success rate, so a working cred typically
			// arrives within 30-60s — but only if our retry loop hasn't
			// already given up.
			//
			// 12 attempts × linear backoff capped at 30s ≈ 2.5 min total wait
			// budget per conn. Long enough to outlast a typical pool refill,
			// short enough that runConnection's outer loop still kicks in if
			// we've truly hit a dead-end.
			const maxTurnReconnectRetries = 12
			retries := 0
			for retries < maxTurnReconnectRetries {
				if connCtx.Err() != nil {
					return
				}
				// allowCaptchaBlock=false: surface CaptchaRequiredError instead
				// of letting cp.fetch invoke the user solver (waitForCaptchaAnswer)
				// which would block indefinitely on captchaCh until a user
				// answer arrives. The CaptchaRequiredError is then caught a
				// few lines below and handled via the explicit captcha-wait
				// probe loop, which periodically probes the pool every 2 min
				// and exits as soon as background grower fills any slot.
				//
				// Without this, a single conn whose TURN goes short-lived at
				// a moment when VK requires captcha would silently sit blocked
				// in the solver forever (observed: conn 0 in vpn.wifi.3.log
				// stuck from 12:51:41 onward, missed every subsequent network
				// reconnect event).
				newAddr, newCreds, newSlot, err := p.resolveTURNAddr(connIdx, false)
				if err != nil {
					// Check if it's a captcha that needs human interaction.
					// Instead of burning retries, freeze and wait for the user.
					var captchaErr *CaptchaRequiredError
					if errors.As(err, &captchaErr) {
						log.Printf("proxy: TURN reconnect needs captcha (slider), waiting for user or periodic retry")
						p.captchaImageURL.Store(captchaErr.ImageURL)
						p.lastCaptchaSID.Store(captchaErr.SID)
						p.lastCaptchaTs.Store(captchaErr.CaptchaTs)
						p.lastCaptchaAttempt.Store(captchaErr.CaptchaAttempt)
						p.lastCaptchaToken1.Store(captchaErr.Token1)
						// Wait for user to solve captcha OR periodic self-retry.
						// Self-retry every 2 min handles the case where VK cools down
						// while the user is unavailable (overnight, meeting, etc.).
						// RefreshCaptchaURL no longer auto-unblocks to avoid ping-pong.
						captchaResolved := false
						turnProbeInterval := 2 * time.Minute
						for !captchaResolved {
							select {
							case answer := <-p.captchaCh:
								p.captchaImageURL.Store("")
								if answer != "" {
									p.lastCaptchaKey.Store(answer)
									log.Printf("proxy: captcha solved during TURN reconnect (%d chars), retrying", len(answer))
								} else {
									log.Printf("proxy: VK no longer requires captcha, retrying normally")
								}
								captchaResolved = true
							case <-time.After(turnProbeInterval):
								// Periodic self-retry: try the full credential flow
								// without captcha solver to see if VK cooled down.
								// But suppress if user is actively viewing captcha WebView
								// (RefreshCaptchaURL was called < 10 min ago). Probing would
								// create new VK sessions that invalidate the current one,
								// causing "Attempt limit reached" in the WebView.
								if lastRefresh := p.lastRefreshCaptchaTime.Load(); lastRefresh > 0 {
									if time.Since(time.Unix(lastRefresh, 0)) < 10*time.Minute {
										log.Printf("proxy: captcha wait timeout, but user is viewing WebView (last refresh %s ago), skipping probe",
											time.Since(time.Unix(lastRefresh, 0)).Round(time.Second))
										continue
									}
								}
								log.Printf("proxy: captcha wait timeout, probing (interval was %s)...", turnProbeInterval)
								// DON'T wholesale-invalidate the pool here.
								// This is the main bleeder: a single conn stuck
								// in captcha-wait would wipe the pool every 2
								// minutes, destroying creds other conns are
								// actively running on. credPool.get below
								// returns cached cred if available — that's
								// the strongest possible signal that VK has
								// cooled down (some other path successfully
								// fetched). If pool is empty, fetch happens
								// with allowCaptchaBlock=false, so captcha
								// surfaces as error and we wait another cycle.
								_, _, probeSlot, probeErr := p.resolveTURNAddr(connIdx, false)
								// Probe is non-consuming; release whatever slot
								// got acquired (or no-op if probeSlot == -1).
								if probeErr == nil {
									p.credPool.release(probeSlot)
								}
								if probeErr == nil {
									log.Printf("proxy: VK no longer requires captcha (probe succeeded), resuming")
									p.captchaImageURL.Store("")
									captchaResolved = true
								} else {
									var probeCapErr *CaptchaRequiredError
									if errors.As(probeErr, &probeCapErr) {
										if probeCapErr.IsRateLimit {
											turnProbeInterval = 10 * time.Minute
											log.Printf("proxy: VK rate-limited (ERROR_LIMIT), backing off to %s", turnProbeInterval)
										} else {
											turnProbeInterval = 2 * time.Minute
											log.Printf("proxy: VK still requires captcha, waiting %s", turnProbeInterval)
										}
										p.captchaImageURL.Store(probeCapErr.ImageURL)
										p.lastCaptchaSID.Store(probeCapErr.SID)
										p.lastCaptchaTs.Store(probeCapErr.CaptchaTs)
										p.lastCaptchaAttempt.Store(probeCapErr.CaptchaAttempt)
										p.lastCaptchaToken1.Store(probeCapErr.Token1)
									} else {
										log.Printf("proxy: probe failed (non-captcha): %v, waiting %s", probeErr, turnProbeInterval)
									}
								}
							case <-connCtx.Done():
								p.captchaImageURL.Store("")
								return
							case <-p.ctx.Done():
								p.captchaImageURL.Store("")
								return
							}
						}
						// Don't increment retries — this wasn't a real failure
						continue
					}
					retries++
					log.Printf("proxy: TURN creds fetch failed (attempt %d/%d): %s", retries, maxTurnReconnectRetries, err)
					// Linear backoff capped at 30s. With maxTurnReconnectRetries=12
					// the per-attempt waits are 2,4,6,8,10,12,14,16,18,20,22,24
					// (caps don't kick in but the cap is defensive). Total
					// ~156s ≈ 2.5 min wait budget.
					backoff := time.Duration(retries*2) * time.Second
					if backoff > 30*time.Second {
						backoff = 30 * time.Second
					}
					select {
					case <-time.After(backoff):
					case <-connCtx.Done():
						return
					}
					continue
				}

				// Track which cred slot this new TURN session will run on
				// so the next short-session detection invalidates the right
				// slot rather than the nominal connIdx.
				//
				// Release the previous slot's active count: resolveTURNAddr
				// already incremented active for the new acquire (whether or
				// not it picked the same slot), and the previous active was
				// from this conn's prior holding. Always one release to
				// balance, regardless of whether newSlot == credSlot.
				p.credPool.release(credSlot)
				credSlot = newSlot
				currentSlot = newSlot

				log.Printf("proxy: [conn %d, cred %d] starting new TURN session (attempt %d)", connIdx, credSlot, retries+1)
				turnStart = time.Now()
				// cancelOnError=false: this loop owns reconnection; an
				// inner connCancel would kill the loop on first failure.
				turnDone = spawnTURN(newAddr, newCreds, false)
				break
			}
			if retries >= maxTurnReconnectRetries {
				log.Printf("proxy: TURN reconnection failed after %d attempts, giving up", maxTurnReconnectRetries)
				return // session dies → runConnection will wait 5 min or ForceReconnect
			}
		}
	}()

	// Bidirectional forwarding: sendCh ↔ dtlsConn (long-lived)
	var wg sync.WaitGroup
	wg.Add(2)

	// Send: sendCh → dtlsConn
	go func() {
		defer wg.Done()
		defer connCancel()
		for {
			select {
			case <-connCtx.Done():
				log.Printf("proxy: [conn %d] DTLS send goroutine: ctx cancelled", connIdx)
				return
			case pkt := <-p.sendCh:
				dtlsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := dtlsConn.Write(pkt); err != nil {
					log.Printf("proxy: [conn %d] DTLS send goroutine: write error: %v", connIdx, err)
					return
				}
			}
		}
	}()

	// Receive: dtlsConn → recvCh
	// Use short read deadline (30s) to keep the goroutine active for iOS
	// (Read syscalls count as visible activity). On timeout, check GLOBAL
	// lastRecvTime — if the tunnel has received ANY packet recently via
	// any connection, this connection is fine (just didn't happen to get
	// the packet). Only reconnect if the entire tunnel is stale.
	//
	// This fixes the "sendCh contention starvation" problem: WireGuard
	// keepalives arrive through one random connection, leaving others
	// without packets. Instead of killing starving connections, we trust
	// the global health check.
	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			dtlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := dtlsConn.Read(buf)
			if err != nil {
				if connCtx.Err() != nil {
					log.Printf("proxy: [conn %d] DTLS recv goroutine: ctx cancelled (err=%v)", connIdx, err)
					return // context cancelled (Pause/Resume/Stop)
				}
				// On timeout, check if the tunnel is globally healthy.
				// If any connection received a packet in the last 3 minutes,
				// keep this connection alive too.
				if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
					lastRecv := p.lastRecvTime.Load()
					if lastRecv > 0 && time.Since(time.Unix(lastRecv, 0)) < 3*time.Minute {
						// Tunnel alive, this connection just didn't get packets
						continue
					}
					// Tunnel stale — reconnect
					staleFor := "unknown"
					if lastRecv > 0 {
						staleFor = time.Since(time.Unix(lastRecv, 0)).Round(time.Second).String()
					}
					log.Printf("proxy: [conn %d] DTLS read timeout, tunnel stale (last recv %s ago), reconnecting", connIdx, staleFor)
					return
				}
				// Real error (not timeout) — reconnect
				log.Printf("proxy: [conn %d] DTLS read error: %v", connIdx, err)
				return
			}
			p.lastRecvTime.Store(time.Now().Unix())
			// Liveness-probe pong recognition: any DTLS payload starting
			// with probePingMagic is a server echo of one of our pings.
			// Update per-conn last-pong time and the global
			// serverProbeable flag, then drop the packet — it must NOT
			// reach WireGuard, which would treat the 0xff... bytes as
			// an invalid message type. With an unpatched server these
			// packets never appear (server forwards our ping to WG and
			// WG drops it; nothing comes back), so this branch is a
			// no-op until the server gets the matching patch.
			if isProbePacket(buf[:n]) {
				p.serverProbeable.Store(true)
				if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
					p.lastPongTimes[connIdx].Store(time.Now().Unix())
				}
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case p.recvCh <- pkt:
			case <-connCtx.Done():
				log.Printf("proxy: [conn %d] DTLS recv goroutine: ctx cancelled during recvCh send", connIdx)
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// runDirectSession runs a direct TURN session (no DTLS).
// TURN reconnects with fresh creds only on failure.
func (p *Proxy) runDirectSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool, connIdx int) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	context.AfterFunc(connCtx, func() {
		conn1.Close()
	})

	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, *signaled)
	if err != nil {
		return err
	}
	currentSlot := credSlot
	defer func() { p.credPool.release(currentSlot) }()

	turnDone := make(chan error, 1)
	go func() {
		turnDone <- p.runTURN(connCtx, turnAddr, creds, conn2, -1)
	}()

	if readyCh != nil && !*signaled {
		*signaled = true
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	// Signal proxy-lifetime bootstrap ready (sync.Once, idempotent).
	p.signalBootstrapDone(nil)

	log.Printf("proxy: [conn %d, cred %d] direct TURN session established", connIdx, credSlot)

	// TURN reconnection loop (same as DTLS version but without DTLS)
	go func() {
		defer connCancel()
		for {
			select {
			case <-turnDone:
			case <-connCtx.Done():
				return
			}
			if connCtx.Err() != nil {
				return
			}
			log.Printf("proxy: [conn %d, cred %d] direct TURN ended, reconnecting...", connIdx, credSlot)
			select {
			case <-time.After(500 * time.Millisecond):
			case <-connCtx.Done():
				return
			}
			retries := 0
			for retries < 5 {
				if connCtx.Err() != nil {
					return
				}
				newAddr, newCreds, newSlot, err := p.resolveTURNAddr(connIdx, true)
				if err != nil {
					retries++
					select {
					case <-time.After(time.Duration(retries) * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}
				// Release the previous slot's quota slot; resolveTURNAddr
				// has already incremented active for the new acquire.
				p.credPool.release(credSlot)
				credSlot = newSlot
				currentSlot = newSlot
				log.Printf("proxy: [conn %d, cred %d] starting new direct TURN session", connIdx, credSlot)
				turnDone = make(chan error, 1)
				go func() {
					turnDone <- p.runTURN(connCtx, newAddr, newCreds, conn2, -1)
				}()
				break
			}
			if retries >= 5 {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer connCancel()
		for {
			select {
			case <-connCtx.Done():
				return
			case pkt := <-p.sendCh:
				conn1.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn1.WriteTo(pkt, p.peer); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			conn1.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, _, err := conn1.ReadFrom(buf)
			if err != nil {
				if connCtx.Err() != nil {
					return
				}
				log.Printf("proxy: direct read error: %v", err)
				return
			}
			p.lastRecvTime.Store(time.Now().Unix())
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case p.recvCh <- pkt:
			case <-connCtx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// runTURN establishes a TURN relay and forwards packets between conn2 and the relay.
// Runs until the relay fails or ctx is cancelled. No forced lifetime —
// the pion/turn client handles allocation refresh automatically.
// conn2's deadline is reset before returning so it can be reused.
func (p *Proxy) runTURN(ctx context.Context, turnAddr string, creds *TURNCreds, conn2 net.PacketConn, connIdx int) error {
	turnUDPAddr, err := net.ResolveUDPAddr("udp", turnAddr)
	if err != nil {
		return fmt.Errorf("resolve TURN: %w", err)
	}

	// Connect to TURN server
	var turnConn net.PacketConn
	if p.config.UseUDP {
		udpConn, err := net.DialUDP("udp", nil, turnUDPAddr)
		if err != nil {
			return fmt.Errorf("dial TURN UDP: %w", err)
		}
		defer udpConn.Close()
		turnConn = &connectedUDPConn{udpConn}
	} else {
		tcpCtx, tcpCancel := context.WithTimeout(ctx, 5*time.Second)
		defer tcpCancel()
		var d net.Dialer
		tcpConn, err := d.DialContext(tcpCtx, "tcp", turnAddr)
		if err != nil {
			return fmt.Errorf("dial TURN TCP: %w", err)
		}
		defer tcpConn.Close()
		turnConn = turn.NewSTUNConn(tcpConn)
	}

	// Determine address family
	var addrFamily turn.RequestedAddressFamily
	if p.peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Username:               creds.Username,
		Password:               creds.Password,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          &turnLoggerFactory{proxy: p},
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("TURN client: %w", err)
	}
	defer client.Close()

	if err = client.Listen(); err != nil {
		return fmt.Errorf("TURN listen: %w", err)
	}

	allocStart := time.Now()
	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("TURN allocate: %w", err)
	}
	defer relayConn.Close()
	p.turnRTTns.Store(int64(time.Since(allocStart)))

	// Log turnConn.LocalAddr() too — this is the source address the OS kernel
	// picked for our outbound UDP socket. On iOS it tells us which interface
	// the Network Extension is using (cellular CGNAT like 10.x.x.x vs WiFi
	// local range like 192.168.x.x), which is otherwise invisible and
	// critically affects which source IP VK TURN sees.
	log.Printf("proxy: [conn %d] TURN relay allocated: %s (RTT %dms, local=%s)",
		connIdx, relayConn.LocalAddr(), time.Since(allocStart).Milliseconds(), turnConn.LocalAddr())

	// NAT keepalive — send a STUN Binding request every 25 seconds on the
	// underlying TURN socket. This prevents WiFi router NAT mapping expiry
	// during iOS sleep.
	//
	// When the phone is awake, WireGuard keepalives (every 25s) flow through
	// the TURN socket and refresh the NAT mapping as a side effect. But when
	// iOS sleeps, WG keepalives stop (TUN device is frozen), and the TURN
	// socket goes silent. Home routers typically expire UDP NAT mappings
	// after 30-120 seconds of inactivity (e.g. pf udp.multiple = 60s).
	// After expiry, the router assigns a new external port for the next
	// outgoing packet, causing a 5-tuple mismatch on the TURN server which
	// rejects further requests with 400 Bad Request.
	//
	// STUN Binding request is ~28 bytes, VK responds with a Binding response.
	// The round-trip refreshes the NAT mapping. During iOS freeze the Go
	// ticker doesn't fire, but on each brief thaw (iOS thaws the process
	// every 10-15 seconds during sleep) the ticker catches up and fires
	// immediately, keeping the mapping alive.
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = client.SendBindingRequest()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Bidirectional forwarding: conn2 ↔ relayConn
	var wg sync.WaitGroup
	wg.Add(2)
	turnCtx, turnCancel := context.WithCancel(ctx)
	defer turnCancel()
	context.AfterFunc(turnCtx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})

	var peerAddr atomic.Value

	// conn2 → relay
	// No select{default} polling — context cancellation is handled via deadline
	// set in context.AfterFunc above, which unblocks ReadFrom.
	go func() {
		defer wg.Done()
		defer turnCancel()
		buf := make([]byte, 1600)
		for {
			n, addr, err := conn2.ReadFrom(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: ReadFrom error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			peerAddr.Store(addr)
			if _, err = relayConn.WriteTo(buf[:n], p.peer); err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: WriteTo error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
		}
	}()

	// relay → conn2
	go func() {
		defer wg.Done()
		defer turnCancel()
		buf := make([]byte, 1600)
		for {
			n, _, err := relayConn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: ReadFrom error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			addr, ok := peerAddr.Load().(net.Addr)
			if !ok {
				log.Printf("proxy: [conn %d] runTURN relay→conn2: peerAddr not set, exiting", connIdx)
				return
			}
			if _, err = conn2.WriteTo(buf[:n], addr); err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: WriteTo error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
		}
	}()

	wg.Wait()
	// Reset conn2 deadline so it can be reused by the next TURN session.
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
	return nil
}

// dialDTLS establishes a DTLS connection using the given PacketConn as transport.
func dialDTLS(ctx context.Context, transport net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	// CipherSuites order is chosen to overlap with Apple WebRTC's ClientHello
	// (captured via Wireshark on a real VK call): c02b, c02f, c00a, c014 are
	// the four Apple ciphers that pion/dtls v3 actually implements. Goal is to
	// shift our JA4 fingerprint away from the unique "single cipher" signature
	// that VK could trivially whitelist against. We don't include Apple's
	// TLS 1.3 ciphers (1301/1302/1303), CHACHA20 (cca8/cca9), AES-128-CBC
	// (c009/c013) or RSA-only (009c/002f/0035) because pion can't fulfil the
	// handshake if the server picks one. Server picks first compatible match,
	// which is c02b (same as before).
	//
	// ConnectionIDGenerator removed: Apple WebRTC does not advertise the
	// connection_id extension in its ClientHello at all. OnlySendCIDGenerator
	// caused us to send a CID extension nobody else sends — distinctive enough
	// to fingerprint by itself.
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xc02b
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 0xc02f
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    // 0xc00a
			dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      // 0xc014
		},
	}
	dtlsConn, err := dtls.Client(transport, peer, config)
	if err != nil {
		return nil, err
	}
	// 15s timeout: shorter than the 30s default so the bootstrap retry
	// loop (see startConnections) gets ~4 chances within ~90s instead of
	// burning ~60s on two long timeouts. Real-world DTLS handshakes
	// complete in ~50-300ms (see "DTLS HS" in stats), so 15s is plenty
	// of headroom for slow networks while still failing fast on transient
	// network breaks worth retrying.
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	defer hsCancel()
	if err := dtlsConn.HandshakeContext(hsCtx); err != nil {
		dtlsConn.Close()
		return nil, err
	}
	return dtlsConn, nil
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

// turnLoggerFactory logs pion/turn refresh and error messages to help debug
// TURN allocation lifetime issues. Only Warn/Error and refresh-related Debug
// messages are logged; everything else is suppressed. The factory holds a
// reference to the owning Proxy so loggers can bump the silent-degradation
// counter when permission/binding refreshes start failing.
type turnLoggerFactory struct {
	proxy *Proxy
}

func (f *turnLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &turnLogger{scope: scope, proxy: f.proxy}
}

type turnLogger struct {
	scope string
	proxy *Proxy
}

func (l *turnLogger) Trace(msg string)                          {}
func (l *turnLogger) Tracef(format string, args ...interface{}) {}
func (l *turnLogger) Debug(msg string) {
	if strings.Contains(msg, "efresh") || strings.Contains(msg, "lifetime") || strings.Contains(msg, "Lifetime") ||
		strings.Contains(msg, "Failed to read") || strings.Contains(msg, "Failed to handle") || strings.Contains(msg, "Exiting loop") {
		log.Printf("pion/%s: %s", l.scope, msg)
	}
}
func (l *turnLogger) Debugf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "efresh") || strings.Contains(msg, "lifetime") || strings.Contains(msg, "Lifetime") || strings.Contains(msg, "ifetime") ||
		strings.Contains(msg, "Failed to read") || strings.Contains(msg, "Failed to handle") || strings.Contains(msg, "Exiting loop") {
		log.Printf("pion/%s: %s", l.scope, msg)
	}
}
func (l *turnLogger) Info(msg string)                          {}
func (l *turnLogger) Infof(format string, args ...interface{}) {}
func (l *turnLogger) Warn(msg string) {
	log.Printf("pion/%s: WARN: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
}
func (l *turnLogger) Warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("pion/%s: WARN: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
}
func (l *turnLogger) Error(msg string) {
	log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
}
func (l *turnLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
}

// maybeCountTransientError bumps the per-Proxy silent-degradation counter when
// the pion client logs a permission or channel-binding refresh failure that
// indicates the VK TURN server is actively rejecting our requests. Both
// failure modes leave the allocation outwardly healthy (conns/lastRecvTime
// stay fresh) while throughput collapses, so the watchdog needs an explicit
// signal to detect the situation.
//
// Server-rejection errors from pion contain the substring "error response"
// because that's how the stun.MessageType for the error class stringifies
// (e.g. "CreatePermission error response (error 400: Bad Request)" or
// "unexpected response type ChannelBind error response"). Any other kind of
// failure is NOT a server rejection and must be excluded:
//
//   - "transaction closed" — pion cancelled in-flight transactions during
//     our own ForceReconnect (client.Close() path). No server rejection.
//   - "all retransmissions failed" — STUN transaction never got a reply,
//     network-layer drop (WiFi handoff, captive portal, iOS freezing the
//     UDP socket). Already covered by watchdog condition 1.
//   - "use of closed network connection" — pion tried to write to a UDP
//     socket we'd already closed during teardown.
//
// Rather than blacklisting each failure mode, we whitelist on the "error
// response" marker — if the server actually responded with an error, it's
// a real degradation signal; otherwise it's local-side noise we ignore.
// This is safe because "No transaction for Refresh error response" is
// logged by pion at Debugf level, not Warnf/Errorf, so it never reaches
// this function.
func (l *turnLogger) maybeCountTransientError(msg string) {
	if l.proxy == nil {
		return
	}
	if !strings.Contains(msg, "error response") {
		return
	}
	if !strings.Contains(msg, "Fail to refresh permissions") && !strings.Contains(msg, "Failed to bind channel") {
		return
	}
	l.proxy.pionTransientErrors.Add(1)
	if l.proxy.firstPionErrorTime.Load() == 0 {
		l.proxy.firstPionErrorTime.Store(time.Now().Unix())
	}
}

// sanitizeLog removes null bytes from log messages (VK TURN server
// includes trailing \0 in STUN error reason phrases).
func sanitizeLog(s string) string { return strings.ReplaceAll(s, "\x00", "") }

// isAuthError returns true if err looks like a TURN/STUN authentication
// failure (401 Unauthorized, 403 Forbidden), meaning the credentials are
// server-side stale and the cred pool slot should be invalidated.
//
// pion/turn surfaces these as e.g.
//   "TURN allocate: Allocate error response (error 401: Unauthorized)"
// We string-match the numeric codes because pion does not export typed
// error wrappers we could errors.As against — the Allocate error is
// constructed via fmt.Errorf with the integer formatted into the message.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "error 401:") || strings.Contains(s, "error 403:")
}

// isQuotaError returns true if err is a 486 Allocation Quota Reached
// response from the TURN server. The cred is fine; the server is just
// telling us to back off because either (a) too many parallel
// allocations are already active on this cred, or (b) the cred's
// allocation token bucket is empty and we should retry after refill
// (~30s for one token after the initial burst of ~10).
//
// Crucially, NOT a signal that the cred should be invalidated — earlier
// versions of this code conflated 486 with 401 via a time-based
// heuristic and wholesale-invalidated working creds whenever a single
// surplus conn hit the quota cap. See vpn.wifi.18.log 20:28:17 for a
// case where this killed the only living cred slot mid-session.
func isQuotaError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "error 486:")
}

// Liveness-probe protocol constants.
//
// probePingMagic is a 4-byte sentinel for sentinel/echo packets sent
// over each conn's DTLS pipe to detect zombie conns. The first byte
// 0xff is deliberately chosen to fall outside WireGuard's 1..4 message
// type range, so an unpatched server forwards the packet to its WG
// instance and WG silently drops it as malformed — making the probe
// fully backward-compatible with non-probe-aware servers.
//
// probeInterval / probeStaleThreshold: the probe goroutine sends a
// ping every probeInterval. After serverProbeable has been observed
// true at least once (i.e. some conn DID get a pong), each conn's
// lastPongTime is checked: if no pong has arrived within
// probeStaleThreshold, the conn is treated as zombie and killed.
// 30s × 4 = 120s gives enough room for one missed probe + reasonable
// network jitter before declaring a conn dead.
var probePingMagic = []byte{0xff, 'P', 'N', 'G'}

const (
	probeInterval       = 30 * time.Second
	probeStaleThreshold = 120 * time.Second
)

// isProbePacket returns true if buf is a probe ping/pong sentinel.
// Both directions use the same magic — server echoes the client's
// packet bytes verbatim — so the same predicate works on both sides.
func isProbePacket(buf []byte) bool {
	if len(buf) < len(probePingMagic) {
		return false
	}
	for i, b := range probePingMagic {
		if buf[i] != b {
			return false
		}
	}
	return true
}
