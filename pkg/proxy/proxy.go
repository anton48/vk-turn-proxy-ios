package proxy

import (
	"context"
	"crypto/tls"
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
	NumConns      int           // number of concurrent connections (default 1)
	CaptchaSolver CaptchaSolver // called when VK requires captcha (may be nil)
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

	// Cached TURN credentials: shared across all connections so only one
	// GetVKCreds call is needed (avoids per-connection captcha).
	cachedCredsMu   sync.Mutex // protects read/write of cached creds
	credsFetchMu    sync.Mutex // serializes GetVKCreds calls (may block on captcha)
	cachedTURNAddr  string
	cachedCreds     *TURNCreds
	cachedCredsTime time.Time

	// Watchdog: last time a packet was received (unix seconds).
	// Used to detect dead tunnels after iOS freeze/thaw.
	lastRecvTime atomic.Int64

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
}

// NewProxy creates a new proxy instance.
func NewProxy(cfg Config) *Proxy {
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	sessCtx, sessCancel := context.WithCancel(ctx)
	p := &Proxy{
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
		sendCh:     make(chan []byte, 256),
		recvCh:     make(chan []byte, 256),
		sessCtx:    sessCtx,
		sessCancel: sessCancel,
		captchaCh:  make(chan string, 1),
	}
	// If no external solver provided, use the built-in channel-based solver
	// that waits for SolveCaptcha() to be called (e.g. from iOS UI).
	if p.config.CaptchaSolver == nil {
		p.config.CaptchaSolver = p.waitForCaptchaAnswer
	}
	return p
}

// Start establishes the DTLS+TURN connection chain.
// It blocks until the first connection is established or an error occurs.
func (p *Proxy) Start() error {
	if p.started.Swap(true) {
		return fmt.Errorf("proxy already started")
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
		return fmt.Errorf("resolve peer: %w", err)
	}
	p.peer = peer

	// Start watchdog goroutine to detect dead tunnels after iOS freeze/thaw.
	// This is the primary self-healing mechanism — it doesn't rely on iOS
	// calling sleep()/wake() which is unreliable.
	go p.runWatchdog()

	return p.startConnections()
}

// startConnections launches all connection goroutines using the current session context.
func (p *Proxy) startConnections() error {
	p.sessMu.Lock()
	sessCtx := p.sessCtx
	p.sessMu.Unlock()

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
	case err := <-errCh:
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
	case <-p.ctx.Done():
		return p.ctx.Err()
	}

	for i := 1; i < p.config.NumConns; i++ {
		p.wg.Add(1)
		connIdx := i
		go func() {
			defer p.wg.Done()
			// Stagger connection launches: 200ms between each to avoid
			// hitting TURN Allocation Quota Reached when all 10 connect at once.
			delay := time.Duration(connIdx*200) * time.Millisecond
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
			p.cachedCredsMu.Lock()
			p.cachedCreds = nil
			p.cachedCredsMu.Unlock()
			_, _, probeErr := p.resolveTURNAddr(p.linkID, false)
			if probeErr == nil {
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
	// Invalidate cached creds so Resume fetches fresh ones
	p.cachedCredsMu.Lock()
	p.cachedCreds = nil
	p.cachedCredsMu.Unlock()
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
	// Invalidate cached creds — after sleep, TURN allocations expired
	p.cachedCredsMu.Lock()
	p.cachedCreds = nil
	p.cachedCredsMu.Unlock()
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
	p.cachedCredsMu.Lock()
	p.cachedCreds = nil
	p.cachedCredsMu.Unlock()
	p.reconnects.Add(1)
	log.Printf("proxy: ForceReconnect — watchdog triggered, starting fresh connections")
	go p.startConnections()
}

// runWatchdog monitors tunnel health and forces reconnection when dead.
// iOS freezes Network Extension processes without calling sleep()/wake().
// After unfreeze, all TURN allocations are expired but goroutines sit on
// dead sockets. The watchdog detects this by tracking the last received packet.
//
// Two conditions trigger a full reconnect:
//  1. No packets for 2 min with active connections → dead tunnel
//  2. Active connections < half of expected for 5+ min → partial recovery stuck
//     (e.g., after Allocation Quota Reached, only 1-2 of 10 connections survive)
func (p *Proxy) runWatchdog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lowConnSince time.Time // when we first noticed too few connections

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
			err = p.runDirectSession(sessCtx, linkID, readyCh, &signaled)
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
					// Invalidate cached creds so we get fresh ones
					p.cachedCredsMu.Lock()
					p.cachedCreds = nil
					p.cachedCredsMu.Unlock()
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

// resolveTURNAddr fetches VK credentials and resolves the TURN server address.
// Uses cached credentials if available (< 5min old) to avoid per-connection captcha.
// Serializes VK API calls via credsFetchMu so only one goroutine fetches at a time.
// If allowCaptchaBlock is false, captcha returns an error instead of blocking.
func (p *Proxy) resolveTURNAddr(linkID string, allowCaptchaBlock bool) (string, *TURNCreds, error) {
	// Fast path: check cache (read lock)
	p.cachedCredsMu.Lock()
	if p.cachedCreds != nil && time.Since(p.cachedCredsTime) < 5*time.Minute {
		addr := p.cachedTURNAddr
		creds := p.cachedCreds
		p.cachedCredsMu.Unlock()
		log.Printf("proxy: using cached TURN creds (age %s)", time.Since(p.cachedCredsTime).Round(time.Second))
		return addr, creds, nil
	}
	p.cachedCredsMu.Unlock()

	// Slow path: serialize credential fetching so only one goroutine calls GetVKCreds.
	// cachedCredsMu is NOT held during fetch — this avoids blocking all goroutines
	// when the solver waits for the user to solve captcha (which can take minutes).
	p.credsFetchMu.Lock()
	defer p.credsFetchMu.Unlock()

	// Re-check cache — another goroutine may have populated it while we waited.
	p.cachedCredsMu.Lock()
	if p.cachedCreds != nil && time.Since(p.cachedCredsTime) < 5*time.Minute {
		addr := p.cachedTURNAddr
		creds := p.cachedCreds
		p.cachedCredsMu.Unlock()
		log.Printf("proxy: using cached TURN creds (age %s)", time.Since(p.cachedCredsTime).Round(time.Second))
		return addr, creds, nil
	}
	p.cachedCredsMu.Unlock()

	var solver CaptchaSolver
	if allowCaptchaBlock {
		solver = p.config.CaptchaSolver
	}
	// Check if we have a solved captcha (success_token from captchaNotRobot.check)
	var solvedSID, solvedKey string
	var solvedTs, solvedAttempt float64
	if v := p.lastCaptchaSID.Load(); v != nil {
		solvedSID, _ = v.(string)
		if solvedSID != "" {
			p.lastCaptchaSID.Store("") // consume it (one-time use)
		}
	}
	if v := p.lastCaptchaKey.Load(); v != nil {
		solvedKey, _ = v.(string)
		if solvedKey != "" {
			p.lastCaptchaKey.Store("") // consume it
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
			p.lastCaptchaToken1.Store("") // consume it
		}
	}
	// solver=nil → CaptchaRequiredError if captcha needed (non-blocking)
	creds, err := GetVKCreds(linkID, solver, solvedSID, solvedKey, solvedTs, solvedAttempt, savedToken1)
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
	addr := net.JoinHostPort(turnHost, turnPort)

	// Cache the credentials for other connections to reuse
	p.cachedCredsMu.Lock()
	p.cachedTURNAddr = addr
	p.cachedCreds = creds
	p.cachedCredsTime = time.Now()
	p.cachedCredsMu.Unlock()

	return addr, creds, nil
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

	// Get initial credentials and start first TURN relay
	turnAddr, creds, err := p.resolveTURNAddr(linkID, *signaled)
	if err != nil {
		return err
	}

	// Start TURN relay FIRST — DTLS handshake goes through it.
	// TURN runs until it fails naturally (no forced lifetime).
	// The pion/turn client handles allocation refresh automatically.
	turnDone := make(chan error, 1)
	go func() {
		turnDone <- p.runTURN(connCtx, turnAddr, creds, conn2, connIdx)
	}()

	// DTLS handshake — packets go through conn1 → conn2 → TURN relay → peer
	dtlsStart := time.Now()
	dtlsConn, err := dialDTLS(connCtx, conn1, p.peer)
	if err != nil {
		connCancel()
		select {
		case turnErr := <-turnDone:
			if turnErr != nil {
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

	log.Printf("proxy: [conn %d] DTLS+TURN session established", connIdx)

	// TURN reconnection loop in background.
	// Only reconnects when TURN actually fails (not proactively).
	// The same conn2 is reused — DTLS doesn't see the reconnection.
	go func() {
		defer connCancel() // if TURN loop gives up, kill DTLS too
		turnStart := time.Now()
		for {
			// Wait for current TURN to finish (it runs until failure)
			select {
			case <-turnDone:
			case <-connCtx.Done():
				return
			}

			if connCtx.Err() != nil {
				return
			}

			turnAge := time.Since(turnStart)
			p.reconnects.Add(1)
			log.Printf("proxy: [conn %d] TURN session ended after %s, reconnecting...", connIdx, turnAge.Round(time.Second))

			// If TURN session was short-lived, the credentials are likely expired.
			// Invalidate cache so the next resolveTURNAddr fetches fresh creds.
			if turnAge < 30*time.Second {
				p.cachedCredsMu.Lock()
				p.cachedCreds = nil
				p.cachedCredsMu.Unlock()
				log.Printf("proxy: [conn %d] short-lived TURN session (%s), invalidated credential cache", connIdx, turnAge.Round(time.Second))
			}

			// Brief pause before reconnecting (longer for short-lived sessions)
			delay := 500 * time.Millisecond
			if turnAge < 5*time.Second {
				delay = 3 * time.Second
			}
			select {
			case <-time.After(delay):
			case <-connCtx.Done():
				return
			}

			// Get fresh VK credentials and reconnect TURN
			retries := 0
			for retries < 5 {
				if connCtx.Err() != nil {
					return
				}
				newAddr, newCreds, err := p.resolveTURNAddr(linkID, true)
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
								p.cachedCredsMu.Lock()
								p.cachedCreds = nil
								p.cachedCredsMu.Unlock()
								_, _, probeErr := p.resolveTURNAddr(linkID, false)
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
					log.Printf("proxy: TURN creds fetch failed (attempt %d/5): %s", retries, err)
					select {
					case <-time.After(time.Duration(retries) * 2 * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}

				log.Printf("proxy: starting new TURN session (attempt %d)", retries+1)
				turnStart = time.Now()
				turnDone = make(chan error, 1)
				go func() {
					turnDone <- p.runTURN(connCtx, newAddr, newCreds, conn2, connIdx)
				}()
				break
			}
			if retries >= 5 {
				log.Printf("proxy: TURN reconnection failed after 5 attempts, giving up")
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
func (p *Proxy) runDirectSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	context.AfterFunc(connCtx, func() {
		conn1.Close()
	})

	turnAddr, creds, err := p.resolveTURNAddr(linkID, *signaled)
	if err != nil {
		return err
	}

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
			log.Printf("proxy: direct TURN ended, reconnecting...")
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
				newAddr, newCreds, err := p.resolveTURNAddr(linkID, true)
				if err != nil {
					retries++
					select {
					case <-time.After(time.Duration(retries) * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}
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
		LoggerFactory:          &turnLoggerFactory{},
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

	log.Printf("proxy: [conn %d] TURN relay allocated: %s (RTT %dms)", connIdx, relayConn.LocalAddr(), time.Since(allocStart).Milliseconds())

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
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	dtlsConn, err := dtls.Client(transport, peer, config)
	if err != nil {
		return nil, err
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, 30*time.Second)
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
// messages are logged; everything else is suppressed.
type turnLoggerFactory struct{}

func (f *turnLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &turnLogger{scope: scope}
}

type turnLogger struct{ scope string }

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
func (l *turnLogger) Info(msg string)                           {}
func (l *turnLogger) Infof(format string, args ...interface{})  {}
func (l *turnLogger) Warn(msg string)                           { log.Printf("pion/%s: WARN: %s", l.scope, sanitizeLog(msg)) }
func (l *turnLogger) Warnf(format string, args ...interface{})  { log.Printf("pion/%s: WARN: %s", l.scope, sanitizeLog(fmt.Sprintf(format, args...))) }
func (l *turnLogger) Error(msg string)                          { log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(msg)) }
func (l *turnLogger) Errorf(format string, args ...interface{}) { log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(fmt.Sprintf(format, args...))) }

// sanitizeLog removes null bytes from log messages (VK TURN server
// includes trailing \0 in STUN error reason phrases).
func sanitizeLog(s string) string { return strings.ReplaceAll(s, "\x00", "") }
