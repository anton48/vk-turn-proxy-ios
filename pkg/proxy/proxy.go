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
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy/srtpwrap"
)

// Config holds proxy configuration.
type Config struct {
	PeerAddr         string        // vk-turn-proxy server address (host:port)
	TurnServer       string        // override TURN server host (optional)
	TurnPort         string        // override TURN port (optional)
	VKLink           string        // VK call invite link or link ID
	UseDTLS          bool          // true = DTLS obfuscation (default mode)
	UseUDP           bool          // true = UDP to TURN, false = TCP
	NumConns         int           // number of concurrent connections (default 1)
	CredPoolCooldown time.Duration // post-failure cooldown per slot in the cred pool; <=0 → default 2m
	CaptchaSolver    CaptchaSolver // called when VK requires captcha (may be nil)
	// SeededTURN, if non-nil, pre-populates credPool slot 0 with these
	// credentials so the first conn establishes immediately without
	// hitting VK's API. Used by the pre-bootstrap captcha flow.
	SeededTURN *TURNCreds
	// CredCachePath is the on-disk JSON file the credPool uses to persist
	// fetched credentials across extension launches. Empty disables
	// persistence. Typically set to "<App Group container>/creds-pool.json"
	// alongside the log file. Cred contents are session tokens with ~8h
	// validity, so the file becomes useful for short-cycle reconnects
	// (user toggling VPN, iOS killing the extension and respawning) but
	// expires naturally on its own clock without active cleanup.
	CredCachePath string

	// UplinkSynthMbit and UplinkSynthSec drive the paced synthetic uplink in
	// synth.go — a DIAGNOSTIC that answers whether the ~19 Mbit/s upload
	// ceiling sits above or below SendPacket. Zero (the default) disables it
	// entirely; anything else runs ONCE, after the connection pool is up, and
	// then never again for the life of the tunnel. Read the result as ΣUP in
	// server1's conn-stats, not from this side. See synth.go for the whole
	// argument and for the two conditions the run needs.
	UplinkSynthMbit float64
	UplinkSynthSec  int

	// UseWrap enables the WRAP obfuscation layer between DTLS and TURN
	// ChannelData (see pkg/proxy/wrap.go). When true, every packet on
	// the wire becomes [nonce][ChaCha20-XOR(WrapKey, nonce, dtls_bytes)],
	// hiding the recognisable DTLS+WireGuard signature that VK's TURN
	// relays use to tag and throttle (peer_ip, peer_port) endpoints.
	// Server side must run with the matching -wrap and -wrap-key flags
	// from the upstream cacggghp/vk-turn-proxy WRAP-aware build —
	// without that, the DTLS handshake fails because the server-side
	// raw bytes get XOR'd by VK-relay-clean-but-WRAP-confused server.
	//
	// NOTE 2026-05-20: WRAP no longer escapes VK's content classifier
	// (see srtp_breakthrough_2026_05_19 memory file). The replacement
	// is UseSrtp below, which falls into VK's "recognised media" bucket
	// and bypasses the per-allocation shape policy entirely. WRAP
	// config fields are kept for backward-compat with existing backups
	// but produce inferior throughput on current VK relays.
	UseWrap bool
	// WrapKey is the 32-byte ChaCha20 shared key, identical on client
	// and server, required when UseWrap is true. Wrong/short keys are
	// caught at proxy startup so the operator gets a clear error.
	WrapKey []byte

	// UseSrtp enables the DTLS+SRTP transport (see pkg/proxy/srtpwrap).
	// When true, the proxy bypasses the existing DTLS+WireGuard path
	// entirely and uses srtpwrap.Client to wrap user traffic as
	// RTP-framed packets encrypted with SRTP, sent through the TURN
	// relay's ChannelData. VK's TURN classifier sees this as legitimate
	// WebRTC media and does not apply the per-allocation shape policy
	// that throttles raw DTLS+WG to ~9 KB/s.
	//
	// Server side must run with the matching -srtp flag (anton48/
	// vk-turn-proxy add-server-srtp-layer branch, deployed on a
	// separate port from the legacy DTLS listener — typically :56004).
	// When UseSrtp is true the client MUST point at the SRTP-mode
	// server port; pointing at a non-SRTP server produces a clean
	// handshake failure.
	//
	// Empirical 2026-05-19/20: sustained 200+ KB/s per conn, 0 % loss,
	// linear scaling across creds — 30-conn production layout delivers
	// ~50 Mbps total (vs ~2 Mbps for the DTLS+WG baseline shape).
	UseSrtp bool

	// UseWrapA enables the "SRTP-WRAP-A" 4th transport mode, wire-compatible
	// with amurcanov's proxy-turn-vk-android server (Android-only client; our
	// iOS users keep asking how to reach it). Stack: UDP/VK-TURN → WRAP-A
	// RTP-obfs (see wrapa.go) → plain DTLS (amurcanov's config) → GETCONF
	// auto-provisioning + WireGuard. Despite the name it is NOT SRTP. The
	// server mints our WireGuard keypair + IP via GETCONF (see getconf.go),
	// so the user enters NO WG keys — only the server address + password.
	// Mutually exclusive with UseSrtp/UseDTLS; selected first in the
	// runConnection dispatch.
	UseWrapA bool
	// WrapAPassword is the shared secret for WRAP-A. Dual-purpose: HKDF input
	// for the obfuscation key (deriveWrapAKey) AND GETCONF authentication.
	// One UI field. Required when UseWrapA is true.
	WrapAPassword string
	// DeviceID is the stable per-install identifier sent in GETCONF. The
	// server keys the minted WireGuard device on it, so it must be constant
	// across all conns of a tunnel (and ideally across launches — the bridge
	// generates+persists one). Empty → NewProxy generates a random UUID for
	// this session.
	DeviceID string

	// UseWrapS enables the "SRTP-WRAP-S" mode — the same DTLS-over-TURN wrap
	// data path as SRTP-WRAP (UseWrap) but the obf codec is chosen by ObfProfile
	// and a Client-ID record is sent first inside DTLS, for interop with
	// samosvalishe/free-turn-proxy. Mutually exclusive with UseWrap; the
	// existing SRTP-WRAP (UseWrap) path is left byte-for-byte unchanged.
	UseWrapS bool
	// ObfProfile selects the SRTP-WRAP-S obf codec: "rtpopus" | "rtpopus2" |
	// "rtpopus3" (see wraps.go). Only consulted when UseWrapS is true.
	ObfProfile string
	// ClientID is the free-turn-proxy Client-ID sent as the first DTLS app
	// record on every SRTP-WRAP-S stream (server allowlist key; read+ignored
	// unless the server runs -clients-file). Only used when UseWrapS.
	ClientID string
}

// Stats holds live tunnel statistics.
type Stats struct {
	TxBytes                int64   `json:"tx_bytes"`
	RxBytes                int64   `json:"rx_bytes"`
	ActiveConns            int32   `json:"active_conns"`
	TotalConns             int32   `json:"total_conns"`
	TurnRTTms              float64 `json:"turn_rtt_ms"`                 // last TURN Allocate RTT
	DTLSHandshakeMs        float64 `json:"dtls_handshake_ms"`           // last DTLS handshake time
	LastHandshakeSec       int64   `json:"last_handshake_sec"`          // seconds since last WG handshake
	Reconnects             int64   `json:"reconnects"`                  // total TURN reconnects
	CredPoolFilled         int32   `json:"cred_pool_filled"`            // slots usable for NEW conns (fresh: cred present, not expiring within 30 min, not pending, not saturated)
	CredPoolWithCreds      int32   `json:"cred_pool_with_creds"`        // slots physically holding a cred — superset of CredPoolFilled. Diverges when a cred crosses the 30-min expiry buffer: drops out of "fresh", but existing conns on it stay alive until VK-side allocation expires
	CredPoolSize           int32   `json:"cred_pool_size"`              // total cred pool capacity
	CredPoolDistinctRelays int32   `json:"cred_pool_distinct_relays"`   // distinct TURN relay addresses held across filled slots (4th "Pool" number)
	CredPoolQuotaRefusals  int64   `json:"cred_pool_quota_refusals"`    // 486s the pool was told of this session, both transports (quotabreaker.go) — the app shows a box once it is non-zero
	CredPoolMintPausedSec  int32   `json:"cred_pool_mint_paused_sec"`   // seconds left of the relay-refusal breaker's mint pause; 0 = minting allowed
	TunnelUptimeSec        int64   `json:"tunnel_uptime_sec"`           // seconds since the proxy instance was created — the iOS UI uses this to render Uptime independent of main-app lifecycle (resists jetsam-respawn of the main app while extension keeps running)
	CaptchaImageURL        string  `json:"captcha_image_url,omitempty"` // non-empty when captcha is pending
	CaptchaSID             string  `json:"captcha_sid,omitempty"`       // captcha_sid for the pending captcha
	AuthError              string  `json:"auth_error,omitempty"`        // non-empty when cookie (VKAuth) auth hit an unrecoverable rejection — the iOS app shows it + stops the tunnel
}

// Proxy manages the DTLS+TURN tunnel to the peer server.
type Proxy struct {
	config Config
	ctx    context.Context // global lifetime (wgTurnOn → wgTurnOff)
	cancel context.CancelFunc

	peer   *net.UDPAddr
	linkID string

	// For packet I/O from the WireGuard side. sendCh carries a sendItem rather
	// than a bare []byte so each packet's enqueue instant travels WITH it —
	// see sendwait.go for why a parallel structure cannot pair them correctly.
	sendCh chan sendItem
	recvCh chan []byte

	// rtpChPeak (build 145, diagnostic): per-interval high-water mark of the
	// plain DTLS+SRTP path's per-conn rtpCh depth, updated at the demux
	// producer (srtpwrap.runDemuxFromPacketConn) and read-and-reset each
	// memstats tick. Tests whether rtpCh (cap 4096 × 2048B = up to 8 MB/conn)
	// fills under RX-burst backpressure and accounts for the phys_footprint
	// climb to the 50 MB jetsam ceiling. Stays 0 on WRAP/legacy paths (they
	// don't use srtpwrap). Must run in plain-SRTP mode to exercise it.
	rtpChPeak atomic.Int64

	// sendChPeak / recvChPeak (build 223, diagnostic): per-interval high-water
	// marks of the two bridge queues, updated at the PRODUCER and read-and-reset
	// each memstats tick — the same shape as rtpChPeak above.
	//
	// 🚨 THEY REPLACE AN INSTANTANEOUS SAMPLE THAT WAS WORSE THAN USELESS. The
	// old HEARTBEAT line printed `sendCh=%d/%d` as len() at the sampling moment.
	// These queues drain in microseconds, so an every-5s sample reads 0 almost
	// always — and a run of zeroes then looks like evidence that the uplink never
	// backs up, when it is really evidence of nothing. Worse, the heartbeat is
	// window-bounded and expired ten seconds BEFORE the first speedtest of every
	// measurement session on 2026-08-08, so the loaded period — the only period
	// anyone wanted to know about — was never observed at all.
	//
	// A peak answers the actual question: did the queue EVER back up in this
	// interval. Zero here means zero, and that is a real negative result.
	sendChPeak atomic.Int64
	recvChPeak atomic.Int64

	// sendChBlockNs / sendChBlockCount (build 224): how long producers actually
	// had to WAIT for room, and how often. This is the number the peak cannot
	// give: notePeak reads len() AFTER the send, and with dozens of consumers
	// draining concurrently a genuinely full queue can be recorded as less than
	// full — so a peak below capacity is NOT proof that nobody blocked.
	//
	// Blocked time has no such ambiguity. Zero means the producer was never once
	// made to wait, which settles "is this queue the limit" outright; a non-zero
	// total says how much of the interval was spent waiting, which is the size
	// of the effect rather than a hint that one exists.
	sendChBlockNs    atomic.Int64
	sendChBlockCount atomic.Int64
	recvChBlockNs    atomic.Int64
	recvChBlockCount atomic.Int64

	// sendWait (build 229): how long each packet WAITED in sendCh, dequeue
	// minus enqueue, as a histogram read-and-reset per memstats tick. The
	// third and last of the sendCh statistics, and the only one that can tell
	// a queue that absorbs a burst harmlessly from one that adds jitter at the
	// scale the inner TCP reacts to. Depth cannot (it is about how bursty the
	// producer is) and blocked time cannot (a queue that never blocks its
	// producer can still hold every packet for 100 ms). Full reasoning, and
	// what it deliberately cannot see, in sendwait.go.
	sendWait sendWaitStats

	// writeWait (build 233): how long the writer then spends INSIDE conn.Write —
	// the mutex in srtpwrap's wrappedConn, the SRTP encrypt, and any blocking
	// when that connection's kernel send buffer is full. Where sendWait ends,
	// this begins; they are consecutive, not overlapping, and must never be
	// added together as if they were one wait.
	//
	// 🚨 What it CANNOT see, and what sockStats below exists for: `Write`
	// returning means the kernel took the bytes, not that they left. A zero here
	// with a deep `sb=` there is a real state — the socket accepts instantly and
	// the packet still waits.
	writeWait sendWaitStats

	// sockStats (build 233): the kernel's own view of the 30 outer TCP sockets.
	// See sockstats.go for why, and for the field whose SDK comment must be read
	// before it is quoted.
	sockStats *sockStats

	// WRAP-A (amurcanov-compatible) transport state. wrapAKey is the derived
	// HKDF obfuscation key (nil unless UseWrapA). The provision is the
	// server-minted WireGuard config from GETCONF, populated exactly once by
	// the first runWrapASession (wrapAProvOnce) and broadcast to waiters
	// (bridge → Swift) by closing wrapAProvCh. wrapAProvCh is nil unless
	// UseWrapA.
	wrapAKey      []byte
	wrapAProvOnce sync.Once
	wrapAProv     atomic.Pointer[WrapAProvision]
	wrapAProvCh   chan struct{}

	wg sync.WaitGroup

	started atomic.Bool

	// Active session context (cancelled on Pause, recreated on Resume)
	sessMu     sync.Mutex
	sessCtx    context.Context
	sessCancel context.CancelFunc

	// Per-conn session bookkeeping for the path-up restart (pathrestart.go):
	// the epoch each running session stamped at its start and the cancel that
	// restarts it, both under connMu so a restart never hits a session that
	// started after its epoch.
	connMu      sync.Mutex
	connEpoch   []int64
	connCancel  []func()
	pathRestart pathRestart

	// ups records when sessions came up, per connection and proxy-wide — what
	// the retry floor asks about (retryfloor.go).
	ups sessionUps

	// dealloc counts what became of the confirmed deallocates over a UDP relay
	// leg (dealloc.go).
	dealloc deallocStats

	// sessionHook, when set, stands in for the transport's session function —
	// the first arm of runConnection's dispatch: the seam the retry-floor herd
	// test drives. Nil in production.
	sessionHook func(ctx context.Context, connIdx int) error

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

	// Snapshot of txBytes at the previous WakeHealthCheck call. Used to
	// detect "user is actively trying to send but no replies are coming
	// back" between consecutive iOS wake() callbacks — a strong signal
	// that the tunnel is broken and rebuild is needed immediately
	// instead of waiting for Condition 2 to re-accumulate ~90s of pion
	// errors after each freeze. See vpn.wifi.4.log on 2026-05-01: user
	// was awake and trying to use the network from 12:20, but tunnel
	// was broken (TURN permissions expired during prior 5m25s freeze)
	// and recovery only completed at 12:26:08 via Condition 2 — a 6+
	// minute outage of the user's network.
	lastWakeTxBytes atomic.Int64

	// Snapshot of txBytes at the previous watchdog tick. Used to gate
	// Condition 1 ("no DTLS RX for 2m+ with active conns → reconnect")
	// on actual user activity: without this gate, a phone sitting idle
	// on the lock screen with WireGuard keepalives flowing but no real
	// traffic looks identical to a broken tunnel. vpn.wifi.5.log on
	// 2026-05-06 reproduced this — 1h+ idle on stable wifi triggered
	// one spurious ForceReconnect at 20:14 because lastRecvTime hadn't
	// updated in 2m14s while the user wasn't sending anything either.
	// Mirrors the txDelta gate in WakeHealthCheck (line 909-920).
	lastWatchdogTxBytes atomic.Int64

	// Guard against multiple concurrent waitCaptchaAndRestart goroutines.
	// Only one should be running at a time; extras just compete on captchaCh.
	captchaWaiterActive atomic.Bool

	// Last time RefreshCaptchaURL was called (= user is looking at captcha WebView).
	// Used to suppress periodic probes while user is actively trying to solve captcha.
	// Probes create new VK sessions that invalidate the current one, causing
	// "Attempt limit reached" errors in the WebView.
	lastRefreshCaptchaTime atomic.Int64 // unix seconds

	// Stats
	txBytes atomic.Int64
	rxBytes atomic.Int64

	// Per-packet counters added 2026-05-27 (build 140) for diagnostic
	// of the "kernel-buffered packet flood on attach" hypothesis. After
	// extension respawn, iOS may dump queued TUN packets (accumulated
	// while extension was dead) into our process. The packet RATE
	// (delta per 10s memstats tick) shows this as a burst that the
	// byte counters obscure when packet sizes are small. Counted at the
	// WG-bind boundary: SendPacket (app→tunnel direction) increments
	// txPackets per packet WG asked us to send. ReceivePacket
	// (tunnel→app) increments rxPackets per packet we delivered to WG
	// for decap. Suspect signature: SendPacket rate >>500/s briefly on
	// fresh-extension attach.
	txPackets   atomic.Int64
	rxPackets   atomic.Int64
	activeConns atomic.Int32
	totalConns  atomic.Int32
	turnRTTns   atomic.Int64 // nanoseconds
	dtlsHSns    atomic.Int64 // nanoseconds
	reconnects  atomic.Int64

	// startedAt is the wall-clock moment NewProxy was called. The Stats
	// getter computes TunnelUptimeSec relative to this so the iOS UI
	// can show a tunnel-side uptime that survives main-app process
	// lifecycle. Without it, the StatsView clock origin had to be
	// stamped in TunnelManager.observeStatus when the app first
	// attached, and got reset every time iOS jetsam'd the main app and
	// re-launched it on next foreground — Uptime would jump back to
	// "0:07" after a 40-min connected session because that was the
	// time since the *app* re-attached, not since the tunnel started.
	// Reporting the real uptime from this side moves the source of
	// truth into the extension, which has the same lifecycle as the
	// tunnel itself.
	startedAt time.Time

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

	// Diagnostic counters for the probe pipeline. Populated by the per-conn
	// probe sender / DTLS-recv branch and read at zombie-kill time so the
	// kill log can attribute the failure: "we sent N pings but got back M
	// pongs since the last successful echo" lets us tell apart "our sender
	// stalled" (delta=0) from "server stopped echoing or echoes were
	// dropped on the return path" (delta>0). firstPingAt/firstPongAt mark
	// the wall-clock moments of the very first sent ping and very first
	// received pong for each conn; both stay at 0 until set, and we use
	// CompareAndSwap so the one-time log fires exactly once per conn.
	// All four are aligned with len(lastPongTimes) and indexed by connIdx.
	lastPingSeq []atomic.Uint64
	lastPongSeq []atomic.Uint64
	firstPingAt []atomic.Int64
	firstPongAt []atomic.Int64

	// Active-probe-on-wake plumbing. WakeHealthCheck() (called from the
	// Swift extension's wake() override via wgWakeHealthCheck) closes
	// wakeCh to broadcast to every per-conn probe goroutine; each one
	// then sends an extra ping out-of-schedule and waits up to 5s for
	// the echo, killing the conn immediately if no echo arrives. This
	// short-circuits the 2-minute timer-based zombie detection during
	// LTE sleep/wake storms (vpn.lte.1.log 2026-05-03 showed cascades
	// where 7 conns went zombie because their last pong predated 7+
	// quick wake events). Throttled per-conn at 30s to avoid pinging
	// 50 conns × N times if the wake events come in rapid succession.
	wakeMu            sync.RWMutex
	wakeCh            chan struct{}
	wakeEpoch         atomic.Uint64
	lastActiveProbeAt []atomic.Int64

	// Per-conn byte counters for diagnostic of throughput asymmetry.
	// Incremented in runTURN's bridge: connTxBytes counts the DTLS-record
	// bytes sent into the TURN ChannelData layer (pre-WRAP), connRxBytes
	// counts what came back. Counters are cumulative across the conn's
	// whole tunnel uptime (NOT reset per session-respawn) so the periodic
	// dump shows how each conn-slot is performing over time. Sized by
	// NumConns; safe to read concurrently with the bridge writers thanks
	// to atomic. The dump goroutine (logConnStatsLoop) runs every 60s
	// and emits one log block listing per-conn delta + cumulative; same
	// dump fires on Stop() so a final snapshot lands before shutdown.
	connTxBytes []atomic.Int64
	connRxBytes []atomic.Int64

	// groupHello is this tunnel's M3 group hello (0xff 'G' 'R' 'P' + a 16-byte
	// session id), sent verbatim on every conn so the server can group this
	// client's connections onto one socket toward WireGuard. nil when the peer
	// is not our server (WRAP-A / WRAP-S) — see groupHelloMagic. Built once in
	// NewProxy and ROTATED on a path-up (pathrestart.go), hence the atomic.
	groupHello atomic.Pointer[[]byte]

	// Per-conn last-activity timestamps (UnixNano) for skip-on-recent-tx
	// wake-probe optimization. Updated alongside connTxBytes/connRxBytes
	// from the data path goroutines (NOT from probe Writes — probes are
	// direct dtlsConn.Write / srtpConn.Write that bypass the byte counter
	// sites). The wake-probe handler reads these and skips probe if the
	// conn had data traffic within a recent window (5s currently),
	// reducing the wake-burst peak from 30 simultaneous probes to N_idle.
	// See open_problem_srtp_silent_extension_restarts.md "Option B" for
	// rationale and the 2026-05-25 16:27:50 jetsam this addresses.
	lastTxAt []atomic.Int64
	lastRxAt []atomic.Int64

	// Per-conn current local IP as observed at TURN allocation time.
	// Stored as host string (no port) so the pathstats logger can compare
	// against the OS default-route IP without parsing. Set by runTURN
	// when "TURN relay allocated" fires; cleared (set to "") when the
	// session ends. The value reflects the bind moment — if iOS later
	// rebinds the underlying socket on a path change (we observed this
	// 2026-05-06 wifi→cellular→wifi: 30 sockets had their reported
	// LocalAddr silently shift), this stored value lags reality, which
	// is the WHOLE POINT: the gap between this and the live os-default
	// is exactly the diagnostic signal we want to see.
	connLocalIPs []atomic.Value // string

	// Bootstrap-ready signaling. Fires exactly once per proxy lifetime, when
	// either (a) the first conn establishes a live DTLS+TURN session (signaled
	// with nil from runConnection), or (b) Start() hits a fatal non-captcha
	// error before any conn comes up. Captcha-pending does NOT signal — the
	// caller waits up to timeout for the user to solve and the first conn to
	// come up after Resume(). Used by bridge's wgWaitBootstrapReady so Swift
	// can defer setTunnelNetworkSettings until VK bootstrap is actually done.
	bootstrapDoneCh   chan error
	bootstrapDoneOnce sync.Once
	// firstSessionUp is set when the first session ever carried traffic
	// (signalBootstrapDone(nil)). Until then a path-up has nothing to
	// restart — see OnPathUp.
	firstSessionUp atomic.Bool
}

// NewProxy creates a new proxy instance.
func NewProxy(cfg Config) *Proxy {
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	if cfg.UseWrap {
		// Catch wrong key length up front so the operator gets a clear
		// error before any TURN allocation happens. Wrong key would
		// otherwise surface much later as a confusing DTLS handshake
		// timeout (server XOR's our wrapped ClientHello with a different
		// key, garbage hits the DTLS state machine, hangs the whole conn).
		if len(cfg.WrapKey) != wrapKeyLen {
			log.Printf("proxy: WARN UseWrap=true but WrapKey is %d bytes (need %d) — disabling WRAP for this session",
				len(cfg.WrapKey), wrapKeyLen)
			cfg.UseWrap = false
		} else {
			log.Printf("proxy: WRAP layer enabled (server must run with matching -wrap and -wrap-key)")
		}
	}
	// WRAP-A (amurcanov-compatible) transport: derive the obfuscation key
	// from the password up front and ensure a stable deviceID. Disable the
	// mode (rather than fail) on bad input so the operator sees a clear log
	// line instead of a confusing DTLS handshake timeout.
	var wrapAKey []byte
	if cfg.UseWrapA {
		if cfg.WrapAPassword == "" {
			log.Printf("proxy: WARN UseWrapA=true but WrapAPassword is empty — disabling WRAP-A")
			cfg.UseWrapA = false
		} else if key, err := deriveWrapAKey(cfg.WrapAPassword); err != nil {
			log.Printf("proxy: WARN WRAP-A key derivation failed: %v — disabling WRAP-A", err)
			cfg.UseWrapA = false
		} else {
			wrapAKey = key
			if cfg.DeviceID == "" {
				cfg.DeviceID = uuid.New().String()
				log.Printf("proxy: WRAP-A generated session deviceID %s (bridge should persist a stable one)", cfg.DeviceID)
			}
			log.Printf("proxy: WRAP-A (amurcanov-compatible) mode enabled — server provisions WireGuard via GETCONF")
		}
	}
	// Fresh global session — clear any leftover pion-degradation counters.
	// (atomic.Int64 zero values are fine for a brand-new struct, but explicit
	//  for clarity in case Proxy is ever pooled in the future.)
	ctx, cancel := context.WithCancel(context.Background())
	sessCtx, sessCancel := context.WithCancel(ctx)
	p := &Proxy{
		linkID:            parseVKLinkID(cfg.VKLink), // fixed here, never in Start
		config:            cfg,
		ctx:               ctx,
		cancel:            cancel,
		sendCh:            make(chan sendItem, 256),
		sockStats:         newSockStats(),
		recvCh:            make(chan []byte, 256),
		sessCtx:           sessCtx,
		sessCancel:        sessCancel,
		captchaCh:         make(chan string, 1),
		bootstrapDoneCh:   make(chan error, 1),
		lastPongTimes:     make([]atomic.Int64, cfg.NumConns),
		lastPingSeq:       make([]atomic.Uint64, cfg.NumConns),
		lastPongSeq:       make([]atomic.Uint64, cfg.NumConns),
		firstPingAt:       make([]atomic.Int64, cfg.NumConns),
		firstPongAt:       make([]atomic.Int64, cfg.NumConns),
		lastActiveProbeAt: make([]atomic.Int64, cfg.NumConns),
		connTxBytes:       make([]atomic.Int64, cfg.NumConns),
		connRxBytes:       make([]atomic.Int64, cfg.NumConns),
		lastTxAt:          make([]atomic.Int64, cfg.NumConns),
		lastRxAt:          make([]atomic.Int64, cfg.NumConns),
		connLocalIPs:      make([]atomic.Value, cfg.NumConns),
		connEpoch:         make([]int64, cfg.NumConns),
		connCancel:        make([]func(), cfg.NumConns),
		wakeCh:            make(chan struct{}),
		startedAt:         time.Now(),
	}
	p.pathRestart.fire = func(olderThan int64) { p.restartSessionsOlderThan(olderThan, "path change") }
	// Wire up WRAP-A state on the constructed proxy (key + provision channel).
	if cfg.UseWrapA {
		p.wrapAKey = wrapAKey
		p.wrapAProvCh = make(chan struct{})
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
	// Cooldown comes from Config; newCredPool falls back to default (2m)
	// if <= 0. Per-entry freshness is now derived from each cred's
	// VK-supplied expiry timestamp (see parseCredExpiry / credExpiryBuffer
	// in creds.go) — no separate TTL setting needed.
	poolSize := poolSizeForNumConns(cfg.NumConns)
	if cookieAuthEnabled.Load() {
		// Cookie (VKAuth) mode: one slot per relay (2 per call link), no 4×
		// reserve — the relays are a finite set, so extra slots would just
		// duplicate a relay and 486. See cookieCredForSlot.
		if n := len(cookieLinks()); n > 0 {
			poolSize = 2 * n
		}
	}
	p.credPool = newCredPool(ctx, poolSize, cfg.CredPoolCooldown, cfg.CredCachePath, p.fetchFreshCreds)
	p.credPool.setColdStartTarget(cfg.NumConns)

	p.initGroupHello(cfg)

	// Seed slot 0 with pre-fetched TURN creds (from main app's pre-bootstrap
	// captcha flow). The first conn's get() returns these without an API
	// call, dodging the .connecting-window captcha deadlock.
	if cfg.SeededTURN != nil {
		// The seed comes from the main app's pre-bootstrap — either a
		// disk-cached cred or a fresh probe. Its address is used VERBATIM: the
		// TurnServer/TurnPort override does NOT apply here. The override only
		// rewrites fresh VK fetches in fetchFreshCreds; a disk-cached seed
		// keeps its stored address (the "setting must not affect cached creds"
		// guarantee), and a fresh probe-seed is already overridden Swift-side
		// before it reaches here.
		turnHost, _, err := net.SplitHostPort(cfg.SeededTURN.Address)
		if err == nil {
			p.credPool.seedSlot(0, cfg.SeededTURN.Address, cfg.SeededTURN)
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
	if err == nil {
		p.firstSessionUp.Store(true)
	}
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

	// p.linkID is fixed in NewProxy (parseVKLinkID) and never written here:
	// RefreshCaptchaURL reads it on Swift's thread with no ordering against
	// this goroutine, so it must be immutable once the Proxy exists.

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

	// Diagnostic heartbeat — fires every 5s for the first 2 minutes after
	// proxy.Start. Logs goroutine count + RSS + per-channel pending depth
	// so that we can see, in the iOS log AFTER an extension-kill event,
	// exactly when the process stopped responding (the last heartbeat
	// timestamp). Without this, multi-second log gaps before iOS kills
	// the extension look identical regardless of whether the process
	// hung 30 seconds ago or 1 second ago.
	//
	// Time-bounded so a long-lived production session doesn't accumulate
	// thousands of heartbeat lines. Investigating build-119 38s-death.
	go p.runDiagnosticHeartbeat(p.ctx, 2*time.Minute, 5*time.Second)

	// Background cred-pool grower: fills empty slots over time without
	// blocking conn startup. Conn 0 still does an inline fetch (needs at
	// least one cred to bootstrap). Conns 1-N use fallback to whichever
	// slots are fresh; the grower backfills pool[1..N-1] slowly so the
	// pool eventually reaches full insurance coverage.
	go p.growCredPool(p.ctx)

	// Per-conn byte-counter dump goroutine. Runs every 60s and emits a
	// log block listing each conn's TX/RX delta + cumulative. Purely
	// diagnostic — used to investigate per-conn throughput asymmetry
	// (e.g. when total speedtest result drops but mechanism unclear).
	// See logConnStatsTick comment for output format.
	go p.logConnStatsLoop(p.ctx)

	// Memory-stats dump goroutine. Runs every 60s and emits one line
	// from runtime.MemStats — Sys (what iOS jetsam looks at), heap
	// usage, goroutine count, GC count. Diagnostic for the Type E
	// silent-extension-kill failure mode (vpn.wifi.2.restart.log on
	// 2026-05-06: extension dropped after 3h 23m of normal operation,
	// no errors, no PathMonitor event — classic memory-pressure
	// jetsam against the NetworkExtension's ~50 MB hard limit).
	// Linear growth in Sys identifies a leak; flat-but-high Sys says
	// the limit is structurally tight at NumConns=50 and we should
	// consider proactive self-restart or a smaller pool.
	go p.logMemStatsLoop(p.ctx)

	// Path-stats dump goroutine. Runs every 60s and emits one line
	// reporting (a) the OS default-route source IP right now, sampled
	// via a fresh dial, and (b) how many of our conns are still bound
	// to that same IP vs lagging on a stale one. Diagnostic for the
	// silent-rebind pattern surfaced 2026-05-06 wifi→cellular→wifi:
	// 30 sockets allocated on 10.101.39.17 had their reported
	// LocalAddr quietly become 192.168.4.21 with NO [PathMonitor]
	// event between the allocation and the failure, masking the fact
	// that the conns were already on a doomed source IP. The level-
	// triggered snapshot complements the existing edge-triggered
	// [PathMonitor] log lines.
	go p.logPathStatsLoop(p.ctx)

	// Paced synthetic uplink — returns immediately unless UplinkSynthMbit is
	// set, in which case it waits for the pool and runs once. Diagnostic only;
	// see synth.go.
	go p.runUplinkSynthLoop(p.ctx)

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

// growCredPool is the native transports' grower: it waits for the bootstrap
// (no point fetching more creds while conn 0 is still establishing the first
// session) and then runs the pool's ONE fill loop — credPool.growLoop in
// credpool.go, the same body csqtt's standalone pool runs — at the production
// pace, with the captcha-pending predicate: while the app is showing a
// captcha the grower adds no VK pressure (another fetch could invalidate the
// captcha session the user is solving).
//
// Lifetime = p.ctx (stops on Proxy.Stop).
func (p *Proxy) growCredPool(ctx context.Context) {
	// Wait until the first conn has a live DTLS+TURN session. There's no
	// value in populating more slots before the tunnel actually works. The
	// text's 2m is defaultGrowPace.bootstrap (TestCredPoolGrowPaceIsPinned).
	if err := p.WaitBootstrap(defaultGrowPace.bootstrap); err != nil {
		log.Printf("credpool-grow: bootstrap did not succeed within 2m (%v), grower exiting", err)
		return
	}
	p.credPool.growLoop(ctx, defaultGrowPace, p.captchaPending)
}

// captchaPending reports whether a captcha is waiting for the user — the
// grower's hold predicate.
func (p *Proxy) captchaPending() bool {
	if v := p.captchaImageURL.Load(); v != nil {
		if s, _ := v.(string); s != "" {
			return true
		}
	}
	return false
}

// The connection start, at package scope so anything that has to WAIT for the
// pool computes the wait from the same numbers that create it.
//
// 🚨 These were local constants inside startConnections until 2026-08-10, and
// the synthetic uplink duly picked its 90-second timeout by eyeballing the
// code — while the 30-conn ramp of that day took 106.8 s BY CONSTRUCTION. It
// gave up 17 seconds short of a full pool and cost a device run. Anything
// with a deadline against the start must call expectedRampTime; never guess
// it.
//
// connStartStagger is the whole ramp: conn 0 is the bootstrap, every other
// connection launches at a random point within this window after it — the
// shape the path-change restart has used since build 360 (thirty re-dials
// within a second; 30/30 in 1.3–2.6 s, no 486 across four switches, §57).
//
// 🚫 Until 2026-09-07 the start was bi-modal — ten at 200 ms, then one every
// 5 s, 1m46.8s to thirty — from commit d2a1a6a (2026-04-28), which read an
// April log (conns 10–15 hitting 486 on ONE credential) as a token bucket
// refilling one allocation per 20–30 s and paced the rest to that refill.
// The measurement of 2026-06-28 (tools/turn_quota_test) replaced the model:
// VK caps SIMULTANEOUS allocations at ~10 per (identity, relay), nothing
// refills, and the pool hands every ten connections their own identity
// (connIdx/10 → slot). The 5 s then paced nothing: the grower and Phase 2 mint slots
// 1 and 2 within seconds of the bootstrap regardless, so the ramp only delayed
// the USE of credentials that already existed (build 368 on a warm cache:
// conn 29 on cred 5, on disk from the start, established at +102 s). Mint
// pacing — the cold-start cap, the grower's cadence, the captcha — stays
// where it lives, in the pool; a connection that finds no slot parks there.
const connStartStagger = time.Second

// connStartDelay is when connection i launches, measured from the bootstrap:
// conn 0 at once, every other one at a random point within connStartStagger.
func connStartDelay(connIdx int) time.Duration {
	if connIdx <= 0 {
		return 0
	}
	return restartStagger()
}

// restartStagger is the sub-second spread that keeps thirty dials from
// landing in one instant — the start and the path-change re-dial share it.
func restartStagger() time.Duration {
	return time.Duration(mathrand.Int63n(int64(connStartStagger)))
}

// expectedRampTime is when the LAST connection of an n-connection pool is
// launched at the latest, measured from startConnections. Establishment takes
// longer still, so callers add their own slack. n ≥ 2 → connStartStagger.
func expectedRampTime(n int) time.Duration {
	if n <= 1 {
		return 0
	}
	return connStartStagger
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
	const maxBootstrapAttempts = 7
	// Linear-progressive backoff for the non-saturated retry path. The
	// backoff before retrying into attempt N (N=2..7) is (N-1) * 10s:
	// 10, 20, 30, 40, 50, 60 seconds. Cumulative timeline of attempt
	// starts (5s dial timeout per attempt + the backoff before next):
	//   attempt 1: t=0   (initial)
	//   attempt 2: t=15  (5s dial + 10s wait)
	//   attempt 3: t=40  (15 + 5 dial + 20 wait)
	//   attempt 4: t=75
	//   attempt 5: t=120
	//   attempt 6: t=175
	//   attempt 7: t=240 (4 minutes)
	// Total bootstrap budget when all 7 fail: ~245s = ~4m5s.
	//
	// Rationale: pre-build-137 was maxBootstrapAttempts=4 with fixed
	// 10s backoff = ~60s total. When network outages last >60s (e.g.
	// 2026-05-26 02:21-02:35 ~14 min ISP/route flap on user's WiFi
	// — see progress_summary_may_25_2026 evening notes / open issue),
	// the 60s budget exhausts and we wait for watchdog Condition 3
	// to fire after 5 min of zero active conns, giving 5-6 min total
	// dead-window per cycle. The 4-min budget here covers most
	// transient network outages (most ISPs recover within 1-2 min),
	// and if it still fails the watchdog cycle adds another ~1 min
	// gap, NOT 5 min — bootstrap is doing the waiting work, not
	// idling. For recoveries that happen mid-bootstrap-budget, the
	// next attempt catches the recovery within at most 60s instead
	// of waiting for the next 5-min watchdog tick.
	bootstrapBackoff := func(failedAttempt int) time.Duration {
		return time.Duration(failedAttempt) * 10 * time.Second
	}
	// Safety window beyond longest cooldown — guards against slot timer
	// firing slightly after our calculated deadline (re-arms, scheduler
	// jitter, etc). Empirically a few seconds is plenty.
	const allSaturatedWaitSafety = 5 * time.Second
	err := spawnConn0()
	for attempt := 1; err != nil && attempt < maxBootstrapAttempts; attempt++ {
		var captchaErr *CaptchaRequiredError
		if errors.As(err, &captchaErr) {
			break
		}

		// Adaptive backoff: when NO slots are usable (either all in 486
		// cooldown OR partly saturated + empty slots that grower can't
		// fill), fixed-duration retries are guaranteed to keep failing
		// — the only thing that can plausibly help is a saturation
		// cooldown expiring (broadcasts on slotAvailableCh) or grower
		// successfully seeding an empty slot (also broadcasts). Wait
		// on the channel instead, with a deadline equal to the longest
		// remaining cooldown (+safety).
		//
		// Why "available == 0" not "saturated == total": when 7 of 12
		// slots are saturated and the other 5 are empty with grower
		// blocked by PoW captcha cascade, available = 0 but saturated
		// (7) != total (12). The old strict condition picked the
		// fixed-backoff path, exhausted 4×10s budget in 40s, and
		// returned — then the watchdog needed 5+ min to retry.
		// Empirically observed in vpn.wifi-lte-wifi.2.log 2026-05-15
		// 17:17:15: bootstrap exhausted at 17:17:45 even though slots
		// [0,1,3,4,5] would expire at 17:18:54 (a 1m9s wait would have
		// recovered); instead recovery came at 17:23:15 via second
		// watchdog tick — wasted 4m20s. Pre-build-90 also hit this in
		// vpn.wifi-lte-wifi.3.log 2026-05-08 21:21-21:33: 11m13s
		// outage, ~4 min of which was waiting for the next watchdog
		// tick after slots 0/2/4 had already cooled down at 21:29:00
		// but no goroutine was listening for the broadcast.
		saturated, total, longest := p.credPool.saturationSnapshot()
		available, _, _ := p.credPool.snapshotSize()
		// canWaitForCooldown requires longest > 0 — without an active
		// cooldown there's no guaranteed wake-up source (grower-fill
		// broadcasts could fire but that's not bounded). Fall back to
		// the progressive-backoff default in the no-cooldown case.
		canWaitForCooldown := total > 0 && available == 0 && longest > 0

		if canWaitForCooldown {
			waitFor := longest + allSaturatedWaitSafety
			log.Printf("proxy: bootstrap attempt %d/%d failed (%v), %d/%d slots saturated, 0 available — waiting up to %s for slot-available signal",
				attempt, maxBootstrapAttempts, err, saturated, total, waitFor.Round(time.Second))
			slotCh := p.wakeChannelFor(err)
			select {
			case <-slotCh:
				log.Printf("proxy: bootstrap attempt %d/%d woken by slot-available signal, retrying immediately",
					attempt, maxBootstrapAttempts)
			case <-time.After(waitFor):
				log.Printf("proxy: bootstrap attempt %d/%d slot-wait timed out after %s, retrying",
					attempt, maxBootstrapAttempts, waitFor.Round(time.Second))
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		} else {
			backoff := bootstrapBackoff(attempt)
			log.Printf("proxy: bootstrap attempt %d/%d failed (%v), retrying conn 0 after %s",
				attempt, maxBootstrapAttempts, err, backoff)
			select {
			case <-time.After(backoff):
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		}

		err = spawnConn0()
		if err == nil {
			log.Printf("proxy: bootstrap attempt %d/%d succeeded", attempt+1, maxBootstrapAttempts)
		}
	}

	if err != nil {
		// Diagnostic: when bootstrap exhausts because pool has zero
		// available slots (either all saturated, or partly saturated +
		// empty slots that grower can't fill due to PoW captcha cascade),
		// log a single clear line so post-mortem readers don't have to
		// correlate N "[conn X] TURN allocate quota error" lines
		// manually. The watchdog will re-trigger after 5 min — see
		// vpn.wifi-lte-wifi.1.log 2026-05-08 (all-saturated case) and
		// vpn.wifi-lte-wifi.2.log 2026-05-15 17:17 (partial-saturated +
		// PoW-blocked case) for canonical examples.
		saturated, total, longest := p.credPool.saturationSnapshot()
		available, _, _ := p.credPool.snapshotSize()
		if total > 0 && available == 0 {
			log.Printf("proxy: bootstrap exhausted — %d/%d slots saturated (longest %s remaining), 0 available (waiting for cooldown expiry or grower fill; watchdog will retry)",
				saturated, total, longest.Round(time.Second))
		}

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

	// Every other connection launches within connStartStagger of the
	// bootstrap — the path-change restart's shape (see the constant for the
	// bi-modal ramp this replaced and why it paced nothing). Credentials come
	// from the pool at each conn's own pace: ten per identity, the cold-start
	// cap and the grower for the mints, a park on the slot-available signal
	// when none is ready yet.
	for i := 1; i < p.config.NumConns; i++ {
		p.wg.Add(1)
		connIdx := i
		go func() {
			defer p.wg.Done()
			delay := connStartDelay(connIdx)
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
			_, probeCreds, probeSlot, probeErr := p.resolveTURNAddr(-1, false)
			// Probe is non-consuming; release whatever slot got acquired so
			// it doesn't leak quota count for a cred we never used.
			if probeErr == nil {
				p.credPool.release(probeSlot, probeCreds)
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
// Network Extension. Its job is to clear stale state that accumulated
// during the iOS freeze: pion's permission-refresh and channel-bind
// transactions issued just before freeze receive late responses on wake
// (so pion treats them as failed), and TURN-server permissions that
// expired during multi-minute freezes get 400 Bad Request on the first
// post-wake refresh. Both inflate pionTransientErrors with values that
// don't reflect ongoing tunnel breakage.
//
// We don't blindly trigger ForceReconnect on accumulated pion errors —
// a single 10-minute freeze produced 150+ pion errors in the same
// wake-millisecond (vpn.wifi.1.log on 2026-05-01), blasting past any
// fixed threshold and cascading into the 486 quota lockout.
//
// Instead we use a TX-vs-RX cross-check: between consecutive wake()
// callbacks, did the user's app try to send packets, and did anything
// come back? A non-trivial TX delta with a stale lastRecvTime is an
// unambiguous signal of "user is using the network but the tunnel is
// dead" — exactly the broken state where users wait for connectivity
// to come back. ForceReconnect on that signal cuts recovery from the
// 90s+ that Condition 2 needs (and may keep resetting on intermittent
// freezes between user-triggered wakes) down to ~5-10s. During
// overnight sleep or other genuinely idle periods, TX delta stays at
// 0 and we don't spuriously reconnect.
//
// vpn.wifi.4.log on 2026-05-01 showed the failure mode this targets:
// 5m25s freeze 12:15:53→12:21:19 expired TURN permissions on 41 conns;
// user awake from 12:20 actively trying to use the network, but
// recovery only completed at 12:26:08 via Condition 2 — a 6+ minute
// outage observable to the user as "internet just doesn't work."
func (p *Proxy) WakeHealthCheck() {
	// Don't interfere with an in-progress captcha flow.
	if v := p.captchaImageURL.Load(); v != nil {
		if url, _ := v.(string); url != "" {
			return
		}
	}
	pionErrs := p.pionTransientErrors.Load()
	if pionErrs > 0 {
		log.Printf("proxy: wake check — clearing %d accumulated pion errors (likely freeze artifacts)", pionErrs)
		p.pionTransientErrors.Store(0)
		p.firstPionErrorTime.Store(0)
	}

	// TX-vs-RX cross-check: if the app sent a meaningful amount of data
	// since the previous wake but the tunnel hasn't received anything
	// recently, the tunnel is broken and the user is currently waiting.
	// 4 KB threshold filters out bookkeeping noise (a single TLS handshake
	// is ~5 KB, a DNS query+response is ~200 B). 90s RX-staleness is past
	// any normal probe-pong cycle (probeInterval 30s × 2-3 cycles).
	txNow := p.txBytes.Load()
	txPrev := p.lastWakeTxBytes.Swap(txNow)
	txDelta := txNow - txPrev
	lastRecv := p.lastRecvTime.Load()
	if txDelta > 4096 && lastRecv > 0 {
		rxStale := time.Since(time.Unix(lastRecv, 0))
		if rxStale > 90*time.Second {
			log.Printf("proxy: wake check — %d bytes TX since last wake but no RX for %s, forcing reconnect",
				txDelta, rxStale.Round(time.Second))
			p.ForceReconnect()
		}
	}

	// Wake every per-conn probe goroutine. Each one will (subject to a
	// 30s throttle) send an out-of-schedule ping and either confirm the
	// data plane is healthy within 5s or kill the conn — much faster
	// than waiting for the timer-based zombie detector (120s).
	p.broadcastWake()
}

// broadcastWake closes the current wakeCh and replaces it with a fresh
// one. Per-conn probe goroutines select on wakeChannel(); closing it
// fans the wake signal out to all of them in one operation. The
// close-and-replace pattern (same one credPool uses for slot wakeups)
// wakes every goroutine PARKED in its select. One that is elsewhere at
// that instant — in its tick branch, which at a thaw is every one of them —
// re-reads the channel after the swap and would never see this wake: that
// is what wakeEpoch is for (wakeWatch, wakeprobe.go).
func (p *Proxy) broadcastWake() {
	p.wakeMu.Lock()
	p.wakeEpoch.Add(1) // FIRST, under the lock: whoever reads the new channel reads the new epoch too — wakeprobe.go
	close(p.wakeCh)
	p.wakeCh = make(chan struct{})
	p.wakeMu.Unlock()
}

// wakeChannel returns the current wake-broadcast channel. Probe
// goroutines must call this once per select iteration to pick up the
// channel that's live at that instant; broadcastWake replaces the
// channel atomically with the close, so a stale captured reference
// won't fire a second time.
func (p *Proxy) wakeChannel() <-chan struct{} {
	p.wakeMu.RLock()
	defer p.wakeMu.RUnlock()
	return p.wakeCh
}

// runWatchdog monitors tunnel health and forces reconnection when dead.
// iOS freezes Network Extension processes without calling sleep()/wake().
// After unfreeze, all TURN allocations are expired but goroutines sit on
// dead sockets. The watchdog detects this by tracking the last received packet.
//
// Three conditions trigger a full reconnect:
//  1. No packets for 2 min with active connections → dead tunnel
//  2. Pion permission/binding refresh failures persist past a threshold →
//     silent partial degradation (some clients still alive, but server-side
//     permissions are gone for the others; UI shows 10/10 with 0 reconnects
//     while throughput collapses to 1/N)
//  3. Zero active connections for 5+ min → bootstrap dead-end (cred fetch
//     can't get past captcha and the conn pool never establishes a single
//     working session)
//
// Removed condition (vpn.wifi.5.log on 2026-04-30): "active < expected/2
// for 5 min → reconnect". Designed for the post-sleep/wake quota cascade,
// where most conns were stuck dormant. Now obsolete:
//   - Stuck conns get killed by the zombie probe in 2 min, not 5+
//   - markSaturated handles 486-cascade with a 3m cooldown that wakes
//     parked conns the moment it expires (broadcastSlotAvailable hook)
//   - Captcha-triggered slow ramp-up commonly leaves us at "10/30 active
//     for 5+ min" while VK rate-limits PoW for our IP. Forcing reconnect
//     in that state killed 10 working conns and didn't help unstick VK.
//
// runDiagnosticHeartbeat fires a single-line log every `interval` for up
// to `window` total duration. Purpose: confirm the extension process is
// still alive at known timestamps when otherwise quiet (post-cold-start
// SRTP MVP runs with no per-packet logging). If the heartbeats stop at
// T+33s while NEVPNStatus → 1 fires at T+38s, we know the Go runtime
// hung at T+33s — vs if the heartbeat continues up to T+37s, the Go
// runtime was fine and iOS killed it externally.
//
// Logs RSS + goroutine count so we also see the shape of the process before
// the death.
//
// ⚠️ IT NO LONGER PRINTS THE QUEUE DEPTHS, deliberately. This heartbeat is
// window-bounded — it is a cold-start liveness trace, and on 2026-08-08 it
// expired ten seconds before the first speedtest of every measurement session,
// so its `sendCh=0/256` never once described a loaded period. Worse, len() at
// the sampling moment reads 0 on a queue that drains in microseconds even when
// it IS backing up. Both problems are fixed in the memstats line, which runs
// for the whole session and reports per-interval PEAKS: `sendch-peak` /
// `recvch-peak`. Do not add an instantaneous depth back here — two readers of
// one read-and-reset peak would steal it from each other.
func (p *Proxy) runDiagnosticHeartbeat(ctx context.Context, window, interval time.Duration) {
	deadline := time.Now().Add(window)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().After(deadline) {
				log.Printf("proxy: heartbeat window expired — stopping diagnostic")
				return
			}
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			rss := "n/a"
			if TaskVMInfoFn != nil {
				if vm := TaskVMInfoFn(); vm.PhysFootprint > 0 {
					rss = fmt.Sprintf("%.1fMB", float64(vm.PhysFootprint)/1024/1024)
				}
			}
			log.Printf("proxy: HEARTBEAT t+%s rss=%s sys=%.1fMB goroutines=%d active-conns=%d tx=%d rx=%d",
				time.Since(p.startedAt).Round(time.Second),
				rss,
				float64(ms.Sys)/1024/1024,
				runtime.NumGoroutine(),
				p.activeConns.Load(),
				p.txBytes.Load(), p.rxBytes.Load())
		}
	}
}

func (p *Proxy) runWatchdog() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var zeroConnSince time.Time // when we first noticed zero connections
	// Tick-gap detector: if the gap between two ticks far exceeds the 30s
	// interval, our goroutine was suspended (iOS Network Extension freeze).
	// During that time we couldn't observe packet receipt, so lastRecvTime
	// is stale through no fault of the tunnel.
	//
	// Without this guard, a 6+ minute iOS freeze (common during overnight
	// sleep) trips Condition 1 on wake even though all 30 conns are alive
	// and well — see vpn.lte-wifi.0.log on 2026-04-30: 28 false-positive
	// ForceReconnects between 01:29 and 04:15, each cascading through 486
	// quota lockouts on all 4 cred slots for 10 minutes. Same pattern as
	// the zombie-probe false positive (commit at proxy.go:1385) — timer
	// goroutine pauses during freeze, and judging stale state on wake is
	// always wrong because we ourselves were not running.
	//
	// Initialize lastTickAt to goroutine-creation time, NOT zero, so the
	// first tick after a freeze that began before any tick-gap reference
	// was established still detects the freeze. (Less critical for the
	// watchdog since it starts once at proxy launch, but keeps the
	// pattern consistent with the per-conn probe-goroutine fix.)
	lastTickAt := time.Now()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			gap := now.Sub(lastTickAt)
			if gap > 90*time.Second {
				log.Printf("proxy: watchdog tick gap %s (freeze detected), resetting lastRecvTime",
					gap.Round(time.Second))
				p.lastRecvTime.Store(now.Unix())
				// Pion errors that hit the counter during freeze are
				// almost always freeze artifacts: refresh transactions
				// issued pre-freeze get late responses post-wake (no
				// matching transaction → counted), and TURN permissions
				// that expired during the freeze return 400 Bad Request
				// on the first post-wake refresh attempt. Reset both
				// counters so Condition 2 only fires on errors that
				// persist beyond 90s after this freeze ended. Defense
				// in depth — WakeHealthCheck does the same on the
				// Swift wake() callback path.
				if cleared := p.pionTransientErrors.Swap(0); cleared > 0 {
					log.Printf("proxy: watchdog cleared %d accumulated pion errors", cleared)
				}
				p.firstPionErrorTime.Store(0)
				lastTickAt = now
				continue
			}
			lastTickAt = now

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

			// Condition 1: User is sending but the tunnel isn't returning
			// anything → dead tunnel. The TX-delta gate is critical: without
			// it, a genuinely idle phone (lock-screen, no app traffic, just
			// WireGuard keepalives at ~2 B/s) trips this every ~2 minutes
			// because lastRecvTime — which only updates on DTLS-decrypted
			// payload arrival, NOT on TURN refreshes — naturally goes stale
			// when there's nothing to receive. Reproduced in vpn.wifi.5.log
			// 2026-05-06: 1h+ stable wifi, no movement, one spurious
			// ForceReconnect at 20:14 after 2 minutes of idle.
			//
			// 4 KB threshold and 2-minute RX-stale window match the equivalent
			// gate in WakeHealthCheck (line 905-920). Below the threshold the
			// user isn't meaningfully using the tunnel and a forced reconnect
			// only buys churn (incl. fresh 486 cascade risk) without any
			// observable improvement to user-perceived connectivity.
			txNow := p.txBytes.Load()
			txDelta := txNow - p.lastWatchdogTxBytes.Swap(txNow)
			if txDelta > 4096 && lastRecv > 0 && active > 0 {
				elapsed := time.Since(time.Unix(lastRecv, 0))
				if elapsed > 2*time.Minute {
					log.Printf("proxy: watchdog — %d bytes TX in last tick but no DTLS RX for %s with %d active conns, forcing reconnect",
						txDelta, elapsed.Round(time.Second), active)
					p.ForceReconnect()
					continue
				}
			}

			// Condition 2 removed in build 66 (2026-05-09).
			//
			// Was: "5+ pion permission/binding errors AND first error
			// >90s ago → ForceReconnect", originally tuned to catch slow
			// silent degradation from vpn11.log where ~1 real VK rejection
			// per 2-min refresh cycle accumulated over many cycles.
			//
			// Removed because the counter was monotonic with no natural
			// decay: a single burst of post-wake errors (60+ in seconds
			// from late refresh responses + permission re-establishment)
			// would meet the threshold, and 90 seconds later — well after
			// new conns had recovered and started carrying traffic — the
			// watchdog would fire and kill the just-restored conns.
			//
			// Empirically across 5 observed incidents (vpn.wifi.0.log
			// 2026-05-09 02:40 / 03:53 / 04:13 / 07:04 + vpn.wifi.7.log
			// 2026-05-08): all 5 were false positives killing just-
			// recovered conns after iOS-wake bursts. Zero true positives.
			//
			// pionTransientErrors counter is kept incrementing (line ~3169)
			// for future diagnosis but no longer drives any action. If
			// silent-degradation patterns resurface, reintroduce with
			// per-conn error tagging that expires on conn death, OR
			// sliding window with natural decay — NOT a monotonic counter.

			// Condition 3: Zero active connections for too long.
			// Conditions 1 and 2 both require active>0, so a hard
			// bootstrap dead-end (e.g. all retry attempts hit cred-486
			// → "first connection failed" → no more retries) leaves
			// the watchdog mute and the tunnel stays down indefinitely.
			// Observed in vpn.lte.0.log on 2026-04-29 at 09:05:52 —
			// log just trails into background captcha activity with
			// 0 active conns and no recovery.
			//
			// 5-minute threshold is long enough that the initial
			// startup phase (typically 5-30s but can stretch to several
			// minutes if the cred pool needs to fetch through captcha)
			// finishes without us spuriously retrying it. After that,
			// firing every 5 minutes gives saturated slots time to
			// recover (3-minute markSaturated cooldown plus parked-conn
			// wake-on-expiry, see broadcastSlotAvailable) between
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

// notePeak raises a high-water mark to depth if it is higher. Called from the
// producer right after a successful enqueue, so the value reflects the queue as
// the writer actually left it. Racy between concurrent producers by design —
// this is a diagnostic, and losing a sample to a lost CAS costs nothing while a
// lock on the packet path would cost real throughput.
func notePeak(mark *atomic.Int64, depth int) {
	d := int64(depth)
	for {
		cur := mark.Load()
		if d <= cur || mark.CompareAndSwap(cur, d) {
			return
		}
	}
}

// SendPacket sends a WireGuard packet through the tunnel.
func (p *Proxy) SendPacket(data []byte) error {
	// 🚨 THE COPY STAYS, and pooling is exactly why it must. Both producers
	// REUSE their argument: synth.go re-sends one mutated buffer per burst and
	// turnbind/bind.go passes wireguard-go's staged buffers, reclaimed the
	// moment Send returns. Aliasing `data` would put one backing array behind
	// many queued items and many writers — the only way to get real corruption
	// out of this design.
	buf := sendPktPoolGet(len(data))
	copy(buf, data)
	// The enqueue instant rides with the packet so a writer can price the wait
	// it actually served — sendwait.go. One clock read per packet, ~25 ns
	// against the make+copy already above it; the dequeue side adds none,
	// reusing the time.Now() it needs for the write deadline anyway.
	//
	// ⚠️ The stamp is taken BEFORE the send, which is the closest a producer can
	// get: entering the channel and returning from the send are the same event,
	// so nothing later can observe the true instant. On the fast path below the
	// gap is a few nanoseconds. On the SLOW path the packet also carries its own
	// blocked time, so its residence is over-stated by exactly that — and the
	// over-statement is BOUNDED, per interval, by the `sendch-block` total
	// printed beside it on the same memstats line. When that reads `0s/0`, every
	// residence in the interval is exact.
	item := sendItem{buf: buf, at: time.Now().UnixNano()}
	// Try without blocking first, so the slow path below runs ONLY when there
	// was genuinely no room. That is what makes the blocked-time counter exact:
	// it measures waiting, not the cost of measuring.
	select {
	case p.sendCh <- item:
		notePeak(&p.sendChPeak, len(p.sendCh))
		p.txBytes.Add(int64(len(data)))
		p.txPackets.Add(1)
		return nil
	default:
	}
	start := time.Now()
	select {
	case p.sendCh <- item:
		p.sendChBlockNs.Add(int64(time.Since(start)))
		p.sendChBlockCount.Add(1)
		notePeak(&p.sendChPeak, len(p.sendCh))
		p.txBytes.Add(int64(len(data)))
		p.txPackets.Add(1)
		return nil
	case <-p.ctx.Done():
		// Ownership: until the send succeeds the buffer is still ours, and this
		// is the ONLY exit that never reaches the channel. Every other exit is
		// a successful enqueue, after which sendCh owns it and writePacket
		// returns it — see the ownership note on sendPktPool.
		sendPktPoolPut(buf)
		return p.ctx.Err()
	}
}

// enqueueRecv hands a received packet to ReceivePacket, measuring how long the
// producer had to wait for room. Returns false if ctx died first — the caller
// still owns pkt and must return it to the pool.
func (p *Proxy) enqueueRecv(ctx context.Context, pkt []byte) bool {
	select {
	case p.recvCh <- pkt:
		notePeak(&p.recvChPeak, len(p.recvCh))
		return true
	default:
	}
	start := time.Now()
	select {
	case p.recvCh <- pkt:
		p.recvChBlockNs.Add(int64(time.Since(start)))
		p.recvChBlockCount.Add(1)
		notePeak(&p.recvChPeak, len(p.recvCh))
		return true
	case <-ctx.Done():
		return false
	}
}

// ReceivePacket receives a packet from the tunnel.
// Blocks until a packet arrives or context is cancelled.
func (p *Proxy) ReceivePacket(buf []byte) (int, error) {
	return p.ReceivePacketUntil(nil, buf)
}

// ReceivePacketUntil is ReceivePacket that also returns when `done` is
// closed — with net.ErrClosed, the conn.Bind word for "this bind is done".
// turnbind's Close closes its bind's channel, so a receiver parked here wakes
// WITHOUT a proxy stop: the device's Down (darwin's EventDown), a UAPI
// listen_port through BindUpdate, or a bind closed beside a live proxy (the
// bridge's two-attaches race) no longer park wireguard-go's net.stopping.Wait
// until the proxy stops. The proxy's own stop still returns ctx.Err(), which
// turnbind maps to the same net.ErrClosed. A nil `done` never fires.
//
// 🚨 A CLOSED BIND TAKES PRECEDENCE OVER A QUEUED PACKET. The select below
// picks at random among its ready cases, so with `done` closed AND a packet
// queued a call could still return data: in the user's reproduction on
// build 386, 40 of 100 calls made AFTER Close returned a packet, and after a
// re-Open the OLD ReceiveFunc took 54 of 100 — stealing from the new
// receiver, whose routine then never sees those packets. The contract says
// net.ErrClosed after Close, so `done` is checked first, without blocking.
// (A call already inside the select when Close lands may still complete with
// a packet — the same window every socket read has; calls that START after
// Close never do.) The proxy's own stop keeps its old behaviour: a few
// packets buffered before the stop may still be delivered before ctx.Err()
// — harmless, the device is closing.
func (p *Proxy) ReceivePacketUntil(done <-chan struct{}, buf []byte) (int, error) {
	select {
	case <-done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case pkt := <-p.recvCh:
		// Downlink disorder is measured HERE and not at the producer side of
		// recvCh. 🚨 That is not a detail: enqueueRecv is entered by up to 30
		// goroutines that then race independently for the channel, so the order
		// observed there is the order they ARRIVED, not the order they won —
		// measured at ~10x less disorder than the queue actually delivers, and
		// always in the direction that would have produced the false reading
		// "the downlink arrives near-ordered". This point is single-threaded
		// (one conn.ReceiveFunc ⇒ one RoutineReceiveIncoming) and is by
		// construction the order wireguard-go gets. → rxreorder.go
		downlinkReorder.observeRx(pkt)
		n := copy(buf, pkt)
		// pkt was allocated via recvPktPoolGet by the producer recv
		// goroutine — return to pool now that contents are copied out.
		// Saves the per-packet allocation that previously hit GC.
		// Build 133.
		recvPktPoolPut(pkt)
		p.rxBytes.Add(int64(n))
		p.rxPackets.Add(1)
		return n, nil
	case <-p.ctx.Done():
		return 0, p.ctx.Err()
	case <-done:
		return 0, net.ErrClosed
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
	poolFresh, poolWithCreds, poolSize := p.credPool.snapshotSize()
	distinctRelays := p.credPool.distinctRelays()
	quotaRefusals, mintPaused := p.credPool.quotaSnapshot()
	return Stats{
		TxBytes:                p.txBytes.Load(),
		RxBytes:                p.rxBytes.Load(),
		ActiveConns:            p.activeConns.Load(),
		TotalConns:             p.totalConns.Load(),
		TurnRTTms:              float64(p.turnRTTns.Load()) / 1e6,
		DTLSHandshakeMs:        float64(p.dtlsHSns.Load()) / 1e6,
		Reconnects:             p.reconnects.Load(),
		CredPoolFilled:         int32(poolFresh),
		CredPoolWithCreds:      int32(poolWithCreds),
		CredPoolSize:           int32(poolSize),
		CredPoolDistinctRelays: int32(distinctRelays),
		CredPoolQuotaRefusals:  quotaRefusals,
		CredPoolMintPausedSec:  int32((mintPaused + time.Second - 1) / time.Second),
		TunnelUptimeSec:        int64(time.Since(p.startedAt).Seconds()),
		CaptchaImageURL:        captchaURL,
		CaptchaSID:             captchaSID,
		AuthError:              CookieAuthFatalError(),
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
	// Phase 10 session-unified identity: share the same TLS profile + UA
	// + cookie jar as creds.go bootstrap and captcha_pow.go solver. See
	// captcha_pow.go GetSessionClient docstring for rationale.
	ua := GetSessionUserAgent()
	name := generateName()

	client := GetSessionClient() // Phase 10: singleton (no Close needed)

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
	step2URL := fmt.Sprintf("https://%s/method/calls.getAnonymousToken?v=5.275&client_id=%s", vkAPIHost(), vc.ClientID)
	step2Data := fmt.Sprintf("vk_join_link="+vkCallJoinBase+"%s&name=%s&access_token=%s",
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
// Phase 10: takes bogdanfinn tls_client.HttpClient (was *http.Client) so it
// uses the shared session client — Safari iOS 26 Phase 9 TLS + cookie jar
// + captured UA — matching all other VK API requests in this process.
func doSimplePost(client tls_client.HttpClient, data, url, ua string) (map[string]interface{}, error) {
	req, err := fhttp.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	// Same Safari header set as creds.go doRequest and captcha_pow.go vkReq.
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://id.vk.ru")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Priority", "u=3, i")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
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

// Stop tears down all connections, blocking until every goroutine
// observes ctx cancellation and returns. Suitable for tests and clean
// shutdown paths where unbounded wait is OK. Production iOS shutdown
// should use StopWithTimeout — iOS force-kills extensions whose
// stopTunnel doesn't return within ~26s, losing log buffers in the
// process; bounding the wait avoids that path.
func (p *Proxy) Stop() {
	p.cancel()
	p.wg.Wait()
}

// Stopped reports whether Stop or StopWithTimeout has run: the root context
// is cancelled and nothing will be received through this proxy again. Read by
// turnbind's tests to prove that a receiver woke on the bind's Close and not
// on a stop.
func (p *Proxy) Stopped() bool {
	return p.ctx.Err() != nil
}

// StopWithTimeout cancels and waits for goroutines, but gives up after
// the given duration if some goroutine refuses to exit promptly. Used
// by wgTurnOff so a slow goroutine (one stuck in pion/turn deallocation,
// blocking syscall.Read, etc.) doesn't keep the extension process busy
// past iOS' tolerance window. After the deadline we return regardless;
// the leftover goroutines die when the Go runtime terminates moments
// later as iOS reaps the extension process.
func (p *Proxy) StopWithTimeout(timeout time.Duration) {
	p.cancel()
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// clean exit — every goroutine returned within budget
	case <-time.After(timeout):
		log.Printf("proxy: StopWithTimeout — %s elapsed, %d goroutines still alive (returning anyway, runtime exit will reap them)",
			timeout.Round(time.Millisecond), runtime.NumGoroutine())
	}
}

// runConnection runs a single connection slot with reconnection.
// Reconnects on failure until sessCtx is cancelled (Pause/Resume) or global ctx is done (Stop).
// After 3 consecutive short-lived failures, goes dormant for up to 1 minute.
// This avoids hammering the TURN server (Allocation Quota Reached) while still
// recovering without relying on iOS sleep()/wake() which are unreliable.
//
// Dormancy was 30-180s pre-build-88. Shortened to 30-60s once credpool
// gained its own VK 486 protection layers (smart-pause / cascade-pause /
// 12m activeAllocationsWindow / compact-fill) — the conn-side long
// dormancy was double-insurance that primarily slowed real recovery. With
// armPauseAcquireBroadcastLocked (creds.go) firing slotAvailableCh on
// pause-expiry, the 30-60s cap rarely runs to completion anyway: conns
// wake within ms of pool-state change.
func (p *Proxy) runConnection(sessCtx context.Context, linkID string, readyCh chan<- struct{}, connIdx int) error {
	signaled := false
	shortFailures := 0
	var floor retryFloor // this connection's retry floor — retryfloor.go

	for {
		select {
		case <-sessCtx.Done():
			return sessCtx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		start := time.Now()
		// A NEW SESSION GETS A FRESH BUCKET. `paceBuckets` is indexed by connection
		// index at package scope, so without this a connection that reconnects onto
		// a brand-new TURN allocation — whose policer at VK's end starts full —
		// would inherit the dead allocation's token debt and be denied its opening
		// burst. One site, all four transport modes. See uplinkpace.go.
		PaceResetConn(connIdx)
		// One context per SESSION under the shared sessCtx, so a path-up can
		// restart this conn alone (pathrestart.go) while Pause/Resume keep
		// cancelling everything through the parent.
		connCtx, connCancel := context.WithCancel(sessCtx)
		p.beginConnSession(connIdx, connCancel)
		var err error
		switch {
		case p.sessionHook != nil: // a test seam, nil in production
			err = p.sessionHook(connCtx, connIdx)
		case p.config.UseWrapA:
			err = p.runWrapASession(connCtx, linkID, readyCh, &signaled, connIdx)
		case p.config.UseSrtp:
			err = p.runSRTPSession(connCtx, linkID, readyCh, &signaled, connIdx)
		case p.config.UseDTLS:
			err = p.runDTLSSession(connCtx, linkID, readyCh, &signaled, connIdx)
		default:
			err = p.runDirectSession(connCtx, linkID, readyCh, &signaled, connIdx)
		}
		// The retry floor's streak (retryfloor.go) ends on a session that CAME
		// UP in this iteration — whatever it returned afterwards. 🚨 Asked here,
		// not under `err != nil` below: runSRTPSession and runDTLSSession return
		// nil after wg.Wait, also when an established session has dropped, and
		// the next iteration can no longer see this one's stamp (it asks
		// "since MY start") — a streak kept across a working session would
		// hold the next failure's wake for seconds instead of 250 ms (the
		// user's review of build 409).
		established := p.ups.since(connIdx, start)
		if established {
			floor.reset()
		}
		// A restart WE asked for (a path-up) ended this session, not the
		// path: no failure count, no dormancy, a sub-second stagger so the
		// thirty re-dials do not land in one instant, and on to a session
		// that announces the new group.
		asked := connCtx.Err() != nil && sessCtx.Err() == nil && p.ctx.Err() == nil
		connCancel()
		p.endConnSession(connIdx)
		if asked {
			log.Printf("proxy: [conn %d] session ended after %s by request (path change) — restarting now",
				connIdx, time.Since(start).Round(time.Second))
			shortFailures = 0
			floor.reset() // a new network: the old one's failures say nothing about it
			select {
			case <-time.After(restartStagger()):
			case <-sessCtx.Done():
				return sessCtx.Err()
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
			continue
		}
		if err != nil {
			duration := time.Since(start)
			log.Printf("proxy: [conn %d] session ended after %s: %s", connIdx, duration.Round(time.Second), err)
			if !signaled && readyCh != nil {
				return err
			}

			// The retry floor (retryfloor.go): a failure with no session in this
			// iteration and no answer from the pool, VK or the relay is the
			// network's — it extends the streak, and the wait below holds a
			// slot-available wake back under the floor.
			floored := false
			if !established && isNetworkClassFailure(err) {
				floor.noteNetworkFailure(time.Now())
				floored = true
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

			// After 3 consecutive short-lived failures, go dormant for up to 1 minute.
			// Originally up to 3 minutes — the long ceiling protected VK from
			// post-cascade Allocate burst before the credpool layer could.
			// Build 87+ has its own 486 defenses (smart-pause + cascade pause +
			// 12m activeAllocationsWindow + compact-fill); the long dormancy
			// became double-insurance that mostly hurt recovery. Shortened to
			// 30-60s in build 88. Critically, slotAvailableCh below short-circuits
			// the wait the moment pool state changes — including pauseAcquireUntil
			// expiry now that armPauseAcquireBroadcastLocked fires on it — so most
			// dormancies wake within ms of the pool unblocking, not at the cap.
			if shortFailures >= 3 {
				// Stagger dormancy wake-up: random 30-60s so all conns
				// don't try to reconnect simultaneously (which used to
				// cause Quota Reached before credpool's own protection).
				dormantDuration := time.Duration(30+mathrand.Intn(30)) * time.Second
				log.Printf("proxy: %d consecutive short failures, sleeping %s before retry", shortFailures, dormantDuration.Round(time.Second))
				// slotAvailableCh wakes the conn early on any pool-state
				// change that could plausibly let it succeed: a fresh
				// cred just landed in some slot (background grower or
				// another conn's Phase 2 fetch), or a release freed
				// capacity. Without this, "no slot available" failures
				// — common during cascade reconnects — wait out the
				// full random dormancy regardless of when slots reopen.
				slotCh := p.wakeChannelFor(err)
				woke, werr := p.waitRetry(sessCtx, connIdx, dormantDuration, slotCh, &floor, floored)
				if werr != nil {
					return werr
				}
				switch woke {
				case retryWakeTimer:
					shortFailures = 0 // reset after dormancy
					log.Printf("proxy: waking from dormancy, retrying connection")
					// DON'T wholesale-invalidate the pool here. This conn was
					// dormant, but other conns may have been running fine on
					// existing creds — wholesale-invalidate destroys them and
					// forces every conn to re-fetch (which often hits captcha).
					// If our retry uses a stale cred and gets a short-lived
					// session, the per-slot invalidateEntry path (line ~1228)
					// drops only that bad slot. Other conns keep their creds.
				case retryWakeSignal:
					// Slot-state change happened. Reset the failure
					// counter — the prior failures were "no slot
					// available" or quota-driven, and external state
					// changed in a way that may resolve them. Treat
					// this as a fresh start instead of letting the
					// next failure immediately re-trigger dormancy.
					//
					// 🚨 Not the retry floor's streak: after a network-class
					// failure waitRetry has already held this wake back under
					// the floor, and the streak resets only on evidence that
					// the network works (retryfloor.go).
					shortFailures = 0
					log.Printf("proxy: waking from dormancy on slot-available signal, retrying")
				}
				continue
			}

			// Staggered delay before reconnect: random 2-7s to avoid
			// all connections hitting TURN server at the same instant.
			// slotAvailableCh short-circuits the wait when an in-flight
			// pool-state change makes immediate retry sensible — see
			// dormancy comment above.
			delay := time.Duration(2000+mathrand.Intn(5000)) * time.Millisecond
			slotCh := p.wakeChannelFor(err)
			if _, werr := p.waitRetry(sessCtx, connIdx, delay, slotCh, &floor, floored); werr != nil {
				return werr
			}
		}
	}
}

// directMode reports the transport with nothing above the TURN relay (no
// DTLS, WRAP-A or SRTP) — the default arm of runConnection's dispatch.
func (p *Proxy) directMode() bool {
	return !p.config.UseWrapA && !p.config.UseSrtp && !p.config.UseDTLS
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
//
// Note: VK's vchat.joinConversationByLink returns multiple TURN endpoints
// (≥2, confirmed in build 53). We parse them into creds.Addresses; each
// conn dials its own cred's Addresses[0], so the pool naturally spreads
// across whatever relays VK hands out per fetch.
//
// CORRECTION 2026-06-08: the previous version of this comment claimed conns
// on a relay != Swift's serverAddress get "recursive-routed back through the
// tunnel → ~0.5 Mbps". That is EMPIRICALLY FALSE (08.06.2026/vpn.change.
// address.log): with serverAddress = relay B, ~10 conns ran on relay A (the
// NON-serverAddress relay) and carried FULL speed both idle and under a
// speedtest (~86 KB/s TX/conn, 8.7 MB cum), all on the physical interface
// (local=192.168.4.21). The extension's own TURN sockets never traverse its
// own tunnel regardless of destination, so a conn's relay need not match
// serverAddress — there is no recursion. (The old "155→90 → 0.5 Mbps"
// anecdote was almost certainly the old relay being DEAD, not recursion.) We
// still don't actively rotate — no demonstrated throughput win — but a
// relay/serverAddress mismatch is harmless. See
// evaluated_alternatives_turn_endpoint_rotation.md.
func (p *Proxy) resolveTURNAddr(connIdx int, allowCaptchaBlock bool) (string, *TURNCreds, int, error) {
	return p.credPool.get(connIdx, allowCaptchaBlock)
}

// wakeChannelFor is the channel a retry parks on after err. A park error
// carries the slot-available channel that was current under the pool's lock
// when the pool said "not now"; a broadcast since then closed exactly that
// channel, so the select returns at once instead of waiting for the NEXT
// broadcast — the lost-wakeup gap between get()'s Unlock and a later
// slotAvailableChannel() call (Sep 7 §71). Any other error parks on the
// pool's current channel, as before. The session functions return the
// pool's error unwrapped (`return err`), so errors.As finds it.
func (p *Proxy) wakeChannelFor(err error) <-chan struct{} {
	var park *poolParkError
	if errors.As(err, &park) && park.wake != nil {
		return park.wake
	}
	return p.credPool.slotAvailableChannel()
}

// fetchFreshCreds is the pool's underlying VK fetcher. It wraps GetVKCreds
// with captcha-token bookkeeping and TURN host:port parsing. NOT serialized:
// get() and tryFill release the pool's lock before they fetch, so mints run
// concurrently up to the cold-start cap (ready + in-flight < ceil(size/4):
// three at N=30, six at N=60) — and since the sub-second start of
// 2026-09-07 two conn-driven mints beside the grower's are the normal
// cold-cache shape, not a race.
func (p *Proxy) fetchFreshCreds(allowCaptchaBlock bool, slot int) (string, *TURNCreds, error) {
	var creds *TURNCreds

	if cookieAuthEnabled.Load() {
		// Cookie (VKAuth) mode: this pool slot maps to a stable (call, relay) so
		// conns spread across relays — each (okcdn_userid, relay) is its own ~10
		// allocation quota (2026-06-28 finding). No captcha bookkeeping here.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, cerr := cookieCredForSlot(ctx, slot)
		cancel()
		if cerr != nil {
			if errors.Is(cerr, ErrCookieRejected) {
				setCookieAuthFatal(cerr.Error())
			}
			return "", nil, fmt.Errorf("cookie auth: %w", cerr)
		}
		clearCookieAuthFatal()
		creds = c
	} else {
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
		c, err := GetVKCreds(p.linkID, solver, solvedSID, solvedKey, solvedTs, solvedAttempt, savedToken1, "")
		if err != nil {
			return "", nil, fmt.Errorf("get VK creds: %w", err)
		}
		creds = c
	} // end else (anonymous path)
	// Apply the "TURN server" override (Settings → optional turn_server/
	// turn_port; empty = no override) to every VK-returned address. This is
	// the fresh-fetch path: the override affects creds RECEIVED FROM VK and
	// bakes into the cred + on-disk cache (intended). Cached/seeded creds are
	// used as STORED — the seed path in NewProxy does NOT re-apply the
	// override (the "setting must not affect cached creds" guarantee). Today
	// only Addresses[0] is dialed (resolveTURNAddr), but we override all
	// entries uniformly so a future failover doesn't redo the pass. Addresses
	// must be non-empty (getVKCredsWithClientID guarantees ≥1).
	for i, vkAddr := range creds.Addresses {
		h, pport, perr := net.SplitHostPort(vkAddr)
		if perr != nil {
			return "", nil, fmt.Errorf("parse TURN address %q: %w", vkAddr, perr)
		}
		if p.config.TurnServer != "" {
			h = p.config.TurnServer
		}
		if p.config.TurnPort != "" {
			pport = p.config.TurnPort
		}
		creds.Addresses[i] = net.JoinHostPort(h, pport)
	}
	creds.Address = creds.Addresses[0]
	firstHost, _, _ := net.SplitHostPort(creds.Addresses[0])
	p.turnServerIP.Store(firstHost)
	return creds.Addresses[0], creds, nil
}

// runDTLSSession runs a long-lived DTLS session.
// DTLS stays alive while TURN reconnects underneath with fresh creds only on failure.
// Only returns when DTLS itself fails (then the caller restarts everything).
func (p *Proxy) runDTLSSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool, connIdx int) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	// Create AsyncPacketPipe: conn1 = DTLS transport, conn2 = TURN transport.
	// One pipe per runDTLSSession invocation — the conns get torn down
	// together when TURN or DTLS fails, and the outer runConnection loop
	// re-enters runDTLSSession to build a fresh pair. See the comment at the
	// relay leg's start below for why we do NOT reuse pipes across TURN reconnects.
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	// Get initial credentials and start first TURN relay. credSlot tells
	// us which pool slot actually provided the cred — may equal connIdx
	// (own slot / fresh fetch) or some other slot's index (fallback).
	// We track it so a short-lived session can invalidate the slot that
	// actually carried the bad cred, not this conn's nominal slot.
	//
	// allowCaptchaBlock=false unconditionally: post-bootstrap conn-driven
	// fetches must NEVER block on captcha because the extension can't show
	// a WebView, so the captcha solver would just sit forever waiting for
	// a SolveCaptcha() call that never comes (jetsam may have killed the
	// main app long ago). Blocking accumulates waiters that all keep
	// captchaImageURL set, which in turn paralyses the background grower
	// (vpn.wifi.1.log on 2026-05-05 showed grower stuck for 5+ hours after
	// the first such waiter started in mid-session). Bootstrap captcha is
	// handled separately at runConnection's level via waitCaptchaAndRestart
	// + captchaWaiterActive guard, before we ever reach this code.
	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, false)
	if err != nil {
		return err
	}
	// Each successful resolveTURNAddr increments cp.pool[credSlot].active
	// to enforce the per-cred quota (~10 simultaneous allocations on VK).
	// A defer pinned to currentSlot via closure releases the LATEST slot
	// at function exit — important because the reconnect loop below may
	// switch us to a different slot, and we need to release whatever
	// slot we're holding when this conn's session finally ends. The lease is
	// the PAIR — the slot and the credential it handed out: the slot may be
	// refilled under us, and the pool counts a release only against the
	// credential it names (credPool.release).
	currentSlot, currentCreds := credSlot, creds
	// The relay leg this session starts below. It also carries the note of the
	// allocation given back, by which the lease is released behind the relay's
	// second (relayjoin.go, seatcool.go).
	var leg relayLeg
	defer func() { p.releaseLease(currentSlot, currentCreds, &leg.gave) }()

	// Start TURN relay FIRST — DTLS handshake goes through it.
	// TURN runs until it fails naturally (no forced lifetime).
	// The pion/turn client handles allocation refresh automatically.
	//
	// On any TURN exit (whether error or normal close) we cancelOnError=true:
	// connCancel propagates to dtlsConn.Close (via context.AfterFunc below)
	// and unblocks both dialDTLS during initial handshake AND the long-lived
	// send/recv goroutines after handshake. runDTLSSession then returns and
	// the outer loop in runConnection rebuilds this conn from scratch with a
	// fresh AsyncPacketPipe, fresh dialDTLS, fresh TURN allocate.
	//
	// We do NOT reconnect TURN within runDTLSSession anymore. The previous
	// in-place reconnect kept the same dtlsConn across TURN reconnects, which
	// looked like an optimization (peer's DTLS session continues seamlessly)
	// but was actually broken: every TURN reconnect from pion's Allocate()
	// hands back a NEW relay address, so peer sees our DTLS source change
	// and treats it as a brand-new session — but our dtlsConn still holds
	// the old session's keys/state and tries to send application data
	// peer can't decrypt. Symptom: silent 2-minute hang after handover (only
	// the zombie probe finally kills the conn so the outer loop can rebuild
	// it). See vpn.lte-wifi.0.log conn 27 around 00:50:18 — first TURN
	// allocate succeeds but DTLS handshake never completes; conn 27's second
	// allocate via the outer loop goes through DTLS in 57 ms.
	//
	// The relay leg runs in a goroutine of its own and is JOINED before this
	// session returns (relayjoin.go). On its exit it always cancels the session:
	// without TURN there's no DTLS transport, so the conn is dead either way.
	turnDone, _ := p.goRunTURN(connCtx, &leg, turnAddr, creds, conn2, connIdx, credSlot, connCancel)
	// Registered BEHIND the credential's release above, so it runs BEFORE it, and
	// ahead of every return below — the early ones too: the session gives its
	// credential back, and its connection re-dials, only after the relay leg's
	// teardown (over UDP: the relay's answer to the deallocate).
	defer p.joinRelayLeg(&leg, connCancel, connIdx)

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
					// markSaturated picks an adaptive cooldown based on
					// the slot's lastUsedAt — short (3m) if 486 is from
					// likely-ghost state, long (11m) if VK still holds
					// our active allocations from a recent session that
					// just got its sockets killed (e.g. iOS multi-interface
					// path-change like vpn.wifi-lte-wifi.1.log). It logs
					// its own decision; here we only log the proxy-side
					// context (which conn, which slot).
					cooldown := p.credPool.markSaturated(credSlot, creds)
					log.Printf("proxy: [conn %d] TURN allocate quota error (486) on slot %d (cooldown %s)",
						connIdx, credSlot, cooldown.Round(time.Second))
				} else if isAuthError(turnErr) {
					p.credPool.invalidateEntry(credSlot, creds)
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

	// SRTP-WRAP-S: send the free-turn-proxy Client-ID as the FIRST DTLS app
	// record, before any WireGuard payload. The server always reads exactly one
	// such record after the handshake; skipping it desyncs the stream. The wrap
	// layer (runTURN) is already active here, so this record is obf-wrapped like
	// any other. No-op for every other mode. See wraps.go / WriteClientID.
	if p.config.UseWrapS {
		if cerr := WriteClientID(dtlsConn, p.config.ClientID); cerr != nil {
			log.Printf("proxy: [conn %d] runDTLSSession: WriteClientID failed: %v", connIdx, cerr)
			dtlsConn.Close()
			return fmt.Errorf("write client-id: %w", cerr)
		}
		log.Printf("proxy: [conn %d] SRTP-WRAP-S: sent Client-ID (%d bytes, profile=%s)", connIdx, len(p.config.ClientID), p.config.ObfProfile)
	}

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

	p.noteSessionUp(connIdx) // the retry floor's evidence that the network works — retryfloor.go
	log.Printf("proxy: [conn %d, cred %d] DTLS+TURN session established", connIdx, credSlot)
	p.resetProbeMarks(connIdx) // this session's pings start from seq 1, and so do its marks — wakeprobe.go

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
		var lastPingAt time.Time // when the ping numbered seq was sent, or zero: written by tickPing and runWakeProbe alone — wakeprobe.go
		pingPkt := make([]byte, len(probePingMagic)+8)
		copy(pingPkt[0:len(probePingMagic)], probePingMagic)
		// sendPing writes one ping — the periodic tick's and the wake probe's alike.
		// Diagnostic bookkeeping, no per-send log (50 conns × 30/hr = 1500 lines/hr
		// of noise): the latest seq, so that the zombie-kill log can show how many
		// pings went out without a matching pong, and firstPingAt the very first
		// time, so that the first-pong log can report the round trip to bootstrap.
		sendPing := func(s uint64, now time.Time) error {
			binary.BigEndian.PutUint64(pingPkt[len(probePingMagic):], s)
			dtlsConn.SetWriteDeadline(now.Add(5 * time.Second))
			if _, err := dtlsConn.Write(pingPkt); err != nil {
				return err
			}
			if connIdx >= 0 && connIdx < len(p.lastPingSeq) {
				p.lastPingSeq[connIdx].Store(s)
				p.firstPingAt[connIdx].CompareAndSwap(0, now.Unix())
			}
			return nil
		}
		// M3 group hello. Sent IMMEDIATELY rather than waiting for the first
		// tick: until the server sees it this conn stays on its own socket, and
		// a probeInterval of that is a probeInterval of the old, skewed
		// downlink at the start of every tunnel. Re-sent on every tick so a
		// lost hello heals by repetition and a restarted server re-groups us.
		p.sendGroupHello(dtlsConn)
		// Tick-gap detector: if the gap between two consecutive ticks is
		// much larger than probeInterval, our goroutine was suspended
		// (iOS Network Extension freeze). During that time we couldn't
		// send pings, so no pongs could come back, and lastPongTime is
		// stale by the freeze duration through no fault of the conn.
		// Reset the pong clock on freeze-wake and skip the zombie check
		// for one round — the next normal tick will send a fresh ping
		// and the regular probeStaleThreshold gives the conn a fair
		// 2-minute window to receive a real pong before being judged.
		//
		// Without this guard, after a 5+ minute iOS freeze every conn
		// observes its lastPongTime as "stale 5m+" and self-cancels —
		// even though the underlying TURN allocation is still valid.
		// See vpn.wifi.11.log on 2026-04-30 for the failure mode where
		// 30 conns went zombie simultaneously on wake, triggering a
		// 486-cascade that locked all 4 cred slots for 10 minutes.
		//
		// Initialize lastTickAt to goroutine-creation time, NOT zero.
		// Otherwise the first tick after a long freeze that started
		// just after goroutine creation skips the gap check (the old
		// `!lastTickAt.IsZero()` guard) and proceeds straight to the
		// zombie check, which fires because lastPongTime is stale by
		// the full freeze duration. See vpn.wifi.4.log on 2026-05-01:
		// conns 41-49 respawned at ~12:15:25, then iOS froze for ~5m54s,
		// and on wake the first probe tick mistakenly killed all of
		// them as zombies even though it should have detected the
		// freeze and reset lastPongTime.
		lastTickAt := time.Now()
		wake := p.newWakeWatch()
		for {
			// Capture the wake channel reference once per iteration. The
			// channel is replaced (not just signaled) on each broadcast,
			// so a stale capture would either fire repeatedly on a closed
			// channel (busy-loop) or miss the next signal entirely.
			wakeCh := p.wakeChannel()
			if wake.pending() {
				// A wake was broadcast while this goroutine was not parked in the select
				// below (its tick branch, at a thaw): the channel it has just read is the
				// NEW one and will not fire for it. The epoch remembers — wakeprobe.go.
				wakeCh = closedWakeCh
			}
			select {
			case <-ticker.C:
				now := time.Now()
				gap := now.Sub(lastTickAt)
				if gap > 90*time.Second {
					log.Printf("proxy: [conn %d] probe tick gap %s (freeze detected), resetting pong clock",
						connIdx, gap.Round(time.Second))
					if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
						p.lastPongTimes[connIdx].Store(now.Unix())
					}
					lastTickAt = now
					continue
				}
				lastTickAt = now
				// The tick's ping is ONE body for both session kinds — seq and the stamp a
				// wake probe may adopt it by move together there (tickPing, wakeprobe.go).
				if err := p.tickPing(&seq, &lastPingAt, now, sendPing); err != nil {
					// Write failure means the conn is already broken.
					// Other goroutines (DTLS recv timeout, TURN reconnect
					// loop) will handle the actual teardown — we just
					// stop sending probes.
					return
				}
				// Zombie check: if no pong for probeStaleThreshold (default
				// 120s) AND the server has been observed responding to at
				// least one probe at some point (serverProbeable), kill
				// this conn so the reconnect path can rebuild it with a
				// fresh TURN allocation.
				//
				// Re-enabled after the original captcha-storm post-mortem
				// (vpn.wifi-lte.0.log 2026-04-29). Conditions improved:
				//   - release-before-get fix (commit fbf7abf) keeps the
				//     reconnect cascade from spuriously logging "no slot
				//     available" 30 times during handover.
				//   - cred TTL increased to 4h default (commit 919f1e0)
				//     means slots are far less likely to be on cooldown
				//     when a kill arrives.
				// The captcha-during-broken-tunnel issue is still real
				// (see feedback_ios_routing.md), but
				// the recovery path now has more headroom: with TTL 4h
				// the spare slot+1 is usually fresh, so 10/30 conns
				// recover instantly on the spare cred without needing a
				// fresh VK fetch. Remaining 20/30 are blocked by VK's
				// per-cred quota until old WiFi allocations expire on
				// VK side (~10 min) — same constraint as before, but
				// now we KNOW we're waiting on quota expiry rather than
				// being silently broken with 35% loss.
				if p.serverProbeable.Load() && connIdx >= 0 && connIdx < len(p.lastPongTimes) {
					lastPong := time.Unix(p.lastPongTimes[connIdx].Load(), 0)
					stale := time.Since(lastPong)
					if stale > probeStaleThreshold {
						// Attribution data: distinguishes "we stopped sending
						// pings" (sentSinceLastPong=0) from "server stopped
						// echoing or echoes were lost on return" (>0). If
						// firstPongAt is 0 the conn never received a single
						// pong, which is its own failure mode — typically
						// means probes never made it through the server at
						// all (unpatched server, or DTLS pipe broken from
						// the start).
						lastPing := p.lastPingSeq[connIdx].Load()
						lastPongS := p.lastPongSeq[connIdx].Load()
						// Guard against uint64 underflow when lastPongS > lastPing.
						// This is possible transiently because the two atomic Loads
						// happen non-atomically with respect to the ping-send /
						// pong-recv paths: a pong for ping N can be observed AFTER
						// we Load lastPing=N-1 but BEFORE lastPongS=N is recorded
						// is purely a function of which Load executes first. Without
						// this clamp the log shows sentSinceLastPong=18446744073709551614
						// (= 2^64 - 2) which is meaningless. Empirical case 2026-05-18
						// vpn.wifi.0.log conn 18 @ 04:05:28.
						var sentSinceLastPong uint64
						if lastPing >= lastPongS {
							sentSinceLastPong = lastPing - lastPongS
						}
						firstPong := p.firstPongAt[connIdx].Load()
						pongHistory := "never"
						if firstPong > 0 {
							pongHistory = time.Since(time.Unix(firstPong, 0)).Round(time.Second).String() + " ago (first pong)"
						}
						authCount := p.credPool.authErrorCount(credSlot)
						log.Printf("proxy: [conn %d on slot %d] zombie detected (no pong for %s, lastPingSeq=%d lastPongSeq=%d sentSinceLastPong=%d firstPong=%s, authErrorsOnSlot=%d), killing",
							connIdx, credSlot, stale.Round(time.Second), lastPing, lastPongS, sentSinceLastPong, pongHistory, authCount)
						connCancel()
						return
					}
				}
			case <-wakeCh:
				// Whether this wake is probed at all (the 30-s throttle, a connection with
				// traffic a moment ago), the jitter and the probe itself are ONE body for
				// both session kinds — wakeWatch.serve, wakeprobe.go (builds 422–424).
				alive, probed, err := wake.serve(connCtx, connIdx, credSlot, "", &seq, &lastPingAt, sendPing)
				if err != nil {
					return
				}
				if !alive {
					connCancel()
					return
				}
				if probed {
					lastTickAt = time.Now()
				}
			case <-connCtx.Done():
				return
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
		// One closure per connection, not per packet — see the SRTP send
		// goroutine for why.
		writeOne := func(pkt []byte, now time.Time) error {
			dtlsConn.SetWriteDeadline(now.Add(30 * time.Second))
			_, werr := dtlsConn.Write(pkt)
			return werr
		}
		for {
			// 🚨 RESERVE BEFORE THE DEQUEUE, at all four writer sites — see
			// uplinkpace.go for why this ordering IS the correctness argument:
			// a writer that took the packet first would hold it inside its own
			// goroutine, where the other 29 writers cannot steal it. Off by
			// default, and when off `paceReserve` returns an empty ticket and
			// `paceSettle` is a no-op, so this is byte-for-byte today's path.
			ticket := p.paceReserve(connIdx)
			select {
			case <-connCtx.Done():
				p.paceSettle(ticket, 0)
				log.Printf("proxy: [conn %d] DTLS send goroutine: ctx cancelled", connIdx)
				return
			case item := <-p.sendCh:
				p.paceSettle(ticket, len(item.buf))
				// -1: this site has never maintained the per-conn TX counters,
				// and writePacket must not quietly start.
				if err := p.writePacket(item, -1, writeOne); err != nil {
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
			deadlineSetAt := time.Now()
			dtlsConn.SetReadDeadline(deadlineSetAt.Add(30 * time.Second))
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
					// Detect iOS Network Extension freeze: if Read took
					// much longer than the 30s deadline, our goroutine was
					// suspended. lastRecvTime is stale by the freeze
					// duration through no fault of the tunnel — treating
					// it as "tunnel dead" would be a false positive (see
					// vpn.lte-wifi.0.log on 2026-04-30 for the cascade
					// mode this triggers). Reset the global clock and
					// continue with a fresh deadline.
					elapsed := time.Since(deadlineSetAt)
					if elapsed > 90*time.Second {
						log.Printf("proxy: [conn %d] DTLS read elapsed %s (freeze detected), resetting lastRecvTime",
							connIdx, elapsed.Round(time.Second))
						p.lastRecvTime.Store(time.Now().Unix())
						continue
					}
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
					now := time.Now()
					nowUnix := now.Unix()
					// Capture the previous pong timestamp and seq BEFORE
					// overwriting them — needed to detect long silences
					// in the echo stream and to attribute them to seqs
					// (e.g. "the gap straddled seq 17 → 19, so seq 18's
					// echo was lost"). Useful for "probing was working,
					// went silent for N seconds, then came back" patterns
					// that don't trip the zombie killer (which only fires
					// above probeStaleThreshold).
					prevPongAt := p.lastPongTimes[connIdx].Load()
					prevPongSeq := p.lastPongSeq[connIdx].Load()
					p.lastPongTimes[connIdx].Store(nowUnix)
					// Pull the seq out of the echoed payload (8 bytes BE
					// right after the magic). Servers echo verbatim so
					// it's the same seq we sent.
					var pongSeq uint64
					if n >= len(probePingMagic)+8 {
						pongSeq = binary.BigEndian.Uint64(buf[len(probePingMagic) : len(probePingMagic)+8])
						p.notePongSeq(connIdx, pongSeq) // forward only — wakeprobe.go
					}
					// One-shot first-pong log: shows when end-to-end
					// probing actually started working for this conn,
					// and how long we waited from the first ping. CAS
					// from 0 ensures the log fires exactly once per conn.
					if p.firstPongAt[connIdx].CompareAndSwap(0, nowUnix) {
						firstPing := p.firstPingAt[connIdx].Load()
						bootstrap := "?"
						if firstPing > 0 {
							bootstrap = time.Since(time.Unix(firstPing, 0)).Round(100 * time.Millisecond).String()
						}
						log.Printf("proxy: [conn %d] first pong received (seq=%d, %s after first ping)",
							connIdx, pongSeq, bootstrap)
					} else if prevPongAt > 0 {
						gap := nowUnix - prevPongAt
						// Pong gap log: 5 min is well above the normal
						// 2-min probeInterval (so two missed pongs in a
						// row trigger it) but well below the 120s zombie
						// threshold (so it can't fire after a kill).
						if gap > 300 {
							log.Printf("proxy: [conn %d] pong gap %ds resolved (prev pongSeq=%d, this pongSeq=%d, missed=%d)",
								connIdx, gap, prevPongSeq, pongSeq, pongSeq-prevPongSeq-1)
						}
					}
				}
				continue
			}
			pkt := recvPktPoolGet(n)
			copy(pkt, buf[:n])
			if !p.enqueueRecv(connCtx, pkt) {
				recvPktPoolPut(pkt)
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

	// allowCaptchaBlock=false — see runDTLSSession's matching comment.
	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, false)
	if err != nil {
		return err
	}
	// The lease is the pair (slot, credential) — see runDTLSSession.
	currentSlot, currentCreds := credSlot, creds
	// The relay leg this session starts below. It also carries the note of the
	// allocation given back, by which the lease is released behind the relay's
	// second (relayjoin.go, seatcool.go).
	var leg relayLeg
	defer func() { p.releaseLease(currentSlot, currentCreds, &leg.gave) }()

	// The relay leg IS this session's transport; it is JOINED before the session
	// returns — behind the credential's release above, so ahead of it
	// (relayjoin.go). The reconnect loop below starts the next one through the
	// same leg.
	turnDone, _ := p.goRunTURN(connCtx, &leg, turnAddr, creds, conn2, connIdx, credSlot, nil)
	defer p.joinRelayLeg(&leg, connCancel, connIdx)

	if readyCh != nil && !*signaled {
		*signaled = true
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	// Signal proxy-lifetime bootstrap ready (sync.Once, idempotent).
	p.signalBootstrapDone(nil)

	// 🚨 No session-up stamp here: this line precedes the allocation (the
	// session IS the TURN relay, started a moment ago and not yet answered). The
	// retry floor's evidence for the direct mode is the allocation itself —
	// runTURN stamps it (retryfloor.go).
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
			// Release before retry loop — see runDTLSSession for full
			// rationale. Same pattern: avoid stale active counts during
			// reconnect storm.
			p.releaseLease(credSlot, currentCreds, &leg.gave) // behind the relay's second, if the leg that ended gave its allocation back
			credSlot = -1
			currentSlot, currentCreds = -1, nil
			retries := 0
			for retries < 5 {
				if connCtx.Err() != nil {
					return
				}
				// allowCaptchaBlock=false — see runDTLSSession's matching comment.
				newAddr, newCreds, newSlot, err := p.resolveTURNAddr(connIdx, false)
				if err != nil {
					retries++
					select {
					case <-time.After(time.Duration(retries) * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}
				credSlot = newSlot
				currentSlot, currentCreds = newSlot, newCreds
				next, started := p.goRunTURN(connCtx, &leg, newAddr, newCreds, conn2, connIdx, newSlot, nil)
				if !started {
					return // the session is ending: nothing is started behind its join
				}
				log.Printf("proxy: [conn %d, cred %d] starting new direct TURN session", connIdx, credSlot)
				turnDone = next
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
		// One closure per connection, not per packet — see the SRTP send
		// goroutine for why.
		writeOne := func(pkt []byte, now time.Time) error {
			conn1.SetWriteDeadline(now.Add(30 * time.Second))
			_, werr := conn1.WriteTo(pkt, p.peer)
			return werr
		}
		for {
			// 🚨 RESERVE BEFORE THE DEQUEUE — see uplinkpace.go.
			ticket := p.paceReserve(connIdx)
			select {
			case <-connCtx.Done():
				p.paceSettle(ticket, 0)
				return
			case item := <-p.sendCh:
				p.paceSettle(ticket, len(item.buf))
				// -1: no per-conn TX accounting at this site today.
				if err := p.writePacket(item, -1, writeOne); err != nil {
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
			pkt := recvPktPoolGet(n)
			copy(pkt, buf[:n])
			if !p.enqueueRecv(connCtx, pkt) {
				recvPktPoolPut(pkt)
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// ─── WRAP-A transport (Config.UseWrapA=true) ───────────────────────────────
//
// runWrapASession is the fourth dispatch target (alongside runDTLSSession /
// runSRTPSession / runDirectSession), selected via Config.UseWrapA. It speaks
// amurcanov's proxy-turn-vk-android wire protocol so our iOS client can reach
// his Android-only server:
//
//	VK-TURN relay → WRAP-A RTP-obfs (wrapa.go) → plain DTLS (his config) →
//	GETCONF auto-provisioning (getconf.go) → WireGuard
//
// It reuses runTURN for the relay (all the cred / quota / keepalive /
// reconnect machinery) by inserting the WRAP-A obfuscation as a
// net.PacketConn wrapper around conn1 — exactly as tools/wrapa_test layered
// DTLS over the UDP socket, proven end-to-end against the live server
// 2026-06-03. Every conn sends GETCONF as its mandatory first message; the
// first to finish stores the server-minted WireGuard config
// (storeWrapAProvision) and the bridge waits on it (WaitWrapAProvision) to
// configure the WG device. MVP, like runSRTPSession — no liveness-probe
// sender / zombie watchdog (amurcanov's server has no probe-echo); self-
// healing rides the global no-RX watchdog + the per-conn read-deadline
// staleness check below.
func (p *Proxy) runWrapASession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool, connIdx int) error {
	_ = linkID // reserved for per-link logging parity with the DTLS path
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, false)
	if err != nil {
		return err
	}
	// The lease is the pair (slot, credential) — see runDTLSSession.
	currentSlot, currentCreds := credSlot, creds
	// The relay leg this session starts below. It also carries the note of the
	// allocation given back, by which the lease is released behind the relay's
	// second (relayjoin.go, seatcool.go).
	var leg relayLeg
	defer func() { p.releaseLease(currentSlot, currentCreds, &leg.gave) }()

	// TURN relay underneath (conn2 ↔ VK relay). Same pattern as
	// runDTLSSession: any TURN exit cancels the conn so the outer loop
	// rebuilds it, and the relay leg is JOINED before this session returns —
	// behind the credential's release above, so ahead of it, and ahead of every
	// return below, the early ones too (relayjoin.go).
	turnDone, _ := p.goRunTURN(connCtx, &leg, turnAddr, creds, conn2, connIdx, credSlot, connCancel)
	defer p.joinRelayLeg(&leg, connCancel, connIdx)

	// WRAP-A obfuscation around the DTLS-transport end of the pipe, then a
	// plain DTLS client with amurcanov's exact config.
	wrapAPC, err := newWrapAPacketConn(conn1, p.peer, p.wrapAKey)
	if err != nil {
		return fmt.Errorf("WRAP-A init: %w", err)
	}
	dtlsStart := time.Now()
	dtlsConn, err := dialDTLSWrapA(connCtx, wrapAPC, p.peer)
	if err != nil {
		connCancel()
		select {
		case turnErr := <-turnDone:
			if turnErr != nil {
				// Mirror runDTLSSession's error attribution so quota / auth
				// failures land on the slot that actually carried the cred.
				if isQuotaError(turnErr) {
					cooldown := p.credPool.markSaturated(credSlot, creds)
					log.Printf("proxy: [conn %d] WRAP-A TURN allocate quota error (486) on slot %d (cooldown %s)",
						connIdx, credSlot, cooldown.Round(time.Second))
				} else if isAuthError(turnErr) {
					p.credPool.invalidateEntry(credSlot, creds)
					log.Printf("proxy: [conn %d] WRAP-A bootstrap auth error on slot %d, invalidated", connIdx, credSlot)
				}
				return fmt.Errorf("WRAP-A DTLS failed: %w (TURN error: %v)", err, turnErr)
			}
		default:
		}
		return fmt.Errorf("WRAP-A DTLS: %w", err)
	}
	defer dtlsConn.Close()
	context.AfterFunc(connCtx, func() { dtlsConn.Close() })

	// GETCONF — MANDATORY first message on every conn (the server sniffs the
	// first datagram). Idempotent per deviceID; the first to finish provisions
	// the WG device. Done synchronously BEFORE the recv pump so the response
	// isn't eaten by the WireGuard read goroutine.
	prov, err := doGetconf(dtlsConn, p.config.DeviceID, p.config.WrapAPassword)
	if err != nil {
		return fmt.Errorf("WRAP-A getconf: %w", err)
	}
	p.storeWrapAProvision(prov)

	p.dtlsHSns.Store(int64(time.Since(dtlsStart)))
	p.activeConns.Add(1)
	p.totalConns.Add(1)
	defer p.activeConns.Add(-1)

	if readyCh != nil && !*signaled {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	*signaled = true
	p.signalBootstrapDone(nil)

	p.noteSessionUp(connIdx) // the retry floor's evidence that the network works — retryfloor.go
	log.Printf("proxy: [conn %d, cred %d] WRAP-A+TURN session established (getconf ok)", connIdx, credSlot)

	if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
		p.lastPongTimes[connIdx].Store(time.Now().Unix())
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Transport keepalive: a 1-byte packet every 20s keeps amurcanov's
	// per-conn DTLS session from idling out. With NumConns conns sharing ONE
	// WG device, most conns rarely carry a WG packet, so WG's own 25s
	// keepalive (which rides only one random conn) can't keep them all alive.
	// The server treats a 1-byte read as a transport keepalive; even if it
	// forwarded the byte to WireGuard, WG drops it as a malformed message.
	// We skip 1-byte reads on the recv side below.
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		ka := []byte{0x00}
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				dtlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, werr := dtlsConn.Write(ka); werr != nil {
					return
				}
			}
		}
	}()

	// Send: sendCh → dtlsConn (shared across all conns; WG packets land on
	// whichever conn's goroutine grabs them).
	go func() {
		defer wg.Done()
		defer connCancel()
		// One closure per connection, not per packet — see the SRTP send
		// goroutine for why.
		writeOne := func(pkt []byte, now time.Time) error {
			dtlsConn.SetWriteDeadline(now.Add(30 * time.Second))
			_, werr := dtlsConn.Write(pkt)
			return werr
		}
		for {
			// 🚨 RESERVE BEFORE THE DEQUEUE — see uplinkpace.go.
			ticket := p.paceReserve(connIdx)
			select {
			case <-connCtx.Done():
				p.paceSettle(ticket, 0)
				return
			case item := <-p.sendCh:
				p.paceSettle(ticket, len(item.buf))
				// -1: no per-conn TX accounting at this site today.
				if err := p.writePacket(item, -1, writeOne); err != nil {
					log.Printf("proxy: [conn %d] WRAP-A send: write error: %v", connIdx, err)
					return
				}
			}
		}
	}()

	// Receive: dtlsConn → recvCh. Mirrors runDTLSSession's global-health
	// staleness handling (don't kill a conn that simply didn't get packets;
	// only reconnect when the whole tunnel is stale) + iOS-freeze detection.
	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			deadlineSetAt := time.Now()
			dtlsConn.SetReadDeadline(deadlineSetAt.Add(30 * time.Second))
			n, rerr := dtlsConn.Read(buf)
			if rerr != nil {
				if connCtx.Err() != nil {
					return
				}
				if strings.Contains(rerr.Error(), "timeout") || strings.Contains(rerr.Error(), "deadline exceeded") {
					elapsed := time.Since(deadlineSetAt)
					if elapsed > 90*time.Second {
						log.Printf("proxy: [conn %d] WRAP-A read elapsed %s (freeze detected), resetting lastRecvTime",
							connIdx, elapsed.Round(time.Second))
						p.lastRecvTime.Store(time.Now().Unix())
						continue
					}
					lastRecv := p.lastRecvTime.Load()
					if lastRecv > 0 && time.Since(time.Unix(lastRecv, 0)) < 3*time.Minute {
						continue
					}
					log.Printf("proxy: [conn %d] WRAP-A read timeout, tunnel stale, reconnecting", connIdx)
					return
				}
				log.Printf("proxy: [conn %d] WRAP-A read error: %v", connIdx, rerr)
				return
			}
			// Skip the server's 1-byte transport keepalive — it must NOT reach
			// WireGuard (which would treat it as an invalid message type).
			if n <= 1 {
				continue
			}
			p.lastRecvTime.Store(time.Now().Unix())
			pkt := recvPktPoolGet(n)
			copy(pkt, buf[:n])
			if !p.enqueueRecv(connCtx, pkt) {
				recvPktPoolPut(pkt)
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// dialDTLSWrapA dials a plain DTLS client over the WRAP-A transport using
// amurcanov's exact config (single cipher TLS_ECDHE_ECDSA_WITH_AES_128_GCM_
// SHA256, RequireExtendedMasterSecret, send-only 8-byte ConnectionID — from
// his go_client/session.go, mirrored in tools/wrapa_test). One handshake
// retry: M3 saw a transient ~20s handshake timeout from UDP loss on the first
// attempt that cleared on retry.
func dialDTLSWrapA(ctx context.Context, transport net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dconn, derr := dtls.Client(transport, peer, config)
		if derr != nil {
			lastErr = derr
			continue
		}
		hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		herr := dconn.HandshakeContext(hsCtx)
		cancel()
		if herr == nil {
			return dconn, nil
		}
		_ = dconn.Close()
		lastErr = herr
		if ctx.Err() != nil {
			break
		}
		log.Printf("proxy: WRAP-A DTLS handshake attempt %d failed: %v — retrying", attempt, herr)
	}
	return nil, lastErr
}

// storeWrapAProvision records the server-minted WireGuard config exactly once
// (the first runWrapASession to finish GETCONF) and wakes any
// WaitWrapAProvision callers by closing wrapAProvCh.
func (p *Proxy) storeWrapAProvision(prov *WrapAProvision) {
	p.wrapAProvOnce.Do(func() {
		p.wrapAProv.Store(prov)
		if p.wrapAProvCh != nil {
			close(p.wrapAProvCh)
		}
		log.Printf("proxy: WRAP-A provisioned: addr=%s dns=%s mtu=%d keepalive=%d",
			prov.Address, prov.DNS, prov.MTU, prov.KeepaliveSec)
	})
}

// WaitWrapAProvision blocks until WRAP-A GETCONF provisioning has produced the
// server-minted WireGuard config, the proxy stopped, or the timeout expired.
// The bridge calls this after WaitBootstrap to build the WG UAPI + iOS network
// settings from server-provided crypto.
func (p *Proxy) WaitWrapAProvision(timeout time.Duration) (*WrapAProvision, error) {
	if p.wrapAProvCh == nil {
		return nil, fmt.Errorf("WRAP-A not enabled")
	}
	select {
	case <-p.wrapAProvCh:
		return p.wrapAProv.Load(), nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("WRAP-A provision timeout after %s", timeout)
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

// addrFamilyFor returns the TURN REQUESTED-ADDRESS-FAMILY matching the peer's
// IP family. The relayed allocation MUST be the same family as the peer it
// sends to: RFC 8656 §9.2 rejects a CreatePermission whose family differs from
// the allocation with 443 (Peer Address Family Mismatch). VK has no IPv6
// relays, so an IPv6 peer yields an IPv6 allocate request that VK silently
// drops — but requesting the *correct* family (rather than hardcoding IPv4,
// which 443s on an IPv6 peer — issue #39) keeps both transport paths
// consistent and makes the failure honest (a timeout meaning "no IPv6 relay"
// instead of a misleading mismatch). Also future-proofs IPv6 if VK ever adds
// IPv6 relays.
func addrFamilyFor(peer *net.UDPAddr) turn.RequestedAddressFamily {
	if peer != nil && peer.IP.To4() == nil {
		return turn.RequestedAddressFamilyIPv6
	}
	return turn.RequestedAddressFamilyIPv4
}

// runTURN establishes a TURN relay and forwards packets between conn2 and the relay.
// Runs until the relay fails or ctx is cancelled. No forced lifetime —
// the pion/turn client handles allocation refresh automatically.
// conn2's deadline is reset before returning so it can be reused.
func (p *Proxy) runTURN(ctx context.Context, turnAddr string, creds *TURNCreds, conn2 net.PacketConn, connIdx int, slotIdx int, gave *gaveBack) error {
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
		// Registered AFTER the Close defer, so LIFO runs unregister FIRST and
		// the sampler can never hold a socket that is being torn down.
		p.sockStats.register(connIdx, tcpConn)
		defer p.sockStats.unregister(connIdx)
		turnConn = turn.NewSTUNConn(tcpConn)
	}

	// Determine the relay address family from the peer (see addrFamilyFor).
	addrFamily := addrFamilyFor(p.peer)

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Username:               creds.Username,
		Password:               creds.Password,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          &turnLoggerFactory{proxy: p, slot: slotIdx},
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
	// The relay accepted this identity: mark it NOW, before anything
	// downstream — the permission, a handshake, the session above — can be
	// delayed or fail. The mark means the allocation, not the session, and it
	// names the CREDENTIAL, not the slot: the slot may have been refilled
	// while the relay's answer was in flight, and a late success of the old
	// credential must not certify the new one (quotabreaker.go; builds 391
	// and 392, both caught on the user's control stand).
	p.credPool.noteAllocated(slotIdx, creds)
	if p.directMode() {
		// The direct session has nothing above the relay: the allocation is the
		// session coming up — the retry floor's evidence that the network works
		// (retryfloor.go). The other three transports stamp it where their
		// handshake over the relay has completed.
		p.noteSessionUp(connIdx)
	}
	// The allocation is given back by ONE body (returnAllocation, seatcool.go).
	// Over a UDP relay leg first the deallocate the relay CONFIRMS: this function
	// returns after the relay's answer, not ahead of a datagram (dealloc.go) — and
	// so does the session above, which JOINS this goroutine before it returns and
	// gives its credential back (relayjoin.go), and only then its restart. Then
	// the relay conn's own Close; and the moment is NOTED for the pool, which
	// keeps counting the seat for the relay's second.
	var release func() deallocVerdict
	if p.config.UseUDP {
		release = func() deallocVerdict { return p.releaseAllocation(client, creds, connIdx) }
	}
	defer func() { _ = returnAllocation(relayConn, release, gave) }()
	// Registered AFTER it, so LIFO runs it FIRST: what returnAllocation writes
	// goes out under relayCloseWriteBudget on the control socket, instead of
	// holding this goroutine (and the socket below it) for ever on a TCP relay
	// that stopped taking bytes.
	defer func() { _ = turnConn.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget)) }()
	p.turnRTTns.Store(int64(time.Since(allocStart)))

	// Log turnConn.LocalAddr() too — this is the source address the OS kernel
	// picked for our outbound UDP socket. On iOS it tells us which interface
	// the Network Extension is using (cellular CGNAT like 10.x.x.x vs WiFi
	// local range like 192.168.x.x), which is otherwise invisible and
	// critically affects which source IP VK TURN sees.
	localAddrStr := turnConn.LocalAddr().String()
	log.Printf("proxy: [conn %d] TURN relay allocated: %s (RTT %dms, local=%s)",
		connIdx, relayConn.LocalAddr(), time.Since(allocStart).Milliseconds(), localAddrStr)

	// Stash the local IP (without port) so logPathStatsLoop can compare
	// per-conn allocation-time IPs against the current OS default route
	// once a minute. Discrepancy = iOS routing has shifted under us
	// without any [PathMonitor] event firing. Cleared on this conn's
	// runTURN exit (success or failure path) so pathstats only counts
	// currently-allocated conns.
	if localHost, _, splitErr := net.SplitHostPort(localAddrStr); splitErr == nil &&
		connIdx >= 0 && connIdx < len(p.connLocalIPs) {
		p.connLocalIPs[connIdx].Store(localHost)
		defer p.connLocalIPs[connIdx].Store("")
	}

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
	hookDone := make(chan struct{}) // closed when the cancel hook has run to its end
	stopHook := context.AfterFunc(turnCtx, func() {
		defer close(hookDone)
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
		// The forwarder toward the relay may be INSIDE a write the relay
		// will never complete — a full TCP send buffer toward the interface
		// a path change just took away. Neither deadline above reaches it
		// (pion's relay conn maps SetDeadline to reads only), and the
		// deallocate's deadline defer runs only after wg.Wait, which that
		// very forwarder holds; the session above restarts without waiting
		// and the goroutine, this socket and the pion client would leak
		// until the kernel failed the write. So the write is bounded HERE,
		// at the cancel, on the control socket we own (user's review,
		// 2026-09-07: the defer was unreachable while the sender sat in
		// Write). This path carries DTLS, WRAP, WRAP-A and WRAP-S. The
		// deadline is in the PAST: nothing this session writes after the
		// cancel is wanted (the deallocate gets its own budget in the defer
		// above, set after wg.Wait), so a stuck write returns now rather
		// than in 500 ms — and, set BEFORE the Close below, it also fails
		// the first write of any transaction registered AFTER that Close
		// (the user's review of 394: cancel → Close → a fresh
		// CreatePermission registers → pion's whole ladder).
		_ = turnConn.SetWriteDeadline(time.Now())
		// The forwarder may instead be WAITING in a transaction — the
		// permission pion asks for on the first packet to the peer, against
		// a relay that took the allocation and answers nothing more. No
		// deadline reaches that wait; until build 394 it ended only when
		// pion's next retransmit write failed the deadline — the rtx ladder
		// 200 → 400 → 800 → 1600 ms, 1.1–2.1 s after the cancel (Sep 6 §63's
		// narrower window). Closing the client closes its transaction map
		// and nothing else — the socket stays ours for the deallocate — and
		// a closed transaction returns errTransactionClosed at once; the
		// deferred Close after wg.Wait is then a no-op. Deadline first, then
		// Close: whichever of the two a late transaction meets, it ends.
		client.Close()
	})

	var peerAddr atomic.Value

	// WRAP layer (see pkg/proxy/wrap.go): when enabled, every UDP datagram
	// that crosses the conn2 ↔ relay boundary is wrapped in an SRTP-shaped
	// envelope (RTP header + explicit nonce + ChaCha20-Poly1305 AEAD
	// ciphertext + tag) so VK's TURN-relay payload classifier matches it
	// as RTP media and forwards it on the fast path instead of shaping /
	// blackholing on a DTLS+WG signature. Both directions MUST run the
	// matching cipher — server must be invoked with -wrap-srtp + -wrap-key.
	//
	// Per-conn cipher state (seq, ts, SSRC, sessionID, counter) lives in
	// the wrapConn. We create ONE wrapConn per runTURN invocation (i.e.
	// per relayed PacketConn lifetime); both TX and RX goroutines share it
	// via atomic increments — the AEAD object itself is thread-safe.
	useWrap := p.config.UseWrap
	var wc *wrapConn
	if useWrap {
		var werr error
		// isServer=false: client side clears the direction MSB in
		// sessionID/SSRC. Server sets it.
		wc, werr = newWrapConn(p.config.WrapKey, false)
		if werr != nil {
			log.Printf("proxy: [conn %d] runTURN: wrap init failed: %v — disabling WRAP for this conn", connIdx, werr)
			useWrap = false
		}
	}

	// SRTP-WRAP-S (samosvalishe/free-turn-proxy): same wrap layer, but the codec
	// is chosen by obf-profile (rtpopus/rtpopus2/rtpopus3). Parallel to the
	// useWrap branch above so the existing SRTP-WRAP path is untouched. The
	// Client-ID record is sent inside DTLS in runDTLSSession, not here.
	useWrapS := p.config.UseWrapS
	var wcs WrapCodec
	if useWrapS {
		var werr error
		wcs, werr = NewWrapCodec(p.config.ObfProfile, p.config.WrapKey, false)
		if werr != nil {
			log.Printf("proxy: [conn %d] runTURN: wrap-S init failed: %v — disabling WRAP-S for this conn", connIdx, werr)
			useWrapS = false
		}
	}

	// conn2 → relay
	// No select{default} polling — context cancellation is handled via deadline
	// set in context.AfterFunc above, which unblocks ReadFrom.
	go func() {
		defer wg.Done()
		defer turnCancel()
		buf := make([]byte, 1600)
		// Per-goroutine TX wire buffer: reused across iterations so we
		// don't allocate per-packet during the hot path. Sized for the
		// worst-case payload + WRAP overhead.
		var wireBuf []byte
		if useWrap {
			wireBuf = make([]byte, wrapMaxWire(1600))
		}
		if useWrapS {
			wireBuf = make([]byte, wcs.Overhead()+1600)
		}
		for {
			n, addr, err := conn2.ReadFrom(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: ReadFrom error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			peerAddr.Store(addr)
			out := buf[:n]
			if useWrap {
				wn, werr := wc.wrapInto(wireBuf, buf[:n])
				if werr != nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: wrap error: %v", connIdx, werr)
					return
				}
				out = wireBuf[:wn]
			}
			if useWrapS {
				wn, werr := wcs.WrapInto(wireBuf, buf[:n])
				if werr != nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: wrap-S error: %v", connIdx, werr)
					return
				}
				out = wireBuf[:wn]
			}
			if _, err = relayConn.WriteTo(out, p.peer); err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN conn2→relay: WriteTo error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			// Per-conn TX byte counter for diagnostic — count the
			// pre-WRAP application-layer bytes (DTLS records that came
			// out of conn2), not the wire bytes including overhead. This
			// matches what an external observer counting WireGuard
			// throughput would see.
			if connIdx >= 0 && connIdx < len(p.connTxBytes) {
				p.connTxBytes[connIdx].Add(int64(n))
				// lastTxAt tracks data-path activity for skip-on-recent-tx
				// wake-probe optimization. Probe Writes (dtlsConn.Write
				// from the probe goroutine) don't pass through this site
				// so they don't mark the conn as "recently active".
				p.lastTxAt[connIdx].Store(time.Now().UnixNano())
			}
		}
	}()

	// relay → conn2
	go func() {
		defer wg.Done()
		defer turnCancel()
		// Read into a slightly larger buffer when WRAP is on so we have
		// room for the 40-byte overhead (RTP+nonce+tag) on top of the
		// worst-case 1600-byte DTLS payload we forward to conn2.
		readBufLen := 1600
		if useWrap {
			readBufLen += wrapOverhead
		}
		if useWrapS {
			readBufLen += wcs.Overhead()
		}
		buf := make([]byte, readBufLen)
		// Plaintext destination buffer for unwrap. Sized for the same
		// 1600-byte upper bound conn2 expects to see.
		plain := make([]byte, 1600)
		for {
			n, _, err := relayConn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: ReadFrom error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			payload := buf[:n]
			if useWrap {
				m, werr := wc.unwrapPacket(buf[:n], plain)
				if werr != nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: unwrap error: %v (n=%d)", connIdx, werr, n)
					// Drop and continue rather than tearing down the TURN
					// session for one bad packet — typically just a stray
					// from before the WRAP-side server (or wrong key) was up.
					continue
				}
				payload = plain[:m]
			}
			if useWrapS {
				m, werr := wcs.UnwrapPacket(buf[:n], plain)
				if werr != nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: unwrap-S error: %v (n=%d)", connIdx, werr, n)
					continue
				}
				payload = plain[:m]
			}
			addr, ok := peerAddr.Load().(net.Addr)
			if !ok {
				log.Printf("proxy: [conn %d] runTURN relay→conn2: peerAddr not set, exiting", connIdx)
				return
			}
			if _, err = conn2.WriteTo(payload, addr); err != nil {
				if ctx.Err() == nil {
					log.Printf("proxy: [conn %d] runTURN relay→conn2: WriteTo error: %v (ctx=%v)", connIdx, err, ctx.Err())
				}
				return
			}
			// Per-conn RX byte counter for diagnostic — count the
			// post-UNWRAP application-layer bytes (DTLS records being
			// handed back to conn2), symmetric with the TX direction.
			if connIdx >= 0 && connIdx < len(p.connRxBytes) {
				p.connRxBytes[connIdx].Add(int64(len(payload)))
				// lastRxAt mirrors lastTxAt update at the TX site — see
				// connTxBytes block above for rationale.
				p.lastRxAt[connIdx].Store(time.Now().UnixNano())
			}
		}
	}()

	wg.Wait()
	// The deferred teardown re-arms a live budget for the deallocate — and
	// the cancel hook may still be RUNNING here: a forwarder exits on the
	// hook's first deadline and wg.Wait returns before its later steps, so
	// the hook's past write deadline could land AFTER the budget and fail
	// the deallocate on a healthy relay, leaving the allocation on the quota
	// for its lifetime (the user's review of 395). The hook is stopped, or
	// waited for, before anything below touches a deadline.
	turnCancel()
	if !stopHook() {
		<-hookDone
	}
	// Reset conn2 deadline so it can be reused by the next TURN session.
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
	return nil
}

// dialDTLS establishes a DTLS connection using the given PacketConn as transport.
// logConnStatsLoop ticks every 60s and emits a per-conn TX/RX byte
// breakdown to the log. Diagnostic-only; meant to surface throughput
// asymmetry across the conn pool that a global TxBytes/RxBytes can't
// show. For example, if 5 of 50 conns are stuck in a partially-shaped
// VK relay state and contribute almost nothing to a speedtest, the
// dump makes it obvious which connIdx values are the slow ones.
//
// Output format (one block per tick) includes per-conn lines sorted by
// total throughput in the interval, plus a summary line listing the
// number of "idle" conns (combined <1 KB in interval) so post-hoc
// grep can quickly count them. Final dump on tunnel shutdown captures
// session totals in one place.
//
// Approximately 50 lines per minute at NumConns=50 — noisy compared to
// stability metrics but a tiny fraction of the pion debug volume (which
// can produce hundreds of lines per second under churn). Acceptable for
// always-on diagnostic.
func (p *Proxy) logConnStatsLoop(ctx context.Context) {
	const interval = 60 * time.Second

	// Snapshot of the previous tick's cumulative counters, used to
	// compute deltas. Zero-initialised so the first tick reports
	// since-spawn totals as the delta — consistent with subsequent
	// per-interval semantics.
	n := len(p.connTxBytes)
	prevTx := make([]int64, n)
	prevRx := make([]int64, n)
	prevTime := time.Now()

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final dump on shutdown — captures whatever fragment of
			// interval was in progress so the last data point isn't
			// lost. Computes against the same prevTime so the rate
			// number stays meaningful even for a partial interval.
			p.dumpConnStats(prevTx, prevRx, prevTime, "final")
			return
		case t := <-tick.C:
			p.dumpConnStats(prevTx, prevRx, prevTime, "tick")
			// Refresh snapshot for next tick.
			for i := 0; i < n; i++ {
				prevTx[i] = p.connTxBytes[i].Load()
				prevRx[i] = p.connRxBytes[i].Load()
			}
			prevTime = t
		}
	}
}

// dumpConnStats emits one log block. Format:
//
//	conn-stats <label> over Xs (NumConns=N):
//	  conn  3:  TX  256.0 KB/s ( 15.4 MB cum)  RX 1.20 MB/s ( 72.0 MB cum)
//	  conn  7:  TX  ...
//	  ...
//	  summary: <K idle> (combined <1KB in interval), top conn TX <X>, RX <Y>
//
// Idle threshold of 1 KB combined catches stuck-mode (~9 KB/s × 60s =
// 540 KB) as not-idle, which is intentional — we want to see those in
// the per-conn list, not bucket them away.
func (p *Proxy) dumpConnStats(prevTx, prevRx []int64, prevTime time.Time, label string) {
	n := len(p.connTxBytes)
	if n == 0 {
		return
	}
	now := time.Now()
	dur := now.Sub(prevTime).Seconds()
	if dur < 0.1 {
		dur = 0.1 // avoid divide-by-zero / nonsensical rates on instant final dump
	}

	type row struct {
		idx          int
		tx, rx       int64 // delta in interval
		txCum, rxCum int64
	}
	rows := make([]row, n)
	idle := 0
	for i := 0; i < n; i++ {
		txCum := p.connTxBytes[i].Load()
		rxCum := p.connRxBytes[i].Load()
		dTx := txCum - prevTx[i]
		dRx := rxCum - prevRx[i]
		rows[i] = row{idx: i, tx: dTx, rx: dRx, txCum: txCum, rxCum: rxCum}
		if dTx+dRx < 1024 {
			idle++
		}
	}
	// Sort descending by combined delta — the busy conns surface at top.
	sort.Slice(rows, func(i, j int) bool {
		return (rows[i].tx + rows[i].rx) > (rows[j].tx + rows[j].rx)
	})

	// Emit one log entry per line, not one big buffer. iOS os_log /
	// idevicesyslog truncates entries past ~1 KB, which silently loses
	// most of a 50-conn block when buffered into a single Write. The
	// underlying async file writer (logChan, buffered 512) handles 50+
	// rapid writes per tick without back-pressure.
	log.Printf("proxy: conn-stats %s over %.1fs (NumConns=%d):", label, dur, n)
	for _, r := range rows {
		log.Printf("  conn %2d:  TX %s/s (%s cum)  RX %s/s (%s cum)",
			r.idx,
			humanBytes(int64(float64(r.tx)/dur)),
			humanBytes(r.txCum),
			humanBytes(int64(float64(r.rx)/dur)),
			humanBytes(r.rxCum))
	}
	log.Printf("  summary: %d idle (combined <1KB in interval), top TX %s/s, top RX %s/s",
		idle,
		humanBytes(int64(float64(rows[0].tx)/dur)),
		humanBytes(int64(float64(rows[0].rx)/dur)))
}

// TaskVMInfo carries the iOS-side process memory accounting fields
// pulled from Mach task_info(TASK_VM_INFO_DATA). All values in bytes.
//
// Field semantics:
//   - PhysFootprint: what iOS jetsam evaluates against the NE per-process
//     memory budget (~50 MB hard cap). The headline number — same as
//     the old `PhysFootprintFn` returned.
//   - Internal: private/anonymous resident pages — Go heap, Swift heap,
//     kernel mbufs attributed to the process. Growth here without a
//     corresponding Go `sys` rise points at non-Go allocation
//     (Swift host code, CFNetwork, NEPacketTunnelProvider framework,
//     mbuf clusters for in-flight TUN traffic).
//   - External: file-backed mappings — binary text, frameworks, dyld.
//     Should be roughly stable; sharp changes hint framework
//     load/unload (rare in a long-running NE).
//   - Reusable: pages marked MADV_FREE'd (kernel can reclaim them
//     without IO). Go's `heap-released` should be a subset
//     (Go releases idle heap this way). If Reusable >> heap-released,
//     something else is also freeing pages.
//   - Compressed: kernel-compressed (swapped) pages. Growth here means
//     system-wide pressure pushed our pages out of physical RAM into
//     compressed swap. Often a sign other apps are crowding us.
//
// Added 2026-05-26 (build 138) for finer-grained jetsam attribution
// after we observed phys_footprint silently growing ~28 MB in <50s
// during pure idleness (2026-05-26 16:26:45 kill) with no visible
// log activity — the standard memstats line couldn't tell us whether
// the growth was Go-side or non-Go.
type TaskVMInfo struct {
	PhysFootprint uint64
	Internal      uint64
	External      uint64
	Reusable      uint64
	Compressed    uint64
}

// TaskVMInfoFn, if set by the embedding application, returns the
// current process's task_vm_info breakdown. On iOS this is wired up
// via the C bridge calling task_info(TASK_VM_INFO_DATA). Single call
// per sample so all fields come from the same atomic kernel snapshot.
//
// PhysFootprint is the SAME number iOS jetsam evaluates against the
// NE per-process memory budget. runtime.MemStats.Sys reports only
// Go-side allocation — on Darwin it overstates the resident footprint
// because madvise(MADV_FREE_REUSABLE) marks pages reclaimable but
// doesn't immediately reduce RSS, so Sys stays at a high-water mark.
// PhysFootprint cuts through that ambiguity, and the Internal/External/
// Reusable/Compressed breakdown distinguishes Go from non-Go drivers.
//
// Set to nil = unavailable, in which case the memstats logger writes
// "rss=n/a" and omits the breakdown fields. No global lock — set
// once at startup before the loop runs.
var TaskVMInfoFn func() TaskVMInfo

// logMemStatsLoop ticks every 10s (was 60s pre-build-138 — bumped for
// finer-grained jetsam-spike attribution after observing phys_footprint
// silently growing 22→50 MB in <50s on 2026-05-26 16:26:45 between
// two 60s samples, leaving us blind to the spike shape) and emits
// one runtime.MemStats + task_vm_info line per tick. Diagnostic for
// the "silent extension kill" failure mode where iOS jetsam terminates
// the NetworkExtension without warning when the process approaches
// the ~50 MB hard per-process memory budget.
//
// Output format (one line per tick):
//
//	memstats rss=23.4 MB vm-internal=18.2 MB vm-external=4.1 MB
//	  vm-reusable=15.0 MB vm-compressed=2.3 MB sys=46.1 MB
//	  heap-alloc=12.1 MB heap-inuse=14.2 MB heap-idle=22.3 MB
//	  heap-released=18.0 MB stack=6.0 MB heap-objects=24813
//	  goroutines=312 numGC=42
//
// What to look for:
//
// Process-level (from Mach task_vm_info, full-process accounting):
//   - rss:            phys_footprint via Mach task_info — what iOS
//     jetsam actually evaluates. The headline number;
//     "n/a" if TaskVMInfoFn isn't wired up.
//   - vm-internal:    private/anonymous resident pages — Go heap +
//     Swift heap + kernel mbufs + framework state.
//     Growth here without Go `sys` rising points at
//     non-Go allocation (CFNetwork, mbufs, Swift host).
//   - vm-external:    file-backed mappings — binary, frameworks, dyld.
//     Should be roughly stable; sharp changes hint
//     framework load/unload.
//   - vm-reusable:    pages MADV_FREE'd (kernel can reclaim). Go's
//     heap-released is a subset. If vm-reusable >>
//     heap-released, something non-Go is also freeing.
//   - vm-compressed:  kernel-compressed (swapped) pages. Growth = we
//     got pushed into compressed swap due to system-
//     wide pressure (often other apps crowding us).
//
// Go runtime (from runtime.MemStats, Go-only accounting):
//   - sys:            bytes Go mapped from the OS. On Darwin overstates
//     resident by 10-20 MB because released pages stay
//     in the address space until kernel reclaim.
//   - heap-alloc:     bytes of currently-live heap objects.
//   - heap-inuse:     in-use spans (>= heap-alloc; gap is fragmentation
//     or retained-but-not-live within active spans).
//   - heap-idle:      bytes in idle (unused) spans, candidates for
//     return-to-OS.
//   - heap-released:  bytes Go has explicitly released to the OS via
//     madvise. heap-released growing alongside churn
//     = scavenger working; stuck at zero while sys
//     climbs = scavenger lazy.
//   - stack:          total stack memory (NumConns × per-conn goroutines
//     × 8 KB initial). Not affected by GOMEMLIMIT.
//   - heap-objects:   count of live objects (rises with allocation
//     leaks even when alloc bytes look stable).
//   - goroutines:     leak indicator; should stabilise at roughly
//     NumConns × small-constant once startup settles.
//   - numGC:          GC cycle count; high deltas between ticks mean
//     heavy alloc churn even if heap-alloc is steady.
//
// Correlation playbook for jetsam attribution:
//   - rss rising + sys rising together → Go-side allocation. Look at
//     heap-alloc, heap-objects, stack for the source.
//   - rss rising + sys flat → non-Go allocation. Check vm-internal
//     delta (probably the same magnitude as rss delta). If so, it's
//     Swift / framework / mbuf accumulation we can't see from Go.
//   - vm-compressed rising → system memory pressure, not our fault.
//     Check for unrelated jetsam events in sysdiagnose PowerLog.
//
// Final dump on shutdown captures the moment-of-death snapshot in
// the same place — useful when comparing pre-kill state across
// multiple jetsam incidents.
// memstatsFastTicks forces the 1 s memstats cadence for as long as it is set,
// independently of the ALLOC-SPIKE window below. Process-global like
// forceLegacyCaptcha, and for the same reason: the app and the extension are
// separate processes with their own copy of this library.
//
// 🎯 WHY IT EXISTS. The 1 s cadence is what makes the tunnel readable at the
// timescale the upload question lives at — the phone's offer against the
// server's ΣUP, second by second (2026-08-11). Until now it could only be
// reached by TRIPPING AN ALLOC-SPIKE, i.e. at moments chosen by the garbage
// collector rather than by whoever is running the measurement: of the three
// A/B logs collected that night, one had 1 s ticks over the interesting burst,
// one had them over the dead gap between runs, and one had none at all.
// A diagnostic you cannot aim is not an instrument.
var memstatsFastTicks atomic.Bool

// SetMemstatsFastTicks turns the forced 1 s cadence on or off. Safe at any time:
// the loop re-reads it every tick, so switching it on mid-session costs at worst
// one 10 s tick of latency and never a reconnect — which matters, because a
// reconnect tears down the thirty sessions and with them the very session
// being measured.
func SetMemstatsFastTicks(on bool) { memstatsFastTicks.Store(on) }

// memstatsCadence picks the tick interval, and is the ONLY thing that does.
//
// 🚨 It is a separate function so the rule is testable and so there is exactly
// one of it. Before build 229 the ALLOC-SPIKE path reset the ticker itself; add
// a second reason to be at 1 s and the two undo each other — a spike landing
// while the switch is on would drop back to 10 s when the SPIKE's window closed,
// silently coarsening a measurement already in progress, with nothing in the log
// that says so. The forced switch therefore outranks the window, and the window
// closing is not by itself a reason to slow down.
// memstatsForcedNote explains a change of the Diagnostics switch that does NOT
// move the cadence — the one case where the log would otherwise show the switch
// changing and nothing happening.
//
// 🚨 THE REPORT THIS CAME FROM (2026-08-11). The switch was turned off at
// 15:25:46 and the 1s lines kept coming; the run was read as "turning it off
// does not work". It did work — an ALLOC-SPIKE at 15:25:29 held the window open
// until 15:25:59, and the tunnel was stopped at 15:25:52, seven seconds before
// the revert would have been logged. Reconstructing that took the log, the spike
// list and arithmetic. The instrument should have said it.
//
// 🚫 The alternative fix — letting the switch cancel the spike window — was
// rejected: that window is the jetsam diagnostic, it predates this switch and
// has nothing to do with it, and a logging preference must not quietly disarm an
// unrelated safety net. The wait is bounded by the window, ≤30 s.
func memstatsForcedNote(forced, fast bool, windowLeft time.Duration) string {
	switch {
	case !forced && fast:
		return fmt.Sprintf("switch OFF, but staying at 1s for up to %s — the "+
			"ALLOC-SPIKE window is still open. This is the spike heuristic, not the switch.",
			windowLeft.Round(time.Second))
	case forced && fast:
		return "switch ON, already at 1s (an ALLOC-SPIKE window was open)"
	default:
		return ""
	}
}

func memstatsCadence(forced, inSpikeWindow bool, normal, fast, spikeWindow time.Duration) (time.Duration, string) {
	switch {
	case forced:
		return fast, "forced by the Diagnostics switch"
	case inSpikeWindow:
		return fast, "ALLOC-SPIKE window, " + spikeWindow.String()
	default:
		return normal, ""
	}
}

func (p *Proxy) logMemStatsLoop(ctx context.Context) {
	const normalInterval = 10 * time.Second
	const highFreqInterval = 1 * time.Second
	const highFreqDuration = 30 * time.Second
	// Alert threshold for heap-alloc growth between consecutive ticks.
	// Empirically (2026-05-27 09:45:29→09:45:39) jetsam was preceded by
	// heap-alloc +6.6 MB then +10.6 MB tick-over-tick. 5 MB is a tight
	// gate that catches the spike pattern without triggering on normal
	// fluctuation (typical tick-delta is ±2 MB under steady idle).
	//
	// ⚠️ IT IS A PER-TICK DELTA, AND SINCE BUILD 230 THE TICK LENGTH IS A
	// VARIABLE. The 5 MB was calibrated against 10 s ticks; at 1 s it is a
	// tenfold stricter growth RATE, and it samples the GC sawtooth rather than
	// averaging over several cycles. So spike counts are not comparable between
	// the two cadences — a definitional consequence, not a measured one. 🚨 The
	// 2026-08-11 log that raised the question cannot settle which way it goes:
	// every loaded tick in it came after the switch was already on, so it has no
	// 10 s control. Do not read a spike rate across cadences without one.
	const allocSpikeThreshold = 5 * 1024 * 1024 // 5 MB

	tick := time.NewTicker(normalInterval)
	defer tick.Stop()
	// The cadence the ticker is currently on. Kept explicitly so the single
	// decision point below resets the ticker only when it actually changes —
	// a Reset on every tick would re-phase the 1 s cadence continuously.
	curInterval := normalInterval

	// Previous-tick state for delta computation. Captured by closure
	// across dump() calls.
	var prevTxPkt, prevRxPkt int64
	var prevHeapAlloc uint64

	// Triggered high-frequency mode (build 141). When an ALLOC-SPIKE is
	// detected, switch to 1s cadence for the next 30s — captures what
	// happens in the 10s slice between standard ticks where we've
	// historically observed jetsam-preceding bursts but had no
	// instrumentation (e.g. 2026-05-27 16:58:19 last snapshot → 16:58:37
	// kill = 18s blind window). Each new spike inside the high-freq
	// window resets the 30s countdown so sustained spike patterns keep
	// detailed instrumentation. Reverts to 10s cadence after the window
	// expires with no further spikes.
	var inHighFreq bool
	var highFreqUntil time.Time
	// Previous state of the Diagnostics switch, so a change that does NOT move
	// the cadence can still be explained — see memstatsForcedNote.
	var prevForced bool

	dump := func(label string) {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		rssStr := "n/a"
		internalStr := "n/a"
		externalStr := "n/a"
		reusableStr := "n/a"
		compressedStr := "n/a"
		if TaskVMInfoFn != nil {
			vm := TaskVMInfoFn()
			// PhysFootprint > 0 is our "task_info syscall succeeded"
			// sentinel: the C bridge returns an all-zero struct on
			// KERN_SUCCESS failure. If the syscall worked, ALL fields
			// are valid measurements (including legitimate 0 — e.g.
			// vm-reusable=0 means "nothing MADV_FREE'd right now",
			// vm-compressed=0 means "no swap pressure yet"). Show 0 B
			// rather than "n/a" so a reader can distinguish measured-zero
			// from no-measurement.
			if vm.PhysFootprint > 0 {
				rssStr = humanBytes(int64(vm.PhysFootprint))
				internalStr = humanBytes(int64(vm.Internal))
				externalStr = humanBytes(int64(vm.External))
				reusableStr = humanBytes(int64(vm.Reusable))
				compressedStr = humanBytes(int64(vm.Compressed))
			}
		}
		// Per-tick packet rate deltas added build 140 for diagnostic of
		// the kernel-buffered packet flood hypothesis. txPkt = WG packets
		// app→tunnel direction (TUN→WG→bind.Send), rxPkt = WG packets
		// tunnel→app direction (bind.Receive→WG→TUN). On the "startup"
		// label both deltas reflect the boot-to-startup window which is
		// trivial so the number is small and meaningless — kept inline
		// for format simplicity. On "tick" labels delta is per-10s.
		curTxPkt := p.txPackets.Load()
		curRxPkt := p.rxPackets.Load()
		txPktDelta := curTxPkt - prevTxPkt
		rxPktDelta := curRxPkt - prevRxPkt
		prevTxPkt = curTxPkt
		prevRxPkt = curRxPkt

		log.Printf("proxy: memstats %s rss=%s vm-internal=%s vm-external=%s vm-reusable=%s vm-compressed=%s sys=%s heap-alloc=%s heap-inuse=%s heap-idle=%s heap-released=%s stack=%s heap-objects=%d goroutines=%d numGC=%d tx-pkt=%d rx-pkt=%d rtpch-peak=%d sendch-peak=%d/%d sendch-block=%s/%d%s%s%s recvch-peak=%d/%d recvch-block=%s/%d%s%s",
			label,
			rssStr,
			internalStr,
			externalStr,
			reusableStr,
			compressedStr,
			humanBytes(int64(ms.Sys)),
			humanBytes(int64(ms.HeapAlloc)),
			humanBytes(int64(ms.HeapInuse)),
			humanBytes(int64(ms.HeapIdle)),
			humanBytes(int64(ms.HeapReleased)),
			humanBytes(int64(ms.StackInuse)),
			ms.HeapObjects,
			runtime.NumGoroutine(),
			ms.NumGC,
			txPktDelta,
			rxPktDelta,
			p.rtpChPeak.Swap(0),
			// Read-and-reset: each line reports the worst backlog seen since
			// the previous line, not the depth at this instant. See the field
			// docs — the instantaneous version read 0 through every loaded
			// period we ever measured, which proved nothing either way.
			p.sendChPeak.Swap(0),
			cap(p.sendCh),
			// Blocked time is the number that settles whether a queue is the
			// limit: the peak can under-report (len() is read after the send,
			// and other consumers drain in between), but waiting either
			// happened or it did not. `0s/0` means the producer was never once
			// made to wait — a real negative result, not a blind one.
			time.Duration(p.sendChBlockNs.Swap(0)).Round(time.Microsecond),
			p.sendChBlockCount.Swap(0),
			// Residence: how long each packet WAITED in sendCh, which neither
			// of the two above can give. Empty when nothing was dequeued.
			// Percentiles are lower bucket edges (250 µs), max is exact — so
			// p50 ≤ p90 ≤ p99 ≤ max must hold, and a violation means the
			// denominator is wrong again. See sendwait.go.
			p.sendWait.summary(),
			// The next leg of the same journey: time spent INSIDE conn.Write.
			// Consecutive with the above, never additive with it — and blind to
			// what happens after Write returns, which is what `sock=` measures.
			p.writeWait.summaryAs("conn-write"),
			// Whether the uplink pacer engaged this interval, and how hard.
			// EMPTY unless the setting is on, so an unpaced tunnel's line is
			// unchanged. `waited=` near zero is the ordinary case under light
			// load, not a fault — see uplinkpace.go before reading it.
			paceSummary(),
			p.recvChPeak.Swap(0),
			cap(p.recvCh),
			time.Duration(p.recvChBlockNs.Swap(0)).Round(time.Microsecond),
			p.recvChBlockCount.Swap(0),
			// Empty unless the TUN wrapper is installed — see tunstats.go. It
			// answers the one question left about the uplink: is wireguard-go
			// STARVED (~100% of its loop inside tun.Read) or SLOW?
			tunReadSummary(),
			// The kernel's own view of the 30 outer sockets — the only thing
			// that can see a packet waiting AFTER Write returned. 🚨 `sb`
			// includes in-flight data by the SDK's own definition; read
			// sockstats.go before quoting it.
			p.sockStats.summary())

		// The downlink's own disorder, on its own line so it can be diffed
		// field-for-field against server1's `reorder(uplink)` line — the two
		// numbers only mean anything next to each other. Silent when no
		// transport packet arrived in the interval. → rxreorder.go
		downlinkReorder.dumpAndReset(time.Now())

		// Alloc-spike alert (build 140): if heap-alloc grew more than
		// allocSpikeThreshold (5 MB) between ticks, emit a dedicated
		// log line with attribution context (packet rates, GC density,
		// goroutine count) so we can post-mortem-attribute the spike
		// even if the kill happens before next tick. Skip on first call
		// (prevHeapAlloc=0 would trigger a false positive on startup).
		//
		// Build 141: spike detection also triggers high-frequency mode —
		// ticker switches to 1s for the next 30s so we capture what
		// happens during the spike's blind window between standard 10s
		// ticks. Each new spike re-extends the high-freq window.
		if prevHeapAlloc > 0 && ms.HeapAlloc > prevHeapAlloc+allocSpikeThreshold {
			gcSinceLastTick := ms.NumGC // can't compute delta without prev — log absolute
			log.Printf("proxy: ALLOC-SPIKE detected — heap-alloc +%s in this tick. tx-pkt=%d rx-pkt=%d goroutines=%d heap-objects=%d numGC=%d (compare to prev tick)",
				humanBytes(int64(ms.HeapAlloc-prevHeapAlloc)),
				txPktDelta,
				rxPktDelta,
				runtime.NumGoroutine(),
				ms.HeapObjects,
				gcSinceLastTick)
			highFreqUntil = time.Now().Add(highFreqDuration)
			inHighFreq = true
		}
		prevHeapAlloc = ms.HeapAlloc

		// The high-freq WINDOW closes on its own. Checked after dumping so the
		// final tick of the window still emits at 1s cadence (catches the last
		// sample before reverting).
		if inHighFreq && time.Now().After(highFreqUntil) {
			inHighFreq = false
		}

		// 🚨 ONE PLACE DECIDES THE CADENCE (build 229). Two independent reasons
		// now want 1 s — the ALLOC-SPIKE window and the Diagnostics switch — and
		// when each reset the ticker itself they could undo each other: a spike
		// landing while the switch was on would drop back to 10 s when ITS
		// window closed, silently ending a measurement in progress with nothing
		// in the log to say why. The switch is re-read every tick, so it needs
		// no reconnect.
		forced := memstatsFastTicks.Load()
		want, why := memstatsCadence(forced, inHighFreq,
			normalInterval, highFreqInterval, highFreqDuration)
		if want != curInterval {
			curInterval = want
			tick.Reset(want)
			if want == highFreqInterval {
				log.Printf("proxy: memstats → 1s cadence (%s)", why)
			} else {
				log.Printf("proxy: memstats → normal cadence (%s)", normalInterval)
			}
		} else if forced != prevForced {
			// The switch moved and the cadence did NOT. Say so, or the log shows
			// "fast ticks = false" followed by 1s lines and no reason.
			if note := memstatsForcedNote(forced, want == highFreqInterval,
				time.Until(highFreqUntil)); note != "" {
				log.Printf("proxy: memstats %s", note)
			}
		}
		prevForced = forced
	}

	// Emit once at startup so we have a baseline anchor for later
	// growth-rate calculations even if the extension is killed before
	// the first tick.
	dump("startup")

	for {
		select {
		case <-ctx.Done():
			dump("final")
			return
		case <-tick.C:
			dump("tick")
		}
	}
}

// pathSnapshotOSDefault returns the OS's current default-route source IP
// for outbound UDP. Implementation: net.Dial("udp", "1.1.1.1:53") doesn't
// actually transmit anything (UDP "connect" just sets the kernel's remote
// for the socket), but it forces the kernel to pick a route and bind a
// local address. We read that, close the socket, and report the IP.
//
// 1.1.1.1:53 is chosen as a stable public IPv4 anycast that exists in any
// routable network (cellular, home wifi, office wifi, captive portal pre-
// auth). We don't care if the actual server responds — we only need the
// route lookup, which happens during connect() in the kernel.
//
// Returns "n/a" if no usable network is up at all (rare on iOS where
// there's almost always at least cellular).
func pathSnapshotOSDefault() string {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return "n/a"
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "n/a"
	}
	return addr.IP.String()
}

// logPathStatsLoop ticks every 60s and emits one path-state snapshot
// per tick. Diagnostic for silent iOS routing changes that don't fire
// a [PathMonitor] event but DO change which interface our existing UDP
// sockets are pinned to (or, more often, which interface a freshly-
// opened UDP socket gets pinned to — at which point our running
// allocations are stranded on a stale path until they fail).
//
// Output format (one line per tick):
//
//	pathstats os-default=192.168.4.21 in-sync=42/50 stale=[10.101.39.17 (8)]
//
// What to look for:
//   - os-default:  current OS-picked source IP for new outbound UDP.
//     Compare across ticks to spot rebinds that didn't
//     fire a [PathMonitor] event.
//   - in-sync:     count of currently-allocated conns whose
//     allocation-time local IP matches os-default. In
//     steady state this should be NumConns/NumConns once
//     bootstrap finishes.
//   - stale:       any local IPs (and conn counts) that don't match
//     os-default. Non-zero stale = some allocations are
//     living on a doomed interface. Empty list if none
//     (omitted from log to keep the line short).
//
// Conns whose connLocalIPs entry is empty (not currently allocated —
// dormant, bootstrap-pending, or just torn down) are excluded from
// both buckets so the in-sync count reflects active state, not history.
// LogPathSnapshot emits one pathstats log line on demand. Same format
// as the periodic logPathStatsLoop but callable from anywhere — used
// by wgLogPathSnapshot bridge so Swift's NWPathMonitor can dump a
// snapshot at the moment of every path transition, not just on the
// 60s tick. Without this, transient interfaces visited during quick
// wifi-lte-wifi handovers are invisible in the pathstats stream
// (e.g. vpn.wifi-lte-wifi.1.log: LTE seen for 20s between two ticks
// at 18:00:45 and 18:01:45, both showing wifi addresses, LTE missed).
//
// Safe to call concurrently with logPathStatsLoop; both just emit
// log lines, no shared mutable state.
// OnPathChange is called from Swift's NWPathMonitor on every real (deduped)
// network-path transition. Forwards to credPool which marks in-use slots
// as pre-emptively saturated. See credPool.MarkInUseSlotsForPathChange
// for the full rationale.
func (p *Proxy) OnPathChange() {
	// The VK client's pooled connections may be bound to the interface this
	// event took away — replace the client before anything mints.
	RotateVKSessionClient()
	if p.credPool != nil {
		p.credPool.MarkInUseSlotsForPathChange()
	}
}

// OnPathTransition is called from Swift's NWPathMonitor when a satisfied
// path event arrives with iface=other (recursive routing fallback —
// typically our own TUN device becoming os-default during the brief gap
// between physical interface changes). Unlike OnPathChange, this does
// NOT trigger smart-pause marking — there are no new active slots to
// mark, the previous physical-iface unsatisfied event already handled
// that. Instead we just extend the pause window so conns don't acquire
// fresh slots during this misleading "recovery" state (which would lead
// to dead allocations + 486 cascade when the real new path eventually
// arrives).
//
// See credPool.ExtendPauseAcquireForTransition for the empirical rationale
// (vpn.over24h.log 2026-05-13 15:26 outage).
func (p *Proxy) OnPathTransition() {
	if p.credPool != nil {
		// 5 seconds covers observed worst-case iface=other window of ~3.3s
		// (vpn.over24h.log 15:26:08 → 15:26:11) with comfortable margin.
		p.credPool.ExtendPauseAcquireForTransition(5 * time.Second)
	}
}

func (p *Proxy) LogPathSnapshot(label string) {
	osDefault := pathSnapshotOSDefault()

	inSync := 0
	stale := map[string]int{}
	active := 0
	for i := range p.connLocalIPs {
		v, _ := p.connLocalIPs[i].Load().(string)
		if v == "" {
			continue // not currently allocated
		}
		active++
		if v == osDefault {
			inSync++
		} else {
			stale[v]++
		}
	}

	if len(stale) == 0 {
		log.Printf("proxy: pathstats %s os-default=%s in-sync=%d/%d",
			label, osDefault, inSync, active)
		return
	}
	// Format stale buckets as [ip1 (n), ip2 (m), ...] — sorted by
	// count desc so the dominant stale IP surfaces first.
	type bucket struct {
		ip    string
		count int
	}
	rows := make([]bucket, 0, len(stale))
	for ip, c := range stale {
		rows = append(rows, bucket{ip, c})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	parts := make([]string, len(rows))
	for i, r := range rows {
		parts[i] = fmt.Sprintf("%s (%d)", r.ip, r.count)
	}
	log.Printf("proxy: pathstats %s os-default=%s in-sync=%d/%d stale=[%s]",
		label, osDefault, inSync, active, strings.Join(parts, ", "))
}

func (p *Proxy) logPathStatsLoop(ctx context.Context) {
	const interval = 60 * time.Second

	tick := time.NewTicker(interval)
	defer tick.Stop()

	p.LogPathSnapshot("startup")

	for {
		select {
		case <-ctx.Done():
			p.LogPathSnapshot("final")
			return
		case <-tick.C:
			p.LogPathSnapshot("tick")
		}
	}
}

// humanBytes renders a byte count with binary units (K / M / G).
// Tuned for the conn-stats dump; same formatting convention as the
// turn_bw_test/turn_bw_server tools so output composes well in
// side-by-side analysis.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

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
	// slot is the cred-pool slot index whose allocation this factory's
	// loggers belong to. -1 if not associated with a pool slot (e.g.
	// runDirectSession path). Loggers inherit it so per-slot auth-error
	// attribution works when pion logs a 401/403 — see turnLogger.maybeFlagAuthError.
	slot int
}

func (f *turnLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &turnLogger{scope: scope, proxy: f.proxy, slot: f.slot}
}

type turnLogger struct {
	scope string
	proxy *Proxy
	slot  int
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
	l.maybeFlagAuthError(msg)
}
func (l *turnLogger) Warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("pion/%s: WARN: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
	l.maybeFlagAuthError(msg)
}
func (l *turnLogger) Error(msg string) {
	log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
	l.maybeFlagAuthError(msg)
}
func (l *turnLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("pion/%s: ERROR: %s", l.scope, sanitizeLog(msg))
	l.maybeCountTransientError(msg)
	l.maybeFlagAuthError(msg)
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
// maybeFlagAuthError surfaces a prominent log line whenever pion logs any
// auth-related error from VK (401 Unauthorized, 403 Forbidden). Empirically
// over 2+ days of testing (April 2026) we have NEVER observed these — TURN
// allocations on a given cred work indefinitely as far as we can tell. The
// dedicated marker exists so that IF a cred actually does expire mid-session
// (most likely visible as "Fail to refresh permissions" with a 401 code from
// VK), we'll see it immediately and can react. Includes the scope (turnc /
// channelbind / etc.) and the original pion message.
//
// This is BESIDES our own runTURN-level isAuthError handling, which catches
// auth errors on the next Allocate retry. The pion-logger path catches them
// during steady-state Refresh cycles, before any reconnect would happen.
func (l *turnLogger) maybeFlagAuthError(msg string) {
	// Match anchored auth-error patterns only.
	//
	// Bare "401" / "403" substring matching produced false positives:
	// vpn.lte-wifi.0.log on 2026-04-30 04:38:58 surfaced "PION AUTH ERROR
	// DETECTED" on a refresh failure where the message contained the
	// ephemeral UDP port "64014" (treated as substring "401"). Real pion
	// auth errors always include either the word "Unauthorized"/"Forbidden"
	// or the STUN error-response prefix "error 401:"/"error 403:".
	if !strings.Contains(msg, "Unauthorized") &&
		!strings.Contains(msg, "Forbidden") &&
		!strings.Contains(msg, "error 401:") &&
		!strings.Contains(msg, "error 403:") {
		return
	}
	if l.proxy != nil && l.proxy.credPool != nil {
		l.proxy.credPool.recordAuthError(l.slot)
	}
	log.Printf("proxy: PION AUTH ERROR DETECTED on slot %d in %s: %s", l.slot, l.scope, sanitizeLog(msg))
}

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
//
//	"TURN allocate: Allocate error response (error 401: Unauthorized)"
//
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

// groupHelloMagic is the M3 group hello: 0xff 'G' 'R' 'P' + a 16-byte session
// id, sent on every conn so the server can put one client's connections on one
// shared socket toward WireGuard. Without it the server has no way to tell two
// clients apart, and its downlink scheduler has to stay a single-client
// experiment flag.
//
// Same construction as probePingMagic above, and for the same reason: 0xff is
// outside WireGuard's 1..4 message-type range, so a server that predates this
// forwards the hello to its WireGuard, which drops it as malformed. Old server
// + new client therefore costs one dropped 20-byte packet per probe interval.
//
// 🚫 NOT SENT IN WRAP-A OR WRAP-S. Those modes talk to a third party's server
// (amurcanov's, samosvalishe's), which cannot act on grouping and whose
// handling of an unknown sentinel we have never read. See sendGroupHello.
var groupHelloMagic = []byte{0xff, 'G', 'R', 'P'}

// groupHelloLen is magic + a 16-byte session id.
const groupHelloLen = 4 + 16

// initGroupHello builds this tunnel's group hello: one session id per tunnel
// start, shared by every conn, so the server can put this client's connections
// on one socket toward WireGuard.
//
// 🚫 Skipped for WRAP-A / WRAP-S. Those peers are other people's servers
// (amurcanov's, samosvalishe's); they cannot act on grouping, and putting an
// unknown sentinel on their wire buys nothing while risking behaviour we have
// never read. A failed random draw also disables it — the server then keeps
// every conn on its own socket, which is the pre-M3 behaviour: correct, slower.
func (p *Proxy) initGroupHello(cfg Config) {
	if cfg.UseWrapA || cfg.UseWrapS {
		return
	}
	id, err := uuid.NewRandom()
	if err != nil {
		log.Printf("proxy: group hello disabled (uuid: %s) — the server will "+
			"keep one socket per conn", err)
		return
	}
	hello := make([]byte, 0, groupHelloLen)
	hello = append(hello, groupHelloMagic...)
	hello = append(hello, id[:]...)
	p.groupHello.Store(&hello)
	log.Printf("proxy: group hello %s (sent on every conn so the server can "+
		"schedule this client's downlink as one group)", id)
}

// groupHelloBytes is the CURRENT hello, or nil when grouping is off.
func (p *Proxy) groupHelloBytes() []byte {
	if h := p.groupHello.Load(); h != nil {
		return *h
	}
	return nil
}

// sendGroupHello writes this tunnel's group hello to one conn, if the peer is
// our own server. Errors are ignored on purpose: the hello is an optimisation,
// it is repeated every probe interval, and a server that never sees one simply
// keeps the connection on its own socket.
func (p *Proxy) sendGroupHello(w io.Writer) {
	if h := p.groupHelloBytes(); h != nil {
		_, _ = w.Write(h)
	}
}

// recvPktPool recycles []byte slices used to hand off freshly-read packets
// from the per-conn recv goroutines (runDTLSSession, runDirectSession,
// runSRTPSession) to ReceivePacket via p.recvCh. Producer-side Get in
// each recv goroutine, consumer-side Put in ReceivePacket after the
// caller's buf has been filled via copy. See srtpwrap.pktPool for the
// symmetric pool on the demux→wrappedConn.Read hand-off; together they
// eliminate ~10 MB/sec of GC churn under speedtest load (~2400 pps × 2
// hand-off points × ~2 KB per packet allocation = ~10 MB/sec generated
// garbage on the SRTP path pre-pool, observed as heap-alloc spikes to
// 28 MB and matching JETSAM_REASON_MEMORY_PERPROCESSLIMIT events in
// builds 130-132). 2048-byte capacity covers max expected payload.
//
// Build 133.
var recvPktPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

// sendPktPool is the TX twin of recvPktPool, for the WireGuard records
// SendPacket hands to the writer goroutines through sendCh.
//
// 🚨 OWNERSHIP, and it is the whole correctness argument:
//
//	before the enqueue  — SendPacket owns the buffer, and Puts it on the one
//	                      exit that never reaches the channel (ctx.Done)
//	after the enqueue   — sendCh owns it; nobody may touch it
//	after the dequeue   — writePacket owns it, and returns it EXACTLY ONCE on
//	                      every outcome, via a defer at the top of the function
//
// ⇒ there are exactly TWO Put sites in the tree and there must never be a
// third. In particular: NOT in the four writer loops (proxy.go, the
// `case item := <-p.sendCh` bodies) and NOT inside a `write` closure. Either
// would be a DOUBLE Put — two of ~30 writer goroutines handed the same backing
// array, concurrently copying different WireGuard records into it. On the wire
// that is corrupt uplink which server1 drops as auth failures, i.e. it would
// read as the per-allocation loss this project is already chasing and be
// blamed on the relay. `-race` does not catch it. `sendpktpool_test.go` counts
// the sites for exactly this reason.
//
// ⚖️ ONE bounded leak is accepted rather than fixed, and it is written down so
// nobody "fixes" it into the double above: teardown GCs up to the 256 items
// still sitting in sendCh, which is created once and never drained. It
// self-heals through New(), and it must NOT be answered by draining the channel
// with a Put in a writer loop.
//
// 🚫 The write-error branch is deliberately NOT on that list. It does not leak —
// writePacket's defer covers it — and naming it as an accepted leak would point
// at the exact branch where a "fix" is the double free above. *(Review-caught:
// the earlier wording said "two leaks" and then retracted the first, which left
// a phantom whose warning argued for the corruption it was meant to prevent.)*
//
// 🚨 AND IT MAKES A DEPENDENCY LOAD-BEARING that was previously irrelevant:
// every transport must COPY the payload before its Write returns. Verified for
// the pinned versions — pion/dtls v3.0.10 (`ApplicationData.Marshal` does
// `append([]byte{}, a.Data...)`, both the DTLS and WRAP-A paths), pion/rtp
// v1.10.1 (`MarshalTo` → `copy(buf[offset:], payload)`, the SRTP path) and
// cbeuw/connutil v1.0.1 (`bytes.Buffer.Write`, the direct path). A bump that
// introduced zero-copy of the application payload would break this silently.
var sendPktPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

// sendPktPoolGet returns a slice of length n from the pool.
func sendPktPoolGet(n int) []byte {
	b := sendPktPool.Get().([]byte)
	if cap(b) < n {
		b = make([]byte, n)
	}
	return b[:n]
}

// sendPktPoolPut returns a slice to the pool, restoring full capacity.
func sendPktPoolPut(b []byte) {
	if b == nil {
		return
	}
	sendPktPool.Put(b[:cap(b)])
}

// recvPktPoolGet returns a slice of length n from the pool.
func recvPktPoolGet(n int) []byte {
	b := recvPktPool.Get().([]byte)
	if cap(b) < n {
		b = make([]byte, n)
	}
	return b[:n]
}

// recvPktPoolPut returns a slice to the pool. Restores full backing-
// array length before storage.
func recvPktPoolPut(b []byte) {
	if b == nil {
		return
	}
	recvPktPool.Put(b[:cap(b)])
}

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

// ─── SRTP transport (Config.UseSrtp=true) ─────────────────────────────────
//
// runSRTPSession is the third dispatch target alongside runDTLSSession and
// runDirectSession (selected via Config.UseSrtp in runConnection). Tunnel
// traffic is framed as DTLS+SRTP+RTP and sent through the TURN relay's
// ChannelData; VK's content classifier sees this as legitimate WebRTC
// media and does NOT apply the per-allocation shape policy. Server-side
// counterpart is anton48/vk-turn-proxy add-server-srtp-layer branch on
// port :56004.
//
// MVP NOTE: this first integration is intentionally simpler than
// runDTLSSession — it omits the probe sender / zombie watchdog / shape-
// probe / iOS-freeze-handling logic that runDTLSSession accumulated over
// months. Those stability features can be ported incrementally once the
// basic SRTP path is empirically validated end-to-end on the iOS app. The
// toggle Config.UseSrtp defaults to false so users on the standard build
// retain the existing DTLS+WG transport unchanged.
func (p *Proxy) runSRTPSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool, connIdx int) error {
	_ = linkID // reserved for future per-link logging parity with DTLS path
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	// Acquire cred — same pattern as runDTLSSession / runDirectSession.
	turnAddr, creds, credSlot, err := p.resolveTURNAddr(connIdx, false)
	if err != nil {
		return err
	}
	// The lease is the pair (slot, credential) — see runDTLSSession.
	currentSlot, currentCreds := credSlot, creds
	// When this session's allocation is given back — by its live Close or by the
	// abort of its setup — the lease is released behind the relay's second
	// (seatcool.go).
	var gave gaveBack
	defer func() { p.releaseLease(currentSlot, currentCreds, &gave) }()

	// Set up TURN allocation and DTLS-SRTP handshake to the peer.
	sessStart := time.Now()
	srtpConn, err := p.setupSRTPSession(connCtx, turnAddr, creds, credSlot, connIdx, &gave)
	if err != nil {
		// Mirror runDTLSSession's error attribution so quota / auth
		// failures land on the correct slot.
		if isQuotaError(err) {
			cooldown := p.credPool.markSaturated(credSlot, creds)
			log.Printf("proxy: [conn %d] SRTP TURN allocate quota error (486) on slot %d (cooldown %s)",
				connIdx, credSlot, cooldown.Round(time.Second))
		} else if isAuthError(err) {
			p.credPool.invalidateEntry(credSlot, creds)
			log.Printf("proxy: [conn %d] SRTP bootstrap auth error on slot %d, invalidated",
				connIdx, credSlot)
		}
		return fmt.Errorf("SRTP setup: %w", err)
	}
	defer srtpConn.Close()
	// Paired with the register in setupSRTPSession, which cannot defer it: that
	// function returns the connection and outlives its own frame.
	defer p.sockStats.unregister(connIdx)
	context.AfterFunc(connCtx, func() { _ = srtpConn.Close() })

	p.dtlsHSns.Store(int64(time.Since(sessStart)))
	p.activeConns.Add(1)
	p.totalConns.Add(1)
	defer p.activeConns.Add(-1)

	if readyCh != nil && !*signaled {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	*signaled = true
	p.signalBootstrapDone(nil)

	p.noteSessionUp(connIdx) // the retry floor's evidence that the network works — retryfloor.go
	log.Printf("proxy: [conn %d, cred %d] SRTP+TURN session established", connIdx, credSlot)
	p.resetProbeMarks(connIdx) // this session's pings start from seq 1, and so do its marks — wakeprobe.go

	if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
		p.lastPongTimes[connIdx].Store(time.Now().Unix())
	}

	// NAT keepalive — mirror the runDTLSSession behaviour from
	// proxy.go:2693. Send a STUN Binding request every 25s on the
	// underlying TCP-control conn to the TURN relay. Two reasons this
	// is critical even more on the SRTP path than the DTLS path:
	//
	//  1. iOS treats the TURN relay as the single exempt host under
	//     includeAllNetworks=true. Multiple silent TCP-control sockets
	//     to that host appear to count against an iOS Network Extension
	//     stability check that fires somewhere around the 35-40s mark
	//     after the tunnel connects — build 117/118/119 (SRTP path
	//     working but no NAT keepalive) consistently saw the extension
	//     killed externally at ~T+38s without a graceful stopTunnel.
	//     With STUN Binding every 25s, each TCP socket sees ~28 bytes
	//     of OUR traffic per cycle even when WG isn't actively sending
	//     on that conn, keeping the socket visibly alive.
	//
	//  2. Standard RFC 5766 reason — refreshes NAT mapping on routers
	//     between the iPhone and the relay during silent periods (e.g.
	//     during iOS sleep). Less critical for TCP than UDP, but free
	//     defence in depth.
	//
	// Type-assert to access the underlying *turn.Client. setupSRTPSession
	// always returns a *srtpSessionConn so the assertion will succeed
	// for the production path; the if-ok guard is defence against any
	// future test mock that might return a bare net.Conn.
	if sess, ok := srtpConn.(*srtpSessionConn); ok && sess.tc != nil {
		go func() {
			ticker := time.NewTicker(25 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					_, _ = sess.tc.SendBindingRequest()
				case <-connCtx.Done():
					return
				}
			}
		}()
	}

	// Liveness-probe sender — ported from runDTLSSession (proxy.go:2084+).
	// Sends a 12-byte ping (0xff PNG + 8-byte BE seq) every probeInterval
	// over the SRTP-wrapped pipe. Server with probe-echo support echoes
	// it back; the recv goroutine recognises the magic, updates
	// lastPongTimes[connIdx] and bumps serverProbeable. After
	// serverProbeable=true, periodic zombie check fires connCancel() if
	// no pong arrives within probeStaleThreshold. Without server-side
	// echo support serverProbeable stays false and the zombie/active-
	// probe gates never fire — fully backward-compatible with the
	// pre-probe-echo SRTP server.
	//
	// Mirrors the DTLS path's tick-gap freeze detector and wakeCh-driven
	// active-probe-on-wake. Mostly verbatim from runDTLSSession; the
	// only structural difference is writing through srtpConn instead of
	// dtlsConn.
	go func() {
		ticker := time.NewTicker(probeInterval)
		defer ticker.Stop()
		var seq uint64
		var lastPingAt time.Time // when the ping numbered seq was sent, or zero: written by tickPing and runWakeProbe alone — wakeprobe.go
		pingPkt := make([]byte, len(probePingMagic)+8)
		copy(pingPkt[0:len(probePingMagic)], probePingMagic)
		// sendPing writes one ping — the periodic tick's and the wake probe's alike
		// (the bookkeeping as in the DTLS session's).
		sendPing := func(s uint64, now time.Time) error {
			binary.BigEndian.PutUint64(pingPkt[len(probePingMagic):], s)
			_ = srtpConn.SetWriteDeadline(now.Add(5 * time.Second))
			if _, err := srtpConn.Write(pingPkt); err != nil {
				return err
			}
			if connIdx >= 0 && connIdx < len(p.lastPingSeq) {
				p.lastPingSeq[connIdx].Store(s)
				p.firstPingAt[connIdx].CompareAndSwap(0, now.Unix())
			}
			return nil
		}
		// M3 group hello. Sent IMMEDIATELY rather than waiting for the first
		// tick: until the server sees it this conn stays on its own socket, and
		// a probeInterval of that is a probeInterval of the old, skewed
		// downlink at the start of every tunnel. Re-sent on every tick so a
		// lost hello heals by repetition and a restarted server re-groups us.
		p.sendGroupHello(srtpConn)
		lastTickAt := time.Now()
		wake := p.newWakeWatch()
		for {
			wakeCh := p.wakeChannel()
			if wake.pending() {
				// A wake was broadcast while this goroutine was not parked in the select
				// below (its tick branch, at a thaw): the channel it has just read is the
				// NEW one and will not fire for it. The epoch remembers — wakeprobe.go.
				wakeCh = closedWakeCh
			}
			select {
			case <-ticker.C:
				now := time.Now()
				gap := now.Sub(lastTickAt)
				if gap > 90*time.Second {
					log.Printf("proxy: [conn %d] SRTP probe tick gap %s (freeze detected), resetting pong clock",
						connIdx, gap.Round(time.Second))
					if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
						p.lastPongTimes[connIdx].Store(now.Unix())
					}
					lastTickAt = now
					continue
				}
				lastTickAt = now
				// The tick's ping is ONE body for both session kinds — seq and the stamp a
				// wake probe may adopt it by move together there (tickPing, wakeprobe.go).
				if err := p.tickPing(&seq, &lastPingAt, now, sendPing); err != nil {
					return
				}
				if p.serverProbeable.Load() && connIdx >= 0 && connIdx < len(p.lastPongTimes) {
					lastPong := time.Unix(p.lastPongTimes[connIdx].Load(), 0)
					stale := time.Since(lastPong)
					if stale > probeStaleThreshold {
						lastPing := p.lastPingSeq[connIdx].Load()
						lastPongS := p.lastPongSeq[connIdx].Load()
						var sentSinceLastPong uint64
						if lastPing >= lastPongS {
							sentSinceLastPong = lastPing - lastPongS
						}
						firstPong := p.firstPongAt[connIdx].Load()
						pongHistory := "never"
						if firstPong > 0 {
							pongHistory = time.Since(time.Unix(firstPong, 0)).Round(time.Second).String() + " ago (first pong)"
						}
						authCount := p.credPool.authErrorCount(credSlot)
						log.Printf("proxy: [conn %d on slot %d] SRTP zombie detected (no pong for %s, lastPingSeq=%d lastPongSeq=%d sentSinceLastPong=%d firstPong=%s, authErrorsOnSlot=%d), killing",
							connIdx, credSlot, stale.Round(time.Second), lastPing, lastPongS, sentSinceLastPong, pongHistory, authCount)
						connCancel()
						return
					}
				}
			case <-wakeCh:
				// Whether this wake is probed at all (the 30-s throttle, a connection with
				// traffic a moment ago), the jitter and the probe itself are ONE body for
				// both session kinds — wakeWatch.serve, wakeprobe.go (builds 422–424).
				alive, probed, err := wake.serve(connCtx, connIdx, credSlot, "SRTP ", &seq, &lastPingAt, sendPing)
				if err != nil {
					return
				}
				if !alive {
					connCancel()
					return
				}
				if probed {
					lastTickAt = time.Now()
				}
			case <-connCtx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Send: sendCh → srtpConn.
	go func() {
		defer wg.Done()
		defer connCancel()
		// Hoisted out of the loop on purpose: one closure per CONNECTION rather
		// than one per packet. At a few thousand packets a second, per-packet
		// closures are avoidable garbage on a device whose GOMEMLIMIT is 35 MB
		// and whose history includes a GC death spiral.
		writeOne := func(pkt []byte, now time.Time) error {
			_ = srtpConn.SetWriteDeadline(now.Add(30 * time.Second))
			_, werr := srtpConn.Write(pkt)
			return werr
		}
		for {
			// 🚨 RESERVE BEFORE THE DEQUEUE — see uplinkpace.go.
			ticket := p.paceReserve(connIdx)
			select {
			case <-connCtx.Done():
				p.paceSettle(ticket, 0)
				log.Printf("proxy: [conn %d] SRTP send goroutine: ctx cancelled", connIdx)
				return
			// connIdx (not -1) below because this site keeps the per-conn TX
			// counters, which writePacket maintains per packet: the pre-SRTP
			// payload bytes — the WireGuard records that came out of sendCh —
			// not the wire bytes after RTP+SRTP framing. That matches what an
			// external observer counting WG throughput sees, and keeps the
			// conn-stats tick reading the same regardless of transport mode.
			case item := <-p.sendCh:
				p.paceSettle(ticket, len(item.buf))
				if err := p.writePacket(item, connIdx, writeOne); err != nil {
					log.Printf("proxy: [conn %d] SRTP send error: %v", connIdx, err)
					return
				}
			}
		}
	}()

	// Recv: srtpConn → recvCh, dropping any probe pongs.
	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			deadlineSetAt := time.Now()
			_ = srtpConn.SetReadDeadline(deadlineSetAt.Add(30 * time.Second))
			n, err := srtpConn.Read(buf)
			if err != nil {
				if connCtx.Err() != nil {
					log.Printf("proxy: [conn %d] SRTP recv goroutine: ctx cancelled (err=%v)", connIdx, err)
					return
				}
				if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
					// Same iOS-freeze + global-tunnel-health pattern as
					// runDTLSSession recv goroutine.
					elapsed := time.Since(deadlineSetAt)
					if elapsed > 90*time.Second {
						log.Printf("proxy: [conn %d] SRTP read elapsed %s (freeze detected), resetting lastRecvTime",
							connIdx, elapsed.Round(time.Second))
						p.lastRecvTime.Store(time.Now().Unix())
						continue
					}
					lastRecv := p.lastRecvTime.Load()
					if lastRecv > 0 && time.Since(time.Unix(lastRecv, 0)) < 3*time.Minute {
						continue
					}
					staleFor := "unknown"
					if lastRecv > 0 {
						staleFor = time.Since(time.Unix(lastRecv, 0)).Round(time.Second).String()
					}
					log.Printf("proxy: [conn %d] SRTP read timeout, tunnel stale (last recv %s ago), reconnecting", connIdx, staleFor)
					return
				}
				log.Printf("proxy: [conn %d] SRTP read error: %v", connIdx, err)
				return
			}
			p.lastRecvTime.Store(time.Now().Unix())

			// Probe pong recognition: drop ping-echo packets so WG never
			// sees the 0xff... magic bytes (it would treat them as
			// invalid message type). Ported from runDTLSSession recv
			// path (proxy.go:2434+) — same seq tracking + first-pong
			// log + pong-gap log so the SRTP zombie / active-probe
			// machinery has identical observability to DTLS.
			if isProbePacket(buf[:n]) {
				p.serverProbeable.Store(true)
				if connIdx >= 0 && connIdx < len(p.lastPongTimes) {
					now := time.Now()
					nowUnix := now.Unix()
					prevPongAt := p.lastPongTimes[connIdx].Load()
					prevPongSeq := p.lastPongSeq[connIdx].Load()
					p.lastPongTimes[connIdx].Store(nowUnix)
					var pongSeq uint64
					if n >= len(probePingMagic)+8 {
						pongSeq = binary.BigEndian.Uint64(buf[len(probePingMagic) : len(probePingMagic)+8])
						p.notePongSeq(connIdx, pongSeq) // forward only — wakeprobe.go
					}
					if p.firstPongAt[connIdx].CompareAndSwap(0, nowUnix) {
						firstPing := p.firstPingAt[connIdx].Load()
						bootstrap := "?"
						if firstPing > 0 {
							bootstrap = time.Since(time.Unix(firstPing, 0)).Round(100 * time.Millisecond).String()
						}
						log.Printf("proxy: [conn %d] SRTP first pong received (seq=%d, %s after first ping)",
							connIdx, pongSeq, bootstrap)
					} else if prevPongAt > 0 {
						gap := nowUnix - prevPongAt
						if gap > 300 {
							log.Printf("proxy: [conn %d] SRTP pong gap %ds resolved (prev pongSeq=%d, this pongSeq=%d, missed=%d)",
								connIdx, gap, prevPongSeq, pongSeq, pongSeq-prevPongSeq-1)
						}
					}
				}
				continue
			}

			// Per-conn RX byte counter, parity with the DTLS path
			// at proxy.go:2874. Counted before the recvCh send so a
			// full recvCh that causes the goroutine to bail still
			// reflects the bytes we actually decrypted and accepted
			// from the wire.
			if connIdx >= 0 && connIdx < len(p.connRxBytes) {
				p.connRxBytes[connIdx].Add(int64(n))
				// lastRxAt mirror — see DTLS path comment in runTURN
				// for skip-on-recent-tx rationale. Probe pongs are
				// filtered above (isProbePacket check + continue), so
				// they never reach this counter — only data RX marks
				// the conn as "recently active".
				p.lastRxAt[connIdx].Store(time.Now().UnixNano())
			}

			pkt := recvPktPoolGet(n)
			copy(pkt, buf[:n])
			if !p.enqueueRecv(connCtx, pkt) {
				recvPktPoolPut(pkt)
				log.Printf("proxy: [conn %d] SRTP recv goroutine: ctx cancelled during recvCh send", connIdx)
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// setupSRTPSession opens a TURN client (UDP or TCP control transport
// based on p.config.UseUDP), allocates a relay, creates a permission
// for p.peer, and performs the DTLS+SRTP handshake. Returns a net.Conn
// (srtpSessionConn wrapper) whose Read/Write framing is RTP+SRTP and
// whose Close tears down the SRTP wrapper, the relay allocation, the
// TURN client, and the underlying control conn together.
func (p *Proxy) setupSRTPSession(ctx context.Context, turnAddr string, creds *TURNCreds, credSlot, connIdx int, gave *gaveBack) (net.Conn, error) {
	// Local control conn: UDP socket (UDP-control) or TCP dial wrapped
	// in turn.NewSTUNConn (TCP-control). Mirrors tools/turn_srtp_test
	// transport plumbing.
	var ctlConn net.PacketConn
	if p.config.UseUDP {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("local udp listen: %w", err)
		}
		ctlConn = uc
	} else {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		tcp, err := dialer.Dial("tcp", turnAddr)
		if err != nil {
			return nil, fmt.Errorf("dial tcp to relay: %w", err)
		}
		// 🚨 THE SECOND DIAL SITE, AND THE ONE THAT MATTERS. Build 233 registered
		// only runTURN's socket and shipped: SRTP is the production transport and
		// dials here, so `sock=` never appeared in a single line of the first
		// device run. Instrument BOTH or neither.
		//
		// Unregistered where the session ends rather than by a defer: this
		// function returns the conn and outlives its own frame.
		p.sockStats.register(connIdx, tcp)
		ctlConn = turn.NewSTUNConn(tcp)
	}

	tc, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: turnAddr,
		Conn:           ctlConn,
		Username:       creds.Username,
		Password:       creds.Password,
		Realm:          "okcdn.ru",
		Software:       "vk-turn-srtp",
		// Custom factory (not pion's default LogLevelError) so SRTP-path TURN refresh/auth failures feed the silent-degradation watchdog + get sanitized, matching runTURN.
		LoggerFactory: &turnLoggerFactory{proxy: p, slot: credSlot},
		// Match the relay family to the peer (see addrFamilyFor) — was
		// hardcoded IPv4, which 443'd ("Peer Address Family Mismatch") on an
		// IPv6 peer (e.g. a DNS name resolving to AAAA) — issue #39.
		RequestedAddressFamily: addrFamilyFor(p.peer),
	})
	if err != nil {
		_ = ctlConn.Close()
		return nil, fmt.Errorf("turn.NewClient: %w", err)
	}
	if err := tc.Listen(); err != nil {
		tc.Close()
		_ = ctlConn.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}

	allocStart := time.Now()
	relayConn, err := tc.Allocate()
	if err != nil {
		tc.Close()
		_ = ctlConn.Close()
		return nil, fmt.Errorf("turn allocate: %w", err)
	}
	// The relay accepted this identity: mark it NOW, before the permission
	// and the SRTP handshake — the mark means the allocation, not the
	// session, and names the credential, not the slot (quotabreaker.go; see
	// runTURN).
	p.credPool.noteAllocated(credSlot, creds)
	allocDur := time.Since(allocStart)
	// Surface the TURN-allocate roundtrip to the UI / Stats endpoint
	// — same field runDTLSSession populates at proxy.go:2706, so the
	// "TURN RTT" tile shows the most recent successful allocate
	// duration regardless of which session type produced it.
	p.turnRTTns.Store(int64(allocDur))
	// A cancel while the permission's transaction is pending — a relay that
	// took the allocation and then went silent, a switch in the RTT between
	// the two — must not wait out pion's retransmit ladder (7 × 200 → 1600
	// ms, 7.8 s): closing the client closes its transaction map and nothing
	// else, and a closed transaction returns at once. But a Close alone
	// releases only what is ALREADY registered: on a ctx cancelled before
	// this point AfterFunc runs the hook in its own goroutine at once,
	// racing CreatePermission's registration, and a transaction registered
	// after the Close waited out the whole ladder (the user's review of
	// 394, 3/3 on their stand). So the hook first puts a write deadline in
	// the PAST on the control socket — the first write of any later
	// transaction fails at once — and only then closes the client:
	// whichever of the two a transaction meets, it ends now. Scoped to this
	// setup: the live session's own teardown closes tc in its order
	// (srtpSessionConn.Close), so the hook is quiesced on return; the
	// teardown below quiesces it too and only then re-arms a live budget
	// for the deallocate its deadline would otherwise fail.
	hookDone := make(chan struct{}) // closed when the hook has run to its end
	disarm := context.AfterFunc(ctx, func() {
		defer close(hookDone)
		_ = ctlConn.SetWriteDeadline(time.Now())
		tc.Close()
	})
	// quiesce: the hook is stopped before it ran, or has finished — never
	// still running when a teardown re-arms its budget. The user's review
	// of 395: the cleanup set now+500 ms, the hook still running replaced
	// it with now, the deallocate failed its write and the allocation
	// stayed on the quota for its lifetime; a stop alone does not wait for
	// a hook that has started. Once: a second stop returns false for a hook
	// that never ran and would wait for ever.
	var quiesceOnce sync.Once
	quiesce := func() {
		quiesceOnce.Do(func() {
			if !disarm() {
				<-hookDone
			}
		})
	}
	defer quiesce()
	// Over a UDP relay leg the allocation is given back by a deallocate the
	// relay CONFIRMS, before the relay conn is closed — here and in the live
	// session's Close alike (dealloc.go). Nil over TCP.
	var release func() deallocVerdict
	if p.config.UseUDP {
		release = func() deallocVerdict { return p.releaseAllocation(tc, creds, connIdx) }
	}
	abortSetup := func() {
		quiesce()
		_ = ctlConn.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget)) // the deallocate goes out under a budget, hook or no hook
		_ = returnAllocation(relayConn, release, gave)                      // confirmed over UDP, and NOTED for the pool — seatcool.go
		tc.Close()
		_ = ctlConn.Close()
	}
	if err := tc.CreatePermission(p.peer); err != nil {
		abortSetup()
		return nil, fmt.Errorf("turn create permission: %w", err)
	}
	log.Printf("proxy: [conn %d] TURN relay allocated: %s (RTT %dms, local=%s)",
		connIdx, relayConn.LocalAddr(), allocDur.Milliseconds(), ctlConn.LocalAddr())

	hsCtx, hsCancel := context.WithTimeout(ctx, srtpwrap.HandshakeTimeout)
	srtpConn, err := srtpwrap.Client(hsCtx, relayConn, p.peer, &p.rtpChPeak)
	hsCancel()
	if err != nil {
		abortSetup()
		return nil, fmt.Errorf("srtp handshake: %w", err)
	}

	return &srtpSessionConn{
		Conn:      srtpConn,
		relayConn: relayConn,
		tc:        tc,
		ctlConn:   ctlConn,
		release:   release,
		gave:      gave,
	}, nil
}

// srtpSessionConn ties the SRTP-wrapped net.Conn returned by srtpwrap.
// Client to the underlying TURN allocation and control conn so a single
// Close() tears down the whole stack.
type srtpSessionConn struct {
	net.Conn  // SRTP-wrapped conn
	relayConn net.PacketConn
	tc        turnSessionClient // *turn.Client; an interface so a test can close without a server
	ctlConn   net.PacketConn
	release   func() deallocVerdict // the confirmed deallocate, run before relayConn is closed — over a UDP relay leg only, nil otherwise (dealloc.go)
	gave      *gaveBack             // the session's note of when its allocation was given back — seatcool.go

	closeOnce sync.Once
}

// turnSessionClient is what srtpSessionConn needs from *turn.Client.
type turnSessionClient interface {
	Close()
	SendBindingRequest() (net.Addr, error)
}

// relayCloseWriteBudget bounds EVERY write a session's teardown makes on the
// control socket we own — DTLS's close_notify (pion/dtls writes it
// synchronously, with no timeout of its own), pion's deallocate when the
// allocation is closed, and any keepalive or refresh already in flight —
// with ONE absolute deadline set before the first of them. The relay conn's
// own SetWriteDeadline is a stub, so the socket beneath it is the only place
// a bound can go; on a relay that stopped taking bytes (a dead TCP relay,
// the interface a path change just took away) each of those writes would
// otherwise block for ever, and with it the session's Close and its restart.
// A healthy relay finishes them in microseconds. 🚨 The deadline is absolute
// from Close's first statement: a Close during a saturated upload can cut
// the close_notify and the deallocate behind a full send buffer, and the
// allocation then lives out its lifetime at VK — the known price of a
// bounded stop.
const relayCloseWriteBudget = 500 * time.Millisecond

func (s *srtpSessionConn) Close() error {
	var firstErr error
	s.closeOnce.Do(func() {
		// ONE absolute deadline for EVERY write this teardown makes on the
		// control socket, set FIRST: DTLS's close_notify (pion writes it
		// synchronously, with a background context and no timeout of its
		// own) goes through the SRTP wrapper and the relay into this very
		// socket, then pion's deallocate. On a relay that stopped taking
		// bytes — the interface a path change just took away — both block
		// for ever, and with them the session's restart. A deadline placed
		// after s.Conn.Close bounded only the deallocate (user's review,
		// 2026-09-07).
		_ = s.ctlConn.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))
		if err := s.Conn.Close(); err != nil {
			firstErr = err
		}
		// The allocation is given back by ONE body (returnAllocation,
		// seatcool.go). Over UDP first the relay's ANSWER to the deallocate,
		// before anything below closes — Close returns after it, and so does
		// the session, and only then does its connection re-dial (dealloc.go);
		// then the relay conn's own Close; and the moment is NOTED for the pool.
		if err := returnAllocation(s.relayConn, s.release, s.gave); err != nil && firstErr == nil {
			firstErr = err
		}
		s.tc.Close()
		if err := s.ctlConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}
