package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <os/log.h>
#include <mach/mach.h>
#include <mach/task_info.h>

// Set GODEBUG=asyncpreemptoff=1 BEFORE Go runtime initializes.
// This prevents "fatal error: non-Go code disabled sigaltstack"
// on iOS Network Extensions where sigaltstack is disabled on some threads.
__attribute__((constructor))
static void disable_async_preempt(void) {
	setenv("GODEBUG", "asyncpreemptoff=1", 1);
}

// Logging callback type matching wireguard-apple convention
typedef void(*logger_fn_t)(int level, const char *msg);
static void callLogger(void *fn, int level, const char *msg) {
	((logger_fn_t)fn)(level, msg);
}

// Write Go log messages to os_log (visible in Console.app)
static void go_os_log(const char *msg) {
	os_log_t log = os_log_create("com.vkturnproxy.tunnel", "go");
	os_log(log, "%{public}s", msg);
}

// Memory breakdown from Mach task_info(TASK_VM_INFO_DATA). Single
// kernel call returns all fields atomically (same snapshot moment) so
// Go side gets a coherent picture rather than separate calls per
// field. Returns all-zero struct on failure (caller treats as
// unavailable / skips logging).
//
// phys_footprint is the SAME number iOS jetsam evaluates against the
// per-process NE memory budget. The internal/external/reusable/
// compressed breakdown distinguishes Go-side from non-Go memory growth
// — added 2026-05-26 (build 138) after observing phys_footprint
// silently grow 22→50 MB in <50s with no log activity (jetsam at
// 16:26:45), which the Go-only memstats couldn't explain.
typedef struct {
	uint64_t phys_footprint;
	uint64_t internal;
	uint64_t external;
	uint64_t reusable;
	uint64_t compressed;
} go_vm_stats_t;

static go_vm_stats_t go_get_vm_stats(void) {
	task_vm_info_data_t info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	go_vm_stats_t r = {0, 0, 0, 0, 0};
	kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO,
	                             (task_info_t)&info, &count);
	if (kr != KERN_SUCCESS) {
		return r;
	}
	r.phys_footprint = (uint64_t)info.phys_footprint;
	r.internal       = (uint64_t)info.internal;
	r.external       = (uint64_t)info.external;
	r.reusable       = (uint64_t)info.reusable;
	r.compressed     = (uint64_t)info.compressed;
	return r;
}
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/cacggghp/vk-turn-proxy/pkg/turnbind"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// tunnelEntry holds a running tunnel's state.
type tunnelEntry struct {
	device *device.Device
	proxy  *proxy.Proxy
	bind   *turnbind.TURNBind
}

var (
	tunnels   = make(map[int32]*tunnelEntry)
	tunnelsMu sync.Mutex
	nextID    int32 = 1
)

// decodeWrapKey parses the hex string the user typed in Settings into
// the 32-byte key proxy.Config.WrapKey expects. Returns (nil, nil) when
// WRAP isn't requested so the typical no-WRAP setup hits no error path
// at all. Any non-empty error from the operator's input is logged and
// disables WRAP for the session — surfacing that in the extension log
// rather than failing silently inside proxy startup.
//
// Strips ALL whitespace from the input before hex decoding. Users
// frequently paste keys with a leading/trailing space (clipboard
// noise) or with internal spaces grouping the hex digits for
// readability. Both used to fail decoding with "encoding/hex: invalid
// byte: U+0020 ' '" — observed 2026-05-07. Any whitespace inside a
// hex key is unambiguously noise (no legitimate hex digit is whitespace),
// so silently stripping it is safe and correct.
func decodeWrapKey(useWrap bool, hexStr string) ([]byte, error) {
	if !useWrap {
		return nil, nil
	}
	hexStr = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, hexStr)
	if hexStr == "" {
		return nil, fmt.Errorf("WRAP enabled but wrap_key_hex is empty")
	}
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("wrap_key_hex not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("wrap_key_hex decodes to %d bytes (need 32)", len(key))
	}
	return key, nil
}

// ProxyConfig is the JSON config passed from Swift.
type ProxyConfig struct {
	VKLink              string            `json:"vk_link"`
	PeerAddr            string            `json:"peer_addr"`
	TurnServer          string            `json:"turn_server,omitempty"`
	TurnPort            string            `json:"turn_port,omitempty"`
	UseDTLS             bool              `json:"use_dtls"`
	UseUDP              bool              `json:"use_udp"`
	// UseWrap enables the WRAP layer between DTLS and TURN ChannelData
	// (see proxy.Config.UseWrap and pkg/proxy/wrap.go). Requires the
	// peer server to be running cacggghp/vk-turn-proxy with matching
	// -wrap and -wrap-key flags (the upstream WRAP-aware build).
	//
	// NOTE 2026-05-20: WRAP no longer escapes VK's content classifier;
	// new code should set UseSrtp instead (see proxy.Config.UseSrtp).
	UseWrap             bool              `json:"use_wrap"`
	// WrapKeyHex is the 64-character hex encoding of the 32-byte
	// ChaCha20 shared key. Required when UseWrap is true and must
	// match the server's -wrap-key value exactly.
	WrapKeyHex          string            `json:"wrap_key_hex"`
	// UseSrtp enables the DTLS+SRTP transport (see pkg/proxy/srtpwrap
	// and proxy.Config.UseSrtp). Requires the peer server to be running
	// anton48/vk-turn-proxy add-server-srtp-layer with the -srtp flag.
	UseSrtp             bool              `json:"use_srtp"`
	NumConns                int `json:"num_conns,omitempty"`
	CredPoolCooldownSeconds int `json:"cred_pool_cooldown_seconds,omitempty"`
	// VKHostIPs is a hostname→[]IP map pre-resolved by the main app
	// before startVPNTunnel. The extension can't resolve VK hosts on
	// its own (no usable DNS context until setTunnelNetworkSettings,
	// which we deliberately defer until bootstrap completes), so the
	// main app — which has full network context — does the lookup
	// and hands us all A-records. The dialer (utls.go) tries each IP
	// in order until one accepts the connection, mirroring how the
	// system resolver normally walks an A-record set.
	VKHostIPs map[string][]string `json:"vk_host_ips,omitempty"`

	// SeededTURN, if non-zero, is a pre-fetched TURN credential set
	// from the main app's pre-bootstrap probe (see wgProbeVKCreds).
	// When present, the proxy seeds credPool slot 0 with it so the
	// first DTLS+TURN session establishes immediately, without any
	// VK API call (no captcha risk in the .connecting window where
	// the main app would be unable to display a WebView).
	SeededTURN *struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"seeded_turn,omitempty"`

	// ForceLegacyCaptcha, when true, makes GetVKCreds skip the captcha-free VK
	// Calls path so the legacy captchaNotRobot.* solver runs — for on-device
	// testing of the captcha fix (the free path is captcha-free, so the solver
	// never runs otherwise). Driven by an undocumented `forceLegacyCaptcha`
	// backup-JSON field. Default false → no production effect.
	ForceLegacyCaptcha bool `json:"force_legacy_captcha,omitempty"`

	// UseCookieAuth selects the non-anonymous "VKAuth" cred path (a logged-in VK
	// session cookie → TURN creds; see pkg/proxy/creds_vkcookie.go). When true,
	// GetVKCreds uses ONLY the cookie path — NO fallback to the anonymous VK
	// Calls / legacy paths (the point is to keep working when VK disabled
	// anonymous join). The cookie itself is NOT carried in this JSON: the
	// extension reads it from the shared Keychain and pushes it via
	// wgSetVKCookieAuth, so it never persists in the VPN providerConfiguration.
	// Default false → anonymous paths as before.
	UseCookieAuth bool `json:"use_cookie_auth,omitempty"`

	// UseWrapA enables the "SRTP-WRAP-A" 4th transport mode — wire-compatible
	// with amurcanov's proxy-turn-vk-android server (see proxy.Config.UseWrapA
	// + pkg/proxy/wrapa.go + getconf.go). The server provisions WireGuard via
	// GETCONF, so the user enters NO WG keys — only the server address +
	// WrapAPassword. Mutually exclusive with use_srtp / use_dtls. After
	// bootstrap, call wgWaitWrapAProvision to fetch the minted WG config.
	UseWrapA bool `json:"use_wrap_a,omitempty"`
	// WrapAPassword is the shared secret: HKDF input for the obfuscation key
	// AND GETCONF authentication. Required when use_wrap_a is true.
	WrapAPassword string `json:"wrap_a_password,omitempty"`
	// DeviceID is the stable per-install identifier sent in GETCONF (the
	// server keys the minted WG device on it). The app should persist one in
	// the App Group; if empty, the proxy generates a per-session UUID.
	DeviceID string `json:"device_id,omitempty"`
}

//export wgTurnOnWithTURN
//
// Legacy single-call entry point: starts VK bootstrap AND attaches WireGuard
// in one synchronous step. Retained so existing callers keep working while
// PacketTunnelProvider is migrated to the split flow (wgStartVKBootstrap +
// wgWaitBootstrapReady + wgAttachWireGuard), after which this export can be
// deleted.
func wgTurnOnWithTURN(settings *C.char, tunFd C.int32_t, proxyConfigJSON *C.char) C.int32_t {
	goSettings := C.GoString(settings)
	goProxyJSON := C.GoString(proxyConfigJSON)

	var pcfg ProxyConfig
	if err := json.Unmarshal([]byte(goProxyJSON), &pcfg); err != nil {
		log.Printf("wgTurnOnWithTURN: invalid proxy config: %s", err)
		return -1
	}
	if pcfg.NumConns <= 0 {
		pcfg.NumConns = 1
	}

	// Apply pre-resolved VK host IPs (set by main app before startVPNTunnel).
	if len(pcfg.VKHostIPs) > 0 {
		log.Printf("wgTurnOnWithTURN: using %d pre-resolved VK host IPs from main app", len(pcfg.VKHostIPs))
		proxy.SetVKHostIPs(pcfg.VKHostIPs)
	}
	proxy.SetForceLegacyCaptcha(pcfg.ForceLegacyCaptcha)
	if !pcfg.UseCookieAuth {
		proxy.SetVKCookieAuth(false, "", nil)
	}

	// Create proxy
	wrapKey, wrapErr := decodeWrapKey(pcfg.UseWrap, pcfg.WrapKeyHex)
	if wrapErr != nil {
		log.Printf("wgTurnOnWithTURN: WRAP key invalid: %s — disabling WRAP", wrapErr)
		pcfg.UseWrap = false
	}
	p := proxy.NewProxy(proxy.Config{
		PeerAddr:         pcfg.PeerAddr,
		TurnServer:       pcfg.TurnServer,
		TurnPort:         pcfg.TurnPort,
		VKLink:           pcfg.VKLink,
		UseDTLS:          pcfg.UseDTLS,
		UseUDP:           pcfg.UseUDP,
		UseWrap:          pcfg.UseWrap,
		WrapKey:          wrapKey,
		UseSrtp:          pcfg.UseSrtp,
		UseWrapA:         pcfg.UseWrapA,
		WrapAPassword:    pcfg.WrapAPassword,
		DeviceID:         pcfg.DeviceID,
		NumConns:         pcfg.NumConns,
		CredPoolCooldown: time.Duration(pcfg.CredPoolCooldownSeconds) * time.Second,
	})

	// Create TURN bind
	bind := turnbind.NewTURNBind(p)

	// Create TUN device from file descriptor
	dupFd, err := dupFD(int(tunFd))
	if err != nil {
		log.Printf("wgTurnOnWithTURN: dup fd failed: %s", err)
		return -2
	}
	tunFile := os.NewFile(uintptr(dupFd), "/dev/tun")
	tunDev, err := tun.CreateTUNFromFile(tunFile, 0)
	if err != nil {
		tunFile.Close()
		log.Printf("wgTurnOnWithTURN: CreateTUNFromFile failed: %s", err)
		return -5
	}

	// Create WireGuard device with our custom bind
	logger := device.NewLogger(device.LogLevelVerbose, "(wireguard-turn) ")
	dev := device.NewDevice(tunDev, bind, logger)

	// Apply UAPI configuration
	if err := dev.IpcSet(goSettings); err != nil {
		log.Printf("wgTurnOnWithTURN: IpcSet: %s", err)
		dev.Close()
		return -3
	}

	if err := dev.Up(); err != nil {
		log.Printf("wgTurnOnWithTURN: Up: %s", err)
		dev.Close()
		return -4
	}

	tunnelsMu.Lock()
	id := nextID
	nextID++
	tunnels[id] = &tunnelEntry{
		device: dev,
		proxy:  p,
		bind:   bind,
	}
	tunnelsMu.Unlock()

	log.Printf("wgTurnOnWithTURN: tunnel %d started", id)
	return C.int32_t(id)
}

// --- APNs-through-tunnel refactor: split entry points ---
//
// The three exports below replace the single synchronous wgTurnOnWithTURN
// with a phased startup so Swift can defer setTunnelNetworkSettings until
// after VK bootstrap is done:
//
//   1. wgStartVKBootstrap   — kicks off VK API + TURN alloc + DTLS in a
//                             goroutine; returns a handle immediately, no
//                             TUN touched yet.
//   2. wgWaitBootstrapReady — blocks up to timeoutMs for the first conn
//                             to have a live DTLS+TURN session.
//   3. wgAttachWireGuard    — attaches a WireGuard device to the already-
//                             working proxy, taking over the provided tunFd.
//
// wgGetTURNServerIP remains unchanged; call it between steps 2 and 3 to get
// the TURN server IP before updating NEVPNProtocol.serverAddress.
// wgTurnOff / wgPause / wgResume / wgSetConfig / wgGetStats work on handles
// from either the legacy or split flow — they just look up tunnelEntry.

//export wgStartVKBootstrap
//
// Starts VK bootstrap (API call, TURN allocation, DTLS handshake) in a
// background goroutine. Does NOT create a TUN device. Returns a tunnel
// handle immediately, or -1 on immediate config-parse failure.
//
// Observable bootstrap progress via wgWaitBootstrapReady: ready=1 once the
// first conn reports a live DTLS+TURN session, timeout=0 if the deadline
// expires, error=-1 on fatal failure before any conn came up. Captcha
// flows remain internal to Proxy — the bootstrap stays "not ready" until
// captcha is solved AND the first conn completes.
func wgStartVKBootstrap(proxyConfigJSON *C.char) C.int32_t {
	goProxyJSON := C.GoString(proxyConfigJSON)

	var pcfg ProxyConfig
	if err := json.Unmarshal([]byte(goProxyJSON), &pcfg); err != nil {
		log.Printf("wgStartVKBootstrap: invalid proxy config: %s", err)
		return -1
	}
	if pcfg.NumConns <= 0 {
		pcfg.NumConns = 1
	}

	// Apply pre-resolved VK host IPs (set by main app before startVPNTunnel).
	if len(pcfg.VKHostIPs) > 0 {
		log.Printf("wgStartVKBootstrap: using %d pre-resolved VK host IPs from main app", len(pcfg.VKHostIPs))
		proxy.SetVKHostIPs(pcfg.VKHostIPs)
	}
	proxy.SetForceLegacyCaptcha(pcfg.ForceLegacyCaptcha)
	// Defensive: when cookie auth isn't requested, force it OFF (the extension
	// process can be reused across connects — clear any stale cookie state).
	// When it IS requested, the extension has already called wgSetVKCookieAuth
	// with the Keychain cookie before this, so leave that state intact.
	if !pcfg.UseCookieAuth {
		proxy.SetVKCookieAuth(false, "", nil)
	}

	// Seeded TURN creds from main app's pre-bootstrap captcha flow (optional).
	var seededTURN *proxy.TURNCreds
	if pcfg.SeededTURN != nil && pcfg.SeededTURN.Address != "" {
		seededTURN = &proxy.TURNCreds{
			Username: pcfg.SeededTURN.Username,
			Password: pcfg.SeededTURN.Password,
			Address:  pcfg.SeededTURN.Address,
		}
		log.Printf("wgStartVKBootstrap: using pre-fetched TURN creds (addr=%s)", seededTURN.Address)
	}

	// Derive cred-cache path from logFilePath (already pointing into the
	// App Group container). Same directory, fixed filename. If logging
	// wasn't configured (logFilePath == ""), persistence is silently
	// disabled — credPool will treat empty path as "no persist".
	var credCachePath string
	if logFilePath != "" {
		credCachePath = filepath.Join(filepath.Dir(logFilePath), "creds-pool.json")
	}

	wrapKey, wrapErr := decodeWrapKey(pcfg.UseWrap, pcfg.WrapKeyHex)
	if wrapErr != nil {
		log.Printf("wgStartVKBootstrap: WRAP key invalid: %s — disabling WRAP", wrapErr)
		pcfg.UseWrap = false
	}
	p := proxy.NewProxy(proxy.Config{
		PeerAddr:         pcfg.PeerAddr,
		TurnServer:       pcfg.TurnServer,
		TurnPort:         pcfg.TurnPort,
		VKLink:           pcfg.VKLink,
		UseDTLS:          pcfg.UseDTLS,
		UseUDP:           pcfg.UseUDP,
		UseWrap:          pcfg.UseWrap,
		WrapKey:          wrapKey,
		UseSrtp:          pcfg.UseSrtp,
		UseWrapA:         pcfg.UseWrapA,
		WrapAPassword:    pcfg.WrapAPassword,
		DeviceID:         pcfg.DeviceID,
		NumConns:         pcfg.NumConns,
		CredPoolCooldown: time.Duration(pcfg.CredPoolCooldownSeconds) * time.Second,
		SeededTURN:       seededTURN,
		CredCachePath:    credCachePath,
	})

	// Proxy.Start blocks until the first conn is ready or a fatal error
	// occurs; run it in a goroutine so this export returns immediately.
	// Start() already signals bootstrapDoneCh with the outcome.
	go func() {
		// Pre-bootstrap path: with seeded TURN creds the very first
		// conn would otherwise try its DTLS handshake within ~5ms of
		// extension launch, racing with iOS still applying the VPN
		// network policy on .connecting transition. The kernel kills
		// the UDP socket mid-handshake ("use of closed network
		// connection"), DTLS times out 30s later, tunnel fails.
		// Without seeded creds the extension's own VK API fetch takes
		// 1-3s and provides this delay implicitly. Add an explicit
		// 1.5s settle delay when we skipped that fetch.
		if seededTURN != nil {
			log.Printf("wgStartVKBootstrap: seeded-TURN path — sleeping 1.5s before first DTLS to let iOS network policy settle")
			time.Sleep(1500 * time.Millisecond)
		}
		if err := p.Start(); err != nil {
			log.Printf("wgStartVKBootstrap: proxy.Start failed: %v", err)
			// Proxy.Start already called signalBootstrapDone(err), so
			// wgWaitBootstrapReady will wake up with the error.
		}
	}()

	tunnelsMu.Lock()
	id := nextID
	nextID++
	tunnels[id] = &tunnelEntry{
		proxy: p,
		// device and bind stay nil until wgAttachWireGuard.
	}
	tunnelsMu.Unlock()

	log.Printf("wgStartVKBootstrap: tunnel %d bootstrap goroutine launched", id)
	return C.int32_t(id)
}

//export wgWaitBootstrapReady
//
// Blocks up to timeoutMs waiting for VK bootstrap to report ready. Returns:
//   1  → first conn established a live DTLS+TURN session
//   0  → timeout (bootstrap still in progress; try again or give up)
//  -1  → fatal error before any conn came up, or tunnel handle not found
//
// Safe to call multiple times; the internal signal is replayed so later
// callers see the same outcome.
func wgWaitBootstrapReady(tunnelHandle C.int32_t, timeoutMs C.int32_t) C.int32_t {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		log.Printf("wgWaitBootstrapReady: tunnel %d not found", id)
		return -1
	}

	timeout := time.Duration(int64(timeoutMs)) * time.Millisecond
	err := entry.proxy.WaitBootstrap(timeout)
	if err == nil {
		log.Printf("wgWaitBootstrapReady: tunnel %d ready", id)
		return 1
	}

	// Differentiate timeout from fatal error — callers (Swift) may want to
	// retry on timeout but fail-fast on error.
	if strings.Contains(err.Error(), "bootstrap timeout") {
		log.Printf("wgWaitBootstrapReady: tunnel %d timeout after %s", id, timeout)
		return 0
	}
	log.Printf("wgWaitBootstrapReady: tunnel %d failed: %v", id, err)
	return -1
}

//export wgAttachWireGuard
//
// Attaches a WireGuard device to an already-bootstrapped proxy. The caller
// is expected to have observed wgWaitBootstrapReady return 1 first (so the
// first TURN conn is live). Creates the TUN from tunFd, wires it to a
// TURNBind over the proxy, applies the UAPI config, and brings the device up.
//
// Returns 1 on success, -1 if tunnel handle not found, -2 if a device is
// already attached, or a negative code in -3..-6 for each setup step.
func wgAttachWireGuard(tunnelHandle C.int32_t, wgConfigSettings *C.char, tunFd C.int32_t) C.int32_t {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		log.Printf("wgAttachWireGuard: tunnel %d not found", id)
		return -1
	}
	if entry.device != nil {
		log.Printf("wgAttachWireGuard: tunnel %d already has a WG device attached", id)
		return -2
	}

	goSettings := C.GoString(wgConfigSettings)

	// TURNBind pumps WG packets into/out of the already-started proxy.
	// Proxy.Start() is idempotent, so when WireGuard calls TURNBind.Open()
	// inside dev.Up() below, the second Start() is a no-op.
	bind := turnbind.NewTURNBind(entry.proxy)

	dupFd, err := dupFD(int(tunFd))
	if err != nil {
		log.Printf("wgAttachWireGuard: dup fd failed: %s", err)
		return -3
	}
	tunFile := os.NewFile(uintptr(dupFd), "/dev/tun")
	tunDev, err := tun.CreateTUNFromFile(tunFile, 0)
	if err != nil {
		tunFile.Close()
		log.Printf("wgAttachWireGuard: CreateTUNFromFile failed: %s", err)
		return -4
	}

	logger := device.NewLogger(device.LogLevelVerbose, "(wireguard-turn) ")
	dev := device.NewDevice(tunDev, bind, logger)

	if err := dev.IpcSet(goSettings); err != nil {
		log.Printf("wgAttachWireGuard: IpcSet: %s", err)
		dev.Close()
		return -5
	}
	if err := dev.Up(); err != nil {
		log.Printf("wgAttachWireGuard: Up: %s", err)
		dev.Close()
		return -6
	}

	tunnelsMu.Lock()
	// Re-check under lock in case two attaches raced.
	if entry.device != nil {
		tunnelsMu.Unlock()
		log.Printf("wgAttachWireGuard: tunnel %d raced — tearing down our device", id)
		dev.Close()
		return -2
	}
	entry.device = dev
	entry.bind = bind
	tunnelsMu.Unlock()

	log.Printf("wgAttachWireGuard: tunnel %d WireGuard attached", id)
	return 1
}

//export wgTurnOff
func wgTurnOff(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	delete(tunnels, id)
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	started := time.Now()
	hasDevice := entry.device != nil
	hasProxy := entry.proxy != nil
	log.Printf("wgTurnOff: tunnel %d stopping (device=%v proxy=%v)", id, hasDevice, hasProxy)

	// Order matters: stop proxy FIRST, device SECOND.
	//
	// Build 56 attempted "device.Close then proxy.StopWithTimeout" —
	// observed in vpn.wifi.3.log 2026-05-08 to never reach the
	// proxy.StopWithTimeout call: device.Close() blocked indefinitely
	// while proxy goroutines kept running ("proxy: session ended" lines
	// continued for the full 20 seconds of iOS' NESMVPNSessionStateStopping
	// timeout). Hypothesis: WG device.Close holds device.state.Lock and
	// waits in device.state.stopping.Wait() / tun.Close() for some
	// goroutine that, in turn, is blocked on proxy I/O — proxy keeps
	// reading/writing TUN until its ctx is cancelled. Classic deadlock:
	// WG waits proxy → proxy waits WG.
	//
	// By cancelling proxy first, its goroutines bail out, release their
	// hold on TUN read/write, and device.Close can complete cleanly.
	// Proxy.StopWithTimeout(2s) is the safety net — if some goroutine
	// won't exit promptly, we still proceed; the Go runtime reaps
	// leftovers when iOS terminates the extension after stopTunnel
	// returns its completionHandler.
	if hasProxy {
		ps := time.Now()
		entry.proxy.StopWithTimeout(2 * time.Second)
		log.Printf("wgTurnOff: tunnel %d proxy.Stop took %s", id, time.Since(ps).Round(time.Millisecond))
	}
	if hasDevice {
		ds := time.Now()
		entry.device.Close()
		log.Printf("wgTurnOff: tunnel %d device.Close took %s", id, time.Since(ds).Round(time.Millisecond))
	}
	log.Printf("wgTurnOff: tunnel %d stopped (total %s)", id, time.Since(started).Round(time.Millisecond))
}

//export wgSetConfig
func wgSetConfig(tunnelHandle C.int32_t, settings *C.char) C.int64_t {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return -1
	}
	if entry.device == nil {
		log.Printf("wgSetConfig: tunnel %d has no WG device yet (call wgAttachWireGuard first)", id)
		return -3
	}

	goSettings := C.GoString(settings)
	if err := entry.device.IpcSet(goSettings); err != nil {
		log.Printf("wgSetConfig: %s", err)
		return -2
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("")
	}
	if entry.device == nil {
		return C.CString("")
	}

	settings, err := entry.device.IpcGet()
	if err != nil {
		return C.CString("")
	}
	return C.CString(settings)
}

//export wgGetTURNServerIP
func wgGetTURNServerIP(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("")
	}
	return C.CString(entry.proxy.TURNServerIP())
}

//export wgWaitWrapAProvision
//
// For the SRTP-WRAP-A mode (use_wrap_a=true): blocks up to timeoutMs for the
// server to mint our WireGuard config via GETCONF over the WRAP-A transport,
// then returns it as JSON:
//
//	{"private_key_hex","peer_public_key_hex","address","dns","mtu",
//	 "keepalive_sec","uapi"}
//
// where "uapi" is the ready-to-IpcSet WireGuard config (server-minted keys +
// a fake loopback endpoint our turnbind ignores). The Swift side uses
// address/dns/mtu to build the NEPacketTunnelNetworkSettings and passes "uapi"
// to wgAttachWireGuard. Returns "" on timeout / error / when the tunnel is not
// in WRAP-A mode. Call this AFTER wgWaitBootstrapReady returns 1.
func wgWaitWrapAProvision(tunnelHandle C.int32_t, timeoutMs C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()
	if !ok {
		log.Printf("wgWaitWrapAProvision: tunnel %d not found", id)
		return C.CString("")
	}

	timeout := time.Duration(int64(timeoutMs)) * time.Millisecond
	prov, err := entry.proxy.WaitWrapAProvision(timeout)
	if err != nil {
		log.Printf("wgWaitWrapAProvision: tunnel %d: %v", id, err)
		return C.CString("")
	}

	out := struct {
		PrivateKeyHex    string `json:"private_key_hex"`
		PeerPublicKeyHex string `json:"peer_public_key_hex"`
		Address          string `json:"address"`
		DNS              string `json:"dns"`
		MTU              int    `json:"mtu"`
		KeepaliveSec     int    `json:"keepalive_sec"`
		UAPI             string `json:"uapi"`
	}{
		PrivateKeyHex:    prov.PrivateKeyHex,
		PeerPublicKeyHex: prov.PeerPublicKeyHex,
		Address:          prov.Address,
		DNS:              prov.DNS,
		MTU:              prov.MTU,
		KeepaliveSec:     prov.KeepaliveSec,
		UAPI:             prov.UAPIConfig(),
	}
	data, err := json.Marshal(out)
	if err != nil {
		log.Printf("wgWaitWrapAProvision: tunnel %d marshal: %v", id, err)
		return C.CString("")
	}
	return C.CString(string(data))
}

//export wgGetStats
func wgGetStats(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("{}")
	}

	stats := entry.proxy.GetStats()
	data, err := json.Marshal(stats)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(data))
}

//export wgPause
func wgPause(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	log.Printf("wgPause: pausing tunnel %d", id)
	entry.proxy.Pause()
}

//export wgResume
func wgResume(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	log.Printf("wgResume: resuming tunnel %d", id)
	entry.proxy.Resume()
}

//export wgWakeHealthCheck
func wgWakeHealthCheck(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	entry.proxy.WakeHealthCheck()
}

//export wgPathChanged
//
// Pre-emptive saturation marking on iOS network-path change. Called
// from Swift's NWPathMonitor pathUpdateHandler after dedup. For each
// pool slot with active>0 OR lastUsedAt within ~10 min, marks the slot
// VK-saturated immediately instead of waiting for the next allocate
// attempt to hit 486 (which fires ~0.4-1s later anyway per build 69
// empirical test). Saves the 486 retry burst, routes fresh conns
// straight to the reserve slots.
//
// History: this was originally proposed alongside pre-emptive
// Refresh(0) ("Fix B"). Refresh(0) was empirically disproved 2026-05-10
// (VK ignores it — quota release is timer-bound to server-side 600s
// lifetime). This pre-emptive marking is what remains — it doesn't try
// to make VK release quota, it just stops US from wasting attempts on
// slots we already know are quota-locked.
//
// See evaluated_alternatives_pre_emptive_refresh.md for the empirical
// disproof of the Refresh(0) approach.
func wgPathChanged(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok || entry.proxy == nil {
		return
	}

	entry.proxy.OnPathChange()
}

//export wgPathInTransition
//
// Pause-only path event handler. Called from Swift's NWPathMonitor on
// satisfied events with iface=other (which empirically means our own TUN
// device becoming os-default during the brief recursive-routing window
// between physical interface changes). Unlike wgPathChanged, this does
// NOT trigger smart-pause re-marking — there's no new active state to
// mark, the previous physical-iface unsatisfied event already handled
// that. Instead this extends the pause-acquire window (currently 5s) so
// conns don't acquire fresh slots during the misleading "recovery"
// state.
//
// Without this, the 500ms pause from the previous unsatisfied event
// expires before the real new physical iface arrives (~3s gap observed
// in vpn.over24h.log 2026-05-13 15:26 outage), allowing conns to acquire
// slots that will then host dead allocations + 486 cascade.
//
// See Proxy.OnPathTransition + credPool.ExtendPauseAcquireForTransition
// for full rationale.
func wgPathInTransition(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok || entry.proxy == nil {
		return
	}

	entry.proxy.OnPathTransition()
}

//export wgLogPathSnapshot
//
// Triggers a one-shot pathstats log line. Called by Swift's NWPathMonitor
// handler on every path transition so transient interfaces (e.g. cellular
// briefly visited during a wifi-cellular-wifi handover) appear in the
// pathstats log stream — the periodic 60s ticker can sample at most one
// state per minute and misses sub-minute transitions. The label argument
// is appended to "pathstats <label>" so the caller can mark each snapshot
// (e.g. "wifi-satisfied", "cellular-satisfied").
func wgLogPathSnapshot(tunnelHandle C.int32_t, label *C.char) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok || entry.proxy == nil {
		return
	}

	entry.proxy.LogPathSnapshot(C.GoString(label))
}

//export wgSolveCaptcha
func wgSolveCaptcha(tunnelHandle C.int32_t, answer *C.char) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	goAnswer := C.GoString(answer)
	log.Printf("wgSolveCaptcha: tunnel %d, answer length=%d", id, len(goAnswer))
	entry.proxy.SolveCaptcha(goAnswer)
}

//export wgRefreshCaptchaURL
func wgRefreshCaptchaURL(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("")
	}

	freshURL := entry.proxy.RefreshCaptchaURL()
	return C.CString(freshURL)
}

//export wgSetVKCookieAuth
//
// Sets this process's cookie ("VKAuth") cred-path state. The caller — the main
// app before wgProbeVKCreds, or the extension before wgStartVKBootstrap — reads
// the harvested logged-in cookie from the shared Keychain and passes it here
// out-of-band. The cookie is deliberately NOT in ProxyConfig JSON so it never
// lands in the persisted VPN providerConfiguration. Pass enabled=0, cookie=""
// to force the anonymous paths. When enabled=1, GetVKCreds uses ONLY the cookie
// path (no anonymous fallback). linksJSON is a JSON array of call links — in
// cookie mode the pool spreads conns across each call's relays (~10 per relay).
// See pkg/proxy/creds_vkcookie.go.
func wgSetVKCookieAuth(enabled C.int32_t, cookie *C.char, linksJSON *C.char) {
	var links []string
	if lj := C.GoString(linksJSON); lj != "" {
		_ = json.Unmarshal([]byte(lj), &links)
	}
	proxy.SetVKCookieAuth(enabled != 0, C.GoString(cookie), links)
}

//export wgGetAuthError
//
// Returns the current cookie ("VKAuth") fatal-auth message, or "" if none. The
// extension polls this after bootstrap (cookie mode only): a non-empty value
// means the logged-in cookie was rejected/expired during a background refresh,
// so the extension stops the tunnel with a user-readable message (it can't show
// a login WebView from the background). Process-global; no handle needed. Caller
// frees the returned C string.
func wgGetAuthError() *C.char {
	return C.CString(proxy.CookieAuthFatalError())
}

// wgProbeVKCreds runs one round of GetVKCreds from the main app's process,
// outside any tunnel session. Used by the pre-bootstrap captcha flow to
// pre-solve VK captcha before startVPNTunnel — Step 4's deferred-tunnel-
// settings architecture means the main app loses kernel-level network
// access the moment startVPNTunnel is called, so any captcha encountered
// after that has nowhere to go (extension can't show UI; main app can't
// reach VK to render the WebView). Solving captcha here, while the main
// app still has full network, avoids the deadlock.
//
// Inputs (all C strings; "" / 0 mean "not provided"):
//   linkID, vkHostIPsJSON         — required
//   savedSID, savedKey, savedTs,
//   savedAttempt, savedToken1,
//   savedClientID                 — set on retry after the user solved
//                                   the captcha in a WebView; the entire
//                                   tuple is reused as-is to retry step2.
//
// Returns a malloc'd C string with one of these JSON shapes; caller frees:
//   {"status":"ok","success_token":"...","saved_token1":"...","client_id":"...",
//    "turn_address":"host:port","turn_username":"...","turn_password":"..."}
//   {"status":"captcha","captcha_url":"...","sid":"...","ts":...,
//    "attempt":...,"token1":"...","client_id":"...","is_rate_limit":false}
//   {"status":"error","message":"..."}
//
//export wgProbeVKCreds
func wgProbeVKCreds(linkID, vkHostIPsJSON, savedSID, savedKey, savedToken1, savedClientID *C.char, savedTs, savedAttempt C.double) *C.char {
	gLinkID := C.GoString(linkID)
	gHostIPsJSON := C.GoString(vkHostIPsJSON)
	gSavedSID := C.GoString(savedSID)
	gSavedKey := C.GoString(savedKey)
	gSavedToken1 := C.GoString(savedToken1)
	gSavedClientID := C.GoString(savedClientID)

	// Apply pre-resolved VK host IPs — same as we do in wgStartVKBootstrap,
	// since the probe happens in the same extension process and the dialer
	// (utls.go) reads from package-level state.
	if gHostIPsJSON != "" {
		var hostIPs map[string][]string
		if err := json.Unmarshal([]byte(gHostIPsJSON), &hostIPs); err == nil {
			proxy.SetVKHostIPs(hostIPs)
			log.Printf("wgProbeVKCreds: applied %d pre-resolved VK host IPs", len(hostIPs))
		}
	}

	resp := map[string]interface{}{}
	creds, err := proxy.GetVKCreds(gLinkID, nil, gSavedSID, gSavedKey, float64(savedTs), float64(savedAttempt), gSavedToken1, gSavedClientID)
	if err != nil {
		if cerr, ok := err.(*proxy.CaptchaRequiredError); ok {
			resp["status"] = "captcha"
			resp["captcha_url"] = cerr.ImageURL
			resp["sid"] = cerr.SID
			resp["ts"] = cerr.CaptchaTs
			resp["attempt"] = cerr.CaptchaAttempt
			resp["token1"] = cerr.Token1
			resp["client_id"] = cerr.ClientID
			resp["is_rate_limit"] = cerr.IsRateLimit
		} else if cuerr, ok := err.(*proxy.CallUnavailableError); ok {
			// Non-retryable VK call/link error (call ended/deleted, invalid
			// link). Swift shows a "проблема со звонком" message + stops, instead
			// of the generic "не удалось подключиться".
			resp["status"] = "error"
			resp["message"] = cuerr.Message
			resp["call_unavailable"] = true
			resp["code"] = cuerr.Code
		} else {
			resp["status"] = "error"
			resp["message"] = err.Error()
			// Let Swift distinguish a dead/expired cookie (→ show a clear
			// re-login message) from other probe errors.
			if errors.Is(err, proxy.ErrCookieRejected) {
				resp["cookie_rejected"] = true
			}
		}
	} else {
		resp["status"] = "ok"
		resp["turn_address"] = creds.Address
		resp["turn_username"] = creds.Username
		resp["turn_password"] = creds.Password
	}

	out, mErr := json.Marshal(resp)
	if mErr != nil {
		out = []byte(fmt.Sprintf(`{"status":"error","message":"marshal failed: %s"}`, mErr.Error()))
	}
	return C.CString(string(out))
}

//export wgVersion
func wgVersion() *C.char {
	return C.CString("0.1.0-turn")
}

//export wgSetLogger
func wgSetLogger(loggerFn unsafe.Pointer) {
	if loggerFn == nil {
		return
	}
	log.SetOutput(&clogWriter{fn: loggerFn})
}

type clogWriter struct {
	fn unsafe.Pointer
}

func (w *clogWriter) Write(p []byte) (int, error) {
	msg := C.CString(string(p))
	defer C.free(unsafe.Pointer(msg))
	C.callLogger(w.fn, 0, msg)
	return len(p), nil
}

func dupFD(fd int) (int, error) {
	return unix.Dup(fd)
}

// --- Shared log file support (fully async, zero impact on caller timing) ---

var (
	logFileMu   sync.Mutex
	logFilePath string
	logChan     chan string
)

func startLogWriter() {
	logChan = make(chan string, 512)
	go func() {
		// Buffer messages locally until logFilePath is set by Swift via
		// wgSetLogFilePath. Without this, init()-time log calls (the
		// GOMEMLIMIT line, the FreeOSMemory scheduled-periodic line,
		// etc.) hit a race: if this writer goroutine is scheduled
		// BEFORE wgSetLogFilePath's body runs, p == "" and the
		// messages are silently dropped. Empirically this race fired
		// inconsistently — build 130 captured the GOMEMLIMIT line, build
		// 131 did not, with no code changes affecting the writer.
		//
		// Buffer cap at 1000 lines prevents unbounded growth in case
		// wgSetLogFilePath is never called (e.g., in tests or some
		// failure mode). Init() typically emits a handful of lines so
		// 1000 is generous.
		var pending []string
		const pendingCap = 1000
		for line := range logChan {
			logFileMu.Lock()
			p := logFilePath
			logFileMu.Unlock()
			if p == "" {
				if len(pending) < pendingCap {
					pending = append(pending, line)
				}
				continue
			}
			f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			// Flush any buffered init()-time messages first, in order.
			for _, prev := range pending {
				f.WriteString(prev)
			}
			pending = nil
			f.WriteString(line)
			// Batch-drain (build 154): write any further already-queued lines
			// within this SAME open, so a bootstrap burst (hundreds of
			// lines/sec) doesn't pay an open+close syscall per line. The
			// previous per-line open/close couldn't drain logChan fast enough,
			// the buffer (512) filled, and the NON-blocking osLogWriter sender
			// silently dropped the overflow — losing most file logs under load
			// while os_log (USB) still got everything. Reopening per BATCH (not
			// holding the handle across iterations) stays correct across the
			// Swift-side rotation rename (vpn.log → vpn.log.1).
		drain:
			for {
				select {
				case more := <-logChan:
					f.WriteString(more)
				default:
					break drain
				}
			}
			f.Close()
		}
	}()
}

//export wgSetLogFilePath
func wgSetLogFilePath(path *C.char) {
	p := C.GoString(path)
	logFileMu.Lock()
	logFilePath = p
	logFileMu.Unlock()
	log.Printf("wgSetLogFilePath: %s", p)

	// Side-effect: derive companion paths in the same App Group container.
	// Both main app (wgProbeVKCreds path) and extension (wgStartVKBootstrap
	// path) call wgSetLogFilePath at startup with the same App Group dir,
	// so each process sees the captured browser profile cache the main
	// app's CaptchaWKWebView writes into vk_profile.json. Empty path
	// disables — solveCaptchaPoW silently falls back to generated fp.
	if p != "" {
		profilePath := filepath.Join(filepath.Dir(p), "vk_profile.json")
		proxy.SetVKProfilePath(profilePath)
		log.Printf("wgSetLogFilePath: vk_profile.json path = %s", profilePath)

		// Redirect this process's stderr to the SAME vpn.log file that
		// SharedLogger writes to. Rationale: our normal log.Printf path
		// uses osLogWriter (doesn't touch stderr), so the only writers
		// to stderr are the Go runtime itself (panic messages,
		// runtime.throw, "fatal error: ...", full goroutine dumps on
		// crash) and any C library that aborts. iOS Network Extensions
		// get killed before any stderr line lands in os_log on a
		// fatal-runtime path, so without this redirect we never see
		// what Go was complaining about — the .ips file just shows
		// runtime.raise_trampoline.abi0 at the top of the panicking
		// thread with no message.
		//
		// Using vpn.log (rather than a separate panic.log) means the
		// existing in-app "share logs" flow surfaces the panic without
		// any UI changes — the panic dump just lands at the end of the
		// log the user already knows how to fetch. There's a minor
		// risk of byte-level interleaving with SharedLogger's writes
		// since both fds write to the same file, but for diagnostic
		// purposes it's acceptable: O_APPEND on both fds makes each
		// write atomic up to PIPE_BUF (typically 4KB on iOS), and the
		// per-line panic text plus goroutine-dump prefixes ("fatal
		// error:", "goroutine N [...]") are unmistakable when grep'd
		// out of the otherwise timestamp-prefixed log.
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			if dupErr := unix.Dup2(int(f.Fd()), int(os.Stderr.Fd())); dupErr != nil {
				log.Printf("wgSetLogFilePath: stderr redirect to %s failed: %v", p, dupErr)
				_ = f.Close()
			} else {
				log.Printf("wgSetLogFilePath: stderr redirected to %s (pid=%d) — Go runtime panics will land in this log", p, os.Getpid())
				// Keep f alive; the underlying fd is now duplicated
				// onto stderr. Closing f would only close the original
				// handle, not the dup'd stderr, so leaking f is fine.
				_ = f
			}
		} else {
			log.Printf("wgSetLogFilePath: failed to open stderr redirect target %s: %v", p, err)
		}
	}
}

// osLogWriter writes Go log output to os_log (visible in Console.app)
// AND queues it to the async file writer (zero blocking on caller).
type osLogWriter struct{}

func (osLogWriter) Write(p []byte) (int, error) {
	s := strings.TrimRight(string(p), "\n")
	msg := C.CString(s)
	defer C.free(unsafe.Pointer(msg))
	C.go_os_log(msg)
	// Build timestamped line using local timezone (set via wgSetTimezoneOffset)
	now := time.Now()
	if goTZ != nil {
		now = now.In(goTZ)
	}
	ts := now.Format("15:04:05.000000")
	line := fmt.Sprintf("[Go] %s %s\n", ts, s)
	// Non-blocking send to async writer; drop if buffer full (never block caller)
	select {
	case logChan <- line:
	default:
	}
	return len(p), nil
}

// goTZ holds the local timezone offset set from Swift (iOS Go runtime lacks tzdata).
var goTZ *time.Location

//export wgSetTimezoneOffset
func wgSetTimezoneOffset(offsetSeconds C.int) {
	off := int(offsetSeconds)
	goTZ = time.FixedZone(fmt.Sprintf("UTC%+d", off/3600), off)
	log.Printf("timezone set to %s (offset %ds)", goTZ, off)
}

func init() {
	// Belt-and-suspenders: also set via Go in case C constructor didn't run first
	os.Setenv("GODEBUG", "asyncpreemptoff=1")
	// Start async log file writer
	startLogWriter()
	// Route all Go logs to os_log so they show in Console.app
	log.SetOutput(osLogWriter{})
	// Use no flags — we add our own timestamp with local timezone in osLogWriter
	log.SetFlags(0)

	// Soft cap on Go runtime memory footprint to defend against the iOS
	// NetworkExtension ~50 MB jetsam limit (Type E in
	// failure_patterns_taxonomy.md).
	//
	// The limit covers everything Go has mapped from the OS except
	// goroutine stacks: heap + MSpan/MCache/BuckHash + GC bookkeeping +
	// the runtime's own scratch. As the live footprint approaches the
	// limit, Go's GC runs more aggressively AND returns idle pages to
	// the OS more eagerly — directly addressing the "sys gets stuck at
	// the high-water mark" pattern observed in vpn.wifi.3 (after a
	// transient allocation burst at 14:48 took sys from 37 → 46 MB,
	// heap-alloc fell back to baseline within one GC cycle but sys
	// stayed at 46 MB for the rest of the session — Go's lazy default
	// release behaviour was leaving us 4 MB from jetsam after a single
	// spike).
	//
	// 40 MB was the original choice for DTLS+WG path. Lowered to 35 MB
	// in build 130 after sysdiagnose PowerLog (2026-05-24) confirmed that
	// SRTP path was being killed by JETSAM_REASON_MEMORY_PERPROCESSLIMIT
	// (ReasonCode=7, Namespace=1) — see open_problem_srtp_silent_extension_
	// restarts.md. SRTP uses ~5 MB more than DTLS+WG (probe sender + NAT
	// keepalive per conn, pion DTLS-SRTP state, scratch buffers), so the
	// previous 40 MB limit + Go runtime overhead + spikes during heap
	// pressure routinely pushed phys_footprint past iOS NE's ~50 MB
	// ceiling. 35 MB = 70% of ceiling (Go community standard); below 60%
	// (30 MB) risks GC death spiral on SRTP path where steady-state heap-
	// inuse is already 11-14 MB + stacks ~4 MB + runtime ~5 MB = ~23 MB
	// minimum floor.
	//
	// Empirical baseline at 35 MB cap is TBD — needs soak after build 130.
	// Trade-offs vs 40 MB: ~2-3× more GC cycles, possibly +5-10% CPU
	// during heavy traffic, possible throughput regression of a few % in
	// speedtest. If those regress noticeably, bump back to 38 MB. If
	// jetsam still fires at 35 MB, the next lever is reducing live
	// working set (smaller per-conn buffers, fewer goroutines, lower
	// NumConns) rather than dropping the limit further.
	debug.SetMemoryLimit(35 << 20)
	log.Printf("bridge: GOMEMLIMIT set to 35 MB (soft cap for jetsam defence — lowered from 40 MB in build 130)")

	// Periodic debug.FreeOSMemory() — added in build 131 after build 130
	// soak confirmed Fix A reduced but did not eliminate JETSAM_REASON_
	// MEMORY_PERPROCESSLIMIT events. Root cause: SetMemoryLimit makes Go
	// MARK idle pages as returnable (heap-released grows), but Go's default
	// scavenger is lazy about actually unmapping them from the address
	// space — pages stay mapped until kernel pressure forces release. iOS
	// jetsam PERPROCESSLIMIT can count mapped pages (not just resident),
	// so even with heap-released=22 MB the extension can be killed for
	// "too much memory mapped" during a sleep cycle.
	//
	// Empirical episode (vpn.wifi.0.log 2026-05-24 16:39:54): rss=24.4 MB
	// sys=45.8 MB heap-released=22.2 MB immediately before sleep → JETSAM
	// fired during the ~6-minute deep-sleep window with no further
	// allocations from our side. sys peak from a 16:18-16:19 speedtest
	// burst stuck at 45.8 MB for 20+ minutes because Go's scavenger hadn't
	// yet unmapped the released pages. FreeOSMemory() forces the unmap
	// immediately.
	//
	// 60s interval = balance between responsiveness (catches high-water-
	// mark spikes within a minute of the spike subsiding) and overhead
	// (FreeOSMemory is heavier than a normal GC — ~10-50ms on phone-class
	// CPU when there's a lot to scavenge, microseconds when there isn't).
	// Net cost in idle: negligible. Net cost during traffic burst: small
	// jitter once per minute, well below user-perceptible threshold.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()
	log.Printf("bridge: scheduled periodic debug.FreeOSMemory() every 60s (build 131)")

	// Wire the proxy's memstats logger to read this process's
	// task_vm_info breakdown via the Mach task_info bridge (see
	// go_get_vm_stats in the cgo preamble). Single kernel call per
	// memstats tick returns phys_footprint + internal/external/
	// reusable/compressed pages atomically. phys_footprint is what
	// iOS jetsam evaluates; the breakdown distinguishes Go-side from
	// non-Go memory growth so we can attribute spikes when
	// runtime.MemStats alone gives an incomplete picture.
	//
	// Replaces the old proxy.PhysFootprintFn (which returned only
	// phys_footprint as a single uint64) — see proxy.TaskVMInfo doc
	// for field semantics.
	proxy.TaskVMInfoFn = func() proxy.TaskVMInfo {
		r := C.go_get_vm_stats()
		return proxy.TaskVMInfo{
			PhysFootprint: uint64(r.phys_footprint),
			Internal:      uint64(r.internal),
			External:      uint64(r.external),
			Reusable:      uint64(r.reusable),
			Compressed:    uint64(r.compressed),
		}
	}
}

func main() {}
