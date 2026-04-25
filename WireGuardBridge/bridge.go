package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <os/log.h>

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
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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

// ProxyConfig is the JSON config passed from Swift.
type ProxyConfig struct {
	VKLink              string            `json:"vk_link"`
	PeerAddr            string            `json:"peer_addr"`
	TurnServer          string            `json:"turn_server,omitempty"`
	TurnPort            string            `json:"turn_port,omitempty"`
	UseDTLS             bool              `json:"use_dtls"`
	UseUDP              bool              `json:"use_udp"`
	NumConns            int               `json:"num_conns,omitempty"`
	CredPoolTTLSeconds  int               `json:"cred_pool_ttl_seconds,omitempty"`
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

	// Create proxy
	p := proxy.NewProxy(proxy.Config{
		PeerAddr:     pcfg.PeerAddr,
		TurnServer:   pcfg.TurnServer,
		TurnPort:     pcfg.TurnPort,
		VKLink:       pcfg.VKLink,
		UseDTLS:      pcfg.UseDTLS,
		UseUDP:       pcfg.UseUDP,
		NumConns:     pcfg.NumConns,
		CredPoolTTL:  time.Duration(pcfg.CredPoolTTLSeconds) * time.Second,
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

	p := proxy.NewProxy(proxy.Config{
		PeerAddr:     pcfg.PeerAddr,
		TurnServer:   pcfg.TurnServer,
		TurnPort:     pcfg.TurnPort,
		VKLink:       pcfg.VKLink,
		UseDTLS:      pcfg.UseDTLS,
		UseUDP:       pcfg.UseUDP,
		NumConns:     pcfg.NumConns,
		CredPoolTTL:  time.Duration(pcfg.CredPoolTTLSeconds) * time.Second,
		SeededTURN:   seededTURN,
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

	// device may be nil if the tunnel was started via wgStartVKBootstrap
	// but wgAttachWireGuard was never called (e.g. bootstrap timed out).
	// In that case we still have to stop the proxy goroutine to release
	// its TURN allocation and background goroutines.
	if entry.device != nil {
		entry.device.Close()
	} else if entry.proxy != nil {
		entry.proxy.Stop()
	}
	log.Printf("wgTurnOff: tunnel %d stopped", id)
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
		} else {
			resp["status"] = "error"
			resp["message"] = err.Error()
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
		for line := range logChan {
			logFileMu.Lock()
			p := logFilePath
			logFileMu.Unlock()
			if p == "" {
				continue
			}
			f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				continue
			}
			f.WriteString(line)
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
}

func main() {}
