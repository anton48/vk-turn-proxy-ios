package main

// csqtt as the app's sixth transport — stage 5, variant B (2026-09-06).
//
// This file is ADDITIONS ONLY: its own handle registry and its own exports,
// and nothing in bridge.go changes. The Swift side holds a TunnelBackend
// enum whose kind decides which family of exports a handle is passed to, so
// a csqtt handle is never looked up in the WireGuard registry or vice versa
// (the two count from 1 independently, on purpose — the enum carries the
// kind, a number never does).
//
// What differs from the WireGuard path: there is no WireGuard device. The
// csqtt server hands the client a tunnel IP and DNS (TUNCONF), the client
// carries RAW IP packets over N TURN allocations, and this file pumps them
// between the TUN descriptor iOS gives us and csqtt.Client. Credentials
// come from the SAME pool policy as the native transport (proxy.CredPool:
// 10 allocations per identity, one relay anonymously, the cold-start cap,
// the grower's pace, the on-disk cache, cookie auth, the TURN override),
// through an adapter that turns the pool's slot into csqtt's credential
// lease. The pool uses its OWN cache file until D unifies the two.

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"

	"golang.zx2c4.com/wireguard/tun"
)

// csqttMTU is the tunnel MTU csqtt runs at: the server's TUN is 1300 and a
// larger packet from our side is dropped there (a 1280-byte QUIC initial
// does NOT fit under it either — 1300 minus the raw-IP framing the server
// counts; measured 2026-09-05). The user's explicit MTU still wins on the
// Swift side, as it does for WRAP-A.
const csqttMTU = 1300

// csqttTunOffset is where a packet starts inside the pump buffers. Darwin's
// utun wants the 4-byte address-family header in front of every packet, and
// wireguard-go's tun reads and writes it at offset-4 — so the offset must be
// at least 4. 16 is what wireguard-go itself uses.
const csqttTunOffset = 16

// csqttMaxPacket bounds one packet in the pumps. The tunnel MTU is 1300, but
// the TUN can hand us anything up to 64 KiB; a packet the server would drop
// is dropped here, with the counter, rather than growing the buffers.
const csqttMaxPacket = 65536

// csqttPrefix is the tunnel address's prefix length in the network settings.
// TUNCONF carries a bare IP; the server's subnet is a /24 with the gateway
// at .1 (stage 3, the console client).
const csqttPrefix = "/24"

// csqttConfig is what csqttStart reads out of the SAME proxy_config JSON the
// WireGuard path is given: the shared fields under their existing names plus
// the csqtt ones. json.Unmarshal ignores what it does not know on both
// sides, so ProxyConfig in bridge.go is untouched.
type csqttConfig struct {
	Server   string `json:"peer_addr"`       // the csqtt server, host:port (the profile's "Proxy Server")
	Password string `json:"csqtt_password"`  // HKDF input for the wire key AND GETCONF authentication
	DeviceID string `json:"csqtt_device_id"` // stable per install: the server binds an unbound password to it

	VKLink                  string              `json:"vk_link"`
	NumConns                int                 `json:"num_conns"`
	UseUDP                  bool                `json:"use_udp"`
	TurnServer              string              `json:"turn_server"`
	TurnPort                string              `json:"turn_port"`
	CredPoolCooldownSeconds int                 `json:"cred_pool_cooldown_seconds"`
	VKHostIPs               map[string][]string `json:"vk_host_ips"`
	SeededTURN              *struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"seeded_turn"`
	UseCookieAuth      bool `json:"use_cookie_auth"`
	ForceLegacyCaptcha bool `json:"force_legacy_captcha"`
}

// csqttClient is what the bridge needs from csqtt.Client — an interface so
// the lifecycle can be tested against a fake on the host, where no VK relay
// answers.
type csqttClient interface {
	WritePacket(pkt []byte) error
	ReadPacket(ctx context.Context) ([]byte, error)
	Close() error
	Stats() csqtt.Stats
	Config() csqtt.ConfigResponse
	OnPathChange()
	WakeHealthCheck()
	Done() <-chan struct{}
	Err() error
}

// csqttDial is csqtt.Dial behind a variable, replaceable by tests.
var csqttDial = func(ctx context.Context, cfg csqtt.Config) (csqttClient, error) {
	c, err := csqtt.Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// csqttNewPool is proxy.NewCredPool behind a variable, so tests can hand the
// pool a fetcher that mints nothing.
var csqttNewPool = func(ctx context.Context, cfg proxy.CredPoolConfig) *proxy.CredPool {
	return proxy.NewCredPool(ctx, cfg)
}

// packetDevice is the part of tun.Device the pumps use.
type packetDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	Events() <-chan tun.Event
	Close() error
}

// csqttOpenTun wraps an ALREADY DUPLICATED descriptor as a utun device.
// Behind a variable so tests can substitute a socketpair-backed device with
// the same Read/Write contract; the production one is wireguard-go's
// darwin tun, which reads the address-family header itself.
var csqttOpenTun = func(dupFd int) (packetDevice, error) {
	f := os.NewFile(uintptr(dupFd), "/dev/tun")
	dev, err := tun.CreateTUNFromFile(f, 0)
	if err != nil {
		f.Close()
		return nil, err
	}
	return dev, nil
}

// csqttAcquireBackstop is how long the credential adapter waits for a slot
// before asking the pool again when no broadcast wakes it (a lost wake-up
// is then a delay, not a hang). Doubles up to csqttAcquireBackstopMax.
var (
	csqttAcquireBackstop    = 250 * time.Millisecond
	csqttAcquireBackstopMax = 5 * time.Second
)

// csqttSeededSettle mirrors wgStartVKBootstrap: with a seeded credential the
// first allocation would go out within milliseconds of extension launch,
// while iOS is still applying the VPN policy for the .connecting transition —
// the kernel then kills that socket mid-handshake. Without a seed the
// extension's own VK fetch provides the delay implicitly.
var csqttSeededSettle = 1500 * time.Millisecond

// csqttPumpJoinBudget bounds how long csqttTurnOff waits for the pumps after
// the client and the device are closed.
const csqttPumpJoinBudget = 2 * time.Second

// csqttEntry is one csqtt tunnel: its pool, its client once dialed, its
// device once attached, and the terminal error if it has one.
type csqttEntry struct {
	id      int32
	ctx     context.Context
	cancel  context.CancelFunc
	pool    *proxy.CredPool
	started time.Time

	dialed chan struct{} // closed when csqttDial returned, either way
	client csqttClient   // set before dialed is closed on success; nil on failure
	fatal  atomic.Pointer[string]

	devMu sync.Mutex
	dev   packetDevice
	pumps sync.WaitGroup

	// pump counters, reported through csqttLogPathSnapshot and the stop line
	tunIn, tunOut, tunTooBig, sendErr atomic.Int64
}

// fail records the tunnel's terminal error (first one wins) and ends its
// lifetime: Dial returns, the pumps stop, csqttWaitReady answers -1 and
// csqttGetError carries the text to Swift.
func (e *csqttEntry) fail(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if e.fatal.CompareAndSwap(nil, &msg) {
		log.Printf("csqtt: tunnel %d: TERMINAL: %s", e.id, msg)
	}
	e.cancel()
}

func (e *csqttEntry) errText() string {
	if p := e.fatal.Load(); p != nil {
		return *p
	}
	return ""
}

var (
	csqttTunnels   = make(map[int32]*csqttEntry)
	csqttTunnelsMu sync.Mutex
	csqttNextID    int32 = 1
)

func csqttLookup(handle int32) *csqttEntry {
	csqttTunnelsMu.Lock()
	defer csqttTunnelsMu.Unlock()
	return csqttTunnels[handle]
}

// csqttPoolAdapter turns proxy.CredPool's slot into csqtt's credential lease.
type csqttPoolAdapter struct {
	pool  *proxy.CredPool
	fatal func(error)
}

// creds is csqtt.Config.Creds. Worker ids are 1-based, the pool's connIdx
// 0-based: worker k → k−1, so ten workers share one credential exactly as
// ten connections do. The pool never blocks: it answers "paused for the
// path-change settle", "cold-start cap — parking" or "no slot available"
// and the caller parks on SlotAvailable — which is taken BEFORE the failed
// Acquire, because a broadcast between the failure and the wait would
// otherwise be missed (the timer backstop turns that into a delay, never a
// hang). A captcha, a dead call link or a rejected cookie is TERMINAL for
// the tunnel: csqtt has no WebView to show, so the tunnel stops with the
// reason instead of retrying for the whole bootstrap budget.
func (a *csqttPoolAdapter) creds(ctx context.Context, workerID int) (csqtt.Credential, error) {
	idx := workerID - 1
	if idx < 0 {
		idx = 0
	}
	wait := csqttAcquireBackstop
	for {
		avail := a.pool.SlotAvailable()
		addr, creds, slot, err := a.pool.Acquire(idx)
		if err == nil {
			var once sync.Once
			return csqtt.Credential{
				TURNCredentials: csqtt.TURNCredentials{Username: creds.Username, Password: creds.Password, Address: addr},
				Release:         func() { once.Do(func() { a.pool.Release(slot) }) },
			}, nil
		}
		if terminal := csqttTerminalCredError(err); terminal != nil {
			a.fatal(terminal)
			return csqtt.Credential{}, terminal
		}
		select {
		case <-avail:
		case <-time.After(wait):
		case <-ctx.Done():
			return csqtt.Credential{}, ctx.Err()
		}
		if wait < csqttAcquireBackstopMax {
			wait *= 2
		}
	}
}

// csqttTerminalCredError names the credential failures no retry can fix
// from inside the extension; nil for the pool's transient answers.
func csqttTerminalCredError(err error) error {
	var captcha *proxy.CaptchaRequiredError
	if errors.As(err, &captcha) {
		return errors.New("VK requires a captcha to mint relay credentials. csqtt cannot show it here — enable VK account auth in Settings, or connect once with the SRTP transport (which can), then try csqtt again.")
	}
	var call *proxy.CallUnavailableError
	if errors.As(err, &call) {
		return fmt.Errorf("VK call link is unusable: %s", call.Error())
	}
	if msg := proxy.CookieAuthFatalError(); msg != "" {
		return fmt.Errorf("VK session rejected or expired (%s). Re-login in Settings.", msg)
	}
	return nil
}

// csqttNextIdentity is the (generation, salt) pair for a NEW session. The
// server keys its epoch on the pair and replaces every older session of the
// device when a different one arrives; the generation is kept strictly
// increasing across connects by persisting the last one beside the cred
// cache (the reference client persists a counter for the same reason).
func csqttNextIdentity(dir string) (uint64, string) {
	var prev uint64
	path := ""
	if dir != "" {
		path = filepath.Join(dir, "csqtt-generation")
		if b, err := os.ReadFile(path); err == nil {
			prev, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		}
	}
	gen, salt := csqtt.NewIdentity(prev)
	if path != "" {
		if err := os.WriteFile(path, []byte(strconv.FormatUint(gen, 10)), 0o600); err != nil {
			log.Printf("csqtt: could not persist the generation: %v", err)
		}
	}
	return gen, salt
}

// csqttCacheDir is where the pool's cache and the generation live: the App
// Group directory the log file is in, or nothing (no persistence) when
// Swift has not set a log path.
func csqttCacheDir() string {
	logFileMu.Lock()
	p := logFilePath
	logFileMu.Unlock()
	if p == "" {
		return ""
	}
	return filepath.Dir(p)
}

// Starts a csqtt tunnel: the credential pool now, the client in a goroutine
// (credentials, N allocations, GETCONF → TUNCONF). No TUN yet. Returns a
// handle at once, -1 on unparseable JSON, -2 when the server or the
// password is missing. Observe progress with csqttWaitReady.
//
//export csqttStart
func csqttStart(proxyConfigJSON *C.char) C.int32_t {
	return C.int32_t(csqttStartImpl(C.GoString(proxyConfigJSON)))
}

func csqttStartImpl(proxyConfigJSON string) int32 {
	var cfg csqttConfig
	if err := json.Unmarshal([]byte(proxyConfigJSON), &cfg); err != nil {
		log.Printf("csqttStart: invalid config JSON: %v", err)
		return -1
	}
	if cfg.Server == "" || cfg.Password == "" {
		log.Printf("csqttStart: server (peer_addr) and csqtt_password are required")
		return -2
	}
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	if cfg.NumConns > csqtt.MaxWorkers {
		cfg.NumConns = csqtt.MaxWorkers
	}

	// The same process-wide switches wgStartVKBootstrap applies: the
	// pre-resolved VK hosts (the extension cannot resolve them itself before
	// setTunnelNetworkSettings), the captcha-path flag, and cookie auth OFF
	// unless asked (the extension process is reused across connects).
	if len(cfg.VKHostIPs) > 0 {
		proxy.SetVKHostIPs(cfg.VKHostIPs)
	}
	proxy.SetForceLegacyCaptcha(cfg.ForceLegacyCaptcha)
	if !cfg.UseCookieAuth {
		proxy.SetVKCookieAuth(false, "", nil)
	}

	dir := csqttCacheDir()
	cachePath := ""
	if dir != "" {
		// Its OWN file: two pools writing creds-pool.json in one process
		// would overwrite each other (the extension is reused across
		// connects). D unifies the pools and the file.
		cachePath = filepath.Join(dir, "creds-pool-csqtt.json")
	}
	var seed *proxy.TURNCreds
	if cfg.SeededTURN != nil && cfg.SeededTURN.Address != "" {
		seed = &proxy.TURNCreds{Address: cfg.SeededTURN.Address, Username: cfg.SeededTURN.Username, Password: cfg.SeededTURN.Password,
			Addresses: []string{cfg.SeededTURN.Address}}
		log.Printf("csqttStart: using pre-fetched TURN creds (addr=%s)", seed.Address)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := csqttNewPool(ctx, proxy.CredPoolConfig{
		VKLink:     cfg.VKLink,
		NumConns:   cfg.NumConns,
		Cooldown:   time.Duration(cfg.CredPoolCooldownSeconds) * time.Second,
		CachePath:  cachePath,
		TurnServer: cfg.TurnServer,
		TurnPort:   cfg.TurnPort,
		SeededTURN: seed,
	})
	e := &csqttEntry{ctx: ctx, cancel: cancel, pool: pool, started: time.Now(), dialed: make(chan struct{})}
	csqttTunnelsMu.Lock()
	e.id = csqttNextID
	csqttNextID++
	csqttTunnels[e.id] = e
	csqttTunnelsMu.Unlock()

	transport := "tcp"
	if cfg.UseUDP {
		transport = "udp"
	}
	gen, salt := csqttNextIdentity(dir)
	adapter := &csqttPoolAdapter{pool: pool, fatal: e.fail}
	// Never the password: the config line Swift logs is the redacted one.
	log.Printf("csqttStart: tunnel %d: server=%s device=%s workers=%d transport=%s gen=%d cache=%v seeded=%v",
		e.id, cfg.Server, cfg.DeviceID, cfg.NumConns, transport, gen, cachePath != "", seed != nil)

	go func() {
		defer close(e.dialed)
		if seed != nil {
			select {
			case <-time.After(csqttSeededSettle):
			case <-ctx.Done():
				return
			}
		}
		server, err := net.ResolveUDPAddr("udp4", cfg.Server)
		if err != nil {
			e.fail(fmt.Errorf("csqtt server %q: %w", cfg.Server, err))
			return
		}
		client, err := csqttDial(ctx, csqtt.Config{
			Server: server, Password: cfg.Password, DeviceID: cfg.DeviceID,
			Generation: gen, Salt: salt, Workers: cfg.NumConns,
			Creds: adapter.creds, TURNTransport: transport, TURNLogLevel: logging.LogLevelWarn,
			Logf: log.Printf,
		})
		if err != nil {
			e.fail(fmt.Errorf("csqtt: %w", err))
			return
		}
		e.client = client
		// The first worker is live: the grower may fill the pool from here,
		// at the same pace the native transport's does.
		go pool.Grow(nil)
		// A client that stops on its own (DENIED is fatal for the whole
		// client) is a terminal failure Swift must hear about.
		go func() {
			select {
			case <-client.Done():
				if err := client.Err(); err != nil {
					e.fail(err)
				}
			case <-ctx.Done():
			}
		}()
		log.Printf("csqttStart: tunnel %d: ready (%s)", e.id, client.Config().Raw)
	}()
	return e.id
}

// Blocks up to timeoutMs for the first worker's TUNCONF: 1 ready, 0 still
// connecting, -1 terminal failure (csqttGetError has the text) or unknown
// handle.
//
//export csqttWaitReady
func csqttWaitReady(handle C.int32_t, timeoutMs C.int32_t) C.int32_t {
	return C.int32_t(csqttWaitReadyImpl(int32(handle), time.Duration(int64(timeoutMs))*time.Millisecond))
}

func csqttWaitReadyImpl(handle int32, timeout time.Duration) int32 {
	e := csqttLookup(handle)
	if e == nil {
		return -1
	}
	select {
	case <-e.dialed:
	case <-e.ctx.Done():
	case <-time.After(timeout):
		return 0
	}
	if e.errText() != "" || e.client == nil {
		return -1
	}
	return 1
}

// The provision the server handed the first worker, for the network
// settings: {"address":"<ip>/24","dns":"<a>[,<b>]","mtu":1300,"stream":"…"}.
// "" (caller frees) before ready or on an unknown handle.
//
//export csqttProvision
func csqttProvision(handle C.int32_t) *C.char {
	return C.CString(csqttProvisionImpl(int32(handle)))
}

func csqttProvisionImpl(handle int32) string {
	e := csqttLookup(handle)
	if e == nil || e.client == nil {
		return ""
	}
	return csqttProvisionJSON(e.client.Config())
}

func csqttProvisionJSON(conf csqtt.ConfigResponse) string {
	if conf.TunnelIP == "" {
		return ""
	}
	out := struct {
		Address string `json:"address"`
		DNS     string `json:"dns"`
		MTU     int    `json:"mtu"`
		Stream  string `json:"stream"`
	}{Address: conf.TunnelIP + csqttPrefix, DNS: conf.DNS, MTU: csqttMTU, Stream: conf.StreamRevision}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// Attaches the TUN: duplicates tunFd (the caller keeps its own), wraps the
// duplicate as a utun device and starts the two pumps — ONE tun reader that
// is the only WritePacket caller, ONE ReadPacket loop writing to the tun —
// plus a drain of the device's event channel. 1 on success; -1 unknown
// handle, -2 already attached or not ready, -3 dup failed, -4 the device.
//
//export csqttAttach
func csqttAttach(handle C.int32_t, tunFd C.int32_t) C.int32_t {
	return C.int32_t(csqttAttachImpl(int32(handle), int(tunFd)))
}

func csqttAttachImpl(handle int32, tunFd int) int32 {
	e := csqttLookup(handle)
	if e == nil {
		return -1
	}
	if e.client == nil {
		log.Printf("csqttAttach: tunnel %d is not ready", e.id)
		return -2
	}
	e.devMu.Lock()
	defer e.devMu.Unlock()
	if e.dev != nil {
		log.Printf("csqttAttach: tunnel %d already has a device", e.id)
		return -2
	}
	dupFd, err := dupFD(tunFd)
	if err != nil {
		log.Printf("csqttAttach: dup fd failed: %v", err)
		return -3
	}
	// Non-blocking, as wireguard-apple does before CreateTUNFromFile: the
	// reads then go through Go's poller and Close wakes the reader. A
	// blocking descriptor leaves the tun reader stuck in read(2) after
	// Close, and TurnOff would wait out its whole join budget.
	if err := unix.SetNonblock(dupFd, true); err != nil {
		log.Printf("csqttAttach: SetNonblock: %v", err)
		unix.Close(dupFd)
		return -3
	}
	dev, err := csqttOpenTun(dupFd)
	if err != nil {
		log.Printf("csqttAttach: open tun failed: %v", err)
		return -4
	}
	e.dev = dev
	e.pumps.Add(3)
	go e.pumpUp(dev)
	go e.pumpDown(dev)
	go e.drainEvents(dev)
	log.Printf("csqttAttach: tunnel %d attached (fd %d → dup %d)", e.id, tunFd, dupFd)
	return 1
}

// pumpUp: TUN → relays. The only caller of WritePacket (not concurrency-safe
// by contract). A packet the server would drop for size is counted and
// dropped here.
func (e *csqttEntry) pumpUp(dev packetDevice) {
	defer e.pumps.Done()
	bufs := [][]byte{make([]byte, csqttTunOffset+csqttMaxPacket)}
	sizes := make([]int, 1)
	for {
		n, err := dev.Read(bufs, sizes, csqttTunOffset)
		if err != nil {
			if e.ctx.Err() == nil {
				log.Printf("csqtt: tunnel %d: tun read: %v", e.id, err)
			}
			return
		}
		if n == 0 {
			continue
		}
		pkt := bufs[0][csqttTunOffset : csqttTunOffset+sizes[0]]
		e.tunIn.Add(1)
		if err := e.client.WritePacket(pkt); err != nil {
			e.sendErr.Add(1)
		}
	}
}

// pumpDown: relays → TUN. csqtt's own out-queue (1024 packets, Dropped in
// its stats) is the bound on this side.
func (e *csqttEntry) pumpDown(dev packetDevice) {
	defer e.pumps.Done()
	wbuf := make([]byte, csqttTunOffset+csqttMaxPacket)
	for {
		p, err := e.client.ReadPacket(e.ctx)
		if err != nil {
			return
		}
		if len(p) > csqttMaxPacket {
			e.tunTooBig.Add(1)
			continue
		}
		copy(wbuf[csqttTunOffset:], p)
		if _, err := dev.Write([][]byte{wbuf[:csqttTunOffset+len(p)]}, csqttTunOffset); err != nil {
			if e.ctx.Err() == nil {
				log.Printf("csqtt: tunnel %d: tun write: %v", e.id, err)
			}
			return
		}
		e.tunOut.Add(1)
	}
}

// drainEvents keeps the device's event channel from filling (wireguard-go's
// device would consume it; here nobody else does).
func (e *csqttEntry) drainEvents(dev packetDevice) {
	defer e.pumps.Done()
	for ev := range dev.Events() {
		log.Printf("csqtt: tunnel %d: tun event %v", e.id, ev)
	}
}

// Stops a csqtt tunnel: the client first (DISCONNECT best-effort, relays
// closed, bounded), then the device (which ends the tun reader), then the
// pumps are joined with a budget, then the pool writes its cache and stops
// minting. Safe on an unknown handle.
//
//export csqttTurnOff
func csqttTurnOff(handle C.int32_t) { csqttTurnOffImpl(int32(handle)) }

func csqttTurnOffImpl(handle int32) {
	csqttTunnelsMu.Lock()
	e, ok := csqttTunnels[handle]
	delete(csqttTunnels, handle)
	csqttTunnelsMu.Unlock()
	if !ok {
		return
	}
	started := time.Now()
	log.Printf("csqttTurnOff: tunnel %d stopping", e.id)
	e.cancel()
	if e.client != nil {
		t := time.Now()
		_ = e.client.Close()
		log.Printf("csqttTurnOff: tunnel %d client.Close took %s", e.id, time.Since(t).Round(time.Millisecond))
	}
	e.devMu.Lock()
	dev := e.dev
	e.devMu.Unlock()
	if dev != nil {
		_ = dev.Close()
	}
	joined := make(chan struct{})
	go func() {
		e.pumps.Wait()
		close(joined)
	}()
	select {
	case <-joined:
	case <-time.After(csqttPumpJoinBudget):
		log.Printf("csqttTurnOff: tunnel %d pumps still running after %s — returning anyway", e.id, csqttPumpJoinBudget)
	}
	e.pool.Close()
	log.Printf("csqttTurnOff: tunnel %d stopped (total %s; tun in=%d out=%d toobig=%d senderr=%d)",
		e.id, time.Since(started).Round(time.Millisecond), e.tunIn.Load(), e.tunOut.Load(), e.tunTooBig.Load(), e.sendErr.Load())
}

// Path change (NWPathMonitor, satisfied on a real interface): the pool marks
// the slots in use and pauses acquires briefly, as it does for the native
// transport; the client takes a new identity and restarts every worker,
// releasing each old lease as its session ends.
//
//export csqttPathChanged
func csqttPathChanged(handle C.int32_t) { csqttPathChangedImpl(int32(handle)) }

func csqttPathChangedImpl(handle int32) {
	e := csqttLookup(handle)
	if e == nil {
		return
	}
	e.pool.OnPathChange()
	if e.client != nil {
		e.client.OnPathChange()
	}
}

// The iface=other transition (our own TUN briefly the default): extend the
// pool's acquire pause, as Proxy.OnPathTransition does, and nothing else.
//
//export csqttPathInTransition
func csqttPathInTransition(handle C.int32_t) {
	if e := csqttLookup(int32(handle)); e != nil {
		e.pool.ExtendPause(5 * time.Second)
	}
}

// Wake: every clock resets and every ready worker is probed; never waits for
// a relay write.
//
//export csqttWakeHealthCheck
func csqttWakeHealthCheck(handle C.int32_t) { csqttWakeHealthCheckImpl(int32(handle)) }

func csqttWakeHealthCheckImpl(handle int32) {
	if e := csqttLookup(handle); e != nil && e.client != nil {
		e.client.WakeHealthCheck()
	}
}

// One log line on demand, the csqtt shape of pathstats.
//
//export csqttLogPathSnapshot
func csqttLogPathSnapshot(handle C.int32_t, label *C.char) {
	e := csqttLookup(int32(handle))
	if e == nil {
		return
	}
	l := C.GoString(label)
	if e.client == nil {
		log.Printf("csqtt: pathstats %s: not ready yet", l)
		return
	}
	s := e.client.Stats()
	log.Printf("csqtt: pathstats %s: workers %d/%d ready, restarts %d, repairs %d, probes %d, lost %d; tun in=%d out=%d",
		l, s.Ready, s.Total, s.Restarts, s.Repairs, s.Probes, s.LostWorkers, e.tunIn.Load(), e.tunOut.Load())
}

// Stats in the app's shape — the same struct the WireGuard path marshals,
// so the keys cannot drift from Swift's TunnelStats. active/total conns are
// ready/total workers, the RTT is the last relay allocation, reconnects are
// worker restarts; auth_error is the cookie latch exactly as on the native
// path (a csqtt terminal reason is csqttGetError's). "{}" on an unknown handle.
//
//export csqttGetStats
func csqttGetStats(handle C.int32_t) *C.char {
	return C.CString(csqttGetStatsImpl(int32(handle)))
}

func csqttGetStatsImpl(handle int32) string {
	e := csqttLookup(handle)
	if e == nil {
		return "{}"
	}
	b, err := json.Marshal(csqttAppStats(e))
	if err != nil {
		return "{}"
	}
	return string(b)
}

func csqttAppStats(e *csqttEntry) proxy.Stats {
	ps := e.pool.Stats()
	s := proxy.Stats{
		CredPoolFilled:         int32(ps.Available),
		CredPoolWithCreds:      int32(ps.WithCreds),
		CredPoolSize:           int32(ps.Size),
		CredPoolDistinctRelays: int32(ps.DistinctRelays),
		TunnelUptimeSec:        int64(time.Since(e.started).Seconds()),
		// The cookie latch only, as on the native path: the app answers a
		// non-empty auth_error with its VK-session text and a disconnect.
		// csqtt's own terminal reason is csqttGetError's, which the
		// extension's watchdog turns into a stop with THAT reason.
		AuthError: proxy.CookieAuthFatalError(),
	}
	if e.client != nil {
		cs := e.client.Stats()
		s.TxBytes = cs.TxBytes
		s.RxBytes = cs.RxBytes
		s.ActiveConns = int32(cs.Ready)
		s.TotalConns = int32(cs.Total)
		s.TurnRTTms = float64(cs.AllocateRTT) / 1e6
		s.Reconnects = cs.Restarts
	}
	return s
}

// The relay host to publish as serverAddress next time — the pool's answer,
// which is non-empty after a warm-cache start too. "" (caller frees) on an
// unknown handle.
//
//export csqttGetRelayIP
func csqttGetRelayIP(handle C.int32_t) *C.char {
	return C.CString(csqttGetRelayIPImpl(int32(handle)))
}

func csqttGetRelayIPImpl(handle int32) string {
	e := csqttLookup(handle)
	if e == nil {
		return ""
	}
	return e.pool.RelayIP()
}

// The terminal error, or "" (caller frees). Non-empty once csqttWaitReady
// has answered -1, or later when the client stopped on its own (DENIED).
//
//export csqttGetError
func csqttGetError(handle C.int32_t) *C.char {
	return C.CString(csqttGetErrorImpl(int32(handle)))
}

func csqttGetErrorImpl(handle int32) string {
	e := csqttLookup(handle)
	if e == nil {
		return ""
	}
	return e.errText()
}
