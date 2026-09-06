package main

// The csqtt bridge's contract with Swift and with the pool, on the host: a
// fake client in place of csqtt.Dial (no VK relay answers here), a
// socketpair-backed device with wireguard-go's darwin tun contract in place
// of the utun, and a pool fed by a fetcher that mints nothing real. What
// these check is what swiftcheck cannot see — descriptor ownership, the
// pumps' offsets, the join, the pool closing behind the stop — and what the
// app relies on: the lease, the terminal errors, the stats keys.
//
// Every claim was seen RED under its own sabotage before the commit; the
// comment on each test names it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"

	"golang.zx2c4.com/wireguard/tun"
)

// ─── fakes ────────────────────────────────────────────────────────────────

// fakeClient stands in for csqtt.Client: packets written by the bridge land
// in `up`, packets the test puts in `down` come out of ReadPacket.
type fakeClient struct {
	up      chan []byte
	down    chan []byte
	done    chan struct{}
	err     error
	closed  atomic.Bool
	conf    csqtt.ConfigResponse
	stats   csqtt.Stats
	pathChg atomic.Int32
	wakes   atomic.Int32
	creds   func(context.Context, int) (csqtt.Credential, error)
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		up: make(chan []byte, 64), down: make(chan []byte, 64), done: make(chan struct{}),
		conf:  csqtt.ConfigResponse{TunnelIP: "10.66.67.3", DNS: "77.88.8.8,77.88.8.1", StreamRevision: "stream-v2", Raw: "TUNCONF:10.66.67.3:77.88.8.8,77.88.8.1:9000:stream-v2"},
		stats: csqtt.Stats{TxBytes: 1234, RxBytes: 5678, Ready: 7, Total: 30, Restarts: 3, AllocateRTT: 131 * time.Millisecond},
	}
}

func (f *fakeClient) WritePacket(p []byte) error {
	select {
	case f.up <- append([]byte(nil), p...):
		return nil
	default:
		return errors.New("fake: up full")
	}
}
func (f *fakeClient) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-f.down:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		return nil, errors.New("fake: closed")
	}
}
func (f *fakeClient) Close() error {
	if f.closed.CompareAndSwap(false, true) {
		close(f.done)
	}
	return nil
}
func (f *fakeClient) Stats() csqtt.Stats           { return f.stats }
func (f *fakeClient) Config() csqtt.ConfigResponse { return f.conf }
func (f *fakeClient) OnPathChange()                { f.pathChg.Add(1) }
func (f *fakeClient) WakeHealthCheck()             { f.wakes.Add(1) }
func (f *fakeClient) Done() <-chan struct{}        { return f.done }
func (f *fakeClient) Err() error                   { return f.err }
func (f *fakeClient) stop(err error)               { f.err = err; f.Close() }

// installFakeDial makes csqttDial hand out `c` after calling the config's
// Creds once for worker 1 (as the real Dial does before its first
// allocation), so the pool adapter is exercised on the start path.
func installFakeDial(t *testing.T, c *fakeClient) {
	t.Helper()
	prev := csqttDial
	csqttDial = func(ctx context.Context, cfg csqtt.Config) (csqttClient, error) {
		c.creds = cfg.Creds
		if _, err := cfg.Creds(ctx, 1); err != nil {
			return nil, err
		}
		return c, nil
	}
	t.Cleanup(func() { csqttDial = prev })
}

// fakePool records what the bridge builds its pool with and lets the test
// supply the fetcher. The pool itself is the real proxy.CredPool.
type fakePool struct {
	mu    sync.Mutex
	pool  *proxy.CredPool
	cfg   proxy.CredPoolConfig
	fetch func(bool, int) (string, *proxy.TURNCreds, error)
}

func installFakePool(t *testing.T, fetch func(bool, int) (string, *proxy.TURNCreds, error)) *fakePool {
	t.Helper()
	fp := &fakePool{fetch: fetch}
	prev := csqttNewPool
	csqttNewPool = func(ctx context.Context, cfg proxy.CredPoolConfig) *proxy.CredPool {
		cfg.Fetch = fp.fetch
		p := proxy.NewCredPool(ctx, cfg)
		fp.mu.Lock()
		fp.pool, fp.cfg = p, cfg
		fp.mu.Unlock()
		return p
	}
	t.Cleanup(func() { csqttNewPool = prev })
	return fp
}

// freshUsername carries a far-future expiry in VK's "<unix>:…" form, which
// is what the pool reads a credential's lifetime from (parseCredExpiry): a
// username without it counts as expired and every acquire mints again.
func freshUsername(tag string) string {
	return fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag)
}

func mintingFetch(counter *atomic.Int32) func(bool, int) (string, *proxy.TURNCreds, error) {
	return func(_ bool, slot int) (string, *proxy.TURNCreds, error) {
		counter.Add(1)
		addr := fmt.Sprintf("95.163.34.%d:19302", 100+slot)
		return addr, &proxy.TURNCreds{Username: freshUsername(fmt.Sprintf("slot-%d", slot)), Password: "p", Address: addr, Addresses: []string{addr}}, nil
	}
}

// pairDevice is a socketpair end with wireguard-go's DARWIN tun contract:
// Read fills bufs[0] from offset-4 and reports the packet without its 4-byte
// address-family header; Write needs offset ≥ 4 and stamps the header in
// front of the packet — exactly NativeTun's Read and Write.
type pairDevice struct {
	f      *os.File
	fd     int
	events chan tun.Event
	closed atomic.Bool
	once   sync.Once
}

func (d *pairDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	buf := bufs[0][offset-4:]
	n, err := d.f.Read(buf)
	if n < 4 {
		return 0, err
	}
	sizes[0] = n - 4
	return 1, err
}

func (d *pairDevice) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		buf[0], buf[1], buf[2] = 0, 0, 0
		switch buf[4] >> 4 {
		case 4:
			buf[3] = unix.AF_INET
		case 6:
			buf[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := d.f.Write(buf); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *pairDevice) Events() <-chan tun.Event { return d.events }
func (d *pairDevice) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.events)
		d.f.Close()
	})
	return nil
}

// installPairTun replaces csqttOpenTun with one that wraps whatever
// descriptor the bridge hands it — recorded, so the test can tell a
// duplicate from the caller's own fd.
func installPairTun(t *testing.T) (opened *atomic.Pointer[pairDevice]) {
	t.Helper()
	opened = &atomic.Pointer[pairDevice]{}
	prev := csqttOpenTun
	csqttOpenTun = func(dupFd int) (packetDevice, error) {
		d := &pairDevice{f: os.NewFile(uintptr(dupFd), "pair"), fd: dupFd, events: make(chan tun.Event, 4)}
		opened.Store(d)
		return d, nil
	}
	t.Cleanup(func() { csqttOpenTun = prev })
	return opened
}

// socketPair returns the two ends of a datagram socketpair (one read = one
// packet, as on a utun).
func socketPair(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fds[0], fds[1]
}

func fdIsOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// ipv4Packet is a minimal IPv4 header with a payload, enough for the
// device's address-family stamp.
func ipv4Packet(payload string) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	p[9] = 17
	copy(p[20:], payload)
	return p
}

func startCsqtt(t *testing.T, extra string) int32 {
	t.Helper()
	cfg := `{"peer_addr":"127.0.0.1:46000","csqtt_password":"pw","csqtt_device_id":"dev","vk_link":"https://vk.ru/call/join/abc","num_conns":30` + extra + `}`
	h := csqttStartImpl(cfg)
	if h < 0 {
		t.Fatalf("csqttStart: %d", h)
	}
	t.Cleanup(func() { csqttTurnOffImpl(h) })
	return h
}

// ─── the checks ───────────────────────────────────────────────────────────

// The whole life of a tunnel on the host: start → ready → provision → attach
// on a DUPLICATE of the caller's fd → packets both ways with the darwin
// address-family header → stop joins the pumps, closes the device, leaves the
// caller's fd open and the pool refusing. Sabotages seen red, one at a time:
// the caller's fd handed to the device instead of a dup (fd closed after
// stop); the device not closed in TurnOff (pumps never join — stop takes the
// whole budget and the reader is still alive); the pool left open after stop
// (Acquire still answers); the pumps reading/writing at offset 0 (the device
// refuses, nothing crosses).
func TestCsqttLifecycleOwnsItsDescriptorAndCleansUp(t *testing.T) {
	var mints atomic.Int32
	fp := installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	installFakeDial(t, fc)
	opened := installPairTun(t)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("csqttWaitReady: %d (error %q)", rc, csqttGetErrorImpl(h))
	}
	prov := csqttProvisionImpl(h)
	var pv struct {
		Address string `json:"address"`
		DNS     string `json:"dns"`
		MTU     int    `json:"mtu"`
	}
	if err := json.Unmarshal([]byte(prov), &pv); err != nil || pv.Address != "10.66.67.3/24" || pv.DNS != "77.88.8.8,77.88.8.1" || pv.MTU != 1300 {
		t.Fatalf("provision %q → %+v (%v): want the TUNCONF address as /24, its DNS, MTU 1300", prov, pv, err)
	}
	if ip := csqttGetRelayIPImpl(h); ip != "95.163.34.100" {
		t.Fatalf("relay IP %q, want the minted relay's host", ip)
	}

	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	if rc := csqttAttachImpl(h, mine); rc != 1 {
		t.Fatalf("csqttAttach: %d", rc)
	}
	dev := opened.Load()
	if dev == nil {
		t.Fatal("the device was never opened")
	}
	if dev.fd == mine {
		t.Fatal("the device was given the caller's own descriptor — it must be a duplicate")
	}

	// TUN → relays: the kernel would prefix the AF header; here the test does.
	pkt := ipv4Packet("up")
	if _, err := unix.Write(theirs, append([]byte{0, 0, 0, unix.AF_INET}, pkt...)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-fc.up:
		if string(got) != string(pkt) {
			t.Fatalf("uplink packet %x, want %x — the address-family header leaked or the offset is off", got, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the TUN packet never reached the client")
	}
	// relays → TUN: the device must stamp the AF header.
	down := ipv4Packet("down")
	fc.down <- down
	rbuf := make([]byte, 4096)
	unix.SetNonblock(theirs, false)
	if err := unix.SetsockoptTimeval(theirs, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	n, err := unix.Read(theirs, rbuf)
	if err != nil || n != 4+len(down) || rbuf[3] != unix.AF_INET || string(rbuf[4:n]) != string(down) {
		t.Fatalf("downlink read n=%d err=%v hdr=%x — want the AF_INET header in front of the packet", n, err, rbuf[:4])
	}

	t0 := time.Now()
	csqttTurnOffImpl(h)
	took := time.Since(t0)
	if !dev.closed.Load() {
		t.Fatal("the device was not closed by TurnOff")
	}
	if took >= csqttPumpJoinBudget {
		t.Fatalf("TurnOff took %s — the pumps did not join (the join budget ran out)", took)
	}
	if !fdIsOpen(mine) {
		t.Fatal("the CALLER's descriptor is closed after TurnOff — the bridge closed what it did not own")
	}
	unix.Close(mine)
	if !fc.closed.Load() {
		t.Fatal("the client was not closed")
	}
	if e := csqttLookup(h); e != nil {
		t.Fatal("the handle is still registered after TurnOff")
	}
	fp.mu.Lock()
	pool := fp.pool
	fp.mu.Unlock()
	if _, _, _, err := pool.Acquire(0); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Acquire after TurnOff: %v — the pool must be closed behind the stop (no minting after stop)", err)
	}
}

// The credential adapter is the pool's policy seen from csqtt: worker k is
// connection k−1 (so worker 10 lands on slot 0 with the first nine, not on
// slot 1), the slot is held for the lease's life and given back by Release
// (the eleventh worker on one credential parks until one releases), and a
// parked worker is woken by the pool, not by a timer (the backstop is off
// here). Sabotages seen red: the −1 dropped (worker 10 fetches into slot 1);
// Release dropped (the eleventh never gets a credential); the wait on
// SlotAvailable dropped (same — with no backstop, nothing wakes it).
func TestCsqttCredentialAdapterMapsWorkersAndLeasesSlots(t *testing.T) {
	var slots []int
	var mu sync.Mutex
	fetch := func(_ bool, slot int) (string, *proxy.TURNCreds, error) {
		mu.Lock()
		slots = append(slots, slot)
		mu.Unlock()
		addr := "95.163.34.180:19302"
		return addr, &proxy.TURNCreds{Username: freshUsername("shared"), Password: "p", Address: addr, Addresses: []string{addr}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := proxy.NewCredPool(ctx, proxy.CredPoolConfig{VKLink: "abc", NumConns: 10, Fetch: fetch})
	defer pool.Close()
	var fatal error
	a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { fatal = err }}
	prevBackstop := csqttAcquireBackstop
	csqttAcquireBackstop, csqttAcquireBackstopMax = time.Hour, time.Hour
	defer func() { csqttAcquireBackstop, csqttAcquireBackstopMax = prevBackstop, 5*time.Second }()

	var leases []csqtt.Credential
	for k := 1; k <= 10; k++ {
		c, err := a.creds(ctx, k)
		if err != nil {
			t.Fatalf("worker %d: %v", k, err)
		}
		leases = append(leases, c)
	}
	mu.Lock()
	got := append([]int(nil), slots...)
	mu.Unlock()
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("fetches into slots %v — ten workers must share ONE credential in slot 0 (worker k → connection k−1)", got)
	}
	// The eleventh parks: slot 0 is at its ten, and the pool's cold-start cap
	// keeps it from minting a second credential for one more worker.
	done := make(chan error, 1)
	go func() { _, err := a.creds(ctx, 11); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("worker 11 got a credential at once (%v) — it must park until a slot frees", err)
	case <-time.After(300 * time.Millisecond):
	}
	leases[0].Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker 11 after a release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker 11 still parked after a release — the lease was not given back, or the wake-up was lost")
	}
	if fatal != nil {
		t.Fatalf("a transient park was reported as terminal: %v", fatal)
	}
}

// A captcha is TERMINAL for a csqtt tunnel — there is no WebView on this
// path — so the start must fail at once with the reason, not spin through
// the whole bootstrap budget. Sabotage seen red: the terminal test dropped
// from the adapter (csqttWaitReady answers 0 — still trying — instead of −1).
func TestCsqttCaptchaIsTerminalForTheStart(t *testing.T) {
	installFakePool(t, func(bool, int) (string, *proxy.TURNCreds, error) {
		return "", nil, fmt.Errorf("get VK creds: %w", &proxy.CaptchaRequiredError{ImageURL: "https://vk.ru/captcha"})
	})
	installFakeDial(t, newFakeClient())
	csqttSeededSettle = 0
	prevBackstop := csqttAcquireBackstop
	csqttAcquireBackstop = 10 * time.Millisecond
	defer func() { csqttAcquireBackstop = prevBackstop }()

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 1500*time.Millisecond); rc != -1 {
		t.Fatalf("csqttWaitReady: %d, want -1 (terminal) — a captcha must not be retried until the budget runs out", rc)
	}
	msg := csqttGetErrorImpl(h)
	if !strings.Contains(msg, "captcha") {
		t.Fatalf("error %q does not name the captcha", msg)
	}
	// Not through auth_error: the app answers that with its VK-session text.
	var st proxy.Stats
	if err := json.Unmarshal([]byte(csqttGetStatsImpl(h)), &st); err != nil || st.AuthError != "" {
		t.Fatalf("stats after the terminal error: %+v (%v) — a csqtt reason must not ride auth_error", st, err)
	}
}

// A client that stops on its own after start (DENIED is fatal for the whole
// client) reaches Swift as what the user must DO: device_mismatch — the one
// a link recipient hits, since a csqtt:// link carries no device id while the
// server may have bound the password to one — names the Device ID setting.
// Sabotages seen red: the Done watcher dropped from csqttStart (no error at
// all); the reason mapping dropped (the raw "csqtt: denied: device_mismatch").
func TestCsqttClientDeathReachesSwift(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	installFakeDial(t, fc)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("csqttWaitReady: %d", rc)
	}
	if e := csqttGetErrorImpl(h); e != "" {
		t.Fatalf("error before any failure: %q", e)
	}
	fc.stop(&csqtt.DeniedError{Reason: "device_mismatch"})
	waitFor(t, "the terminal error", func() bool { return csqttGetErrorImpl(h) != "" })
	if e := csqttGetErrorImpl(h); !strings.Contains(e, "Device ID") {
		t.Fatalf("error %q does not tell the user what to do about the device id", e)
	}
}

// The stats JSON carries the keys Swift's TunnelStats decodes — pinned here
// as the literal list from TunnelManager.swift's CodingKeys — with csqtt's
// counters under the app's meanings: active/total conns are ready/total
// workers, the RTT is the relay allocation, reconnects are restarts.
// Sabotage seen red: active_conns mapped from Total.
func TestCsqttStatsCarryTheAppsKeys(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	installFakeDial(t, fc)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("csqttWaitReady: %d", rc)
	}
	raw := csqttGetStatsImpl(h)
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	// TunnelManager.swift, TunnelStats.CodingKeys — the omitempty ones last.
	for _, k := range []string{"tx_bytes", "rx_bytes", "active_conns", "total_conns", "turn_rtt_ms", "dtls_handshake_ms",
		"reconnects", "cred_pool_filled", "cred_pool_with_creds", "cred_pool_size", "cred_pool_distinct_relays", "tunnel_uptime_sec"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("stats lack %q (Swift's TunnelStats decodes it): %s", k, raw)
		}
	}
	var st proxy.Stats
	_ = json.Unmarshal([]byte(raw), &st)
	if st.ActiveConns != 7 || st.TotalConns != 30 || st.Reconnects != 3 || st.TxBytes != 1234 || st.RxBytes != 5678 || st.TurnRTTms != 131 {
		t.Fatalf("stats mapping: %+v — want ready 7 / total 30 / restarts 3 / bytes 1234,5678 / RTT 131 ms", st)
	}
	if st.CredPoolSize == 0 || st.CredPoolWithCreds == 0 {
		t.Fatalf("pool stats missing: %+v", st)
	}
}

// Path change and wake reach the client; the pool is marked first so the
// restarted workers' acquires spread. Sabotage seen red: the client's
// OnPathChange dropped from csqttPathChanged.
func TestCsqttPathChangeAndWakeReachTheClient(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	installFakeDial(t, fc)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("csqttWaitReady: %d", rc)
	}
	csqttPathChangedImpl(h)
	csqttWakeHealthCheckImpl(h)
	if fc.pathChg.Load() != 1 || fc.wakes.Load() != 1 {
		t.Fatalf("path changes %d wakes %d, want 1 and 1", fc.pathChg.Load(), fc.wakes.Load())
	}
}
