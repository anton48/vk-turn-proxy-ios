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
	"regexp"
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

// installGatedDial makes csqttDial block until `release` is closed, then
// return `c` ALIVE whatever the ctx says — the shape of a dial that
// finished after the stop (a stop in .connecting, or Dial's select picking
// TUNCONF over the cancel).
func installGatedDial(t *testing.T, c *fakeClient, release chan struct{}) {
	t.Helper()
	prev := csqttDial
	csqttDial = func(ctx context.Context, cfg csqtt.Config) (csqttClient, error) {
		<-release
		return c, nil
	}
	t.Cleanup(func() { csqttDial = prev })
}

// A stop during the dial: TurnOff waits for the dial to come back and
// closes the client it returns BEFORE returning — the extension's
// stopTunnel then really has everything down. Sabotage seen red: the wait
// on `dialed` dropped from TurnOff (it returns at once, the client is still
// open when it does — the goroutine closes it later, which is the next
// test's claim, not this one's).
func TestCsqttTurnOffDuringTheDialClosesTheClientBeforeReturning(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	release := make(chan struct{})
	installGatedDial(t, fc, release)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	done := make(chan struct{})
	go func() { csqttTurnOffImpl(h); close(done) }()
	time.Sleep(100 * time.Millisecond) // TurnOff is now inside its wait
	close(release)                     // the dial comes back with a live client
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TurnOff did not return after the dial came back")
	}
	if !fc.closed.Load() {
		t.Fatal("the client the dial returned is still open after TurnOff returned")
	}
}

// A dial that outlives TurnOff's wait closes its own client: the tunnel was
// cancelled, nobody else will. Sabotage seen red: the ctx check after Dial
// dropped from the start goroutine (the client stays open for ever).
func TestCsqttDialFinishingAfterTheStopClosesItsClient(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	release := make(chan struct{})
	installGatedDial(t, fc, release)
	csqttSeededSettle = 0
	prev := csqttDialJoinBudget
	csqttDialJoinBudget = 20 * time.Millisecond
	defer func() { csqttDialJoinBudget = prev }()

	h := startCsqtt(t, "")
	csqttTurnOffImpl(h) // gives up on the dial after 20 ms
	if fc.closed.Load() {
		t.Fatal("the fixture is wrong: the client cannot be closed before the dial returned it")
	}
	close(release) // the dial comes back into a cancelled tunnel
	waitFor(t, "the late client to be closed", func() bool { return fc.closed.Load() })
}

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

// Swift calls wake / path-change / stats / provision on the handle from its
// own callbacks while the start goroutine is still dialling; the assignment
// of the client the dial returns must be synchronised with every one of
// those readers (the race detector flagged WakeHealthCheck against the
// assignment, 2026-09-06). The race detector IS the check. 🚨 ONE GOROUTINE
// PER READER: a goroutine that makes a LOCKED read (clientNow) after the
// publication is ordered after it, and a bare read later in the same
// goroutine is invisible to -race — a single loop over all readers caught a
// bare Wake in ~1 run of 4 and a bare PathChanged almost never (the review
// of 2026-09-06). Alone in its goroutine, a bare reader's reads are
// unordered against the assignment and -race reports the pair (mostly the
// write against an earlier bare read). Probabilistic, not certain: with
// each of the four readers on the bare field in turn, separate processes
// read red 10/10, 9/10, 10/10, 10/10 on a quiet host and 80–95 % per
// reader with other suites running beside it — the detector's shadow cells
// are finite. The source scans below are the deterministic guard.
func TestCsqttReadersDuringTheBootstrapDoNotRaceTheDial(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	release := make(chan struct{})
	installGatedDial(t, fc, release)
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for _, read := range []func(){
		func() { csqttWakeHealthCheckImpl(h) },
		func() { _ = csqttGetStatsImpl(h) },
		func() { _ = csqttProvisionImpl(h) },
		func() { csqttPathChangedImpl(h) },
	} {
		readers.Add(1)
		go func(read func()) {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				read()
			}
		}(read)
	}
	time.Sleep(30 * time.Millisecond)
	close(release) // the dial returns and the client is assigned under the readers
	if rc := csqttWaitReadyImpl(h, 3*time.Second); rc != 1 {
		t.Fatalf("csqttWaitReady: %d (error %q)", rc, csqttGetErrorImpl(h))
	}
	time.Sleep(30 * time.Millisecond)
	close(stop)
	readers.Wait()
	if fc.wakes.Load() == 0 {
		t.Fatal("fixture: no wake reached the client after the dial — the readers did not overlap the assignment")
	}
}

// Every read of the entry's client goes through clientNow() — a source
// scan beside the -race test, because -race sees a bare read only when it
// is unordered against the assignment in ITS goroutine (a test that mixed
// readers in one loop missed most of them, the review of 2026-09-06), and a
// scan does not depend on the interleaving.
// The -race test above proves the mechanism dynamically; this scan pins
// every reader by its spelling, whatever the interleaving. Sabotage seen
// red: csqttAppStats reading e.client directly.
func TestCsqttClientFieldReadsGoThroughTheAccessor(t *testing.T) {
	// Every non-test file of the package (bridge.go shares it), any receiver
	// spelling — `x.client` or `(*x).client` — the field itself (not
	// clientMu); tracked per enclosing function, so the two legitimate lines
	// are pinned to THEIR functions and counted exactly once each.
	field := regexp.MustCompile(`(?:\b[A-Za-z_][A-Za-z0-9_]*|\))\.client\b`)
	funcLine := regexp.MustCompile(`^func (?:\([^)]*\) )?([A-Za-z0-9_]+)\(`)
	allowed := map[string]string{"publishClient": "e.client = c", "clientNow": "return e.client"}
	seen := map[string]int{}
	for _, name := range packageSources(t) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		current := ""
		for i, line := range strings.Split(string(src), "\n") {
			if m := funcLine.FindStringSubmatch(line); m != nil {
				current = m[1]
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || !field.MatchString(trimmed) {
				continue
			}
			if name == "csqtt_bridge.go" && allowed[current] == trimmed {
				seen[current]++
				continue
			}
			t.Errorf("%s:%d touches the client field outside publishClient/clientNow (in %s): %q — the start goroutine assigns it while Swift's callbacks read it", name, i+1, current, trimmed)
		}
	}
	if seen["publishClient"] != 1 || seen["clientNow"] != 1 {
		t.Errorf("want exactly one assignment in publishClient and one read in clientNow, saw %v", seen)
	}
}

// packageSources lists the package's non-test Go files (the test runs in
// the package directory).
func packageSources(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			out = append(out, n)
		}
	}
	if len(out) < 2 {
		t.Fatalf("found only %v — the scan must run in the package directory", out)
	}
	return out
}

// The stop checks sit UNDER the locks TurnOff reads under — pinned by
// spelling, because a hook can only freeze the goroutine where the hook is:
// a check hoisted out of the lock with the hook left inside still passes
// the interleaving tests (the re-check of 2026-09-06). publishClient:
// Lock → ctx.Err → the assignment; csqttAttachImpl: devMu.Lock → e.ctx.Err
// → dupFD. Sabotage seen red: either check hoisted above its Lock.
func TestCsqttStopChecksSitUnderTheLocks(t *testing.T) {
	src, err := os.ReadFile("csqtt_bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := func(pattern string) string {
		m := regexp.MustCompile(pattern).FindString(string(src))
		if m == "" {
			t.Fatalf("function not found: %s", pattern)
		}
		return m
	}
	ordered := func(name, body string, steps ...string) {
		last := -1
		for _, step := range steps {
			i := strings.Index(body, step)
			if i < 0 {
				t.Errorf("%s: %q not found", name, step)
				return
			}
			if i < last {
				t.Errorf("%s: %q comes BEFORE the previous step — the check is outside the lock", name, step)
			}
			last = i
		}
	}
	ordered("publishClient", fn(`(?ms)^func \(e \*csqttEntry\) publishClient\(.*?^}`), "e.clientMu.Lock()", "ctx.Err()", "e.client = c")
	ordered("csqttAttachImpl", fn(`(?ms)^func csqttAttachImpl\(.*?^}`), "e.devMu.Lock()", "e.ctx.Err()", "dupFD(")
}

// A stop that lands between publishClient's ctx check and its assignment —
// the instant the lock exists for. The goroutine is held there (the hook
// runs under clientMu, after the check); TurnOff cancels, spends its budget
// and then reads the field: with the check-and-set it BLOCKS on the lock,
// the assignment completes, TurnOff reads the client and closes it. With
// the check hoisted out of the lock (the review's "natural regression" —
// the hook stays after the check, now outside the lock) TurnOff reads nil at
// once, returns, and the assignment lands on a stopped tunnel nobody owns.
// Sabotage seen red: exactly that hoist.
func TestCsqttStopBetweenTheCheckAndThePublicationLeavesOneOwner(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	release := make(chan struct{})
	installGatedDial(t, fc, release)
	hold := make(chan struct{})
	prevHook := csqttAfterPublishCheck
	csqttAfterPublishCheck = func() { <-hold }
	defer func() { csqttAfterPublishCheck = prevHook }()
	prev := csqttDialJoinBudget
	csqttDialJoinBudget = 20 * time.Millisecond
	defer func() { csqttDialJoinBudget = prev }()
	csqttSeededSettle = 0

	h := startCsqtt(t, "")
	close(release) // the dial returns; the goroutine passes the ctx check and holds at the hook
	time.Sleep(20 * time.Millisecond)
	done := make(chan struct{})
	go func() { csqttTurnOffImpl(h); close(done) }() // cancels, spends its budget, then reads the field
	time.Sleep(60 * time.Millisecond)
	if fc.closed.Load() {
		t.Fatal("fixture: the client was closed before it was even published")
	}
	close(hold) // the assignment completes beside the stop
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TurnOff did not return")
	}
	if !fc.closed.Load() {
		t.Fatal("the client published beside the stop is still open — nobody owns it")
	}
}

// A stop that lands between csqttAttach's handle lookup and its device
// section: TurnOff has cancelled and already read `dev` (nil) under devMu,
// so an attach that went on would install a device nobody closes — the
// dup'd fd and two pumps until jetsam. The check-and-install under devMu
// against TurnOff's cancel-then-read. Sabotage seen red: the ctx check
// dropped from the devMu section (attach answers 1, a device is open on a
// stopped tunnel).
func TestCsqttAttachBesideTheStopInstallsNoDevice(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	installFakeDial(t, fc)
	opened := installPairTun(t)
	csqttSeededSettle = 0
	hold := make(chan struct{})
	prevHook := csqttAfterAttachLookup
	csqttAfterAttachLookup = func() { <-hold }
	defer func() { csqttAfterAttachLookup = prevHook }()

	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3*time.Second); rc != 1 {
		t.Fatalf("csqttWaitReady: %d (error %q)", rc, csqttGetErrorImpl(h))
	}
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	defer unix.Close(mine)
	rc := make(chan int32, 1)
	go func() { rc <- csqttAttachImpl(h, mine) }()
	time.Sleep(20 * time.Millisecond) // attach resolved the handle and holds at the hook
	csqttTurnOffImpl(h)               // cancels, reads dev == nil, returns
	close(hold)                       // attach goes on into its device section
	select {
	case got := <-rc:
		if got != -2 {
			t.Fatalf("attach beside the stop answered %d, want -2 (stopped)", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("attach did not return")
	}
	if opened.Load() != nil {
		t.Fatal("a device was opened on a stopped tunnel — nobody will close it")
	}
}
