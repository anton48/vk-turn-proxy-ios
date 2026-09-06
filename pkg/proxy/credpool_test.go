package proxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A fake VK minter: counts calls, stamps each call, hands out one relay.
// The username carries a far-future expiry in VK's "<unix>:…" form so the
// entry counts as fresh (parseCredExpiry) and survives a cache round trip.
type fakeMinter struct {
	mu       sync.Mutex
	calls    int
	at       []time.Time
	fail     func(int) error
	blocking int // fetches that were ALLOWED to block on a captcha
}

func (m *fakeMinter) fetch(allowCaptchaBlock bool, slot int) (string, *TURNCreds, error) {
	m.mu.Lock()
	m.calls++
	n := m.calls
	m.at = append(m.at, time.Now())
	if allowCaptchaBlock {
		m.blocking++
	}
	m.mu.Unlock()
	if m.fail != nil {
		if err := m.fail(n); err != nil {
			return "", nil, err
		}
	}
	addr := "95.163.34.180:19302"
	return addr, &TURNCreds{
		Username:  fmt.Sprintf("%d:test-slot-%d-mint-%d", time.Now().Add(8*time.Hour).Unix(), slot, n),
		Password:  "pw",
		Address:   addr,
		Addresses: []string{addr},
	}, nil
}

func (m *fakeMinter) count() int   { m.mu.Lock(); defer m.mu.Unlock(); return m.calls }
func (m *fakeMinter) blocked() int { m.mu.Lock(); defer m.mu.Unlock(); return m.blocking }
func (m *fakeMinter) stamps() []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]time.Time(nil), m.at...)
}

// The pool is sized by the SAME rule as Proxy's: ceil(NumConns × 2/5), min 2.
// Literals on purpose — a size derived from the rule under test would pass
// under any rule (instance 2 of the sabotage file).
func TestCredPoolSizeFollowsProxysRule(t *testing.T) {
	for _, tc := range []struct{ conns, size int }{{30, 12}, {10, 4}, {1, 2}, {50, 20}} {
		p := NewCredPool(context.Background(), CredPoolConfig{NumConns: tc.conns, Fetch: (&fakeMinter{}).fetch})
		if got := p.Stats().Size; got != tc.size {
			t.Errorf("NumConns %d: pool size %d, want %d", tc.conns, got, tc.size)
		}
	}
}

// Ten connections share ONE mint — VK's quota is ~10 allocations per
// (identity, relay) — and the eleventh gets its own slot and a second mint.
// That sharing is the pool's own guarantee (get() enforces it whatever
// connIdx says — a sabotage passing a constant index stays GREEN, which is
// how this comment learned it). What the wrapper adds, and what its sabotage
// reddens, is that no acquire may block on a captcha: Acquire passing `true`
// makes the minter see a blocking fetch.
func TestCredPoolTenConnectionsShareOneMint(t *testing.T) {
	m := &fakeMinter{}
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, Fetch: m.fetch})
	for i := 0; i < 10; i++ {
		addr, creds, slot, err := p.Acquire(i)
		if err != nil {
			t.Fatalf("Acquire(%d): %v", i, err)
		}
		if slot != 0 || addr != "95.163.34.180:19302" || creds == nil {
			t.Fatalf("Acquire(%d): slot %d addr %q creds %v, want slot 0 on the relay", i, slot, addr, creds != nil)
		}
	}
	if m.count() != 1 {
		t.Fatalf("ten connections cost %d mints, want exactly 1", m.count())
	}
	_, _, slot, err := p.Acquire(10)
	if err != nil {
		t.Fatalf("Acquire(10): %v", err)
	}
	if slot != 1 || m.count() != 2 {
		t.Fatalf("the eleventh connection: slot %d after %d mints, want slot 1 after the second mint", slot, m.count())
	}
	if st := p.Stats(); st.DistinctRelays != 1 || st.WithCreds != 2 {
		t.Fatalf("stats after two mints on one relay: %+v", st)
	}
	if m.blocked() != 0 {
		t.Fatalf("%d of %d fetches were allowed to block on a captcha — a csqtt worker has no captcha UI to block on", m.blocked(), m.count())
	}
}

// After a warm-cache start no mint happens, so Proxy.TURNServerIP stays empty
// (2026-09-05: the console client pinned no relay and the tunnel swallowed
// its own relay sockets). This pool answers from the cache. Sabotage seen
// red: RelayHosts ignoring the entries.
func TestCredPoolRelayHostsSurviveAWarmCache(t *testing.T) {
	// Not t.TempDir: each pool's background saver writes the cache once more
	// after Close (tmp + rename, asynchronously), which races t.TempDir's
	// RemoveAll into "directory not empty" — seen 2 runs in 8. Our own dir,
	// removed best-effort after the pools are closed.
	dir, err := os.MkdirTemp("", "credpool-warm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cache := filepath.Join(dir, "creds-pool.json")

	warm := &fakeMinter{}
	a := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, CachePath: cache, Fetch: warm.fetch})
	if _, _, _, err := a.Acquire(0); err != nil {
		t.Fatalf("first pool Acquire: %v", err)
	}
	// Close is the stop path. ⚠️ Its synchronous save is NOT what this fixture
	// proves: the mint inside Acquire already wrote the file, and after Close
	// cancels the context the background saver writes once more within
	// microseconds — the sabotage "Close does not save" stays GREEN here (the
	// fixture set cannot separate the two writers). What the test proves is
	// the LOAD side: a warm start answers its relay from the cache.
	a.Close()

	cold := &fakeMinter{fail: func(int) error { return fmt.Errorf("the warm-cache pool must not mint") }}
	b := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, CachePath: cache, Fetch: cold.fetch})
	defer b.Close()
	if hosts := b.RelayHosts(); len(hosts) != 1 || hosts[0] != "95.163.34.180" {
		t.Fatalf("RelayHosts from the cache = %v, want [95.163.34.180]", hosts)
	}
	if ip := b.RelayIP(); ip != "95.163.34.180" {
		t.Fatalf("RelayIP from the cache = %q, want 95.163.34.180", ip)
	}
	if cold.count() != 0 {
		t.Fatalf("the warm-cache pool minted %d times reading its relay", cold.count())
	}
}

// The grower fills fast until ceil(NumConns/10) slots are usable, then adds
// one slot per stagger interval, and Close ends it: nothing is minted after
// Close. Run in milliseconds; the production pace is pinned separately.
// Sabotages seen red: Grow never leaving cold start (the fourth mint follows
// the third at the fast interval); Grow running on context.Background()
// instead of the pool's lifetime (mints continue after Close).
func TestCredPoolGrowFastUntilTargetThenStaggers(t *testing.T) {
	m := &fakeMinter{}
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, Fetch: m.fetch}) // target = 3 slots of 12
	// Set before the goroutine starts — the go statement orders it.
	p.pace = growPace{fast: 3 * time.Millisecond, slow: 20 * time.Millisecond, staggerMin: 150 * time.Millisecond, staggerMax: 200 * time.Millisecond, bootstrap: time.Second}
	staggerMin := p.pace.staggerMin
	ready := make(chan struct{})
	close(ready)
	t0 := time.Now()
	go p.Grow(ready)

	deadline := time.After(2 * time.Second)
	for p.Stats().Available < 3 {
		select {
		case <-deadline:
			t.Fatalf("cold-start target not reached: %+v after %d mints", p.Stats(), m.count())
		case <-time.After(time.Millisecond):
		}
	}
	reached := time.Since(t0)
	if reached > 100*time.Millisecond {
		t.Fatalf("three slots took %s at a 3 ms fast interval", reached)
	}
	deadline = time.After(2 * time.Second)
	for m.count() < 4 {
		select {
		case <-deadline:
			t.Fatalf("maintenance never filled a fourth slot (%d mints)", m.count())
		case <-time.After(time.Millisecond):
		}
	}
	at := m.stamps()
	if gap := at[3].Sub(at[2]); gap < staggerMin-10*time.Millisecond {
		t.Fatalf("fourth mint %s after the third — maintenance should wait at least %s", gap, staggerMin)
	}
	p.Close()
	after := m.count()
	time.Sleep(3 * p.pace.staggerMax)
	if m.count() != after {
		t.Fatalf("Close did not stop the grower: %d mints after Close (was %d)", m.count()-after, after)
	}
}

// Production pace, as literals: Proxy.growCredPool's numbers.
func TestCredPoolGrowPaceIsPinned(t *testing.T) {
	d := defaultGrowPace
	if d.fast != 2*time.Second || d.slow != 30*time.Second || d.staggerMin != 120*time.Second || d.staggerMax != 300*time.Second || d.bootstrap != 2*time.Minute {
		t.Fatalf("grower pace drifted: %+v", d)
	}
	if p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 1, Fetch: (&fakeMinter{}).fetch}); p.pace != d {
		t.Fatalf("a new pool does not start at the production pace: %+v", p.pace)
	}
}

// The TURN override rewrites every address (the fresh-fetch path only) and
// the primary follows. Sabotage seen red: skipping the port override.
func TestApplyTURNOverride(t *testing.T) {
	c := &TURNCreds{Addresses: []string{"95.163.34.180:19302", "91.231.135.146:19302"}}
	addr, err := applyTURNOverride(c, "", "3478")
	if err != nil || addr != "95.163.34.180:3478" || c.Address != addr || c.Addresses[1] != "91.231.135.146:3478" {
		t.Fatalf("port override: addr %q err %v creds %+v", addr, err, c)
	}
	addr, err = applyTURNOverride(c, "10.0.0.1", "")
	if err != nil || addr != "10.0.0.1:3478" || c.Addresses[1] != "10.0.0.1:3478" {
		t.Fatalf("host override: addr %q err %v creds %+v", addr, err, c)
	}
	if _, err := applyTURNOverride(&TURNCreds{}, "", ""); err == nil {
		t.Fatal("no addresses must be an error, not an empty primary")
	}
	if got := parseVKLinkID("https://vk.ru/call/join/hO-B7Xq?x=1"); got != "hO-B7Xq" {
		t.Fatalf("parseVKLinkID = %q", got)
	}
}

// Cookie (VKAuth) mode sizes the pool as NewProxy does: one slot per relay,
// two per call link, no 4× reserve — extra slots would duplicate an
// (okcdn_userid, relay) pair and 486. Sabotage seen red: the cookie branch
// dropped (30 connections → 12 slots again).
func TestCredPoolCookieModeSizesOneSlotPerRelay(t *testing.T) {
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	for _, tc := range []struct {
		links []string
		size  int
	}{
		{[]string{"https://vk.ru/call/join/abcdef"}, 2},
		{[]string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}, 4},
	} {
		SetVKCookieAuth(true, "remixsid=x", tc.links)
		p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, Fetch: (&fakeMinter{}).fetch})
		if got := p.Stats().Size; got != tc.size {
			t.Errorf("cookie mode with %d link(s): pool size %d, want %d", len(tc.links), got, tc.size)
		}
		p.Close()
	}
}

// A seed (the app's pre-bootstrap captcha flow) serves the first acquire
// without a VK call and names the relay at once — without it the captcha
// would land inside iOS's .connecting window. Sabotage seen red: the seed
// ignored (the first acquire mints).
func TestCredPoolSeedServesTheFirstAcquireWithoutAMint(t *testing.T) {
	m := &fakeMinter{}
	seed := &TURNCreds{
		Username:  fmt.Sprintf("%d:seed", time.Now().Add(8*time.Hour).Unix()),
		Password:  "pw",
		Address:   "95.163.34.181:19302",
		Addresses: []string{"95.163.34.181:19302"},
	}
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, SeededTURN: seed, TurnPort: "3478", Fetch: m.fetch})
	defer p.Close()
	if ip := p.RelayIP(); ip != "95.163.34.181" {
		t.Fatalf("RelayIP before any acquire = %q, want the seed's host", ip)
	}
	addr, creds, slot, err := p.Acquire(0)
	if err != nil {
		t.Fatalf("Acquire(0): %v", err)
	}
	// Verbatim: the port override must NOT touch the seed (a cached cred keeps
	// its stored address, as in NewProxy).
	if slot != 0 || addr != "95.163.34.181:19302" || creds == nil || creds.Username != seed.Username {
		t.Fatalf("Acquire(0) = slot %d addr %q creds %+v, want the seed in slot 0 untouched", slot, addr, creds)
	}
	if m.count() != 0 {
		t.Fatalf("the first acquire minted %d time(s) despite the seed", m.count())
	}
}

// After Close a late acquire (a worker racing the stop) must not reach VK.
// Sabotage seen red: the closed check dropped (the acquire mints).
func TestCredPoolAcquireRefusedAfterClose(t *testing.T) {
	m := &fakeMinter{}
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, Fetch: m.fetch})
	p.Close()
	if _, _, _, err := p.Acquire(0); err == nil {
		t.Fatal("Acquire after Close returned no error")
	}
	if m.count() != 0 {
		t.Fatalf("Acquire after Close minted %d time(s)", m.count())
	}
}
