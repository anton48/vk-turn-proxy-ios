package proxy

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The cold-start target is ceil(N/10) bounded by the pool — for the anonymous
// pool the old inverse ceil(size/4) gave the same number, for the cookie pool
// (2 × links slots) it did not: 3 links, 30 conns ⇒ 6 slots ⇒ 2 where three
// (call, relay) buckets are needed (vpn.vkauth.srtp.wifi.lte.0.log, 20/50 for
// 1m24s after a switch). Sabotage seen red: the inverse restored in get().
func TestColdStartTargetIsCeilConnsOverTenBoundedByThePool(t *testing.T) {
	for _, tc := range []struct{ conns, size, want int }{
		{30, 12, 3}, // anonymous: N=30 ⇒ 12 slots
		{30, 6, 3},  // cookie: 3 links ⇒ 6 slots — the old inverse said 2
		{30, 2, 2},  // cookie: 1 link ⇒ 2 slots ⇒ 20 seats, the target is the pool
		{20, 4, 2},
		{60, 24, 6},
		{5, 2, 1},
		{0, 12, 1},
	} {
		if got := coldStartTargetFor(tc.conns, tc.size); got != tc.want {
			t.Errorf("coldStartTargetFor(%d conns, %d slots) = %d, want %d", tc.conns, tc.size, got, tc.want)
		}
	}
}

// get()'s Phase-2 cap counts against that target: on a cookie-shaped pool
// (6 slots, 30 conns) with two full slots and nothing in flight, a third
// connection must MINT its third bucket — the old ceil(6/4) = 2 parked it.
func TestColdStartCapOnACookieShapedPoolMintsTheThirdBucket(t *testing.T) {
	const relay = "95.163.34.180:19302"
	mk := func(tag string) *TURNCreds {
		return &TURNCreds{Username: fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag),
			Password: "p", Address: relay, Addresses: []string{relay}}
	}
	fetched := 0
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		fetched++
		return relay, mk(fmt.Sprintf("bucket-%d", slot)), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 6, 2*time.Minute, "", fetch)
	cp.setColdStartTarget(30)
	cp.mu.Lock()
	for i := 0; i < 2; i++ {
		cp.pool[i] = credPoolEntry{addr: relay, creds: mk(fmt.Sprintf("bucket-%d", i)), ts: time.Now(), active: 10}
	}
	cp.mu.Unlock()
	_, _, slot, err := cp.get(25, false)
	if err != nil {
		t.Fatalf("get parked instead of minting the third bucket: %v", err)
	}
	if fetched != 1 || slot < 2 {
		t.Fatalf("fetched=%d slot=%d, want one mint into a third slot", fetched, slot)
	}
	// With three buckets covered the cap holds: a fourth is not started.
	cp.mu.Lock()
	cp.pool[slot].active = 10
	cp.mu.Unlock()
	if _, _, _, err := cp.get(26, false); err == nil || !strings.Contains(err.Error(), "cold-start cap (3 ready+inflight >= 3 target)") {
		t.Fatalf("a fourth mint was not parked by the cap: err = %v (fetched=%d)", err, fetched)
	}
}

// Both constructors set the target from the connection count — NewCredPool
// on the cookie pool sizes it 2 × links and still targets ceil(N/10) — and the
// grower in proxy.go reads the pool's number rather than computing its own.
func TestColdStartTargetIsSetWhereTheConnectionCountIsKnown(t *testing.T) {
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	SetVKCookieAuth(true, "remixsid=x", []string{"https://vk.ru/call/join/aaaaaa", "https://vk.ru/call/join/bbbbbb", "https://vk.ru/call/join/cccccc"})
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 30, Fetch: (&fakeMinter{}).fetch})
	defer p.Close()
	if size, target := p.Stats().Size, p.cp.coldStartTargetValue(); size != 6 || target != 3 {
		t.Fatalf("cookie pool: size %d target %d, want 6 and 3", size, target)
	}

	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "p.credPool = newCredPool(")
	if i < 0 || !regexp.MustCompile(`(?s)p\.credPool = newCredPool\([^\n]*\n\s*p\.credPool\.setColdStartTarget\(cfg\.NumConns\)`).MatchString(s[i:]) {
		t.Fatal("NewProxy does not set the pool's cold-start target from cfg.NumConns right after building the pool")
	}
	if !strings.Contains(s, "coldStartSlots := p.credPool.coldStartTargetValue()") {
		t.Fatal("growCredPool computes its own cold-start target instead of reading the pool's")
	}
}
