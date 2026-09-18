package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A pool that parks every caller: the path-change pause is in force. The
// fetcher must never be reached.
func parkingPool(t *testing.T) *credPool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, "", func(bool, int) (string, *TURNCreds, error) {
		t.Fatal("the fetcher was reached — the pool did not park")
		return "", nil, nil
	})
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	cp.pauseAcquireUntil = time.Now().Add(time.Minute)
	cp.mu.Unlock()
	return cp
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// THE GAP, made explicit. get() parks a conn and returns; a broadcast lands
// before the conn asks for a channel to wait on (in the app: the "session
// ended" log line and the failure bookkeeping sit in between, and the
// cold-start herd's mints land exactly then). The channel the park error
// CARRIES is the one that broadcast closed — the conn wakes at once; the
// channel a later slotAvailableChannel() hands out is the NEXT one — the
// conn would sleep its 2–7 s timer or the 30–60 s dormancy for a broadcast
// that already happened. Sabotage seen red: the park returned as a plain
// fmt.Errorf (no channel) — errors.As finds nothing.
func TestAParkCarriesTheChannelTheNextBroadcastCloses(t *testing.T) {
	cp := parkingPool(t)
	_, _, slot, err := cp.get(3, false)
	if err == nil || slot != -1 || !strings.Contains(err.Error(), "paused for path-change settle") {
		t.Fatalf("get on a paused pool = (slot %d, %v), want the pause park", slot, err)
	}
	var park *poolParkError
	if !errors.As(err, &park) || park.wake == nil {
		t.Fatalf("the park error carries no channel: %T %v", err, err)
	}
	if isClosed(park.wake) {
		t.Fatal("the carried channel is already closed before any broadcast")
	}

	// The broadcast in the gap.
	cp.broadcastSlotAvailable()

	if !isClosed(park.wake) {
		t.Fatal("the carried channel was not the one the broadcast closed — the park captured a stale or future channel")
	}
	if isClosed(cp.slotAvailableChannel()) {
		t.Fatal("the channel handed out AFTER the broadcast is closed — the broadcast did not replace it")
	}
}

// The three parks — the pause, the cold-start cap, no slot — all carry the
// channel, and the text of each is exactly what the log lines and the older
// tests read.
func TestEveryParkCarriesTheChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const relay = "95.163.34.180:19302"
	full := func(slot int) credPoolEntry {
		return credPoolEntry{addr: relay, ts: time.Now(), active: 10,
			creds: &TURNCreds{Username: fmt.Sprintf("%d:s%d", time.Now().Add(8*time.Hour).Unix(), slot), Password: "p", Address: relay, Addresses: []string{relay}}}
	}
	cases := []struct {
		name, want string
		arrange    func(cp *credPool)
	}{
		{"the pause", "paused for path-change settle", func(cp *credPool) { cp.pauseAcquireUntil = time.Now().Add(time.Minute) }},
		{"the cold-start cap", "cold-start cap", func(cp *credPool) {
			// Three full slots meet the target of 3 (12 slots, no NumConns: the
			// old inverse ceil(12/4)); a fourth caller must park, not mint.
			cp.pool[0], cp.pool[1], cp.pool[2] = full(0), full(1), full(2)
		}},
		{"no slot", "no slot available", func(cp *credPool) {
			// Every slot is empty and on its per-relay cooldown: nothing to hand
			// out, nothing ready or in flight (so the cap does not fire first),
			// and no slot to mint into.
			for i := range cp.pool {
				cp.pool[i].cooldownUntil = time.Now().Add(time.Hour)
			}
		}},
	}
	for _, c := range cases {
		cp := newCredPool(ctx, 12, 2*time.Minute, "", func(bool, int) (string, *TURNCreds, error) {
			return "", nil, errors.New("the fetcher must not be reached by a parked caller")
		})
		cp.mu.Lock()
		for len(cp.pool) < cp.size {
			cp.pool = append(cp.pool, credPoolEntry{})
		}
		c.arrange(cp)
		cp.mu.Unlock()
		_, _, _, err := cp.get(5, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: get = %v, want an error containing %q", c.name, err, c.want)
		}
		var park *poolParkError
		if !errors.As(err, &park) || park.wake == nil {
			t.Fatalf("%s: the park carries no channel: %T %v", c.name, err, err)
		}
		if park.wake != cp.slotAvailableChannel() {
			t.Fatalf("%s: the carried channel is not the pool's current one", c.name)
		}
	}
}

// wakeChannelFor hands a retry the park's own channel — also through a
// wrapping — and the pool's current channel for any other error. Sabotage
// seen red: wakeChannelFor always answering slotAvailableChannel().
func TestWakeChannelForPrefersTheParkErrorsChannel(t *testing.T) {
	cp := parkingPool(t)
	p := &Proxy{credPool: cp}
	_, _, _, err := cp.get(7, false)
	var park *poolParkError
	if !errors.As(err, &park) {
		t.Fatalf("not a park: %v", err)
	}
	if got := p.wakeChannelFor(err); got != park.wake {
		t.Fatal("wakeChannelFor did not return the park error's channel")
	}
	if got := p.wakeChannelFor(fmt.Errorf("session: %w", err)); got != park.wake {
		t.Fatal("wakeChannelFor did not find the park error through a wrapping")
	}
	// After a broadcast the park's channel is closed and the pool's current one
	// is not: the two answers must differ, and the park's must be the closed one.
	cp.broadcastSlotAvailable()
	if got := p.wakeChannelFor(err); !isClosed(got) {
		t.Fatal("after the broadcast, the park's channel must read closed")
	}
	if got := p.wakeChannelFor(errors.New("some other session error")); got != cp.slotAvailableChannel() || isClosed(got) {
		t.Fatal("for a non-park error wakeChannelFor must return the pool's current (open) channel")
	}
}

// The retry waits use the helper, not the pool's channel directly — pinned by
// spelling, because the gap is a matter of WHEN the channel is read and no
// unit test can drive runConnection's select. Three sites: the bootstrap
// wait on a saturated pool, the dormancy, the 2–7 s retry delay. And every
// park in creds.go captures the channel BEFORE it releases the lock.
// Sabotage seen red: one retry site back on p.credPool.slotAvailableChannel();
// a park capturing the channel after Unlock.
func TestRetryWaitsTakeTheParkErrorsChannel(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	if n := strings.Count(code, "p.wakeChannelFor(err)"); n != 3 {
		t.Errorf("proxy.go has %d retry sites on p.wakeChannelFor(err), want 3 (the bootstrap wait, the dormancy, the retry delay)", n)
	}
	if n := strings.Count(code, "p.credPool.slotAvailableChannel()"); n != 1 {
		t.Errorf("proxy.go reads p.credPool.slotAvailableChannel() %d times, want 1 — inside wakeChannelFor only; a retry site that reads it directly reopens the gap", n)
	}
	creds, err := os.ReadFile("creds.go")
	if err != nil {
		t.Fatal(err)
	}
	c := string(creds)
	parks := regexp.MustCompile(`&poolParkError\{`).FindAllStringIndex(c, -1)
	if len(parks) != 5 {
		t.Fatalf("creds.go constructs poolParkError %d times, want 5 (the pause, the relay-refusal breaker's mint pause, the cold-start cap, no slot, a credential issued again with all its previous holders still out)", len(parks))
	}
	for _, m := range parks {
		window := c[max(0, m[0]-400):m[0]]
		capture := strings.LastIndex(window, "wake := cp.slotAvailableCh")
		unlock := strings.LastIndex(window, "cp.mu.Unlock()")
		if capture < 0 || unlock < 0 || capture > unlock {
			t.Errorf("a park at creds.go offset %d does not capture the channel (`wake := cp.slotAvailableCh`) BEFORE cp.mu.Unlock() — a channel read after the unlock can already be the next one", m[0])
		}
	}
	for _, msg := range []string{"paused for path-change settle", "cold-start cap", "no slot available"} {
		if strings.Contains(c, `fmt.Errorf("credpool: `+msg) {
			t.Errorf("creds.go still returns %q as a plain fmt.Errorf — a park without its channel", msg)
		}
	}
}
