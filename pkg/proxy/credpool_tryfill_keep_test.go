package proxy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The grower's cold-start mint lands AFTER the conn-driven mints have reached
// the cold-start target — the normal cold start since the sub-second launch
// of 2026-09-07 (the grower starts 2 s late and its mint can lose 20 s to a
// client_id collision). The fetched credential is a paid VK solve and goes
// into its slot regardless: the pool reads 4/12, not 3/12 with a discarded
// mint and a "skipped/failed" line (vpn.srtp.lte.2.log 23:10:30, §85).
//
// Sabotage seen red: the post-fetch discard restored (`countAvailableLocked()
// >= abortIfAvailableGTE` after the fetch) — the slot stays empty and tryFill
// answers false.
func TestTryFillKeepsACredentialThatLandsAfterTheTargetIsMet(t *testing.T) {
	const relay = "95.163.34.180:19302"
	mk := func(tag string) *TURNCreds {
		return &TURNCreds{Username: fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag),
			Password: "p", Address: relay, Addresses: []string{relay}}
	}
	gate := make(chan struct{})
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		<-gate
		return relay, mk(fmt.Sprintf("grower-%d", slot)), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	// The seeded slot 0 with conn 0 on it — the grower has a reason to fill.
	cp.pool[0] = credPoolEntry{addr: relay, creds: mk("seeded-0"), ts: time.Now(), active: 1}
	cp.mu.Unlock()

	const target = 3 // ceil(12/4), the grower's cold-start abortGuard
	done := make(chan bool, 1)
	go func() { done <- cp.tryFill(3, false, target) }()

	// The grower is inside its fetch. Meanwhile the conn-driven mints land
	// on slots 1 and 2: available = 3 = target.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cp.mu.Lock()
		inFlight := cp.pool[3].fetching
		cp.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the grower's fetch never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cp.mu.Lock()
	cp.pool[1] = credPoolEntry{addr: relay, creds: mk("conn-1"), ts: time.Now(), active: 10}
	cp.pool[2] = credPoolEntry{addr: relay, creds: mk("conn-2"), ts: time.Now(), active: 7}
	available := cp.countAvailableLocked()
	cp.mu.Unlock()
	if available < target {
		t.Fatalf("fixture: available = %d, want >= %d so the old post-fetch guard would have fired", available, target)
	}

	close(gate)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("tryFill answered false for a fetch that succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tryFill did not return")
	}
	cp.mu.Lock()
	filled := cp.countFreshLocked()
	kept := cp.pool[3].creds != nil && cp.pool[3].creds.Username != "" && !cp.pool[3].fetching
	cp.mu.Unlock()
	if !kept {
		t.Fatal("slot 3 is empty — the fetched credential was discarded")
	}
	if filled != 4 {
		t.Fatalf("pool reads %d/12 after the cold start, want 4 (three conn-driven + the kept grower's)", filled)
	}
}

// The pre-fetch checkpoint stays: a mint the conn-driven fetches have already
// made redundant is not STARTED (no VK call, no `fetching` flag).
func TestTryFillStillSkipsAMintTheTargetHasMadeRedundant(t *testing.T) {
	const relay = "95.163.34.180:19302"
	mk := func(tag string) *TURNCreds {
		return &TURNCreds{Username: fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag),
			Password: "p", Address: relay, Addresses: []string{relay}}
	}
	fetched := 0
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		fetched++
		return relay, mk(fmt.Sprintf("grower-%d", slot)), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	for i := 0; i < 3; i++ {
		cp.pool[i] = credPoolEntry{addr: relay, creds: mk(fmt.Sprintf("conn-%d", i)), ts: time.Now(), active: 10}
	}
	cp.mu.Unlock()
	if cp.tryFill(3, false, 3) {
		t.Fatal("tryFill answered true with the target already met before the fetch")
	}
	if fetched != 0 {
		t.Fatalf("the fetcher ran %d time(s); the pre-fetch checkpoint must skip it", fetched)
	}
}
