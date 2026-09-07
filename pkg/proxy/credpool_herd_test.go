package proxy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Twenty-nine connections asking the pool within a second of the bootstrap —
// the cold-cache start since the sub-second stagger of 2026-09-07 (and every
// Resume: it invalidates the pool first). The POOL bounds the mints, not the
// launch timing: nine seat on the seeded slot 0 beside conn 0, exactly TWO
// callers mint (the cold-start cap counts ready + in-flight against
// ceil(size/4) = 3, and the full slot 0 is "ready"), the other eighteen park
// on the cap's error — in the app they retry on the 2–7 s timer or the
// slot-available broadcast — and seat on the minted slots; three identities
// in all, never a fourth.
//
// Sabotage seen red: the cap counting ready alone (in-flight dropped) — every
// parked caller becomes a minter.
func TestColdStartHerdMintsTwoAndParksTheRest(t *testing.T) {
	gate := make(chan struct{})
	var entered, mints atomic.Int32
	const relay = "95.163.34.180:19302"
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		entered.Add(1)
		<-gate
		mints.Add(1)
		return relay, &TURNCreds{Username: fmt.Sprintf("%d:minted-%d", time.Now().Add(8*time.Hour).Unix(), slot),
			Password: "p", Address: relay, Addresses: []string{relay}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	seed := &TURNCreds{Username: fmt.Sprintf("%d:seeded-0", time.Now().Add(8*time.Hour).Unix()), Password: "p",
		Address: relay, Addresses: []string{relay}}
	// conn 0, the bootstrap, already holds its seat on the seeded slot.
	cp.pool[0] = credPoolEntry{addr: relay, creds: seed, ts: time.Now(), active: 1}
	cp.mu.Unlock()

	type result struct {
		idx, slot int
		err       error
	}
	results := make(chan result, 29)
	var wg sync.WaitGroup
	for i := 1; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, slot, err := cp.get(idx, false)
			results <- result{idx, slot, err}
		}(i)
	}

	// First wave: twenty-seven answers at once while two callers sit inside
	// the fetch.
	seated, parkedIdx := 0, []int{}
	deadline := time.After(5 * time.Second)
	for seated+len(parkedIdx) < 27 {
		select {
		case r := <-results:
			switch {
			case r.err == nil && r.slot == 0:
				seated++
			case r.err != nil && strings.Contains(r.err.Error(), "cold-start cap"):
				parkedIdx = append(parkedIdx, r.idx)
			default:
				t.Fatalf("first wave: conn %d slot %d err %v — want a seat on slot 0 or a cold-start-cap park", r.idx, r.slot, r.err)
			}
		case <-deadline:
			t.Fatalf("first wave: %d seated, %d parked after 5 s, %d fetches entered", seated, len(parkedIdx), entered.Load())
		}
	}
	if seated != 9 || len(parkedIdx) != 18 || entered.Load() != 2 {
		t.Fatalf("first wave: %d seated, %d parked, %d fetches entered — want 9 / 18 / 2", seated, len(parkedIdx), entered.Load())
	}
	cp.mu.Lock()
	fetching := 0
	for i := range cp.pool {
		if cp.pool[i].fetching {
			fetching++
		}
	}
	active0 := cp.pool[0].active
	cp.mu.Unlock()
	if fetching != 2 || active0 != 10 {
		t.Fatalf("during the mints: %d slots fetching, slot 0 active %d — want 2 and 10", fetching, active0)
	}

	// The mints land: the two minters seat on their new slots, the parked
	// eighteen retry and seat beside them.
	close(gate)
	wg.Wait()
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil || r.slot == 0 {
			t.Fatalf("minter conn %d: slot %d err %v — want a seat on its freshly minted slot", r.idx, r.slot, r.err)
		}
	}
	for _, idx := range parkedIdx {
		_, _, slot, err := cp.get(idx, false)
		if err != nil || slot == 0 {
			t.Fatalf("retry of parked conn %d: slot %d err %v — want a seat on a minted slot", idx, slot, err)
		}
	}
	if mints.Load() != 2 {
		t.Fatalf("mints = %d, want exactly 2 — three identities for thirty connections", mints.Load())
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	withCreds, seats := 0, 0
	for i := range cp.pool {
		if cp.pool[i].creds != nil {
			withCreds++
		}
		if cp.pool[i].active > 10 {
			t.Fatalf("slot %d active %d — more than VK's ten per identity", i, cp.pool[i].active)
		}
		seats += cp.pool[i].active
	}
	if withCreds != 3 || seats != 30 {
		t.Fatalf("after the herd: %d slots with creds, %d seats — want 3 and 30", withCreds, seats)
	}
}
