package proxy

// The pool after a path change (2026-09-06, build 360): the marking saturates
// every in-use slot for 10 min, the restarted connections come back at once,
// and the pool must MINT for them — a fresh fetch is a new VK identity with
// its own quota — instead of parking them behind creds whose allocations are
// dead. Two things stood in the way: the cold-start cap counted saturated
// slots as "ready" (Phase 1 refuses them — count by the predicate you hand
// out by), and Phase 2 would never fetch into a saturated slot even when no
// connection was bound to it any more.

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pathChangedPool is a 12-slot pool the way an LTE→Wi-Fi switch leaves it:
// slots 0/4/5 hold fresh creds just MARKED saturated (their sessions gone,
// active 0), the rest are disk-loaded and pending, and slot 3 is empty or
// pending as the caller says.
func pathChangedPool(t *testing.T, slot3Empty bool) (*credPool, *atomic.Int32) {
	t.Helper()
	var mints atomic.Int32
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		mints.Add(1)
		addr := "95.163.34.180:19302"
		return addr, &TURNCreds{Username: fmt.Sprintf("%d:minted-%d", time.Now().Add(8*time.Hour).Unix(), slot),
			Password: "p", Address: addr, Addresses: []string{addr}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	now := time.Now()
	for i := range cp.pool {
		creds := &TURNCreds{Username: fmt.Sprintf("%d:loaded-%d", now.Add(8*time.Hour).Unix(), i), Password: "p",
			Address: "95.163.34.180:19302", Addresses: []string{"95.163.34.180:19302"}}
		switch i {
		case 0, 4, 5:
			cp.pool[i] = credPoolEntry{addr: creds.Address, creds: creds, ts: now.Add(-3 * time.Minute), saturatedUntil: now.Add(10 * time.Minute)}
		case 3:
			if slot3Empty {
				cp.pool[i] = credPoolEntry{}
			} else {
				cp.pool[i] = credPoolEntry{addr: creds.Address, creds: creds, ts: now.Add(-5 * time.Minute), availableAt: now.Add(5 * time.Minute)}
			}
		default:
			cp.pool[i] = credPoolEntry{addr: creds.Address, creds: creds, ts: now.Add(-5 * time.Minute), availableAt: now.Add(5 * time.Minute)}
		}
	}
	cp.mu.Unlock()
	return cp, &mints
}

// With an empty slot in the pool, a connection that finds every usable slot
// saturated MINTS into it instead of parking: the cap counts the slots Phase
// 1 would hand out (none), not the saturated ones. Sabotage seen red: the
// cap counting fresh-but-saturated slots as ready (countFreshLocked) — the
// acquire parks on "cold-start cap (3 ready+inflight >= 3 target)".
func TestPathChangeMintsInsteadOfParkingBehindSaturatedSlots(t *testing.T) {
	cp, mints := pathChangedPool(t, true)
	addr, creds, slot, err := cp.get(0, false)
	if err != nil {
		t.Fatalf("acquire after the path change: %v — thirty connections would wait out a 10-minute cooldown here", err)
	}
	if mints.Load() != 1 || slot != 3 || addr == "" || creds == nil || !strings.HasSuffix(creds.Username, "minted-3") {
		t.Fatalf("mints %d slot %d creds %v — want one fresh mint into the empty slot 3", mints.Load(), slot, creds)
	}
}

// With NO empty slot (every slot saturated or pending), the pool replaces a
// saturated slot that no connection is bound to — its sessions were restarted
// and its allocations are dead at VK — and still refuses to replace one with
// connections on it. Sabotage seen red: the second pass dropped from Phase 2
// ("no slot available" with three idle saturated slots in the pool).
func TestPathChangeReplacesAnIdleSaturatedSlotWhenNothingIsEmpty(t *testing.T) {
	cp, mints := pathChangedPool(t, false)
	_, creds, slot, err := cp.get(0, false)
	if err != nil {
		t.Fatalf("acquire with every slot saturated or pending: %v — the idle saturated slots are free to reuse", err)
	}
	if mints.Load() != 1 || (slot != 0 && slot != 4 && slot != 5) || creds == nil || !strings.HasPrefix(creds.Username[strings.Index(creds.Username, ":")+1:], "minted") {
		t.Fatalf("mints %d slot %d creds %v — want one fresh mint into an idle saturated slot", mints.Load(), slot, creds)
	}
	// The minted slot fills up, and conns are still bound to the other two
	// saturated slots: those must stay — a park, not a replaced cred.
	cp.mu.Lock()
	for _, i := range []int{0, 4, 5} {
		cp.pool[i].active = 10
	}
	cp.mu.Unlock()
	if _, _, _, err := cp.get(11, false); err == nil || !strings.Contains(err.Error(), "no slot available") {
		t.Fatalf("acquire with the remaining saturated slots in use: %v — want a park, not a replaced cred under ten live conns", err)
	}
}
