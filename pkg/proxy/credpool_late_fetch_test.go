package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A fetch that began before a Resume reset the pool must not publish into
// the slot index it started with: by the time it returns, new connections
// have refilled that slot and are counted on it. Found by the user's review
// of build 375 (2026-09-08): on the real pool with a stub fetch the late
// grower replaced the credential and reset active 10 → 0 — the sessions
// lived on, unaccounted, and every later release, quota check and
// path-change marking worked on a wrong count.

const lateRelay = "95.163.34.180:19302"

func lateCreds(tag string) *TURNCreds {
	return &TURNCreds{Username: fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag),
		Password: "p", Address: lateRelay, Addresses: []string{lateRelay}}
}

// lateFetchPool is a 12-slot pool whose fetcher parks on `gate` and then
// answers a credential named after its slot, or the error set in `fail`.
type lateFetchPool struct {
	cp   *credPool
	gate chan struct{}
	fail atomic.Bool
	seen atomic.Int32
}

func newLateFetchPool(t *testing.T) *lateFetchPool {
	t.Helper()
	l := &lateFetchPool{gate: make(chan struct{})}
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		l.seen.Add(1)
		<-l.gate
		if l.fail.Load() {
			return "", nil, errors.New("vk said no")
		}
		return lateRelay, lateCreds(fmt.Sprintf("late-%d", slot)), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.cp = newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	l.cp.mu.Lock()
	for len(l.cp.pool) < l.cp.size {
		l.cp.pool = append(l.cp.pool, credPoolEntry{})
	}
	l.cp.mu.Unlock()
	return l
}

func (l *lateFetchPool) waitFetching(t *testing.T, slot int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		l.cp.mu.Lock()
		f := l.cp.pool[slot].fetching
		l.cp.mu.Unlock()
		if f {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no fetch started on slot %d", slot)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// resetAndRefill is the Resume: the pool is invalidated and the new
// connections fill `slot` with their own credential and `active` seats.
func (l *lateFetchPool) resetAndRefill(slot, active int) {
	l.cp.invalidate()
	l.cp.mu.Lock()
	l.cp.pool[slot] = credPoolEntry{addr: lateRelay, creds: lateCreds(fmt.Sprintf("conn-%d", slot)), ts: time.Now(), active: active}
	l.cp.mu.Unlock()
}

func (l *lateFetchPool) entry(slot int) credPoolEntry {
	l.cp.mu.Lock()
	defer l.cp.mu.Unlock()
	return l.cp.pool[slot]
}

func (l *lateFetchPool) slotsNamed(prefix string) []int {
	l.cp.mu.Lock()
	defer l.cp.mu.Unlock()
	var out []int
	for i, e := range l.cp.pool {
		if e.creds != nil && strings.Contains(e.creds.Username, ":"+prefix) {
			out = append(out, i)
		}
	}
	return out
}

// The grower's fetch outlives a Resume: the refilled slot keeps its
// credential and its ten seats; the late credential lands in an empty slot.
// Sabotage seen red: ownsLocked returning true unconditionally — slot 3 is
// overwritten and its active count reads 0.
func TestLateGrowerFetchDoesNotOverwriteARefilledSlot(t *testing.T) {
	l := newLateFetchPool(t)
	done := make(chan bool, 1)
	go func() { done <- l.cp.tryFill(3, false, 0) }()
	l.waitFetching(t, 3)
	l.resetAndRefill(3, 10)
	close(l.gate)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tryFill did not return")
	}
	e := l.entry(3)
	if e.creds == nil || !strings.Contains(e.creds.Username, ":conn-3") || e.active != 10 {
		t.Fatalf("slot 3 after the late fetch: creds=%v active=%d — the new connections' slot was overwritten", e.creds, e.active)
	}
	if e.fetching || !e.cooldownUntil.IsZero() {
		t.Fatalf("slot 3 was touched by the late fetch: fetching=%v cooldown=%v", e.fetching, e.cooldownUntil)
	}
	placed := l.slotsNamed("late-3")
	if len(placed) != 1 || placed[0] == 3 {
		t.Fatalf("the late credential sits in slots %v, want exactly one slot other than 3", placed)
	}
}

// A connection's own Phase-2 fetch outlives the Resume the same way: the
// conn is seated on an empty slot with the credential it fetched, and the
// refilled slot keeps its ten seats.
func TestLateConnFetchDoesNotOverwriteARefilledSlot(t *testing.T) {
	l := newLateFetchPool(t)
	type result struct {
		slot int
		err  error
	}
	done := make(chan result, 1)
	go func() { _, _, slot, err := l.cp.get(5, false); done <- result{slot, err} }()
	l.waitFetching(t, 0) // conn 5's own slot is 0 (connIdx/10) and the pool is empty
	l.resetAndRefill(0, 10)
	close(l.gate)
	var r result
	select {
	case r = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("get did not return")
	}
	if r.err != nil || r.slot < 0 || r.slot == 0 {
		t.Fatalf("get: slot %d err %v — want a seat on a slot other than the refilled 0", r.slot, r.err)
	}
	if e := l.entry(0); e.creds == nil || !strings.Contains(e.creds.Username, ":conn-0") || e.active != 10 || e.fetching {
		t.Fatalf("slot 0 after the late fetch: creds=%v active=%d fetching=%v — overwritten", e.creds, e.active, e.fetching)
	}
	if e := l.entry(r.slot); e.creds == nil || !strings.Contains(e.creds.Username, ":late-0") || e.active != 1 {
		t.Fatalf("slot %d: creds=%v active=%d — want the fetched credential with the conn's one seat", r.slot, e.creds, e.active)
	}
}

// A late fetch that FAILS leaves the new owner alone too: no cooldown on the
// refilled slot, no `fetching` reset — and the conn still falls back through
// the pool onto that very slot when it has a seat free.
func TestLateFetchFailureLeavesTheNewOwnerAlone(t *testing.T) {
	l := newLateFetchPool(t)
	l.fail.Store(true)
	done := make(chan bool, 1)
	go func() { done <- l.cp.tryFill(3, false, 0) }()
	l.waitFetching(t, 3)
	l.resetAndRefill(3, 10)
	close(l.gate)
	if ok := <-done; ok {
		t.Fatal("tryFill answered true for a failed fetch")
	}
	if e := l.entry(3); !e.cooldownUntil.IsZero() || e.fetching || e.active != 10 {
		t.Fatalf("slot 3 after the failed late fetch: cooldown=%v fetching=%v active=%d — touched", e.cooldownUntil, e.fetching, e.active)
	}

	l2 := newLateFetchPool(t)
	l2.fail.Store(true)
	type result struct {
		slot int
		err  error
	}
	res := make(chan result, 1)
	go func() { _, _, slot, err := l2.cp.get(5, false); res <- result{slot, err} }()
	l2.waitFetching(t, 0)
	l2.resetAndRefill(0, 4) // six seats free — the fallback may take one
	close(l2.gate)
	r := <-res
	if r.err != nil || r.slot != 0 {
		t.Fatalf("get after a failed late fetch: slot %d err %v — want the fallback seat on the refilled slot 0", r.slot, r.err)
	}
	if e := l2.entry(0); e.active != 5 || !e.cooldownUntil.IsZero() {
		t.Fatalf("slot 0: active=%d cooldown=%v — want 5 seats and no cooldown from a fetch that was not its own", e.active, e.cooldownUntil)
	}
}

// With every slot taken after the reset the late credential is dropped and
// nothing is overwritten.
func TestLateFetchWithNoEmptySlotDropsTheCredential(t *testing.T) {
	l := newLateFetchPool(t)
	done := make(chan bool, 1)
	go func() { done <- l.cp.tryFill(3, false, 0) }()
	l.waitFetching(t, 3)
	l.cp.invalidate()
	l.cp.mu.Lock()
	for i := range l.cp.pool {
		l.cp.pool[i] = credPoolEntry{addr: lateRelay, creds: lateCreds(fmt.Sprintf("conn-%d", i)), ts: time.Now(), active: 2}
	}
	l.cp.mu.Unlock()
	close(l.gate)
	if ok := <-done; ok {
		t.Fatal("tryFill answered true although its credential had nowhere to go")
	}
	if got := l.slotsNamed("late-"); len(got) != 0 {
		t.Fatalf("the late credential was written into slots %v", got)
	}
	for i := 0; i < 12; i++ {
		if e := l.entry(i); e.active != 2 || !strings.Contains(e.creds.Username, fmt.Sprintf(":conn-%d", i)) {
			t.Fatalf("slot %d disturbed: %+v", i, e)
		}
	}
}

// A fetch nobody interrupted publishes exactly as before — into its own slot.
func TestUninterruptedFetchPublishesIntoItsOwnSlot(t *testing.T) {
	l := newLateFetchPool(t)
	close(l.gate)
	if !l.cp.tryFill(3, false, 0) {
		t.Fatal("tryFill failed")
	}
	if e := l.entry(3); e.creds == nil || !strings.Contains(e.creds.Username, ":late-3") || e.fetching {
		t.Fatalf("slot 3: %+v", e)
	}
	_, _, slot, err := l.cp.get(5, false)
	if err != nil || slot != 3 {
		// slot 3 is fresh with free seats; compact-fill seats conn 5 there
		// rather than minting into its own slot 0.
		t.Fatalf("get: slot %d err %v", slot, err)
	}
}

// Cookie (VKAuth) mode: a slot is one (call, relay) bucket and the fetcher
// returns the SAME credential for the same slot. A late fetch for slot 0
// returns relay A's credential, which the new fetch has already put back into
// slot 0 with ten seats — it must NOT be moved into the free slot 1 (relay
// B's): that would be an eleventh allocation on A and a filled-looking slot 1
// with B unused (user's review, reproduced 3/3 on 376). Sabotage seen red:
// the cookie-mode refusal removed — the copy lands in slot 1.
func TestLateFetchInCookieModeIsNotRelocated(t *testing.T) {
	cookieAuthEnabled.Store(true)
	t.Cleanup(func() { cookieAuthEnabled.Store(false) })
	credA := lateCreds("cookie-A")
	l := newLateFetchPool(t)
	// The cookie fetcher: slot 0 always answers relay A's credential.
	l.cp.mu.Lock()
	l.cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) {
		l.seen.Add(1)
		<-l.gate
		if slot == 0 {
			return lateRelay, credA, nil
		}
		return lateRelay, lateCreds(fmt.Sprintf("cookie-%d", slot)), nil
	}
	l.cp.mu.Unlock()

	// The grower's late fetch for slot 0.
	done := make(chan bool, 1)
	go func() { done <- l.cp.tryFill(0, false, 0) }()
	l.waitFetching(t, 0)
	l.cp.invalidate()
	l.cp.mu.Lock()
	l.cp.pool[0] = credPoolEntry{addr: lateRelay, creds: credA, ts: time.Now(), active: 10}
	l.cp.mu.Unlock()
	close(l.gate)
	if ok := <-done; ok {
		t.Fatal("tryFill answered true although relay A's credential was already in slot 0")
	}
	if got := l.slotsNamed("cookie-A"); len(got) != 1 || got[0] != 0 {
		t.Fatalf("relay A's credential sits in slots %v, want slot 0 alone", got)
	}
	if e := l.entry(0); e.active != 10 {
		t.Fatalf("slot 0 active = %d, want 10", e.active)
	}

	// A connection's own late fetch for slot 0 while A is full: no eleventh
	// seat on A anywhere — the conn is told to retry.
	l2 := newLateFetchPool(t)
	l2.cp.mu.Lock()
	l2.cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) { <-l2.gate; return lateRelay, credA, nil }
	l2.cp.mu.Unlock()
	type result struct {
		slot int
		err  error
	}
	res := make(chan result, 1)
	go func() { _, _, slot, err := l2.cp.get(5, false); res <- result{slot, err} }()
	l2.waitFetching(t, 0)
	l2.cp.invalidate()
	l2.cp.mu.Lock()
	l2.cp.pool[0] = credPoolEntry{addr: lateRelay, creds: credA, ts: time.Now(), active: 10}
	l2.cp.mu.Unlock()
	close(l2.gate)
	r := <-res
	if r.err == nil || r.slot != -1 {
		t.Fatalf("get: slot %d err %v — want a retry error, not an eleventh seat on relay A", r.slot, r.err)
	}
	if got := l2.slotsNamed("cookie-A"); len(got) != 1 || got[0] != 0 {
		t.Fatalf("relay A's credential sits in slots %v, want slot 0 alone", got)
	}
	if e := l2.entry(0); e.active != 10 || !e.cooldownUntil.IsZero() {
		t.Fatalf("slot 0: active=%d cooldown=%v — want the ten seats untouched and no cooldown", e.active, e.cooldownUntil)
	}

	// The window the Username check cannot see: after the reset a NEW fetch
	// for slot 0 is in flight (fetching, no credential yet) when the late one
	// returns relay A's credential. Nothing in the pool matches it, yet it
	// must not move into slot 1 — the new fetch is about to put the same
	// credential into slot 0. This is the case the cookie-mode refusal exists
	// for (the sabotage that removes only that refusal is red here alone).
	l3 := newLateFetchPool(t)
	l3.cp.mu.Lock()
	l3.cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) { <-l3.gate; return lateRelay, credA, nil }
	l3.cp.mu.Unlock()
	done3 := make(chan bool, 1)
	go func() { done3 <- l3.cp.tryFill(0, false, 0) }()
	l3.waitFetching(t, 0)
	l3.cp.invalidate()
	l3.cp.mu.Lock()
	l3.cp.claimForFetchLocked(0) // the new fetch for relay A has started
	l3.cp.mu.Unlock()
	close(l3.gate)
	if ok := <-done3; ok {
		t.Fatal("tryFill answered true with relay A's credential moved out of its slot")
	}
	if got := l3.slotsNamed("cookie-A"); len(got) != 0 {
		t.Fatalf("relay A's credential was placed into slots %v while its own slot's fetch was in flight", got)
	}
	if e := l3.entry(0); !e.fetching || e.creds != nil {
		t.Fatalf("slot 0 (the new fetch's claim) was touched: fetching=%v creds=%v", e.fetching, e.creds)
	}
}

// Anonymous mode: a late credential whose Username is already in the pool is
// the same cred set and must not become a second copy of one quota, even with
// empty slots around. Sabotage seen red: the duplicate check removed.
func TestLateDuplicateCredentialIsNotRelocated(t *testing.T) {
	same := lateCreds("same-set")
	l := newLateFetchPool(t)
	l.cp.mu.Lock()
	l.cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) { <-l.gate; return lateRelay, same, nil }
	l.cp.mu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- l.cp.tryFill(3, false, 0) }()
	l.waitFetching(t, 3)
	l.cp.invalidate()
	l.cp.mu.Lock()
	l.cp.pool[3] = credPoolEntry{addr: lateRelay, creds: same, ts: time.Now(), active: 10}
	l.cp.mu.Unlock()
	close(l.gate)
	if ok := <-done; ok {
		t.Fatal("tryFill answered true for a duplicate credential")
	}
	if got := l.slotsNamed("same-set"); len(got) != 1 || got[0] != 3 {
		t.Fatalf("the credential sits in slots %v, want slot 3 alone", got)
	}
}
