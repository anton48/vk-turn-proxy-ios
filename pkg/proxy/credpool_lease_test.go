package proxy

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A LEASE NAMES ITS CREDENTIAL (the field run of 2026-09-18). The grower
// renews a credential ~30 min before it expires whether or not sessions still
// run on it — they do: the relay keeps refreshing an existing allocation past
// the credential's expiry — and the refill replaces the whole entry, so the
// slot's `active` restarts at 0 under up to ten live sessions. Two things went
// wrong from there: the path-change gate read the entries and said "nothing
// live" with forty sessions up (no cascade arming), and an old session's
// release(slot) took a seat off the NEW identity's count. These tests drive the
// production refill (pickSlotToFill → tryFill), invalidate() and
// invalidateEntry on a bare pool.

const leaseTestRelay = "95.163.34.180:19302"

// leasePool is a 12-slot pool whose fetcher mints a fresh identity per call.
func leasePool(t *testing.T, mints *atomic.Int32) *credPool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
		n := mints.Add(1)
		return leaseTestRelay, &TURNCreds{Username: fmt.Sprintf("%d:mint-%d-slot-%d", time.Now().Add(8*time.Hour).Unix(), n, slot),
			Password: "p", Address: leaseTestRelay, Addresses: []string{leaseTestRelay}}, nil
	})
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	cp.mu.Unlock()
	return cp
}

// expiringUnderTenSessions puts a credential ten minutes from its expiry into
// slot 0 with ten sessions on it — the state every in-use slot reaches once
// per credential lifetime (get() cannot produce it in a test: it hands out
// only credentials more than credExpiryBuffer from expiry, and the buffer is
// a constant). Returns the credential those ten leases name.
func expiringUnderTenSessions(cp *credPool) *TURNCreds {
	old := &TURNCreds{Username: fmt.Sprintf("%d:expiring", time.Now().Add(10*time.Minute).Unix()),
		Password: "p", Address: leaseTestRelay, Addresses: []string{leaseTestRelay}}
	cp.mu.Lock()
	cp.pool[0] = credPoolEntry{addr: leaseTestRelay, creds: old, ts: time.Now().Add(-7*time.Hour - 30*time.Minute)}
	seatLocked(cp, 0, connsPerSlot)
	cp.mu.Unlock()
	return old
}

func leaseCounts(cp *credPool, slot int) (active, live int, username string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if c := cp.pool[slot].creds; c != nil {
		username = c.Username
	}
	return cp.pool[slot].active, cp.liveLeases, username
}

// The accounting. After the grower's refill under ten sessions the new
// identity starts at 0 and the ten leases are still counted; ten NEW holders
// fill it; the old sessions' releases then take nothing off it and announce no
// room on it (it is full — an 11th holder would earn a 486); a new holder's
// own release does both. Sabotages seen red: the identity check dropped from
// release (the old release takes a seat: active 9); liveLeases reset by the
// refill (0 after it).
func TestAReleaseCountsOnlyAgainstTheCredentialItNames(t *testing.T) {
	var mints atomic.Int32
	cp := leasePool(t, &mints)
	old := expiringUnderTenSessions(cp)

	if slot := cp.pickSlotToFill(); slot != 0 {
		t.Fatalf("pickSlotToFill = %d, want 0 — the premise: the grower takes a slot near expiry whether or not it is in use", slot)
	}
	if !cp.tryFill(0, false, 0) {
		t.Fatal("the refill of slot 0 failed")
	}
	active, live, now := leaseCounts(cp, 0)
	if now == old.Username || now == "" {
		t.Fatalf("slot 0 holds %q after the refill, want a new identity", now)
	}
	if active != 0 {
		t.Fatalf("the refilled slot's active = %d, want 0 — the new identity has no holder yet", active)
	}
	if live != connsPerSlot {
		t.Fatalf("liveLeases after the refill = %d, want %d — the ten sessions on the old identity are still running", live, connsPerSlot)
	}

	fresh := make([]*TURNCreds, 0, connsPerSlot)
	for i := 0; i < connsPerSlot; i++ { // ten new holders (conns 0–9 prefer slot 0)
		_, c, slot, err := cp.get(i, false)
		if err != nil || slot != 0 {
			t.Fatalf("get(%d) = slot %d, %v — want a seat on the refilled slot 0", i, slot, err)
		}
		fresh = append(fresh, c)
	}
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != 2*connsPerSlot {
		t.Fatalf("after ten new holders: active %d, liveLeases %d — want %d, %d", active, live, connsPerSlot, 2*connsPerSlot)
	}

	wake := cp.slotAvailableChannel()
	cp.release(0, old) // an OLD session ends
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot {
		t.Fatalf("an old session's release took a seat off the NEW identity: active %d, want %d — the pool would seat an eleventh holder and earn a 486", active, connsPerSlot)
	} else if live != 2*connsPerSlot-1 {
		t.Fatalf("liveLeases after an old session's release = %d, want %d — the lease did end", live, 2*connsPerSlot-1)
	}
	if isClosed(wake) {
		t.Fatal("an old session's release announced room on the refilled slot — it is full")
	}
	for i := 1; i < connsPerSlot; i++ {
		cp.release(0, old)
	}
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != connsPerSlot {
		t.Fatalf("after all ten old releases: active %d, liveLeases %d — want %d, %d", active, live, connsPerSlot, connsPerSlot)
	}
	if isClosed(wake) {
		t.Fatal("the old sessions' releases broadcast slot-available")
	}

	// The arm that must go THROUGH: a holder of the credential the slot holds.
	cp.release(0, fresh[0])
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot-1 || live != connsPerSlot-1 {
		t.Fatalf("after a new holder's own release: active %d, liveLeases %d — want %d, %d", active, live, connsPerSlot-1, connsPerSlot-1)
	}
	if !isClosed(wake) {
		t.Fatal("a release from a FULL slot by a holder of its credential did not broadcast slot-available")
	}
}

// The gate. A path event after the refill still finds the ten sessions:
// the cascade detector is armed and the refilled slot is NOT benched (the new
// identity has no allocation at the relay). Sabotage seen red: the gate back
// on the entries' own `active`.
func TestAPathEventAfterARefillStillFindsTheSessions(t *testing.T) {
	var mints atomic.Int32
	cp := leasePool(t, &mints)
	expiringUnderTenSessions(cp)
	if !cp.tryFill(0, false, 0) {
		t.Fatal("the refill of slot 0 failed")
	}
	cp.MarkInUseSlotsForPathChange()
	if armedAt, _ := cp.cascadeState(); armedAt.IsZero() {
		t.Fatal("a path event with ten sessions up read \"nothing live\" after their slot was refilled — the cascade detector stays unarmed")
	}
	cp.mu.Lock()
	benched := cp.pool[0].saturatedUntil.After(time.Now())
	cp.mu.Unlock()
	if benched {
		t.Fatal("the refilled slot was marked saturated — it holds a new identity with no allocation at the relay")
	}
}

// A Resume's invalidate() empties every slot under its holders; the same
// conn then mints B into the same slot number. The late releases of A's
// holders leave B's count alone and wind the lease count down to B's own;
// B's release stamps lastUsedAt; a stray extra release cannot go negative.
// Sabotage seen red: the identity check dropped from release (B's count 0
// while B's holder is up).
func TestLateReleasesAfterAnInvalidateLeaveTheNewHolderCounted(t *testing.T) {
	var mints atomic.Int32
	cp := leasePool(t, &mints)
	var a *TURNCreds
	for i := 0; i < connsPerSlot; i++ { // the real path: ten leases on a fresh credential
		_, c, slot, err := cp.get(i, false)
		if err != nil || slot != 0 {
			t.Fatalf("get(%d) = slot %d, %v — want slot 0", i, slot, err)
		}
		a = c
	}
	cp.invalidate()
	if _, live, _ := leaseCounts(cp, 0); live != connsPerSlot {
		t.Fatalf("liveLeases after invalidate() = %d, want %d — the sessions end later, one by one", live, connsPerSlot)
	}
	_, b, slot, err := cp.get(0, false)
	if err != nil || slot != 0 || b.Username == a.Username {
		t.Fatalf("the next get = slot %d, %v, same identity %v — want a new identity in slot 0", slot, err, b != nil && b.Username == a.Username)
	}
	for i := 0; i < connsPerSlot; i++ {
		cp.release(0, a)
	}
	if active, live, _ := leaseCounts(cp, 0); active != 1 || live != 1 {
		t.Fatalf("after A's ten late releases: active %d, liveLeases %d — want 1, 1 (B's holder is up)", active, live)
	}
	cp.release(0, b)
	cp.mu.Lock()
	active, live, stamped := cp.pool[0].active, cp.liveLeases, !cp.pool[0].lastUsedAt.IsZero()
	cp.mu.Unlock()
	if active != 0 || live != 0 || !stamped {
		t.Fatalf("after B's own release: active %d, liveLeases %d, lastUsedAt stamped %v — want 0, 0, true", active, live, stamped)
	}
	cp.release(0, b) // a stray second release
	if _, live, _ := leaseCounts(cp, 0); live != 0 {
		t.Fatalf("liveLeases after a stray release = %d, want 0", live)
	}
}

// A 486 and a 401 name their credential too. The slot holds B; a holder of A
// (leased before the refill) reports a 486 twice and then a 401: B is not
// benched, the breaker — which would read two refusals on a FRESH credential
// with no success as the relay refusing fresh identities — hears nothing, and
// B is not dropped; the session's 486 total still counts them. Then B's own
// holder reports the same and both act. Sabotages seen red: the check dropped
// from markSaturated (B benched, minting paused); from invalidateEntry (B
// dropped).
func TestARefusalNamesTheCredentialItWasFor(t *testing.T) {
	var mints atomic.Int32
	cp := leasePool(t, &mints)
	_, a, slot, err := cp.get(0, false)
	if err != nil || slot != 0 {
		t.Fatalf("get = slot %d, %v", slot, err)
	}
	cp.invalidate() // a Resume between A's lease and the relay's answer
	_, b, slot, err := cp.get(0, false)
	if err != nil || slot != 0 || b.Username == a.Username {
		t.Fatalf("the refill = slot %d, %v — want a new identity in slot 0", slot, err)
	}

	if cd := cp.markSaturated(0, a); cd != 0 {
		t.Fatalf("a 486 for the OLD credential chose a cooldown of %s, want 0 — nothing to mark", cd)
	}
	cp.markSaturated(0, a)
	cp.mu.Lock()
	benched := cp.pool[0].saturatedUntil.After(time.Now())
	cp.mu.Unlock()
	if benched {
		t.Fatal("a 486 for the OLD credential benched the new identity in its slot")
	}
	if refusals, paused := cp.quotaSnapshot(); refusals != 2 || paused != 0 {
		t.Fatalf("after two 486s for the OLD credential: (%d, paused %s), want (2, 0) — they are 486s the pool was told of, and no evidence about the fresh identity in the slot", refusals, paused)
	}
	cp.invalidateEntry(0, a)
	if _, _, now := leaseCounts(cp, 0); now != b.Username {
		t.Fatalf("a 401 for the OLD credential dropped the new identity: slot 0 holds %q, want %q", now, b.Username)
	}

	// The arms that must go THROUGH.
	if cd := cp.markSaturated(0, b); cd <= 0 {
		t.Fatal("a 486 for the credential the slot holds marked nothing")
	}
	cp.invalidateEntry(0, b)
	if _, _, now := leaseCounts(cp, 0); now != "" {
		t.Fatalf("a 401 for the credential the slot holds left it there (%q)", now)
	}
}

var (
	oneArgPoolCall = regexp.MustCompile(`\b(release|markSaturated|invalidateEntry|Release|MarkSaturated|InvalidateSlot)\(\s*\w+\s*\)`)
	leaseWrite     = regexp.MustCompile(`liveLeases\s*(\+\+|--|[-+*/]?=[^=])`)
)

// Every holder tells the pool WHICH credential: a scan of the call sites, and
// of who may write the lease count. Sabotages seen red: a session function's
// release back on the slot alone would not compile — so the scan's own
// sabotage is the adapter naming nil, and a refill resetting liveLeases.
func TestEveryLeaseHolderNamesItsCredential(t *testing.T) {
	code := func(path string) string {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return stripComments(string(src))
	}
	proxySrc, bridge, creds := code("proxy.go"), code("../../WireGuardBridge/csqtt_bridge.go"), code("creds.go")

	for name, src := range map[string]string{"proxy.go": proxySrc, "csqtt_bridge.go": bridge, "credpool.go": code("credpool.go")} {
		if m := oneArgPoolCall.FindString(src); m != "" {
			t.Errorf("%s: %q tells the pool a slot number alone — a lease names its credential", name, m)
		}
	}
	// The sessions release the PAIR they hold, the probe what it was handed.
	if n := strings.Count(proxySrc, "p.credPool.release(currentSlot, currentCreds)"); n != 4 {
		t.Errorf("proxy.go: %d deferred releases of (currentSlot, currentCreds), want 4 — one per session function", n)
	}
	for _, call := range []string{
		"p.credPool.release(probeSlot, probeCreds)",
		"p.credPool.release(credSlot, currentCreds)",    // the direct session's re-lease
		"currentSlot, currentCreds = newSlot, newCreds", // … which takes a new pair
		"currentSlot, currentCreds = -1, nil",           // … after giving the old one back
	} {
		if !strings.Contains(proxySrc, call) {
			t.Errorf("proxy.go lacks %q", call)
		}
	}
	if n := strings.Count(proxySrc, "markSaturated(credSlot, creds)"); n != 3 {
		t.Errorf("proxy.go: %d markSaturated(credSlot, creds) calls, want 3", n)
	}
	if n := strings.Count(proxySrc, "invalidateEntry(credSlot, creds)"); n != 3 {
		t.Errorf("proxy.go: %d invalidateEntry(credSlot, creds) calls, want 3", n)
	}
	for _, call := range []string{"a.pool.Release(slot, creds)", "a.pool.MarkSaturated(slot, creds)", "a.pool.InvalidateSlot(slot, creds)", "a.refused(workerID, slot, creds, err)"} {
		if !strings.Contains(bridge, call) {
			t.Errorf("csqtt_bridge.go lacks %q — the adapter must hand the leased credential on", call)
		}
	}

	// The lease count: taken at get()'s three seats, given back in release,
	// and written NOWHERE else — a refill, invalidate() and invalidateEntry
	// replace entries, never this.
	writes := leaseWrite.FindAllString(creds, -1)
	ups, downs := 0, 0
	for _, w := range writes {
		switch {
		case strings.HasSuffix(w, "++"):
			ups++
		case strings.HasSuffix(w, "--"):
			downs++
		default:
			t.Errorf("creds.go writes liveLeases with %q — only get()'s seats (++) and release (--) may", strings.TrimSpace(w))
		}
	}
	if ups != 3 || downs != 1 {
		t.Errorf("creds.go: liveLeases++ ×%d, -- ×%d — want 3 (get()'s seats) and 1 (release)", ups, downs)
	}
	get := goFuncBody(t, "creds.go", "func (cp *credPool) get(")
	if n := strings.Count(get, "cp.liveLeases++"); n != 3 {
		t.Errorf("get(): %d lease counts, want 3 — Phase 1's seat, the fetched credential's, the fallback's", n)
	}
	for _, seat := range []string{"cp.pool[slot].active++\n\t\tcp.liveLeases++"} {
		if n := strings.Count(get, seat); n != 2 {
			t.Errorf("get(): %d seats of the form active++ / liveLeases++, want 2", n)
		}
	}
	rel := goFuncBody(t, "creds.go", "func (cp *credPool) release(")
	if !strings.Contains(rel, "cp.liveLeases--") || !strings.Contains(rel, "cp.holdsLocked(slot, creds)") {
		t.Error("release(): the lease is not taken off liveLeases, or the entry is touched without the identity check")
	}
	if i, j := strings.Index(rel, "cp.holdsLocked(slot, creds)"), strings.Index(rel, "cp.pool[slot].active--"); i < 0 || j < 0 || j < i {
		t.Error("release(): the entry's count is decremented before (or without) the identity check")
	}
	gate := goFuncBody(t, "creds.go", "func (cp *credPool) MarkInUseSlotsForPathChange(")
	if !strings.Contains(gate, "live := cp.liveLeases > 0") {
		t.Error("the path-change gate does not read the pool's lease count")
	}
	if regexp.MustCompile(`live\s*=\s*true`).MatchString(gate) {
		t.Error("the path-change gate derives `live` from the entries again — a refilled slot's active restarts at 0 under its sessions")
	}
}
