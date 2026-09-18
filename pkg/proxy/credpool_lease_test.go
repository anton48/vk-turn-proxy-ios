package proxy

import (
	"context"
	"errors"
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
	seatHolders(cp, 0, connsPerSlot)
	cp.mu.Unlock()
	return old
}

func leaseCounts(cp *credPool, slot int) (active, live int, username string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if c := cp.pool[slot].creds; c != nil {
		username = c.Username
	}
	return cp.pool[slot].active, cp.liveLeasesLocked(), username
}

// The accounting. After the grower's refill under ten sessions the new
// identity starts at 0 and the ten leases are still counted; ten NEW holders
// fill it; the old sessions' releases then take nothing off it and announce no
// room on it (it is full — an 11th holder would earn a 486); a new holder's
// own release does both. Sabotages seen red: the identity check dropped from
// release (the old release takes a seat: active 9); the record of leases reset by the
// refill (0 out after it).
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
		t.Fatalf("leases out after the refill = %d, want %d — the ten sessions on the old identity are still running", live, connsPerSlot)
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
		t.Fatalf("after ten new holders: active %d, leases out %d — want %d, %d", active, live, connsPerSlot, 2*connsPerSlot)
	}

	wake := cp.slotAvailableChannel()
	cp.release(0, old) // an OLD session ends
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot {
		t.Fatalf("an old session's release took a seat off the NEW identity: active %d, want %d — the pool would seat an eleventh holder and earn a 486", active, connsPerSlot)
	} else if live != 2*connsPerSlot-1 {
		t.Fatalf("leases out after an old session's release = %d, want %d — the lease did end", live, 2*connsPerSlot-1)
	}
	if isClosed(wake) {
		t.Fatal("an old session's release announced room on the refilled slot — it is full")
	}
	for i := 1; i < connsPerSlot; i++ {
		cp.release(0, old)
	}
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != connsPerSlot {
		t.Fatalf("after all ten old releases: active %d, leases out %d — want %d, %d", active, live, connsPerSlot, connsPerSlot)
	}
	if isClosed(wake) {
		t.Fatal("the old sessions' releases broadcast slot-available")
	}

	// The arm that must go THROUGH: a holder of the credential the slot holds.
	cp.release(0, fresh[0])
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot-1 || live != connsPerSlot-1 {
		t.Fatalf("after a new holder's own release: active %d, leases out %d — want %d, %d", active, live, connsPerSlot-1, connsPerSlot-1)
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
		t.Fatalf("leases out after invalidate() = %d, want %d — the sessions end later, one by one", live, connsPerSlot)
	}
	_, b, slot, err := cp.get(0, false)
	if err != nil || slot != 0 || b.Username == a.Username {
		t.Fatalf("the next get = slot %d, %v, same identity %v — want a new identity in slot 0", slot, err, b != nil && b.Username == a.Username)
	}
	for i := 0; i < connsPerSlot; i++ {
		cp.release(0, a)
	}
	if active, live, _ := leaseCounts(cp, 0); active != 1 || live != 1 {
		t.Fatalf("after A's ten late releases: active %d, leases out %d — want 1, 1 (B's holder is up)", active, live)
	}
	cp.release(0, b)
	cp.mu.Lock()
	active, live, stamped := cp.pool[0].active, cp.liveLeasesLocked(), !cp.pool[0].lastUsedAt.IsZero()
	cp.mu.Unlock()
	if active != 0 || live != 0 || !stamped {
		t.Fatalf("after B's own release: active %d, leases out %d, lastUsedAt stamped %v — want 0, 0, true", active, live, stamped)
	}
	cp.release(0, b) // a stray second release
	if _, live, _ := leaseCounts(cp, 0); live != 0 {
		t.Fatalf("leases out after a stray release = %d, want 0", live)
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
)

// Every holder tells the pool WHICH credential: a scan of the call sites, and
// of who may write the lease count. Sabotages seen red: a session function's
// release back on the slot alone would not compile — so the scan's own
// sabotage is the adapter naming nil, and a refill resetting the record.
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

	// The record of leases still out (credPool.holders). A seat is taken ONE
	// way — seatLocked, which moves the entry's count and the record together;
	// a lease comes off the record in release and nowhere else; nothing resets
	// it — a refill, invalidate() and invalidateEntry replace entries, never
	// this; and every publish of a credential takes the entry's count FROM it.
	if raises := regexp.MustCompile(`\.active\s*(\+\+|\+=)`).FindAllString(creds, -1); len(raises) != 1 {
		t.Errorf("creds.go raises an entry's active in %d places, want 1 — seatLocked alone, or a seat is taken without its record", len(raises))
	}
	seat := goFuncBody(t, "creds.go", "func (cp *credPool) seatLocked(")
	if !strings.Contains(seat, "cp.pool[slot].active++") || !strings.Contains(seat, "cp.holders[leaseKeyOf(slot, cp.pool[slot].creds)]++") {
		t.Error("seatLocked does not move the entry's count and the record together")
	}
	get := goFuncBody(t, "creds.go", "func (cp *credPool) get(")
	if n := strings.Count(get, "cp.seatLocked("); n != 3 {
		t.Errorf("get(): %d seats through seatLocked, want 3 — Phase 1's, the fetched credential's own slot, the fallback's", n)
	}
	if m := regexp.MustCompile(`cp\.holders\s*=[^=]|clear\(cp\.holders\)`).FindAllString(creds, -1); len(m) != 1 {
		t.Errorf("creds.go assigns or clears the record in %d places, want 1 — seatLocked's lazy make; nothing may reset the leases still out", len(m))
	}
	if n := strings.Count(creds, "leaseKey{"); n != 1 {
		t.Errorf("creds.go builds a lease key in %d places, want 1 — leaseKeyOf, the slot AND the username", n)
	}
	if n := strings.Count(creds, "delete(cp.holders,"); n != 1 {
		t.Errorf("creds.go deletes from the record in %d places, want 1 — release, at a key's last lease", n)
	}
	for _, fn := range []string{"func (cp *credPool) invalidate()", "func (cp *credPool) invalidateEntry(", "func (cp *credPool) tryFill("} {
		if body := goFuncBody(t, "creds.go", fn); strings.Contains(body, "cp.holders[") || strings.Contains(body, "cp.holders =") || strings.Contains(body, "delete(cp.holders") {
			t.Errorf("%s touches the record of leases still out — it replaces ENTRIES; their holders' sessions live on", fn)
		}
	}
	// Every publish of a credential reads its count from the record — none
	// restarts it blindly (`active: 1`, or no `active` at all beside `creds:`).
	for _, lit := range regexp.MustCompile(`(?s)credPoolEntry\{[^{}]*?creds:[^{}]*?\}`).FindAllString(creds, -1) {
		if !strings.Contains(lit, "cp.outstandingLocked(") && !regexp.MustCompile(`active:\s*held\b`).MatchString(lit) {
			t.Errorf("creds.go publishes a credential without taking its count from the record: %q", strings.Join(strings.Fields(lit), " "))
		}
	}
	if !regexp.MustCompile(`held := cp\.outstandingLocked\(target, creds\)`).MatchString(get) || !strings.Contains(get, "if held >= connsPerSlot {") {
		t.Error("get(): the fetched credential's count is not read from the record, or a credential issued again with all its previous holders still out still seats the fetching conn — an eleventh lease")
	}
	rel := goFuncBody(t, "creds.go", "func (cp *credPool) release(")
	if !strings.Contains(rel, "k := leaseKeyOf(slot, creds)") || !strings.Contains(rel, "delete(cp.holders, k)") || !strings.Contains(rel, "cp.holdsLocked(slot, creds)") {
		t.Error("release(): the lease is not taken off the record of what it was taken on, or the entry is touched without the identity check")
	}
	if i, j := strings.Index(rel, "cp.holdsLocked(slot, creds)"), strings.Index(rel, "cp.pool[slot].active--"); i < 0 || j < 0 || j < i {
		t.Error("release(): the entry's count is decremented before (or without) the identity check")
	}
	gate := goFuncBody(t, "creds.go", "func (cp *credPool) MarkInUseSlotsForPathChange(")
	if !strings.Contains(gate, "live := len(cp.holders) > 0") {
		t.Error("the path-change gate does not read the record of leases still out")
	}
	if regexp.MustCompile(`live\s*=\s*true`).MatchString(gate) {
		t.Error("the path-change gate derives `live` from the entries again — a refilled slot's active restarts at 0 under its sessions")
	}
}

// countsMatchTheRecord is the invariant the pool keeps: a slot that holds a
// credential has active == the leases still out on that (slot, credential).
func countsMatchTheRecord(t *testing.T, cp *credPool, when string) {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for i, e := range cp.pool {
		if e.creds == nil {
			continue
		}
		if out := cp.holders[leaseKeyOf(i, e.creds)]; e.active != out {
			t.Fatalf("%s: slot %d says active %d, the record has %d lease(s) out on its credential", when, i, e.active, out)
		}
	}
}

// sameCredentialPool mints like cookie mode: the credential of a slot keeps
// its USERNAME from one fetch to the next (cookieCredForSlot hands out the
// call's cached mint until it nears expiry), and the two relays of one call
// are two slots with ONE username.
func sameCredentialPool(t *testing.T) *credPool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	username := fmt.Sprintf("%d:the-calls-mint", time.Now().Add(8*time.Hour).Unix())
	cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
		relay := fmt.Sprintf("95.163.34.%d:19302", 180+slot)
		return relay, &TURNCreds{Username: username, Password: "p", Address: relay, Addresses: []string{relay}}, nil
	})
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	cp.mu.Unlock()
	return cp
}

// THE SAME CREDENTIAL ISSUED AGAIN (the user's review of build 409). Ten
// sessions hold slot 0's credential; a Resume's invalidate() empties the pool
// under them; the next get() is handed the SAME username for the slot. By
// username alone, with the count restarted at 0, the old sessions' late
// releases read as the new issuance's: ten new holders became nine, room was
// announced and an eleventh was seated. Now the credential comes back with its
// previous holders still on it: there is no seat until one of THEM releases —
// not for the conn that fetched it either — every release frees a seat that
// was really taken, and the count never falls below the leases out.
// Sabotages seen red: a publish restarting the count (`active: 0` / seating
// the fetching conn whatever the record says); invalidate() clearing the
// record.
func TestTheSameCredentialIssuedAgainKeepsItsHolders(t *testing.T) {
	cp := sameCredentialPool(t)
	cp.setColdStartTarget(connsPerSlot) // one slot is this pool's whole target: a conn with no seat parks instead of minting the call's other relay
	var first *TURNCreds
	for i := 0; i < connsPerSlot; i++ {
		_, c, slot, err := cp.get(i, false)
		if err != nil || slot != 0 {
			t.Fatalf("get(%d) = slot %d, %v — want slot 0", i, slot, err)
		}
		first = c
	}
	cp.invalidate()

	_, _, slot, err := cp.get(0, false) // fetches: the same username comes back for slot 0
	var park *poolParkError
	if !errors.As(err, &park) || slot != -1 {
		t.Fatalf("the conn that fetched the credential again got slot %d, %v — want a park: its ten previous holders are still out, a seat now is an eleventh lease", slot, err)
	}
	if active, live, now := leaseCounts(cp, 0); now != first.Username || active != connsPerSlot || live != connsPerSlot {
		t.Fatalf("after the re-issue: slot 0 holds %q (want the same username), active %d, leases out %d — want %d, %d: the previous holders are still seated", now, active, live, connsPerSlot, connsPerSlot)
	}
	countsMatchTheRecord(t, cp, "after the re-issue")
	if _, _, slot, err := cp.get(1, false); err == nil {
		t.Fatalf("a second conn was seated on slot %d with ten leases out on its credential", slot)
	}

	cp.release(0, first) // the first old session ends: a seat that was really taken is free
	if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot-1 || live != connsPerSlot-1 {
		t.Fatalf("after one old release: active %d, leases out %d — want %d, %d", active, live, connsPerSlot-1, connsPerSlot-1)
	}
	if !isClosed(park.wake) {
		t.Fatal("the release that opened a seat on the full re-issued slot did not wake the parked conn")
	}
	_, again, slot, err := cp.get(0, false)
	if err != nil || slot != 0 {
		t.Fatalf("after the release: get = slot %d, %v — want the freed seat on slot 0", slot, err)
	}
	if _, _, slot, err := cp.get(1, false); err == nil {
		t.Fatalf("an ELEVENTH holder was seated on slot %d: nine old sessions and one new hold its credential", slot)
	}
	countsMatchTheRecord(t, cp, "nine old holders and one new")

	for i := 1; i < connsPerSlot; i++ {
		cp.release(0, first)
	}
	if active, live, _ := leaseCounts(cp, 0); active != 1 || live != 1 {
		t.Fatalf("after every old release: active %d, leases out %d — want 1, 1 (the new holder)", active, live)
	}
	cp.release(0, again)
	cp.release(0, again) // and a stray one
	if active, live, _ := leaseCounts(cp, 0); active != 0 || live != 0 {
		t.Fatalf("after the new holder's release: active %d, leases out %d — want 0, 0", active, live)
	}
	countsMatchTheRecord(t, cp, "at the end")
}

// Two relays of one call are two slots with ONE username (cookie mode), each
// its own quota bucket: their holders are counted apart, so the slot is part
// of what a lease names. Sabotage seen red: the record keyed by username
// alone.
func TestTwoSlotsWithOneUsernameCountTheirHoldersApart(t *testing.T) {
	cp := sameCredentialPool(t)
	_, c0, slot, err := cp.get(0, false) // mints slot 0
	if err != nil || slot != 0 {
		t.Fatalf("get(0) = slot %d, %v", slot, err)
	}
	if !cp.tryFill(1, false, 0) { // the grower fills the call's second relay: the same username
		t.Fatal("the fill of slot 1 failed")
	}
	_, c1, slot, err := cp.get(connsPerSlot, false) // conn 10's own slot is 1
	if err != nil || slot != 1 || c1.Username != c0.Username {
		t.Fatalf("get(10) = slot %d, %v, same username %v — want slot 1 with the call's username", slot, err, c1 != nil && c1.Username == c0.Username)
	}
	cp.release(1, c1)
	if a0, live, _ := leaseCounts(cp, 0); a0 != 1 || live != 1 {
		t.Fatalf("after slot 1's release: slot 0 active %d, leases out %d — want 1, 1: slot 0's holder is still up", a0, live)
	}
	cp.invalidate()
	if !cp.tryFill(1, false, 0) || !cp.tryFill(0, false, 0) {
		t.Fatal("the re-issue failed")
	}
	a0, _, _ := leaseCounts(cp, 0)
	a1, _, _ := leaseCounts(cp, 1)
	if a0 != 1 || a1 != 0 {
		t.Fatalf("after the re-issue: slot 0 active %d, slot 1 active %d — want 1 and 0: only slot 0's holder is still out", a0, a1)
	}
	countsMatchTheRecord(t, cp, "after the re-issue")
}
