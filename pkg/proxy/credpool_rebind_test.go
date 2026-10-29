// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The user's review of 454 (issue #105's re-resolution), two findings.
//
// (1) The re-resolved list re-pointed every slot by its INDEX while the
// slots' leases stayed where they were: with slot 0 holding ten leases on A
// and B unreachable, a DNS answer in the other order ([A, B] → [B, A]) put
// slot 1 "on A" with active 0 — the next Acquire was an eleventh seat on A.
// A slot's relay is its own: the list's change keeps every filled slot on
// the relay it holds while the list still names it; a slot whose relay the
// list dropped keeps it while leases are live on it (the seats are that
// relay's; the slot is handed out no more) and takes a free entry of the list
// once none is — at the change, or at the release that frees the last.
//
// (2) The re-resolution read the app's bootstrap map first — the names it
// had resolved at start — and never asked DNS: a path change, an exhausted
// list and an invalidate all got the start's answer back.

const ipR3 = "203.0.113.23"

// cookieNamePool: a cookie-mode CredPool under a one-name override list whose
// DNS answer the test controls; the mints are cached (no network).
func cookieNamePool(t *testing.T, numConns int, answer *atomic.Value) *CredPool {
	t.Helper()
	links := []string{"https://vk.ru/call/join/abcdef"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieMu.Unlock()
	old := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = old })
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
		var out []net.IP
		for _, s := range answer.Load().([]string) {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: numConns, TurnServers: []string{nameRelay}})
	t.Cleanup(cp.Close)
	return cp
}

// waitForList polls until the pool's resolved list reads `want` (the
// resolution runs off the lock).
func waitForList(t *testing.T, cp *CredPool, want ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := cp.cp.overrideServers()
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the resolved list is %v after 3 s, want %v", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func slotAddrs(cp *CredPool, slot int) []string {
	cp.cp.mu.Lock()
	defer cp.cp.mu.Unlock()
	return append([]string(nil), cp.cp.pool[slot].addrs...)
}

func TestCookieModeAReorderedListKeepsEachSlotOnItsRelay(t *testing.T) {
	var answer atomic.Value
	answer.Store([]string{ipR1, ipR2})
	cp := cookieNamePool(t, 20, &answer)
	r1, r2 := ipR1+":19302", ipR2+":19302"
	// Slot 0 fills its ten seats on R1.
	var held []*TURNCreds
	for conn := 0; conn < 10; conn++ {
		addr, creds, slot, err := cp.Acquire(conn)
		if err != nil || addr != r1 || slot != 0 {
			t.Fatalf("conn %d: %q slot %d %v — want slot 0 on %s", conn, addr, slot, err, r1)
		}
		held = append(held, creds)
	}
	// Slot 1 is on R2, which goes silent with evidence → marked.
	addr, creds1, slot, err := cp.Acquire(10)
	if err != nil || addr != r2 || slot != 1 {
		t.Fatalf("conn 10: %q slot %d %v — want slot 1 on %s", addr, slot, err, r2)
	}
	cp.Release(1, creds1)
	cp.cp.health.answered("", time.Time{})
	cp.NoteRelayUnanswered(10, 1, creds1, r2, time.Now())
	// DNS answers in the other order; the exhaustion (slot 0 full, slot 1
	// marked) has the list resolved again.
	answer.Store([]string{ipR2, ipR1})
	for i := 0; i < 20 && strings.Join(cp.cp.overrideServers(), ",") != ipR2+":19302,"+r1; i++ {
		if a, c, s, err := cp.Acquire(11); err == nil {
			cp.Release(s, c)
			if a == r1 {
				t.Fatalf("conn 11 was handed %s — an eleventh seat on R1 (slot %d)", a, s)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitForList(t, cp, r2, r1)
	if a0, a1 := slotAddrs(cp, 0), slotAddrs(cp, 1); strings.Join(a0, ",") != r1 || strings.Join(a1, ",") != r2 {
		t.Fatalf("after the re-ordered answer: slot 0 dials %v, slot 1 %v — want slot 0 still on %s (its ten leases), slot 1 still on %s", a0, a1, r1, r2)
	}
	for i := 0; i < 5; i++ {
		if a, c, s, err := cp.Acquire(11); err == nil {
			cp.Release(s, c)
			if a == r1 {
				t.Fatalf("conn 11 was handed %s on slot %d — an eleventh seat on R1 (slot 0 holds ten)", a, s)
			}
		}
	}
	// Slot 1 refilled by a mint: the minter is told what the pool holds —
	// R1 — and the pool places the credential on the relay the minter chose,
	// not the list's second entry (R1 again, a twin of slot 0).
	cp.cp.mu.Lock()
	cp.cp.pool[1] = credPoolEntry{}
	cp.cp.mu.Unlock()
	a, c, s, err := cp.Acquire(10)
	if err == nil {
		cp.Release(s, c)
	}
	if a1 := slotAddrs(cp, 1); err == nil && a == r1 || strings.Join(a1, ",") == r1 {
		t.Fatalf("slot 1 refilled under the list [R2, R1] with R1 held by slot 0: handed %q (slot %d, %v), slot 1 dials %v — want R2", a, s, err, a1)
	}
	for _, c := range held {
		cp.Release(0, c)
	}
}

func TestCookieModeARelayDroppedFromTheListKeepsItsLeasesSeats(t *testing.T) {
	var answer atomic.Value
	answer.Store([]string{ipR1, ipR2})
	cp := cookieNamePool(t, 20, &answer)
	r1, r2, r3 := ipR1+":19302", ipR2+":19302", ipR3+":19302"
	// Slot 0 full (ten on R1), slot 1 on R2 — then seven of the ten end:
	// three leases live on R1.
	var held []*TURNCreds
	for conn := 0; conn < 10; conn++ {
		addr, creds, slot, err := cp.Acquire(conn)
		if err != nil || addr != r1 || slot != 0 {
			t.Fatalf("conn %d: %q slot %d %v — want slot 0 on %s", conn, addr, slot, err, r1)
		}
		held = append(held, creds)
	}
	if addr, creds, slot, err := cp.Acquire(10); err != nil || addr != r2 || slot != 1 {
		t.Fatalf("conn 10: %q slot %d %v — want slot 1 on %s", addr, slot, err, r2)
	} else {
		cp.Release(slot, creds)
	}
	for _, c := range held[3:] {
		cp.Release(0, c)
	}
	held = held[:3]
	// DNS drops R1 and adds R3; the path change has the list resolved again.
	answer.Store([]string{ipR2, ipR3})
	cp.OnPathChange()
	waitForList(t, cp, r2, r3)
	if a0, a1 := slotAddrs(cp, 0), slotAddrs(cp, 1); strings.Join(a0, ",") != r1 || strings.Join(a1, ",") != r2 {
		t.Fatalf("R1 dropped with three leases live on it: slot 0 dials %v, slot 1 %v — want slot 0 kept on %s, slot 1 on %s", a0, a1, r1, r2)
	}
	cp.cp.mu.Lock()
	off, usable := cp.cp.configuredOffLocked(0), cp.cp.usableLocked(0)
	cp.cp.mu.Unlock()
	if !off || usable {
		t.Fatalf("slot 0 on a relay the list dropped: configured off %v, usable %v — want off, not usable (its seats are R1's; the list no longer names R1)", off, usable)
	}
	// A connection whose own slot is 0 is seated elsewhere, never on R1 —
	// after the pool's post-path-change pause.
	deadline := time.Now().Add(3 * time.Second)
	for {
		addr, creds, slot, err := cp.Acquire(0)
		if err == nil {
			cp.Release(slot, creds)
			if addr == r1 || slot == 0 {
				t.Fatalf("conn 0 after R1 left the list: %q on slot %d — want another slot, not R1", addr, slot)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("conn 0 after the path change: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The leases end: R1's clock moves (not R3's), and slot 0 takes the free
	// entry R3 at the release that frees the last seat.
	before := time.Now()
	for i, c := range held {
		cp.Release(0, c)
		if i < len(held)-1 {
			if a0 := slotAddrs(cp, 0); strings.Join(a0, ",") != r1 {
				t.Fatalf("after %d of 3 releases slot 0 dials %v — want still %s (leases live)", i+1, a0, r1)
			}
		}
	}
	cp.cp.mu.Lock()
	a0 := append([]string(nil), cp.cp.pool[0].addrs...)
	usedR1, usedR3 := cp.cp.relayUsedAt[r1], cp.cp.relayUsedAt[r3]
	cp.cp.mu.Unlock()
	if strings.Join(a0, ",") != r3 {
		t.Fatalf("after the last release slot 0 dials %v — want the list's free entry %s", a0, r3)
	}
	if usedR1.Before(before) || !usedR3.IsZero() {
		t.Fatalf("the quota clock after the leases on R1 ended: R1 %v, R3 %v — want R1 stamped now, R3 untouched", usedR1, usedR3)
	}
}

func TestCookieModeTheMintUnderAListTakesTheEntryNotHeld(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieMu.Unlock()
	ctx := context.Background()
	list := []string{relayE, relayF}
	// Slot 1 asks while slot 0 holds the list's SECOND entry (the list came
	// back in another order): the first, not a twin.
	if c, err := cookieCredForSlot(ctx, 1, list, []string{relayF}); err != nil || c.Address != relayE {
		t.Fatalf("slot 1 under [E, F] with F held by another slot: %+v %v — want E", c, err)
	}
	// Its own entry free: its own, as before.
	if c, err := cookieCredForSlot(ctx, 1, list, []string{relayE}); err != nil || c.Address != relayF {
		t.Fatalf("slot 1 under [E, F] with E held: %+v %v — want F", c, err)
	}
	// Every entry held: unfilled, and the message says why.
	if _, err := cookieCredForSlot(ctx, 0, list, []string{relayE, relayF}); err == nil || !strings.Contains(err.Error(), "unfilled") || !strings.Contains(err.Error(), "held") {
		t.Fatalf("slot 0 with every entry held: %v — want the shortage refused, naming the held entries", err)
	}
	// Beyond the list: unfilled whatever is free.
	if _, err := cookieCredForSlot(ctx, 2, list, nil); err == nil || !strings.Contains(err.Error(), "unfilled") {
		t.Fatalf("slot 2 under a two-entry list: %v — want the shortage refused", err)
	}
}

func TestTheReResolutionBypassesTheAppsBootstrapMap(t *testing.T) {
	old := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = old })
	var lookups atomic.Int32
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP(ipR2)}, nil
	}
	SetVKHostIPs(map[string][]string{nameHost: {ipR1}})
	t.Cleanup(func() { SetVKHostIPs(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 2, TurnServers: []string{nameRelay},
		Fetch: func(_ bool, slot int) (string, *TURNCreds, error) {
			return relayA, &TURNCreds{Username: futureUser("vk"), Password: "p", Address: relayA, Addresses: []string{relayA}}, nil
		}})
	defer cp.Close()
	// The start takes the app's map (resolved on the app's side, #105).
	if got := cp.cp.overrideServers(); strings.Join(got, ",") != ipR1+":19302" || lookups.Load() != 0 {
		t.Fatalf("at start: list %v, lookups %d — want the app's map used, no lookup", got, lookups.Load())
	}
	// The re-resolution asks DNS: the map is the start's snapshot.
	cp.OnPathChange()
	waitForList(t, cp, ipR2+":19302")
	if lookups.Load() == 0 {
		t.Fatal("the re-resolution made no lookup")
	}
}

// The list arrives after the cache was read (NewCredPool: load, then
// setOverride): a stored address that is a list entry at another index than
// its slot's keeps it — and the slot whose index that entry is takes a free
// one, not a twin.
func TestCookieModeTheListArrivingAfterTheLoadMakesNoTwins(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 0, Address: relayO, Addresses: []string{relayO}, Username: futureUser("s0-on-the-lists-second"), Password: "p"},
		credCacheEntry{Slot: 1, Address: relayA, Addresses: []string{relayA}, Username: futureUser("s1-off-the-list"), Password: "p"},
		credCacheEntry{Slot: 2, Address: relayB, Addresses: []string{relayB}, Username: futureUser("s2-off-the-list"), Password: "p"},
	)
	cp, _, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayE, relayO}})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	c0, c1, c2 := cp.candidatesLocked(0), cp.candidatesLocked(1), cp.candidatesLocked(2)
	if strings.Join(c0, ",") != relayO || strings.Join(c1, ",") != relayE || len(c2) != 0 {
		t.Fatalf("the list [E, O] over a cache with slot 0 on O: slot 0 dials %v, slot 1 %v, slot 2 %v — want O, E (not O: a twin) and nothing (beyond the list)", c0, c1, c2)
	}
}

// The user's review of 455, two findings.
//
// (1) A mint begun before the list changed: the minter picked B from [A, B];
// before the result was placed the list became [C, A]. Slot 0 (ten leases)
// stayed on A — but the credential for B, no longer in the list, was placed
// by INDEX: servers[1] == A, an eleventh seat on A. The placement asks the
// CURRENT list and the relays the other slots hold, under the pool's lock:
// its own relay when the list names it and no slot holds it, else a free
// entry, else nothing.
func TestCookieModeAMintPlacedAfterTheListChangedAsksTheListAgain(t *testing.T) {
	var answer atomic.Value
	answer.Store([]string{ipR1, ipR2})
	cp := cookieNamePool(t, 20, &answer)
	r1, r2, r3 := ipR1+":19302", ipR2+":19302", ipR3+":19302"
	var held []*TURNCreds
	for conn := 0; conn < 10; conn++ {
		addr, creds, slot, err := cp.Acquire(conn)
		if err != nil || addr != r1 || slot != 0 {
			t.Fatalf("conn %d: %q slot %d %v — want slot 0 on %s", conn, addr, slot, err, r1)
		}
		held = append(held, creds)
	}
	// The mint for slot 1 is in flight with R2; the list becomes [R3, R1].
	minted := &TURNCreds{Username: futureUser("in-flight"), Password: "p", Address: r2, Addresses: []string{r2}}
	answer.Store([]string{ipR3, ipR1})
	cp.OnPathChange()
	waitForList(t, cp, r3, r1)
	cp.cp.mu.Lock()
	got := cp.cp.candidatesForSlot(1, minted)
	cp.cp.mu.Unlock()
	if strings.Join(got, ",") != r3 {
		t.Fatalf("a credential minted for %s placed into slot 1 under the list [R3, R1] with R1 held by slot 0: dials %v — want the free entry %s, never R1 (an eleventh seat)", r2, got, r3)
	}
	// A credential minted for R1 itself (two mints in flight took one entry):
	// R1 is slot 0's — the free entry, not a twin.
	cp.cp.mu.Lock()
	got = cp.cp.candidatesForSlot(1, &TURNCreds{Username: futureUser("twin"), Password: "p", Address: r1, Addresses: []string{r1}})
	cp.cp.mu.Unlock()
	if strings.Join(got, ",") != r3 {
		t.Fatalf("a credential minted for R1 placed into slot 1 while slot 0 dials R1: dials %v — want the free entry %s", got, r3)
	}
	// The minter reserved R2 for slot 1; the placement put the slot on R3 —
	// the reservation follows, or R2, back in the list later, is refused to
	// the slot that could take it ("every one held").
	cookieAssignMu.Lock()
	cookieRelayAssigned[1] = r2
	cookieAssignMu.Unlock()
	cp.cp.mu.Lock()
	cp.cp.placeLocked(1, credPoolEntry{addr: r2, addrs: cp.cp.candidatesForSlot(1, minted), creds: minted, ts: time.Now()})
	cp.cp.mu.Unlock()
	cookieAssignMu.Lock()
	reserved := cookieRelayAssigned[1]
	cookieAssignMu.Unlock()
	if reserved != r3 {
		t.Fatalf("the minter's reservation for slot 1 after the placement on %s: %q — want %s", r3, reserved, r3)
	}
	if c, err := cookieCredForSlot(context.Background(), 2, []string{r2, r3, r1}, []string{r3, r1}); err != nil || c.Address != r2 {
		t.Fatalf("the minter for slot 2 under [R2, R3, R1] with R3 and R1 held: %+v %v — want R2 (slot 1 dials R3, its old reservation of R2 must not stand)", c, err)
	}
	for _, c := range held {
		cp.Release(0, c)
	}
}

// (2) The list shrinks [A, B] → [B] with both slots filled and no leases:
// slot 0 found B still slot 1's while slot 1 was not yet switched off as
// beyond the list — both slots ended without a relay, B idle, and the
// minter's reservation of B for slot 1 refused the next mint ("every one
// held"). The re-binding frees first, then assigns; a reservation held by a
// slot beyond the list reserves nothing.
func TestCookieModeAShrunkListHandsTheFreedEntryOn(t *testing.T) {
	var answer atomic.Value
	answer.Store([]string{ipR1, ipR2})
	cp := cookieNamePool(t, 20, &answer)
	r1, r2 := ipR1+":19302", ipR2+":19302"
	// Slot 0 full for a moment so that conn 10 fills slot 1; then every
	// lease ends.
	var held []*TURNCreds
	for conn := 0; conn < 10; conn++ {
		addr, creds, slot, err := cp.Acquire(conn)
		if err != nil || addr != r1 || slot != 0 {
			t.Fatalf("conn %d: %q slot %d %v — want slot 0 on %s", conn, addr, slot, err, r1)
		}
		held = append(held, creds)
	}
	if addr, creds, slot, err := cp.Acquire(10); err != nil || addr != r2 || slot != 1 {
		t.Fatalf("conn 10: %q slot %d %v — want slot 1 on %s", addr, slot, err, r2)
	} else {
		cp.Release(slot, creds)
	}
	for _, c := range held {
		cp.Release(0, c)
	}
	answer.Store([]string{ipR2})
	cp.OnPathChange()
	waitForList(t, cp, r2)
	if a0, a1 := slotAddrs(cp, 0), slotAddrs(cp, 1); strings.Join(a0, ",") != r2 || len(a1) != 0 {
		t.Fatalf("the list shrunk to [R2]: slot 0 dials %v, slot 1 %v — want slot 0 on the freed %s, slot 1 (beyond the list) nothing", a0, a1, r2)
	}
	// The minter, asked for slot 0 with nothing held: R2 — slot 1's old
	// reservation (set here as the minter left it) is a slot beyond the list.
	cookieAssignMu.Lock()
	cookieRelayAssigned[1] = r2
	cookieAssignMu.Unlock()
	if c, err := cookieCredForSlot(context.Background(), 0, []string{r2}, nil); err != nil || c.Address != r2 {
		t.Fatalf("the minter for slot 0 under [R2] with nothing held: %+v %v — want R2 (slot 1's reservation is beyond the list)", c, err)
	}
	// And the pool hands R2 out — on slot 0 — once R2's quota clock (slot 1's
	// lease on it ended a moment ago: the relay's cooldown) has run out.
	cp.cp.mu.Lock()
	cp.cp.relayUsedAt[r2] = time.Now().Add(-2 * credSaturationCooldown)
	cp.cp.applyRelayQuarantineLocked(0)
	cp.cp.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for {
		addr, creds, slot, err := cp.Acquire(0)
		if err == nil {
			cp.Release(slot, creds)
			if addr != r2 || slot != 0 {
				t.Fatalf("conn 0 after the shrink: %q on slot %d — want %s on slot 0", addr, slot, r2)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("conn 0 after the shrink: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The list arriving after the load: a loaded slot BEYOND the list whose
// stored address is a list entry must not keep that entry from the slot
// whose index it is (the entry would sit idle).
func TestCookieModeTheListArrivingAfterTheLoadLeavesNoEntryIdle(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA}, Username: futureUser("s0"), Password: "p"},
		credCacheEntry{Slot: 1, Address: relayB, Addresses: []string{relayB}, Username: futureUser("s1"), Password: "p"},
		credCacheEntry{Slot: 3, Address: relayO, Addresses: []string{relayO}, Username: futureUser("s3-on-the-lists-second"), Password: "p"},
	)
	cp, _, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayE, relayO}})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	c0, c1, c3 := cp.candidatesLocked(0), cp.candidatesLocked(1), cp.candidatesLocked(3)
	if strings.Join(c0, ",") != relayE || strings.Join(c1, ",") != relayO || len(c3) != 0 {
		t.Fatalf("the list [E, O] over a cache with slot 3 (beyond) on O: slot 0 dials %v, slot 1 %v, slot 3 %v — want E, O and nothing", c0, c1, c3)
	}
}

// The user's review of 456: the minter holds cookieMu across its HTTP mint
// (up to the fetch's 30 s), and the pool's placement — under cp.mu — told
// the minter where the slot now dials by taking cookieMu: one slow mint held
// the whole pool (Stats, releases, the hand-out of a READY slot waited for
// the HTTP request). The reservations have a mutex of their own, never held
// across I/O; the pool's sync takes that one.
func TestAPlacementDoesNotWaitForTheMintersHTTPRequest(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 4, 2*time.Minute, "", nil)
	cp.setOverride(turnOverride{servers: []string{relayE, relayF}})
	// A mint in flight: cookieMu held for the length of its HTTP request.
	cookieMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c := &TURNCreds{Username: futureUser("ready"), Password: "p", Address: relayE, Addresses: []string{relayE}}
		cp.mu.Lock()
		cp.placeLocked(0, credPoolEntry{addr: relayE, addrs: cp.candidatesForSlot(0, c), creds: c, ts: time.Now()})
		cp.mu.Unlock()
		cp.heldRelaysExcept(1) // another look under cp.mu
	}()
	waited := false
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		waited = true
	}
	cookieMu.Unlock()
	<-done
	if waited {
		t.Fatal("a placement under cp.mu waited for the minter's HTTP request (cookieMu held): the whole pool is held for up to 30 s")
	}
	// The reservation was recorded all the same.
	cookieAssignMu.Lock()
	got := cookieRelayAssigned[0]
	cookieAssignMu.Unlock()
	if got != relayE {
		t.Fatalf("the minter's reservation for slot 0 after the placement: %q, want %s", got, relayE)
	}
}
