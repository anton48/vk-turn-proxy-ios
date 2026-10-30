// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func goFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 2026-10-30, the user's design after the $vkurls runs: an entry of the TURN
// override list may carry a third field, host:port:quota — the relay's limit
// of allocations per identity. 0 means the relay has no quota: the slot on
// it takes every connection (both modes), it has no quota clock and no
// smart-pause, and while it answers every connection is seated on it;
// `addr.example:1234:0,$vkurls` runs everything through the user's relay and
// moves to VK's when it stops answering. N > 0 is that limit (10 is VK's).

func TestParseTURNServersAcceptsAQuota(t *testing.T) {
	got, err := ParseTURNServers("relay.example:19302:0, 203.0.113.5:3478:25,$vkurls, 203.0.113.5:3478:7")
	if err != nil || strings.Join(got, ",") != "relay.example:19302:0,203.0.113.5:3478:25,"+TURNServersVK {
		t.Fatalf("%v %v — want the quotas kept, the second spelling of one address dropped", got, err)
	}
	for _, tc := range []struct {
		entry, addr string
		quota       int
		has         bool
	}{
		{"relay.example:19302:0", "relay.example:19302", 0, true},
		{"203.0.113.5:3478:25", "203.0.113.5:3478", 25, true},
		{"203.0.113.5:3478", "203.0.113.5:3478", 0, false},
		{"[2001:db8::1]:19302:3", "[2001:db8::1]:19302", 3, true},
	} {
		addr, quota, has, ok := splitTURNEntry(tc.entry)
		if !ok || addr != tc.addr || quota != tc.quota || has != tc.has {
			t.Fatalf("%q → %q %d %v %v, want %q %d %v", tc.entry, addr, quota, has, ok, tc.addr, tc.quota, tc.has)
		}
	}
	for _, bad := range []string{"relay.example:19302:x", "relay.example:19302:-1", "relay.example:19302:", "relay.example:19302:1:2"} {
		if _, err := ParseTURNServers(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestResolveTURNServersKeepsTheQuota(t *testing.T) {
	pre := func(host string) []string {
		if host == nameHost {
			return []string{ipR1, ipR2}
		}
		return nil
	}
	got := ResolveTURNServers(context.Background(), []string{nameRelay + ":0", "203.0.113.5:3478:25"}, pre)
	if strings.Join(got, ",") != ipR1+":19302:0,"+ipR2+":19302:0,203.0.113.5:3478:25" {
		t.Fatalf("resolved: %v — want the name's IPs each with the name's quota", got)
	}
	if !allIPs(got) || !(turnOverride{raw: []string{nameRelay + ":0"}}).hasName() {
		t.Fatal("a quota suffix confused allIPs or hasName")
	}
	o := turnOverride{}
	o.setServers(got)
	if q, ok := o.quota(ipR1 + ":19302"); !ok || q != 0 {
		t.Fatalf("the quota of the first IP: %d %v, want 0", q, ok)
	}
	if q, ok := o.quota("203.0.113.5:3478"); !ok || q != 25 {
		t.Fatalf("the quota of the second entry: %d %v, want 25", q, ok)
	}
	if c := o.candidatesFor(&TURNCreds{Addresses: []string{relayA}}); strings.Join(c, ",") != ipR1+":19302,"+ipR2+":19302,203.0.113.5:3478" {
		t.Fatalf("the candidates carry no quota suffix: %v", c)
	}
}

// Anonymous mode: with the list `O:0,$vkurls` every connection is seated on
// the credential dialling O — the slot's cap is the relay's — and once O is
// marked the cap is VK's ten again: the next ask does not pile onto it.
func TestAnUnlimitedRelayTakesEveryConnection(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	list, err := ParseTURNServers(relayO + ":0," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	var held []*TURNCreds
	for conn := 0; conn < 40; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relayO || slot != 0 {
			t.Fatalf("conn %d: %q on slot %d — want every connection on slot 0's %s (no quota)", conn, addr, slot, relayO)
		}
		held = append(held, creds)
	}
	if mints.Load() != 0 || cp.pool[0].active != 40 {
		t.Fatalf("mints %d, slot 0 active %d — want no mint, forty seats on the one credential", mints.Load(), cp.pool[0].active)
	}
	// A connection whose attempt on O went silent without evidence (its
	// cursor moved on) is handed O again, not VK's next: the relay without a
	// quota takes everyone while it is not marked.
	cp.release(0, held[1])
	cp.noteRelayUnanswered(1, 0, held[1], relayO, time.Now().Add(-5*time.Second))
	if addr, creds, slot := mustGet(t, cp, 1); addr != relayO || slot != 0 {
		t.Fatalf("conn 1 after a silent attempt on O: %q on slot %d — want O again", addr, slot)
	} else {
		held[1] = creds
	}
	cp.mu.Lock()
	cap0 := cp.capLocked(0)
	cp.mu.Unlock()
	if cap0 <= 40 {
		t.Fatalf("slot 0's cap on an unlimited relay: %d", cap0)
	}
	// O silent with evidence → marked: the slot's cap is VK's ten on the VK
	// relays left — the next ask is a mint, not a forty-first on A.
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, 0, held[0], relayO, time.Now())
	cp.mu.Lock()
	cap0 = cp.capLocked(0)
	cp.mu.Unlock()
	if cap0 != connsPerSlot {
		t.Fatalf("slot 0's cap after O is marked: %d, want %d", cap0, connsPerSlot)
	}
	if _, _, slot := mustGet(t, cp, 40); slot == 0 || mints.Load() != 1 {
		t.Fatalf("conn 40 after O is marked: slot %d, mints %d — want another slot, one mint", slot, mints.Load())
	}
}

// Cookie mode: the slot on a relay without a quota has no quota clock, no
// smart-pause, an open cap, and takes every connection first.
func TestCookieModeAnUnlimitedRelayHasNoQuotaClock(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 4, 2*time.Minute, "", nil)
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp.setOverride(turnOverride{servers: list})
	cp.mu.Lock()
	own := &TURNCreds{Username: futureUser("own"), Password: "p", Address: relayO, Addresses: []string{relayO}}
	cp.relayUsedAt[relayO] = time.Now()
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp.candidatesForSlot(0, own), creds: own, ts: time.Now(), lastUsedAt: time.Now().Add(-time.Minute)})
	vk := &TURNCreds{Username: futureUser("vk"), Password: "p", Address: relayA, Addresses: []string{relayA}}
	cp.placeLocked(1, credPoolEntry{addr: relayA, addrs: cp.candidatesForSlot(1, vk), creds: vk, ts: time.Now()})
	until, avail, cap0 := cp.relayQuarantineUntilLocked(relayO), cp.pool[0].availableAt, cp.capLocked(0)
	cp.mu.Unlock()
	if !until.IsZero() || !avail.IsZero() || cap0 <= connsPerSlot {
		t.Fatalf("slot 0 on %s (no quota): quarantine until %v, availableAt %v, cap %d — want no clock, ready, an open cap", relayO, until, avail, cap0)
	}
	// A path change: no smart-pause for the slot without a quota.
	cp.MarkInUseSlotsForPathChange()
	cp.mu.Lock()
	sat := cp.pool[0].saturatedUntil
	cp.pauseAcquireUntil = time.Time{}
	cp.mu.Unlock()
	if !sat.IsZero() {
		t.Fatalf("slot 0 smart-paused until %v — a relay without a quota holds no seats", sat)
	}
	// Conn 15 (own slot 1) is seated on slot 0 all the same: the relay
	// without a quota takes everyone while it answers.
	for conn := 0; conn < 25; conn++ {
		if addr, _, slot := mustGet(t, cp, conn); slot != 0 || addr != relayO {
			t.Fatalf("conn %d: %q on slot %d — want slot 0's %s", conn, addr, slot, relayO)
		}
	}
}

// (A) The smart-pause (MarkInUseSlotsForPathChange) marks a slot by its
// entry's lastUsedAt — the history of the relay the slot HELD. A loaded slot
// re-pointed by the list to a relay never used was marked six minutes for
// its old relay's seats (the user's run 6: slot 1 moved to the second fixed
// entry, then the path event at the start marked it; the bootstrap timed
// out). The history goes with the relay (the relay clock has it already): a
// slot whose relay changes starts with no history and no mark.
func TestCookieModeASmartPauseMarkDoesNotFollowTheSlotToAnotherRelay(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA}, Username: futureUser("s0"), Password: "p"},
		credCacheEntry{Slot: 1, Address: relayB, Addresses: []string{relayB}, Username: futureUser("s1"), Password: "p", LastUsedAt: time.Now().Add(-4 * time.Minute).Unix()},
	)
	cp, _, _ := relayPool(t, path, relayC)
	// The list re-points slot 1 to F, never used; then the path event.
	cp.setOverride(turnOverride{servers: []string{relayE, relayF}})
	cp.MarkInUseSlotsForPathChange()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.pauseAcquireUntil = time.Time{}
	if c := cp.candidatesLocked(1); strings.Join(c, ",") != relayF {
		t.Fatalf("slot 1 under [E, F]: %v", c)
	}
	if !cp.pool[1].saturatedUntil.IsZero() || !cp.pool[1].lastUsedAt.IsZero() {
		t.Fatalf("slot 1 re-pointed to %s: smart-paused until %v, lastUsedAt %v — the history was %s's", relayF, cp.pool[1].saturatedUntil, cp.pool[1].lastUsedAt, relayB)
	}
	// Slot 0, still on the list's first entry by index, keeps nothing either
	// (A was its relay; E is new) — and a slot whose relay stays keeps its mark.
	if !cp.pool[0].lastUsedAt.IsZero() {
		t.Fatalf("slot 0 re-pointed to %s keeps lastUsedAt %v", relayE, cp.pool[0].lastUsedAt)
	}
}

// (B) The minter's discovery is told which VK relays sit in the pool's
// quota quarantine: another distinct relay is preferred; one in quarantine
// is taken only when nothing else is free (the user's runs 6–7: a fresh
// mint onto a relay used minutes ago parked for the rest of the window).
func TestCookieModeTheMintForAVKSlotAvoidsARelayInQuarantine(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieCache[cookieLinkID(links[1])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link2"), Password: "p", Address: relayC, Addresses: []string{relayC, relayD}}}
	cookieMu.Unlock()
	ctx := context.Background()
	if c, err := cookieCredForSlot(ctx, 0, nil, nil, []string{relayA}); err != nil || c.Address != relayB {
		t.Fatalf("slot 0 with A in quarantine: %+v %v — want B", c, err)
	}
	cookieNoteSlotRelay(0, "")
	if c, err := cookieCredForSlot(ctx, 0, nil, nil, []string{relayA, relayB, relayC, relayD}); err != nil || c.Address != relayA {
		t.Fatalf("slot 0 with every relay in quarantine: %+v %v — want A all the same (nothing else is free)", c, err)
	}
	// The pool names its quarantined relays, and both fetch closures pass them.
	cookieTestMode(t)
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx2, 4, 2*time.Minute, "", nil)
	cp.mu.Lock()
	cp.relayUsedAt[relayA] = time.Now()
	cp.relayUsedAt[relayB] = time.Now().Add(-2 * credSaturationCooldown)
	cp.mu.Unlock()
	if q := cp.quarantinedRelays(); strings.Join(q, ",") != relayA {
		t.Fatalf("quarantined relays: %v, want [%s] (B's window is over)", q, relayA)
	}
	for _, f := range []string{"credpool.go", "proxy.go"} {
		if !strings.Contains(goFile(t, f), ".heldRelaysExcept(slot), ") || !strings.Contains(goFile(t, f), ".quarantinedRelays())") {
			t.Fatalf("%s: the pool's cookie fetch does not tell cookieCredForSlot the quarantined relays", f)
		}
	}
}
