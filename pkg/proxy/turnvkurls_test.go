// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Issue #105 (2), 2026-10-29: the TURN override list may name VK's own
// relays — the addresses the credential came with — by the word `$vkurls`,
// in place: `myrelay.example:19302,$vkurls` dials the user's relay while it
// answers and VK's when it does not (the issue's scheme, without the VK
// addresses typed by hand, which change). `$vkurls` alone is no override.

func TestParseTURNServersAcceptsTheVKPlaceholder(t *testing.T) {
	got, err := ParseTURNServers("myrelay.example:19302, $VKurls,$vkurls")
	if err != nil || strings.Join(got, ",") != "myrelay.example:19302,"+TURNServersVK {
		t.Fatalf("%v %v — want the relay and ONE $vkurls (case folded, deduplicated)", got, err)
	}
	if got, err := ParseTURNServers("$vkurls"); err != nil || len(got) != 1 || got[0] != TURNServersVK {
		t.Fatalf("$vkurls alone: %v %v", got, err)
	}
	if _, err := ParseTURNServers("$vkurl"); err == nil {
		t.Fatal("$vkurl (a misspelling) accepted — it is neither host:port nor the word")
	}
}

func TestTheVKPlaceholderExpandsToTheCredentialsRelays(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO, TURNServersVK}})
	if c := cp.candidatesLocked(0); strings.Join(c, ",") != strings.Join([]string{relayO, relayA, relayB}, ",") {
		t.Fatalf("[O, $vkurls] over a credential with [A, B]: candidates %v — want O then A, B", c)
	}
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO {
		t.Fatalf("the first hand-out: %q, want the user's relay first", addr)
	}
	// The user's relay silent with evidence → marked → VK's next, no mint.
	cp.release(slot, creds)
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, slot, creds, relayO, time.Now())
	if addr, _, _ := mustGet(t, cp, 1); addr != relayA || mints.Load() != 0 {
		t.Fatalf("after the user's relay is marked: %q (mints %d) — want VK's first relay, no mint", addr, mints.Load())
	}
	// `$vkurls` alone is no override at all.
	cp.setOverride(turnOverride{servers: []string{TURNServersVK}})
	cp.mu.Lock()
	set, c := cp.override.set(), cp.candidatesLocked(0)
	cp.mu.Unlock()
	if set || strings.Join(c, ",") != relayA+","+relayB {
		t.Fatalf("$vkurls alone: override set %v, candidates %v — want no override, VK's addresses", set, c)
	}
}

// With the list fixed, every relay marked means a mint names the same list —
// the connections wait. With `$vkurls` in it a fresh credential may come with
// other VK relays: the pool mints, as without an override.
func TestWithTheVKPlaceholderAnExhaustedListMints(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO, TURNServersVK}})
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO {
		t.Fatalf("precondition: %q", addr)
	}
	cp.release(slot, creds)
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, slot, creds, relayO, time.Now())
	cp.noteRelayUnanswered(0, slot, creds, relayA, time.Now())
	addr, _, _, err := cp.get(1, false)
	if err != nil || mints.Load() != 1 || addr != relayC {
		t.Fatalf("every relay of [O, $vkurls] marked: addr %q err %v mints %d — want a mint and its relay handed out (the list is not fixed)", addr, err, mints.Load())
	}
}

func TestResolveTURNServersKeepsTheVKPlaceholder(t *testing.T) {
	pre := func(host string) []string {
		if host == nameHost {
			return []string{ipR1}
		}
		return nil
	}
	got := ResolveTURNServers(context.Background(), []string{nameRelay, TURNServersVK}, pre)
	if strings.Join(got, ",") != ipR1+":19302,"+TURNServersVK {
		t.Fatalf("resolved: %v — want the name's IP and the word kept in place", got)
	}
	if !allIPs(got) {
		t.Fatal("a resolved list with $vkurls counted as a failed resolution")
	}
	if (turnOverride{raw: []string{TURNServersVK}}).hasName() {
		t.Fatal("$vkurls taken for a DNS name")
	}
}

// Cookie mode: a slot IS a relay. The fixed entries before `$vkurls` take
// the slots 0..m-1; `$vkurls` takes every slot from m on — VK's distinct
// relays, as without a list; entries after it are not used.
func TestCookieModeATrailingVKPlaceholderTakesTheRemainingSlots(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieCache[cookieLinkID(links[1])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link2"), Password: "p", Address: relayC, Addresses: []string{relayC, relayD}}}
	cookieMu.Unlock()
	ctx := context.Background()
	list := []string{relayO, TURNServersVK}
	for slot, want := range []string{relayO, relayA, relayB, relayC, relayD} {
		c, err := cookieCredForSlot(ctx, slot, list, nil, nil)
		if err != nil || c.Address != want {
			t.Fatalf("slot %d under [O, $vkurls]: %+v %v — want %s", slot, c, err, want)
		}
	}
	if _, err := cookieCredForSlot(ctx, 5, list, nil, nil); err == nil || !strings.Contains(err.Error(), "unfilled") {
		t.Fatalf("slot 5 with four VK relays found: %v — want the shortage refused", err)
	}
	// A VK slot never takes a relay another slot holds (the reservations of
	// the slots above, from the loop, let go first — they are not the case).
	for s := 1; s <= 4; s++ {
		cookieNoteSlotRelay(s, "")
	}
	if c, err := cookieCredForSlot(ctx, 1, list, []string{relayA}, nil); err != nil || c.Address != relayB {
		t.Fatalf("slot 1 with A held elsewhere: %+v %v — want B", c, err)
	}
	// The pool: slot 0 is the fixed entry's, slot 1 and 5 are VK slots on the
	// credential's own relay, switched on; an entry after `$vkurls` is unused.
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx2, 6, 2*time.Minute, "", nil)
	cp.setOverride(turnOverride{servers: []string{relayO, TURNServersVK, relayF}})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	credA := &TURNCreds{Username: futureUser("a"), Password: "p", Address: relayA, Addresses: []string{relayA}}
	credB := &TURNCreds{Username: futureUser("b"), Password: "p", Address: relayB, Addresses: []string{relayB}}
	if c := cp.candidatesForSlot(0, credA); strings.Join(c, ",") != relayO {
		t.Fatalf("slot 0 (fixed) with a VK credential: %v, want the fixed entry %s", c, relayO)
	}
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: []string{relayO}, creds: &TURNCreds{Username: futureUser("o"), Password: "p", Address: relayO, Addresses: []string{relayO}}, ts: time.Now()})
	if c := cp.candidatesForSlot(1, credA); strings.Join(c, ",") != relayA {
		t.Fatalf("slot 1 (a VK slot) with the credential for A: %v, want A (not %s, the entry after $vkurls)", c, relayF)
	}
	cp.placeLocked(1, credPoolEntry{addr: relayA, addrs: cp.candidatesForSlot(1, credA), creds: credA, ts: time.Now()})
	if c := cp.candidatesForSlot(5, credB); strings.Join(c, ",") != relayB {
		t.Fatalf("slot 5 (a VK slot beyond the fixed entries): %v, want B", c)
	}
	cp.placeLocked(5, credPoolEntry{addr: relayB, addrs: cp.candidatesForSlot(5, credB), creds: credB, ts: time.Now()})
	if cp.configuredOffLocked(1) || cp.configuredOffLocked(5) || !cp.usableLocked(5) {
		t.Fatalf("VK slots switched off: slot 1 off %v, slot 5 off %v usable %v", cp.configuredOffLocked(1), cp.configuredOffLocked(5), cp.usableLocked(5))
	}
	// A twin of slot 1's relay is not placed on it.
	if c := cp.candidatesForSlot(2, credA); len(c) != 0 {
		t.Fatalf("slot 2 with the relay slot 1 dials: %v, want nothing", c)
	}
	// Beyond the fixed entries WITHOUT the word: off, as before.
	cp.override.servers = []string{relayO}
	if !cp.configuredOffLocked(5) {
		t.Fatal("slot 5 beyond a one-entry list without $vkurls is not off")
	}
}

// A credential whose every relay went silent (no evidence, no mark) is cycled
// again under a FIXED list — there is nothing else to mint for. With `$vkurls`
// in the list a mint may bring other VK relays: the pool mints, as without an
// override (TestASilentOnlyCandidateMakesThePoolMint).
func TestWithTheVKPlaceholderASilentOnlyCredentialMints(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO, TURNServersVK}})
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO || mints.Load() != 0 {
		t.Fatalf("precondition: %q mints %d", addr, mints.Load())
	}
	cp.release(slot, creds)
	cp.noteRelayUnanswered(0, slot, creds, relayO, time.Now().Add(-5*time.Second))
	cp.noteRelayUnanswered(0, slot, creds, relayA, time.Now().Add(-5*time.Second))
	if cp.health.isDead(relayO) || cp.health.isDead(relayA) {
		t.Fatal("marked with no evidence")
	}
	if _, creds2, _ := mustGet(t, cp, 0); mints.Load() != 1 || creds2.Username == creds.Username {
		t.Fatalf("every relay of [O, $vkurls] silent: mints %d, user %q — want one fresh mint, not the silent relays again", mints.Load(), creds2.Username)
	}
}
