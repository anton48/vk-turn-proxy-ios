package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cookie mode (2026-10-20, the user's runs 7–10 on build 448): every
// credential carries ONE okcdn user id, so the relay's quota of ten is shared
// by every slot that names that relay — a slot IS a relay. Two slots on one
// relay are one quota: the second drew 486 in the field (run 9, slot 8).

const (
	relayE = "203.0.113.15:19302"
	relayF = "203.0.113.16:19302"
	relayG = "203.0.113.17:19302"
)

func cookieTestMode(t *testing.T, links ...string) {
	t.Helper()
	if len(links) == 0 {
		links = []string{"https://vk.ru/call/join/abcdef"}
	}
	SetVKCookieAuth(true, "remixsid=x", links)
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
}

func writeCookieCache(t *testing.T, dir string, entries ...credCacheEntry) string {
	t.Helper()
	path := filepath.Join(dir, "creds-pool.json")
	b, _ := json.Marshal(credCacheFile{Version: credCacheVersion, SavedAt: time.Now().Unix(), Mode: credCacheModeCookie, Creds: entries})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func userExpiring(in time.Duration, tag string) string {
	return fmt.Sprintf("%d:%s", time.Now().Add(in).Unix(), tag)
}

// (1) At load, two slots whose relay coincides are one: the fresher
// credential stays, the other is skipped (run 8's backup: slots 2 and 8 both
// on one relay, slots 0 and 4 on another).
func TestCookieModeTwoSlotsOnOneRelayAreOneAtLoad(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 2, Address: relayA, Addresses: []string{relayA}, Username: userExpiring(7*time.Hour, "older-on-A"), Password: "p"},
		credCacheEntry{Slot: 5, Address: relayB, Addresses: []string{relayB}, Username: userExpiring(7*time.Hour, "on-B"), Password: "p"},
		credCacheEntry{Slot: 8, Address: relayA, Addresses: []string{relayA}, Username: userExpiring(8*time.Hour, "fresher-on-A"), Password: "p"},
	)
	cp, _, _ := relayPool(t, path, relayC)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.pool[2].creds != nil {
		t.Fatalf("slot 2 (the older credential on A) kept beside slot 8 on the same relay: two slots, one quota")
	}
	if cp.pool[8].creds == nil || !strings.HasSuffix(cp.pool[8].creds.Username, ":fresher-on-A") {
		t.Fatalf("slot 8 (the fresher credential on A) not kept: %+v", cp.pool[8].creds)
	}
	if cp.pool[5].creds == nil {
		t.Fatal("slot 5 on another relay was dropped")
	}
}

// (2) The seed clears the slot that holds its relay under another identity
// (every start: the app's probe mints link 1 → VK's first relay, while the
// previous run's seed on that relay sits on disk under another call id) — and
// a displaced pending credential on the seed's relay is not relocated.
func TestCookieModeTheSeedClearsItsRelaysTwin(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 6, 2*time.Minute, "", nil)
	place := func(slot int, relay, tag string, pending bool) {
		c := &TURNCreds{Username: futureUser(tag), Password: "p", Address: relay, Addresses: []string{relay}}
		e := credPoolEntry{addr: relay, addrs: cp.candidatesForSlot(slot, c), creds: c, ts: time.Now()}
		if pending {
			e.availableAt = time.Now().Add(5 * time.Minute)
		}
		cp.mu.Lock()
		cp.pool[slot] = e
		cp.mu.Unlock()
	}
	place(0, relayA, "pre-seed-pending-on-A", true) // displaced by the seed: on the seed's relay → dropped
	place(4, relayA, "old-seed-on-A", false)        // the previous run's seed → cleared
	place(5, relayB, "on-B", false)                 // another relay → kept
	cp.seedSlot(0, relayA, &TURNCreds{Username: futureUser("seed-on-A"), Password: "p", Address: relayA, Addresses: []string{relayA}})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	onA := 0
	for i := range cp.pool {
		if e := cp.pool[i]; e.creds != nil && e.creds.Address == relayA {
			onA++
		}
	}
	if onA != 1 {
		t.Fatalf("%d slots on relay A after the seed, want the seed alone (slot 4: %v, relocated pending: %v)", onA, cp.pool[4].creds != nil, cp.pool[1].creds != nil || cp.pool[2].creds != nil || cp.pool[3].creds != nil)
	}
	if cp.pool[5].creds == nil {
		t.Fatal("slot 5 on another relay was cleared")
	}
}

// (3) The mint is told the relays the pool already holds (loaded, seeded,
// minted) and never hands one of them to another slot; a slot keeps its own
// relay across refills; with nothing free the slot stays unfilled.
func TestCookieModeTheMintAvoidsTheRelaysOtherSlotsHold(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieCache[cookieLinkID(links[1])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link2"), Password: "p", Address: relayC, Addresses: []string{relayC, relayD}}}
	cookieMu.Unlock()
	ctx := context.Background()
	// Slot 8 asks while slot 2 (loaded) holds A: the first relay NOT held.
	c, err := cookieCredForSlot(ctx, 8, nil, []string{relayA})
	if err != nil || c.Address != relayB {
		t.Fatalf("slot 8 with A held elsewhere: %+v %v — want B (run 9's 486: the mint returned the relay slot 2 held)", c, err)
	}
	// Slot 9 asks while slot 8's mint is still in flight (B handed out, not
	// yet held by the pool): A held, B taken → C.
	if c, err := cookieCredForSlot(ctx, 9, nil, []string{relayA}); err != nil || c.Address != relayC {
		t.Fatalf("slot 9 beside slot 8's mint in flight: %+v %v — want C (two mints must not take one relay)", c, err)
	}
	// Slot 8 again (a refill): its own relay B is not held by another → B, stable.
	if c, err := cookieCredForSlot(ctx, 8, nil, []string{relayA, relayC}); err != nil || c.Address != relayB {
		t.Fatalf("slot 8 refilled: %+v %v — want its own B again", c, err)
	}
	// Everything held: unfilled, and the message says why.
	if _, err := cookieCredForSlot(ctx, 10, nil, []string{relayA, relayB, relayC, relayD}); err == nil || !strings.Contains(err.Error(), "unfilled") || !strings.Contains(err.Error(), "held") {
		t.Fatalf("slot 10 with every relay held: %v — want the shortage refused, naming the held relays", err)
	}
}

// The pool tells the mint what it holds: every slot's relay but the asking
// slot's own — and both pools' fetch closures pass it.
func TestThePoolTellsTheCookieMintItsRelays(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 6, 2*time.Minute, "", nil)
	for slot, relay := range map[int]string{1: relayA, 3: relayB, 4: relayA} {
		c := &TURNCreds{Username: futureUser("x"), Password: "p", Address: relay, Addresses: []string{relay}}
		cp.mu.Lock()
		cp.pool[slot] = credPoolEntry{addr: relay, addrs: cp.candidatesForSlot(slot, c), creds: c, ts: time.Now()}
		cp.mu.Unlock()
	}
	held := cp.heldRelaysExcept(3)
	if strings.Join(held, ",") != relayA {
		t.Fatalf("held except slot 3: %v, want [%s] (B is slot 3's own; A once)", held, relayA)
	}
	var nilPool *credPool
	if nilPool.heldRelaysExcept(0) != nil {
		t.Fatal("a nil pool holds nothing")
	}
	for _, f := range []string{"credpool.go", "proxy.go"} {
		src, err := os.ReadFile(filepath.Join("..", "..", "pkg", "proxy", f))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "cookieCredForSlot(ctx, slot,") && strings.Contains(line, ".heldRelaysExcept(slot)") {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: the pool's cookie fetch does not tell cookieCredForSlot the relays the pool holds", f)
		}
	}
}

// (4) With an override list, a loaded slot beyond the list's length has no
// relay to dial: its stored address may coincide with a list entry (run 10:
// slot 8 held the list's third relay).
func TestCookieModeALoadedSlotBeyondTheListIsNotUsable(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA}, Username: futureUser("s0"), Password: "p"},
		credCacheEntry{Slot: 1, Address: relayB, Addresses: []string{relayB}, Username: futureUser("s1"), Password: "p"},
		credCacheEntry{Slot: 3, Address: relayO, Addresses: []string{relayO}, Username: futureUser("s3-on-the-lists-second"), Password: "p"},
	)
	cp, _, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayE, relayO}})
	cp.mu.Lock()
	cands, usable := cp.candidatesLocked(3), cp.usableLocked(3)
	cp.mu.Unlock()
	if len(cands) != 0 || usable {
		t.Fatalf("slot 3 beyond a two-entry list: candidates %v usable %v — want none, not usable (it would be a second slot on %s)", cands, usable, relayO)
	}
	// A connection whose own slot is 3 is seated elsewhere.
	if _, _, slot := mustGet(t, cp, 30); slot == 3 {
		t.Fatal("conn 30 was handed slot 3")
	}
	// The list gone: the slot's own relay again, usable.
	cp.setOverride(turnOverride{})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if c := cp.candidatesLocked(3); len(c) != 1 || c[0] != relayO {
		t.Fatalf("slot 3 without the list: %v, want its own relay", c)
	}
}

// The user's review of 449, (1): a slot switched off by configuration (cookie
// mode, beyond the override list) is not a slot whose relays are unreachable —
// it must not make healthParkLocked hold every connection, or a pool whose
// only cached credential sits beyond the list never mints (the bootstrap
// without a seed: slots 0–1 empty, the grower not yet running).
func TestASlotBeyondTheListDoesNotHoldTheBootstrap(t *testing.T) {
	cookieTestMode(t)
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 3, Address: relayO, Addresses: []string{relayO}, Username: futureUser("s3-beyond"), Password: "p"},
	)
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayE, relayO}})
	addr, _, slot, err := cp.get(0, false)
	if err != nil || slot == 3 || mints.Load() != 1 || addr != relayE {
		t.Fatalf("get(0) with the only cached credential beyond the list: addr %q slot %d mints %d err %v — want a mint into a slot of the list, the list's first relay", addr, slot, mints.Load(), err)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.health.rec) != 0 {
		t.Fatalf("relay health records %d, want none — nothing was marked", len(cp.health.rec))
	}
}

// (2): two slots on one relay share the relay's quota — the credential that
// stays inherits the other's quota history (lastUsedAt / availableAt), at
// load whichever is kept, and at seed from the twin cleared and the pending
// credential dropped; a fresh credential does not free the relay's seats.
func TestCookieModeTheKeptTwinInheritsTheQuotaHistory(t *testing.T) {
	usedAMinuteAgo := time.Now().Add(-time.Minute).Unix()
	older := credCacheEntry{Slot: 2, Address: relayA, Addresses: []string{relayA}, Username: userExpiring(7*time.Hour, "older-used"), Password: "p", LastUsedAt: usedAMinuteAgo}
	fresher := credCacheEntry{Slot: 8, Address: relayA, Addresses: []string{relayA}, Username: userExpiring(8*time.Hour, "fresher-unused"), Password: "p"}
	for name, order := range map[string][]credCacheEntry{"the used one loaded first": {older, fresher}, "the unused one loaded first": {fresher, older}} {
		t.Run(name, func(t *testing.T) {
			cookieTestMode(t)
			cp, _, _ := relayPool(t, writeCookieCache(t, t.TempDir(), order...), relayC)
			cp.mu.Lock()
			defer cp.mu.Unlock()
			e := cp.pool[8]
			if e.creds == nil || cp.pool[2].creds != nil {
				t.Fatalf("the fresher credential (slot 8) not the one kept: slot 8 %v slot 2 %v", e.creds != nil, cp.pool[2].creds != nil)
			}
			if e.lastUsedAt.Unix() != usedAMinuteAgo || e.availableAt.IsZero() || cp.isFreshLocked(8) {
				t.Fatalf("the kept credential lost the relay's quota history: lastUsedAt %v availableAt %v fresh %v — want the older's, pending", e.lastUsedAt, e.availableAt, cp.isFreshLocked(8))
			}
		})
	}
	t.Run("the seed", func(t *testing.T) {
		cookieTestMode(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cp := newCredPool(ctx, 6, 2*time.Minute, "", nil)
		used, avail := time.Now().Add(-time.Minute), time.Now().Add(9*time.Minute)
		c := &TURNCreds{Username: futureUser("old-seed-on-A"), Password: "p", Address: relayA, Addresses: []string{relayA}}
		cp.mu.Lock()
		cp.pool[4] = credPoolEntry{addr: relayA, addrs: cp.candidatesForSlot(4, c), creds: c, ts: time.Now(), lastUsedAt: used, availableAt: avail}
		cp.mu.Unlock()
		cp.seedSlot(0, relayA, &TURNCreds{Username: futureUser("seed-on-A"), Password: "p", Address: relayA, Addresses: []string{relayA}})
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if e := cp.pool[0]; !e.lastUsedAt.Equal(used) || !e.availableAt.Equal(avail) || cp.isFreshLocked(0) {
			t.Fatalf("the seed on a relay whose seats are still held: lastUsedAt %v availableAt %v fresh %v — want the cleared twin's history, pending", e.lastUsedAt, e.availableAt, cp.isFreshLocked(0))
		}
	})
}
