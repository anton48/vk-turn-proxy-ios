// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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
		e, ok := parseTURNEntry(tc.entry)
		if !ok || e.addr != tc.addr || e.quota != tc.quota || e.hasQuota != tc.has {
			t.Fatalf("%q → %+v %v, want %q %d %v", tc.entry, e, ok, tc.addr, tc.quota, tc.has)
		}
	}
	// `host:port:1:2` is the four-field form since 2026-11-07 (a quota of one
	// and a pace of two) — a FIFTH field is what has no form.
	for _, bad := range []string{"relay.example:19302:x", "relay.example:19302:-1", "relay.example:19302:", "relay.example:19302:1:2:3"} {
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
	// A connection whose attempt on O went silent without evidence is NOT
	// handed O again (2026-11-01, Nov 1 §488): the relay without a quota takes
	// everyone while it ANSWERS — a silent one is passed until it answers or
	// the path changes; VK's relay on the same slot has room.
	cp.release(0, held[1], "")
	cp.noteRelayUnanswered(1, 0, held[1], relayO, time.Now().Add(-5*time.Second))
	if addr, creds, slot := mustGet(t, cp, 1); addr == relayO || slot != 0 {
		t.Fatalf("conn 1 after a silent attempt on O: %q on slot %d — want VK's relay on slot 0, not the silent O", addr, slot)
	} else {
		cp.release(0, creds, addr) // its seat on VK's relay back: the ten below count from nought there
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
	// The forty seats are O's: on VK's relay the credential holds none, so
	// the next ten dial VK on slot 0 under VK's quota there (the seats are
	// the relay's they were created on — relayhist.go); the eleventh mints.
	for conn := 40; conn < 50; conn++ {
		if addr, _, slot := mustGet(t, cp, conn); slot != 0 || addr == relayO {
			t.Fatalf("conn %d after O is marked: %q on slot %d, mints %d — want VK's relay on slot 0 (no seat of this credential is on it)", conn, addr, slot, mints.Load())
		}
	}
	if _, _, slot := mustGet(t, cp, 50); slot == 0 || mints.Load() != 1 {
		t.Fatalf("conn 50 after ten on VK's relay: slot %d, mints %d — want another slot, one mint", slot, mints.Load())
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
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp.candidatesForSlot(0, own), creds: own, ts: time.Now(), relayHist: relayHist{lastUsedAt: time.Now().Add(-time.Minute)}})
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

// 2026-10-31, the stand (459, own.parked.log): anonymous mode, a restart within
// ten minutes of a session through VK with the list `O:0,$vkurls` — every slot
// of the console's pool of four was pending by VK's clock (lastUsedAt + 10 min)
// and twenty connections parked for 95 s with "no slot available". Readiness
// read the entry's clock whatever relay the slot dials; the clock is VK's seats
// on the credential, and a relay without a quota holds none of them.

// The stand's shape: a pool of four, every slot pending by VK's clock, the list
// O:0,$vkurls — twenty connections on slot 0's O at once, no mint, no park, and
// the override says why. The clock is KEPT: once O is marked the slot dials
// VK's relays, whose seats the credential may still hold — not fresh, VK's cap,
// nobody seated on it at VK inside the clock.
func TestAnonModeASlotPendingByVKsClockIsReadyOnARelayWithoutAQuota(t *testing.T) {
	used := time.Now().Add(-2 * time.Minute).Unix()
	var entries []credCacheEntry
	for slot := 0; slot < 4; slot++ {
		entries = append(entries, credCacheEntry{Slot: slot, Address: relayA, Addresses: []string{relayA, relayB},
			Username: futureUser(fmt.Sprintf("used-%d", slot)), Password: "p", LastUsedAt: used})
	}
	path := writeCache(t, t.TempDir(), entries...)
	cp, mints, _ := relayPoolN(t, path, 4, relayC)
	logged := captureLog(t)
	list, err := ParseTURNServers(relayO + ":0," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	var held []*TURNCreds
	for conn := 0; conn < 20; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relayO || slot != 0 {
			t.Fatalf("conn %d: %q on slot %d — want every connection on slot 0's %s (no quota) although the slot is pending by VK's clock", conn, addr, slot, relayO)
		}
		held = append(held, creds)
	}
	if mints.Load() != 0 || cp.pool[0].active != 20 {
		t.Fatalf("mints %d, slot 0 active %d — want no mint, twenty seats on the one credential", mints.Load(), cp.pool[0].active)
	}
	cp.mu.Lock()
	avail, pending := cp.pool[0].availableAt, cp.pendingLocked(0)
	fresh0, avail0 := cp.isFreshLocked(0), cp.availableLocked(0) // the counts, the grower, the UI: the same answer as the hand-out
	cp.mu.Unlock()
	if !fresh0 || !avail0 {
		t.Fatalf("slot 0 dialling %s (no quota): fresh %v, available %v — want both, as the hand-out found it", relayO, fresh0, avail0)
	}
	if avail.IsZero() || !time.Now().Before(avail) {
		t.Fatalf("slot 0's VK clock erased: availableAt %v — want kept for the fallback to VK's relays", avail)
	}
	if pending {
		t.Fatalf("slot 0 is pending to the mint paths while it dials %s (no quota) — it is ready there", relayO)
	}
	if !strings.Contains(logged(), "pending by VK's clock") {
		t.Fatalf("the override does not say the pending slots are ready on %s:\n%s", relayO, logged())
	}
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, 0, held[0], relayO, time.Now())
	cp.mu.Lock()
	fresh, pending, cap0, after := cp.isFreshLocked(0), cp.pendingLocked(0), cp.capLocked(0), cp.pool[0].availableAt
	cp.mu.Unlock()
	if fresh || !pending || cap0 != connsPerSlot || !after.Equal(avail) {
		t.Fatalf("slot 0 after O is marked: fresh %v, pending %v, cap %d, availableAt %v (was %v) — want VK's clock applied again (pending, not fresh), VK's cap, the clock untouched", fresh, pending, cap0, after, avail)
	}
	if _, _, slot, err := cp.get(20, false); err == nil && slot == 0 {
		t.Fatalf("conn 20 seated on slot 0 at VK inside the credential's clock")
	}
}

// Every readiness question about a LIVE slot is asked of the slot — the
// relay-aware wrappers isFreshLocked / pendingLocked / availableLocked — never
// of the entry alone: that was the defect's shape (release, Phase 2, tryFill,
// pickSlotToFill, the counts and the transition log all read entryIsFresh /
// entryIsPending off cp.pool[...] before 460).
func TestEveryReadinessQuestionAboutASlotIsAskedOfTheSlot(t *testing.T) {
	allowed := map[string]bool{
		"func entryIsFresh(": true, "func entryIsPending(": true, "func entryCredValid(": true,
		"func (cp *credPool) isFreshLocked(": true, "func (cp *credPool) pendingLocked(": true,
		"func (cp *credPool) availableLocked(": true, "func (cp *credPool) sayReadyDespiteTheClockLocked(": true,
		"func (cp *credPool) freshOnLocked(": true, // the per-relay half of isFreshLocked (relayhist.go)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		for _, fn := range strings.Split(goFile(t, f), "\nfunc ")[1:] {
			head := "func " + fn[:strings.Index(fn, "{")+1]
			ok := false
			for a := range allowed {
				if strings.HasPrefix(head, a) {
					ok = true
				}
			}
			if ok {
				continue
			}
			for _, bare := range []string{"entryIsFresh(", "entryIsPending(", "entryIsAvailable(", "entryCredValid("} {
				if strings.Contains(fn, bare) {
					t.Errorf("%s: %s asks %s of the entry — ask the slot (isFreshLocked / pendingLocked / availableLocked): the entry's clock is VK's, not the relay's the slot dials now", f, strings.TrimSpace(head), bare)
				}
			}
		}
	}
}

// The user's review of 2026-10-31 (2): cookie mode sizes the pool at two
// slots per link and the list's FIXED entries took the first of them — with
// three links answering six distinct VK relays and one own relay, sixty
// connections sat on the own relay and only fifty found a VK slot when it
// died. The fixed entries ADD to the VK budget: 2 × links + fixed.
func TestCookieModeTheFixedEntriesAddToTheVKSlots(t *testing.T) {
	cookieTestMode(t, "https://vk.ru/call/join/aaa", "https://vk.ru/call/join/bbb", "https://vk.ru/call/join/ccc")
	list, _ := ParseTURNServers(relayO + ":0," + relayC + "," + TURNServersVK)
	p := NewCredPool(context.Background(), CredPoolConfig{NumConns: 60, Fetch: (&fakeMinter{}).fetch, TurnServers: list})
	t.Cleanup(p.Close)
	if got := p.Stats().Size; got != 8 {
		t.Fatalf("NewCredPool, three links and two fixed entries: %d slots — want 8 = 2 × 3 + 2", got)
	}
	cfg := Config{NumConns: 60, PeerAddr: "127.0.0.1:1", TurnServers: list}
	px := NewProxy(cfg)
	t.Cleanup(px.Stop)
	if got := px.credPool.size; got != 8 {
		t.Fatalf("NewProxy, three links and two fixed entries: %d slots — want 8 = 2 × 3 + 2", got)
	}
	// A list that grows later (a name resolving to two IPs, a changed
	// setting) grows the pool with it — never shrinks it.
	cp := px.credPool
	l2, _ := ParseTURNServers(relayO + ":0," + relayA + "," + relayB + "," + relayC + "," + TURNServersVK)
	cp.setOverride(turnOverride{servers: l2})
	if cp.size != 10 || len(cp.pool) != 10 {
		t.Fatalf("after the list grew to four fixed entries: size %d, %d entries — want 10", cp.size, len(cp.pool))
	}
	l1, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp.setOverride(turnOverride{servers: l1})
	if cp.size != 10 {
		t.Fatalf("after the list shrank: size %d — the pool never shrinks (10)", cp.size)
	}
}

// Sixty connections on the own relay, the own relay dies: every one of them
// finds a VK slot — six for the three links' six relays, beside the own
// relay's slot (a pool of 2 × 3 slots would have left ten of them parked).
func TestCookieModeEveryConnectionFindsAVKSlotWhenTheOwnRelayDies(t *testing.T) {
	cookieTestMode(t, "https://vk.ru/call/join/aaa", "https://vk.ru/call/join/bbb", "https://vk.ru/call/join/ccc")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	o := turnOverride{servers: list}
	cp := newCredPool(ctx, cookiePoolSize(3, o), 2*time.Minute, "", nil)
	cp.setOverride(o)
	if cp.size != 7 {
		t.Fatalf("size %d — want 7 = 2 × 3 + 1", cp.size)
	}
	vk := []string{"203.0.113.21:19302", "203.0.113.22:19302", "203.0.113.23:19302", "203.0.113.24:19302", "203.0.113.25:19302", "203.0.113.26:19302"}
	cp.mu.Lock()
	own := &TURNCreds{Username: futureUser("own"), Password: "p", Address: relayO, Addresses: []string{relayO}}
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp.candidatesForSlot(0, own), creds: own, ts: time.Now()})
	for i, r := range vk {
		c := &TURNCreds{Username: futureUser("vk"), Password: "p", Address: r, Addresses: []string{r}}
		cp.placeLocked(1+i, credPoolEntry{addr: r, addrs: cp.candidatesForSlot(1+i, c), creds: c, ts: time.Now()})
	}
	cp.mu.Unlock()
	held := map[int]*TURNCreds{}
	for conn := 0; conn < 60; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if slot != 0 || addr != relayO {
			t.Fatalf("conn %d: %q on slot %d — want the own relay", conn, addr, slot)
		}
		held[conn] = creds
	}
	for conn := 0; conn < 60; conn++ {
		cp.release(0, held[conn], "")
	}
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, 0, held[0], relayO, time.Now())
	perSlot := map[int]int{}
	for conn := 0; conn < 60; conn++ {
		_, _, slot := mustGet(t, cp, conn)
		perSlot[slot]++
	}
	if len(perSlot) != 6 || perSlot[0] != 0 {
		t.Fatalf("after the own relay died the sixty sat on slots %v — want ten on each of the six VK slots", perSlot)
	}
}

// The user's review of 2026-10-31 (1): the history is the RELAY's the seats
// were created on. With the own relay (`host:port:0`) dead, ten connections
// sit on VK's relay; the path change clears the relay marks, the own relay is
// the first candidate again, and the smart-pause must still mark the slot on
// VK's relay — the seats are there. The own relay dead again, the same
// credential must NOT go back to VK's relay (its ten allocations may still be
// held there): a mint, not a 486 cascade. On the 460 code the smart-pause
// skipped the slot as one on a relay without a quota.
func TestAnonModeTheSeatsStayWithTheRelayTheyWereCreatedOnAcrossAPathChange(t *testing.T) {
	cp, mints, _ := relayPoolN(t, "", 4, relayC)
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp.setOverride(turnOverride{servers: list})
	// The own relay is dead (marked with evidence); conn 0's first seat was on it.
	addr, c0, slot := mustGet(t, cp, 0)
	if addr != relayO || slot != 0 {
		t.Fatalf("conn 0: %q on slot %d — want the own relay first", addr, slot)
	}
	cp.release(0, c0, relayO)
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(0, 0, c0, relayO, time.Now())
	// Ten connections on VK's relay, slot 0's credential.
	held := map[int]*TURNCreds{}
	for conn := 0; conn < 10; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relayC || slot != 0 {
			t.Fatalf("conn %d with the own relay marked: %q on slot %d — want VK's relay on slot 0", conn, addr, slot)
		}
		held[conn] = creds
	}
	// The network changes: the marks are cleared (the own relay is the first
	// candidate again), the slots in use are smart-paused — ON THE RELAY THE
	// SEATS ARE ON — and the dying sessions give their seats back.
	cp.MarkInUseSlotsForPathChange()
	cp.mu.Lock()
	cp.pauseAcquireUntil = time.Time{}
	onC, onO := cp.markLocked(0, relayC), cp.markLocked(0, relayO)
	cp.mu.Unlock()
	if !onC.After(time.Now()) || !onO.IsZero() {
		t.Fatalf("after the path change slot 0 is benched on %s until %v and on %s until %v — want VK's relay benched (its ten seats), the own relay not", relayC, onC, relayO, onO)
	}
	for conn := 0; conn < 10; conn++ {
		cp.release(0, held[conn], relayC)
	}
	// The own relay answers again: the slot takes everyone there.
	if addr, creds, slot := mustGet(t, cp, 10); addr != relayO || slot != 0 {
		t.Fatalf("conn 10 after the path change: %q on slot %d — want the own relay on slot 0", addr, slot)
	} else {
		cp.release(0, creds, relayO)
	}
	// The own relay dead again: the credential's seats on VK's relay may
	// still be held — NOT handed out for it; a fresh credential instead.
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(11, 0, held[0], relayO, time.Now())
	addr, _, slot = mustGet(t, cp, 11)
	if slot == 0 || addr != relayC || mints.Load() != 2 {
		t.Fatalf("conn 11 with the own relay dead again: %q on slot %d, mints %d — want a fresh credential (slot 0's ten seats on %s may still be held: a 486 cascade)", addr, slot, mints.Load(), relayC)
	}
}

// The user's review of 2026-10-31 (3): the quota is the RELAY's the connection
// dials. Under `A:20,B:2` with A silent and not yet marked (no evidence), the
// connections' cursors move on to B — whose quota of two is the one to check,
// not A's twenty. On the 460 code the cap was read off the first unmarked
// candidate (A) and a third seat was handed out on B.
func TestTheQuotaCheckedIsTheRelaysTheConnectionDials(t *testing.T) {
	cp, mints, clock := relayPoolN(t, "", 4, relayC)
	list, _ := ParseTURNServers(relayA + ":20," + relayB + ":2")
	cp.setOverride(turnOverride{servers: list})
	cp.setColdStartTarget(30) // three buckets: the cold-start cap does not park the third connection
	seatedOnB := map[int]int{}
	for conn := 0; conn < 3; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relayA {
			t.Fatalf("conn %d's first attempt: %q — want A, the list's first", conn, addr)
		}
		// A is silent; no evidence that the network works (the mint's answer
		// is older than the evidence window) → not marked, the cursor moves
		// on. The attempt's seat is given back.
		*clock = clock.Add(2 * relayEvidenceWindow)
		cp.release(slot, creds, relayA)
		cp.noteRelayUnanswered(conn, slot, creds, relayA, *clock)
		addr, _, slot = mustGet(t, cp, conn)
		if addr != relayB {
			t.Fatalf("conn %d's second attempt: %q — want B at the cursor", conn, addr)
		}
		seatedOnB[slot]++
	}
	cp.mu.Lock()
	onB0 := cp.seatsOnLocked(0, relayB)
	cp.mu.Unlock()
	if onB0 > 2 || seatedOnB[0] > 2 || mints.Load() != 2 {
		t.Fatalf("slot 0's credential holds %d seats on %s (quota 2); the three connections sat on slots %v with %d mints — want two on slot 0, the third on a fresh credential", onB0, relayB, seatedOnB, mints.Load())
	}
	// A seat given back on B is a seat on B again — for a connection at the
	// cursor on B, on slot 0, no mint.
	cp.mu.Lock()
	k := leaseKeyOf(0, cp.pool[0].creds)
	creds0 := cp.pool[0].creds
	cp.cursor[9] = 1
	cp.mu.Unlock()
	cp.release(0, creds0, relayB)
	if addr, _, slot := mustGet(t, cp, 9); addr != relayB || slot != 0 || mints.Load() != 2 {
		t.Fatalf("conn 9 after a seat on %s was given back: %q on slot %d, mints %d — want %s on slot 0, no mint", relayB, addr, slot, mints.Load(), relayB)
	}
	_ = k
}

// A 486 benches the credential ON THE RELAY it came from: on another relay
// of the list the same credential has a quota of its own (relayhist.go).
func TestA486BenchesTheCredentialOnTheRelayItCameFrom(t *testing.T) {
	cp, mints, _ := relayPoolN(t, "", 4, relayC)
	cp.setOverride(turnOverride{servers: []string{relayA, relayB}})
	cp.setColdStartTarget(30)
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA || slot != 0 {
		t.Fatalf("conn 0: %q on slot %d", addr, slot)
	}
	if cd := cp.markSaturated(0, creds, relayA); cd <= 0 {
		t.Fatalf("the 486 on %s applied no cooldown (%v)", relayA, cd)
	}
	cp.mu.Lock()
	onA, onB := cp.markLocked(0, relayA), cp.markLocked(0, relayB)
	cp.cursor[1] = 1
	cp.mu.Unlock()
	if !onA.After(time.Now()) || !onB.IsZero() {
		t.Fatalf("after a 486 from %s slot 0 is benched on it until %v and on %s until %v — want the one relay benched", relayA, onA, relayB, onB)
	}
	if addr, _, slot := mustGet(t, cp, 1); addr != relayB || slot != 0 || mints.Load() != 1 {
		t.Fatalf("conn 1 at the cursor on %s after the 486 on %s: %q on slot %d, mints %d — want %s on slot 0, no mint", relayB, relayA, addr, slot, mints.Load(), relayB)
	}
}

// The cache keeps the last use BY RELAY (`used_on`): the next start applies
// the clock to the relay it belongs to — a slot dialling another relay of
// the list is ready there. A file from before the field (one `last_used_at`)
// is read as every relay's.
func TestTheCacheKeepsTheLastUseByRelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds-pool.json")
	cp, _, _ := relayPoolN(t, path, 4, relayC)
	cp.setOverride(turnOverride{servers: []string{relayA, relayB}})
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA || slot != 0 {
		t.Fatalf("conn 0: %q on slot %d", addr, slot)
	}
	cp.release(0, creds, relayA)
	cp.saveToDisk()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f credCacheFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Creds) != 1 || f.Creds[0].UsedOn[relayA] == 0 || f.Creds[0].UsedOn[relayB] != 0 || f.Creds[0].LastUsedAt != f.Creds[0].UsedOn[relayA] {
		t.Fatalf("the file: %+v — want used_on with %s alone, last_used_at the same moment", f.Creds, relayA)
	}
	// The next start: pending on A, ready on B.
	cp2, _, _ := relayPoolN(t, path, 4, relayC)
	cp2.setOverride(turnOverride{servers: []string{relayA, relayB}})
	cp2.mu.Lock()
	onA, onB := cp2.clockLocked(0, relayA), cp2.clockLocked(0, relayB)
	freshA, freshB, pending := cp2.freshOnLocked(0, relayA), cp2.freshOnLocked(0, relayB), cp2.pendingLocked(0)
	cp2.mu.Unlock()
	if !onA.After(time.Now()) || !onB.IsZero() || freshA || !freshB || !pending {
		t.Fatalf("loaded: clock on %s %v, on %s %v, fresh %v / %v, pending %v — want A's clock running, B's none", relayA, onA, relayB, onB, freshA, freshB, pending)
	}
	// A connection whose cursor stands on B is seated — on B.
	cp2.mu.Lock()
	cp2.cursor[7] = 1
	cp2.mu.Unlock()
	if addr, _, slot := mustGet(t, cp2, 7); addr != relayB || slot != 0 {
		t.Fatalf("conn 7 at the cursor on B: %q on slot %d — want B on slot 0 (no clock there)", addr, slot)
	}
	// A file from before `used_on`: the one last use applies to every relay.
	old := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayC, Addresses: []string{relayC}, Username: futureUser("old"), Password: "p", LastUsedAt: time.Now().Add(-time.Minute).Unix()})
	cp3, _, _ := relayPoolN(t, old, 4, relayC)
	cp3.setOverride(turnOverride{servers: []string{relayA, relayB}})
	cp3.mu.Lock()
	a3, b3 := cp3.clockLocked(0, relayA), cp3.clockLocked(0, relayB)
	cp3.mu.Unlock()
	if !a3.After(time.Now()) || !b3.After(time.Now()) {
		t.Fatalf("a file without used_on: clock on %s %v, on %s %v — want the one last use on every relay", relayA, a3, relayB, b3)
	}
}

// Every field the Go cache file carries is in the Swift mirror (CredCache.swift):
// BackupManager re-encodes the struct into the backup and back, and a field
// the mirror lacks is dropped on the way (the user's rule of 2026-10-20).
func TestTheSwiftMirrorCarriesEveryCacheField(t *testing.T) {
	swift, err := os.ReadFile(filepath.Join("..", "..", "VKTurnProxy", "VKTurnProxy", "CredCache.swift"))
	if err != nil {
		t.Fatal(err)
	}
	src := goFile(t, "creds.go")
	for _, typ := range []string{"type credCacheFile struct {", "type credCacheEntry struct {"} {
		body := src[strings.Index(src, typ):]
		body = body[:strings.Index(body, "\n}\n")]
		tags := regexp.MustCompile("json:\"([a-z_]+)").FindAllStringSubmatch(body, -1)
		if len(tags) < 3 {
			t.Fatalf("%s: %d json tags read", typ, len(tags))
		}
		for _, m := range tags {
			if !strings.Contains(string(swift), "let "+m[1]+":") {
				t.Errorf("CredCache.swift lacks `let %s:` — the Go cache file's field is dropped by a backup and restore", m[1])
			}
		}
	}
}

// The user's review of 461 (1): a file from before `used_on` was loaded with
// its one last use as every relay's; the credential then ran on the own relay
// and the save wrote `used_on` with that relay alone — the next load, seeing
// the field, dropped the old clock with nine minutes still on it. The history
// whose relay is not known is saved under "*" and applies to every relay.
func TestAFileFromBeforeUsedOnKeepsItsClockAcrossASave(t *testing.T) {
	dir := t.TempDir()
	old := writeCache(t, dir, credCacheEntry{Slot: 0, Address: relayC, Addresses: []string{relayC}, Username: futureUser("old"), Password: "p", LastUsedAt: time.Now().Add(-time.Minute).Unix()})
	cp, _, _ := relayPoolN(t, old, 4, relayC)
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp.setOverride(turnOverride{servers: list})
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO || slot != 0 {
		t.Fatalf("conn 0: %q on slot %d — want the own relay on slot 0", addr, slot)
	}
	cp.release(0, creds, relayO)
	cp.saveToDisk()
	raw, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	var f credCacheFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Creds) != 1 || f.Creds[0].UsedOn["*"] == 0 || f.Creds[0].UsedOn[relayO] == 0 {
		t.Fatalf("the saved file: %+v — want used_on with \"*\" (the old history) beside %s", f.Creds, relayO)
	}
	cp2, _, _ := relayPoolN(t, old, 4, relayC)
	cp2.setOverride(turnOverride{servers: list})
	cp2.mu.Lock()
	onC, onO := cp2.clockLocked(0, relayC), cp2.clockLocked(0, relayO)
	cp2.mu.Unlock()
	left := time.Until(onC)
	if left < 8*time.Minute || left > 9*time.Minute+30*time.Second || !onO.IsZero() {
		t.Fatalf("after the save the clock on %s has %v left (want ≈9 min: the old history), on %s %v (want none)", relayC, left.Round(time.Second), relayO, onO)
	}
}

// The user's review of 461 (2): with every candidate marked, the hand-out
// judged the slot on the list's first candidate while the probe handed out
// the relay longest due for a re-try — a third seat on B under A's quota.
// The slot is judged on the relay the re-try would dial.
func TestTheReTryIsJudgedOnTheRelayItDials(t *testing.T) {
	cp, mints, clock := relayPoolN(t, "", 4, relayC)
	list, _ := ParseTURNServers(relayA + ":20," + relayB + ":2")
	cp.setOverride(turnOverride{servers: list})
	cp.setColdStartTarget(30)
	// Two seats on B (the connections' cursors stand on it).
	cp.mu.Lock()
	cp.cursor[0], cp.cursor[1] = 1, 1
	cp.mu.Unlock()
	var creds0 *TURNCreds
	for conn := 0; conn < 2; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relayB || slot != 0 {
			t.Fatalf("conn %d: %q on slot %d — want B on slot 0", conn, addr, slot)
		}
		creds0 = creds
	}
	// B marked first, A a second later (both with evidence): B's re-try comes
	// due first. Then both are due.
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(5, 0, creds0, relayB, *clock)
	*clock = clock.Add(time.Second)
	cp.health.answered("", time.Time{})
	cp.noteRelayUnanswered(6, 0, creds0, relayA, *clock)
	*clock = clock.Add(probeBackoff(0) + 2*time.Second)
	addr, _, slot := mustGet(t, cp, 2)
	cp.mu.Lock()
	onB := cp.seatsOnLocked(0, relayB)
	cp.mu.Unlock()
	if onB != 2 || slot == 0 || addr != relayB || mints.Load() != 2 {
		t.Fatalf("conn 2 with both relays marked and B's re-try due: %q on slot %d, slot 0's seats on B %d, mints %d — want the re-try on B from a fresh credential (slot 0's two seats on B are its quota)", addr, slot, onB, mints.Load())
	}
}

// The user's review of 462 (1): the load wrote the latest moment over every
// `used_on` record onto the entry's own history, and the next save wrote it
// back as "*" — a relay never used was quarantined on the own relay's history.
// The entry's own history comes from "*" or a legacy file alone; the latest
// moment is for the log line.
func TestASavedRelayHistoryDoesNotBecomeEveryRelays(t *testing.T) {
	dir := t.TempDir()
	used := time.Now().Add(-time.Minute).Unix()
	path := writeCache(t, dir, credCacheEntry{Slot: 0, Address: relayC, Addresses: []string{relayC}, Username: futureUser("own-only"), Password: "p", LastUsedAt: used, UsedOn: map[string]int64{relayO: used}})
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp, _, _ := relayPoolN(t, path, 4, relayC)
	cp.setOverride(turnOverride{servers: list})
	cp.saveToDisk()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f credCacheFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Creds) != 1 || f.Creds[0].UsedOn["*"] != 0 || f.Creds[0].UsedOn[relayO] == 0 || f.Creds[0].LastUsedAt != used {
		t.Fatalf("after a load and a save: %+v — want used_on with %s alone (no \"*\" out of the own relay's history), last_used_at kept", f.Creds, relayO)
	}
	cp2, _, _ := relayPoolN(t, path, 4, relayC)
	cp2.setOverride(turnOverride{servers: list})
	cp2.mu.Lock()
	onC, onO := cp2.clockLocked(0, relayC), cp2.clockLocked(0, relayO)
	cp2.mu.Unlock()
	if !onC.IsZero() || !onO.IsZero() {
		t.Fatalf("the next load: a clock on %s until %v, on %s until %v — want none (the own relay's history is the own relay's)", relayC, onC, relayO, onO)
	}
}

// 2026-11-01, the stands (Nov 1 §488, defect 2): a relay without a quota took
// every connection "while it answers" — read as "while it is not marked", and
// a mark needs evidence that something ELSE answered. With a ready credential
// nothing mints and nobody dials VK, so a silent own relay was dialled for
// ever: a start on a ready cache with `O:0,$vkurls` and O silent had no
// session in 75 s; a path change with O dead held 0/10 for 150 s. Now "while
// it answers" is "while no attempt on it went unanswered on this path since
// the last answer" (relayHealth.untried): a silent O is passed by every
// connection at once, VK's first answer marks it, its own answer or a path
// change puts it first again.
func TestASilentRelayWithoutAQuotaIsPassedUntilItAnswers(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	list, err := ParseTURNServers(relayO + ":0," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	addr, c0, slot := mustGet(t, cp, 0)
	if addr != relayO || slot != 0 {
		t.Fatalf("conn 0: %q on slot %d — want the own relay first", addr, slot)
	}
	// O silent, NO evidence (nothing else has answered on this path): not
	// marked — and still passed: by conn 0, whose cursor moved, and by conn 1,
	// whose cursor did not.
	cp.release(0, c0, relayO)
	cp.noteRelayUnanswered(0, 0, c0, relayO, time.Now())
	if cp.health.isDead(relayO) {
		t.Fatalf("O marked without evidence")
	}
	held := map[int]*TURNCreds{}
	where := map[int]string{}
	for conn := 0; conn < 2; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		if addr == relayO || slot != 0 {
			t.Fatalf("conn %d after a silent attempt on O: %q on slot %d — want VK's relay on slot 0 (O is passed while it is silent)", conn, addr, slot)
		}
		held[conn], where[conn] = creds, addr
	}
	if mints.Load() != 0 {
		t.Fatalf("mints %d — the ready credential has room on VK's relay", mints.Load())
	}
	// VK's relay answers: the evidence — O is marked now.
	cp.noteAllocatedAt(0, held[0], where[0], time.Now())
	if !cp.health.isDead(relayO) {
		t.Fatalf("O not marked after VK's relay answered")
	}
	// A path change clears the marks and the records: O is first again.
	for conn := 0; conn < 2; conn++ {
		cp.release(0, held[conn], where[conn])
	}
	cp.MarkInUseSlotsForPathChange()
	cp.mu.Lock()
	cp.pauseAcquireUntil = time.Time{}
	cp.mu.Unlock()
	addr, c2, slot := mustGet(t, cp, 2)
	if addr != relayO || slot != 0 {
		t.Fatalf("conn 2 after the path change: %q on slot %d — want the own relay first again", addr, slot)
	}
	// Silent again without evidence: passed; then O ANSWERS: its record is
	// cleared and it takes everyone again.
	cp.release(0, c2, relayO)
	cp.noteRelayUnanswered(2, 0, c2, relayO, time.Now())
	if addr, creds, _ := mustGet(t, cp, 3); addr == relayO {
		t.Fatalf("conn 3 handed the silent O again")
	} else {
		cp.release(0, creds, addr)
	}
	cp.health.answered(relayO, time.Time{})
	if addr, _, slot := mustGet(t, cp, 4); addr != relayO || slot != 0 {
		t.Fatalf("conn 4 after O answered: %q on slot %d — want the own relay first again", addr, slot)
	}
}

// Cookie mode, the same silence: the slot on the own relay is passed (its one
// candidate went unanswered, nothing is marked) and the sixty find the six VK
// slots; VK's answer then marks O. Green on the 463 code too — a cookie slot
// with `$vkurls` fell out through hasCandidate already; the guard stays for the
// one rule.
func TestCookieModeASilentRelayWithoutAQuotaIsPassedUntilItAnswers(t *testing.T) {
	cookieTestMode(t, "https://vk.ru/call/join/aaa", "https://vk.ru/call/join/bbb", "https://vk.ru/call/join/ccc")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	o := turnOverride{servers: list}
	cp := newCredPool(ctx, cookiePoolSize(3, o), 2*time.Minute, "", nil)
	cp.setOverride(o)
	vk := []string{"203.0.113.21:19302", "203.0.113.22:19302", "203.0.113.23:19302", "203.0.113.24:19302", "203.0.113.25:19302", "203.0.113.26:19302"}
	cp.mu.Lock()
	own := &TURNCreds{Username: futureUser("own"), Password: "p", Address: relayO, Addresses: []string{relayO}}
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp.candidatesForSlot(0, own), creds: own, ts: time.Now()})
	for i, r := range vk {
		c := &TURNCreds{Username: futureUser("vk"), Password: "p", Address: r, Addresses: []string{r}}
		cp.placeLocked(1+i, credPoolEntry{addr: r, addrs: cp.candidatesForSlot(1+i, c), creds: c, ts: time.Now()})
	}
	cp.mu.Unlock()
	addr, c0, slot := mustGet(t, cp, 0)
	if slot != 0 || addr != relayO {
		t.Fatalf("conn 0: %q on slot %d — want the own relay", addr, slot)
	}
	cp.release(0, c0, relayO)
	cp.noteRelayUnanswered(0, 0, c0, relayO, time.Now()) // no evidence: not marked
	if cp.health.isDead(relayO) {
		t.Fatalf("O marked without evidence")
	}
	perSlot := map[int]int{}
	var first *TURNCreds
	firstSlot, firstAddr := -1, ""
	for conn := 0; conn < 60; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		perSlot[slot]++
		if first == nil {
			first, firstSlot, firstAddr = creds, slot, addr
		}
	}
	if len(perSlot) != 6 || perSlot[0] != 0 {
		t.Fatalf("with the own relay silent the sixty sat on slots %v — want ten on each of the six VK slots, none on O", perSlot)
	}
	cp.noteAllocatedAt(firstSlot, first, firstAddr, time.Now())
	if !cp.health.isDead(relayO) {
		t.Fatalf("O not marked after a VK relay answered")
	}
}

// Cookie mode under a FIXED list (no $vkurls): the list is cycled, never
// minted around — the own relay's slot stays usable (an outage must not strand
// every connection) but it no longer comes FIRST while silent: a connection
// whose own slot is the other entry's goes there, and that relay's answer
// marks O. The user's review of 48ccc45 (2026-11-01): conn 0's OWN slot is
// O's, and the bootstrap's first connection is alone — the others start only
// after it — so «conn 10 goes to B» never happened and conn 0 dialled the
// silent O for ever, B untried, no mint. An eligible slot whose relay is
// untried beats the own slot whose relay went silent; the silent one is dialled
// again only when no such alternative is left.
func TestCookieModeASilentRelayWithoutAQuotaIsNotTakenFirst(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	list, _ := ParseTURNServers(relayO + ":0," + relayE)
	cp := newCredPool(ctx, 4, 2*time.Minute, "", nil)
	cp.setOverride(turnOverride{servers: list})
	cp.mu.Lock()
	own := &TURNCreds{Username: futureUser("own"), Password: "p", Address: relayO, Addresses: []string{relayO}}
	cp.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp.candidatesForSlot(0, own), creds: own, ts: time.Now()})
	e := &TURNCreds{Username: futureUser("e"), Password: "p", Address: relayE, Addresses: []string{relayE}}
	cp.placeLocked(1, credPoolEntry{addr: relayE, addrs: cp.candidatesForSlot(1, e), creds: e, ts: time.Now()})
	cp.mu.Unlock()
	addr, c10, slot := mustGet(t, cp, 10)
	if slot != 0 || addr != relayO {
		t.Fatalf("conn 10 with O untried: %q on slot %d — want the own relay first", addr, slot)
	}
	cp.release(0, c10, relayO)
	cp.noteRelayUnanswered(10, 0, c10, relayO, time.Now())
	if addr, _, slot := mustGet(t, cp, 10); slot != 1 || addr != relayE {
		t.Fatalf("conn 10 with O silent: %q on slot %d — want its own slot's %s", addr, slot, relayE)
	}
	// conn 0, whose OWN slot is O's: B's slot all the same — the bootstrap's
	// only connection must reach the relay that may answer.
	addr, c0, slot := mustGet(t, cp, 0)
	if slot != 1 || addr != relayE {
		t.Fatalf("conn 0 with O silent under a fixed list: %q on slot %d — want the other entry's slot, its relay untried", addr, slot)
	}
	// E's answer is the evidence: O marked; conn 0 stays on E.
	cp.noteAllocatedAt(1, c0, relayE, time.Now())
	if !cp.health.isDead(relayO) {
		t.Fatalf("O not marked after E answered")
	}
	// With NO alternative left (E silent too, nothing marked) the silent own
	// relay is dialled again — the list is cycled, not minted around.
	cp2 := newCredPool(ctx, 4, 2*time.Minute, "", nil)
	cp2.setOverride(turnOverride{servers: list})
	cp2.mu.Lock()
	cp2.placeLocked(0, credPoolEntry{addr: relayO, addrs: cp2.candidatesForSlot(0, own), creds: own, ts: time.Now()})
	cp2.placeLocked(1, credPoolEntry{addr: relayE, addrs: cp2.candidatesForSlot(1, e), creds: e, ts: time.Now()})
	cp2.mu.Unlock()
	cp2.health.unanswered(relayO, cp2.health.now())
	cp2.health.unanswered(relayE, cp2.health.now())
	addr, c, slot := mustGet(t, cp2, 0)
	if slot != 0 || addr != relayO {
		t.Fatalf("conn 0 with O and E both silent: %q on slot %d — want its own slot's O (nothing untried is left; the list is cycled)", addr, slot)
	}
	// CYCLED: the user's review of ddb1fc1 — the own slot preferred for ever
	// dialled O, O, O while E had come back. Every unanswered attempt moves the
	// connection's cursor, and the cursor walks the silent slots: O, E, O, E.
	cp2.release(0, c, relayO)
	cp2.noteRelayUnanswered(0, 0, c, relayO, time.Now())
	addr, c, slot = mustGet(t, cp2, 0)
	if slot != 1 || addr != relayE {
		t.Fatalf("conn 0 after another silent attempt on O: %q on slot %d — want E's slot next (the silent slots are cycled)", addr, slot)
	}
	cp2.release(1, c, relayE)
	cp2.noteRelayUnanswered(0, 1, c, relayE, time.Now())
	addr, c, slot = mustGet(t, cp2, 0)
	if slot != 0 || addr != relayO {
		t.Fatalf("conn 0 after a silent attempt on E: %q on slot %d — want O's slot again", addr, slot)
	}
	// E back: its answer to the next attempt clears its record (untried — the
	// first round) and marks O.
	cp2.release(0, c, relayO)
	cp2.noteRelayUnanswered(0, 0, c, relayO, time.Now())
	addr, c, slot = mustGet(t, cp2, 0)
	if slot != 1 || addr != relayE {
		t.Fatalf("conn 0: %q on slot %d — want E's slot", addr, slot)
	}
	cp2.noteAllocatedAt(1, c, relayE, time.Now())
	if !cp2.health.isDead(relayO) {
		t.Fatalf("O not marked after E answered")
	}
	cp2.release(1, c, relayE)
	if addr, _, slot := mustGet(t, cp2, 0); slot != 1 || addr != relayE {
		t.Fatalf("conn 0 with E back and O marked: %q on slot %d — want E", addr, slot)
	}
}

// The hand-out's pick and its peek select the relay by ONE rule in every
// state of the own relay: untried, silent, marked, answered again.
func TestTheHandOutAndItsPeekSelectTheRelayAlike(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	list, _ := ParseTURNServers(relayO + ":0," + TURNServersVK)
	cp.setOverride(turnOverride{servers: list})
	cp.mu.Lock()
	defer cp.mu.Unlock()
	check := func(state string, wantO bool) {
		t.Helper()
		for conn := 0; conn < 4; conn++ {
			cp.cursor[conn] = conn
			peek := cp.peekAddrLocked(0, conn)
			pick, ok := cp.pickAddrLocked(0, conn)
			if !ok || peek != pick {
				t.Fatalf("%s, conn %d (cursor %d): peek %q, pick %q ok %v — one rule", state, conn, conn, peek, pick, ok)
			}
			if (pick == relayO) != wantO {
				t.Fatalf("%s, conn %d: %q — want O: %v", state, conn, pick, wantO)
			}
		}
	}
	check("O untried", true)
	cp.health.unanswered(relayO, cp.health.now())
	check("O silent, unmarked", false)
	cp.health.answered(relayA, time.Time{})
	if !cp.health.isDead(relayO) {
		t.Fatalf("O not marked by A's answer")
	}
	check("O marked", false)
	cp.health.answered(relayO, time.Time{})
	check("O answered again", true)
}

// 2026-11-01, the stands (Nov 1 §488, defect 1 — a regression of 461): the
// hand-out judges a slot on the relay the CONNECTION dials (its cursor's),
// and the cold-start cap counted the slots by the relay the SLOT dials now
// (the first alive). Under `A:20,B:2` with A silent after a path change —
// unmarked, no evidence — every slot was benched on B (its seats there) and
// free on A: "ready" to the cap, refused to the connection; nothing minted, so
// nothing answered, so A was never marked: 0/6 for two minutes where 460
// minted in five seconds. The cap counts by the question the hand-out asks,
// for this connection (the rule of builds 204 / 360, quoted in the cap's own
// comment); Phase 2's second pass judges the bench on that relay too.
func TestTheColdStartCapCountsByTheRelayTheConnectionDials(t *testing.T) {
	for _, size := range []int{2, 3} { // 2: no empty slot (the second pass must take the benched one); 3: the cap alone
		t.Run(fmt.Sprintf("pool-%d", size), func(t *testing.T) {
			// A ready cache: a mint would be the evidence that marks A (rule 24
			// in the pool — the refused arm runs on a cache that needs no mint).
			path := writeCache(t, t.TempDir(),
				credCacheEntry{Slot: 0, Address: relayC, Addresses: []string{relayC}, Username: futureUser("cached-0"), Password: "p"},
				credCacheEntry{Slot: 1, Address: relayC, Addresses: []string{relayC}, Username: futureUser("cached-1"), Password: "p"})
			cp, mints, _ := relayPoolN(t, path, size, relayC)
			list, _ := ParseTURNServers(relayA + ":20," + relayB + ":2")
			cp.setOverride(turnOverride{servers: list})
			// Two slots, each with its two seats on B: the connections' attempts
			// on A went unanswered without evidence, their cursors moved to B.
			held := map[int]*TURNCreds{}
			for conn := 0; conn < 4; conn++ {
				addr, creds, slot := mustGet(t, cp, conn)
				if addr != relayA {
					t.Fatalf("conn %d: %q — want A first", conn, addr)
				}
				cp.release(slot, creds, relayA)
				cp.noteRelayUnanswered(conn, slot, creds, relayA, time.Now())
				addr, creds, slot = mustGet(t, cp, conn)
				if addr != relayB || slot != conn/2 {
					t.Fatalf("conn %d after A went silent: %q on slot %d — want B on slot %d", conn, addr, slot, conn/2)
				}
				held[conn] = creds
			}
			if cp.health.isDead(relayA) || mints.Load() != 0 {
				t.Fatalf("A marked %v, mints %d — want A unmarked (no evidence), the two cached credentials", cp.health.isDead(relayA), mints.Load())
			}
			// The path change: both slots benched on B, the cursors and the
			// evidence cleared; the sessions give their seats back.
			cp.MarkInUseSlotsForPathChange()
			cp.mu.Lock()
			cp.pauseAcquireUntil = time.Time{}
			benched := cp.markLocked(0, relayB).After(time.Now()) && cp.markLocked(1, relayB).After(time.Now()) && cp.markLocked(0, relayA).IsZero()
			cp.mu.Unlock()
			if !benched {
				t.Fatalf("after the path change the slots are not benched on B alone")
			}
			for conn := 0; conn < 4; conn++ {
				cp.release(conn/2, held[conn], relayB)
			}
			// A first again, silent again, still no evidence: conn 0's cursor
			// moves to B, where the slot is benched — a MINT, not a park.
			addr, creds, slot := mustGet(t, cp, 0)
			if addr != relayA {
				t.Fatalf("conn 0 after the path change: %q — want A first", addr)
			}
			cp.release(slot, creds, relayA)
			cp.noteRelayUnanswered(0, slot, creds, relayA, time.Now())
			addr, creds, slot, err := cp.get(0, false)
			if err != nil {
				t.Fatalf("conn 0 with the slots benched on B and free on silent A: %v — want a fresh credential (the cap counted the slots ready on A)", err)
			}
			if mints.Load() != 1 || creds.Username == held[0].Username || creds.Username == held[2].Username {
				t.Fatalf("conn 0: %q on slot %d, mints %d — want a fresh credential", addr, slot, mints.Load())
			}
		})
	}
}

// The predicate itself: one slot, benched on B and free on A — ready to the
// connection whose cursor is on A, not to the one whose cursor is on B; and
// the slot-level count (the grower, the UI) is the slot's own question.
func TestASlotCountsAsReadyForTheConnectionItCanSeat(t *testing.T) {
	cp, _, _ := relayPoolN(t, "", 2, relayC)
	list, _ := ParseTURNServers(relayA + ":20," + relayB + ":2")
	cp.setOverride(turnOverride{servers: list})
	_, creds, _ := mustGet(t, cp, 0)
	cp.release(0, creds, relayA)
	cp.markSaturated(0, creds, relayB)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.cursor[0], cp.cursor[1] = 0, 1
	if !cp.availableForLocked(0, 0) || cp.availableForLocked(0, 1) {
		t.Fatalf("slot 0 benched on B: ready for conn 0 (on A) %v, for conn 1 (on B) %v — want true, false", cp.availableForLocked(0, 0), cp.availableForLocked(0, 1))
	}
	if cp.countAvailableForLocked(0) != 1 || cp.countAvailableForLocked(1) != 0 || cp.countAvailableLocked() != 1 {
		t.Fatalf("counts: for conn 0 %d, for conn 1 %d, the slot's own %d — want 1, 0, 1", cp.countAvailableForLocked(0), cp.countAvailableForLocked(1), cp.countAvailableLocked())
	}
}

// A FULL slot is provisioned to the cap (room is not its question): with the
// one credential the target needs holding every seat, the eleventh connection
// parks to share, it does not mint — the herd's rule.
func TestAFullSlotIsProvisionedToTheColdStartCap(t *testing.T) {
	cp, mints, _ := relayPoolN(t, "", 3, relayC)
	cp.setColdStartTarget(10)
	for conn := 0; conn < connsPerSlot; conn++ {
		if _, _, slot := mustGet(t, cp, conn); slot != 0 {
			t.Fatalf("conn %d on slot %d", conn, slot)
		}
	}
	_, _, _, err := cp.get(10, false)
	if err == nil || !strings.Contains(err.Error(), "cold-start cap") || mints.Load() != 1 {
		t.Fatalf("conn 10 with the one credential full: err %v, mints %d — want the cold-start cap's park, one credential", err, mints.Load())
	}
}

// Cookie mode: a slot dials one relay — the connection's question and the
// slot's are one, and the two counts agree.
func TestCookieModeTheCapsCountIsTheSlotsOwn(t *testing.T) {
	cookieTestMode(t, "https://vk.ru/call/join/aaa")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 2, 2*time.Minute, "", nil)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for i, r := range []string{relayA, relayB} {
		c := &TURNCreds{Username: futureUser("vk"), Password: "p", Address: r, Addresses: []string{r}}
		cp.placeLocked(i, credPoolEntry{addr: r, addrs: cp.candidatesForSlot(i, c), creds: c, ts: time.Now()})
	}
	cp.pool[1].saturatedUntil = time.Now().Add(time.Minute)
	for conn := 0; conn < 3; conn++ {
		cp.cursor[conn] = conn
		if cp.countAvailableForLocked(conn) != cp.countAvailableLocked() || cp.countAvailableLocked() != 1 {
			t.Fatalf("conn %d: the cap's count %d, the slot's own %d — want both 1", conn, cp.countAvailableForLocked(conn), cp.countAvailableLocked())
		}
	}
}

// A slot whose every relay is marked has nothing to dial — not ready to the
// cap either: with the one credential the target needs in that state the
// connection mints (a fresh credential may name other relays), it does not
// park to share what nobody can use.
func TestASlotWithEveryRelayMarkedIsNotReadyToTheColdStartCap(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPoolN(t, path, 1, relayC)
	cp.health.answered("", time.Time{}) // the evidence
	cp.health.unanswered(relayA, cp.health.now())
	cp.health.unanswered(relayB, cp.health.now())
	cp.mu.Lock()
	ready := cp.availableForLocked(0, 0)
	cp.mu.Unlock()
	if ready || !cp.health.isDead(relayA) || !cp.health.isDead(relayB) {
		t.Fatalf("slot 0 with A and B marked (%v, %v): ready for conn 0 %v — want not ready", cp.health.isDead(relayA), cp.health.isDead(relayB), ready)
	}
	if addr, _, _, err := cp.get(0, false); err != nil || addr != relayC || mints.Load() != 1 {
		t.Fatalf("conn 0 with the one slot's relays all marked: %q, %v, mints %d — want a fresh credential on %s", addr, err, mints.Load(), relayC)
	}
}

// 2026-11-07, the user's design: an entry may carry a FOURTH field,
// host:port:quota:pace — the pace of the relay's connections in KiB/s of
// counted bytes, in both directions: the client's uplink bucket on that
// relay takes it, and the client declares it to the server for the downlink
// (groupPaceMagic). 0 = no pacer (the user's own relay has no per-allocation
// policer — §562: the uplink pacer cost 224 → 72 there); absent = the default
// (the app's uplink toggle; the server's -downlink-pace). The field rides on
// the quota field: the pace of a relay is a property of the relay, and the
// relay without a quota is the one that wants it.
func TestParseTURNServersAcceptsAPace(t *testing.T) {
	got, err := ParseTURNServers("relay.example:19302:0:0, 203.0.113.5:3478:25:500,$vkurls, 203.0.113.5:3478:7:0")
	if err != nil || strings.Join(got, ",") != "relay.example:19302:0:0,203.0.113.5:3478:25:500,"+TURNServersVK {
		t.Fatalf("%v %v — want the pace fields kept, the second spelling of one address dropped", got, err)
	}
	for _, tc := range []struct {
		entry string
		want  turnEntry
	}{
		{"relay.example:19302:0:0", turnEntry{addr: "relay.example:19302", hasQuota: true, hasPace: true}},
		{"203.0.113.5:3478:25:500", turnEntry{addr: "203.0.113.5:3478", quota: 25, hasQuota: true, pace: 500, hasPace: true}},
		{"203.0.113.5:3478:25", turnEntry{addr: "203.0.113.5:3478", quota: 25, hasQuota: true}},
		{"203.0.113.5:3478", turnEntry{addr: "203.0.113.5:3478"}},
		{"[2001:db8::1]:19302:3:247", turnEntry{addr: "[2001:db8::1]:19302", quota: 3, hasQuota: true, pace: 247, hasPace: true}},
	} {
		got, ok := parseTURNEntry(tc.entry)
		if !ok || got != tc.want {
			t.Fatalf("%q → %+v %v, want %+v", tc.entry, got, ok, tc.want)
		}
		if got.String() != tc.entry {
			t.Fatalf("%q spelled back as %q", tc.entry, got.String())
		}
	}
	// A pace rides on a quota field: no pace without one; digits only; no
	// fifth field; and no more than the wire's uint16 (65535 KiB/s) — the
	// user's review of 9d58dda: the parser took 100000, the uplink paced at
	// it and the declaration clamped it, two rates for one field.
	if _, err := ParseTURNServers("relay.example:19302:0:65535"); err != nil {
		t.Fatalf("the field's ceiling rejected: %v", err)
	}
	for _, bad := range []string{"relay.example:19302:0:x", "relay.example:19302:0:-1", "relay.example:19302:0:", "relay.example:19302:0:1:2", "relay.example:19302::500", "relay.example:19302:0:65536", "relay.example:19302:0:100000"} {
		if _, err := ParseTURNServers(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestResolveTURNServersKeepsThePace(t *testing.T) {
	pre := func(host string) []string {
		if host == nameHost {
			return []string{ipR1, ipR2}
		}
		return nil
	}
	got := ResolveTURNServers(context.Background(), []string{nameRelay + ":0:0", "203.0.113.5:3478:25:500", "203.0.113.6:3478:10"}, pre)
	if strings.Join(got, ",") != ipR1+":19302:0:0,"+ipR2+":19302:0:0,203.0.113.5:3478:25:500,203.0.113.6:3478:10" {
		t.Fatalf("resolved: %v — want the name's IPs each with the name's quota and pace", got)
	}
	o := turnOverride{}
	o.setServers(got)
	if p, ok := o.pace(ipR1 + ":19302"); !ok || p != 0 {
		t.Fatalf("the pace of the first IP: %d %v, want 0 (no pacer), set", p, ok)
	}
	if p, ok := o.pace("203.0.113.5:3478"); !ok || p != 500 {
		t.Fatalf("the pace of the second entry: %d %v, want 500", p, ok)
	}
	if _, ok := o.pace("203.0.113.6:3478"); ok {
		t.Fatal("an entry without the field has a pace")
	}
	if q, ok := o.quota("203.0.113.5:3478"); !ok || q != 25 {
		t.Fatalf("the quota beside the pace: %d %v, want 25", q, ok)
	}
	if c := o.candidatesFor(&TURNCreds{Addresses: []string{relayA}}); strings.Join(c, ",") != ipR1+":19302,"+ipR2+":19302,203.0.113.5:3478,203.0.113.6:3478" {
		t.Fatalf("the candidates carry no field: %v", c)
	}
	// The pool answers for its override under its lock.
	cp := &credPool{}
	cp.override = o
	if p, ok := cp.relayPace("203.0.113.5:3478"); !ok || p != 500 {
		t.Fatalf("the pool's relayPace: %d %v, want 500", p, ok)
	}
}

// A re-resolution of a NAME keeps the name's pace on its new IPs (the user's
// review of 9d58dda): reresolveOverride replaced the addresses and the
// quotas and left the old paces map — a relay that moved from A to B was
// handed out as B with no pace, the uplink back at the toggle and nothing
// declared to the server.
func TestAReresolutionKeepsTheRelaysPace(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	old := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = old })
	answer := ipR2
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
		if host != nameHost {
			return nil, errors.New("unknown host")
		}
		return []net.IP{net.ParseIP(answer)}, nil
	}
	cp.setOverride(turnOverride{servers: []string{ipR1 + ":19302:0:500", TURNServersVK}, raw: []string{nameRelay + ":0:500", TURNServersVK}})
	if kib, ok := cp.relayPace(ipR1 + ":19302"); !ok || kib != 500 {
		t.Fatalf("before: the pace of %s is %d %v, want 500", ipR1, kib, ok)
	}
	cp.reresolveOverride("test", false)
	if got := strings.Join(cp.overrideServers(), ","); got != ipR2+":19302,"+TURNServersVK {
		t.Fatalf("the list after the re-resolution: %s", got)
	}
	if kib, ok := cp.relayPace(ipR2 + ":19302"); !ok || kib != 500 {
		t.Fatalf("after: the pace of %s is %d %v, want the name's 500", ipR2, kib, ok)
	}
	if q, ok := cp.override.quota(ipR2 + ":19302"); !ok || q != 0 {
		t.Fatalf("after: the quota of %s is %d %v, want the name's 0", ipR2, q, ok)
	}
}

// An entry the parser does not read is DROPPED, never dialled (the user's
// review of 7271aef): the app's list reaches the pool through
// ResolveTURNServers and setServers, which kept an unparsable entry «as an
// unresolved name» — a `host:port:10:65536` the app's validator let through
// (its host:port check split on the last colon) became a dial target.
func TestAnUnparsableOverrideEntryIsDroppedNotDialled(t *testing.T) {
	bad := "relay.example:19302:10:65536"
	got := ResolveTURNServers(context.Background(), []string{bad, relayA, "x:1:2:3:4"}, nil)
	if strings.Join(got, ",") != relayA {
		t.Fatalf("resolved: %v — want the unparsable entries dropped, %s alone", got, relayA)
	}
	o := turnOverride{}
	o.setServers([]string{bad, relayA, TURNServersVK})
	if strings.Join(o.servers, ",") != relayA+","+TURNServersVK {
		t.Fatalf("setServers kept an unparsable entry as an address: %v", o.servers)
	}
	// A NAME that did not resolve is not unparsable: it stays, as before.
	o.setServers([]string{nameRelay + ":0:500", relayA})
	if strings.Join(o.servers, ",") != nameRelay+","+relayA {
		t.Fatalf("an unresolved name was dropped: %v", o.servers)
	}
}
