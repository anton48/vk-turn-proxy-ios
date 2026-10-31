// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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
	cp.release(0, held[1], "")
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
