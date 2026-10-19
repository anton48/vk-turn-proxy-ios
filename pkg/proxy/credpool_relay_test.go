package proxy

// Unreachable TURN relays (issues #98 and #102, 2026-10-19): the pool hands a
// connection the first relay of its credential that is not marked
// unreachable, moves it to the next candidate after an unanswered Allocate,
// marks a relay only with evidence that the network works, applies the TURN
// override list to cached credentials too, keeps a credential whose every
// relay is marked (not ready, not dropped), and keeps every VK address in the
// cache. Sabotage seen red label by label (RL series).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	relayA = "203.0.113.11:19302"
	relayB = "203.0.113.12:19302"
	relayC = "203.0.113.13:19302"
	relayO = "198.51.100.7:19302" // the override's
)

func futureUser(tag string) string {
	return fmt.Sprintf("%d:%s", time.Now().Add(8*time.Hour).Unix(), tag)
}

// relayPool: a 12-slot pool with a fake clock on its relay health and a
// minter that hands out credentials naming the given relays.
func relayPool(t *testing.T, cachePath string, relays ...string) (*credPool, *atomic.Int32, *time.Time) {
	t.Helper()
	if cachePath != "" && !strings.HasPrefix(cachePath, os.TempDir()) && !strings.Contains(cachePath, "Test") {
		t.Fatalf("a cache under a temp dir: %s", cachePath)
	}
	var mints atomic.Int32
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		n := mints.Add(1)
		return relays[0], &TURNCreds{Username: futureUser(fmt.Sprintf("minted-%d-%d", slot, n)), Password: "p",
			Address: relays[0], Addresses: append([]string(nil), relays...)}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, cachePath, fetch)
	if cachePath != "" {
		t.Cleanup(func() { cancel(); <-cp.saverDone }) // before the temp dir goes
	}
	clock := time.Now()
	cp.health.now = func() time.Time { return clock }
	return cp, &mints, &clock
}

func writeCache(t *testing.T, dir string, entries ...credCacheEntry) string {
	t.Helper()
	path := filepath.Join(dir, "creds-pool.json")
	b, _ := json.Marshal(credCacheFile{Version: credCacheVersion, SavedAt: time.Now().Unix(), Mode: credCacheModeAnon, Creds: entries})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustGet(t *testing.T, cp *credPool, conn int) (string, *TURNCreds, int) {
	t.Helper()
	addr, creds, slot, err := cp.get(conn, false)
	if err != nil {
		t.Fatalf("get(%d): %v", conn, err)
	}
	return addr, creds, slot
}

// Issue #102: the override reaches a CACHED credential — the address is
// chosen when the credential is handed out, not baked in at the mint.
func TestTheOverrideListReachesACachedCredential(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO}})
	addr, creds, _ := mustGet(t, cp, 0)
	if addr != relayO || !strings.HasSuffix(creds.Username, ":cached") || mints.Load() != 0 {
		t.Fatalf("a cached credential under the override list: addr %q user %q mints %d — want the override's relay on the cached credential, no mint", addr, creds.Username, mints.Load())
	}
	// Without an override the cached credential is dialled on VK's own first.
	cp.setOverride(turnOverride{})
	if addr, _, _ := mustGet(t, cp, 1); addr != relayA {
		t.Fatalf("no override: %q, want VK's first %q", addr, relayA)
	}
}

// Issue #98: an Allocate that got no answer moves the connection to the next
// candidate at once — and with no evidence that the network works nothing is
// marked; the mark comes when another relay answers.
func TestAnUnansweredRelayMovesTheConnectionOnAndIsMarkedByEvidence(t *testing.T) {
	// A cached credential: nothing has answered in this process yet (a mint
	// would be VK answering — evidence).
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA {
		t.Fatalf("the first attempt dials %q, want VK's first %q", addr, relayA)
	}
	cp.release(slot, creds)
	cp.noteRelayUnanswered(0, slot, creds, relayA, time.Now().Add(-5*time.Second))
	if cp.health.isDead(relayA) {
		t.Fatal("relay A marked with nothing else having answered — the failure may be the network's")
	}
	if addr, _, _ = mustGet(t, cp, 0); addr != relayB {
		t.Fatalf("the next attempt dials %q, want the next candidate %q", addr, relayB)
	}
	// Another connection, no failure of its own: still VK's first.
	if addr, _, _ = mustGet(t, cp, 1); addr != relayA {
		t.Fatalf("a connection with no failure of its own dials %q, want %q", addr, relayA)
	}
	// B answers: A, unanswered since before that answer, is marked now.
	cp.noteAllocatedAt(slot, creds, relayB)
	if !cp.health.isDead(relayA) || cp.health.isDead(relayB) {
		t.Fatalf("after B answered: A dead %v (want true), B dead %v (want false)", cp.health.isDead(relayA), cp.health.isDead(relayB))
	}
	for conn := 2; conn < 6; conn++ {
		if addr, _, _ = mustGet(t, cp, conn); addr != relayB {
			t.Fatalf("conn %d dials %q after A was marked, want %q", conn, addr, relayB)
		}
	}
}

// The evidence window: an answer inside (start − 60 s, end) marks the
// unanswered relay at once; an older answer does not.
func TestAnUnansweredRelayIsMarkedOnlyWithEvidenceInsideTheWindow(t *testing.T) {
	h := newRelayHealth()
	clock := time.Now()
	h.now = func() time.Time { return clock }
	h.answered("") // VK's API answered at T
	clock = clock.Add(90 * time.Second)
	if h.unanswered(relayA, clock.Add(-29*time.Second)) { // the attempt began 61 s after the answer
		t.Fatal("an answer 61 s before the attempt began is no evidence — marked all the same")
	}
	if !h.unanswered(relayB, clock.Add(-31*time.Second)) { // began 59 s after the answer
		t.Fatal("an answer 59 s before the attempt began is evidence — not marked")
	}
	// A later answer marks A, unanswered since before it.
	h.answered(relayC)
	if !h.isDead(relayA) {
		t.Fatal("A, unanswered since before C's answer, not marked when C answered")
	}
}

// A path change clears every mark: the verdicts were about the old network.
func TestAPathChangeClearsTheRelayMarks(t *testing.T) {
	cp, _, _ := relayPool(t, "", relayA, relayB)
	_, creds, slot := mustGet(t, cp, 0)
	cp.noteAllocatedAt(slot, creds, relayB)
	cp.noteRelayUnanswered(1, slot, creds, relayA, time.Now())
	if !cp.health.isDead(relayA) {
		t.Fatal("precondition: A marked")
	}
	cp.MarkInUseSlotsForPathChange()
	if cp.health.isDead(relayA) || len(cp.cursor) != 0 {
		t.Fatalf("after a path change: A dead %v, cursors %d — want cleared", cp.health.isDead(relayA), len(cp.cursor))
	}
}

// A credential whose every relay is marked is NOT READY — skipped, kept, and
// re-tried once a mark is due; a fresh mint that names the same dead relays
// pauses the minting instead of being repeated.
func TestACredentialWithEveryRelayMarkedIsKeptNotReadyAndTheMintingPauses(t *testing.T) {
	cp, mints, clock := relayPool(t, "", relayA, relayB)
	_, creds, slot := mustGet(t, cp, 0)
	cp.release(slot, creds)
	cp.health.answered("") // evidence: VK answered just now
	cp.noteRelayUnanswered(0, slot, creds, relayA, *clock)
	cp.noteRelayUnanswered(0, slot, creds, relayB, *clock)
	if !cp.health.isDead(relayA) || !cp.health.isDead(relayB) {
		t.Fatal("precondition: both marked")
	}
	before := mints.Load()
	_, _, _, err := cp.get(1, false)
	var park *poolParkError
	if !errors.As(err, &park) || !strings.Contains(err.Error(), "marked unreachable") {
		t.Fatalf("get with every relay marked: %v — want a park naming the marks", err)
	}
	if mints.Load() != before+1 {
		t.Fatalf("%d mint(s) — want exactly one fresh mint (the dead pair may have changed)", mints.Load()-before)
	}
	if cp.pool[slot].creds == nil || cp.pool[slot].creds.Username != creds.Username {
		t.Fatal("the blocked credential was dropped — want kept, not ready")
	}
	if cp.deadMintUntil.IsZero() {
		t.Fatal("a mint that named only marked relays did not pause the minting")
	}
	// Within the pause: no second mint, a park.
	if _, _, _, err = cp.get(2, false); !errors.As(err, &park) || mints.Load() != before+1 {
		t.Fatalf("inside the pause: err %v, mints %d — want a park and no mint", err, mints.Load()-before)
	}
	// A minute on: the oldest mark is due — ONE connection re-tries it.
	*clock = clock.Add(relayProbeBackoffMin + time.Second)
	addr, _, _, err := cp.get(3, false)
	if err != nil || (addr != relayA && addr != relayB) {
		t.Fatalf("a re-try due: addr %q err %v — want one of the marked relays handed out once", addr, err)
	}
	if _, _, _, err = cp.get(4, false); err == nil {
		t.Fatal("a second connection got the relay under re-try — want the re-try reserved for one connection")
	}
}

// With the override list every candidate marked, a mint is no way out: the
// connections wait for a re-try, nothing is minted.
func TestWithTheOverrideListMarkedTheConnectionsWaitAndMintNothing(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Username: futureUser("cached"), Password: "p"})
	cp, mints, clock := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO}})
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO {
		t.Fatalf("precondition: %q", addr)
	}
	cp.release(slot, creds)
	cp.health.answered("")
	cp.noteRelayUnanswered(0, slot, creds, relayO, *clock)
	_, _, _, err := cp.get(1, false)
	if err == nil || !strings.Contains(err.Error(), "override list") || mints.Load() != 0 {
		t.Fatalf("override list all marked: err %v mints %d — want a park, no mint", err, mints.Load())
	}
	*clock = clock.Add(relayProbeBackoffMin + time.Second)
	if addr, _, _, err := cp.get(1, false); err != nil || addr != relayO {
		t.Fatalf("the re-try due: addr %q err %v", addr, err)
	}
}

// The cache keeps every VK address with the credential; a file without them
// (from before 2026-10-19) has the one address.
func TestTheCacheKeepsEveryVKAddress(t *testing.T) {
	dir := t.TempDir()
	cp, _, _ := relayPool(t, filepath.Join(dir, "creds-pool.json"), relayA, relayB)
	mustGet(t, cp, 0)
	cp.saveToDisk()
	b, err := os.ReadFile(filepath.Join(dir, "creds-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f credCacheFile
	if err := json.Unmarshal(b, &f); err != nil || len(f.Creds) != 1 {
		t.Fatalf("the cache: %v %+v", err, f)
	}
	if e := f.Creds[0]; e.Address != relayA || len(e.Addresses) != 2 || e.Addresses[1] != relayB {
		t.Fatalf("the saved entry: %+v — want address %s and both addresses", e, relayA)
	}
	// Loaded again: both candidates, the override applied on top.
	ctx, cancel := context.WithCancel(context.Background())
	var pools []*credPool
	t.Cleanup(func() { // before the temp dirs go: the savers write once more on their way out
		cancel()
		for _, p := range pools {
			<-p.saverDone
		}
	})
	cp2 := newCredPool(ctx, 12, 2*time.Minute, filepath.Join(dir, "creds-pool.json"), nil)
	pools = append(pools, cp2)
	if c := cp2.candidatesLocked(0); len(c) != 2 || c[1] != relayB {
		t.Fatalf("loaded candidates: %v", c)
	}
	cp2.setOverride(turnOverride{servers: []string{relayO}})
	if c := cp2.candidatesLocked(0); len(c) != 1 || c[0] != relayO {
		t.Fatalf("loaded candidates under the override: %v", c)
	}
	// An old file: one address.
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Username: futureUser("old"), Password: "p"})
	cp3 := newCredPool(ctx, 12, 2*time.Minute, path, nil)
	pools = append(pools, cp3)
	if c := cp3.candidatesLocked(0); len(c) != 1 || c[0] != relayA {
		t.Fatalf("an old file's candidates: %v", c)
	}
}

// What is «no answer» from a relay, and what is not.
func TestIsRelayUnanswered(t *testing.T) {
	for _, tc := range []struct {
		err  string
		want bool
	}{
		{"TURN allocate: all retransmissions failed for abc", true},
		{"dial TURN TCP: dial tcp 203.0.113.11:19302: i/o timeout", true},
		{"dial tcp to relay: dial tcp 203.0.113.11:19302: connect: connection refused", true},
		{"TURN allocate: Allocate error response (error 486: Allocation Quota Reached)", false},
		{"TURN allocate: Allocate error response (error 401: Unauthorized)", false},
		{"turn allocate: error 437: Invalid allocation", false},
		// A route error is «no answer» too: an ISP's null route for ONE relay
		// (issue #98) reads as this on the stand — FreeBSD's blackhole route
		// gave «network is unreachable» at once (2026-10-19); a network that is
		// down fails every candidate, the cursor's turn costs nothing, and a
		// mark needs evidence anyway.
		{"dial TURN UDP: dial udp: connect: network is unreachable", true},
		{"dial TURN TCP: dial tcp: connect: no route to host", true},
		{"SRTP setup: dial tcp to relay: dial tcp 203.0.113.11:19302: connect: network is unreachable", true},
		{"TURN listen: use of closed network connection", false},
		{"dial TURN TCP: dial tcp 203.0.113.11:19302: operation was canceled", false},
		{"TURN allocate: context canceled", false},
	} {
		if got := isRelayUnanswered(errors.New(tc.err)); got != tc.want {
			t.Errorf("isRelayUnanswered(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
	if isRelayUnanswered(nil) {
		t.Error("nil")
	}
}

// The override list as the app's setting and the console's flag spell it.
func TestParseTURNServers(t *testing.T) {
	got, err := ParseTURNServers(" 198.51.100.7:19302, 198.51.100.8:3478\n198.51.100.7:19302 ")
	if err != nil || len(got) != 2 || got[0] != "198.51.100.7:19302" || got[1] != "198.51.100.8:3478" {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := ParseTURNServers(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"198.51.100.7", "198.51.100.7:port", ":19302", "198.51.100.7:70000"} {
		var e *TURNServerListError
		if _, err := ParseTURNServers(bad); !errors.As(err, &e) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Every way a relay leg fails before its allocation goes through
// relayUnanswered, so an unanswered relay reaches the pool from every site —
// pinned by spelling: runTURN's three dial errors and its Allocate,
// setupSRTPSession's two dials and its Allocate. Sabotage seen red: a site's
// error returned bare.
func TestEveryRelayLegFailureIsToldToTheRelayHealth(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	turn := goFuncBody(t, "proxy.go", "func (p *Proxy) runTURN(")
	srtp := goFuncBody(t, "proxy.go", "func (p *Proxy) setupSRTPSession(")
	for _, tc := range []struct {
		body, name string
		calls      int
		slot       string
	}{
		{turn, "runTURN", 4, "p.relayUnanswered(connIdx, slotIdx, creds, turnAddr, attempt, "},
		{srtp, "setupSRTPSession", 3, "p.relayUnanswered(connIdx, credSlot, creds, turnAddr, attempt, "},
	} {
		if n := strings.Count(tc.body, tc.slot); n != tc.calls {
			t.Errorf("%s: %d relay-leg failures told to the relay health, want %d", tc.name, n, tc.calls)
		}
		for _, bare := range []string{`return fmt.Errorf("dial TURN`, `return fmt.Errorf("TURN allocate`, `return nil, fmt.Errorf("dial tcp to relay`, `return nil, fmt.Errorf("udp to relay`, `return nil, fmt.Errorf("turn allocate`} {
			if strings.Contains(tc.body, bare) {
				t.Errorf("%s returns a relay-leg failure bare: %s", tc.name, bare)
			}
		}
		if !strings.Contains(tc.body, "attempt := time.Now()") {
			t.Errorf("%s does not stamp when its relay attempt began", tc.name)
		}
	}
	if !strings.Contains(code, "if isRelayUnanswered(err) {\n\t\tp.credPool.noteRelayUnanswered(connIdx, slot, creds, turnAddr, attempt)") {
		t.Error("relayUnanswered does not hand an unanswered relay to the pool")
	}
	bridge, err := os.ReadFile("../../WireGuardBridge/csqtt_bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bridge), "case proxy.IsRelayUnanswered(err):\n\t\ta.pool.NoteRelayUnanswered(connIdx, slot, creds, addr, attempt)") {
		t.Error("csqtt_bridge.go: the adapter does not hand an unanswered relay to the pool")
	}
}

// Cookie mode: a slot IS a relay. With an override list the slots are made of
// the list — slot s dials its s-th entry, a seed in slot 0 included — and a
// list shorter than the slots asked for leaves the rest unfilled, as a short
// relay set does. Sabotage seen red: the list ignored in cookie mode; the
// shortage not refused.
func TestCookieModeSlotsFollowTheOverrideList(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}
	SetVKCookieAuth(true, "remixsid=x", links)
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	// The mints cached: no network.
	cookieMu.Lock()
	for _, l := range cookieLinks() {
		cookieCache[l] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("cookie-" + l[len(l)-6:]), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	}
	cookieMu.Unlock()
	override := []string{relayO, relayC}
	for slot, want := range override {
		c, err := cookieCredForSlot(context.Background(), slot, override)
		if err != nil || c.Address != want || len(c.Addresses) != 1 || c.Addresses[0] != want {
			t.Fatalf("slot %d under the list: %+v %v — want %s", slot, c, err, want)
		}
	}
	if _, err := cookieCredForSlot(context.Background(), 2, override); err == nil || !strings.Contains(err.Error(), "unfilled") {
		t.Fatalf("slot 2 with a two-entry list: %v — want the shortage refused", err)
	}
	// Without the list: VK's distinct relays, as before.
	if c, err := cookieCredForSlot(context.Background(), 1, nil); err != nil || c.Address != relayB {
		t.Fatalf("slot 1 without a list: %+v %v — want VK's second relay", c, err)
	}
	// The pool in cookie mode: a seed in slot 0 takes the list's first; its
	// own address without a list.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := newCredPool(ctx, 4, 2*time.Minute, "", nil)
	if cp.mode != credCacheModeCookie {
		t.Fatalf("mode %q", cp.mode)
	}
	cp.setOverride(turnOverride{servers: override})
	seed := &TURNCreds{Username: futureUser("seed"), Password: "p", Address: relayA, Addresses: []string{relayA}}
	cp.seedSlot(0, relayA, seed)
	if c := cp.candidatesLocked(0); len(c) != 1 || c[0] != relayO {
		t.Fatalf("the cookie seed's candidates under the list: %v, want [%s]", c, relayO)
	}
	cp.setOverride(turnOverride{})
	if c := cp.candidatesLocked(0); len(c) != 1 || c[0] != relayA {
		t.Fatalf("the cookie seed's candidates without a list: %v, want [%s]", c, relayA)
	}
}

// A cached credential with ONE relay (a file from before 2026-10-19, or a
// pair whose other half is marked): when it goes unanswered and nothing else
// has answered, the pool does not dial it until the credential expires — the
// credential is not ready and a fresh mint is made; VK's answer is the
// evidence that marks the silent relay, and the fresh credential's other
// relay is dialled. Seen on ams-int 2026-10-19 (3 of 3 attempts on the dead
// relay before this). Sabotage seen red: a silent candidate still worth a try.
func TestASilentOnlyCandidateMakesThePoolMint(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayA, relayB) // VK keeps returning the same pair, A first
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA || mints.Load() != 0 {
		t.Fatalf("precondition: %q mints %d", addr, mints.Load())
	}
	cp.release(slot, creds)
	cp.noteRelayUnanswered(0, slot, creds, relayA, time.Now().Add(-5*time.Second))
	if cp.health.isDead(relayA) {
		t.Fatal("A marked with no evidence")
	}
	addr, creds2, _ := mustGet(t, cp, 0)
	if mints.Load() != 1 || creds2.Username == creds.Username {
		t.Fatalf("the next ask: mints %d, user %q — want one fresh mint instead of the silent relay again", mints.Load(), creds2.Username)
	}
	if addr != relayB || !cp.health.isDead(relayA) {
		t.Fatalf("the fresh credential dialled on %q, A dead %v — want B, A marked by VK's answer", addr, cp.health.isDead(relayA))
	}
	if cp.pool[slot].creds == nil || cp.pool[slot].creds.Username != creds.Username {
		t.Fatal("the cached credential was dropped — want kept (not ready, not dropped)")
	}
}

// With the override LIST there is nothing to mint for: a list whose entries
// all went unanswered is cycled through again, no mint.
func TestTheOverrideListIsCycledAgainWhenEveryEntryWentUnanswered(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Username: futureUser("cached"), Password: "p"})
	cp, mints, _ := relayPool(t, path, relayC)
	cp.setOverride(turnOverride{servers: []string{relayO}})
	addr, creds, slot := mustGet(t, cp, 0)
	cp.release(slot, creds)
	cp.noteRelayUnanswered(0, slot, creds, addr, time.Now())
	if addr, _, _ := mustGet(t, cp, 0); addr != relayO || mints.Load() != 0 {
		t.Fatalf("after the list's one entry went unanswered: %q, mints %d — want the entry again, no mint", addr, mints.Load())
	}
}
