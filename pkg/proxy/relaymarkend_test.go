// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// 2026-11-07, the failover run on 476 (Nov 7 §591): the own relay black-holed,
// ONE mark at +66 s on VK's answer — and the forty sessions still on it came
// back +66 … +138 s, in the waves of each session's own kernel giving up
// (Nov 2 §517's picture). The pool KNEW the relay was dead from the mark on;
// now a relay marked UNREACHABLE ends every live session still seated on it
// at once, and each re-dials through its cursor to the next address — the
// restart is a REQUEST (as a path restart's), never a failure.

// The pool tells the proxy which relay each connection was handed
// (resolveTURNAddr, the one hand-out site), the proxy ends the sessions on a
// relay when asked, and forgets a connection's relay with its session.
func TestAMarkedRelayEndsTheSessionsStillOnIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, connEpoch: make([]int64, 4), connCancel: make([]func(), 4), connRelay: make([]string, 4)}
	var ended [4]int
	for i := 0; i < 3; i++ {
		i := i
		p.beginConnSession(i, func() { ended[i]++ })
	}
	p.setConnRelay(0, relayA)
	p.setConnRelay(1, relayA)
	p.setConnRelay(2, relayB)
	// conn 3: no session.
	if n := p.endSessionsOnRelay(relayA, p.relayHandSeq.Load()); n != 2 || ended != [4]int{1, 1, 0, 0} {
		t.Fatalf("ended %d, cancels %v — want the two sessions on A and nothing else", n, ended)
	}
	// A session that ended forgets its relay: the next mark finds nothing of it.
	p.endConnSession(0)
	if r, _ := p.connRelayOf(0); r != "" {
		t.Fatalf("conn 0's relay after its session ended: %q", r)
	}
	if n := p.endSessionsOnRelay(relayA, p.relayHandSeq.Load()); n != 1 || ended[0] != 1 {
		t.Fatalf("the second mark ended %d (conn 0 again: %d) — want conn 1 alone, conn 0's old cancel never again", n, ended[0])
	}
	if p.endSessionsOnRelay("203.0.113.99:1", p.relayHandSeq.Load()) != 0 {
		t.Fatal("a relay nobody is on ended something")
	}
}

func TestTheHandOutRecordsTheConnectionsRelay(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	list, err := ParseTURNServers(relayO + ":0," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	p := &Proxy{credPool: cp, connEpoch: make([]int64, 8), connCancel: make([]func(), 8), connRelay: make([]string, 8)}
	addr, _, _, err := p.resolveTURNAddr(3, false)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := p.connRelayOf(3); !ok || r != addr {
		t.Fatalf("conn 3's relay after the hand-out: %q %v, want %q", r, ok, addr)
	}
	if _, _, _, err := p.resolveTURNAddr(-1, false); err != nil {
		t.Fatal(err)
	}
}

// Both ways a relay gets marked fire the hook once per newly marked address —
// the failing attempt's own verdict (noteRelayUnanswered with evidence) and
// another relay's answer marking what was left unanswered (noteAllocatedAt) —
// OUTSIDE the pool's lock (the hook ends sessions, whose re-dials ask the
// pool); «no verdict» and «not marked» fire nothing.
func TestAMarkFiresTheHookOncePerRelayOutsideTheLock(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	clock := time.Now()
	cp.health.now = func() time.Time { return clock }
	var got []string
	underLock := 0
	cp.onRelayMarked = func(addr string, stamp uint64) {
		got = append(got, addr)
		// The hook's re-dials take the pool's lock: fired under it they would
		// deadlock. Asked with TryLock so that the sabotage reads as a FAIL
		// line and not as a hung test binary (a goroutine parked on the lock
		// held the fixture's cleanup for ever — seen 2026-11-07).
		if cp.mu.TryLock() {
			cp.mu.Unlock()
		} else {
			underLock++
		}
	}
	bounded := func(name string, f func()) {
		f()
		if underLock > 0 {
			t.Fatalf("%s fired the hook UNDER the pool's lock", name)
		}
	}
	// (1) The failing attempt's own verdict: B answered after O's attempt began.
	cp.health.answered(relayB, time.Time{})
	clock = clock.Add(10 * time.Second)
	begun := clock
	clock = clock.Add(2 * time.Second)
	cp.health.answered(relayB, time.Time{})
	clock = clock.Add(3 * time.Second)
	bounded("noteRelayUnanswered", func() { cp.noteRelayUnanswered(1, 0, nil, relayO, begun) })
	if strings.Join(got, ",") != relayO {
		t.Fatalf("after the marking verdict the hook saw %v, want %s once", got, relayO)
	}
	// The same relay again: already dead, no second firing.
	bounded("noteRelayUnanswered again", func() { cp.noteRelayUnanswered(2, 0, nil, relayO, clock) })
	if len(got) != 1 {
		t.Fatalf("a mark on a dead relay fired again: %v", got)
	}
	// (2) No evidence yet → not marked → nothing; then another relay's answer
	// marks it → the hook once.
	cp.health.pathChanged()
	got = nil
	clock = clock.Add(70 * time.Second)
	begun = clock
	clock = clock.Add(5 * time.Second)
	bounded("noteRelayUnanswered without evidence", func() { cp.noteRelayUnanswered(3, 0, nil, relayC, begun) })
	if len(got) != 0 {
		t.Fatalf("an unmarked relay fired the hook: %v", got)
	}
	addr, creds, slot := mustGet(t, cp, 4)
	bounded("noteAllocatedAt", func() { cp.noteAllocatedAt(slot, creds, addr, time.Time{}) })
	if strings.Join(got, ",") != relayC {
		t.Fatalf("after another relay's answer the hook saw %v, want %s once", got, relayC)
	}
}

// The wiring: the hand-out records the relay, NewProxy hands the pool the
// proxy's ending as the hook.
func TestTheRelayMarkEndingIsWired(t *testing.T) {
	b, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{"p.setConnRelay(connIdx, addr)", "p.credPool.onRelayMarked = func(addr string, stamp uint64) { p.endSessionsOnRelay(addr, stamp) }", "p.credPool.markStamp = p.relayHandSeq.Load"} {
		if strings.Count(src, want) != 1 {
			t.Errorf("proxy.go holds %d × %q, want 1", strings.Count(src, want), want)
		}
	}
}

// The user's review of 589dfb2, two findings.
//
// (1) VK's API answering is the THIRD way a relay gets marked (noteVKAnsweredLocked,
// called under the pool's lock from get and tryFill): a relay unanswered with no
// evidence yet, then a successful mint — marked, and 589dfb2 fired nothing; a later
// Allocate on another relay could not help (the relay already in the dead set, so
// never «newly» dead). The VK path fires the hook too — outside the lock, from a
// goroutine, since its callers hold the lock across several returns.
func TestAVKAnswerThatMarksARelayEndsItsSessions(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	clock := time.Now()
	cp.health.now = func() time.Time { return clock }
	got := make(chan string, 4)
	underLock := make(chan bool, 4)
	cp.onRelayMarked = func(addr string, stamp uint64) {
		if cp.mu.TryLock() {
			cp.mu.Unlock()
			underLock <- false
		} else {
			underLock <- true
		}
		got <- addr
	}
	// O unanswered with no evidence inside the window: not marked, nothing fired.
	cp.noteRelayUnanswered(1, 0, nil, relayO, clock)
	clock = clock.Add(5 * time.Second)
	select {
	case a := <-got:
		t.Fatalf("an unmarked relay fired the hook: %s", a)
	case <-time.After(200 * time.Millisecond):
	}
	// VK's API answers (a mint): O is marked by it — the hook fires once, outside the lock.
	cp.mu.Lock()
	cp.noteVKAnsweredLocked(time.Time{})
	cp.mu.Unlock()
	select {
	case a := <-got:
		if a != relayO {
			t.Fatalf("the hook saw %s, want %s", a, relayO)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VK's answer marked O and the hook never fired")
	}
	if <-underLock {
		t.Fatal("the VK path fired the hook under the pool's lock")
	}
	select {
	case a := <-got:
		t.Fatalf("a second firing: %s", a)
	case <-time.After(200 * time.Millisecond):
	}
}

// (2) A notice that arrives late — the mark made, the lock released, a path change
// clearing the marks, a NEW session handed the same relay and allocated — must not
// end that new session. The notice carries the proxy's hand-out stamp as it stood at
// the mark (read under the pool's lock through markStamp), and the ending spares
// every session handed its relay after it.
func TestALateNoticeSparesASessionHandedTheRelayAfterTheMark(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, connEpoch: make([]int64, 3), connCancel: make([]func(), 3), connRelay: make([]string, 3), connRelaySeq: make([]uint64, 3)}
	var ended [3]int
	for i := 0; i < 3; i++ {
		i := i
		p.beginConnSession(i, func() { ended[i]++ })
	}
	p.setConnRelay(0, relayA)
	p.setConnRelay(1, relayA)
	stamp := p.relayHandSeq.Load() // the mark happens here
	p.setConnRelay(2, relayA)      // handed A after the mark (a path change cleared it, say)
	if n := p.endSessionsOnRelay(relayA, stamp); n != 2 || ended != [3]int{1, 1, 0} {
		t.Fatalf("ended %d, cancels %v — want the two sessions handed A before the mark, the later one spared", n, ended)
	}
	// The ended sessions end (production: endConnSession behind the session's
	// return); a connection handed A again later carries a fresher stamp — an
	// old notice never reaches it.
	p.endConnSession(0)
	p.endConnSession(1)
	p.beginConnSession(0, func() { ended[0]++ })
	p.setConnRelay(0, relayA)
	if n := p.endSessionsOnRelay(relayA, stamp); n != 0 {
		t.Fatalf("an old notice ended %d fresh session(s)", n)
	}
}

// The pool reads the stamp UNDER its lock, at the mark, on all three paths.
func TestTheNoticeCarriesTheStampReadAtTheMark(t *testing.T) {
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	clock := time.Now()
	cp.health.now = func() time.Time { return clock }
	var stampAt uint64 = 7
	cp.markStamp = func() uint64 { return stampAt }
	got := make(chan uint64, 8)
	cp.onRelayMarked = func(addr string, stamp uint64) { got <- stamp }
	take := func(name string) uint64 {
		select {
		case s := <-got:
			return s
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the hook never fired", name)
			return 0
		}
	}
	// The verdict path.
	cp.health.answered(relayB, time.Time{})
	clock = clock.Add(10 * time.Second)
	begun := clock
	clock = clock.Add(2 * time.Second)
	cp.health.answered(relayB, time.Time{})
	clock = clock.Add(3 * time.Second)
	cp.noteRelayUnanswered(1, 0, nil, relayO, begun)
	if s := take("verdict"); s != 7 {
		t.Fatalf("the verdict's notice carries stamp %d, want 7", s)
	}
	// The neighbour's-answer path.
	cp.health.pathChanged()
	stampAt = 11
	clock = clock.Add(70 * time.Second)
	cp.noteRelayUnanswered(2, 0, nil, relayC, clock)
	clock = clock.Add(5 * time.Second)
	addr, creds, slot := mustGet(t, cp, 3)
	cp.noteAllocatedAt(slot, creds, addr, time.Time{})
	if s := take("neighbour"); s != 11 {
		t.Fatalf("the neighbour's notice carries stamp %d, want 11", s)
	}
	// The VK path.
	cp.health.pathChanged()
	stampAt = 13
	clock = clock.Add(70 * time.Second)
	cp.noteRelayUnanswered(4, 0, nil, relayO, clock)
	clock = clock.Add(5 * time.Second)
	cp.mu.Lock()
	cp.noteVKAnsweredLocked(time.Time{})
	cp.mu.Unlock()
	if s := take("VK"); s != 13 {
		t.Fatalf("VK's notice carries stamp %d, want 13", s)
	}
}
