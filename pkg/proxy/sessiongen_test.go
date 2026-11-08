// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// 2026-11-08, the user's review of af80e3c (two findings). (1) The replacement
// sentinel's generation was READ BACK from the connection table at every send
// — and Resume / ForceReconnect start new sessions without waiting for the old
// ones, so an old session's tick declared the NEW hand-out's stamp, and the old
// session's end cleared the row under the new one (which then declared 0). Now
// the generation is THIS hand-out's stamp, returned by the pool from under its
// lock (handOut → resolveTURNAddr) and held by the session for its hello and
// its ticks. (2) The registration — the cancel, the relay, the stamp — is
// written and cleared only by the session whose serial it holds
// (beginConnSession → the session's context → recordHandOut / endConnSession).

// The hand-out's stamp is the session's generation: what resolveTURNAddr
// returns is what the pool stamped THIS hand-out with, and a later hand-out on
// the index moves the table, not what the session declares.
func TestTheHandOutsStampIsThisSessionsGeneration(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA, relayB}, Username: futureUser("cached"), Password: "p"})
	cp, _, _ := relayPool(t, path, relayC)
	list, err := ParseTURNServers(relayO + ":0," + TURNServersVK)
	if err != nil {
		t.Fatal(err)
	}
	cp.setOverride(turnOverride{servers: list})
	p := &Proxy{credPool: cp, connEpoch: make([]int64, 8), connCancel: make([]func(), 8), connRelay: make([]string, 8), connRelaySeq: make([]uint64, 8), connSerial: make([]uint64, 8)}
	p.initGroupHello(Config{})
	ctx := context.Background()
	_, _, _, gen3, err := p.resolveTURNAddr(ctx, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	seqOf := func(i int) uint64 {
		p.connMu.Lock()
		defer p.connMu.Unlock()
		return p.connRelaySeq[i]
	}
	if gen3 == 0 || gen3 != cp.handStampOf(3) || gen3 != seqOf(3) {
		t.Fatalf("the hand-out returned generation %d; the pool stamped %d, the table holds %d", gen3, cp.handStampOf(3), seqOf(3))
	}
	_, _, _, gen4, err := p.resolveTURNAddr(ctx, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	if gen4 != gen3+1 {
		t.Fatalf("the next hand-out's generation %d, want %d", gen4, gen3+1)
	}
	// A later hand-out on index 3 (another session's, after a Resume) moves the
	// table; the session that was handed gen3 declares gen3 still.
	p.setConnRelay(3, relayA, gen3+10)
	var buf bytes.Buffer
	p.sendGroupHello(&buf, 3, gen3)
	if want := append(append([]byte(nil), p.groupHelloBytes()...), groupReplaceBytes(3, gen3)...); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("the hello declares % x, want the session's own generation %d", buf.Bytes(), gen3)
	}
	var seq uint64
	var lastPingAt time.Time
	buf.Reset()
	if err := p.tickPing(&seq, &lastPingAt, time.Now(), func(uint64, time.Time) error { return nil }, &buf, 3, gen3); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), groupReplaceBytes(3, gen3)) {
		t.Fatalf("the tick declares % x, want the session's own generation %d", buf.Bytes(), gen3)
	}
}

// Two sessions of one index alive at once (Resume, ForceReconnect): the old
// one's end clears nothing of the successor's registration, and its late
// hand-out overwrites nothing of it; a serial of 0 clears unconditionally.
func TestAnOldSessionsEndDoesNotClearItsSuccessorsRegistration(t *testing.T) {
	p := &Proxy{ctx: context.Background(), connEpoch: make([]int64, 4), connCancel: make([]func(), 4), connRelay: make([]string, 4), connRelaySeq: make([]uint64, 4), connSerial: make([]uint64, 4)}
	seqOf := func(i int) uint64 {
		p.connMu.Lock()
		defer p.connMu.Unlock()
		return p.connRelaySeq[i]
	}
	var oldCancelled, newCancelled int
	s1 := p.beginConnSession(2, func() { oldCancelled++ })
	if s1 == 0 {
		t.Fatal("a session with a table got serial 0")
	}
	p.recordHandOut(withConnSerial(context.Background(), s1), 2, relayA, 41)
	// Resume: the new loop registers before the old session has returned.
	s2 := p.beginConnSession(2, func() { newCancelled++ })
	if s2 == s1 {
		t.Fatalf("the successor got the same serial %d", s2)
	}
	p.recordHandOut(withConnSerial(context.Background(), s2), 2, relayA, 57)
	// The old session's late hand-out (its context cancelled, its get returned
	// all the same): the row stays the successor's.
	p.recordHandOut(withConnSerial(context.Background(), s1), 2, relayB, 58)
	if r, _ := p.connRelayOf(2); r != relayA || seqOf(2) != 57 {
		t.Fatalf("after the old session's late hand-out the row is %s / %d, want %s / 57", r, seqOf(2), relayA)
	}
	// The old session ends: the successor's row stands, its cancel included.
	p.endConnSession(2, s1)
	if r, _ := p.connRelayOf(2); r != relayA || seqOf(2) != 57 {
		t.Fatalf("after the old session's end the row is %s / %d, want %s / 57", r, seqOf(2), relayA)
	}
	if n := p.endSessionsOnRelay(relayA, 57); n != 1 || newCancelled != 1 || oldCancelled != 0 {
		t.Fatalf("a mark after the old session's end ended %d (new %d, old %d), want the successor alone", n, newCancelled, oldCancelled)
	}
	// The successor ends: cleared.
	p.endConnSession(2, s2)
	if r, _ := p.connRelayOf(2); r != "" || seqOf(2) != 0 {
		t.Fatalf("after the successor's end the row is %s / %d, want cleared", r, seqOf(2))
	}
	// No serial: unconditional, the probes' and the tests' way.
	p.beginConnSession(2, func() {})
	p.setConnRelay(2, relayB, 60)
	p.endConnSession(2, 0)
	if r, _ := p.connRelayOf(2); r != "" || seqOf(2) != 0 {
		t.Fatalf("a serial of 0 left the row %s / %d", r, seqOf(2))
	}
	// A context without a serial records unconditionally too.
	p.beginConnSession(2, func() {})
	p.recordHandOut(context.Background(), 2, relayB, 61)
	if r, _ := p.connRelayOf(2); r != relayB || seqOf(2) != 61 {
		t.Fatalf("a context without a serial did not record: %s / %d", r, seqOf(2))
	}
}
