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

// The user's review of 048b944, finding 1: beginConnSession replaced the cancel
// and moved the serial but KEPT the old relay and stamp — until the new
// session's hand-out the row read «the new cancel on the OLD relay», and a mark
// of that relay ended the new attempt, which had no address yet (the old
// session's end rightly declines to clear a row that is not its own, so the
// gap lasted until recordHandOut). A new session starts with no relay.
func TestANewSessionStartsWithNoRelayOnItsRow(t *testing.T) {
	p := &Proxy{ctx: context.Background(), connEpoch: make([]int64, 4), connCancel: make([]func(), 4), connRelay: make([]string, 4), connRelaySeq: make([]uint64, 4), connSerial: make([]uint64, 4)}
	seqOf := func(i int) uint64 {
		p.connMu.Lock()
		defer p.connMu.Unlock()
		return p.connRelaySeq[i]
	}
	var oldCancelled, newCancelled int
	s1 := p.beginConnSession(2, func() { oldCancelled++ })
	p.recordHandOut(withConnSerial(context.Background(), s1), 2, relayA, 41)
	// Resume: the new loop registers; the old session has not ended yet.
	p.beginConnSession(2, func() { newCancelled++ })
	if r, _ := p.connRelayOf(2); r != "" || seqOf(2) != 0 {
		t.Fatalf("a new session's row still reads %s / %d — the predecessor's relay and stamp", r, seqOf(2))
	}
	// A mark of the old relay: the new attempt (no address yet) is not on it.
	if n := p.endSessionsOnRelay(relayA, 41); n != 0 || newCancelled != 0 {
		t.Fatalf("a mark of the predecessor's relay ended %d session(s) (new cancelled %d), want none", n, newCancelled)
	}
	if oldCancelled != 0 {
		t.Fatalf("the old cancel fired %d time(s) through the row", oldCancelled)
	}
}

// Finding 2: recordHandOut checked the row's owner in setConnRelayFor, then
// asked the pool (its lock) and ended the session through connCancel[connIdx]
// WITHOUT re-checking — an old registration that had passed the check, waited
// for the pool, found its relay marked and ended the SUCCESSOR registered
// meanwhile. The end re-checks, under connMu, the serial AND the hand-out it
// is about (the relay and the stamp on the row).
func TestTheMarksEndReChecksTheSerialAndTheHandOut(t *testing.T) {
	p := &Proxy{ctx: context.Background(), connEpoch: make([]int64, 4), connCancel: make([]func(), 4), connRelay: make([]string, 4), connRelaySeq: make([]uint64, 4), connSerial: make([]uint64, 4)}
	var oldCancelled, newCancelled int
	s1 := p.beginConnSession(2, func() { oldCancelled++ })
	p.recordHandOut(withConnSerial(context.Background(), s1), 2, relayA, 41)
	// The successor registers and is handed its relay while the old
	// registration waits for the pool.
	s2 := p.beginConnSession(2, func() { newCancelled++ })
	p.recordHandOut(withConnSerial(context.Background(), s2), 2, relayA, 57)
	// The old registration's mark check completes: its end names ITS serial
	// and ITS hand-out — neither is the row's any more.
	if p.endConnOnMarkedRelayFor(s1, 2, relayA, 41); newCancelled != 0 || oldCancelled != 0 {
		t.Fatalf("a stale registration's end cancelled: new %d old %d", newCancelled, oldCancelled)
	}
	// The right serial with a hand-out that is not the row's: nothing either.
	if p.endConnOnMarkedRelayFor(s2, 2, relayB, 57); newCancelled != 0 {
		t.Fatal("an end naming another relay cancelled the session")
	}
	if p.endConnOnMarkedRelayFor(s2, 2, relayA, 56); newCancelled != 0 {
		t.Fatal("an end naming another stamp cancelled the session")
	}
	// A stale registration whose hand-out numbers EQUAL the row's (a counter
	// that restarted, a hand-made stamp): the serial alone tells it apart.
	if p.endConnOnMarkedRelayFor(s1, 2, relayA, 57); newCancelled != 0 {
		t.Fatal("a stale registration's end with the row's own numbers cancelled the successor — the serial is not checked")
	}
	// The successor's own end, its hand-out: the session ends.
	if p.endConnOnMarkedRelayFor(s2, 2, relayA, 57); newCancelled != 1 || oldCancelled != 0 {
		t.Fatalf("the successor's own end cancelled new %d old %d, want 1 0", newCancelled, oldCancelled)
	}
	// Without a serial (a bare context) the hand-out alone decides.
	p.beginConnSession(2, func() { newCancelled++ })
	p.recordHandOut(context.Background(), 2, relayB, 60)
	if p.endConnOnMarkedRelayFor(0, 2, relayB, 59); newCancelled != 1 {
		t.Fatal("a serial-less end with another stamp cancelled")
	}
	if p.endConnOnMarkedRelayFor(0, 2, relayB, 60); newCancelled != 2 {
		t.Fatalf("a serial-less end with the row's hand-out did not cancel (%d)", newCancelled)
	}
}
