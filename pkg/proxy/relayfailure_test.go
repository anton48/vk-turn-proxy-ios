// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// 2026-11-08, the user's 3-hour run on 478 (Nov 8 §620): at a Wi-Fi → LTE switch
// the new path passed nothing for ≈18 s. Every connection's attempt on the own
// relay timed out (8 s); the attempts on VK's relay began AFTER those had given
// up and were answered once the path came alive — and that answer marked the
// own relay, which had never stopped working. The evidence rule asked only
// «did someone else answer after the attempt began»; it never asked whether
// the answered attempt and the silent one were in flight at the SAME TIME.
//
// Now a failure has a KIND. SILENCE (a timeout: nobody answered during the
// attempt's window) is judged only by an answer to an attempt that overlapped
// it — one begun before the silent attempt gave up, answered after the silent
// one began. The PATH's own answer (an errno: no route to host, refused,
// reset — §618's failover) keeps the old rule: a later answer within the
// window is evidence, the path has already spoken.

// The verdict's evidence for a silent streak must overlap it in time.
func TestASilentAttemptIsJudgedOnlyByAnAnswerInFlightBesideIt(t *testing.T) {
	T := time.Now()
	fresh := func() (*relayHealth, *time.Time) {
		h := newRelayHealth()
		clock := T
		h.now = func() time.Time { return clock }
		h.pathChanged()
		return h, &clock
	}
	// §620's shape: O's attempt begun T+1 gives up at T+9 (silent); A's attempt
	// begun T+12 is answered at T+19 — no overlap: O stays unmarked.
	h, clock := fresh()
	*clock = T.Add(9 * time.Second)
	if h.failed(relayO, T.Add(1*time.Second), true) {
		t.Fatal("a silent attempt with no answer around it was marked")
	}
	*clock = T.Add(19 * time.Second)
	h.answered(relayA, T.Add(12*time.Second))
	if h.isDead(relayO) {
		t.Fatal("a silent attempt was marked by an answer to an attempt begun after it had given up (§620's false mark)")
	}
	// The same, but A's attempt began at T+5 — while O's attempt was still
	// waiting: the two shared the network's moment, O is marked.
	h, clock = fresh()
	*clock = T.Add(9 * time.Second)
	h.failed(relayO, T.Add(1*time.Second), true)
	*clock = T.Add(19 * time.Second)
	h.answered(relayA, T.Add(5*time.Second))
	if !h.isDead(relayO) {
		t.Fatal("a silent attempt overlapped by an answered one was not marked")
	}
	// An answer whose attempt's start is unknown (zero) overlaps nothing it
	// can show: a silent streak stays.
	h, clock = fresh()
	*clock = T.Add(9 * time.Second)
	h.failed(relayO, T.Add(1*time.Second), true)
	*clock = T.Add(19 * time.Second)
	h.answered(relayA, time.Time{})
	if h.isDead(relayO) {
		t.Fatal("a start-less answer marked a silent streak")
	}
	// The path's own answer (an errno) is judged as before: a later answer
	// within the window is evidence, overlap or not (§618: no route to host
	// at +22.3, VK's answer 0.7 s later to an attempt begun after it).
	h, clock = fresh()
	*clock = T.Add(1 * time.Second)
	h.failed(relayO, T.Add(1*time.Second), false)
	*clock = T.Add(19 * time.Second)
	h.answered(relayA, T.Add(12*time.Second))
	if !h.isDead(relayO) {
		t.Fatal("an errno failure was not marked by a later answer")
	}
	// A streak with one errno in it is the path's: an errno at T+1, a silent
	// failure at T+9 — a later answer marks.
	h, clock = fresh()
	*clock = T.Add(1 * time.Second)
	h.failed(relayO, T.Add(1*time.Second), false)
	*clock = T.Add(9 * time.Second)
	h.failed(relayO, T.Add(2*time.Second), true)
	*clock = T.Add(19 * time.Second)
	h.answered(relayA, T.Add(12*time.Second))
	if !h.isDead(relayO) {
		t.Fatal("a streak with an errno in it was treated as silence")
	}
}

// The failure's own evidence (unanswered's path): for silence the other's
// answer must have come at or after the attempt began — not up to 60 s before
// it; an errno keeps the window.
func TestASilentAttemptTakesNoEvidenceFromBeforeItBegan(t *testing.T) {
	T := time.Now()
	h := newRelayHealth()
	clock := T
	h.now = func() time.Time { return clock }
	h.pathChanged()
	h.answered("", T) // VK's API answered at T
	// A silent attempt begun T+30, giving up at T+38: the answer at T is
	// before its start — no evidence for silence.
	clock = T.Add(38 * time.Second)
	if h.failed(relayO, T.Add(30*time.Second), true) {
		t.Fatal("a silent attempt was marked by an answer from before it began")
	}
	// An errno attempt begun T+30: the answer 30 s before is inside the
	// window — marked as before.
	if !h.failed(relayB, T.Add(30*time.Second), false) {
		t.Fatal("an errno attempt was not marked by an answer inside the window")
	}
	// A silent attempt begun T+40 with B's answer at T+45 (to an attempt
	// begun T+41) arriving before it gives up at T+48: marked.
	clock = T.Add(45 * time.Second)
	h.answered(relayC, T.Add(41*time.Second))
	clock = T.Add(48 * time.Second)
	if !h.failed(relayO, T.Add(40*time.Second), true) {
		t.Fatal("a silent attempt with an answer during its window was not marked")
	}
}

// pathSpoke tells the path's own answer from silence, through the chain and
// through the text the relay leg wraps its errors into.
func TestTheDialErrorTellsSilenceFromThePathsAnswer(t *testing.T) {
	spoke := []error{
		&net.OpError{Op: "dial", Err: &net.OpError{Op: "connect", Err: syscall.EHOSTUNREACH}},
		syscall.ECONNREFUSED,
		fmt.Errorf("SRTP dial to relay failed: %v", errors.New("dial tcp 203.0.113.9:3478: connect: no route to host")),
		errors.New("read tcp 203.0.113.9:3478: connection reset by peer"),
		errors.New("write: broken pipe"),
		errors.New("dial tcp 203.0.113.9:3478: connect: network is unreachable"),
	}
	silent := []error{
		&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ETIMEDOUT}}, // the kernel's give-up IS silence (the user's review of b724d42)
		fmt.Errorf("SRTP dial to relay failed: %v", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ETIMEDOUT}}),
		syscall.EAGAIN,
		errors.New("dial tcp 203.0.113.9:3478: connect: operation timed out"),
		errors.New("dial tcp 203.0.113.9:3478: i/o timeout"),
		fmt.Errorf("allocate failed: %v", errors.New("all retransmissions failed for 1234")),
		errors.New("context deadline exceeded"),
		errors.New("turn: retransmissions exhausted"),
	}
	for _, e := range spoke {
		if !pathSpoke(e) {
			t.Errorf("read as silence: %v", e)
		}
	}
	for _, e := range silent {
		if pathSpoke(e) {
			t.Errorf("read as the path's answer: %v", e)
		}
	}
	if pathSpoke(nil) {
		t.Error("nil spoke")
	}
}

// The user's review of b724d42, finding 1: an answer that does not overlap a
// silent streak used to leave the streak OPEN — unanswered > 0, not dead — a
// state the hand-out does not know: neither untried nor marked-and-due, so a
// credential naming only that relay was never handed out again, and the
// streak's old start kept a LATER, overlapping answer from marking it. Now
// such an answer ENDS the streak: the verdict is void (the network's state
// during those attempts is unknown), the address is untried again on this
// path, and a new streak begins with its own start.
func TestANonOverlappingAnswerEndsASilentStreak(t *testing.T) {
	T := time.Now()
	h := newRelayHealth()
	clock := T
	h.now = func() time.Time { return clock }
	h.pathChanged()
	// O silent [1 … 9]; A's attempt [12 … 19] answered: no verdict on O — and
	// no limbo either: O is untried again, a candidate.
	clock = T.Add(9 * time.Second)
	h.failed(relayO, T.Add(1*time.Second), true)
	clock = T.Add(19 * time.Second)
	h.answered(relayA, T.Add(12*time.Second))
	if h.isDead(relayO) {
		t.Fatal("marked without overlap")
	}
	if got := h.untried([]string{relayO}); len(got) != 1 {
		t.Fatalf("after a non-overlapping answer O is not untried again: %v", got)
	}
	if !h.hasCandidate([]string{relayO}) {
		t.Fatal("a credential naming O alone has no candidate — the hand-out would park")
	}
	// A NEW silent streak [21 … 29] and A's attempt [25 … 30] answered: they
	// overlap — O is marked (the old streak's start no longer stands in the way).
	clock = T.Add(29 * time.Second)
	h.failed(relayO, T.Add(21*time.Second), true)
	clock = T.Add(30 * time.Second)
	h.answered(relayA, T.Add(25*time.Second))
	if !h.isDead(relayO) {
		t.Fatal("a new silent streak overlapped by an answer was not marked — the old streak's start stood in the way")
	}
}

// The user's repro at the pool: one VK address, a silent failure on it, then
// VK's API minting again for the same address — the pool hands the address
// out again instead of parking for good.
func TestASingleRelayComesBackAfterAnUnconfirmedTimeout(t *testing.T) {
	cp, _, clock := relayPool(t, "", relayA)
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA {
		t.Fatalf("handed %s, want the one address", addr)
	}
	cp.release(slot, creds, "")
	// The attempt on A begins 5 s after the mint's answer and times out 8 s
	// later; nothing else has answered meanwhile.
	*clock = clock.Add(13 * time.Second)
	cp.noteRelayFailure(0, slot, creds, relayA, clock.Add(-8*time.Second), true)
	// The network recovers: VK's API answers a mint begun after the failure.
	*clock = clock.Add(20 * time.Second)
	cp.mu.Lock()
	cp.noteVKAnsweredLocked(clock.Add(-2 * time.Second))
	cp.mu.Unlock()
	if cp.health.isDead(relayA) {
		t.Fatal("the one address marked on an answer that did not overlap its silent attempt")
	}
	for _, later := range []time.Duration{3 * time.Minute, 20 * time.Minute, 60 * time.Minute} {
		*clock = clock.Add(later)
		got, _, _, err := cp.get(1, false)
		if err != nil || got != relayA {
			t.Fatalf("after %v the pool does not hand the one address out again: %q, %v", later, got, err)
		}
	}
}

// Finding 2: ETIMEDOUT through the relay leg's chain (net.OpError →
// os.SyscallError → errno) is the kernel's give-up — silence — and takes no
// evidence from before the attempt began.
func TestETIMEDOUTIsSilenceThroughTheRelayLeg(t *testing.T) {
	cp, _, clock := relayPool(t, "", relayA)
	p := &Proxy{credPool: cp}
	T := *clock
	cp.mu.Lock()
	cp.noteVKAnsweredLocked(T) // VK answered at T
	cp.mu.Unlock()
	_, creds, slot := mustGet(t, cp, 0)
	cp.release(slot, creds, "")
	*clock = T.Add(38 * time.Second)
	var err error = &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ETIMEDOUT}}
	if got := p.relayUnanswered(0, slot, creds, relayA, T.Add(30*time.Second), err); got != err {
		t.Fatal("the error did not come back as it was")
	}
	if cp.health.isDead(relayA) {
		t.Fatal("ETIMEDOUT read as the path's answer: marked on VK's answer from before the attempt began")
	}
}
