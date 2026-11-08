// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"errors"
	"fmt"
	"net"
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
