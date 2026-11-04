// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"testing"
	"time"
)

// The overnight run of 2026-11-03 on build 474: at the tunnel's start one
// connection's dial to the own relay failed at once with ENETUNREACH (the
// routes still settling) while the relay was answering its neighbours — its
// answer to conn 0 94 ms before, to conn 3 11 ms after. The failure was taken
// for the relay's silence, the relay's OWN fresh answer served as the evidence
// that the network works, and the relay was marked UNREACHABLE for a moment
// (its next answer reset the record) with the connection sent to the next
// address. Two rules, read against the design of 2026-10-19 («another relay or
// VK answered»):
//
//   - the evidence for a mark is someone ELSE's answer — another relay's or
//     VK's API — never the accused relay's own;
//   - a relay's own answer inside relayAnswerGrace before the attempt began
//     voids the verdict, as an answer after the start always did: a relay
//     answering its neighbours around the attempt was not silent to it.
func TestAMarkNeedsEvidenceFromAnotherAddressOrVK(t *testing.T) {
	h := newRelayHealth()
	clock := time.Now()
	h.now = func() time.Time { return clock }
	h.answered(relayA, time.Time{}) // A's own answer at T
	// An attempt on A begun past the grace fails: no verdict on A's own answer.
	clock = clock.Add(10 * time.Second)
	begun := clock
	clock = clock.Add(5 * time.Second)
	if h.unanswered(relayA, begun) {
		t.Fatal("A marked with nothing but its OWN answer as the evidence")
	}
	if h.isDead(relayA) {
		t.Fatal("A dead")
	}
	// VK answers: A, unanswered since after A's own answer, is marked by it.
	clock = clock.Add(time.Second)
	h.answered("", time.Time{})
	if !h.isDead(relayA) {
		t.Fatal("VK answered behind A's unanswered attempt — A not marked")
	}
	// Another relay's answer is evidence too — B's.
	h2 := newRelayHealth()
	h2.now = func() time.Time { return clock }
	h2.answered(relayA, time.Time{})
	clock = clock.Add(10 * time.Second)
	begun = clock
	clock = clock.Add(2 * time.Second)
	h2.answered(relayB, time.Time{}) // B answers while A's attempt is out
	clock = clock.Add(3 * time.Second)
	if !h2.unanswered(relayA, begun) || !h2.isDead(relayA) {
		t.Fatal("B answered inside the window — A's failure is a verdict, A not marked")
	}
	if h2.isDead(relayB) {
		t.Fatal("B marked")
	}
}

func TestAFailureWhileTheRelayAnswersItsNeighboursIsNoVerdict(t *testing.T) {
	h := newRelayHealth()
	clock := time.Now()
	h.now = func() time.Time { return clock }
	h.answered("", time.Time{}) // VK's API answered — evidence for everything below
	clock = clock.Add(time.Second)
	h.answered(relayA, time.Time{}) // A answers conn 0 at T
	// conn 30's dial begins 90 ms later and fails at once (ENETUNREACH, the
	// routes settling): A answered inside the grace before it — no verdict.
	clock = clock.Add(90 * time.Millisecond)
	begun := clock
	clock = clock.Add(10 * time.Millisecond)
	if h.unanswered(relayA, begun) || h.isDead(relayA) {
		t.Fatal("a failure 90 ms behind A's own answer marked A, with VK's answer as the evidence")
	}
	if r := h.rec[relayA]; r.unanswered != 0 {
		t.Fatalf("the voided failure started a streak (%d) — VK's next answer would mark A", r.unanswered)
	}
	if !h.answeredAround(relayA, begun) {
		t.Fatal("answeredAround does not see A's answer inside the grace")
	}
	// The blackhole of Nov 3 §529 kept: A's last answer 45 s old, the attempt
	// begun after it fails with VK's answer inside the window — marked at once.
	clock = clock.Add(45 * time.Second)
	begun = clock
	clock = clock.Add(time.Second)
	h.answered("", time.Time{})
	clock = clock.Add(4 * time.Second)
	if !h.unanswered(relayA, begun) || !h.isDead(relayA) {
		t.Fatal("an attempt begun 45 s after A's last answer failed with VK's fresh answer — A not marked")
	}
	// The grace is anchored at the answer's MOMENT, not at the start of the
	// attempt that was answered: a slow Allocate begun at T and answered at
	// T+3 s covers a failure begun at T+2.5 s (inside the grace before the
	// answer), which a stamp at the answered attempt's start would not.
	h3 := newRelayHealth()
	h3.now = func() time.Time { return clock }
	h3.answered("", time.Time{})
	slowBegun := clock
	clock = clock.Add(2500 * time.Millisecond)
	failedBegun := clock
	clock = clock.Add(500 * time.Millisecond)
	h3.answered(relayA, slowBegun) // answered at T+3 s, the attempt begun at T
	clock = clock.Add(100 * time.Millisecond)
	if h3.unanswered(relayA, failedBegun) || h3.isDead(relayA) {
		t.Fatal("a failure begun 0.5 s before A's answer (to a slow attempt begun 3 s earlier) marked A — the line is the answer's moment")
	}
	// The grace is short: 2 s, not the evidence window.
	if relayAnswerGrace > 2*time.Second || relayAnswerGrace >= relayEvidenceWindow {
		t.Fatalf("relayAnswerGrace = %s", relayAnswerGrace)
	}
}
