// SPDX-License-Identifier: GPL-3.0-only

package proxy

// The pool's side of the relay health (relayhealth.go): which address of a
// credential a connection is handed, what an unanswered Allocate does, what
// an allocation proves, and when a pool whose relays are all marked waits
// instead of minting. Everything here runs under cp.mu unless said otherwise.

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// setOverride installs the user's TURN relay setting and recomputes every
// loaded credential's candidates by it (the cache was read before the
// setting arrived). Not under cp.mu.
func (cp *credPool) setOverride(o turnOverride) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.override = o
	for i := range cp.pool {
		if cp.pool[i].creds != nil {
			cp.pool[i].addrs = cp.candidatesForSlot(i, cp.pool[i].creds)
		}
	}
	if o.set() {
		log.Printf("credpool: TURN relay override: %s — applied to every credential, cached ones included, when it is handed out", strings.Join(o.candidatesFor(&TURNCreds{Addresses: []string{"<vk-relay>:19302"}}), ", "))
	}
}

// candidatesForSlot is the list a credential in `slot` may be dialled on in
// THIS pool: the override's shape of VK's addresses — except in cookie mode,
// where a slot IS a relay (cookieCredForSlot: one (identity, relay) quota per
// slot): with an override list the slot's relay is the list's s-th entry
// (a seed in slot 0 included), without one the credential's own address.
// slot < 0: no slot yet (a credential looked at before it is placed).
func (cp *credPool) candidatesForSlot(slot int, creds *TURNCreds) []string {
	if cp.mode == credCacheModeCookie {
		if n := len(cp.override.servers); n > 0 && slot >= 0 && slot < n {
			return []string{cp.override.servers[slot]}
		}
		// The slot's ONE relay (an (identity, relay) quota of its own): never
		// the credential's whole list — the same username sits in other slots
		// for other relays (the user's review: a merged list let two slots
		// allocate on one relay under one identity, 20 where 10 is the quota).
		if creds != nil && creds.Address != "" {
			return []string{creds.Address}
		}
		return (turnOverride{}).candidatesFor(creds)
	}
	return cp.override.candidatesFor(creds)
}

// candidatesLocked is the list slot's credential may be dialled on.
func (cp *credPool) candidatesLocked(slot int) []string {
	if slot < 0 || slot >= len(cp.pool) {
		return nil
	}
	e := cp.pool[slot]
	if len(e.addrs) > 0 {
		return e.addrs
	}
	if e.addr != "" {
		return []string{e.addr}
	}
	return nil
}

// usableLocked: the slot's credential is fresh AND has a relay to dial — a
// candidate not yet unanswered, or a marked one due for a re-try. 🚫 A
// credential whose every relay is marked unreachable, or went unanswered with
// no evidence either way, is NOT READY, not dropped: the pool mints (a mint
// that answers is the evidence), a network outage marks everything, and the
// marks are cleared at the path change. With the override LIST there is no
// other relay to mint for: its unmarked entries are cycled through again.
func (cp *credPool) usableLocked(slot int) bool {
	if !cp.isFreshLocked(slot) {
		return false
	}
	cands := cp.candidatesLocked(slot)
	if cp.health.hasCandidate(cands) {
		return true
	}
	return len(cp.override.servers) > 0 && len(cp.health.alive(cands)) > 0
}

// pickAddrLocked chooses the address connIdx dials on slot's credential: the
// unmarked candidate at the connection's cursor (an unanswered attempt moves
// the cursor on, so the next attempt takes the next candidate even before any
// mark), or — with every candidate marked — the one longest due for a re-try,
// reserved for this connection. ok=false: nothing to dial now.
func (cp *credPool) pickAddrLocked(slot, connIdx int) (string, bool) {
	cands := cp.candidatesLocked(slot)
	if alive := cp.health.alive(cands); len(alive) > 0 {
		i := cp.cursor[connIdx] % len(alive)
		if i < 0 {
			i = -i
		}
		return alive[i], true
	}
	addr, ok, _ := cp.health.probe(cands)
	if ok {
		log.Printf("credpool: conn %d: every relay of slot %d is marked unreachable (%s) — trying %s again", connIdx, slot, cp.health.deadList(cands), addr)
	}
	return addr, ok
}

// noteRelayUnanswered: connIdx's Allocate on addr (slot's credential) got no
// answer; the attempt began at start. The connection's cursor moves on; the
// address is marked only with evidence that the network works (relayhealth.go).
func (cp *credPool) noteRelayUnanswered(connIdx, slot int, creds *TURNCreds, addr string, start time.Time) {
	if cp == nil || addr == "" {
		return
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.cursor[connIdx]++
	marked := cp.health.unanswered(addr, start)
	switch {
	case marked:
		log.Printf("credpool: conn %d: relay %s did not answer — marked UNREACHABLE (another relay or VK answered meanwhile); the connections move to the next address", connIdx, addr)
	default:
		log.Printf("credpool: conn %d: relay %s did not answer — not marked (nothing else has answered since); the next attempt takes the next address", connIdx, addr)
	}
}

// noteAllocatedAt: the relay at addr accepted slot's credential — the pool's
// quota bookkeeping (noteAllocated) and the health's evidence: the address
// is alive, the network works, and every address left unanswered since the
// previous answer is marked now.
func (cp *credPool) noteAllocatedAt(slot int, creds *TURNCreds, addr string, start time.Time) {
	if cp == nil {
		return
	}
	cp.noteAllocated(slot, creds)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	before := cp.deadCountLocked()
	cp.health.answered(addr, start)
	if after := cp.deadCountLocked(); after > before {
		log.Printf("credpool: relay %s answered — %d relay(s) unanswered since the previous answer marked UNREACHABLE", addr, after-before)
	}
}

func (cp *credPool) deadCountLocked() int {
	n := 0
	for _, r := range cp.health.rec {
		if r.dead {
			n++
		}
	}
	return n
}

// noteVKAnsweredLocked: VK's API minted a credential (the fetch begun at
// start) — the network works.
func (cp *credPool) noteVKAnsweredLocked(start time.Time) {
	before := cp.deadCountLocked()
	cp.health.answered("", start)
	if after := cp.deadCountLocked(); after > before {
		log.Printf("credpool: VK answered — %d relay(s) unanswered since the previous answer marked UNREACHABLE", after-before)
	}
}

// noteMintLocked: a fresh credential landed in slot. With no candidate to
// dial (every relay it names is marked), the pool pauses its minting — VK
// keeps handing out the dead pair — for a growing while; a mint with a live
// relay ends the pause. It reports whether the credential can be dialled.
func (cp *credPool) noteMintLocked(slot int) bool {
	cands := cp.candidatesLocked(slot)
	if cp.health.hasCandidate(cands) {
		cp.deadMintPause = 0
		return true
	}
	if cp.deadMintPause == 0 {
		cp.deadMintPause = deadMintPause
	} else if cp.deadMintPause < deadMintPauseMax {
		cp.deadMintPause *= 2
	}
	cp.deadMintUntil = cp.health.now().Add(cp.deadMintPause)
	log.Printf("credpool: the fresh credential in slot %d names only relays marked unreachable (%s) — kept, and no mint for %s", slot, cp.health.deadList(cands), cp.deadMintPause)
	cp.armHealthWakeLocked(cp.deadMintUntil)
	return false
}

// healthParkLocked: with every fresh credential blocked by its marks, a mint
// is no way out when the override list is set (the mint would name the same
// list) or while the dead-mint pause runs; the connections wait for a re-try
// to come due, a mark to clear or the pause to end. nil: carry on to a mint.
func (cp *credPool) healthParkLocked() error {
	now := cp.health.now()
	blocked, nextDue := 0, time.Time{}
	for i := range cp.pool {
		if !cp.isFreshLocked(i) || cp.usableLocked(i) {
			continue
		}
		blocked++
		if _, _, due := cp.health.probe(cp.candidatesLocked(i)); !due.IsZero() && (nextDue.IsZero() || due.Before(nextDue)) {
			nextDue = due
		}
	}
	if blocked == 0 {
		return nil
	}
	var why string
	switch {
	case len(cp.override.servers) > 0:
		why = "every relay of the TURN override list is marked unreachable"
	case now.Before(cp.deadMintUntil):
		why = fmt.Sprintf("no relay answers and minting is paused for %s more", cp.deadMintUntil.Sub(now).Round(time.Second))
		if nextDue.IsZero() || cp.deadMintUntil.Before(nextDue) {
			nextDue = cp.deadMintUntil
		}
	default:
		return nil
	}
	cp.armHealthWakeLocked(nextDue)
	wait := "a re-try is due"
	if !nextDue.IsZero() {
		wait = fmt.Sprintf("the next re-try in %s", nextDue.Sub(now).Round(time.Second))
	}
	return &poolParkError{msg: fmt.Sprintf("credpool: %s (%d credential(s) held) — parking, %s", why, blocked, wait), wake: cp.slotAvailableCh}
}

// armHealthWakeLocked wakes the parked connections at `at` (a re-try due, a
// pause's end), keeping the earliest moment asked for.
func (cp *credPool) armHealthWakeLocked(at time.Time) {
	if at.IsZero() {
		return
	}
	delay := time.Until(at)
	if delay <= 0 {
		delay = time.Millisecond
	}
	if cp.healthTimer != nil && !cp.healthWakeAt.IsZero() && cp.healthWakeAt.After(time.Now()) && !cp.healthWakeAt.After(at) {
		return // an earlier wake is already armed
	}
	if cp.healthTimer != nil {
		cp.healthTimer.Stop()
	}
	cp.healthWakeAt = at
	cp.healthTimer = time.AfterFunc(delay, cp.broadcastSlotAvailable)
}

// pathChangedHealthLocked: the network changed — every mark and every
// cursor was about the old one.
func (cp *credPool) pathChangedHealthLocked() {
	if n := cp.deadCountLocked(); n > 0 {
		log.Printf("credpool: path changed — %d relay mark(s) cleared (they were about the old network)", n)
	}
	cp.health.pathChanged()
	cp.cursor = map[int]int{}
	cp.deadMintUntil, cp.deadMintPause = time.Time{}, 0
}
