// SPDX-License-Identifier: GPL-3.0-only

package proxy

// The pool's side of the relay health (relayhealth.go): which address of a
// credential a connection is handed, what an unanswered Allocate does, what
// an allocation proves, and when a pool whose relays are all marked waits
// instead of minting. Everything here runs under cp.mu unless said otherwise.

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

// setOverride installs the user's TURN relay setting and recomputes every
// loaded credential's candidates by it (the cache was read before the
// setting arrived). Not under cp.mu.
func (cp *credPool) setOverride(o turnOverride) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if o.raw == nil {
		o.raw = o.servers
	}
	o.setServers(o.servers) // the quota fields apart from the addresses
	// `$vkurls` alone — VK's own relays and nothing else — is no override.
	if len(o.servers) == 1 && o.servers[0] == TURNServersVK {
		o.servers, o.raw, o.quotas = nil, nil, nil
	}
	if fixed, vkTail := o.cookieShape(); cp.mode == credCacheModeCookie && vkTail && len(o.servers) > len(fixed)+1 {
		log.Printf("credpool: TURN relay override: cookie mode — %s takes every slot after the %d fixed entr(ies); the %d entr(ies) after it are not used", TURNServersVK, len(fixed), len(o.servers)-len(fixed)-1)
	}
	cp.override = o
	cp.growForListLocked() // the fixed entries add to the VK slots
	// Cookie mode under a list: every slot asks the list afresh, in order —
	// its stored address when the list names it and no slot holds it, else a
	// free entry (candidatesForSlot). Cleared first: a slot BEYOND the list
	// whose stored address is a list entry would otherwise hold that entry
	// from the slot whose index it is while that slot is computed, and the
	// entry sat idle (the user's review of 455).
	if cp.mode == credCacheModeCookie && len(o.servers) > 0 {
		for i := range cp.pool {
			cp.pool[i].addrs = nil
		}
	}
	for i := range cp.pool {
		if cp.pool[i].creds != nil {
			cp.pool[i].addrs = cp.candidatesForSlot(i, cp.pool[i].creds)
			// The marks and the last use are the RELAY's the seats were on
			// (relayhist.go): a slot re-pointed to another relay starts there
			// with neither, and keeps the old relay's for the fallback.
			cp.applyRelayQuarantineLocked(i) // the clock of the relay the slot dials NOW (cookie mode)
			cp.sayReadyDespiteTheClockLocked(i, "TURN relay override")
			cp.syncMinterLocked(i)
		}
	}
	if o.set() {
		var quotas []string
		for _, a := range o.servers {
			if q, ok := o.quota(a); ok {
				if q == 0 {
					quotas = append(quotas, a+" no quota")
				} else {
					quotas = append(quotas, fmt.Sprintf("%s quota %d", a, q))
				}
			}
		}
		qs := ""
		if len(quotas) > 0 {
			qs = " (" + strings.Join(quotas, ", ") + ")"
		}
		log.Printf("credpool: TURN relay override: %s%s — applied to every credential, cached ones included, when it is handed out", strings.Join(o.candidatesFor(&TURNCreds{Addresses: []string{"<vk-relay>:19302"}}), ", "), qs)
	}
}

// candidatesForSlot is the list a credential in `slot` may be dialled on in
// THIS pool: the override's shape of VK's addresses — except in cookie mode,
// where a slot IS a relay (cookieCredForSlot: one (identity, relay) quota per
// slot): with an override list, an entry of the list no OTHER slot holds —
// the credential's own relay when the list names it (the minter's choice),
// else the slot's index's, else the first free, else nothing; without a list
// the credential's own address. Asked under cp.mu at the PLACEMENT, against
// the list and the slots as they are THEN (the user's review of 455: a mint
// begun under [A, B] for B was placed after the list became [C, A] — by
// index, onto A, the slot 0 holds ten leases on; the user's review of 454:
// a list resolved in another order made the index a twin). slot < 0: no
// slot yet (a credential looked at before it is placed).
func (cp *credPool) candidatesForSlot(slot int, creds *TURNCreds) []string {
	if cp.mode == credCacheModeCookie {
		if n := len(cp.override.servers); n > 0 && slot >= 0 {
			fixed, vkTail := cp.override.cookieShape()
			if slot < len(fixed) {
				if creds != nil && cp.inOverrideListLocked(creds.Address) && !cp.heldByAnotherLocked(slot, creds.Address) {
					return []string{creds.Address}
				}
				if next := cp.freeListRelayLocked(slot); next != "" {
					return []string{next}
				}
				return nil // every entry held: the slot dials nothing until one is free (rebindOverrideSlotsLocked)
			}
			if vkTail {
				// A VK slot (`$vkurls`): the credential's own relay — one of
				// VK's, the minter's discovery — unless a fixed entry names it
				// or another slot dials it (one okcdn user id, one quota).
				if creds != nil && creds.Address != "" && !cp.inOverrideListLocked(creds.Address) && !cp.heldByAnotherLocked(slot, creds.Address) {
					return []string{creds.Address}
				}
				return nil
			}
			// Beyond the list: nothing to dial. A slot loaded from disk keeps
			// its stored address, which may be one of the list's own relays
			// (2026-10-20, the user's run 10: slot 8 held the list's third) —
			// a second slot on one relay, one quota.
			return nil
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
	// Cookie mode under a list: a slot the list gives no relay — beyond the
	// list, or no entry free for it (rebindSlotLocked) — dials nothing, not
	// its stored address either (candidatesForSlot).
	if cp.mode == credCacheModeCookie && len(cp.override.servers) > 0 {
		return nil
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
	return cp.isFreshLocked(slot) && cp.hasRelayLocked(slot)
}

// hasRelayLocked: the slot's credential has a relay to dial — the second half
// of usableLocked, asked on its own by a hand-out that judges the freshness
// on the relay picked for the connection (pickAcquireSlotLocked).
func (cp *credPool) hasRelayLocked(slot int) bool {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return false
	}
	if cp.configuredOffLocked(slot) { // no relay by configuration: the list dropped its own, or gives it none
		return false
	}
	cands := cp.candidatesLocked(slot)
	if cp.health.hasCandidate(cands) {
		return true
	}
	return len(cp.override.servers) > 0 && !cp.override.hasVK() && len(cp.health.alive(cands)) > 0
}

// pickAddrLocked chooses the address connIdx dials on slot's credential: the
// relay without a quota while it answers (unlimitedFirstLocked), else the
// unmarked candidate at the connection's cursor (an unanswered attempt moves
// the cursor on, so the next attempt takes the next candidate even before any
// mark), or — with every candidate marked — the one longest due for a re-try,
// reserved for this connection. ok=false: nothing to dial now.
func (cp *credPool) pickAddrLocked(slot, connIdx int) (string, bool) {
	cands := cp.candidatesLocked(slot)
	if alive := cp.health.alive(cands); len(alive) > 0 {
		if addr, ok := cp.unlimitedFirstLocked(alive); ok {
			return addr, true
		}
		return cp.cursorPickLocked(alive, connIdx), true
	}
	addr, ok, _ := cp.health.probe(cands)
	if ok {
		log.Printf("credpool: conn %d: every relay of slot %d is marked unreachable (%s) — trying %s again", connIdx, slot, cp.health.deadList(cands), addr)
	}
	return addr, ok
}

// relayPace: the pace the override list gives the relay at addr, in KiB/s
// (0 = no pacer), ok false = the direction's default; the session asks it at
// its hand-out (resolveTURNAddr → uplinkpace.go), the hello carries it to
// the server. Under the pool's lock: setOverride replaces the list.
func (cp *credPool) relayPace(addr string) (int, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.override.pace(addr)
}

// unlimitedFirstLocked: the relay without a quota that takes every connection
// NOW — the list's first unmarked candidate when it has no quota and no attempt
// on it went unanswered on this path since the last answer (relayHealth.untried).
// That is what "while it answers" means: a mark needs evidence that something
// ELSE answered, and with a ready credential nothing else is dialled (the
// stands, 2026-11-01: a silent own relay held every connection for good). A
// silent one is passed by every connection at once; VK's first answer marks it;
// its own answer, or a path change, puts it first again. ok=false: none. The ONE
// rule behind pickAddrLocked and peekAddrLocked.
func (cp *credPool) unlimitedFirstLocked(alive []string) (string, bool) {
	if len(alive) == 0 || !cp.override.unlimited(alive[0]) {
		return "", false
	}
	if len(cp.health.untried(alive[:1])) == 0 {
		return "", false
	}
	return alive[0], true
}

// cursorPickLocked: the unmarked candidate at connIdx's cursor — the silent
// relay without a quota left out while another candidate is left (it is not
// cycled back to by the cursor: it comes back when it answers or the path
// changes); alone, it is dialled again (nothing else to dial).
func (cp *credPool) cursorPickLocked(alive []string, connIdx int) string {
	if len(alive) > 1 && cp.override.unlimited(alive[0]) {
		alive = alive[1:]
	}
	i := cp.cursor[connIdx] % len(alive)
	if i < 0 {
		i = -i
	}
	return alive[i]
}

// relayParkLocked: a hand-out found no address to dial on slot's credential
// after all (every relay marked, no re-try due or one already out) — the
// connection parks until the next re-try comes due; no seat is taken.
func (cp *credPool) relayParkLocked(connIdx, slot int) *poolParkError {
	cands := cp.candidatesLocked(slot)
	_, _, due := cp.health.probe(cands)
	cp.armHealthWakeLocked(due)
	wait := "a re-try is out on another connection"
	if !due.IsZero() {
		wait = fmt.Sprintf("the next re-try in %s", due.Sub(cp.health.now()).Round(time.Second))
	}
	log.Printf("credpool: conn %d: slot %d has no relay to dial (%s marked) — parking, %s", connIdx, slot, cp.health.deadList(cands), wait)
	return &poolParkError{msg: fmt.Sprintf("credpool: slot %d has no relay to dial — parking, %s", slot, wait), wake: cp.slotAvailableCh}
}

// noteRelayUnanswered: connIdx's Allocate on addr (slot's credential) got no
// answer; the attempt began at start. The connection's cursor moves on; the
// address is marked only with evidence that the network works (relayhealth.go).
func (cp *credPool) noteRelayUnanswered(connIdx, slot int, creds *TURNCreds, addr string, start time.Time) {
	if cp == nil || addr == "" {
		return
	}
	cp.mu.Lock()
	cp.cursor[connIdx]++
	before := cp.deadAddrsLocked()
	marked := cp.health.unanswered(addr, start)
	switch {
	case marked:
		log.Printf("credpool: conn %d: relay %s did not answer — marked UNREACHABLE (another relay or VK answered meanwhile); the connections move to the next address", connIdx, addr)
	case cp.health.answeredAround(addr, start):
		log.Printf("credpool: conn %d: relay %s answered its neighbours around this attempt — no verdict on it; the next attempt takes the next address", connIdx, addr)
	default:
		log.Printf("credpool: conn %d: relay %s did not answer — not marked (nothing else has answered since); the next attempt takes the next address", connIdx, addr)
	}
	newly := cp.newlyDeadLocked(before)
	stamp := cp.stampLocked()
	cp.mu.Unlock()
	cp.fireRelayMarked(newly, stamp)
}

// deadAddrsLocked: the relays marked UNREACHABLE now.
func (cp *credPool) deadAddrsLocked() map[string]bool {
	out := map[string]bool{}
	for a, r := range cp.health.rec {
		if r.dead {
			out[a] = true
		}
	}
	return out
}

// newlyDeadLocked: the relays marked since `before` was taken; each records
// the hand-out stamp its mark saw (relayMarkedSince reads it).
func (cp *credPool) newlyDeadLocked(before map[string]bool) []string {
	var out []string
	for a, r := range cp.health.rec {
		if r.dead && !before[a] {
			r.markSeq = cp.handSeq
			out = append(out, a)
		}
	}
	return out
}

// fireRelayMarked tells the hook of every newly marked relay, with the
// hand-out stamp read at the mark — OUTSIDE the pool's lock: the hook ends
// sessions whose re-dials ask the pool (relaymarkend.go).
func (cp *credPool) fireRelayMarked(addrs []string, stamp uint64) {
	if cp.onRelayMarked == nil {
		return
	}
	for _, a := range addrs {
		cp.onRelayMarked(a, stamp)
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
	before := cp.deadAddrsLocked()
	cp.health.answered(addr, start)
	newly := cp.newlyDeadLocked(before)
	if len(newly) > 0 {
		log.Printf("credpool: relay %s answered — %d relay(s) unanswered since the previous answer marked UNREACHABLE", addr, len(newly))
	}
	stamp := cp.stampLocked()
	cp.mu.Unlock()
	cp.fireRelayMarked(newly, stamp)
}

// stampLocked: the hand-out counter as it stands now, under the lock — the
// notice of a mark carries it (relaymarkend.go). The counter is the POOL's
// and moves where an address is handed out, under this same lock (get →
// stampHandOutLocked): a hand-out and a mark are thereby ordered — a stamp
// at or below the mark's was made before it (the user's review of 6e86895:
// a counter moved after get returned let a mark in between read a stamp
// below the hand-out's own, and the notice spared the session).
func (cp *credPool) stampLocked() uint64 {
	return cp.handSeq
}

// handOutLocked is THE hand-out: the seat taken on slot's credential at addr
// and the connection's stamp moved, under the lock, as one body — get's
// three ways of handing an address out (a ready slot, a fresh mint, the slot
// found after a failed fetch) all go through it (the user's review of
// b220706: the stamp behind the first of the three alone left a hand-out
// after a mint with the connection's previous stamp, and a late notice of an
// old mark ended the new session). A scan pins that get seats nothing bare.
func (cp *credPool) handOutLocked(connIdx, slot int, addr string) uint64 {
	cp.seatLocked(slot, addr)
	return cp.stampHandOutLocked(connIdx)
}

// stampHandOutLocked moves the hand-out counter for connIdx's hand-out, under
// the lock, at the moment the address is handed out (handOutLocked), and
// returns THIS hand-out's stamp — the session's generation (the user's review
// of af80e3c: read back from the table later, the stamp was whatever the
// LATEST hand-out on the index had left there, another session's after a
// Resume or a ForceReconnect, which start new sessions without waiting for
// the old ones).
func (cp *credPool) stampHandOutLocked(connIdx int) uint64 {
	cp.handSeq++
	if cp.handStamp == nil {
		cp.handStamp = map[int]uint64{}
	}
	cp.handStamp[connIdx] = cp.handSeq
	return cp.handSeq
}

// handStampOf: the stamp of connIdx's latest hand-out (0 = none).
func (cp *credPool) handStampOf(connIdx int) uint64 {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.handStamp[connIdx]
}

// relayMarkedSince: whether addr is marked UNREACHABLE now and the stamp its
// mark saw — the record of a hand-out asks it (recordHandOut): a hand-out
// stamped at or below it was made before the mark and is ended there.
func (cp *credPool) relayMarkedSince(addr string) (uint64, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	r := cp.health.rec[addr]
	if r == nil || !r.dead {
		return 0, false
	}
	return r.markSeq, true
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
	before := cp.deadAddrsLocked()
	cp.health.answered("", start)
	newly := cp.newlyDeadLocked(before)
	if len(newly) == 0 {
		return
	}
	log.Printf("credpool: VK answered — %d relay(s) unanswered since the previous answer marked UNREACHABLE", len(newly))
	// The third way a relay gets marked fires the hook too (the user's review
	// of 589dfb2) — from a goroutine, since this runs under the lock inside
	// get and tryFill, across several of their returns; the stamp is read
	// here, under the lock, as on the other two paths.
	stamp := cp.stampLocked()
	go cp.fireRelayMarked(newly, stamp)
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
		if !cp.isFreshLocked(i) || cp.usableLocked(i) || cp.configuredOffLocked(i) {
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
	if len(cp.override.servers) > 0 {
		go cp.reresolveOverride("every relay of the list marked unreachable", true) // DNS may name another relay by now (#105)
	}
	var why string
	switch {
	case len(cp.override.servers) > 0 && !cp.override.hasVK():
		// A FIXED list: a mint would name the same relays. With `$vkurls` in
		// it a fresh credential may come with other VK relays — a mint is the
		// way out, as without an override (the cases below).
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
	go cp.reresolveOverride("path change", false) // the new network may see another DNS answer (#105)
}

// overrideServers is the override list as the pool dials it — the ONE list
// the cookie minter is handed too (the user's review of 453: the minter was
// given the configured names while the pool held their IPs; a name resolving
// to two IPs left slot 1 "unfilled" with the second IP in the pool).
func (cp *credPool) overrideServers() []string {
	if cp == nil {
		return nil
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.override.servers...)
}

// overrideResolveMinGap: how often the exhaustion trigger may resolve the
// names again (the park fires on every hand-out while the list is dead).
const overrideResolveMinGap = 30 * time.Second

// reresolveOverride resolves the override list's names again — when every
// relay of the list is marked (limited: once per overrideResolveMinGap), at a
// path change and on an invalidate (unlimited): a DNS change to another relay
// reaches the client (the user's review of 453: one resolution for the pool's
// whole life). Runs without the lock (DNS I/O); a lookup that leaves a name
// unresolved keeps the list as it was; a changed list recomputes every slot's
// candidates and wakes the parked connections.
func (cp *credPool) reresolveOverride(reason string, limited bool) {
	cp.mu.Lock()
	o := cp.override
	now := time.Now()
	if !o.hasName() || cp.overrideResolving || (limited && !cp.overrideResolvedAt.IsZero() && now.Sub(cp.overrideResolvedAt) < overrideResolveMinGap) {
		cp.mu.Unlock()
		return
	}
	cp.overrideResolving = true
	cp.overrideResolvedAt = now
	raw := append([]string(nil), o.raw...)
	cp.mu.Unlock()

	// 🚫 Not the app's pre-resolved map (resolvedVKHostIPs): it is the
	// start's snapshot of these very names — read first, it answered every
	// re-resolution with the start's IPs and no lookup was ever made (the
	// user's review of 454). DNS, bounded (ResolveTURNServers).
	servers := ResolveTURNServers(context.Background(), raw, nil)

	cp.mu.Lock()
	cp.overrideResolving = false
	before := strings.Join(cp.override.servers, ", ")
	var next turnOverride
	next.setServers(servers)
	switch {
	case !allIPs(servers):
		cp.mu.Unlock()
		log.Printf("credpool: TURN relay override not resolved again (%s): a name did not resolve — the list stays %s", reason, before)
		return
	case strings.Join(next.servers, ", ") == before:
		cp.mu.Unlock()
		return
	}
	cp.override.servers, cp.override.quotas, cp.override.paces = next.servers, next.quotas, next.paces // the name's fields on its new IPs — the paces too (the user's review of 9d58dda)
	servers = next.servers
	if cp.mode == credCacheModeCookie {
		cp.growForListLocked()               // more fixed entries: more slots, VK's kept
		cp.rebindOverrideSlotsLocked(reason) // the slot's relay is its own, not the list's i-th
	}
	for i := range cp.pool {
		if cp.pool[i].creds == nil || cp.mode == credCacheModeCookie {
			continue
		}
		cp.pool[i].addrs = cp.candidatesForSlot(i, cp.pool[i].creds)
		cp.applyRelayQuarantineLocked(i)
	}
	cp.mu.Unlock()
	log.Printf("credpool: TURN relay override resolved again (%s): %s → %s", reason, before, strings.Join(servers, ", "))
	cp.broadcastSlotAvailable()
}

// cookiePoolSize: the cookie pool's slots — two per call link (one per VK
// relay of the link's answer) PLUS the list's fixed entries: a fixed entry
// took one of the link's two slots and the VK fallback lost a relay for each
// (the user's review, 2026-10-31: three links, six VK relays, one own relay —
// sixty connections on it, fifty found a VK slot when it died). The ONE rule,
// applied by setOverride at the pool's creation and at every later list
// (growForListLocked); the constructors size two per link.
func cookiePoolSize(links int, o turnOverride) int {
	fixed, _ := o.cookieShape()
	return 2*links + len(fixed)
}

// growForListLocked (cookie mode): the pool has at least cookiePoolSize slots
// for the list it holds now — a list that gained fixed entries (a name
// resolving to more IPs, a changed setting) takes none of VK's slots. The pool
// never shrinks: a slot beyond the list dials nothing (candidatesForSlot).
func (cp *credPool) growForListLocked() {
	if cp.mode != credCacheModeCookie {
		return
	}
	want := cookiePoolSize(len(cookieLinks()), cp.override)
	for len(cp.pool) < want {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	if want > cp.size {
		log.Printf("credpool: cookie mode — the pool grows %d → %d slots for the list's %d fixed entr(ies)", cp.size, want, want-2*len(cookieLinks()))
		cp.size = want
	}
}

// unlimitedCap: a slot's cap on a relay without a quota.
const unlimitedCap = math.MaxInt32

// unlimitedRelayLocked: the relay slot's connections dial now, when the list
// says it has no quota (pickAddrLocked hands it out ahead of the cursor), ""
// otherwise.
func (cp *credPool) unlimitedRelayLocked(slot int) string {
	if relay := cp.dialNowLocked(slot); relay != "" && cp.override.unlimited(relay) {
		return relay
	}
	return ""
}

// capLocked is how many connections slot's credential may seat on the relay
// its connections dial now: the relay's configured quota when it has one (0 =
// no limit — the user's own relay), else VK's ten (connsPerSlot). For the
// logs and the counts; a hand-out asks of the relay picked for the connection
// (capOnLocked, roomOnLocked).
func (cp *credPool) capLocked(slot int) int {
	return cp.capOnLocked(cp.dialNowLocked(slot))
}

// quarantinedRelays: the relays whose quota clock is running (cookie mode) —
// what the minter's discovery is told to prefer others over. Not under cp.mu.
func (cp *credPool) quarantinedRelays() []string {
	if cp == nil {
		return nil
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var out []string
	for relay := range cp.relayUsedAt {
		if !cp.relayQuarantineUntilLocked(relay).IsZero() {
			out = append(out, relay)
		}
	}
	sort.Strings(out)
	return out
}

// heldRelaysExcept lists the relays the pool's slots hold — every filled
// slot's candidates but slot's own — for the cookie mint: in cookie mode a
// relay held by one slot must not be minted for another (one okcdn user id,
// one quota of ten per relay; 2026-10-20, the user's run 9: two slots on one
// relay, 486 on the second). nil pool, no slots: nothing.
func (cp *credPool) heldRelaysExcept(slot int) []string {
	if cp == nil {
		return nil
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var out []string
	for i := range cp.pool {
		if i == slot || cp.pool[i].creds == nil {
			continue
		}
		out = append(out, cp.candidatesLocked(i)...)
	}
	return dedupeAddrs(out)
}

// cookieRelayTwinLocked: in cookie mode, the other filled slot whose one relay
// is the same as slot's would be — two slots on one relay under one okcdn
// user id are one quota of ten (the user's run 9: 486 on the second). -1: none.
func (cp *credPool) cookieRelayTwinLocked(slot int, creds *TURNCreds) int {
	if cp.mode != credCacheModeCookie || creds == nil {
		return -1
	}
	key := cp.candidatesForSlot(slot, creds)
	if len(key) != 1 {
		return -1
	}
	for i := range cp.pool {
		if i == slot || cp.pool[i].creds == nil {
			continue
		}
		if c := cp.candidatesLocked(i); len(c) == 1 && c[0] == key[0] {
			return i
		}
	}
	return -1
}

// configuredOffLocked: the slot has no relay by CONFIGURATION — cookie mode
// under an override list: a slot beyond the list, a filled slot whose relay
// the list no longer names (rebindSlotLocked keeps it there while leases are
// live on it) or one the list has no free entry for — not because its relays
// are unreachable: it holds nothing back (the user's review of 449: the only
// cached credential beyond the list made healthParkLocked park every
// connection before the first mint), and it is handed out no more.
func (cp *credPool) configuredOffLocked(slot int) bool {
	if cp.mode != credCacheModeCookie || len(cp.override.servers) == 0 {
		return false
	}
	fixed, vkTail := cp.override.cookieShape()
	if slot >= len(fixed) && !vkTail {
		return true
	}
	if slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return false
	}
	c := cp.candidatesLocked(slot)
	if slot >= len(fixed) {
		return len(c) != 1 // a VK slot: its own relay, or nothing
	}
	return len(c) != 1 || !cp.inOverrideListLocked(c[0])
}

// inOverrideListLocked: a FIXED entry of the list names this relay.
func (cp *credPool) inOverrideListLocked(relay string) bool {
	if relay == "" {
		return false
	}
	fixed, _ := cp.override.cookieShape()
	for _, s := range fixed {
		if s == relay {
			return true
		}
	}
	return false
}

// freeListRelayLocked (cookie mode under a list): the entry of the list no
// OTHER filled slot dials — slot's own index preferred, else the first free;
// "" when every entry is held.
func (cp *credPool) freeListRelayLocked(slot int) string {
	held := map[string]bool{}
	for i := range cp.pool {
		if i == slot || cp.pool[i].creds == nil {
			continue
		}
		for _, a := range cp.candidatesLocked(i) {
			held[a] = true
		}
	}
	list, _ := cp.override.cookieShape() // the fixed entries; a VK slot takes none
	if slot >= len(list) {
		return ""
	}
	if !held[list[slot]] {
		return list[slot]
	}
	for _, a := range list {
		if !held[a] {
			return a
		}
	}
	return ""
}

// rebindSlotLocked (cookie mode under a list): the list changed under a
// filled slot — its relay is ITS OWN, not the list's s-th entry (the user's
// review of 454: a DNS answer in the other order re-pointed slot 0, ten leases
// on A, to B by index, and slot 1, now "on A" with none, was handed an
// eleventh). The slot keeps its relay while the list still names it. A slot
// whose relay the list dropped keeps it while leases are live on it — the
// seats are that relay's, its releases move that relay's clock, and the slot
// is handed out no more (configuredOffLocked) — and takes the free entry of
// the list once none is: here, or at the release that frees the last seat
// (rebindOverrideSlotsLocked). Beyond the list the slot dials nothing once
// its leases are gone.
//
// Two passes over the pool (rebindOverrideSlotsLocked): first every slot that
// LOSES its relay lets go of it — beyond the list, or a dropped relay with no
// lease left — then every slot of the list without a relay takes a free entry.
// In one pass, slot 0 found B still slot 1's while slot 1 was yet to be
// switched off as beyond the shrunk list [B]: both ended without a relay and
// B sat idle (the user's review of 455).
func (cp *credPool) rebindSlotLocked(slot int, reason string) {
	cp.releaseStaleRelayLocked(slot, reason)
	cp.takeFreeEntryLocked(slot, reason)
}

// releaseStaleRelayLocked — the first pass: the slot lets go of a relay the
// list no longer gives it, unless leases are live on it.
func (cp *credPool) releaseStaleRelayLocked(slot int, reason string) {
	if cp.mode != credCacheModeCookie || len(cp.override.servers) == 0 || slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return
	}
	e := &cp.pool[slot]
	if len(e.addrs) != 1 {
		return
	}
	cur := e.addrs[0]
	if e.active > 0 {
		return // leases live on its relay: the slot stays that relay's
	}
	fixed, vkTail := cp.override.cookieShape()
	if slot >= len(fixed) && vkTail {
		return // a VK slot: its relay is VK's, not the list's to drop
	}
	if slot < len(fixed) && cp.inOverrideListLocked(cur) {
		return // the list still names it
	}
	e.addrs = nil
	cp.applyRelayQuarantineLocked(slot)
	cp.syncMinterLocked(slot)
	if slot >= len(fixed) {
		log.Printf("credpool: slot %d: beyond the TURN override list (%s) and its leases on %s are gone — the slot dials nothing", slot, reason, cur)
	} else {
		log.Printf("credpool: slot %d: the TURN override list (%s) no longer names its relay %s — the slot lets it go", slot, reason, cur)
	}
}

// takeFreeEntryLocked — the second pass: a slot of the list without a relay
// takes a free entry, when there is one.
func (cp *credPool) takeFreeEntryLocked(slot int, reason string) {
	fixed, _ := cp.override.cookieShape()
	if cp.mode != credCacheModeCookie || slot < 0 || slot >= len(fixed) || slot >= len(cp.pool) || cp.pool[slot].creds == nil || len(cp.pool[slot].addrs) > 0 {
		return
	}
	next := cp.freeListRelayLocked(slot)
	if next == "" {
		log.Printf("credpool: slot %d: the TURN override list (%s) has no free entry — the slot dials nothing until one is free", slot, reason)
		return
	}
	cp.pool[slot].addrs = []string{next}
	cp.pool[slot].addr = next
	cp.applyRelayQuarantineLocked(slot)
	cp.syncMinterLocked(slot)
	log.Printf("credpool: slot %d: the TURN override list (%s) has a free entry — the slot dials %s", slot, reason, next)
}

// rebindOverrideSlotsLocked: the two passes over every filled slot — at a
// re-resolution of the list and at the release that frees the last seat of a
// slot the list switched off (its relay dropped).
func (cp *credPool) rebindOverrideSlotsLocked(reason string) {
	if cp.mode != credCacheModeCookie || len(cp.override.servers) == 0 {
		return
	}
	for i := range cp.pool {
		cp.releaseStaleRelayLocked(i, reason)
	}
	for i := range cp.pool {
		cp.takeFreeEntryLocked(i, reason)
	}
}

// relayQuarantineUntilLocked: until when the relay's seats may still be held
// by leases that ended (cookie mode: one okcdn user id, the quota the
// relay's) — the zero time when the relay was not used within the cooldown.
func (cp *credPool) relayQuarantineUntilLocked(relay string) time.Time {
	if cp.mode != credCacheModeCookie || relay == "" || cp.override.unlimited(relay) {
		return time.Time{} // a relay without a quota holds no seats
	}
	t, ok := cp.relayUsedAt[relay]
	if !ok {
		return time.Time{}
	}
	if until := t.Add(credSaturationCooldown); until.After(time.Now()) {
		return until
	}
	return time.Time{}
}

// noteRelayUsedLocked: a lease on slot's relay ended at `at` — the relay's
// clock moves (cookie mode; the relay the slot DIALS, one in that mode).
func (cp *credPool) noteRelayUsedLocked(slot int, at time.Time) {
	if cp.mode != credCacheModeCookie {
		return
	}
	if c := cp.candidatesLocked(slot); len(c) == 1 && at.After(cp.relayUsedAt[c[0]]) {
		cp.relayUsedAt[c[0]] = at
	}
}

// applyRelayQuarantineLocked (cookie mode): slot's availableAt IS the clock
// of the relay it dials now — not of a relay it dialled under an earlier
// override, not of a twin on another relay (the user's review of 450: A's
// quarantine carried onto a never-used B; a twin's quarantine lost with it).
// The slot's own history lives in the clock already (noteRelayUsedLocked,
// loadFromDisk). Anonymous mode: the entry's own availableAt, untouched.
func (cp *credPool) applyRelayQuarantineLocked(slot int) {
	if cp.mode != credCacheModeCookie || slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return
	}
	var until time.Time
	if c := cp.candidatesLocked(slot); len(c) == 1 {
		until = cp.relayQuarantineUntilLocked(c[0])
	}
	cp.pool[slot].availableAt = until
}

// placeLocked puts an entry into slot and applies the relay's quota clock to
// it (cookie mode) — the ONE way an entry with a credential enters the pool.
func (cp *credPool) placeLocked(slot int, e credPoolEntry) {
	for len(cp.pool) <= slot {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	cp.pool[slot].stopSaturationTimers()
	cp.pool[slot] = e
	cp.applyRelayQuarantineLocked(slot)
	cp.syncMinterLocked(slot)
}

// syncMinterLocked (cookie mode under a list): the minter's reservation of a
// relay for slot follows what the slot dials NOW — the placement may have put
// the credential on another entry than the minter chose (candidatesForSlot),
// a re-binding may have moved or emptied it; a reservation left behind kept
// the next mint from that entry ("every one held" — the user's review of
// 455, with the list shrunk under two filled slots).
func (cp *credPool) syncMinterLocked(slot int) {
	if cp.mode != credCacheModeCookie || len(cp.override.servers) == 0 {
		return
	}
	relay := ""
	if c := cp.candidatesLocked(slot); len(c) == 1 {
		relay = c[0]
	}
	cookieNoteSlotRelay(slot, relay)
}

// heldByAnotherLocked: a filled slot other than slot dials relay.
func (cp *credPool) heldByAnotherLocked(slot int, relay string) bool {
	for i := range cp.pool {
		if i == slot || cp.pool[i].creds == nil {
			continue
		}
		for _, a := range cp.candidatesLocked(i) {
			if a == relay {
				return true
			}
		}
	}
	return false
}
