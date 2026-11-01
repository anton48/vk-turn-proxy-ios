package proxy

import (
	"log"
	"time"
)

// relayHist is what a credential did on ONE relay: the seats it held there and
// the marks about them. VK's quota is per (identity, relay) — measured
// 2026-09-21 — so the history is too: a slot's ten seats on VK's relay say
// nothing about the user's own relay in front of it, and the other way round.
//
// Until 2026-10-31 an entry kept ONE history whatever relay its connections
// dialled, and every readiness question read it against the FIRST candidate
// of the moment. The user's review: with the own relay (`host:port:0`) dead,
// ten connections sat on VK's relay; a path change cleared the relay marks,
// the own relay was the first candidate again, and the smart-pause skipped
// the slot as one that holds no seats — when the own relay was found dead
// again the pool handed the same credential out for VK's relay at once, its
// ten allocations still held there: a 486 cascade where a pause was due.
//
// A credential's entry holds one relayHist per relay it was dialled on
// (credPoolEntry.on) and ONE for history whose relay is not known — the entry's
// own embedded fields: a cache file from before `used_on`, a seed, a mark that
// named no relay. A question about a relay without a record of its own is
// answered by that one (histLocked).
type relayHist struct {
	// lastUsedAt is the moment the last seat on this relay was given back —
	// while seats are held it is not moved (saveToDisk writes "now" for a
	// relay with seats). Zero: never used.
	lastUsedAt time.Time

	// availableAt is VK's clock on this relay: the earliest moment the
	// credential's seats there can all have expired. Set by loadFromDisk
	// from the file's `used_on` (lastUsedAt + credSaturationCooldown) when
	// that is still ahead; zero otherwise. In cookie mode the clock is the
	// RELAY's, pool-wide (relayQuarantineUntilLocked), and this field is not
	// read. A relay without a quota has no clock (clockLocked).
	availableAt time.Time

	// saturatedUntil: a 486 from this relay, or a path change's smart-pause
	// over the seats held there, benches the credential ON THIS RELAY until
	// then — on another relay the same credential is not benched.
	saturatedUntil time.Time

	// saturationTimer fires broadcastSlotAvailable when saturatedUntil
	// passes (markSaturated's timer; nil when never marked).
	saturationTimer *time.Timer
}

// histLocked is the credential's history on relay, for reading: the entry's
// history whose relay is not known — it applies to EVERY relay — joined with
// the relay's own record, the later moment of each. The zero history for an
// empty slot. Caller holds cp.mu.
func (cp *credPool) histLocked(slot int, relay string) relayHist {
	if slot < 0 || slot >= len(cp.pool) {
		return relayHist{}
	}
	e := &cp.pool[slot]
	h := e.relayHist
	h.saturationTimer = nil
	if relay == "" {
		return h
	}
	if r := e.on[relay]; r != nil {
		if r.lastUsedAt.After(h.lastUsedAt) {
			h.lastUsedAt = r.lastUsedAt
		}
		if r.availableAt.After(h.availableAt) {
			h.availableAt = r.availableAt
		}
		if r.saturatedUntil.After(h.saturatedUntil) {
			h.saturatedUntil = r.saturatedUntil
		}
	}
	return h
}

// histPtrLocked is the credential's history on relay, for writing: the
// relay's own record, made when there is none; the entry's own for a relay
// not known (""). nil for an empty slot. Caller holds cp.mu.
func (cp *credPool) histPtrLocked(slot int, relay string) *relayHist {
	if slot < 0 || slot >= len(cp.pool) {
		return nil
	}
	e := &cp.pool[slot]
	if relay == "" {
		return &e.relayHist
	}
	if e.on == nil {
		e.on = map[string]*relayHist{}
	}
	h := e.on[relay]
	if h == nil {
		h = &relayHist{}
		e.on[relay] = h
	}
	return h
}

// dialNowLocked is the relay the slot's connections dial now: the first
// candidate not marked unreachable, else the first candidate (every one
// marked: the re-try path), "" with none. The slot-level readiness questions
// (counts, the grower, the logs) are asked of this relay; a hand-out asks of
// the relay picked for THAT connection (pickAcquireSlotLocked). Caller holds
// cp.mu.
func (cp *credPool) dialNowLocked(slot int) string {
	cands := cp.candidatesLocked(slot)
	if len(cands) == 0 {
		return ""
	}
	if alive := cp.health.alive(cands); len(alive) > 0 {
		return alive[0]
	}
	return cands[0]
}

// peekAddrLocked is the relay connIdx would be handed on slot's credential —
// pickAddrLocked's choice without its side effect (a re-try's claim): the
// relay without a quota while it answers (unlimitedFirstLocked), else the
// unmarked candidate at the connection's cursor (cursorPickLocked); every
// candidate marked, the one the re-try would dial (probePeek — the same
// selection the claim is taken by); else the relay the slot dials now. Caller
// holds cp.mu.
func (cp *credPool) peekAddrLocked(slot, connIdx int) string {
	cands := cp.candidatesLocked(slot)
	if alive := cp.health.alive(cands); len(alive) > 0 {
		if addr, ok := cp.unlimitedFirstLocked(alive); ok {
			return addr
		}
		return cp.cursorPickLocked(alive, connIdx)
	}
	if addr, ok := cp.health.probePeek(cands); ok {
		return addr
	}
	return cp.dialNowLocked(slot)
}

// clockLocked is VK's clock for the credential in slot ON relay: until when
// its seats there may still be held by a session that ended. Anonymous mode:
// the relay's history (loadFromDisk's `used_on`, or the entry's own for a
// file from before it). Cookie mode: the relay's clock under one okcdn user
// id as it stood when the slot was placed or re-pointed (the entry's own
// availableAt — applyRelayQuarantineLocked; a slot dials one relay there). A
// relay without a quota — the list's host:port:0 — has none. Zero: no clock.
// Caller holds cp.mu.
func (cp *credPool) clockLocked(slot int, relay string) time.Time {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return time.Time{}
	}
	if relay != "" && cp.override.unlimited(relay) {
		return time.Time{}
	}
	if cp.mode == credCacheModeCookie {
		return cp.pool[slot].availableAt
	}
	return cp.histLocked(slot, relay).availableAt
}

// markLocked: until when the credential in slot is benched ON relay (a 486
// from it, a path change's smart-pause over the seats held there). A relay
// without a quota is never benched. Zero: not benched. Caller holds cp.mu.
func (cp *credPool) markLocked(slot int, relay string) time.Time {
	if slot < 0 || slot >= len(cp.pool) {
		return time.Time{}
	}
	if relay != "" && cp.override.unlimited(relay) {
		return time.Time{}
	}
	return cp.histLocked(slot, relay).saturatedUntil
}

// capOnLocked is how many connections a credential may seat ON relay: the
// relay's configured quota (0 = no limit — the user's own relay), else VK's
// ten (connsPerSlot). Caller holds cp.mu.
func (cp *credPool) capOnLocked(relay string) int {
	if q, ok := cp.override.quota(relay); ok {
		if q == 0 {
			return unlimitedCap
		}
		return q
	}
	return connsPerSlot
}

// seatsOnLocked: the leases out on slot's credential that were handed out
// FOR relay — the record's count (credPool.seats). Caller holds cp.mu; 0 for
// an empty slot.
func (cp *credPool) seatsOnLocked(slot int, relay string) int {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return 0
	}
	return cp.seats[leaseKeyOf(slot, cp.pool[slot].creds)][relay]
}

// oneRelayWithSeatsLocked: the relay the leases on k are out on, when they are
// all on one; "" with none or with seats on several — for a caller that does
// not name the relay (a lease taken before the record was kept, a test).
// Caller holds cp.mu.
func (cp *credPool) oneRelayWithSeatsLocked(k leaseKey) string {
	found := ""
	for relay, n := range cp.seats[k] {
		if n > 0 {
			if found != "" {
				return ""
			}
			found = relay
		}
	}
	return found
}

// unattributedLocked: the seats the entry counts (active) beyond those the
// record knows the relay of — leases from before the record, a seed's own
// seat, a test's — read as held on EVERY relay. Caller holds cp.mu.
func (cp *credPool) unattributedLocked(slot int) int {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return 0
	}
	n := cp.pool[slot].active
	for _, c := range cp.seats[leaseKeyOf(slot, cp.pool[slot].creds)] {
		n -= c
	}
	if n < 0 {
		return 0
	}
	return n
}

// roomOnLocked: slot's credential may seat one more connection ON relay —
// its seats there (and the seats whose relay is not known) are under the
// relay's quota (the user's review of 2026-10-31: the cap was read off the
// FIRST unmarked candidate while the connection's cursor dialled the second
// — a third seat on a relay with a quota of two). Caller holds cp.mu.
func (cp *credPool) roomOnLocked(slot int, relay string) bool {
	return cp.seatsOnLocked(slot, relay)+cp.unattributedLocked(slot) < cp.capOnLocked(relay)
}

// freshOnLocked: the credential in slot may be handed out for relay as far as
// VK's clock goes — valid, and the clock on THAT relay has run out. Caller
// holds cp.mu.
func (cp *credPool) freshOnLocked(slot int, relay string) bool {
	if slot < 0 || slot >= len(cp.pool) || !entryCredValid(cp.pool[slot]) {
		return false
	}
	return !time.Now().Before(cp.clockLocked(slot, relay))
}

// relaysWithHistoryLocked lists the relays the credential in slot has a
// record on — seats out, or a history of its own — and "" when the entry's
// own history (relay not known) has seats or a last use. Caller holds cp.mu.
func (cp *credPool) relaysWithHistoryLocked(slot int) []string {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return nil
	}
	e := &cp.pool[slot]
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for r, n := range cp.seats[leaseKeyOf(slot, e.creds)] {
		if n > 0 {
			add(r)
		}
	}
	for r := range e.on {
		add(r)
	}
	// The entry's own history (relay not known) stands for every relay the
	// slot dials: seats the record cannot place, or a last use with no
	// record at all (a file from before `used_on`).
	if cp.unattributedLocked(slot) > 0 || (len(e.on) == 0 && !e.lastUsedAt.IsZero()) {
		add("")
	}
	return out
}

// stopSaturationTimersLocked stops every mark's timer on the entry (the entry
// is about to be replaced). Caller holds cp.mu.
func (e *credPoolEntry) stopSaturationTimers() {
	if e.saturationTimer != nil {
		e.saturationTimer.Stop()
	}
	for _, h := range e.on {
		if h.saturationTimer != nil {
			h.saturationTimer.Stop()
		}
	}
}

// sayReadyDespiteTheClockLocked assumes cp.mu is held: a slot whose
// credential waits for VK's clock on one relay but dials a relay without a
// quota now is said so once, at the override (the load precedes it, so the
// load's own line says "pending"), so the log reads why a "pending" slot
// seats connections.
func (cp *credPool) sayReadyDespiteTheClockLocked(slot int, when string) {
	if slot < 0 || slot >= len(cp.pool) || cp.pool[slot].creds == nil {
		return
	}
	relay := cp.dialNowLocked(slot)
	if relay == "" || !cp.override.unlimited(relay) {
		return
	}
	now := time.Now()
	var until time.Time
	e := &cp.pool[slot]
	if e.availableAt.After(now) {
		until = e.availableAt
	}
	for _, h := range e.on {
		if h.availableAt.After(until) {
			until = h.availableAt
		}
	}
	if !until.After(now) {
		return
	}
	log.Printf("credpool: %s: slot %d pending by VK's clock (usable at VK in %s) — ready on %s now, which has no quota",
		when, slot, until.Sub(now).Round(time.Second), relay)
}
