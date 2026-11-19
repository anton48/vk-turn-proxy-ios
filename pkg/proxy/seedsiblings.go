package proxy

import (
	"log"
	"time"
)

// Cookie mode: the seed's credential on every relay VK named with it.
//
// In anonymous mode the relays VK names with a credential are that slot's
// candidates, so a seed that carries the list can fail over on a cold cache.
// In cookie mode a slot IS a relay — one (account, relay) quota of its own —
// and a slot dials its credential's ONE relay: the seed's list was read by
// nothing, and a cold pool knew one relay. Behind a peer handshake timeout
// through it there was no alternate to plan; behind a silent one, no second
// slot without a mint.
//
// The minter serves both relays of one call from ONE credential into two
// slots (cookieCredForSlot); the seed's further relays are slots of that very
// kind, made here from the answer the app's probe already holds: no VK
// request, and there before the first connection asks. A cold start then
// looks like a warm one.
//
// The relay each slot dials is the PLACEMENT's word (candidatesForSlot), as
// for every credential: without an override list the relay VK named; under a
// list its free entry for a fixed slot, VK's own for a slot behind `$vkurls`,
// nothing beyond the list.
//
// 🚫 A relay a filled slot already dials gets no second slot — loaded from
// disk, relocated, minted, a sibling placed a moment ago: two slots on one
// relay are one quota. The sibling yields; it evicts nobody.
// 🚫 A slot with a credential in it, or a fetch in flight for it, is not
// taken.

// seedSibling: a slot filled with the seed's credential, and the relay it dials.
type seedSibling struct {
	slot  int
	relay string
}

// seedSiblingsLocked places the seed's credential into the empty slots that
// may dial a relay nobody dials yet. Caller holds cp.mu.
func (cp *credPool) seedSiblingsLocked(seed *TURNCreds) []seedSibling {
	if cp.mode != credCacheModeCookie || seed == nil {
		return nil
	}
	named := append([]string{seed.Address}, seed.Addresses...) // its own relay first: a fixed slot of a list asks for no more
	var placed []seedSibling
	for slot := range cp.pool[:min(cp.size, len(cp.pool))] { // never a slot beyond the pool's size: nothing counts or refills one
		if cp.pool[slot].creds != nil || cp.pool[slot].fetching {
			continue
		}
		for _, relay := range named {
			sib := &TURNCreds{Username: seed.Username, Password: seed.Password, Address: relay, Addresses: []string{relay}}
			dial := cp.candidatesForSlot(slot, sib)
			if len(dial) != 1 || cp.heldByAnotherLocked(slot, dial[0]) {
				continue
			}
			cp.nextGen++
			cp.placeLocked(slot, credPoolEntry{addr: relay, addrs: dial, creds: sib, ts: time.Now(), active: cp.outstandingLocked(slot, sib), gen: cp.nextGen})
			placed = append(placed, seedSibling{slot: slot, relay: dial[0]})
			break
		}
	}
	return placed
}

// dialsAnotherRelayLocked (cookie mode): slot's credential dials one relay and
// `creds`, placed there, would dial another — the slot's content is not the
// credential being placed, whatever their usernames. Caller holds cp.mu.
func (cp *credPool) dialsAnotherRelayLocked(slot int, creds *TURNCreds) bool {
	if cp.mode != credCacheModeCookie {
		return false
	}
	now, then := cp.candidatesLocked(slot), cp.candidatesForSlot(slot, creds)
	return len(now) == 1 && len(then) == 1 && now[0] != then[0]
}

// seedSiblingsPlaced: what follows a placement outside the lock — the line,
// and each slot's auth-error tally begun anew for the credential it now holds.
func (cp *credPool) seedSiblingsPlaced(placed []seedSibling) {
	for _, s := range placed {
		log.Printf("credpool: slot %d takes the seed's credential on relay %s (cookie mode: every relay VK named with the seed is a slot of its own — no VK request)", s.slot, s.relay)
		if s.slot < len(cp.authErrors) {
			cp.authErrors[s.slot].Store(0)
		}
	}
}
