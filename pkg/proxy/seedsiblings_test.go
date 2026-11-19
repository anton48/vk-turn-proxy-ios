package proxy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Cookie mode, a cold cache. The app's probe mints the first call link, VK
// names two relays with the credential, and the pool's seed was one slot on
// the first of them: a slot IS a relay there, so the second relay had no slot
// until somebody asked VK again. With the first relay dead — silent, or
// answering TURN and not forwarding — the bootstrap's lone connection had
// nowhere to go without a request to VK.
//
// The seed's credential is a slot on EVERY relay VK named with it, as the
// minter's own credential is; the probe's answer carries the list.

var seedRelayNames = map[string]string{relayA: "A", relayB: "B", relayC: "C", relayE: "E", relayF: "F", relayO: "O"}

// cookieSeedPool: a cookie-mode pool of `size` slots; a mint would land on C.
func cookieSeedPool(t *testing.T, cachePath string, size int) (*credPool, *atomic.Int32, *time.Time) {
	t.Helper()
	cookieTestMode(t)
	return relayPoolN(t, cachePath, size, relayC)
}

// seedSlotsOf: every filled slot as "slot:relay:tag" — the relay it DIALS and
// the tag of the credential it holds. Two slots on one relay fail the test:
// in cookie mode that is one quota.
func seedSlotsOf(t *testing.T, cp *credPool) []string {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	var out []string
	dialled := map[string]int{}
	for i := range cp.pool {
		if cp.pool[i].creds == nil {
			continue
		}
		var names []string
		for _, relay := range cp.candidatesLocked(i) {
			name, ok := seedRelayNames[relay]
			if !ok {
				name = "?"
			}
			names = append(names, name)
			if prev, twice := dialled[relay]; twice && cp.mode == credCacheModeCookie {
				t.Fatalf("slots %d and %d both dial relay %s — two slots on one relay are one quota", prev, i, name)
			}
			dialled[relay] = i
		}
		user := cp.pool[i].creds.Username
		out = append(out, fmt.Sprintf("%d:%s:%s", i, strings.Join(names, "+"), user[strings.LastIndex(user, ":")+1:]))
	}
	return out
}

func wantSeedSlots(t *testing.T, cp *credPool, want ...string) {
	t.Helper()
	if got := seedSlotsOf(t, cp); !reflect.DeepEqual(got, want) {
		t.Fatalf("the pool's slots (slot:relay:credential) = %v, want %v", got, want)
	}
}

func TestACookieSeedIsASlotOnEveryRelayVKNamedWithIt(t *testing.T) {
	for _, c := range []struct {
		name      string
		cookie    bool
		addresses []string
		want      []string
	}{
		{"VK named two relays: a slot on each", true, []string{relayA, relayB}, []string{"0:A:seed", "1:B:seed"}},
		{"three relays: three slots", true, []string{relayA, relayB, relayE}, []string{"0:A:seed", "1:B:seed", "2:E:seed"}},
		{"one relay: the seed alone, as it always was", true, nil, []string{"0:A:seed"}},
		{"anonymous mode: the list is the ONE slot's candidates", false, []string{relayA, relayB}, []string{"0:A+B:seed"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cp *credPool
			var mints *atomic.Int32
			if c.cookie {
				cp, mints, _ = cookieSeedPool(t, "", 4)
			} else {
				cp, mints, _ = relayPoolN(t, "", 4, relayC)
			}
			seed := SeedCreds(relayA, futureUser("seed"), "pw", c.addresses)
			cp.seedSlot(0, relayA, seed)
			wantSeedSlots(t, cp, c.want...)
			if n := mints.Load(); n != 0 {
				t.Fatalf("%d credential(s) minted while seeding — the seed's slots are made of the seed", n)
			}
			if !c.cookie || len(c.want) < 2 {
				return
			}
			// The sibling is a credential of its own for ITS relay — the seed's
			// name and password, never the seed's struct nor its list.
			cp.mu.Lock()
			defer cp.mu.Unlock()
			sib := cp.pool[1].creds
			if sib == seed || sib == cp.pool[0].creds {
				t.Fatal("the second slot shares the seed's TURNCreds — a relay written into one would move the other")
			}
			if sib.Username != seed.Username || sib.Password != "pw" || sib.Address != relayB || !reflect.DeepEqual(sib.Addresses, []string{relayB}) {
				t.Fatalf("the second slot's credential: address %q, list %v, the seed's name %v, password %q", seedRelayNames[sib.Address], len(sib.Addresses), sib.Username == seed.Username, sib.Password)
			}
			if cp.pool[1].gen == 0 || cp.pool[1].gen == cp.pool[0].gen {
				t.Fatalf("the second slot carries no claim stamp of its own (%d)", cp.pool[1].gen)
			}
		})
	}
}

// What follows a placement: the line a device run is read by, the slot's
// auth-error tally begun anew, and nothing of either for a seed with one relay.
func TestASiblingsPlacementIsSaidAndItsTallyBegunAnew(t *testing.T) {
	const line = "takes the seed's credential on relay " + relayB
	for _, c := range []struct {
		name      string
		addresses []string
		said      int
		tally     int64
	}{
		{"two relays", []string{relayA, relayB}, 1, 0},
		{"one relay", nil, 0, 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp, _, _ := cookieSeedPool(t, "", 4)
			cp.authErrors[1].Store(5)
			logged := captureLog(t)
			cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", c.addresses))
			if n := strings.Count(logged(), "credpool: slot 1 "+line); n != c.said {
				t.Fatalf("the placement's line was written %d time(s), want %d", n, c.said)
			}
			if got := cp.authErrors[1].Load(); got != c.tally {
				t.Fatalf("slot 1's auth-error tally is %d, want %d", got, c.tally)
			}
		})
	}
}

// Never a slot beyond the pool's size — nothing counts such a slot or refills
// it; a relay without a slot inside the size waits for the minter.
func TestASiblingNeverTakesASlotBeyondThePoolsSize(t *testing.T) {
	cp, _, _ := cookieSeedPool(t, "", 2)
	cp.mu.Lock()
	cp.pool = append(cp.pool, credPoolEntry{}, credPoolEntry{}) // slots 2 and 3: beyond the size
	cp.mu.Unlock()
	cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB, relayE}))
	wantSeedSlots(t, cp, "0:A:seed", "1:B:seed")
}

// The same credential placed into its slot again keeps the leases still out
// on it — every publish takes its count from the record (credPool.holders).
func TestASiblingPlacedAgainKeepsItsLeases(t *testing.T) {
	path := writeCookieCache(t, t.TempDir(),
		credCacheEntry{Slot: 0, Address: relayA, Addresses: []string{relayA}, Username: futureUser("disk-A"), Password: "p"})
	cp, _, _ := cookieSeedPool(t, path, 2)
	user := futureUser("seed") // ONE name for both seedings: it carries the clock's second, and a second may pass between them
	seed := func() *TURNCreds { return SeedCreds(relayA, user, "pw", []string{relayA, relayB}) }
	cp.seedSlot(0, relayA, seed())
	wantSeedSlots(t, cp, "0:A:disk-A", "1:B:seed")
	cp.mu.Lock()
	sib := cp.pool[1].creds
	for i := 0; i < 3; i++ {
		cp.seatLocked(1, relayB)
	}
	cp.pool[1] = credPoolEntry{} // the entry goes (an invalidation); its three leases are still out
	cp.mu.Unlock()
	cp.seedSlot(0, relayA, seed())
	wantSeedSlots(t, cp, "0:A:disk-A", "1:B:seed")
	cp.mu.Lock()
	active := cp.pool[1].active
	cp.mu.Unlock()
	if active != 3 {
		t.Fatalf("the slot placed again counts %d lease(s), want the three still out", active)
	}
	for i := 0; i < 3; i++ {
		cp.release(1, sib, relayB)
	}
}

// Anonymous mode is as it was. A seed that is ignored places nothing — its
// credential is not a spare slot; and one username is ONE credential set
// there: a seed with the name of the slot's credential replaces it in place.
func TestAnonymousSeedsAreAsTheyWere(t *testing.T) {
	t.Run("an ignored seed places nothing", func(t *testing.T) {
		path := writeCache(t, t.TempDir(), credCacheEntry{Slot: 0, Address: relayE, Addresses: []string{relayE}, Username: futureUser("disk-E"), Password: "p"})
		cp, _, _ := relayPoolN(t, path, 4, relayC)
		wake := cp.slotAvailableChannel()
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
		wantSeedSlots(t, cp, "0:E:disk-E")
		select {
		case <-wake:
			t.Fatal("an ignored seed that placed nothing woke the parked connections")
		default:
		}
	})
	t.Run("a seed with the slot's own name replaces it in place", func(t *testing.T) {
		cp, _, _ := relayPoolN(t, "", 4, relayC)
		user := futureUser("seed")
		old := &TURNCreds{Username: user, Password: "pw", Address: relayA, Addresses: []string{relayA}}
		cp.mu.Lock()
		cp.pool[0] = credPoolEntry{addr: relayA, addrs: []string{relayA}, creds: old, ts: time.Now(), relayHist: relayHist{availableAt: time.Now().Add(5 * time.Minute)}}
		pending := cp.pendingLocked(0)
		cp.mu.Unlock()
		if !pending {
			t.Fatal("fixture: slot 0 is not pending")
		}
		cp.seedSlot(0, relayB, SeedCreds(relayB, user, "pw", nil))
		if got := seedSlotsOf(t, cp); len(got) != 1 || !strings.HasPrefix(got[0], "0:") {
			t.Fatalf("the pool's slots = %v — one username is one credential set in anonymous mode, want slot 0 alone", got)
		}
	})
}

// The cold start itself, through the pool, for both kinds of a dead first
// relay — and nothing is asked of VK on the way.
func TestACookiePoolsColdStartMovesToTheSecondRelayWithoutAskingVK(t *testing.T) {
	t.Run("the first relay answers TURN and does not forward: the alternate is planned", func(t *testing.T) {
		for _, c := range []struct {
			name      string
			addresses []string
			planned   bool
		}{
			{"the seed names VK's two relays", []string{relayA, relayB}, true},
			{"the seed names one relay: nothing to plan (a call for which VK names one)", nil, false},
		} {
			t.Run(c.name, func(t *testing.T) {
				cp, mints, clock := cookieSeedPool(t, "", 4)
				cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", c.addresses))
				addr, creds, slot := mustGet(t, cp, 0)
				if addr != relayA {
					t.Fatalf("fixture: conn 0 was handed %s first, want the seed's own relay", seedRelayNames[addr])
				}
				cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), relayA,
					handshakeObservation{started: *clock, lastRetry: clock.Add(7 * time.Second), ended: clock.Add(10 * time.Second), timedOut: true},
					context.DeadlineExceeded, nil)
				cp.release(slot, creds, relayA)
				if planned := cp.peerProbe.pending && cp.peerProbe.alternate == relayB; planned != c.planned {
					t.Fatalf("an alternate planned: %v, want %v", planned, c.planned)
				}
				if !c.planned {
					return
				}
				next, creds2, slot2 := mustGet(t, cp, 0)
				if next != relayB {
					t.Fatalf("conn 0's next attempt was handed %s, want the second relay", seedRelayNames[next])
				}
				cp.release(slot2, creds2, next)
				if n := mints.Load(); n != 0 {
					t.Fatalf("the cold pool minted %d credential(s) to reach the second relay", n)
				}
			})
		}
	})
	t.Run("the first relay is silent: the next attempt takes the second slot", func(t *testing.T) {
		cp, mints, clock := cookieSeedPool(t, "", 4)
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
		addr, creds, slot := mustGet(t, cp, 0)
		if addr != relayA {
			t.Fatalf("fixture: conn 0 was handed %s first, want the seed's own relay", seedRelayNames[addr])
		}
		cp.noteRelayFailure(0, slot, creds, relayA, *clock, true)
		cp.release(slot, creds, relayA)
		next, creds2, slot2 := mustGet(t, cp, 0)
		if next != relayB {
			t.Fatalf("behind a silent first relay conn 0 was handed %s, want the second relay", seedRelayNames[next])
		}
		cp.release(slot2, creds2, next)
		if n := mints.Load(); n != 0 {
			t.Fatalf("the cold pool minted %d credential(s) to reach the second relay", n)
		}
	})
}

// Two slots of one credential are two quotas: ten seats on each relay, and
// the leases of one are not the other's.
func TestTheSeedsTwoSlotsSeatTenConnectionsEach(t *testing.T) {
	cp, mints, _ := cookieSeedPool(t, "", 2)
	cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
	on := map[string]int{}
	type lease struct {
		slot  int
		creds *TURNCreds
		addr  string
	}
	var leases []lease
	for conn := 0; conn < 2*connsPerSlot; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		on[addr]++
		leases = append(leases, lease{slot, creds, addr})
	}
	if on[relayA] != connsPerSlot || on[relayB] != connsPerSlot || mints.Load() != 0 {
		t.Fatalf("twenty connections: %d on the first relay, %d on the second, %d minted — want ten, ten, none", on[relayA], on[relayB], mints.Load())
	}
	cp.mu.Lock()
	a, b := cp.pool[0].active, cp.pool[1].active
	cp.mu.Unlock()
	if a != connsPerSlot || b != connsPerSlot {
		t.Fatalf("the slots count %d and %d leases, want ten each (one username, two records)", a, b)
	}
	for _, l := range leases {
		if l.slot == 1 {
			cp.release(l.slot, l.creds, l.addr)
		}
	}
	cp.mu.Lock()
	a, b = cp.pool[0].active, cp.pool[1].active
	cp.mu.Unlock()
	if a != connsPerSlot || b != 0 {
		t.Fatalf("behind the second slot's ten releases the slots count %d and %d, want ten and none", a, b)
	}
}

// A relay somebody dials gets no second slot — whoever dials it: a slot
// loaded from disk, a credential the seed displaced, the seed itself.
func TestTheSeedsSiblingYieldsToWhateverDialsTheRelay(t *testing.T) {
	t.Run("a slot loaded from disk holds the second relay", func(t *testing.T) {
		path := writeCookieCache(t, t.TempDir(),
			credCacheEntry{Slot: 3, Address: relayB, Addresses: []string{relayB}, Username: futureUser("disk-B"), Password: "p"})
		cp, _, _ := cookieSeedPool(t, path, 4)
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
		wantSeedSlots(t, cp, "0:A:seed", "3:B:disk-B")
	})
	t.Run("the credential the seed displaced is relocated first", func(t *testing.T) {
		cp, _, _ := cookieSeedPool(t, "", 4)
		pre := &TURNCreds{Username: futureUser("pre-seed"), Password: "p", Address: relayB, Addresses: []string{relayB}}
		cp.mu.Lock()
		cp.pool[0] = credPoolEntry{addr: relayB, addrs: []string{relayB}, creds: pre, ts: time.Now(), relayHist: relayHist{availableAt: time.Now().Add(5 * time.Minute)}}
		cp.mu.Unlock()
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
		wantSeedSlots(t, cp, "0:A:seed", "1:B:pre-seed")
	})
	t.Run("a fetch in flight owns its slot", func(t *testing.T) {
		cp, _, _ := cookieSeedPool(t, "", 4)
		cp.mu.Lock()
		gen := cp.claimForFetchLocked(1)
		cp.mu.Unlock()
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
		wantSeedSlots(t, cp, "0:A:seed", "2:B:seed")
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if !cp.ownsLocked(1, gen) || !cp.pool[1].fetching {
			t.Fatal("the fetch in flight for slot 1 lost its claim to the seed's sibling")
		}
	})
}

// A warm cache: slot 0 holds a fresh credential and the seed is ignored — the
// relays it names that nobody dials still get a slot each, and it is saved.
func TestAnIgnoredCookieSeedStillFillsTheRelaysNobodyDials(t *testing.T) {
	disk := func(slot int, relay, tag string) credCacheEntry {
		return credCacheEntry{Slot: slot, Address: relay, Addresses: []string{relay}, Username: futureUser(tag), Password: "p"}
	}
	for _, c := range []struct {
		name   string
		disk   []credCacheEntry
		want   []string
		placed bool
	}{
		{"the cache holds the first relay alone", []credCacheEntry{disk(0, relayA, "disk-A")}, []string{"0:A:disk-A", "1:B:seed"}, true},
		{"the cache holds both: nothing of the seed is placed", []credCacheEntry{disk(0, relayA, "disk-A"), disk(1, relayB, "disk-B")}, []string{"0:A:disk-A", "1:B:disk-B"}, false},
		{"the cache's slot 0 is on a third relay: both of the seed's get a slot", []credCacheEntry{disk(0, relayE, "disk-E")}, []string{"0:E:disk-E", "1:A:seed", "2:B:seed"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeCookieCache(t, t.TempDir(), c.disk...)
			cp, mints, _ := cookieSeedPool(t, path, 4)
			wake := cp.slotAvailableChannel()
			logged := captureLog(t)
			cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
			wantSeedSlots(t, cp, c.want...)
			if n := mints.Load(); n != 0 {
				t.Fatalf("%d credential(s) minted", n)
			}
			seeds := 0
			for _, w := range c.want {
				if strings.HasSuffix(w, ":seed") {
					seeds++
				}
			}
			if n := strings.Count(logged(), " takes the seed's credential on relay "); n != seeds {
				t.Fatalf("%d placement line(s) for %d slot(s) of the seed", n, seeds)
			}
			// A slot that became ready wakes the parked connections; nothing
			// placed, nobody woken.
			woken := false
			select {
			case <-wake:
				woken = true
			default:
			}
			if woken != c.placed {
				t.Fatalf("the parked connections woken: %v, want %v", woken, c.placed)
			}
			again, _, _ := relayPoolN(t, path, 4, relayC)
			wantSeedSlots(t, again, c.want...)
		})
	}
}

// The next start. The seed's slots are saved and come back as they were; a
// new probe's seed finds both relays dialled and adds nothing; and a CACHED
// seed that is one of them — the same credential, another relay — takes slot 0
// and wipes neither sibling: one username in several slots is as many quotas
// in cookie mode, never a duplicate.
func TestTheSeedsSlotsSurviveTheNextStart(t *testing.T) {
	path := t.TempDir() + "/creds-pool.json"
	first, _, _ := cookieSeedPool(t, path, 4)
	user := futureUser("seed")
	first.seedSlot(0, relayA, SeedCreds(relayA, user, "pw", []string{relayA, relayB, relayE}))
	wantSeedSlots(t, first, "0:A:seed", "1:B:seed", "2:E:seed")

	t.Run("a new probe's seed adds nothing", func(t *testing.T) {
		cp, mints, _ := relayPoolN(t, path, 4, relayC)
		wantSeedSlots(t, cp, "0:A:seed", "1:B:seed", "2:E:seed")
		cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("probe-2"), "pw", []string{relayA, relayB, relayE}))
		wantSeedSlots(t, cp, "0:A:seed", "1:B:seed", "2:E:seed")
		if n := mints.Load(); n != 0 {
			t.Fatalf("%d credential(s) minted", n)
		}
	})
	t.Run("a cached seed that is slot 0's own credential replaces it in place", func(t *testing.T) {
		cp, _, _ := relayPoolN(t, path, 4, relayC)
		cp.mu.Lock()
		cp.relayUsedAt[relayA] = time.Now().Add(-time.Minute)
		cp.applyRelayQuarantineLocked(0)
		cp.mu.Unlock()
		logged := captureLog(t)
		cp.seedSlot(0, relayA, SeedCreds(relayA, user, "pw", nil))
		wantSeedSlots(t, cp, "0:A:seed", "1:B:seed", "2:E:seed")
		if strings.Contains(logged(), "under another identity") {
			t.Fatal("the slot's own credential, seeded again, was counted as a twin on its relay")
		}
	})
	t.Run("a cached seed that is the sibling on the other relay keeps both relays", func(t *testing.T) {
		cp, mints, _ := relayPoolN(t, path, 4, relayC)
		// The first relay's clock runs (the previous session's seats): slot 0
		// is pending, so the seed is not ignored.
		cp.mu.Lock()
		cp.relayUsedAt[relayA] = time.Now().Add(-time.Minute)
		cp.applyRelayQuarantineLocked(0)
		pending := cp.pendingLocked(0)
		cp.mu.Unlock()
		if !pending {
			t.Fatal("fixture: slot 0 is not pending")
		}
		cp.seedSlot(0, relayB, SeedCreds(relayB, user, "pw", nil))
		wantSeedSlots(t, cp, "0:B:seed", "1:A:seed", "2:E:seed")
		if n := mints.Load(); n != 0 {
			t.Fatalf("%d credential(s) minted", n)
		}
	})
}

// Under a TURN override list the relay each slot dials is the list's word, as
// for every credential: its free entry for a fixed slot, VK's own relay for a
// slot behind `$vkurls`, nothing beyond the list.
func TestTheSeedsSlotsFollowTheOverrideList(t *testing.T) {
	two := []string{relayA, relayB}
	for _, c := range []struct {
		name  string
		list  []string
		named []string
		want  []string
	}{
		{"two fixed entries: a slot on each", []string{relayO, relayE}, two, []string{"0:O:seed", "1:E:seed"}},
		{"two fixed entries and a seed with ONE relay: the list's entries still", []string{relayO, relayE}, nil, []string{"0:O:seed", "1:E:seed"}},
		{"one fixed entry: nothing beyond the list", []string{relayO}, two, []string{"0:O:seed"}},
		{"a fixed entry, then VK's own: VK's relays behind it", []string{relayO, TURNServersVK}, two, []string{"0:O:seed", "1:A:seed", "2:B:seed"}},
		{"a fixed entry that is one of VK's: that relay once", []string{relayA, TURNServersVK}, two, []string{"0:A:seed", "1:B:seed"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp, mints, _ := cookieSeedPool(t, "", 4)
			cp.setOverride(turnOverride{servers: c.list})
			logged := captureLog(t)
			cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", c.named))
			wantSeedSlots(t, cp, c.want...)
			said := logged()
			if n := mints.Load(); n != 0 {
				t.Fatalf("%d credential(s) minted", n)
			}
			// The minter's reservations follow the placement (syncMinterLocked):
			// a relay the seed's slot dials is not minted for another slot.
			assigned := cookieAssigned()
			for _, w := range c.want {
				var slot int
				var relay, tag string
				if _, err := fmt.Sscanf(strings.ReplaceAll(w, ":", " "), "%d %s %s", &slot, &relay, &tag); err != nil {
					t.Fatal(err)
				}
				if got := seedRelayNames[assigned[slot]]; got != relay {
					t.Fatalf("the minter's reservation for slot %d is %q, want %s", slot, got, relay)
				}
				// The line names the relay the slot DIALS — the list's, not VK's.
				if line := fmt.Sprintf("credpool: slot %d takes the seed's credential on relay %s ", slot, assigned[slot]); slot > 0 && strings.Count(said, line) != 1 {
					t.Fatalf("slot %d's placement on relay %s is written %d time(s), want once", slot, relay, strings.Count(said, line))
				}
			}
		})
	}
}

// The probe. In cookie mode it is cookieCredForSlot's slot 0 — a mint cut to
// one relay — so its answer named one relay and the app's seed carried one.
// It names every relay of the call the credential came from, the credential's
// own first, and no other call's.
func TestTheCookieProbeNamesEveryRelayOfItsCall(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p1", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieCache[cookieLinkID(links[1])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link2"), Password: "p2", Address: relayE, Addresses: []string{relayE, relayF}}}
	cookieMu.Unlock()

	slot0, err := cookieCredForSlot(context.Background(), 0, nil, nil, nil)
	if err != nil || !reflect.DeepEqual(slot0.Addresses, []string{relayA}) {
		t.Fatalf("fixture: the slot's own credential names %d relay(s) (%v), want its one", len(slot0.Addresses), err)
	}
	for name, probe := range map[string]func() (*TURNCreds, error){
		"cookieSeedCred": func() (*TURNCreds, error) { return cookieSeedCred(context.Background()) },
		"GetVKCreds":     func() (*TURNCreds, error) { return GetVKCreds("abcdef", nil, "", "", 0, 0, "", "") },
	} {
		for i := 0; i < 20; i++ { // a map is walked in any order: the other call's list must never win
			creds, err := probe()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if creds.Address != relayA || !strings.HasSuffix(creds.Username, ":link1") || creds.Password != "p1" {
				t.Fatalf("%s: the credential is not slot 0's (address %s)", name, seedRelayNames[creds.Address])
			}
			var got []string
			for _, a := range creds.Addresses {
				got = append(got, seedRelayNames[a])
			}
			if !reflect.DeepEqual(got, []string{"A", "B"}) {
				t.Fatalf("%s: the probe names relays %v, want [A B] — the call's own, its relay first", name, got)
			}
		}
	}
	// The credential's own relay first, whatever the mint's order.
	cookieTestMode(t, links[0])
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p1", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieMu.Unlock()
	cookieNoteSlotRelay(0, relayB) // slot 0 was given the call's SECOND relay
	creds, err := cookieSeedCred(context.Background())
	if err != nil || creds.Address != relayB || !reflect.DeepEqual(creds.Addresses, []string{relayB, relayA}) {
		t.Fatalf("with slot 0 on the call's second relay the probe answers address %s and %d relay(s) (%v) — want that relay first, then the other", seedRelayNames[creds.Address], len(creds.Addresses), err)
	}
}

// The wiring: seedSlot asks for the siblings on BOTH of its ways out — the
// seed placed and the seed ignored — under the pool's lock, and the placed
// branch asks behind its dedup passes and the relocation.
func TestSeedSlotAsksForTheSiblingsOnBothWaysOut(t *testing.T) {
	body := goFuncBody(t, "creds.go", "func (cp *credPool) seedSlot(")
	if n := strings.Count(body, "cp.seedSiblingsLocked(creds)"); n != 2 {
		t.Fatalf("seedSlot asks for the seed's siblings %d time(s), want 2 (ignored, placed)", n)
	}
	at := 0
	for _, want := range []string{
		"cp.isFreshLocked(slot) {",
		"siblings := cp.seedSiblingsLocked(creds)",
		"cp.mu.Unlock()",
		"twin := cp.cookieRelayTwinLocked(slot, creds)",
		"cp.placeLocked(i, *displaced)",
		"siblings := cp.seedSiblingsLocked(creds)",
		"cp.mu.Unlock()",
		"cp.seedSiblingsPlaced(siblings)",
		"cp.saveToDisk()",
	} {
		i := strings.Index(body[at:], want)
		if i < 0 {
			t.Fatalf("seedSlot: %q is missing, or out of its order", want)
		}
		at += i + len(want)
	}
}
