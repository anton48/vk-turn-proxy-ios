package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Three follow-ups to the peer relay marks, each from a phone's run of
// 2026-11-18 or from a review of that code.

// ── A cleared mark is SAID ────────────────────────────────────────────────
//
// peer-hs-marked counts the marks SET and never falls, and the clearing wrote
// no line: a relay's return to use could only be read off its allocations.

func TestAClearedPeerMarkIsSaidInTheLog(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	logged := captureLog(t)
	success := func(conn int, relay string) {
		t.Helper()
		addr, creds, slot := mustGet(t, cp, conn)
		if addr != relay {
			t.Fatalf("fixture: conn %d was handed %s, want %s", conn, addr, relay)
		}
		cp.notePeerHandshakeResult(context.Background(), conn, cp.handStampOf(conn), relay,
			handshakeObservation{started: *clock, ended: clock.Add(time.Second)}, nil, nil)
		cp.release(slot, creds, relay)
	}
	const cleared = "passed its peer handshake recovery check"

	success(0, relayA) // nothing is marked: an ordinary handshake clears nothing and says nothing
	if strings.Contains(logged(), cleared) {
		t.Fatal("an ordinary handshake through an unmarked relay was said to clear a mark")
	}

	cp.markPeerFailedLocked(relayA)
	*clock = clock.Add(probeBackoff(0))
	success(1, relayA) // the recovery check, and it goes through
	if cp.health.isPeerFailed(relayA) {
		t.Fatal("fixture: the check's success left the mark set")
	}
	out := logged()
	if n := strings.Count(out, cleared); n != 1 {
		t.Fatalf("the clearing of the mark was said %d time(s), want once", n)
	}
	at := strings.Index(out, cleared)
	line := out[strings.LastIndex(out[:at], "\n")+1:]
	if !strings.Contains(line[:strings.Index(line, cleared)], "conn 1") || !strings.Contains(line[:strings.Index(line, cleared)], relayA) {
		t.Fatalf("the line does not name the connection and the relay: %q", strings.TrimSpace(line[:strings.Index(line, cleared)]))
	}
}

func TestAPathChangeSaysThePeerMarksItClears(t *testing.T) {
	cp, _ := peerHandshakePool(t, false, relayA, relayB)
	logged := captureLog(t)
	const said = "peer handshake mark(s) cleared"

	cp.mu.Lock()
	cp.pathChangedHealthLocked() // no mark: nothing to say
	cp.mu.Unlock()
	if strings.Contains(logged(), said) {
		t.Fatal("a path change with no peer mark said it cleared some")
	}

	cp.markPeerFailedLocked(relayA)
	cp.mu.Lock()
	cp.pathChangedHealthLocked()
	cp.mu.Unlock()
	if !strings.Contains(logged(), "1 "+said) {
		t.Fatal("a path change that cleared one peer mark did not say so, with the count")
	}
	if cp.health.isPeerFailed(relayA) {
		t.Fatal("the path change left the peer mark set")
	}
}

// ── "Consecutive" short failures end at a session that came up ────────────
//
// A phone: a connection whose third set-up failure of the run came behind a
// twelve-minute session slept 35 s — "3 consecutive short failures" — while
// the other thirty-nine carried the tunnel. The count was reset by a path
// change, a dormancy or an error behind five minutes only; a session that ran
// returns nil.

func TestASessionThatCameUpEndsTheRunOfShortFailures(t *testing.T) {
	const dormancy = "consecutive short failures, sleeping"
	setUp := errors.New("SRTP handshake: dtls client handshake: context deadline exceeded")
	for _, c := range []struct {
		name        string
		third       func(p *Proxy, connIdx int) error
		wantDormant bool
	}{
		{"three failures in a row: the dormancy, as before", func(*Proxy, int) error { return setUp }, true},
		{"two failures, a session that came up and was ended by us (nil), a failure: no dormancy",
			func(p *Proxy, connIdx int) error { p.noteSessionUp(connIdx); return nil }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
				return "", nil, fmt.Errorf("unexpected mint into slot %d", slot)
			})
			p := &Proxy{ctx: ctx, credPool: cp}
			logged := captureLog(t)
			var mu sync.Mutex
			attempts := 0
			p.sessionHook = func(hctx context.Context, connIdx int) error {
				mu.Lock()
				attempts++
				n := attempts
				mu.Unlock()
				switch n {
				case 1, 2:
					return setUp
				case 3:
					return c.third(p, connIdx)
				case 4:
					return setUp
				default:
					<-hctx.Done()
					return hctx.Err()
				}
			}
			go func() { // every wait is signalled at once: a dormancy is seen by its line, not by its length
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-tick.C:
						cp.broadcastSlotAvailable()
					case <-ctx.Done():
						return
					}
				}
			}()
			done := make(chan struct{})
			go func() { defer close(done); _ = p.runConnection(ctx, "", nil, 0) }()
			deadline := time.After(20 * time.Second)
			for {
				mu.Lock()
				n := attempts
				mu.Unlock()
				if n >= 5 {
					break
				}
				select {
				case <-deadline:
					t.Fatalf("only %d attempts in 20 s", n)
				case <-time.After(5 * time.Millisecond):
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("runConnection did not return behind the cancel")
			}
			if got := strings.Contains(logged(), dormancy); got != c.wantDormant {
				t.Fatalf("the dormancy line said: %v, want %v", got, c.wantDormant)
			}
		})
	}
}

// ── The slot choice and the hand-out agree on the address ────────────────
//
// A review's stand: every seat of the main relay taken, the alternate free
// and reserved for a connection, the reserve's claim running out between the
// slot choice (judged on the alternate) and the address pick — an eleventh
// seat on the main relay. The lock does not stop the clock: the claim can run
// out at ANY reading of it, so every reading is tried.

func TestARunOutReserveNeverHandsOutAMainRelayThatCannotSeat(t *testing.T) {
	for _, why := range []struct {
		name string
		make func(t *testing.T, cp *credPool)
	}{
		{"every seat of the main relay is taken", func(t *testing.T, cp *credPool) {
			for conn := 0; conn < connsPerSlot; conn++ {
				if addr, _, _ := mustGet(t, cp, conn); addr != relayA {
					t.Fatalf("fixture: conn %d was handed %s, want %s", conn, addr, relayA)
				}
			}
		}},
		{"the credential is benched on the main relay", func(t *testing.T, cp *credPool) {
			cp.histPtrLocked(0, relayA).saturatedUntil = time.Now().Add(time.Minute)
		}},
		{"the credential's clock on the main relay has not run out", func(t *testing.T, cp *credPool) {
			cp.histPtrLocked(0, relayA).availableAt = time.Now().Add(time.Minute)
		}},
	} {
		t.Run(why.name, func(t *testing.T) {
			handedAlternate := false
			for k := 0; k <= 12; k++ {
				cp, clock := peerHandshakePool(t, false, relayA, relayB)
				why.make(t, cp)
				if cp.seatableOnLocked(0, relayA) || !cp.seatableOnLocked(0, relayB) {
					t.Fatal("fixture: the main relay can seat, or the alternate cannot")
				}
				own := cp.pool[0].creds.Username
				base := *clock
				cp.peerProbe = relayHandshakeProbe{primary: relayA, alternate: relayB, slot: 0, conn: connsPerSlot,
					pending: true, claimedUntil: base.Add(relayProbeClaim)}
				readings := 0
				cp.health.now = func() time.Time { // the claim runs out behind the k-th reading of the clock
					readings++
					if readings > k {
						return base.Add(relayProbeClaim + time.Second)
					}
					return base
				}
				addr, creds, _, err := cp.get(connsPerSlot, false)
				if seats := cp.seatsOnLocked(0, relayA); seats > connsPerSlot {
					t.Fatalf("the claim run out behind reading %d of the clock: %d seats on the main relay, its quota is %d (handed %q, err %v)",
						k, seats, connsPerSlot, addr, err)
				}
				if err == nil && addr == relayA && creds.Username == own {
					t.Fatalf("the claim run out behind reading %d of the clock: the connection was handed the main relay, which could not seat it", k)
				}
				if err == nil && addr == relayB {
					handedAlternate = true
				}
			}
			if !handedAlternate {
				t.Fatal("fixture: in no run did the reserve hold through both looks — the alternate was never handed out, the test saw one side only")
			}
		})
	}
}

// A refused address is not the end of the choice: the pool chooses once
// more, and another ready slot is taken — the connection is neither parked
// nor made to mint while a credential that can seat it lies in the pool.
func TestARefusedAddressIsFollowedByAnotherChoiceNotAMint(t *testing.T) {
	handedAlternate, handedOther := false, false
	for k := 0; k <= 12; k++ {
		cp, mints, clock := relayPoolN(t, "", 2, relayA, relayB)
		for slot := 0; slot < 2; slot++ {
			cp.seedSlot(slot, relayA, &TURNCreds{Username: futureUser(fmt.Sprintf("two-slots-%d", slot)), Password: "pw",
				Address: relayA, Addresses: []string{relayA, relayB}})
		}
		for i := 0; i < connsPerSlot; i++ {
			cp.seatLocked(0, relayA) // slot 0's main relay is full; slot 1 is untouched
		}
		if cp.seatableOnLocked(0, relayA) || !cp.seatableOnLocked(0, relayB) || !cp.seatableOnLocked(1, relayA) {
			t.Fatal("fixture: slot 0's main relay can seat, or its alternate or slot 1 cannot")
		}
		base := *clock
		const conn = 4 // its own slot is slot 0
		cp.peerProbe = relayHandshakeProbe{primary: relayA, alternate: relayB, slot: 0, conn: conn,
			pending: true, claimedUntil: base.Add(relayProbeClaim)}
		readings := 0
		cp.health.now = func() time.Time {
			readings++
			if readings > k {
				return base.Add(relayProbeClaim + time.Second)
			}
			return base
		}
		addr, _, slot, err := cp.get(conn, false)
		if err != nil {
			t.Fatalf("the claim run out behind reading %d of the clock: the connection got nothing (%v) with a ready slot in the pool", k, err)
		}
		if n := mints.Load(); n != 0 {
			t.Fatalf("the claim run out behind reading %d: %d credential(s) minted with a ready slot in the pool", k, n)
		}
		switch {
		case slot == 0 && addr == relayB:
			handedAlternate = true
		case slot == 1:
			handedOther = true
		default:
			t.Fatalf("the claim run out behind reading %d: handed slot %d on %s", k, slot, addr)
		}
	}
	if !handedAlternate || !handedOther {
		t.Fatalf("fixture: the runs did not cover both sides (the reserve held: %v, the other slot taken: %v)", handedAlternate, handedOther)
	}
}

// Every hand-out of a ready slot in handOut (get's one body) goes through the agreed pick — the
// second one (behind a fetch that failed) has no test of its own to tell.
func TestHandOutTakesAReadySlotThroughTheAgreedPickOnly(t *testing.T) {
	src, err := os.ReadFile("creds.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "\nfunc (cp *credPool) handOut(")
	if start < 0 {
		t.Fatal("credPool.handOut not found")
	}
	body := s[start+1:]
	if end := strings.Index(body, "\nfunc "); end >= 0 {
		body = body[:end]
	}
	if strings.Contains(body, "cp.pickAcquireSlotLocked(") {
		t.Error("handOut chooses a slot with pickAcquireSlotLocked itself — the address it then picks is not the one the slot was judged on")
	}
	if n := strings.Count(body, "cp.pickForHandOutLocked("); n != 2 {
		t.Errorf("handOut asks the agreed pick %d time(s), want 2 (a ready slot; a slot found behind a failed fetch)", n)
	}
}
