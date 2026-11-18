package proxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A phone, 2026-11-18 (native / UDP / LTE, one VK relay dropped at the
// server): behind a long sleep every session was dead, the watchdog's
// ForceReconnect began a bootstrap — conn 0 alone — and the peer recovery
// check, due by then, was handed to that one connection. Its handshake ran
// into the deadline, the bootstrap paused ten seconds, and the forty
// connections came up 21 s behind the wake instead of one.
//
// The bootstrap's connection is not handed a recovery check while it has
// another relay to dial; the check waits for the first connection behind it.

func TestTheBootstrapsConnectionIsNotHandedARecoveryCheck(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cookie"}[cookie], func(t *testing.T) {
			cp, clock := peerHandshakePool(t, cookie, relayA, relayB)
			cp.markPeerFailedLocked(relayA)
			*clock = clock.Add(probeBackoff(0)) // the first check is due
			if _, relay, _ := cp.peerRecoveryChoiceLocked(-1); relay != relayA {
				t.Fatalf("fixture: no recovery check is due on %s (got %q)", relayA, relay)
			}

			cp.beginBootstrap()
			addr, creds, slot := mustGet(t, cp, 0)
			if addr != relayB {
				t.Fatalf("the bootstrap's connection was handed %s — the whole tunnel waits behind a check of a marked relay; want %s", addr, relayB)
			}
			if got := cp.health.peerFailed[relayA].retries; got != 0 {
				t.Fatalf("the bootstrap's hand-out consumed a recovery check (retries %d)", got)
			}
			if peek := cp.peekAddrLocked(slot, 0); peek == relayA {
				t.Fatal("the peek names the marked relay for the bootstrap's connection — the slot would be judged on it")
			}
			cp.endBootstrap()

			// Behind the bootstrap the check goes to the next connection that asks, as before.
			addr1, creds1, slot1 := mustGet(t, cp, 1)
			if addr1 != relayA {
				t.Fatalf("behind the bootstrap conn 1 was handed %s, want the due check on %s", addr1, relayA)
			}
			if got := cp.health.peerFailed[relayA].retries; got != 1 {
				t.Fatalf("the check behind the bootstrap was not claimed (retries %d)", got)
			}
			cp.release(slot1, creds1, relayA)
			cp.release(slot, creds, relayB)
		})
	}
}

// With nothing else to dial the check is the only way up — a bootstrap must
// not be left without a relay because the one it has is marked.
func TestABootstrapWithNothingElseToDialStillTakesTheRecoveryCheck(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cookie"}[cookie], func(t *testing.T) {
			cp, mints, clock := peerHandshakePoolMints(t, cookie, relayA)
			cp.markPeerFailedLocked(relayA)
			*clock = clock.Add(probeBackoff(0))

			cp.beginBootstrap()
			defer cp.endBootstrap()
			addr, creds, slot, err := cp.get(0, false)
			if err != nil {
				t.Fatalf("the bootstrap's connection got no relay at all (%v) — the marked one is the only one it has", err)
			}
			if addr != relayA {
				t.Fatalf("got %s, want %s", addr, relayA)
			}
			if n := mints.Load(); n != 0 {
				t.Fatalf("the bootstrap minted %d credential(s) to reach the check — it is taken on the credential the pool has", n)
			}
			if got := cp.health.peerFailed[relayA].retries; got != 1 {
				t.Fatalf("the hand-out did not claim the check (retries %d)", got)
			}
			cp.release(slot, creds, relayA)
		})
	}
}

// "Another relay to dial" means one the slot can SEAT a connection on now. An
// unmarked relay that is full, benched behind a 486 or inside its clock is no
// alternative: the first cut asked only whether one was unmarked, and the
// bootstrap parked — or minted — with a due check in hand.
func TestABootstrapTakesTheCheckWhenTheOtherRelayCannotSeat(t *testing.T) {
	for _, why := range []struct {
		name string
		make func(cp *credPool)
	}{
		{"the other relay is full", func(cp *credPool) {
			for i := 0; i < connsPerSlot; i++ {
				cp.seatLocked(0, relayB)
			}
		}},
		{"the credential is benched on the other relay (a 486)", func(cp *credPool) {
			cp.histPtrLocked(0, relayB).saturatedUntil = time.Now().Add(time.Minute)
		}},
		{"the credential's clock on the other relay has not run out", func(cp *credPool) {
			cp.histPtrLocked(0, relayB).availableAt = time.Now().Add(time.Minute)
		}},
	} {
		t.Run(why.name, func(t *testing.T) {
			cp, mints, clock := peerHandshakePoolMints(t, false, relayA, relayB)
			cp.markPeerFailedLocked(relayA)
			*clock = clock.Add(probeBackoff(0))
			why.make(cp)
			if cp.seatableOnLocked(0, relayB) || !cp.seatableOnLocked(0, relayA) || len(cp.health.alive([]string{relayB})) != 1 {
				t.Fatal("fixture: the other relay can seat, or is marked, or the marked one cannot seat")
			}

			cp.beginBootstrap()
			defer cp.endBootstrap()
			const conn = connsPerSlot + 1
			addr, creds, slot, err := cp.get(conn, false)
			if err != nil {
				t.Fatalf("the bootstrap's connection got nothing (%v) with a due check on a relay it can seat", err)
			}
			if n := mints.Load(); n != 0 {
				t.Fatalf("the bootstrap minted %d credential(s) instead of taking the due check", n)
			}
			if addr != relayA {
				t.Fatalf("got %s, want the due check on %s", addr, relayA)
			}
			if got := cp.health.peerFailed[relayA].retries; got != 1 {
				t.Fatalf("the hand-out did not claim the check (retries %d)", got)
			}
			cp.release(slot, creds, relayA)
		})
	}
}

// A count, not a flag: a ForceReconnect can begin a bootstrap before the
// previous one has returned, and an end without a begin must not open a
// hole for the next bootstrap.
func TestBootstrapsAreCountedAndNeverBelowZero(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	cp.markPeerFailedLocked(relayA)
	*clock = clock.Add(probeBackoff(0))
	handed := func(conn int) string {
		t.Helper()
		addr, creds, slot := mustGet(t, cp, conn)
		cp.release(slot, creds, addr)
		return addr
	}

	cp.endBootstrap() // an end with nothing begun
	cp.beginBootstrap()
	if addr := handed(0); addr != relayB {
		t.Fatalf("an end without a begin cancelled the next bootstrap: conn 0 handed %s", addr)
	}
	cp.beginBootstrap() // a second one begins before the first has ended
	cp.endBootstrap()
	if addr := handed(0); addr != relayB {
		t.Fatalf("one end closed two bootstraps: conn 0 handed %s", addr)
	}
	cp.endBootstrap()
	if addr := handed(1); addr != relayA {
		t.Fatalf("behind both ends conn 1 was handed %s, want the due check on %s", addr, relayA)
	}
}

// The wiring: startConnections tells the pool for the length of conn 0's
// attempts — begun before the first attempt, ended before the other
// connections are started, and on every way out (a defer).
func TestStartConnectionsBracketsTheBootstrapForThePool(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "func (p *Proxy) startConnections() error {")
	if start < 0 {
		t.Fatal("startConnections not found")
	}
	body := s[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}
	order := []string{
		"boot := p.credPool.bootstrap()",
		"defer boot.end()",
		"err := spawnConn0()",
		"\n\tboot.end()\n",
		"for i := 1; i < p.config.NumConns; i++ {",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(body[at:], want)
		if i < 0 {
			t.Fatalf("startConnections: %q is missing, or out of its order (begin, the defer, conn 0, the end, the other connections)", strings.TrimSpace(want))
		}
		at += i + len(want)
	}
}

// One bootstrap is ended once: startConnections asks for the end twice (where
// conn 0's attempts end, and by its defer), and the second asking must not
// close the bootstrap of a startConnections that began in between.
func TestABootstrapIsEndedOnceHoweverOftenItsEndIsAsked(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	cp.markPeerFailedLocked(relayA)
	*clock = clock.Add(probeBackoff(0))

	first := cp.bootstrap()
	first.end()
	second := cp.bootstrap() // a ForceReconnect's, begun before the first startConnections has returned
	first.end()              // the first one's defer
	addr, creds, slot := mustGet(t, cp, 0)
	cp.release(slot, creds, addr)
	if addr != relayB {
		t.Fatalf("the first bootstrap's second end closed the second bootstrap: conn 0 handed %s, want %s", addr, relayB)
	}
	second.end()
	addr, creds, slot = mustGet(t, cp, 1)
	cp.release(slot, creds, addr)
	if addr != relayA {
		t.Fatalf("behind the last end conn 1 was handed %s, want the due check on %s", addr, relayA)
	}
}
