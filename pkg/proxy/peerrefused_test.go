package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// A phone, 2026-11-19: the user's own relay first in the override list (no
// quota), VK's relays behind it, and the relay started with an allow-list of
// peers that did not name the server. It accepted every allocation and
// answered every CreatePermission with an error, in milliseconds. Nobody read
// that answer: conn 0 was handed slot 0 and that relay five times with the
// bootstrap's pauses between, and the tunnel was stopped at its two minutes.
//
// The relay's refusal is its own word about our peer: the relay is peer-marked
// at once, the next attempt goes elsewhere, and the mark's recovery checks
// bring the relay back when it serves the peer again.

func TestThePermissionsRefusalIsReadOffTheRelaysAnswer(t *testing.T) {
	for _, c := range []struct {
		err  string
		want bool
	}{
		{"CreatePermission error response", true},                         // pion: an error answer with no code
		{"turn create permission: CreatePermission error response", true}, // the SRTP set-up's wrap
		{"SRTP setup: turn create permission: CreatePermission error response", true},
		{"DTLS failed: x (TURN error: TURN create permission: CreatePermission error response)", true},
		{"turn create permission: CreatePermission error response (error 403: Forbidden)", true},
		// The other answers a relay gives to a permission are not about the peer:
		{"turn create permission: CreatePermission error response (error 400: Bad Request)", false},         // no allocation for this 5-tuple (a changed mapping)
		{"turn create permission: CreatePermission error response (error 437: Allocation Mismatch)", false}, // the same
		{"turn create permission: CreatePermission error response (error 401: Unauthorized)", false},        // the credential
		{"turn create permission: CreatePermission error response (error 438: Stale Nonce)", false},
		{"turn create permission: CreatePermission error response (error 4030: x)", false}, // a code that only begins like it
		// …and an error that is not the permission's answer at all:
		{"turn allocate: Allocate error response (error 403: Forbidden)", false},
		{"turn allocate: Allocate error response (error 486: Allocation Quota Reached)", false},
		{"turn create permission: all retransmissions failed", false},
		{"dial tcp to relay: i/o timeout", false},
	} {
		if got := isPeerRefused(errors.New(c.err)); got != c.want {
			t.Errorf("isPeerRefused(%q) = %v, want %v", c.err, got, c.want)
		}
		if got := IsPeerRefused(errors.New(c.err)); got != c.want {
			t.Errorf("IsPeerRefused(%q) = %v, want %v", c.err, got, c.want)
		}
	}
	if isPeerRefused(nil) {
		t.Error("no error is a refusal")
	}
}

// The words are pion's, taken from a REAL relay: a pion TURN server whose
// permission handler refuses the peer — what tools/turn-relay's -peer list
// does — answers with an error of no code, and the client's error is exactly
// the phrase the classifier looks for. With the handler allowing: no error.
func TestARealRelaysRefusalOfThePeerIsRead(t *testing.T) {
	for _, c := range []struct {
		name  string
		allow bool
	}{{"the relay refuses the peer", false}, {"the relay allows it", true}} {
		t.Run(c.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv, err := turn.NewServer(turn.ServerConfig{
				Realm: "okcdn.ru",
				AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
					return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
				},
				PacketConnConfigs: []turn.PacketConnConfig{{
					PacketConn:            pc,
					RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
					PermissionHandler:     func(net.Addr, net.IP) bool { return c.allow },
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { // the server goes only after its allocations have
				deadline := time.Now().Add(2 * time.Second)
				for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				_ = srv.Close()
			})
			ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ctl.Close()
			tc, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: pc.LocalAddr().String(), Conn: ctl, Username: "u", Password: "pw", Realm: "okcdn.ru"})
			if err != nil {
				t.Fatal(err)
			}
			defer tc.Close()
			if err := tc.Listen(); err != nil {
				t.Fatal(err)
			}
			relayConn, err := tc.Allocate()
			if err != nil {
				t.Fatalf("fixture: the relay refused the allocation: %v", err)
			}
			defer relayConn.Close() // the deallocate: the stand's server is empty again
			perr := tc.CreatePermission(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if c.allow {
				if perr != nil {
					t.Fatalf("the relay allows the peer and the permission failed: %v", perr)
				}
				return
			}
			if perr == nil {
				t.Fatal("fixture: the relay granted a permission its handler refuses")
			}
			if perr.Error() != permissionErrorResponse {
				t.Fatalf("pion words the refusal %q — the classifier reads %q", perr.Error(), permissionErrorResponse)
			}
			wrapped := fmt.Errorf("SRTP setup: %w", fmt.Errorf("turn create permission: %w", perr))
			if !isPeerRefused(wrapped) {
				t.Fatal("a real relay's refusal of the peer is not read as one")
			}
			// It is the relay's ANSWER about the peer — none of the other kinds.
			if isRelayUnanswered(wrapped) || isAuthError(wrapped) || isQuotaError(wrapped) || isNetworkClassFailure(wrapped) {
				t.Fatalf("the refusal is also read as: unanswered %v, auth %v, quota %v, a network failure %v",
					isRelayUnanswered(wrapped), isAuthError(wrapped), isQuotaError(wrapped), isNetworkClassFailure(wrapped))
			}
		})
	}
}

// A 403 on the PERMISSION is the relay's policy about the peer, not a dead
// credential: read as an auth error it invalidated the slot and a new
// credential was minted for the same refusal at every attempt.
func TestAForbiddenPermissionIsNotAnAuthError(t *testing.T) {
	for _, c := range []struct {
		err  string
		auth bool
	}{
		{"turn create permission: CreatePermission error response (error 403: Forbidden)", false},
		{"turn create permission: CreatePermission error response (error 401: Unauthorized)", true},
		{"turn allocate: Allocate error response (error 403: Forbidden)", true},
		{"turn allocate: Allocate error response (error 401: Unauthorized)", true},
	} {
		if got := isAuthError(errors.New(c.err)); got != c.auth {
			t.Errorf("isAuthError(%q) = %v, want %v", c.err, got, c.auth)
		}
	}
	refusal := errors.New("SRTP setup: turn create permission: CreatePermission error response")
	if isNetworkClassFailure(refusal) {
		t.Error("the relay's refusal is counted as a failure of the NETWORK — it is the relay's answer, and the retry floor is the network's")
	}
	if !isNetworkClassFailure(errors.New("SRTP setup: turn create permission: all retransmissions failed")) {
		t.Error("fixture: a permission nobody answered is no longer a network failure")
	}
}

func refusedRelayName(a string) string {
	return map[string]string{relayO: "the own relay", relayA: "VK's first", relayB: "VK's second", "": "nothing"}[a]
}

// The phone's start itself, through the pool: the own relay without a quota
// first, VK's behind it; conn 0 alone (a bootstrap); the own relay refuses.
func TestARefusingOwnRelayIsLeftAtTheNextAttempt(t *testing.T) {
	cp, mints, clock := relayPoolN(t, "", 4, relayA, relayB)
	cp.setOverride(turnOverride{servers: []string{relayO + ":0", TURNServersVK}})
	cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", []string{relayA, relayB}))
	logged := captureLog(t)
	boot := cp.bootstrap()
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayO {
		t.Fatalf("fixture: conn 0 was handed %s first, want the own relay", refusedRelayName(addr))
	}
	cp.notePeerRefused(0, relayO, *clock)
	cp.release(slot, creds, relayO)
	if !cp.health.isPeerFailed(relayO) {
		t.Fatal("the relay refused the permission for our peer and is not marked — the next attempt dials it again (the phone: five times, then the tunnel's stop)")
	}
	if _, marked := cp.peerHandshakeStats(); marked != 1 {
		t.Fatalf("the peer marks count %d, want 1", marked)
	}
	next, creds2, slot2 := mustGet(t, cp, 0)
	if next != relayA {
		t.Fatalf("conn 0's next attempt was handed %s, want VK's first relay", refusedRelayName(next))
	}
	cp.release(slot2, creds2, next)
	boot.end()
	// The others never dial it: no second wave on a relay that has said no.
	for conn := 1; conn <= 9; conn++ {
		a, c, s := mustGet(t, cp, conn)
		if a == relayO {
			t.Fatalf("conn %d was handed the relay that refused our peer", conn)
		}
		defer cp.release(s, c, a)
	}
	if n := mints.Load(); n != 0 {
		t.Fatalf("%d credential(s) minted on the way off the refusing relay", n)
	}
	said := logged()
	if n := strings.Count(said, "credpool: conn 0: relay "+relayO+" REFUSED the permission for our peer — marked at once"); n != 1 {
		t.Fatalf("the mark was said %d time(s), want once", n)
	}
	if strings.Contains(said, "peer handshake failed while another relay carried") {
		t.Fatal("the refusal was said in the handshake mark's words")
	}
}

// No witness is asked for — and none of the handshake mark's conditions: one
// connection, no other relay ever heard from, the mark is set. Every mode.
func TestARefusalMarksAtOnceInEveryMode(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cookie"}[cookie], func(t *testing.T) {
			cp, mints, clock := peerHandshakePoolMints(t, cookie, relayA, relayB)
			addr, creds, slot := mustGet(t, cp, 0)
			if addr != relayA {
				t.Fatalf("fixture: conn 0 was handed %s", refusedRelayName(addr))
			}
			cp.notePeerRefused(0, relayA, *clock)
			cp.release(slot, creds, relayA)
			if !cp.health.isPeerFailed(relayA) || cp.health.isPeerFailed(relayB) {
				t.Fatalf("marked: first %v, second %v — want the refusing relay alone", cp.health.isPeerFailed(relayA), cp.health.isPeerFailed(relayB))
			}
			next, creds2, slot2 := mustGet(t, cp, 0)
			if next != relayB || mints.Load() != 0 {
				t.Fatalf("the next attempt: %s, %d minted — want the other relay, nothing minted", refusedRelayName(next), mints.Load())
			}
			cp.release(slot2, creds2, next)
		})
	}
}

// The way back is the peer mark's own: a recovery check at the first hand-out
// once due. A check the relay refuses again leaves the mark and its schedule
// (the claim moved them); one that comes up clears it.
func TestARefusingRelayIsTriedAgainOnTheMarksSchedule(t *testing.T) {
	cp, _, clock := peerHandshakePoolMints(t, false, relayA, relayB)
	cp.notePeerRefused(0, relayA, *clock)
	if a, c, s := mustGet(t, cp, 1); a != relayB {
		t.Fatalf("inside the first interval conn 1 was handed %s", refusedRelayName(a))
	} else {
		cp.release(s, c, a)
	}
	*clock = clock.Add(probeBackoff(0))
	logged := captureLog(t)
	a, c, s := mustGet(t, cp, 1)
	if a != relayA {
		t.Fatalf("with the first check due conn 1 was handed %s, want the marked relay", refusedRelayName(a))
	}
	due := cp.health.peerFailed[relayA].next
	cp.notePeerRefused(1, relayA, *clock)
	cp.release(s, c, a)
	if !cp.health.isPeerFailed(relayA) || !cp.health.peerFailed[relayA].next.Equal(due) || cp.health.peerFailed[relayA].retries != 1 {
		t.Fatalf("a check refused again: marked %v, the next check moved %v, retries %d — want the mark and the claim's schedule as they were", cp.health.isPeerFailed(relayA), !cp.health.peerFailed[relayA].next.Equal(due), cp.health.peerFailed[relayA].retries)
	}
	if _, marked := cp.peerHandshakeStats(); marked != 1 {
		t.Fatalf("a refusal of a relay already marked was counted as a new mark (%d)", marked)
	}
	said := logged()
	if strings.Count(said, "credpool: conn 1: relay "+relayA+" refused the permission for our peer again — its mark stands") != 1 || strings.Contains(said, "marked at once") {
		t.Fatal("a refused recovery check is not said as one (or is said as a new mark)")
	}
	if a, c, s := mustGet(t, cp, 1); a != relayB {
		t.Fatalf("behind the refused check conn 1 was handed %s, want the other relay", refusedRelayName(a))
	} else {
		cp.release(s, c, a)
	}
}

// An attempt begun before the last path change says nothing about the network
// we are on now — as every late result.
func TestARefusalOfAnAttemptFromTheOldNetworkMarksNothing(t *testing.T) {
	cp, _, clock := peerHandshakePoolMints(t, false, relayA, relayB)
	begun := *clock
	*clock = clock.Add(2 * time.Second)
	cp.pathChangedHealthLocked()
	cp.notePeerRefused(0, relayA, begun)
	if cp.health.isPeerFailed(relayA) {
		t.Fatal("an attempt begun on the old network marked a relay on the new one")
	}
	cp.notePeerRefused(0, relayA, *clock)
	if !cp.health.isPeerFailed(relayA) {
		t.Fatal("an attempt begun at the path change itself is of the new network — not marked")
	}
	cp.notePeerRefused(0, "", *clock) // no relay named: nothing to mark, nothing to break
	if cp.health.isPeerFailed("") {
		t.Fatal("a refusal with no relay named set a mark on nothing")
	}
	var none *credPool
	none.notePeerRefused(0, relayA, *clock)
}

// With nothing else to dial the refusing relay is not hammered and nothing is
// minted for it: the connection parks until the mark's check is due.
func TestARefusingSoleRelayIsNotHammered(t *testing.T) {
	cp, mints, clock := relayPoolN(t, "", 4, relayA, relayB)
	cp.setOverride(turnOverride{servers: []string{relayO + ":0"}})
	cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", nil))
	addr, creds, slot := mustGet(t, cp, 0)
	cp.notePeerRefused(0, addr, *clock)
	cp.release(slot, creds, addr)
	for i := 0; i < 3; i++ {
		a, _, _, err := cp.get(0, false)
		var park *poolParkError
		if !errors.As(err, &park) {
			t.Fatalf("attempt %d inside the first interval: handed %q, err %v — want a park", i, refusedRelayName(a), err)
		}
	}
	*clock = clock.Add(probeBackoff(0))
	a, c, s := mustGet(t, cp, 0)
	if a != relayO {
		t.Fatalf("with the check due: %s", refusedRelayName(a))
	}
	cp.release(s, c, a)
	if n := mints.Load(); n != 0 {
		t.Fatalf("%d credential(s) minted for a relay that refuses the peer", n)
	}
}

// The wiring. Both of native's CreatePermission exits hand their error to
// relayRefusedPeer with the connection, the relay and the attempt's start —
// and that tells the pool of a refusal and of nothing else.
func TestNativesPermissionExitsTellThePool(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		`return p.relayRefusedPeer(connIdx, turnAddr, attempt, fmt.Errorf("TURN create permission: %w", err))`,
		`return nil, p.relayRefusedPeer(connIdx, turnAddr, attempt, fmt.Errorf("turn create permission: %w", err))`,
	} {
		if strings.Count(s, want) != 1 {
			t.Errorf("proxy.go: %q is missing — a permission's failure leaves without the pool hearing of a refusal", want)
		}
	}
	if n := strings.Count(s, "create permission: %w"); n != 2 {
		t.Errorf("proxy.go wraps a permission's failure %d time(s), 2 are known — a new exit must tell the pool too", n)
	}

	cp, _, clock := peerHandshakePoolMints(t, false, relayA, relayB)
	p := &Proxy{credPool: cp}
	other := errors.New("turn create permission: CreatePermission error response (error 400: Bad Request)")
	if got := p.relayRefusedPeer(0, relayA, *clock, other); got != other || cp.health.isPeerFailed(relayA) {
		t.Fatalf("a permission answered 400 — a changed mapping: the error came back changed (%v) or the relay was marked (%v)", got != other, cp.health.isPeerFailed(relayA))
	}
	refusal := errors.New("turn create permission: CreatePermission error response")
	if got := p.relayRefusedPeer(3, relayA, *clock, refusal); got != refusal || !cp.health.isPeerFailed(relayA) {
		t.Fatalf("a refusal: the error came back changed (%v), the relay marked: %v", got != refusal, cp.health.isPeerFailed(relayA))
	}
	if cp.health.isPeerFailed(relayB) {
		t.Fatal("the mark was set on another relay than the one named")
	}
}
