package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPeerRelayRecoveryUsesBackoffAndRequiresPeerSuccess(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cookie"}[cookie], func(t *testing.T) {
			cp, clock := peerHandshakePool(t, cookie, relayA, relayB)
			servers, err := ParseTURNServers(relayA + ":0," + relayB)
			if err != nil {
				t.Fatal(err)
			}
			cp.setOverride(turnOverride{servers: servers})
			cp.markPeerFailedLocked(relayA)
			cp.onRelayMarked = func(string, uint64) { t.Error("peer mark interrupted a live session") }

			get := func(conn int, want string) (*TURNCreds, int) {
				t.Helper()
				addr, creds, slot := mustGet(t, cp, conn)
				if addr != want {
					t.Fatalf("conn %d got %s, want %s", conn, addr, want)
				}
				return creds, slot
			}
			firstDue := clock.Add(probeBackoff(0))
			*clock = firstDue.Add(-time.Millisecond)
			workingCreds, workingSlot := get(0, relayB)
			defer cp.release(workingSlot, workingCreds, relayB)

			*clock = firstDue
			if cp.peekAddrLocked(0, 1) != relayA || !cp.health.peerFailed[relayA].next.Equal(firstDue) {
				t.Fatal("peeking did not select the due probe or consumed it")
			}
			probeCreds, probeSlot := get(1, relayA)
			cp.noteAllocatedAt(probeSlot, probeCreds, relayA, *clock)
			before := cp.slotAvailableChannel()
			otherCreds, otherSlot := get(2, relayB)
			cp.release(otherSlot, otherCreds, relayB)
			if !cp.health.isPeerFailed(relayA) {
				t.Fatal("TURN Allocate cleared the peer mark")
			}
			cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), relayA,
				handshakeObservation{started: *clock, lastRetry: clock.Add(time.Second), ended: clock.Add(2 * time.Second), timedOut: true},
				context.DeadlineExceeded, nil)
			cp.release(probeSlot, probeCreds, relayA)
			if cp.peerProbe.pending {
				t.Fatal("failed recovery triggered discovery of another alternate")
			}

			secondDue := firstDue.Add(probeBackoff(1))
			*clock = secondDue.Add(-time.Millisecond)
			otherCreds, otherSlot = get(2, relayB)
			cp.release(otherSlot, otherCreds, relayB)
			*clock = secondDue
			probeCreds, probeSlot = get(1, relayA)
			defer cp.release(probeSlot, probeCreds, relayA)
			cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), relayA,
				handshakeObservation{started: *clock, ended: clock.Add(2 * time.Second)}, nil, nil)
			select {
			case <-before:
			case <-time.After(time.Second):
				t.Fatal("recovery did not wake parked connections")
			}
			if cp.health.isPeerFailed(relayA) {
				t.Fatal("successful recovery left the peer mark set")
			}
			otherCreds, otherSlot = get(2, relayA)
			cp.release(otherSlot, otherCreds, relayA)
		})
	}
}

func TestPeerRelayRecoveryWaitsForTURNRetryAndKeepsSingleClaim(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	cp.markPeerFailedLocked(relayA)
	*clock = clock.Add(30 * time.Second)
	cp.health.markLocked(cp.health.record(relayA), *clock)
	firstControlDue := clock.Add(probeBackoff(0))

	*clock = firstControlDue.Add(-time.Millisecond)
	if addr, creds, slot := mustGet(t, cp, 0); addr != relayB {
		t.Fatalf("peer recovery bypassed TURN's retry schedule: %s", addr)
	} else {
		cp.release(slot, creds, addr)
	}
	*clock = firstControlDue
	if cp.health.hasCandidate([]string{relayA}) {
		t.Fatal("a TURN retry made the peer-marked relay ordinarily available")
	}
	if _, ok := cp.health.probePeek([]string{relayA}); ok {
		t.Fatal("the ordinary TURN probe ignored the peer mark")
	}
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA || cp.health.record(relayA).claimedAt != *clock {
		t.Fatal("peer recovery did not claim the due TURN retry")
	}
	cp.noteRelayUnanswered(0, slot, creds, addr, *clock)
	cp.release(slot, creds, addr)
	retry := cp.health.record(relayA)
	if retry.retries != 1 || !retry.claimedUntil.IsZero() || !cp.health.isPeerFailed(relayA) {
		t.Fatal("failed TURN retry did not keep both backoffs")
	}
}

func TestPeerRelayRecoveryRespectsQuota(t *testing.T) {
	cp, clock := peerHandshakePool(t, true, relayA, relayB)
	cp.markPeerFailedLocked(relayA)
	*clock = clock.Add(probeBackoff(0))
	assertBlocked := func(reason string) {
		t.Helper()
		if slot, _, _ := cp.peerRecoveryChoiceLocked(-1); slot >= 0 {
			t.Fatalf("peer retry bypassed %s", reason)
		}
	}
	cp.pool[0].availableAt = time.Now().Add(time.Minute)
	assertBlocked("the credential cooldown")
	cp.pool[0].availableAt = time.Time{}

	hist := cp.histPtrLocked(0, relayA)
	hist.saturatedUntil = clock.Add(time.Minute)
	assertBlocked("the saturation mark")
	hist.saturatedUntil = time.Time{}

	for range cp.capOnLocked(relayA) {
		cp.seatLocked(0, relayA)
	}
	assertBlocked("the relay seat limit")
	cp.release(0, cp.pool[0].creds, relayA)
	if slot, relay, _ := cp.peerRecoveryChoiceLocked(-1); slot != 0 || relay != relayA {
		t.Fatal("a free seat did not unblock the due retry")
	}
}

func TestPeerRelayRecoverySchedulesParkedConnections(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA)
	cp.setOverride(turnOverride{servers: []string{relayA}})
	cp.markPeerFailedLocked(relayA)
	t.Cleanup(func() {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if cp.healthTimer != nil {
			cp.healthTimer.Stop()
		}
	})
	_, _, _, err := cp.get(0, false)
	var parked *poolParkError
	if !errors.As(err, &parked) || !cp.healthWakeAt.Equal(clock.Add(probeBackoff(0))) {
		t.Fatalf("parked attempt missed the peer retry deadline: err=%v, wake=%v", err, cp.healthWakeAt)
	}
	*clock = cp.healthWakeAt
	addr, creds, slot := mustGet(t, cp, 0)
	if addr != relayA {
		t.Fatalf("only relay was skipped after its retry deadline: %s", addr)
	}
	cp.release(slot, creds, addr)
}
