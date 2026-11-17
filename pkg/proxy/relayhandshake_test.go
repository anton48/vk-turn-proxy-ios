package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPeerHandshakeMarkRequiresSuccessBeforeRetry(t *testing.T) {
	for _, test := range []struct {
		name         string
		failureFirst bool
		successAt    time.Duration
		wantMark     bool
	}{
		{name: "success reported first", successAt: 2 * time.Second, wantMark: true},
		{name: "failure reported first", failureFirst: true, successAt: 2 * time.Second, wantMark: true},
		{name: "success in the quiet tail", successAt: 9900 * time.Millisecond},
		{name: "quiet tail success reported second", failureFirst: true, successAt: 9900 * time.Millisecond},
		{name: "success at the last retry", successAt: 7 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, false, relayA, relayB)
			_, credsA, slotA := mustGet(t, cp, 0)
			generationA := cp.handStampOf(0)
			cp.mu.Lock()
			cp.cursor[1] = 1
			cp.mu.Unlock()
			_, credsB, slotB := mustGet(t, cp, 1)
			generationB := cp.handStampOf(1)
			failure := handshakeObservation{started: *clock, ended: clock.Add(10 * time.Second), lastRetry: clock.Add(7 * time.Second), timedOut: true}
			success := handshakeObservation{started: clock.Add(test.successAt - time.Second), ended: clock.Add(test.successAt)}
			cp.onRelayMarked = func(string, uint64) { t.Error("peer evidence canceled existing TURN sessions") }
			failed := func() {
				cp.notePeerHandshakeResult(context.Background(), 0, generationA, relayA, failure, context.DeadlineExceeded, nil)
			}
			succeeded := func() {
				cp.notePeerHandshakeResult(context.Background(), 1, generationB, relayB, success, nil, nil)
			}
			if !test.failureFirst {
				succeeded()
				failed()
			} else {
				failed()
				cp.noteAllocatedAt(slotB, credsB, relayB, success.started)
				if cp.health.isDead(relayA) {
					t.Fatal("an Allocate reply became peer reachability evidence")
				}
				succeeded()
			}
			if !test.wantMark {
				if cp.health.isDead(relayA) || cp.peerMarks != 0 {
					t.Fatal("success at or after the last send marked the failed relay")
				}
				if len(cp.peerFailures) != 1 {
					t.Fatal("fixture did not record the uncorroborated timeout")
				}
				cp.mu.Lock()
				cp.pathChangedHealthLocked()
				staleFailures := len(cp.peerFailures)
				cp.mu.Unlock()
				if staleFailures != 0 {
					t.Fatal("path change retained an uncorroborated timeout")
				}
				cp.release(slotA, credsA, "")
				cp.release(slotB, credsB, "")
				return
			}
			if cp.peerProbe.primary != "" {
				t.Fatal("marking the primary left a pending alternate probe")
			}
			if !cp.health.isDead(relayA) || cp.health.isDead(relayB) || cp.peerMarks != 1 || cp.peerTimeouts != 1 {
				t.Fatal("overlapping peer success did not produce one global mark")
			}
			cp.noteAllocatedAt(slotA, credsA, relayA, failure.started)
			if !cp.health.isDead(relayA) {
				t.Fatal("successful Allocate cleared a peer-handshake mark")
			}
			cp.release(slotA, credsA, "")
			cp.release(slotB, credsB, "")
			addr, creds, slot := mustGet(t, cp, 2)
			if addr != relayB {
				t.Fatalf("another connection ignored the global mark: %s", addr)
			}
			cp.release(slot, creds, "")
			cp.mu.Lock()
			cp.pathChangedHealthLocked()
			cp.mu.Unlock()
			if cp.health.isDead(relayA) || len(cp.peerFailures) != 0 || len(cp.peerHandshakes) != 0 || cp.peerProbe.primary != "" {
				t.Fatal("path change retained peer reachability evidence")
			}
			addr, creds, slot = mustGet(t, cp, 0)
			cp.release(slot, creds, "")
			if addr != relayA {
				t.Fatal("path change did not restore the primary relay")
			}
		})
	}
}

func TestPeerHandshakeMarkUsesCurrentSessionReceiveEvidence(t *testing.T) {
	for _, evidence := range []string{"overlapping receive", "early receive", "late receive", "before handshake success", "no retry", "stale generation", "same relay"} {
		t.Run(evidence, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, false, relayA, relayB)
			_, credsA, slotA := mustGet(t, cp, 0)
			defer cp.release(slotA, credsA, "")
			generationA := cp.handStampOf(0)
			if evidence != "same relay" {
				cp.mu.Lock()
				cp.cursor[1] = 1
				cp.mu.Unlock()
			}
			addrB, credsB, slotB := mustGet(t, cp, 1)
			defer cp.release(slotB, credsB, "")
			generationB := cp.handStampOf(1)
			success := handshakeObservation{started: clock.Add(-20 * time.Second), ended: clock.Add(-15 * time.Second)}
			cp.notePeerHandshakeResult(context.Background(), 1, generationB, addrB, success, nil, nil)
			failure := handshakeObservation{started: *clock, ended: clock.Add(10 * time.Second), lastRetry: clock.Add(7 * time.Second), timedOut: true}
			received := []int64{0, clock.Add(5 * time.Second).UnixNano()}
			switch evidence {
			case "early receive":
				received[1] = clock.Add(-time.Second).UnixNano()
			case "late receive":
				received[1] = clock.Add(9 * time.Second).UnixNano()
			case "before handshake success":
				success.ended = clock.Add(8 * time.Second)
				cp.notePeerHandshakeResult(context.Background(), 1, generationB, addrB, success, nil, nil)
			case "no retry":
				failure.lastRetry = time.Time{}
			case "stale generation":
				_, nextCreds, nextSlot := mustGet(t, cp, 1)
				cp.release(nextSlot, nextCreds, "")
			}
			cp.notePeerHandshakeResult(context.Background(), 0, generationA, relayA, failure, context.DeadlineExceeded, received)
			if cp.health.isDead(relayA) != (evidence == "overlapping receive") {
				t.Fatalf("wrong mark for %s", evidence)
			}
		})
	}
}

func TestPeerHandshakeFailuresProbeOneAlternateWithoutSweepingSlots(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "cookie"}[cookie], func(t *testing.T) {
			cp, clock := peerHandshakePool(t, cookie, relayA, relayB, relayC)
			fail := func(want string) {
				addr, creds, slot := mustGet(t, cp, 0)
				if addr != want {
					t.Fatalf("relay %s, want %s", addr, want)
				}
				window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
				*clock = window.ended
				cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr, window, context.DeadlineExceeded, nil)
				cp.release(slot, creds, "")
			}
			fail(relayA)
			fail(relayB)
			for range 4 {
				fail(relayA)
			}
			if cp.peerProbe.alternate != relayB || cp.peerProbe.retries != 1 || cp.peerMarks != 0 {
				t.Fatal("all-peer failure swept alternates or marked a relay")
			}
			*clock = cp.peerProbe.next.Add(time.Millisecond)
			fail(relayA)
			fail(relayB)
			if cp.peerProbe.alternate != relayB || cp.peerProbe.retries != 2 {
				t.Fatal("probe backoff did not retain the bounded alternate")
			}
			for _, relay := range []string{relayA, relayB, relayC} {
				if cp.health.isDead(relay) {
					t.Fatal("server-wide failure produced a relay verdict")
				}
			}
		})
	}
}

func TestPeerHandshakeCookieBootstrapPreparesOneEmptySlot(t *testing.T) {
	cp, clock := peerHandshakePool(t, true, relayA, relayB, relayC)
	cp.pool[1], cp.pool[2] = credPoolEntry{}, credPoolEntry{}
	cp.setColdStartTarget(1)
	fetched := 0
	cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) {
		fetched++
		if slot != 1 {
			t.Fatalf("fetched slot %d, want the reserved slot 1", slot)
		}
		return relayB, &TURNCreds{Username: futureUser("bootstrap-alternate"), Password: "pw", Address: relayB, Addresses: []string{relayA, relayB}}, nil
	}
	fail := func(want string) {
		t.Helper()
		addr, creds, slot := mustGet(t, cp, 0)
		if addr != want {
			t.Fatalf("relay %s, want %s", addr, want)
		}
		window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
		*clock = window.ended
		cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr, window, context.DeadlineExceeded, nil)
		cp.release(slot, creds, "")
	}
	addr, creds, slot := mustGet(t, cp, 0)
	cp.release(slot, creds, "")
	if addr != relayA || fetched != 0 {
		t.Fatal("bootstrap fetched an alternate before a handshake timeout")
	}
	fail(relayA)
	// Other workers can keep using the primary while the probe is reserved.
	addr, creds, slot = mustGet(t, cp, 1)
	cp.release(slot, creds, "")
	if addr != relayA || fetched != 0 {
		t.Fatal("another connection consumed the cold-start probe")
	}
	fail(relayB)
	for range 3 {
		fail(relayA)
	}
	*clock = cp.peerProbe.next.Add(time.Millisecond)
	fail(relayA)
	fail(relayB)
	if fetched != 1 || cp.pool[2].creds != nil || cp.peerProbe.retries != 2 || cp.peerMarks != 0 {
		t.Fatal("bootstrap swept empty slots, refetched credentials or marked a relay without evidence")
	}
	if cp.pool[0].active != 0 || cp.pool[1].active != 0 {
		t.Fatal("bootstrap probe leaked a pool seat")
	}
}

func TestPeerHandshakeCookieBootstrapFillFailureKeepsOneSlotAndBackoff(t *testing.T) {
	cp, clock := peerHandshakePool(t, true, relayA, relayB, relayC)
	cp.pool[1], cp.pool[2] = credPoolEntry{}, credPoolEntry{}
	fetched := 0
	cp.fetch = func(_ bool, slot int) (string, *TURNCreds, error) {
		fetched++
		if slot != 1 {
			t.Fatalf("failed probe swept to slot %d", slot)
		}
		return "", nil, errors.New("credential fetch failed")
	}
	for range 4 {
		addr, creds, slot := mustGet(t, cp, 0)
		if addr != relayA {
			t.Fatal("failed fill lost the primary credential")
		}
		cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr,
			handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}, context.DeadlineExceeded, nil)
		cp.release(slot, creds, "")
	}
	if fetched != 1 || !cp.peerProbe.prepare || cp.pool[1].cooldownUntil.IsZero() || cp.pool[2].creds != nil {
		t.Fatal("failed bootstrap fill ignored fetch cooldown or probe backoff")
	}
}

func TestPeerHandshakeCookieBootstrapFillIgnoresChangedAttempt(t *testing.T) {
	for _, change := range []string{"network path", "canceled pool", "superseded attempt"} {
		t.Run(change, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, true, relayA, relayB)
			cp.pool[1] = credPoolEntry{}
			ctx, cancel := context.WithCancel(cp.ctx)
			defer cancel()
			cp.ctx = ctx
			cp.fetch = func(_ bool, _ int) (string, *TURNCreds, error) {
				cp.mu.Lock()
				switch change {
				case "network path":
					cp.pathChangedHealthLocked()
				case "canceled pool":
					cancel()
				case "superseded attempt":
					cp.handStamp[0]++
				}
				cp.mu.Unlock()
				return relayB, &TURNCreds{Username: futureUser("changed-bootstrap"), Password: "pw", Address: relayB}, nil
			}
			addr, creds, slot := mustGet(t, cp, 0)
			cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr,
				handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}, context.DeadlineExceeded, nil)
			cp.release(slot, creds, "")
			cp.preparePeerProbe(0, false)
			if cp.peerProbe.pending || cp.peerMarks != 0 || cp.pool[1].active != 0 {
				t.Fatal("stale bootstrap fill published a probe or took a seat")
			}
		})
	}
}

func TestPeerHandshakeCookieBootstrapRespectsMintAndSlotPauses(t *testing.T) {
	for _, blocked := range []string{"quota", "dead mint", "slot cooldown", "pending credential", "fetch in progress", "path settle", "canceled pool"} {
		t.Run(blocked, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, true, relayA, relayB)
			cp.pool[1] = credPoolEntry{}
			fetched := 0
			cp.fetch = func(bool, int) (string, *TURNCreds, error) {
				fetched++
				return "", nil, errors.New("unexpected credential fetch")
			}
			addr, creds, slot := mustGet(t, cp, 0)
			cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr,
				handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}, context.DeadlineExceeded, nil)
			cp.release(slot, creds, "")
			until := time.Now().Add(time.Minute)
			switch blocked {
			case "quota":
				cp.quota.pausedUntil = until
			case "dead mint":
				cp.deadMintUntil = until
			case "slot cooldown":
				cp.pool[1].cooldownUntil = until
			case "pending credential":
				cp.seedSlot(1, relayB, &TURNCreds{Username: futureUser("pending-bootstrap"), Password: "pw", Address: relayB})
				cp.pool[1].availableAt = until
			case "fetch in progress":
				cp.claimForFetchLocked(1)
			case "path settle":
				cp.pauseAcquireUntil = until
			case "canceled pool":
				ctx, cancel := context.WithCancel(cp.ctx)
				cancel()
				cp.ctx = ctx
			}
			cp.preparePeerProbe(0, false)
			if fetched != 0 || cp.pool[1].active != 0 || cp.peerProbe.alternate != "" {
				t.Fatal("bootstrap probe bypassed a mint or slot restriction")
			}
		})
	}
}

func TestPeerHandshakeCookieBootstrapFillIsSharedAcrossWorkers(t *testing.T) {
	cp, clock := peerHandshakePool(t, true, relayA, relayB, relayC)
	cp.pool[1], cp.pool[2] = credPoolEntry{}, credPoolEntry{}
	entered, proceed := make(chan struct{}), make(chan struct{})
	cp.fetch = func(bool, int) (string, *TURNCreds, error) {
		close(entered)
		<-proceed
		return relayB, &TURNCreds{Username: futureUser("shared-bootstrap"), Password: "pw", Address: relayB}, nil
	}
	addr, creds, slot := mustGet(t, cp, 0)
	window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
	cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr, window, context.DeadlineExceeded, nil)
	cp.release(slot, creds, "")
	done := make(chan error, 1)
	go func() {
		addr, creds, slot, err := cp.get(0, false)
		if err == nil {
			cp.release(slot, creds, "")
			if addr != relayB {
				err = errors.New("reserved worker did not use the prepared alternative")
			}
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(proceed)
		t.Fatal("bootstrap fill did not start")
	}
	for conn := 1; conn < 5; conn++ {
		addr, creds, slot := mustGet(t, cp, conn)
		cp.notePeerHandshakeResult(context.Background(), conn, cp.handStampOf(conn), addr, window, context.DeadlineExceeded, nil)
		cp.release(slot, creds, "")
	}
	close(proceed)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap fill did not return")
	}
	if cp.pool[2].creds != nil || cp.pool[0].active != 0 || cp.pool[1].active != 0 {
		t.Fatal("concurrent workers filled another slot or leaked a seat")
	}
}

func TestPeerHandshakeResultIgnoresCanceledSuspendedAndStaleAttempts(t *testing.T) {
	for _, reason := range []string{"parent canceled", "suspended", "non-deadline", "stale generation", "old path"} {
		t.Run(reason, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, false, relayA, relayB)
			addr, creds, slot := mustGet(t, cp, 0)
			defer cp.release(slot, creds, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
			generation := cp.handStampOf(0)
			err := error(context.DeadlineExceeded)
			switch reason {
			case "parent canceled":
				cancel()
			case "suspended":
				window.suspended = true
			case "non-deadline":
				window.timedOut = false
				err = errors.New("handshake failed")
			case "stale generation":
				generation++
			case "old path":
				cp.health.pathChangedAt = window.started.Add(time.Second)
			}
			cp.notePeerHandshakeResult(ctx, 0, generation, addr, window, err, nil)
			if cp.peerTimeouts != 0 || cp.peerMarks != 0 || len(cp.peerFailures) != 0 || cp.peerProbe.primary != "" {
				t.Fatalf("%s affected peer relay health or probe selection", reason)
			}
		})
	}
}

func TestPeerHandshakeProbePreservesUnavailableAlternativeAndCache(t *testing.T) {
	for _, blocked := range []string{"saturated", "full", "expired", "cooldown", "unanswered"} {
		t.Run(blocked, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, true, relayA, relayB)
			addr, creds, slot := mustGet(t, cp, 0)
			filled := cp.pool[slot].ts
			switch blocked {
			case "saturated":
				cp.histPtrLocked(1, relayB).saturatedUntil = clock.Add(time.Minute)
			case "unanswered":
				cp.health.record(relayB).unanswered = 1
			case "full":
				for range connsPerSlot {
					heldAddr, heldCreds, heldSlot := mustGet(t, cp, 10)
					if heldAddr != relayB {
						t.Fatal("fixture did not fill alternate relay B")
					}
					defer cp.release(heldSlot, heldCreds, "")
				}
			case "expired":
				cp.pool[1].creds.Username = "1:expired"
			case "cooldown":
				cp.pool[1].availableAt = clock.Add(time.Minute)
			}
			until, available := cp.markLocked(1, relayB), cp.pool[1].availableAt
			alternateUser, alternateActive := cp.pool[1].creds.Username, cp.pool[1].active
			cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr,
				handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}, context.DeadlineExceeded, nil)
			cp.release(slot, creds, "")
			gotAddr, gotCreds, gotSlot := mustGet(t, cp, 0)
			defer cp.release(gotSlot, gotCreds, "")
			if gotAddr != relayA || gotSlot != slot || gotCreds.Username != creds.Username || !cp.pool[slot].ts.Equal(filled) {
				t.Fatal("blocked alternate replaced the cached credential")
			}
			if !cp.markLocked(1, relayB).Equal(until) || !cp.pool[1].availableAt.Equal(available) || cp.peerProbe.alternate != "" || cp.pool[1].creds.Username != alternateUser || cp.pool[1].active != alternateActive {
				t.Fatal("peer probing bypassed or changed the alternate's quota, cooldown or credential")
			}
		})
	}
}

func TestPeerHandshakeMarkOverridesCookieAndUnlimitedPriorities(t *testing.T) {
	for _, test := range []struct {
		name      string
		cookie    bool
		unlimited bool
	}{
		{name: "cookie", cookie: true},
		{name: "unlimited", unlimited: true},
		{name: "cookie unlimited", cookie: true, unlimited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, test.cookie, relayA, relayB)
			_, credsA, slotA := mustGet(t, cp, 0)
			generationA := cp.handStampOf(0)
			connB := 1
			if test.cookie {
				connB = connsPerSlot
			} else {
				cp.cursor[connB] = 1
			}
			addrB, credsB, slotB := mustGet(t, cp, connB)
			if addrB != relayB {
				t.Fatal("fixture did not establish B before testing primary priority")
			}
			if test.unlimited {
				servers, err := ParseTURNServers(relayA + ":0," + relayB)
				if err != nil {
					t.Fatal(err)
				}
				cp.setOverride(turnOverride{servers: servers})
			}
			success := handshakeObservation{started: clock.Add(time.Second), ended: clock.Add(2 * time.Second)}
			failure := handshakeObservation{started: *clock, ended: clock.Add(10 * time.Second), lastRetry: clock.Add(7 * time.Second), timedOut: true}
			cp.notePeerHandshakeResult(context.Background(), connB, cp.handStampOf(connB), relayB, success, nil, nil)
			cp.notePeerHandshakeResult(context.Background(), 0, generationA, relayA, failure, context.DeadlineExceeded, nil)
			cp.release(slotA, credsA, "")
			cp.release(slotB, credsB, "")
			for _, conn := range []int{2, 3} {
				addr, creds, slot := mustGet(t, cp, conn)
				if addr != relayB {
					t.Fatal("marked primary retained own-slot or unlimited priority")
				}
				cp.notePeerHandshakeResult(context.Background(), conn, cp.handStampOf(conn), addr, success, nil, nil)
				cp.release(slot, creds, "")
				cp.noteAllocatedAt(slotA, credsA, relayA, failure.started)
				if !cp.health.isDead(relayA) || cp.peerMarks != 1 {
					t.Fatal("a new session or Allocate reply reset the global peer mark")
				}
			}
		})
	}
}

func TestPeerHandshakeRecoveryClearsOnlyPendingFailure(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	_, credsA, slotA := mustGet(t, cp, 0)
	defer cp.release(slotA, credsA, "")
	_, recoveredCreds, recoveredSlot := mustGet(t, cp, 2)
	defer cp.release(recoveredSlot, recoveredCreds, "")
	cp.cursor[1] = 1
	_, credsB, slotB := mustGet(t, cp, 1)
	defer cp.release(slotB, credsB, "")
	failure := handshakeObservation{started: *clock, ended: clock.Add(10 * time.Second), lastRetry: clock.Add(7 * time.Second), timedOut: true}
	success := handshakeObservation{started: clock.Add(time.Second), ended: clock.Add(2 * time.Second)}
	cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), relayA, failure, context.DeadlineExceeded, nil)
	cp.notePeerHandshakeResult(context.Background(), 2, cp.handStampOf(2), relayA, success, nil, nil)
	cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), relayB, success, nil, nil)
	if cp.health.isDead(relayA) || len(cp.peerFailures) != 0 || cp.peerProbe.primary != "" {
		t.Fatal("successful primary recovery retained its pending failure or probe")
	}
}

func TestPeerHandshakeMarkedRelayCannotCorroborateAnotherMark(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	_, credsA, slotA := mustGet(t, cp, 0)
	_, activeCreds, activeSlot := mustGet(t, cp, 2)
	defer cp.release(activeSlot, activeCreds, "")
	cp.cursor[1] = 1
	_, credsB, slotB := mustGet(t, cp, 1)
	defer cp.release(slotB, credsB, "")
	activeA := handshakeObservation{started: clock.Add(-20 * time.Second), ended: clock.Add(-15 * time.Second)}
	cp.notePeerHandshakeResult(context.Background(), 2, cp.handStampOf(2), relayA, activeA, nil, nil)
	successB := handshakeObservation{started: clock.Add(time.Second), ended: clock.Add(2 * time.Second)}
	failureA := handshakeObservation{started: *clock, ended: clock.Add(10 * time.Second), lastRetry: clock.Add(7 * time.Second), timedOut: true}
	cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), relayB, successB, nil, nil)
	cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), relayA, failureA, context.DeadlineExceeded, nil)
	if !cp.health.isDead(relayA) {
		t.Fatal("fixture did not mark A using successful B")
	}
	failureB := handshakeObservation{started: clock.Add(19 * time.Second), ended: clock.Add(25 * time.Second), lastRetry: clock.Add(24 * time.Second), timedOut: true}
	received := []int64{0, 0, clock.Add(22 * time.Second).UnixNano()}
	cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), relayB, failureB, context.DeadlineExceeded, received)
	if !cp.health.isDead(relayA) || cp.health.isDead(relayB) || cp.peerMarks != 1 {
		t.Fatal("traffic from a marked relay cleared its mark or made another relay unusable")
	}

	recovered := handshakeObservation{started: clock.Add(30 * time.Second), ended: clock.Add(31 * time.Second)}
	cp.notePeerHandshakeResult(context.Background(), 2, cp.handStampOf(2), relayA, recovered, nil, nil)
	if cp.health.isDead(relayA) || cp.health.isDead(relayB) {
		t.Fatal("a successful peer handshake did not restore the relay for new attempts")
	}
	cp.release(slotA, credsA, "")
	addr, nextCreds, nextSlot := mustGet(t, cp, 0)
	defer cp.release(nextSlot, nextCreds, "")
	if addr != relayA {
		t.Fatal("the recovered relay remained excluded from new attempts")
	}
}

func TestPeerHandshakeProbeIsReservedToOneConnection(t *testing.T) {
	cp, clock := peerHandshakePool(t, true, relayA, relayB, relayC)
	addr, creds, slot := mustGet(t, cp, 0)
	window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
	cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr, window, context.DeadlineExceeded, nil)
	cp.release(slot, creds, "")
	addr, creds, slot = mustGet(t, cp, 1)
	if addr != relayA {
		t.Fatal("another connection stole the pending alternate probe")
	}
	cp.notePeerHandshakeResult(context.Background(), 1, cp.handStampOf(1), addr, window, context.DeadlineExceeded, nil)
	cp.release(slot, creds, "")
	addr, creds, slot = mustGet(t, cp, 0)
	defer cp.release(slot, creds, "")
	if addr != relayB || cp.peerProbe.retries != 1 {
		t.Fatal("the reserved probe was replaced or consumed more than once")
	}
}

func TestPeerHandshakeProbeFollowsChangedRelayCandidates(t *testing.T) {
	const relayD = "203.0.113.14:19302"
	for _, change := range []struct {
		name               string
		override           bool
		primary, alternate string
	}{
		{name: "configured relays", override: true, primary: relayC, alternate: relayB},
		{name: "VK credential relays", primary: relayC, alternate: relayD},
		{name: "VK alternate removed", primary: relayA, alternate: relayC},
	} {
		t.Run(change.name, func(t *testing.T) {
			cp, clock := peerHandshakePool(t, false, relayA, relayB)
			fail := func(want string) {
				addr, creds, slot := mustGet(t, cp, 0)
				if addr != want {
					t.Fatalf("relay %s, want %s", addr, want)
				}
				window := handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}
				*clock = window.ended
				cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), addr, window, context.DeadlineExceeded, nil)
				cp.release(slot, creds, "")
			}
			fail(relayA)
			if !change.override {
				fail(relayB)
			}
			if cp.peerProbe.primary != relayA || cp.peerProbe.alternate != relayB || cp.peerProbe.pending != change.override || !change.override && !clock.Before(cp.peerProbe.next) {
				t.Fatal("fixture did not establish the old bounded probe backoff")
			}
			quotaClock := *clock
			cp.health.markPeerFailed(relayO)
			cp.relayUsedAt[relayO] = quotaClock
			if change.override {
				servers, err := ParseTURNServers(change.primary + ":0," + change.alternate)
				if err != nil {
					t.Fatal(err)
				}
				cp.setOverride(turnOverride{servers: servers})
			} else {
				credential := &TURNCreds{
					Username: futureUser("changed-relays"), Password: "pw", Address: change.primary,
					Addresses: []string{change.primary, change.alternate},
				}
				cp.mu.Lock()
				cp.placeLocked(0, credPoolEntry{addr: change.primary, addrs: credential.Addresses, ts: time.Now(), creds: credential})
				cp.mu.Unlock()
			}
			fail(change.primary)
			addr, creds, slot := mustGet(t, cp, 0)
			defer cp.release(slot, creds, "")
			if addr != change.alternate || cp.peerProbe.primary != change.primary || cp.peerProbe.alternate != change.alternate || cp.peerProbe.retries != 1 {
				t.Fatalf("the old probe blocked new relay exploration: chosen=%s primary=%s alternate=%s retries=%d", addr, cp.peerProbe.primary, cp.peerProbe.alternate, cp.peerProbe.retries)
			}
			if !cp.health.isPeerFailed(relayO) || !cp.relayUsedAt[relayO].Equal(quotaClock) {
				t.Fatal("updating probe candidates changed an existing relay mark or quota clock")
			}
		})
	}
}

func TestPeerProbeKeepsItsChosenRelayWhenItRunsOutOfSeats(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB, relayC)
	cp.planPeerProbeLocked(0, relayA)
	if addr := cp.peekAddrLocked(0, 0); addr != relayB {
		t.Fatalf("peek did not see conn 0's reserved probe: %s", addr)
	}

	cp.histPtrLocked(0, relayB).saturatedUntil = clock.Add(time.Hour)
	*clock = cp.peerProbe.claimedUntil
	if _, _, ok := cp.peerProbeChoiceLocked(0); ok {
		t.Fatal("a reservation could be selected after its claim expired")
	}
	cp.planPeerProbeLocked(0, relayA)
	if cp.peerProbe.alternate != relayB {
		t.Fatal("an unavailable alternate caused a sweep to another relay")
	}
	cp.histPtrLocked(0, relayB).saturatedUntil = time.Time{}
	cp.planPeerProbeLocked(1, relayC)
	if cp.peerProbe.primary != relayA || cp.peerProbe.alternate != relayB || cp.peerProbe.conn != 0 {
		t.Fatal("an unrelated failure redirected the alternate probe")
	}
}

func TestPeerProbeRejectsAnExpiredReservation(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	cp.planPeerProbeLocked(0, relayA)
	*clock = cp.peerProbe.claimedUntil
	if _, _, ok := cp.peerProbeChoiceLocked(0); ok {
		t.Fatal("a ready relay was returned for an expired probe reservation")
	}
}

func TestPeerProbeRejectsDisabledCookieSlot(t *testing.T) {
	cp, _ := peerHandshakePool(t, true, relayA, relayB)
	cp.override.setServers([]string{relayA})
	if cp.peerRelayReadyLocked(1, relayB) {
		t.Fatal("a cached credential was considered for a disabled slot")
	}
}

func TestPeerProbeResetsOnAChangedDNSAnswer(t *testing.T) {
	oldLookup := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = oldLookup })
	lookupTURNHost = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.33")}, nil
	}
	cp, clock := peerHandshakePool(t, false, relayA, relayB)
	cp.override.raw = []string{"relay.example:3478"}
	cp.override.setServers([]string{relayA})
	cp.peerProbe = relayHandshakeProbe{primary: relayA, alternate: relayB, next: clock.Add(time.Hour)}
	cp.reresolveOverride("test", false)
	if cp.peerProbe != (relayHandshakeProbe{}) {
		t.Fatal("a changed DNS answer retained the old alternate probe")
	}
}

func peerHandshakePool(t *testing.T, cookie bool, relays ...string) (*credPool, *time.Time) {
	t.Helper()
	if cookie {
		SetVKCookieAuth(true, "remixsid=test", []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"})
		t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	}
	size := 1
	if cookie {
		size = len(relays)
	}
	cp, _, clock := relayPoolN(t, "", size, relays...)
	if cookie {
		for slot, addr := range relays {
			cp.seedSlot(slot, addr, &TURNCreds{Username: futureUser(addr), Password: "pw", Address: addr, Addresses: []string{addr}})
		}
	} else {
		cp.seedSlot(0, relays[0], &TURNCreds{Username: futureUser("handshake"), Password: "pw", Address: relays[0], Addresses: relays})
	}
	return cp, clock
}
