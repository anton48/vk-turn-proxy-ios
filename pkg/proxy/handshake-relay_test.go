package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHandshakeTimeoutTriesEveryAvailableRelay(t *testing.T) {
	for _, test := range []struct {
		name      string
		cookie    bool
		unlimited bool
	}{
		{name: "anonymous"},
		{name: "cookie", cookie: true},
		{name: "anonymous unlimited", unlimited: true},
		{name: "cookie unlimited", cookie: true, unlimited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			relays := []string{relayA, relayB, relayC}
			if test.unlimited {
				relays[0] = relayO
			}
			cp := handshakeRelayPool(t, test.cookie, relays...)
			if test.unlimited {
				list, err := ParseTURNServers(relayO + ":0," + relayB + "," + relayC)
				if err != nil {
					t.Fatal(err)
				}
				cp.setOverride(turnOverride{servers: list})
			}
			for _, want := range append(append([]string(nil), relays...), relays...) {
				addr, creds, slot := mustGet(t, cp, 0)
				if addr != want {
					t.Fatalf("next relay %q, want %q", addr, want)
				}
				start := time.Now()
				cp.noteAllocatedAt(slot, creds, addr, start)
				generation := cp.handStampOf(0)
				cp.release(slot, creds, "")
				cp.noteHandshakeResult(context.Background(), 0, generation, addr, start, context.DeadlineExceeded)
				if cp.health.isDead(addr) || len(cp.health.untried([]string{addr})) != 1 {
					t.Fatal("peer timeout changed TURN control health")
				}
			}
			addr, creds, slot := mustGet(t, cp, 0)
			if addr == "" {
				t.Fatal("exhausting handshake candidates blocked normal retries")
			}
			cp.release(slot, creds, "")
			addr, creds, slot = mustGet(t, cp, 1)
			if addr != relays[0] {
				t.Fatalf("another connection inherited handshake failures: %q", addr)
			}
			cp.release(slot, creds, "")
		})
	}
}

func TestHandshakeTimeoutKeepsASingleRelayAndCredential(t *testing.T) {
	cp := handshakeRelayPool(t, false, relayA)
	addr, creds, slot := mustGet(t, cp, 0)
	start := time.Now()
	cp.noteAllocatedAt(slot, creds, addr, start)
	generation := cp.handStampOf(0)
	cp.release(slot, creds, "")
	cp.noteHandshakeResult(context.Background(), 0, generation, addr, start, context.DeadlineExceeded)
	gotAddr, gotCreds, gotSlot := mustGet(t, cp, 0)
	defer cp.release(gotSlot, gotCreds, "")
	if gotAddr != addr || gotCreds.Username != creds.Username || gotSlot != slot {
		t.Fatal("a single-relay timeout replaced the credential or blocked retry")
	}
}

func TestHandshakeTimeoutFallsBackWhenTheAlternativeHasNoQuotaRoom(t *testing.T) {
	for _, blocked := range []string{"saturated", "full"} {
		t.Run(blocked, func(t *testing.T) {
			cp := handshakeRelayPool(t, false, relayA, relayB)
			addr, creds, slot := mustGet(t, cp, 0)
			start := time.Now()
			cp.noteAllocatedAt(slot, creds, addr, start)
			generation := cp.handStampOf(0)
			cp.release(slot, creds, "")
			cp.noteHandshakeResult(context.Background(), 0, generation, addr, start, context.DeadlineExceeded)
			filledAt := cp.pool[slot].ts
			until := time.Time{}
			if blocked == "saturated" {
				until = time.Now().Add(time.Minute)
				cp.mu.Lock()
				cp.histPtrLocked(slot, relayB).saturatedUntil = until
				cp.mu.Unlock()
			} else {
				cp.mu.Lock()
				cp.cursor[1] = 1
				cp.mu.Unlock()
				for range connsPerSlot {
					heldAddr, heldCreds, heldSlot := mustGet(t, cp, 1)
					if heldAddr != relayB {
						t.Fatalf("occupied relay %q, want %q", heldAddr, relayB)
					}
					defer cp.release(heldSlot, heldCreds, "")
				}
			}
			gotAddr, gotCreds, gotSlot, err := cp.get(0, false)
			if err != nil {
				t.Fatalf("available failed relay should remain usable: %v", err)
			}
			defer cp.release(gotSlot, gotCreds, "")
			if gotAddr != relayA || gotSlot != slot || gotCreds.Username != creds.Username || !cp.pool[slot].ts.Equal(filledAt) {
				t.Fatal("unavailable alternative replaced the cached credential or changed its lifetime")
			}
			if !cp.markLocked(slot, relayB).Equal(until) {
				t.Fatal("handshake fallback changed the alternative's quota cooldown")
			}
		})
	}
}

func TestHandshakeResultIgnoresCancellationStaleSessionsAndOldPaths(t *testing.T) {
	for _, reason := range []string{"parent canceled", "canceled handshake", "other error", "stale session", "old path"} {
		t.Run(reason, func(t *testing.T) {
			cp := handshakeRelayPool(t, false, relayA, relayB)
			addr, creds, slot := mustGet(t, cp, 0)
			defer cp.release(slot, creds, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			generation := cp.handStampOf(0)
			start := time.Now()
			var err error = context.DeadlineExceeded
			switch reason {
			case "parent canceled":
				cancel()
			case "canceled handshake":
				err = context.Canceled
			case "other error":
				err = errors.New("unsupported certificate")
			case "stale session":
				generation++
			case "old path":
				cp.mu.Lock()
				cp.health.pathChangedAt = start.Add(time.Second)
				cp.mu.Unlock()
			}
			cp.noteHandshakeResult(ctx, 0, generation, addr, start, err)
			if len(cp.handshakeFailures[0]) != 0 || cp.cursor[0] != 0 {
				t.Fatal("an unrelated or obsolete failure changed relay selection")
			}
		})
	}
}

func TestHandshakeSuccessAndPathChangeClearRelayPreferences(t *testing.T) {
	for _, reason := range []string{"success", "path change"} {
		t.Run(reason, func(t *testing.T) {
			cp := handshakeRelayPool(t, true, relayA, relayB, relayC)
			for _, want := range []string{relayA, relayB} {
				addr, creds, slot := mustGet(t, cp, 0)
				if addr != want {
					t.Fatalf("relay %q, want %q", addr, want)
				}
				generation := cp.handStampOf(0)
				cp.release(slot, creds, "")
				cp.noteHandshakeResult(context.Background(), 0, generation, addr, time.Now(), context.DeadlineExceeded)
			}
			if reason == "success" {
				cp.noteHandshakeResult(context.Background(), 0, cp.handStampOf(0), relayB, time.Now(), nil)
			} else {
				cp.mu.Lock()
				cp.pathChangedHealthLocked()
				cp.mu.Unlock()
			}
			if len(cp.handshakeFailures[0]) != 0 {
				t.Fatal("completed handshake or path change retained relay failures")
			}
			addr, creds, slot := mustGet(t, cp, 0)
			defer cp.release(slot, creds, "")
			if addr != relayA {
				t.Fatalf("own relay preference was not restored: %q", addr)
			}
		})
	}
}

func handshakeRelayPool(t *testing.T, cookie bool, relays ...string) *credPool {
	t.Helper()
	if cookie {
		SetVKCookieAuth(true, "remixsid=test", []string{"https://vk.ru/call/join/abcdef", "https://vk.ru/call/join/ghijkl"})
		t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	}
	size := 1
	if cookie {
		size = len(relays)
	}
	cp, _, _ := relayPoolN(t, "", size, relays...)
	if cookie {
		for slot, addr := range relays {
			cp.seedSlot(slot, addr, &TURNCreds{Username: futureUser(addr), Password: "pw", Address: addr, Addresses: []string{addr}})
		}
	} else {
		cp.seedSlot(0, relays[0], &TURNCreds{Username: futureUser("handshake"), Password: "pw", Address: relays[0], Addresses: relays})
	}
	return cp
}
