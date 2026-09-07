package proxy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

const cascadeTestRelay = "95.163.34.180:19302"

// cascadePool is a 12-slot pool with creds in the first three slots and
// nothing in flight; the caller sets active / lastUsedAt / saturation to
// shape the event under test. No fetcher is ever reached.
func cascadePool(t *testing.T) *credPool {
	t.Helper()
	fetch := func(_ bool, slot int) (string, *TURNCreds, error) {
		t.Fatalf("unexpected mint into slot %d", slot)
		return "", nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, "", fetch)
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	for i := 0; i < 3; i++ {
		creds := &TURNCreds{Username: fmt.Sprintf("%d:loaded-%d", time.Now().Add(8*time.Hour).Unix(), i), Password: "p",
			Address: cascadeTestRelay, Addresses: []string{cascadeTestRelay}}
		cp.pool[i] = credPoolEntry{addr: cascadeTestRelay, creds: creds, ts: time.Now().Add(-3 * time.Minute)}
	}
	cp.mu.Unlock()
	return cp
}

func (cp *credPool) cascadeState() (armedAt time.Time, pause time.Duration) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.lastPathEventAt, time.Until(cp.pauseAcquireUntil)
}

// The tunnel's own start report — a path event on a pool with nothing live
// (conn 0 takes its seat 1.5 s later) — must not arm the cascade detector,
// or the first real switch within 90 s of Connect reads as a cascade and
// pays 30 s (07.09 run B: 89 parks, 39 dormancies, 30/30 only 31.5 s after
// the event). The real switch then, with thirty sessions live, gets the
// normal 500 ms pause and arms the detector itself.
//
// Sabotage seen red: lastPathEventAt recorded unconditionally (the second
// event is a "cascade", pause 30 s).
func TestStartReportOnAnIdlePoolDoesNotArmTheCascadeDetector(t *testing.T) {
	cp := cascadePool(t)
	cp.MarkInUseSlotsForPathChange() // the start: creds loaded, active 0 everywhere
	if armedAt, _ := cp.cascadeState(); !armedAt.IsZero() {
		t.Fatalf("the start's report armed the detector (lastPathEventAt %s) — nothing was live", armedAt)
	}

	// 600 ms later — inside the 500 ms … 90 s cascade window — the first real
	// switch arrives with thirty sessions on the three slots.
	time.Sleep(600 * time.Millisecond)
	cp.mu.Lock()
	for i := 0; i < 3; i++ {
		cp.pool[i].active = 10
	}
	cp.mu.Unlock()
	cp.MarkInUseSlotsForPathChange()
	armedAt, pause := cp.cascadeState()
	if pause > pauseAcquireAfterPathEvent {
		t.Fatalf("the first real switch after the start paid a %s pause — it read as a cascade of the start's own report", pause.Round(time.Millisecond))
	}
	if armedAt.IsZero() {
		t.Fatal("the real switch (three slots live) did not arm the detector — a following flap must still read as a cascade")
	}
	cp.mu.Lock()
	marked := 0
	for i := 0; i < 3; i++ {
		if cp.pool[i].saturatedUntil.After(time.Now()) {
			marked++
		}
	}
	cp.mu.Unlock()
	if marked != 3 {
		t.Fatalf("the real switch marked %d of the three live slots, want 3", marked)
	}
}

// A start on a WARM cache marks disk-loaded slots "active-recent" (lastUsedAt
// inside activeAllocationsWindow but past the load-cooldown) although nothing
// is live — so the gate cannot be "did the event mark anything": it is "did
// the event find sessions".
//
// Sabotage seen red: the gate written as len(markedSlots) > 0.
func TestWarmCacheStartReportMarksSlotsButDoesNotArm(t *testing.T) {
	cp := cascadePool(t)
	cp.mu.Lock()
	for i := 0; i < 3; i++ {
		cp.pool[i].lastUsedAt = time.Now().Add(-(credSaturationCooldown + 10*time.Second))
	}
	cp.mu.Unlock()
	cp.MarkInUseSlotsForPathChange()
	cp.mu.Lock()
	marked := 0
	for i := 0; i < 3; i++ {
		if cp.pool[i].saturatedUntil.After(time.Now()) {
			marked++
		}
	}
	cp.mu.Unlock()
	if marked != 3 {
		t.Fatalf("the warm-cache start marked %d slots active-recent, want 3 — the fixture no longer models the case", marked)
	}
	if armedAt, _ := cp.cascadeState(); !armedAt.IsZero() {
		t.Fatalf("a start that marked active-recent slots armed the detector (lastPathEventAt %s) — no session was live", armedAt)
	}
}

// A chain of real flaps keeps its 30 s pause even at a moment when every
// connection is parked and no slot is live: the event that detects the
// cascade re-arms the detector itself, so the chain continues.
//
// Sabotage seen red: the gate reduced to `live` alone (the cascade branch
// stops re-arming; the next event 600 ms later is an isolated 500 ms).
func TestACascadeEventReArmsEvenWithNothingLive(t *testing.T) {
	cp := cascadePool(t)
	cp.mu.Lock()
	cp.lastPathEventAt = time.Now().Add(-600 * time.Millisecond) // a previous armed event
	for i := 0; i < 3; i++ {
		cp.pool[i].saturatedUntil = time.Now().Add(10 * time.Minute) // marked by that event; sessions gone
	}
	cp.mu.Unlock()
	before := time.Now()
	cp.MarkInUseSlotsForPathChange()
	armedAt, pause := cp.cascadeState()
	if pause < cascadePauseDuration-time.Second {
		t.Fatalf("an event 600 ms after an armed one paid only %s — the cascade was not detected", pause.Round(time.Millisecond))
	}
	if armedAt.Before(before) {
		t.Fatalf("the cascade event did not re-arm the detector (lastPathEventAt %s is the previous event's) — the chain would end here", armedAt)
	}
}

// `live` is read BEFORE the per-slot skips: a slot already saturated (by the
// first event of an iOS burst, or by a 486 with its other conns still bound)
// still carries its sessions, and an event that finds them counts. Moving
// the read below the saturation skip would leave a burst's later events
// unarmed while the sessions live on.
//
// Sabotage seen red: the active check moved below the saturated-slot skip.
func TestSaturatedSlotsWithSessionsStillCountAsLive(t *testing.T) {
	cp := cascadePool(t)
	cp.mu.Lock()
	for i := 0; i < 3; i++ {
		cp.pool[i].saturatedUntil = time.Now().Add(10 * time.Minute)
		cp.pool[i].active = 10
	}
	cp.mu.Unlock()
	cp.MarkInUseSlotsForPathChange()
	if armedAt, _ := cp.cascadeState(); armedAt.IsZero() {
		t.Fatal("an event that found thirty sessions on already-saturated slots did not arm the detector")
	}
}

// An iOS burst is measured from its LAST event: a follow-up within the
// 500 ms dual-event range of an armed event keeps the stamp moving even when
// it finds nothing live — csqtt releases every lease within ms of the
// path-change kick, so its second and third events see an idle pool. Without
// this the third event of a burst spanning 500 ms would read as a cascade
// there (native bursts observed at 313–397 ms).
//
// Sabotage seen red: the dual-event clause dropped from the gate.
func TestDualFollowUpOnAnIdlePoolKeepsTheStampMoving(t *testing.T) {
	cp := cascadePool(t)
	cp.mu.Lock()
	cp.lastPathEventAt = time.Now().Add(-300 * time.Millisecond) // the burst's first event, armed
	for i := 0; i < 3; i++ {
		cp.pool[i].saturatedUntil = time.Now().Add(10 * time.Minute) // marked by it; the leases already released
	}
	cp.mu.Unlock()
	before := time.Now()
	cp.MarkInUseSlotsForPathChange()
	armedAt, pause := cp.cascadeState()
	if pause > pauseAcquireAfterPathEvent {
		t.Fatalf("a dual follow-up paid a %s pause — it read as a cascade", pause.Round(time.Millisecond))
	}
	if armedAt.Before(before) {
		t.Fatalf("the dual follow-up left the stamp at the burst's first event (%s) — a third event 500 ms after the first would read as a cascade", armedAt)
	}
}
