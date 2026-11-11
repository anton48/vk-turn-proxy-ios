package proxy

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ReleaseHeld is the pool's hold for a lease made outside this package (csqtt's,
// through the bridge): the seat stays counted until the moment it is given,
// then goes; a moment already past frees it at once; and the line says the
// reason it was GIVEN — a csqtt lease is also held when its deallocate was
// never answered, and a log that called that a 437 would lie.
func TestReleaseHeldKeepsTheSeatCountedUntilItsMomentAndSaysWhy(t *testing.T) {
	step := seatHoldStep
	seatHoldStep = 20 * time.Millisecond
	t.Cleanup(func() { seatHoldStep = step })

	t.Run("held until its moment", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		said := captureLog(t)
		p := &CredPool{cp: cp}
		wake := cp.slotAvailableChannel()
		t0 := time.Now()
		p.ReleaseHeld(0, creds, "", t0.Add(150*time.Millisecond), "its deallocate was not answered")
		if active, live, _ := leaseCounts(cp, 0); active != connsPerSlot || live != connsPerSlot {
			t.Fatalf("right behind the hold the slot counts %d seat(s), %d lease(s) out — want %d and %d: the seat went back at once", active, live, connsPerSlot, connsPerSlot)
		}
		select {
		case <-wake:
		case <-time.After(2 * time.Second):
			t.Fatal("the held seat was never let go")
		}
		if took := time.Since(t0); took < 150*time.Millisecond {
			t.Errorf("the held seat was let go after %v, want not before its moment (150ms)", took)
		}
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("behind its moment the slot counts %d seat(s), want %d", active, connsPerSlot-1)
		}
		out := said()
		if !strings.Contains(out, "keeps a seat counted") || !strings.Contains(out, "its deallocate was not answered") {
			t.Errorf("the hold's line does not say the reason it was given")
		}
		if strings.Contains(out, "answered 437") {
			t.Errorf("the hold's line calls an unanswered deallocate a 437")
		}
	})

	t.Run("a moment already past frees the seat at once", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		(&CredPool{cp: cp}).ReleaseHeld(0, creds, "", time.Now().Add(-time.Second), "its deallocate was answered 437")
		if active, _, _ := leaseCounts(cp, 0); active != connsPerSlot-1 {
			t.Errorf("the slot counts %d seat(s), want %d", active, connsPerSlot-1)
		}
	})

	t.Run("native's own hold still names the 437", func(t *testing.T) {
		var mints atomic.Int32
		cp, creds := fullSlot0(t, &mints)
		said := captureLog(t)
		thawAtCleanup(t, cp, 0, connsPerSlot-1)
		cp.holdSeatUntil(0, creds, "", time.Now().Add(time.Minute))
		if out := said(); !strings.Contains(out, "its deallocate was answered 437") {
			t.Errorf("native's hold line lost its reason")
		}
	})
}
