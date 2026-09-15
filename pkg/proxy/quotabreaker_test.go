package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A pool whose fetcher mints a fresh credential on demand and counts the
// mints; the pauses shrunk to milliseconds and restored afterwards.
func breakerPool(t *testing.T, mints *atomic.Int32) *credPool {
	t.Helper()
	prevBase, prevMax := quotaPauseBase, quotaPauseMax
	quotaPauseBase, quotaPauseMax = 60*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { quotaPauseBase, quotaPauseMax = prevBase, prevMax })
	const relay = "95.163.34.180:19302"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, slot int) (string, *TURNCreds, error) {
		n := mints.Add(1)
		return relay, &TURNCreds{Username: fmt.Sprintf("%d:mint-%d-slot-%d", time.Now().Add(8*time.Hour).Unix(), n, slot),
			Password: "p", Address: relay, Addresses: []string{relay}}, nil
	})
	cp.mu.Lock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	cp.mu.Unlock()
	return cp
}

// mintFor is get() for connIdx when it is expected to MINT: the slot it
// landed on, or a fatal.
func mintFor(t *testing.T, cp *credPool, connIdx int) int {
	t.Helper()
	_, _, slot, err := cp.get(connIdx, false)
	if err != nil {
		t.Fatalf("get(%d) = %v, want a mint", connIdx, err)
	}
	return slot
}

// THE STORM, cut short at the second fresh refusal. Two credentials minted
// and refused with 486 within a minute of their mint pause minting: get()
// parks with the breaker's line instead of minting a third identity, the
// grower's tryFill mints nothing, the stats say so, and the pause ends with
// a broadcast that lets the next get() mint again. Sabotages seen red: the
// hook dropped from markSaturated (a third mint); get()'s gate dropped
// (same); tryFill's gate dropped (the grower mints during the pause).
func TestTwoFreshRefusalsPauseMinting(t *testing.T) {
	var mints atomic.Int32
	cp := breakerPool(t, &mints)

	a := mintFor(t, cp, 0)
	cp.markSaturated(a) // 486 on a credential minted a moment ago: fresh refusal 1
	b := mintFor(t, cp, 1)
	if b == a {
		t.Fatalf("the second get seated on the saturated slot %d instead of minting", a)
	}
	cp.markSaturated(b) // fresh refusal 2 → the breaker trips
	if got := mints.Load(); got != 2 {
		t.Fatalf("mints before the trip = %d, want 2", got)
	}

	_, _, _, err := cp.get(2, false)
	if err == nil || !strings.Contains(err.Error(), "minting paused") {
		t.Fatalf("get after two fresh refusals = %v, want the breaker's park (\"minting paused\")", err)
	}
	var park *poolParkError
	if !errors.As(err, &park) || park.wake == nil {
		t.Fatalf("the breaker's park carries no wake channel: %T", err)
	}
	if cp.tryFill(5, false, 0) {
		t.Fatal("tryFill minted during the pause — the grower must respect the breaker")
	}
	if got := mints.Load(); got != 2 {
		t.Fatalf("mints during the pause = %d, want 2 — a third identity was minted for a relay that refuses them", got)
	}
	refusals, paused := cp.quotaSnapshot()
	if refusals != 2 || paused <= 0 {
		t.Fatalf("quotaSnapshot = (%d refusals, paused %s), want (2, > 0)", refusals, paused)
	}

	// The pause ends with a broadcast on the channel the park carried, and
	// minting resumes.
	select {
	case <-park.wake:
	case <-time.After(2 * time.Second):
		t.Fatal("the pause's end did not broadcast on the park's channel")
	}
	if _, paused := cp.quotaSnapshot(); paused > 0 {
		t.Fatalf("still paused %s after the broadcast", paused)
	}
	c := mintFor(t, cp, 2)
	if c == a || c == b || mints.Load() != 3 {
		t.Fatalf("after the pause: slot %d, mints %d — want a fresh mint into a third slot", c, mints.Load())
	}
}

// THE CONTROL: a 486 on an OLD credential is a real quota — VK still holds
// that identity's allocations (the ghost case after a switch) — and a fresh
// identity is exactly its cure, so it must not count. Two of them trip
// nothing and get() mints. Sabotage seen red: the freshness test dropped
// from noteQuotaRefusalLocked (every 486 counts).
func TestARefusalOnAnOldCredentialIsNotFresh(t *testing.T) {
	var mints atomic.Int32
	cp := breakerPool(t, &mints)
	const relay = "95.163.34.180:19302"
	cp.mu.Lock()
	for i := 0; i < 2; i++ {
		cp.pool[i] = credPoolEntry{addr: relay, ts: time.Now().Add(-2 * quotaFreshCredWindow), active: 1,
			creds: &TURNCreds{Username: fmt.Sprintf("%d:old-%d", time.Now().Add(8*time.Hour).Unix(), i), Password: "p", Address: relay, Addresses: []string{relay}}}
	}
	cp.mu.Unlock()
	cp.markSaturated(0)
	cp.markSaturated(1)
	refusals, paused := cp.quotaSnapshot()
	if refusals != 2 || paused != 0 {
		t.Fatalf("quotaSnapshot after two old-credential 486s = (%d, paused %s), want (2, 0) — old refusals must not trip the breaker", refusals, paused)
	}
	mintFor(t, cp, 5)
	if mints.Load() != 1 {
		t.Fatalf("mints = %d, want 1 — a fresh identity is the cure for a real quota", mints.Load())
	}
}

// The ladder: a trip within quotaLadderWindow of the previous one doubles
// the pause, up to quotaPauseMax; the next trip needs two NEW fresh
// refusals (the count is cleared at the trip). Driven with the pool's own
// clock so the arithmetic is exact. Sabotage seen red: the doubling loop
// dropped (every pause is the base).
func TestTheMintPauseDoublesPerTripAndCaps(t *testing.T) {
	var mints atomic.Int32
	cp := breakerPool(t, &mints)
	quotaPauseBase, quotaPauseMax = 100*time.Millisecond, 350*time.Millisecond
	now := time.Now()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.pool[0] = credPoolEntry{ts: now, active: 1, creds: &TURNCreds{Username: "x"}}
	trip := func(at time.Time) time.Duration {
		cp.noteQuotaRefusalLocked(0, at)
		if _, paused := cp.mintPausedLocked(at); paused {
			t.Fatalf("one fresh refusal at %s tripped the breaker — the trip needs %d", at.Sub(now), quotaRefusalTrip)
		}
		cp.noteQuotaRefusalLocked(0, at)
		remaining, paused := cp.mintPausedLocked(at)
		if !paused {
			t.Fatalf("two fresh refusals at %s did not trip the breaker", at.Sub(now))
		}
		return remaining
	}
	if p := trip(now); p != 100*time.Millisecond {
		t.Fatalf("first pause = %s, want the base 100ms", p)
	}
	if p := trip(now.Add(time.Second)); p != 200*time.Millisecond {
		t.Fatalf("second pause = %s, want 2× the base", p)
	}
	if p := trip(now.Add(2 * time.Second)); p != 350*time.Millisecond {
		t.Fatalf("third pause = %s, want the cap 350ms", p)
	}
	// Refusals DURING a pause do not stack another trip on top.
	cp.pool[0].ts = now.Add(2 * time.Second)
	cp.noteQuotaRefusalLocked(0, now.Add(2*time.Second+10*time.Millisecond))
	cp.noteQuotaRefusalLocked(0, now.Add(2*time.Second+20*time.Millisecond))
	if len(cp.quota.trips) != 3 {
		t.Fatalf("refusals inside the pause added a trip: %d trips, want 3", len(cp.quota.trips))
	}
	// After a quiet quotaLadderWindow the ladder starts over at the base.
	later := now.Add(2*time.Second + quotaLadderWindow + time.Second)
	cp.pool[0].ts = later
	if p := trip(later); p != 100*time.Millisecond {
		t.Fatalf("pause after a quiet ladder window = %s, want the base 100ms", p)
	}
}

// The hooks sit where the traffic is — pinned by spelling, because the
// three call sites are in creds.go, a file gofmt never touches and a unit
// test cannot see the ORDER of: markSaturated must note the refusal (every
// 486 of both transports goes through it), get() must consult the pause
// BEFORE the cold-start cap (so the park says why), tryFill BEFORE its
// claim (so the grower mints nothing). Sabotage seen red: any of the three
// removed.
func TestTheBreakerHooksSitOnEveryMintPath(t *testing.T) {
	src, err := os.ReadFile("creds.go")
	if err != nil {
		t.Fatal(err)
	}
	c := string(src)
	inOrder := func(fn string, steps ...string) {
		t.Helper()
		start := strings.Index(c, fn)
		if start < 0 {
			t.Fatalf("%s not found in creds.go", fn)
		}
		body := c[start:]
		if end := strings.Index(body[1:], "\nfunc "); end > 0 {
			body = body[:end+1]
		}
		from := 0
		for _, step := range steps {
			i := strings.Index(body[from:], step)
			if i < 0 {
				t.Fatalf("%s: %q not found after the previous step — the breaker hook is missing or out of order", fn, step)
			}
			from += i + len(step)
		}
	}
	inOrder("func (cp *credPool) markSaturated(", "entry := cp.pool[slot]", "cp.noteQuotaRefusalLocked(slot, time.Now())", "cp.applySaturationLocked(slot, cooldown, reason)")
	inOrder("func (cp *credPool) get(", "cp.mintPausedLocked(time.Now()); paused {", "wake := cp.slotAvailableCh", "cp.mu.Unlock()", "minting paused", "Phase 2 cold-start cap")
	inOrder("func (cp *credPool) tryFill(", "cp.mintPausedLocked(time.Now()); paused {", "cp.mu.Unlock()", "return false", "gen := cp.claimForFetchLocked(slot)")
	if strings.Count(c, "cp.noteQuotaRefusalLocked(") != 1 {
		t.Errorf("creds.go calls noteQuotaRefusalLocked %d times, want exactly 1 — inside markSaturated, the one place every 486 reaches the pool", strings.Count(c, "cp.noteQuotaRefusalLocked("))
	}
	if strings.Count(c, "cp.mintPausedLocked(time.Now()); paused {") != 2 {
		t.Errorf("creds.go consults the mint pause %d times, want 2 — get()'s Phase 2 and tryFill", strings.Count(c, "cp.mintPausedLocked(time.Now()); paused {"))
	}
}
