package proxy

// Build 433 — the review of 432. The lifetime the relay was last HEARD to grant
// is not the upper bound of an allocation's life: a refresh can be granted while
// its answer is lost. The bound counts every refresh that was SENT and not heard
// granted (outofreach.go — lifeHeard, refreshAsked, refreshEnded, boundLocked).
// The production session against a relay that does exactly that is
// TestARefreshGrantedWithItsAnswerLostStillHoldsTheSeat.

import (
	"testing"
	"time"
)

// lifeClock puts the clock an allocation's life is stamped by into the test's
// hands, and the slack at one second.
func lifeClock(t *testing.T) (now func() time.Time, pass func(time.Duration)) {
	t.Helper()
	at := time.Now().Round(0)
	clock, slack := wallClock, lifeSlack
	wallClock = func() time.Time { return at }
	lifeSlack = time.Second
	t.Cleanup(func() { wallClock, lifeSlack = clock, slack })
	return func() time.Time { return at }, func(d time.Duration) { at = at.Add(d) }
}

const lostNoAnswer = "Failed to refresh allocation: failed to refresh allocation: all retransmissions failed for TXID"

func TestAnAllocationsLifeCountsARefreshNotHeardGranted(t *testing.T) {
	const granted = 600 * time.Second
	after := func(t0 time.Time, d time.Duration) time.Time { return t0.Add(d + time.Second) } // a lifetime and the slack behind a moment
	want := func(t *testing.T, what string, got, want time.Time) {
		t.Helper()
		if !got.Equal(want) {
			t.Errorf("%s: the bound of the allocation's life is off by %s (got − want)", what, got.Sub(want))
		}
	}
	t.Run("answered with no grant: a lifetime behind the moment its transaction came back — and no later", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		t0 := now()
		l.heardDebug("Initial lifetime: 600 seconds")
		want(t, "the Allocate alone", l.expiry(now()), after(t0, granted))
		pass(300 * time.Second)
		l.heardDebug(pionRefreshSent)
		pass(200 * time.Millisecond) // a copy granted unheard, the next one refused from another mapping
		back := now()
		l.heardDebug(pionRefreshAnswered) // …and pion says nothing of the refusal
		want(t, "a refresh answered with no grant", l.expiry(now()), after(back, granted))
		if !l.expiry(now()).After(after(t0, granted)) {
			t.Error("the last lifetime HEARD is taken for the bound — a refresh granted with its answer lost keeps the allocation alive behind it")
		}
		pass(200 * time.Second)
		want(t, "…200 s on", l.expiry(now()), after(back, granted))
	})
	t.Run("no answer at all: the same, from pion's failure line", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		l.heardDebug("Initial lifetime: 600 seconds")
		pass(300 * time.Second)
		l.heardDebug(pionRefreshSent)
		pass(7800 * time.Millisecond)
		gaveUp := now()
		l.heardError(lostNoAnswer)
		pass(100 * time.Second)
		want(t, "a refresh that came back with no answer", l.expiry(now()), after(gaveUp, granted))
		if l.isGone() {
			t.Error("a refresh that failed marked the socket as one the relay has disowned")
		}
	})
	t.Run("still on its way when asked: a copy may be leaving NOW", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		l.heardDebug("Initial lifetime: 600 seconds")
		pass(300 * time.Second)
		l.heardDebug(pionRefreshSent)
		for range 3 {
			pass(2 * time.Second)
			want(t, "a refresh with nothing heard of it", l.expiry(now()), after(now(), granted))
		}
	})
	t.Run("a grant settles it — a stale nonce's retry too", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		l.heardDebug("Initial lifetime: 600 seconds")
		pass(300 * time.Second)
		l.heardDebug(pionRefreshSent)
		pass(50 * time.Millisecond)
		l.heardDebug(pionRefreshAnswered)
		l.heardDebug("Refresh allocation: 438, got new nonce.")
		l.heardDebug(pionRefreshSent)
		pass(50 * time.Millisecond)
		l.heardDebug(pionRefreshAnswered)
		grantedAt := now()
		l.heardDebug("Updated lifetime: 600 seconds")
		pass(250 * time.Second)
		want(t, "a refresh heard granted", l.expiry(now()), after(grantedAt, granted))
		l.heardDebug(pionRefreshAnswered) // a line with no refresh out means nothing
		l.heardError(lostNoAnswer)
		want(t, "…and nothing is left of what was sent before it", l.expiry(now()), after(grantedAt, granted))
	})
	t.Run("a refresh sent when the allocation has certainly expired revives nothing", func(t *testing.T) {
		now, pass := lifeClock(t)
		var gave gaveBack
		t0 := now()
		gave.lifeOf().heardDebug("Initial lifetime: 600 seconds")
		pass(700 * time.Second) // a sleep that outlasted the lifetime: the overdue refresh goes out at the wake
		gave.lifeOf().heardDebug(pionRefreshSent)
		gave.lifeOf().heardDebug(pionRefreshAnswered)
		want(t, "a refresh behind the allocation's end", gave.lifeOf().expiry(now()), after(t0, granted))
		if err := returnAllocation(closerFunc(func() error { return nil }), func() deallocVerdict { return deallocGone }, &gave); err != nil {
			t.Fatal(err)
		}
		if until, held := gave.takeHold(); held {
			t.Errorf("the seat is held until %s from now — a 437 behind a lifetime that has run out is honest: forty such seats after a long sleep would be held for a lifetime each", until.Sub(now()))
		}
	})
	t.Run("…and one sent a moment before it could have expired counts", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		l.heardDebug("Initial lifetime: 600 seconds")
		pass(600 * time.Second) // inside the slack: the relay's clock may run that much behind this side's
		l.heardDebug(pionRefreshSent)
		sent := now()
		l.heardDebug(pionRefreshAnswered)
		want(t, "a refresh sent inside the bound", l.expiry(now()), after(sent, granted))
	})
	t.Run("nothing heard of a lifetime: the assumed one, for the refresh too", func(t *testing.T) {
		now, pass := lifeClock(t)
		var l allocLife
		l.heardDebug(pionRefreshSent)
		pass(time.Second)
		back := now()
		l.heardDebug(pionRefreshAnswered)
		pass(time.Minute)
		if got, floor := l.expiry(now()), after(back, assumedAllocLifetime); got.Before(floor) {
			t.Errorf("the allocation can have lived until %s short of a whole assumed lifetime behind the refresh", floor.Sub(got))
		}
	})
	t.Run("THE REVIEW, at the teardown: the confirmed lifetime has run out, the deallocate is answered 437 — and the seat is HELD", func(t *testing.T) {
		for _, refreshed := range []bool{true, false} {
			now, pass := lifeClock(t)
			var gave gaveBack
			gave.lifeOf().heardDebug("Initial lifetime: 4 seconds")
			pass(2 * time.Second)
			var back time.Time
			if refreshed {
				lg := (&turnLoggerFactory{slot: 0, life: gave.lifeOf()}).NewLogger("turnc")
				lg.Debugf("Send refresh request (dontWait=%v)", false) // pion's own calls, allocation.go
				pass(200 * time.Millisecond)
				back = now()
				lg.Debug("Refresh request sent, and waiting response")
			}
			pass(3300 * time.Millisecond) // 5.5 s: behind the four seconds heard and their slack, ahead of the relay's 2.2 + 4
			if err := returnAllocation(closerFunc(func() error { return nil }), func() deallocVerdict { return deallocGone }, &gave); err != nil {
				t.Fatal(err)
			}
			until, held := gave.takeHold()
			switch {
			case refreshed && !held:
				t.Error("the seat was let go at once — by the last CONFIRMED lifetime, although a refresh had been sent inside it and was never heard granted: the relay may hold the allocation for that refresh's lifetime")
			case refreshed:
				want(t, "the hold", until, after(back, 4*time.Second))
			case held:
				t.Errorf("control: no refresh was sent, the lifetime heard has run out — and the seat is held until %s from now", until.Sub(now()))
			}
		}
	})
}
