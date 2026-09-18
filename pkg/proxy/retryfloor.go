package proxy

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// THE RETRY FLOOR — what bounds a connection's retry rate while the NETWORK
// itself is failing.
//
// runConnection's two waits after a failed session (the 2–7 s delay, the
// 30–60 s dormancy) both return at once on the pool's slot-available
// broadcast, and the dormancy's wake resets the failure counter. That is
// right for what the broadcast was built for — a connection parked for a
// slot wakes the moment one opens — and wrong when the failure had nothing to
// do with slots: a failing connection's release() broadcasts whenever its slot
// was FULL, so forty connections whose dials fail instantly wake one another at
// the speed of the failure. Seen in the field twice: a captive portal answering
// RST (345 refused dials in one second, 2026-09-17) and a Wi-Fi whose route
// was not up yet, where the failure is a local errno with no round trip at
// all — 2 778 dials in 0.6 s, 69 per connection, 19 411 log lines in one
// second and +5 MB of rss under a 35 MB cap (2026-09-18). The chain stops by
// itself once a wave releases from slots below their cap, but nothing in the
// code bounded it.
//
// The floor: after a NETWORK-CLASS failure a slot-available wake is honoured no
// sooner than floor(k) after that failure, k = this connection's consecutive
// network-class failures — 250 ms, 500 ms, 1 s … capped at 8 s. The timers are
// untouched (they are ≥ 2 s already) and a wake does not reset k.
//
// 🚨 What it must NOT cost: the recovery from a silent dead zone (no path
// event — iOS keeps reporting the interface satisfied). There the dormant
// connections come back through these very wakes once the first dials
// succeed. So the floor is VOID as soon as ANY connection's session came up
// after this connection's last failure: the network has proved itself, and a
// connection holding a wake back is released at that moment (sessionUps'
// broadcast), not at the end of its hold.
//
// Network-class is decided by what HAPPENED, not by the error's text: the
// iteration ended with an error, no session was established in it, and the
// error is none of the pool's own answers (a park), a captcha, a 486 or a
// 401/403 — those are the relay or VK ANSWERING, which a dead network does not.
const (
	retryFloorBase = 250 * time.Millisecond
	retryFloorCap  = 8 * time.Second
)

// retryFloor is one connection's state; owned by its runConnection goroutine.
type retryFloor struct {
	failures int       // consecutive network-class failures
	lastFail time.Time // when the last of them ended
}

// noteNetworkFailure records one more network-class failure, ended at now.
func (f *retryFloor) noteNetworkFailure(now time.Time) {
	f.failures++
	f.lastFail = now
}

// reset forgets the streak: the connection's own session came up, or a path
// change restarted it onto a new network.
func (f *retryFloor) reset() { *f = retryFloor{} }

// retryFloorFor is the floor after the k-th consecutive network-class failure.
func retryFloorFor(k int) time.Duration {
	if k <= 0 {
		return 0
	}
	d := retryFloorBase
	for i := 1; i < k && d < retryFloorCap; i++ {
		d *= 2
	}
	if d > retryFloorCap {
		d = retryFloorCap
	}
	return d
}

// hold is how much longer a slot-available wake seen at now must be held back;
// zero when there is no streak, when the floor has passed, or when a session
// came up (anywhere in the proxy) after this connection's last failure.
func (f *retryFloor) hold(now, lastSessionUp time.Time) time.Duration {
	if f.failures == 0 || lastSessionUp.After(f.lastFail) {
		return 0
	}
	if d := f.lastFail.Add(retryFloorFor(f.failures)).Sub(now); d > 0 {
		return d
	}
	return 0
}

// isNetworkClassFailure reports whether err — the error of an iteration in
// which NO session was established (the caller's half of the rule) — is a
// failure of the network rather than an answer from the pool, VK or the relay.
func isNetworkClassFailure(err error) bool {
	if err == nil {
		return false
	}
	var park *poolParkError
	var captcha *CaptchaRequiredError
	if errors.As(err, &park) || errors.As(err, &captcha) || isQuotaError(err) || isAuthError(err) {
		return false
	}
	return true
}

// sessionUps records when sessions came up: per connection (did THIS iteration
// establish one?) and proxy-wide (has the network proved itself since a
// failure?), with a close-and-replace broadcast so a connection holding a wake
// back under its floor learns of it at once. The zero value is ready.
type sessionUps struct {
	mu   sync.Mutex
	last time.Time
	per  map[int]time.Time
	ch   chan struct{}
}

// note records that connIdx's session came up at now and wakes the holders.
func (s *sessionUps) note(connIdx int, now time.Time) {
	s.mu.Lock()
	s.last = now
	if s.per == nil {
		s.per = make(map[int]time.Time)
	}
	s.per[connIdx] = now
	old := s.ch
	s.ch = make(chan struct{})
	s.mu.Unlock()
	if old != nil {
		close(old)
	}
}

// since reports whether connIdx's session came up at or after t.
func (s *sessionUps) since(connIdx int, t time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.per[connIdx]
	return ok && !up.Before(t)
}

// lastAndWake returns the latest session-up of any connection and the channel
// the NEXT one closes — read together, so none can fall between the two.
func (s *sessionUps) lastAndWake() (time.Time, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch == nil {
		s.ch = make(chan struct{})
	}
	return s.last, s.ch
}

// noteSessionUp is called where a session function logs "session established".
func (p *Proxy) noteSessionUp(connIdx int) { p.ups.note(connIdx, time.Now()) }

// retryWake says what ended a retry wait.
type retryWake int

const (
	retryWakeTimer  retryWake = iota // the wait's own timer ran out
	retryWakeSignal                  // the pool's slot-available broadcast, once the floor allowed it
)

// waitRetry is runConnection's wait between a failed session and the next
// attempt: up to d, cut short by the slot-available broadcast on slotCh — which
// after a network-class failure (floored) is honoured only once the
// connection's floor has passed or a session has come up somewhere since. The
// error is the context's when the session or the proxy stops. A held wake is
// SAID, once per wait, and so is its early release: in a log the floor at work
// must not look like a broadcast that never came.
func (p *Proxy) waitRetry(sessCtx context.Context, connIdx int, d time.Duration, slotCh <-chan struct{}, floor *retryFloor, floored bool) (retryWake, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	signalled, held := false, false
	for {
		lastUp, upCh := p.ups.lastAndWake()
		var holdC <-chan time.Time
		var holdTimer *time.Timer
		sigC := slotCh
		if signalled {
			hold := time.Duration(0)
			if floored {
				hold = floor.hold(time.Now(), lastUp)
			}
			if hold <= 0 {
				if held && lastUp.After(floor.lastFail) {
					log.Printf("proxy: [conn %d] held wake released — a session came up, the network works", connIdx)
				}
				return retryWakeSignal, nil
			}
			if !held {
				held = true
				log.Printf("proxy: [conn %d] slot-available wake held %s under the retry floor (%d network-class failure(s) in a row)",
					connIdx, hold.Round(time.Millisecond), floor.failures)
			}
			holdTimer = time.NewTimer(hold)
			holdC = holdTimer.C
			sigC = nil // already seen; a closed channel must not spin the loop
		} else {
			upCh = nil // before the broadcast a session-up changes nothing here
		}
		var why retryWake
		var err error
		done := true
		select {
		case <-timer.C:
			why = retryWakeTimer
		case <-sigC:
			signalled, done = true, false
		case <-holdC:
			done = false // the floor has passed — the next turn returns
		case <-upCh:
			done = false // a session came up — the next turn finds the floor void
		case <-sessCtx.Done():
			err = sessCtx.Err()
		case <-p.ctx.Done():
			err = p.ctx.Err()
		}
		if holdTimer != nil {
			holdTimer.Stop()
		}
		if done {
			return why, err
		}
	}
}
