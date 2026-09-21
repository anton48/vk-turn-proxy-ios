package proxy

// The allocation out of reach (build 432).
//
// MEASURED on a stand (2026-09-21, UDP and TCP, 48 questions, no exception): a
// request that reaches the VK relay from a 5-tuple that has NO allocation is
// answered 400 "Bad Request" (CreatePermission, ChannelBind) or 437 "Invalid
// allocation" (Refresh — the unauthenticated one already). The relay does not
// say WHY there is none, and there are two whys:
//
//   - the allocation is gone — it expired, or was given back: its seat is free;
//   - the client's address MAPPING CHANGED under a UDP socket — a translator on
//     the path forgot the flow across a silence: the allocation lives on under
//     the OLD 5-tuple, out of this socket's reach, and HOLDS ITS SEAT on the
//     identity's quota until it expires.
//
// The field showed the second (430 over UDP, asleep, 2026-09-21): eight sessions
// of one burst had their permission refresh answered 400 at the first wake after
// a 150-s freeze, were found dead by the probe 82 s later, and their deallocates
// were answered 437. Build 430 read a 437 as "the relay holds nothing" and gave
// those leases back at once; the pool seated three re-dials on the identity —
// five seats in their second plus three new, eight of ten by its count — and all
// three were refused with 486: the relay still counted the five.
//
// So a session keeps what it learns of its allocation's LIFE at the relay
// (allocLife — hung on the note its lease is released by, gaveBack):
//
//   - WHEN IT CAN HAVE EXPIRED, at the latest: pion says the lifetime the relay
//     granted, at the Allocate and at every refresh that succeeded — the only
//     place a refresh's outcome is heard — and the session stamps it on the WALL
//     clock: the relay's runs in real time, which a freeze of this process does
//     not stop. 🚫 The last lifetime HEARD is not that bound (the review of 432):
//     a refresh can reach the relay and be GRANTED while its answer is lost — the
//     mapping changes right behind the request — and the copies retransmitted
//     from the new mapping are refused, of which pion says nothing. So a refresh
//     that was SENT and not heard granted counts as granted, from the last moment
//     a copy of it can have left (lifeHeard, refreshAsked) — unless the
//     allocation had certainly expired before it was sent: nothing revives that;
//   - a seat whose deallocate was answered 437 stays COUNTED until then
//     (returnAllocation → gaveBack.noteOutOfReach → credPool.holdSeatUntil).
//     EXPIRED BY THE CLOCK — a sleep that outlasted the lifetime — the 437 is
//     honest and the seat free at once: holding forty such seats for ten
//     minutes would send every re-dial after a long sleep to a fresh identity;
//   - a permission refresh answered 400 is the EARLIEST sign that the session is
//     dead at the relay: it is ended at once, not when the probe has listened
//     its thirty seconds out (pion's allocation refresh says nothing on a 437 —
//     it returns the error response's nil parse error: read in v5.0.2);
//   - and the session SAYS what its mapping did — the reflexive address asked at
//     the Allocate against one asked now, a STUN Binding each (UDP only: over
//     TCP the 5-tuple is the connection's) — one line, for whoever reads the log.
//     The address itself is not printed: the port, and whether the address is
//     the same.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// assumedAllocLifetime stands in for a lifetime nobody heard the relay grant:
// pion asks for the default and the VK relay grants it (LIFETIME 600, measured).
// A var so that a test can shrink it; nothing else writes it.
var assumedAllocLifetime = 10 * time.Minute

// mappingAskBudget bounds the Binding that asks the relay how it sees this
// socket NOW: one round trip and a retransmission of it. A var for tests.
var mappingAskBudget = 300 * time.Millisecond

// allocLife is what ONE session knows of its allocation's life at the relay. The
// zero value knows nothing; a nil *allocLife is no bookkeeping.
type allocLife struct {
	mapped atomic.Pointer[net.UDPAddr] // how the relay saw this socket at the Allocate (UDP; nil = not asked, or not answered)
	gone   atomic.Bool                 // the relay has answered for this socket as for one that has no allocation
	said   atomic.Bool                 // the mapping has been said: once per session
	client atomic.Pointer[turn.Client] // whom to ask

	mu     sync.Mutex
	heard  lifeHeard      // what pion has said of the allocation's life
	ending bool           // wait has been called: nothing is begun behind it
	asks   sync.WaitGroup // the goroutines that ask the relay: joined behind the client's Close (wait)

	// Set by the session before its client exists, never written again.
	kill    func() // ends the session
	connIdx int
	udp     bool
}

// lifeHeard is what a session has HEARD of its allocation's life — read and
// written together, under allocLife.mu. Every moment in it is a WALL-clock one.
type lifeHeard struct {
	until   time.Time     // by its last GRANT the relay lets the allocation go here at the latest; zero = none heard
	granted time.Duration // that grant's lifetime — what pion asks for at the next refresh
	asked   time.Time     // a refresh SENT and not heard granted — a copy of it may have been granted all the same; zero = none
	ended   time.Time     // when that refresh's transaction was heard to end: no copy of it left later; zero = not heard
}

// lifeSlack is added to every bound of the allocation's life: a copy of a
// request still on its way when the answer was read sets the relay's clock a path
// delay later than this side's. A var for tests.
var lifeSlack = 2 * time.Second

// fresh forgets the allocation before: called right BEFORE an Allocate — pion
// says the lifetime it was granted from inside that call. (The direct session
// makes one allocation after another under one note.)
func (l *allocLife) fresh() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.ending = false // the asks of the allocation before were joined behind its client's Close
	l.heard = lifeHeard{}
	l.mu.Unlock()
	l.mapped.Store(nil)
	l.client.Store(nil)
	l.gone.Store(false)
	l.said.Store(false)
}

// isGone: the relay has answered for this socket as for one with no allocation.
func (l *allocLife) isGone() bool { return l != nil && l.gone.Load() }

// granted stamps the lifetime the relay has just been HEARD to grant. The grant
// settles whatever was sent before it: the relay's clock was set by the copy it
// answered, and that copy left before now.
func (l *allocLife) granted(d time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.heard = lifeHeard{until: wallClock().Add(d + lifeSlack), granted: d}
	l.mu.Unlock()
}

// refreshAsked: pion is about to send a refresh. Until it is heard GRANTED it may
// have been granted unheard. 🚫 Except when the allocation has certainly expired
// already — a refresh cannot bring a dead allocation back: the overdue refreshes
// of a wake behind a long sleep must not turn forty honest 437s into forty seats
// held for a lifetime.
func (l *allocLife) refreshAsked() {
	if l == nil {
		return
	}
	now := wallClock()
	l.mu.Lock()
	if now.Before(l.boundLocked(now)) {
		l.heard.asked, l.heard.ended = now, time.Time{}
	}
	l.mu.Unlock()
}

// refreshEnded: the transaction of the refresh last sent has come back — with an
// answer that may be no grant, or with none. No copy of it leaves after this.
func (l *allocLife) refreshEnded() {
	if l == nil {
		return
	}
	now := wallClock()
	l.mu.Lock()
	if !l.heard.asked.IsZero() && l.heard.ended.IsZero() {
		l.heard.ended = now
	}
	l.mu.Unlock()
}

// boundLocked is when the allocation can have expired at the LATEST: the last
// grant heard — nothing heard: a whole assumed lifetime from now — or, later
// than that, a lifetime behind the last moment a copy of a refresh that was not
// heard granted can have left. Caller holds l.mu.
func (l *allocLife) boundLocked(now time.Time) time.Time {
	h := l.heard
	until := h.until
	if until.IsZero() {
		until = now.Add(assumedAllocLifetime)
	}
	if !h.asked.IsZero() {
		last := h.ended
		if last.IsZero() {
			last = now // its transaction is still running: a copy may be leaving now
		}
		lifetime := h.granted
		if lifetime <= 0 {
			lifetime = assumedAllocLifetime
		}
		if u := last.Add(lifetime + lifeSlack); u.After(until) {
			until = u
		}
	}
	return until.Round(0)
}

// expiry is when the allocation can have expired at the latest — boundLocked.
func (l *allocLife) expiry(now time.Time) time.Time {
	if l == nil {
		return now.Add(assumedAllocLifetime).Round(0)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundLocked(now.Round(0))
}

// begin registers one more goroutine that asks the relay; false once the session
// is ending — a WaitGroup must not be added to beside its Wait.
func (l *allocLife) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ending {
		return false
	}
	l.asks.Add(1)
	return true
}

// wait joins whatever is still asking the relay on this session's behalf. Called
// behind the client's Close, which makes a pending question return at once.
func (l *allocLife) wait() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.ending = true
	l.mu.Unlock()
	l.asks.Wait()
}

// pion's own words (internal/client, v5.0.2) — pinned by a test that reads them
// in the module's source, so that an upgrade which rewords them is SEEN.
var pionLifetimeLine = regexp.MustCompile(`^(?:Initial|Updated) lifetime: (\d+) seconds$`)

const (
	pionPermissionRefreshFailed = "Fail to refresh permissions: "
	relayAnswered400            = "error response (error 400:"
	// An allocation refresh, as pion says it (allocation.go, refreshAllocation):
	// the first line BEFORE the transaction — the first copy is about to leave;
	// the second when the transaction has come back WITH an answer, whatever it
	// says (a refusal other than a stale nonce is then swallowed without a
	// word); the third, from the timer, when it came back with none.
	pionRefreshSent     = "Send refresh request (dontWait=false)"
	pionRefreshAnswered = "Refresh request sent, and waiting response"
	pionRefreshFailed   = "Failed to refresh allocation: "
)

// heardDebug is pion's Debug line: a lifetime the relay granted, or a refresh on
// its way out and back.
func (l *allocLife) heardDebug(msg string) {
	if l == nil {
		return
	}
	switch msg {
	case pionRefreshSent:
		l.refreshAsked()
		return
	case pionRefreshAnswered:
		l.refreshEnded()
		return
	}
	if m := pionLifetimeLine.FindStringSubmatch(msg); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
			l.granted(time.Duration(n) * time.Second)
		}
	}
}

// heardError is pion's Warn / Error line. The permission refresh answered 400
// is the relay saying that this socket has no allocation (the header): the
// session is dead at the relay, whatever the probe will find in half a minute.
// Anchored on pion's prefix and on the error-code form — a bare "400" is a
// port number as often as not.
func (l *allocLife) heardError(msg string) {
	if l == nil {
		return
	}
	if strings.HasPrefix(msg, pionRefreshFailed) {
		l.refreshEnded() // no answer at all: whether a copy was granted stays unknown — but none leaves later
		return
	}
	if !strings.HasPrefix(msg, pionPermissionRefreshFailed) || !strings.Contains(msg, relayAnswered400) {
		return
	}
	l.outOfReach("its permission refresh was answered 400")
}

// outOfReach is called when the relay has answered for this socket as for one
// that has no allocation. Once per session: the mapping is asked about and
// SAID, then the session is ended. Never on the caller's goroutine — pion's
// refresh loop calls from inside the client — and joined by wait.
func (l *allocLife) outOfReach(what string) {
	if l == nil || !l.gone.CompareAndSwap(false, true) || !l.begin() {
		return
	}
	go func() {
		defer l.asks.Done()
		l.sayMapping(what)
		log.Printf("proxy: [conn %d] the session is dead at the relay (%s) — ending it now, ahead of the probe's verdict", l.connIdx, what)
		if l.kill != nil {
			l.kill()
		}
	}()
}

// askMappingAtAllocate asks the relay how it sees this socket while the
// allocation is fresh — what a later answer is compared with. In the background:
// nothing of the session's setup waits for it. UDP only.
func (l *allocLife) askMappingAtAllocate(tc *turn.Client) {
	if l == nil {
		return
	}
	l.client.Store(tc)
	if !l.udp || !l.begin() {
		return
	}
	go func() {
		defer l.asks.Done()
		if a, err := l.reflexiveNow(tc, 0); err == nil {
			l.mapped.Store(a)
		}
	}()
}

// reflexiveNow asks the relay for this socket's reflexive address — a STUN
// Binding through the client's transaction layer (retransmitted by it). With a
// budget the WAIT is abandoned when it runs out; the question itself ends with
// the client's Close at the latest, and its goroutine is one of those wait
// joins behind that Close: nothing is left running behind a teardown.
func (l *allocLife) reflexiveNow(tc *turn.Client, budget time.Duration) (*net.UDPAddr, error) {
	req, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return nil, err
	}
	if !l.begin() {
		return nil, errors.New("the session is ending")
	}
	type answer struct {
		a   *net.UDPAddr
		err error
	}
	done := make(chan answer, 1)
	go func() {
		defer l.asks.Done()
		res, err := tc.PerformTransaction(req, tc.TURNServerAddr(), false)
		if err != nil {
			done <- answer{nil, err}
			return
		}
		var x stun.XORMappedAddress
		if err := x.GetFrom(res.Msg); err != nil {
			done <- answer{nil, err}
			return
		}
		done <- answer{&net.UDPAddr{IP: x.IP, Port: x.Port}, nil}
	}()
	if budget <= 0 {
		r := <-done
		return r.a, r.err
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.a, r.err
	case <-timer.C:
		return nil, fmt.Errorf("no answer within %s", budget)
	}
}

// sayMapping says, once per session, what this socket's mapping has done since
// the Allocate — the direct evidence for one of the header's two whys.
func (l *allocLife) sayMapping(what string) {
	if l == nil || !l.said.CompareAndSwap(false, true) {
		return
	}
	left := time.Until(l.expiry(time.Now())).Round(time.Second)
	held := fmt.Sprintf("if the allocation lives on under another mapping it holds its quota seat for %s more", left)
	if left <= 0 {
		held = "its lifetime has run out by the clock: the seat is free"
	}
	if !l.udp {
		log.Printf("proxy: [conn %d] the relay has NO allocation for this connection (%s) — over TCP the 5-tuple is the connection's own: the relay let the allocation go; %s",
			l.connIdx, what, held)
		return
	}
	was, tc := l.mapped.Load(), l.client.Load()
	if was == nil || tc == nil {
		log.Printf("proxy: [conn %d] the relay has NO allocation for this socket (%s) — the mapping at the Allocate is not known (it was not answered in time): cannot tell whether it changed; %s",
			l.connIdx, what, held)
		return
	}
	now, err := l.reflexiveNow(tc, mappingAskBudget)
	switch {
	case err != nil:
		log.Printf("proxy: [conn %d] the relay has NO allocation for this socket (%s) — the mapping was port %d at the Allocate, and the relay did not say what it is now (%v); %s",
			l.connIdx, what, was.Port, err, held)
	case now.Port == was.Port && now.IP.Equal(was.IP):
		log.Printf("proxy: [conn %d] the relay has NO allocation for this socket (%s) — the mapping is UNCHANGED (port %d): the relay let the allocation go by itself; %s",
			l.connIdx, what, was.Port, held)
	default:
		addr := "the same address"
		if !now.IP.Equal(was.IP) {
			addr = "ANOTHER address"
		}
		log.Printf("proxy: [conn %d] the relay has NO allocation for this socket (%s) — the mapping CHANGED: port %d at the Allocate, port %d now, %s — the allocation lives on under the old mapping, out of reach; %s",
			l.connIdx, what, was.Port, now.Port, addr, held)
	}
}
