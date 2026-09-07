package proxy

// Variant A of the post-switch hole (2026-09-06, §52 of that day's record).
//
// After an interface switch every session is dead — its socket is bound to
// the interface that went away — but the SERVER cannot see that: the VK
// allocation lives on for up to 600 s and the relay↔server leg is the
// relay's own, so the dead members stay in this client's downlink group and
// keep stealing packets onto dead allocations until the server's idle reaper
// removes them (groupIdleTimeout, 150 s). Measured: the in-app speed test
// hangs at ping, then 0.7 Mbit/s, then normal at exactly +150–165 s, on UDP
// and TCP alike. The client's own close never reaches the server either.
//
// The fix a csqtt server gets for free (a new identity replaces every older
// session) done client-side against ours, with no protocol change: on a path
// UP the client mints a NEW group session id and restarts every session that
// announced the old one. The new sessions form a new group with its own hub
// socket, WireGuard roams onto it with their first packet, and the dead
// members go on stealing only from the old group's queue — which nothing
// feeds any more — until the reaper. An old server without groups drops the
// hello as it always did and is unaffected.
//
// Two rules, both from the measurements:
//   - EVERY session moves (promotion is one-shot on the server, a live
//     session cannot be re-grouped by a second hello), because the downlink
//     follows ONE endpoint and a survivor left in the old group would carry
//     uplink only.
//   - The restart is DEBOUNCED behind the last path-up: iOS delivers a switch
//     as 2–3 events within ~500 ms (a ghost satisfied-wifi-without-SSID, an
//     unsatisfied, the real one), and the pool pauses acquires for 500 ms
//     after each; restarting on the first event would rebuild the sessions
//     on the dying interface and park them on "paused". Sessions that
//     reconnect on their own inside the window already carry the new id
//     (the rotation itself is immediate) and are spared by their epoch.

import (
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

// pathRestartSettle is how long after the LAST path-up the old sessions are
// restarted. Longer than credPool's post-path-change acquire pause (500 ms),
// so the restarted sessions do not park on "paused for path-change settle"
// — which the reconnect loop would count as a short failure — and longer
// than iOS's event burst, so one switch means one restart. A variable so a
// test can shrink it.
var pathRestartSettle = time.Second

// pathRestart is the debounce: an epoch every session stamps at its start,
// bumped on every path-up, and one timer that fires the restart for
// everything older than the epoch it was armed with.
type pathRestart struct {
	mu    sync.Mutex
	epoch int64
	timer *time.Timer
	// after is time.AfterFunc; a test substitutes one it can fire by hand.
	after func(time.Duration, func()) *time.Timer
	// fire restarts every session whose epoch is older than the argument.
	fire func(olderThan int64)
}

// current is the epoch a session starting now stamps itself with.
func (r *pathRestart) current() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.epoch
}

// pathUp bumps the epoch and (re)arms the settle timer for the restart of
// everything older than the new epoch. Returns the new epoch.
func (r *pathRestart) pathUp() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.epoch++
	e := r.epoch
	if r.timer != nil {
		r.timer.Stop()
	}
	fire := r.fire
	if fire == nil {
		return e // nothing wired to restart (a bare Proxy in a test)
	}
	after := r.after
	if after == nil {
		after = time.AfterFunc
	}
	r.timer = after(pathRestartSettle, func() { fire(e) })
	return e
}

// OnPathUp is the app's "a real interface is satisfied" hook (the path
// monitor's satisfied event on wifi/cellular/wired; wgPathChanged still runs
// for every event and does the pool marking). The group id rotates at once,
// so a session that starts from here — on its own or by the restart below —
// announces the new group; the restart of the old sessions is debounced.
func (p *Proxy) OnPathUp() {
	p.rotateGroupHello()
	// 🚨 Before the first session ever came up there is nothing to move to a
	// new group — and the tunnel's OWN start report can land here: NWPath-
	// Monitor's initial "satisfied" reaches Go in a minority of starts (a
	// race with Swift's backend assignment), 1.5 s before conn 0 on the seeded
	// path (harmless: "restarting 0 session(s)") but DURING conn 0's bootstrap
	// handshake on the unseeded one, where the settle timer would cancel that
	// attempt and cost a re-dial (≤ ~1 s and one allocate/deallocate pair —
	// never observed: every archived start is seeded). The hello still rotates
	// (the bootstrap announces the fresh id); the restart waits for a session
	// to exist. The trade, accepted and stated: a REAL switch inside an
	// unseeded bootstrap's relay handshake is left to that handshake's own
	// bounded failure — the 5 s relay dial and pion's ~8 s Allocate ladder are
	// not ctx-bound anyway, only the 10 s SRTP handshake was ever cut by the
	// settle timer — and that failure then leaves runConnection through the
	// bootstrap rule (`!signaled && readyCh != nil` → return err), so attempt 2
	// waits the bootstrap ladder's 10 s backoff: the new interface is dialled
	// at ~+8–20 s where the settle restart would have re-dialled at ~+1–2 s.
	// Pre-build-360 behaviour, on a sub-second window of a rare path; a switch
	// during a captcha-pending or WebView bootstrap has no session either way.
	if !p.firstSessionUp.Load() {
		log.Printf("proxy: path up before the first session — group rotated, nothing to restart")
		return
	}
	e := p.pathRestart.pathUp()
	log.Printf("proxy: path up — group rotated; every session older than epoch %d restarts in %s", e, pathRestartSettle)
}

// rotateGroupHello mints a new group session id. A no-op when grouping is
// off (a third-party peer, or the first draw failed): those servers never
// read the id.
func (p *Proxy) rotateGroupHello() {
	if p.groupHello.Load() == nil {
		return
	}
	id, err := uuid.NewRandom()
	if err != nil {
		log.Printf("proxy: group hello NOT rotated (uuid: %s) — the old sessions still restart", err)
		return
	}
	hello := make([]byte, 0, groupHelloLen)
	hello = append(hello, groupHelloMagic...)
	hello = append(hello, id[:]...)
	p.groupHello.Store(&hello)
	log.Printf("proxy: group hello rotated to %s — the server's old group keeps only the dead sessions", id)
}

// beginConnSession stamps a starting session with the current epoch and
// records the cancel that restarts it. Under one lock with the restart, so
// a restart can never cancel a session that started after its epoch.
func (p *Proxy) beginConnSession(connIdx int, cancel func()) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if connIdx < 0 || connIdx >= len(p.connEpoch) {
		return
	}
	p.connEpoch[connIdx] = p.pathRestart.current()
	p.connCancel[connIdx] = cancel
}

// endConnSession forgets the cancel once the session is over.
func (p *Proxy) endConnSession(connIdx int) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if connIdx < 0 || connIdx >= len(p.connCancel) {
		return
	}
	p.connCancel[connIdx] = nil
}

// restartSessionsOlderThan cancels every running session stamped before
// `epoch`. The reconnect loop sees the cancel as a REQUEST (not a failure):
// no short-failure count, no dormancy, a sub-second stagger, and the new
// session announces the current group.
func (p *Proxy) restartSessionsOlderThan(epoch int64, reason string) {
	if p.ctx != nil && p.ctx.Err() != nil {
		return
	}
	p.connMu.Lock()
	n := 0
	for i := range p.connEpoch {
		if p.connEpoch[i] < epoch && p.connCancel[i] != nil {
			p.connCancel[i]()
			n++
		}
	}
	p.connMu.Unlock()
	log.Printf("proxy: %s — restarting %d session(s) older than epoch %d", reason, n, epoch)
}
