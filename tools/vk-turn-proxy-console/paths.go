// SPDX-License-Identifier: MIT

package main

// What the proxy is told about the network: the monitor's events in the
// credential pool's terms.
//
// The pool (pkg/proxy) was tuned on iPhones. A path change marks every
// identity in use — their allocations stay behind on the path that went away
// and hold their seats at the relay for up to ten minutes — and TWO path
// changes 0.5–90 s apart are a second handover, a cascade, which pauses every
// acquire for 30 s. An iPhone's events of ONE switch arrive within half a
// second: cellular takes over at once. A laptop has nothing to fall to: its
// switch is "no network" for seconds and then the new one, and a poller
// cannot report the two closer than its interval. Told as two path changes,
// every switch read as a cascade (the field, 2026-09-30: a Wi-Fi → hotspot
// switch cost 33 s where about 4.5 s were due).
//
// So ONE handover is ONE path change:
//
//   - the network is gone: a path change — the identities in use are marked
//     now, while every session still counts as theirs;
//   - still gone: the acquires are held (there is nothing to acquire on, and
//     the end of the hold is what wakes a connection that went dormant
//     meanwhile); nothing is marked, nothing counts as an event;
//   - a network is back: the VK client dials on it and the sessions are
//     rebuilt — NOT a second path change;
//   - one network replaced by another between two readings: the whole
//     handover in one event — a path change and the rebuild.
//
// A second handover within the pool's window is still a cascade: it begins
// with its own "gone" (or its own replacement), a path change of its own.

// pathSink is the proxy's side of it — *proxy.Proxy itself in production: the
// names are the proxy's own, so that nothing stands between an event and the
// method it means.
type pathSink interface {
	WakeHealthCheck()  // a wake after a sleep: look at every session
	OnPathChange()     // a handover: mark the identities in use, judge a cascade
	OnPathTransition() // no usable path yet: hold the acquires, mark nothing
	OnPathUp()         // a network is there: rebuild the sessions on it
}

// tellPath tells the proxy what one step of the monitor saw. rotateVK is
// proxy.RotateVKSessionClient: OnPathChange rotates the VK client itself, and
// a network that comes back without a path change of its own needs the same.
func tellPath(p pathSink, rotateVK func(), ev netEvents) {
	if ev.slept > 0 {
		p.WakeHealthCheck()
	}
	switch {
	case ev.changed && !ev.up: // the network is gone — the handover begins
		p.OnPathChange()
	case !ev.changed && !ev.up: // still gone
		p.OnPathTransition()
	case ev.changed && ev.prevUp: // one network replaced by another in one reading
		p.OnPathChange()
		p.OnPathUp()
	case ev.changed: // back after "gone": the second half of that handover
		rotateVK()
		p.OnPathUp()
	}
}
