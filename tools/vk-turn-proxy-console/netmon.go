// SPDX-License-Identifier: MIT

package main

// The network monitor: the console's PathMonitor. Every tick it reads the
// physical default route; a change of the network (next hop, interface, the
// interface's own addresses) or its loss is an event, and a tick that comes
// much later by the WALL clock than it was due is a wake from sleep (a laptop
// lid) — the proxy is told both, the way the app's extension tells it:
// OnPathChange on every change, OnPathUp when a network is there, WakeHealthCheck
// after a sleep.

import (
	"context"
	"time"
)

// wakeSlack: a tick later than its interval by this much, by the wall clock,
// is a sleep (the monotonic clock stands still while a Mac sleeps).
const wakeSlack = 10 * time.Second

type netEvents struct {
	changed   bool
	up        bool
	prev, cur gateway
	prevUp    bool
	slept     time.Duration // > 0: a wake after a sleep this long
}

type netMonitor struct {
	every    time.Duration
	read     func() (gateway, bool)
	identity func(gateway, bool) string

	cur    gateway
	up     bool
	id     string
	lastAt time.Time // wall clock, monotonic reading stripped
}

func newNetMonitor(every time.Duration, read func() (gateway, bool), identity func(gateway, bool) string, cur gateway, up bool, now time.Time) *netMonitor {
	return &netMonitor{every: every, read: read, identity: identity, cur: cur, up: up, id: identity(cur, up), lastAt: now.Round(0)}
}

// step reads the route once and says what happened since the last step.
func (m *netMonitor) step(now time.Time) netEvents {
	now = now.Round(0)
	var ev netEvents
	if gap := now.Sub(m.lastAt); gap > m.every+wakeSlack {
		ev.slept = gap
	}
	m.lastAt = now
	g, up := m.read()
	if id := m.identity(g, up); id != m.id {
		ev.changed = true
		ev.prev, ev.prevUp = m.cur, m.up
		m.cur, m.up, m.id = g, up, id
	}
	ev.cur, ev.up = m.cur, m.up
	return ev
}

// run steps every interval until ctx ends, handing each step's events on.
func (m *netMonitor) run(ctx context.Context, handle func(netEvents)) {
	t := time.NewTicker(m.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			handle(m.step(time.Now()))
		}
	}
}
