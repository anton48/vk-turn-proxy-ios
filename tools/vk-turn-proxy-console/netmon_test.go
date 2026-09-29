package main

// The network monitor. Sabotage seen red: a change of the interface's address
// alone not seen; the network's loss not seen; a late tick by the wall clock
// not read as a wake; an on-time tick read as one.

import (
	"testing"
	"time"
)

func TestTheMonitorSeesChangesAndWakes(t *testing.T) {
	route := gateway{IP: "192.168.1.1", Iface: "en0"}
	up := true
	addr := "192.168.1.5/24"
	identity := func(g gateway, up bool) string {
		if !up {
			return "down"
		}
		return g.String() + " " + addr
	}
	t0 := time.Date(2026, 9, 29, 22, 0, 0, 0, time.UTC)
	m := newNetMonitor(2*time.Second, func() (gateway, bool) { return route, up }, identity, route, true, t0)

	if ev := m.step(t0.Add(2 * time.Second)); ev.changed || ev.slept != 0 {
		t.Fatalf("a quiet tick: %+v", ev)
	}
	addr = "192.168.1.77/24" // the same router address on another Wi-Fi
	if ev := m.step(t0.Add(4 * time.Second)); !ev.changed || !ev.up {
		t.Fatalf("another network behind the same router address: %+v", ev)
	}
	up = false
	if ev := m.step(t0.Add(6 * time.Second)); !ev.changed || ev.up || !ev.prevUp {
		t.Fatalf("the network gone: %+v", ev)
	}
	up, route = true, gateway{IP: "172.20.10.1", Iface: "en5"}
	ev := m.step(t0.Add(6*time.Second + 5*time.Minute)) // the lid was closed
	if ev.slept < 5*time.Minute || !ev.changed || ev.cur.Iface != "en5" || ev.prevUp {
		t.Fatalf("a wake on another network: %+v", ev)
	}
	if ev := m.step(t0.Add(6*time.Second + 5*time.Minute + 2*time.Second)); ev.slept != 0 || ev.changed {
		t.Fatalf("the tick after: %+v", ev)
	}
}
