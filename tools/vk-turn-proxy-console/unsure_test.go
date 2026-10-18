package main

// A check that FAILED is not «the route is gone» (the user's remark of
// 2026-10-18, on 1eed858). Sabotage seen red: a failed `route get` read as
// gone (the remake met «File exists» and our own route became foreign, its
// undo dropped — never re-pointed again, left behind at the stop); a failed
// query at a re-point remade the pin likewise; Linux's failed replace dropped
// the pin, and the next ask's add made it foreign; «File exists» for an
// address whose undo is ours taken for a foreign route; a pin whose check
// failed never checked again.

import (
	"strings"
	"testing"
)

func noAddAfter(t *testing.T, f *fakeRun, from int, host string) {
	t.Helper()
	for _, c := range f.list()[from:] {
		if strings.Contains(c, " add ") && strings.Contains(c, host+"/32") {
			t.Fatalf("a pin of ours made again although its route is there: %q", c)
		}
	}
}

func countCmds(f *fakeRun, from int, verb, host string) int {
	n := 0
	for _, c := range f.list()[from:] {
		if strings.Contains(c, verb) && strings.Contains(c, host) {
			n++
		}
	}
	return n
}

func TestAFailedRecheckKeepsThePinOurs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmds    netCmds
		freebsd bool
	}{
		{"macOS", darwinCmds{}, false},
		{"FreeBSD", freebsdCmds{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const host = "203.0.113.50"
			p, f, j := bsdPinner(t, tc.cmds, tc.freebsd)
			gw := p.gw
			if err := p.ensure(host); err != nil {
				t.Fatal(err)
			}
			from := len(f.list())
			p.setGateway(gateway{}, false, nil) // a short break: the route survives it
			f.mu.Lock()
			f.failQ[host] = 1 // and the check after it fails
			f.mu.Unlock()
			p.setGateway(gw, true, nil)
			noAddAfter(t, f, from, host)
			if _, ours := p.pinned[host]; !ours || p.foreign[host] || !j.has(pinKey(host)) {
				t.Fatalf("after a failed check: ours %v, foreign %v, undo journaled %v — want ours, not foreign, journaled", ours, p.foreign[host], j.has(pinKey(host)))
			}
			if err := p.ensure(host); err != nil { // checked again, the table answers now
				t.Fatal(err)
			}
			noAddAfter(t, f, from, host)
			if n := countCmds(f, from, " get ", host); n < 2 {
				t.Fatalf("the table asked %d time(s) about the pin — want the failed check repeated at the next ask", n)
			}
			// Still ours in every way that matters: re-pointed at the next
			// gateway, taken back at the stop.
			gw2 := gateway{IP: "172.20.10.1", Iface: "en5"}
			p.setGateway(gw2, true, nil)
			if via, _ := f.via(host); via != "172.20.10.1" {
				t.Fatalf("the pin via %q after a gateway change — want re-pointed", via)
			}
			p.removeAll()
			if _, there := f.via(host); there {
				t.Fatal("the pin is left behind at the stop")
			}
		})
	}
}

func TestLinuxsFailedReplaceKeepsThePinOurs(t *testing.T) {
	const host = "203.0.113.50"
	p, f, j := testPinner(t)
	p.cmds = linuxCmds{}
	gw := p.gw
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.exists[host] = true // the route is in the table: a later add would get «File exists»
	f.fail[host] = 1      // the replace after the break fails once
	f.mu.Unlock()
	from := len(f.list())
	p.setGateway(gateway{}, false, nil)
	p.setGateway(gw, true, nil)
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	noAddAfter(t, f, from, host)
	if n := countCmds(f, from, " replace ", host); n < 2 {
		t.Fatalf("%d replace(s) — want the failed one repeated at the next ask", n)
	}
	if _, ours := p.pinned[host]; !ours || p.foreign[host] || !j.has(pinKey(host)) {
		t.Fatalf("after a failed replace: ours %v, foreign %v, journaled %v", ours, p.foreign[host], j.has(pinKey(host)))
	}
	p.removeAll()
	if !strings.Contains(strings.Join(f.list(), "\n"), "ip -4 route del "+host+"/32") {
		t.Fatal("the pin is not taken back at the stop")
	}
}

func TestAFailedQueryAtARePointDoesNotRemake(t *testing.T) {
	const host = "203.0.113.50"
	p, f, j := bsdPinner(t, freebsdCmds{}, true)
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	from := len(f.list())
	f.mu.Lock()
	f.failQ[host] = 1
	f.mu.Unlock()
	gw2 := gateway{IP: "172.20.10.1", Iface: "en5"}
	p.setGateway(gw2, true, nil) // a new network, and the query fails
	noAddAfter(t, f, from, host)
	if _, ours := p.pinned[host]; !ours || p.foreign[host] || !j.has(pinKey(host)) {
		t.Fatalf("after a failed query at a re-point: ours %v, foreign %v, journaled %v", ours, p.foreign[host], j.has(pinKey(host)))
	}
	if err := p.ensure(host); err != nil { // the next ask re-points it
		t.Fatal(err)
	}
	if via, _ := f.via(host); via != "172.20.10.1" {
		t.Fatalf("the pin via %q — want re-pointed at the next ask", via)
	}
}

func TestFileExistsForAnAddressWhoseUndoIsOursKeepsItOurs(t *testing.T) {
	const host = "203.0.113.50"
	p, f, j := bsdPinner(t, darwinCmds{}, false)
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	delete(p.pinned, host) // the pinner lost track; the route and its undo are there
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	if p.foreign[host] || !j.has(pinKey(host)) {
		t.Fatalf("«File exists» for our own journaled pin: foreign %v, journaled %v — want ours", p.foreign[host], j.has(pinKey(host)))
	}
	p.removeAll()
	if _, there := f.via(host); there {
		t.Fatal("the pin is left behind at the stop")
	}
}
