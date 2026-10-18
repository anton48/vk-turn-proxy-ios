package main

// A pin whose route went away with its interface is made again, never
// «re-pointed». Sabotage seen red: no query before route change (on macOS
// the change, answered 0, re-points the covering route — the default, or
// the half of the address space that is in the tunnel); the query's answer
// ignored; FreeBSD's «route has not been found» from the change not
// followed by a remake; a remake that failed still counted as a pin; the
// parser blind to the HOST flag, to a /32 mask, to the destination; macOS's
// «not in table» not read as not found.

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func bsdPinner(t *testing.T, cmds netCmds, freebsd bool) (*pinner, *fakeRun, *journal) {
	t.Helper()
	p, f, j := testPinner(t)
	p.cmds = cmds
	f.freebsd = freebsd
	return p, f, j
}

func TestAPinThatVanishedWithItsInterfaceIsMadeAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmds    netCmds
		freebsd bool
	}{
		{"macOS", darwinCmds{}, false},
		{"FreeBSD", freebsdCmds{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, f, j := bsdPinner(t, tc.cmds, tc.freebsd)
			if err := p.ensure("203.0.113.50"); err != nil {
				t.Fatal(err)
			}
			f.vanish("203.0.113.50") // the old interface went, and its routes with it
			gw2 := gateway{IP: "172.20.10.1", Iface: "en5"}
			_, lte, _ := net.ParseCIDR("172.20.10.2/28")
			p.setGateway(gw2, true, []*net.IPNet{lte})
			if f.coverChanged != 0 {
				t.Fatalf("route change ran on a /32 that was gone: the covering route was re-pointed %d time(s)", f.coverChanged)
			}
			if via, ok := f.via("203.0.113.50"); !ok || via != "172.20.10.1" {
				t.Fatalf("the vanished pin in the table: %q, %v — want it made again via the new gateway", via, ok)
			}
			if p.pinned["203.0.113.50"] != gw2 || !j.has(pinKey("203.0.113.50")) {
				t.Fatalf("pinned %v, journaled %v — want via %v, journaled", p.pinned["203.0.113.50"], j.has(pinKey("203.0.113.50")), gw2)
			}
			before := len(f.list())
			if err := p.ensure("203.0.113.50"); err != nil || len(f.list()) != before {
				t.Fatalf("an ask after the remake ran %q (%v) — want nothing", f.list()[before:], err)
			}
		})
	}
}

// A route present at the query and gone at the change (FreeBSD answers «not
// found»): made again too.
func TestAPinGoneBetweenTheQueryAndTheChangeIsMadeAgain(t *testing.T) {
	p, f, _ := bsdPinner(t, freebsdCmds{}, true)
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	gw2 := gateway{IP: "172.20.10.1", Iface: "en5"}
	p.run = func(argv []string) (string, error) {
		if len(argv) > 3 && argv[3] == "change" {
			f.vanish("203.0.113.50") // gone right before the change reaches the kernel
		}
		return f.run(argv)
	}
	p.setGateway(gw2, true, nil)
	if via, ok := f.via("203.0.113.50"); !ok || via != "172.20.10.1" {
		t.Fatalf("the pin in the table: %q, %v — want it made again via the new gateway", via, ok)
	}
}

// A remake that failed is no pin: not counted, not journaled, made at the
// next ask.
func TestARemakeThatFailedIsTriedAgain(t *testing.T) {
	p, f, j := bsdPinner(t, darwinCmds{}, false)
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	f.vanish("203.0.113.50")
	f.mu.Lock()
	f.fail["203.0.113.50"] = 1 // the new network's first add fails
	f.mu.Unlock()
	p.setGateway(gateway{IP: "172.20.10.1", Iface: "en5"}, true, nil)
	if p.count() != 0 || j.has(pinKey("203.0.113.50")) {
		t.Fatalf("a remake that failed: pins %d, journaled %v — want 0, false", p.count(), j.has(pinKey("203.0.113.50")))
	}
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatalf("the next ask: %v", err)
	}
	if via, ok := f.via("203.0.113.50"); !ok || via != "172.20.10.1" || f.coverChanged != 0 {
		t.Fatalf("after the next ask: %q %v, covers changed %d", via, ok, f.coverChanged)
	}
}

// Linux re-points with `ip route replace`, which makes a route that is gone:
// no query.
func TestLinuxRePointsWithoutAQuery(t *testing.T) {
	p, f, _ := testPinner(t)
	p.cmds = linuxCmds{}
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	p.setGateway(gateway{IP: "172.20.10.1", Iface: "eth1"}, true, nil)
	got := strings.Join(f.list(), "\n")
	if strings.Contains(got, " get ") || !strings.Contains(got, "ip -4 route replace 203.0.113.50/32 via 172.20.10.1 dev eth1") {
		t.Fatalf("Linux's re-point:\n%s", got)
	}
}

// The parser on what route(8) printed on the stands (2026-10-18).
func TestOwnHostRouteIsReadOffRouteGet(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      bool
	}{
		{"FreeBSD, the host's own route (HOST flag, no mask line)", "   route to: 203.0.113.77\ndestination: 203.0.113.77\n  interface: lo0\n      flags: <UP,HOST,DONE,STATIC>\n", true},
		{"macOS, the host's own route (a /32 mask, no HOST flag)", "   route to: 203.0.113.77\ndestination: 203.0.113.77\n       mask: 255.255.255.255\n  interface: lo0\n      flags: <UP,DONE,STATIC,PRCLONING>\n", true},
		{"FreeBSD, gone: the default answers", "   route to: 203.0.113.77\ndestination: 0.0.0.0\n       mask: 0.0.0.0\n      flags: <UP,GATEWAY,DONE,STATIC>\n", false},
		{"macOS, gone: the default answers", "   route to: 203.0.113.77\ndestination: default\n       mask: default\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n", false},
		{"a covering network", "   route to: 203.0.113.77\ndestination: 203.0.113.0\n       mask: 255.255.255.0\n      flags: <UP,DONE,STATIC>\n", false},
		{"another host's /32 (never ours)", "destination: 203.0.113.78\n       mask: 255.255.255.255\n      flags: <UP,HOST,DONE,STATIC>\n", false},
		{"nothing", "", false},
	} {
		if got := isOwnHostRoute(tc.out, "203.0.113.77"); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("route -q -n change -inet 203.0.113.77/32 192.0.2.1: exit status 1: route: route has not been found"), true},
		{errors.New("route -q -n delete -inet 203.0.113.77/32: exit status 1: route: writing to routing socket: not in table"), true},
		{errors.New("route -q -n change -inet 203.0.113.77/32 192.0.2.1: exit status 1: Network is unreachable"), false},
		{nil, false},
	} {
		if got := routeNotFound(tc.err); got != tc.want {
			t.Errorf("routeNotFound(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
