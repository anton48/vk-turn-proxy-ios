package main

// The OS commands, all three families read on one machine. Sabotage seen red:
// the default route touched instead of the two halves; a pin without its /32;
// FreeBSD's address given the point-to-point form; FreeBSD's leftover
// interface not destroyed; a pin on a point-to-point default without
// -interface / dev.

import (
	"strings"
	"testing"
)

func joined(argv []string) string { return strings.Join(argv, " ") }

func changes(rs []routeChange) (add, del []string) {
	for _, r := range rs {
		add = append(add, r.key+": "+joined(r.add))
		del = append(del, r.key+": "+joined(r.del))
	}
	return add, del
}

func TestTheDefaultRouteIsNeverTouchedOnlyTheTwoHalves(t *testing.T) {
	for name, c := range map[string]netCmds{"darwin": darwinCmds{}, "freebsd": freebsdCmds{}, "linux": linuxCmds{}} {
		add, del := changes(c.splitRoutes("tun9"))
		all := strings.Join(append(add, del...), "\n")
		if strings.Contains(all, "default") || strings.Contains(all, "0.0.0.0/0") {
			t.Errorf("%s: the default route is touched:\n%s", name, all)
		}
		if len(add) != 2 || !strings.HasPrefix(add[0], "0.0.0.0/1: ") || !strings.HasPrefix(add[1], "128.0.0.0/1: ") {
			t.Errorf("%s: halves = %q", name, add)
		}
	}
	add, del := changes(darwinCmds{}.splitRoutes("utun7"))
	if add[0] != "0.0.0.0/1: route -q -n add -inet 0.0.0.0/1 -interface utun7" || del[1] != "128.0.0.0/1: route -q -n delete -inet 128.0.0.0/1 -interface utun7" {
		t.Errorf("darwin halves: %q / %q", add, del)
	}
	add, del = changes(linuxCmds{}.splitRoutes("vktp0"))
	if add[1] != "128.0.0.0/1: ip -4 route add 128.0.0.0/1 dev vktp0" || del[0] != "0.0.0.0/1: ip -4 route del 0.0.0.0/1 dev vktp0" {
		t.Errorf("linux halves: %q / %q", add, del)
	}
}

func TestAPinIsAHostRouteViaThePhysicalGateway(t *testing.T) {
	gw := gateway{IP: "192.168.1.1", Iface: "en0"}
	p2p := gateway{Iface: "ppp0"}
	for _, tc := range []struct {
		c                     netCmds
		gw                    gateway
		wantAdd, wantDel, rep string
	}{
		{darwinCmds{}, gw, "route -q -n add -inet 203.0.113.5/32 192.168.1.1", "route -q -n delete -inet 203.0.113.5/32", "route -q -n change -inet 203.0.113.5/32 192.168.1.1"},
		{freebsdCmds{}, p2p, "route -q -n add -inet 203.0.113.5/32 -interface ppp0", "route -q -n delete -inet 203.0.113.5/32", "route -q -n change -inet 203.0.113.5/32 -interface ppp0"},
		{linuxCmds{}, gw, "ip -4 route add 203.0.113.5/32 via 192.168.1.1 dev en0", "ip -4 route del 203.0.113.5/32", "ip -4 route replace 203.0.113.5/32 via 192.168.1.1 dev en0"},
		{linuxCmds{}, p2p, "ip -4 route add 203.0.113.5/32 dev ppp0", "ip -4 route del 203.0.113.5/32", "ip -4 route replace 203.0.113.5/32 dev ppp0"},
	} {
		add, del := tc.c.pin("203.0.113.5", tc.gw)
		if joined(add) != tc.wantAdd || joined(del) != tc.wantDel || joined(tc.c.repin("203.0.113.5", tc.gw)) != tc.rep {
			t.Errorf("%T via %v: add %q del %q repin %q", tc.c, tc.gw, joined(add), joined(del), joined(tc.c.repin("203.0.113.5", tc.gw)))
		}
	}
}

func TestTheTunnelAddressTakesEachSystemsForm(t *testing.T) {
	var got []string
	for _, c := range (darwinCmds{}).addrUp("utun7", "10.66.66.2/24", 1280) {
		got = append(got, joined(c))
	}
	if strings.Join(got, "; ") != "ifconfig utun7 inet 10.66.66.2/24 10.66.66.2 alias; ifconfig utun7 mtu 1280 up" {
		t.Errorf("darwin: %q", got)
	}
	add, del := (darwinCmds{}).subnetRoute("utun7", "10.66.66.2/24")
	if joined(add) != "route -q -n add -inet 10.66.66.0/24 -interface utun7" || joined(del) != "route -q -n delete -inet 10.66.66.0/24 -interface utun7" {
		t.Errorf("darwin subnet route: %q / %q", joined(add), joined(del))
	}
	// FreeBSD's tun is broadcast-type: the prefix puts the subnet on-link, and the
	// "inet a b" point-to-point form would be ignored.
	if got := (freebsdCmds{}).addrUp("vktp0", "10.66.66.2/24", 1280); len(got) != 1 || joined(got[0]) != "ifconfig vktp0 inet 10.66.66.2/24 mtu 1280 up" {
		t.Errorf("freebsd: %q", got)
	}
	got = nil
	for _, c := range (linuxCmds{}).addrUp("vktp0", "10.66.66.2/24", 1280) {
		got = append(got, joined(c))
	}
	if strings.Join(got, "; ") != "ip -4 address add 10.66.66.2/24 dev vktp0; ip link set dev vktp0 mtu 1280 up" {
		t.Errorf("linux: %q", got)
	}
	for _, c := range []netCmds{freebsdCmds{}, linuxCmds{}} {
		if add, _ := c.subnetRoute("vktp0", "10.66.66.2/24"); add != nil {
			t.Errorf("%T routes the subnet by hand: the address already does", c)
		}
	}
}

// FreeBSD's cloned tun outlives its process (the stand, 2026-09-29) — the
// console destroys it; on the others it goes with the descriptor.
func TestOnlyFreeBSDNeedsItsInterfaceDestroyed(t *testing.T) {
	if got := joined(freebsdCmds{}.destroy("vktp0")); got != "ifconfig vktp0 destroy" {
		t.Errorf("freebsd destroy = %q", got)
	}
	if (darwinCmds{}).destroy("utun7") != nil || (linuxCmds{}).destroy("vktp0") != nil {
		t.Error("an interface destroyed by hand on a system that removes it itself")
	}
}

func TestIPv6IsBlockedByTheTwoHalvesIntoTheTunnel(t *testing.T) {
	add, _ := changes(freebsdCmds{}.ipv6Block("vktp0"))
	if strings.Join(add, "; ") != "::/1: route -q -n add -inet6 ::/1 -interface vktp0; 8000::/1: route -q -n add -inet6 8000::/1 -interface vktp0" {
		t.Errorf("freebsd: %q", add)
	}
	add, del := changes(linuxCmds{}.ipv6Block("vktp0"))
	if add[0] != "::/1: ip -6 route add ::/1 dev vktp0" || del[1] != "8000::/1: ip -6 route del 8000::/1 dev vktp0" {
		t.Errorf("linux: %q / %q", add, del)
	}
}
