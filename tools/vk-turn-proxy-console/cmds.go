// SPDX-License-Identifier: MIT

package main

// The commands the console gives the OS, as pure builders — one set per
// family, all compiled on every OS so that the tests on one machine read all
// three. Each change comes with the command that undoes it; the undo goes to
// the state file BEFORE the change is made (state.go), so a crash leaves
// nothing a later start cannot take back.
//
// The routing shape is wg-quick's, on every OS:
//   - the default route is NOT touched: two halves, 0.0.0.0/1 and 128.0.0.0/1,
//     go to the tunnel and win over the default by their longer prefix. On exit
//     (or when the interface goes) the halves go and the default was never
//     changed — tools/native_client's `route change default` left a FreeBSD
//     stand without one when it died (2026-09-29).
//   - the proxy's own destinations (the relays, VK's hosts, the network's DNS),
//     the SSH client and -keep-hosts are PINNED: a /32 via the physical
//     gateway, made at dial time (pins.go).

import (
	"fmt"
	"net"
)

// gateway is the physical default route: a next hop, or (point-to-point
// links) the interface alone.
type gateway struct {
	IP    string // "" when the route names only an interface
	Iface string
}

func (g gateway) String() string {
	if g.IP == "" {
		return "dev " + g.Iface
	}
	return g.IP + " dev " + g.Iface
}

// routeChange is one route with its undo, keyed by what it routes.
type routeChange struct {
	key      string
	add, del []string
}

type netCmds interface {
	// addrUp gives the tunnel interface its address and MTU and brings it up.
	addrUp(ifname, cidr string, mtu int) [][]string
	// subnetRoute routes the tunnel's own subnet into it where the address
	// alone does not (utun is point-to-point); nil where it does.
	subnetRoute(ifname, cidr string) (add, del []string)
	// splitRoutes are the two halves of the address space into the tunnel.
	splitRoutes(ifname string) []routeChange
	// ipv6Block sends IPv6 into the tunnel, where WireGuard (allowed_ip
	// 0.0.0.0/0 only) drops it — -block-ipv6.
	ipv6Block(ifname string) []routeChange
	// viaTunnel routes one host into the tunnel (-route, in split mode).
	viaTunnel(ifname, ip string) (add, del []string)
	// pin routes one host via the physical gateway; repin points an existing
	// pin at a new one.
	pin(ip string, gw gateway) (add, del []string)
	repin(ip string, gw gateway) []string
	// destroy removes a tunnel interface that outlives its process (FreeBSD's
	// cloned tun); nil elsewhere.
	destroy(ifname string) []string
}

// bsdRoutes is the route(8) grammar darwin and FreeBSD share.
type bsdRoutes struct{}

func (bsdRoutes) splitRoutes(ifname string) []routeChange {
	var out []routeChange
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out = append(out, routeChange{key: half,
			add: []string{"route", "-q", "-n", "add", "-inet", half, "-interface", ifname},
			del: []string{"route", "-q", "-n", "delete", "-inet", half, "-interface", ifname}})
	}
	return out
}

func (bsdRoutes) ipv6Block(ifname string) []routeChange {
	var out []routeChange
	for _, half := range []string{"::/1", "8000::/1"} {
		out = append(out, routeChange{key: half,
			add: []string{"route", "-q", "-n", "add", "-inet6", half, "-interface", ifname},
			del: []string{"route", "-q", "-n", "delete", "-inet6", half, "-interface", ifname}})
	}
	return out
}

func (bsdRoutes) viaTunnel(ifname, ip string) (add, del []string) {
	return []string{"route", "-q", "-n", "add", "-inet", ip + "/32", "-interface", ifname},
		[]string{"route", "-q", "-n", "delete", "-inet", ip + "/32", "-interface", ifname}
}

func bsdHop(gw gateway) []string {
	if gw.IP == "" {
		return []string{"-interface", gw.Iface}
	}
	return []string{gw.IP}
}

func (bsdRoutes) pin(ip string, gw gateway) (add, del []string) {
	return append([]string{"route", "-q", "-n", "add", "-inet", ip + "/32"}, bsdHop(gw)...),
		[]string{"route", "-q", "-n", "delete", "-inet", ip + "/32"}
}

func (bsdRoutes) repin(ip string, gw gateway) []string {
	return append([]string{"route", "-q", "-n", "change", "-inet", ip + "/32"}, bsdHop(gw)...)
}

type darwinCmds struct{ bsdRoutes }

// addrUp is wg-quick's darwin form: utun is point-to-point, so the address is
// its own destination and the subnet is routed separately (subnetRoute).
func (darwinCmds) addrUp(ifname, cidr string, mtu int) [][]string {
	ip, _, _ := net.ParseCIDR(cidr)
	return [][]string{
		{"ifconfig", ifname, "inet", cidr, ip.String(), "alias"},
		{"ifconfig", ifname, "mtu", fmt.Sprint(mtu), "up"},
	}
}

func (darwinCmds) subnetRoute(ifname, cidr string) (add, del []string) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil
	}
	return []string{"route", "-q", "-n", "add", "-inet", n.String(), "-interface", ifname},
		[]string{"route", "-q", "-n", "delete", "-inet", n.String(), "-interface", ifname}
}

func (darwinCmds) destroy(string) []string { return nil } // utun goes with its descriptor

type freebsdCmds struct{ bsdRoutes }

// addrUp: wireguard-go's tun on FreeBSD is a BROADCAST-type interface, not
// point-to-point — the "inet a b" peer form is silently ignored and nothing
// routes to the gateway; the address with its prefix puts the server's
// WireGuard subnet on-link (tools/native_client's finding, 2026-09-04).
func (freebsdCmds) addrUp(ifname, cidr string, mtu int) [][]string {
	return [][]string{{"ifconfig", ifname, "inet", cidr, "mtu", fmt.Sprint(mtu), "up"}}
}

func (freebsdCmds) subnetRoute(string, string) (add, del []string) { return nil, nil }

// destroy: a cloned tun OUTLIVES the process that made it (seen on the stand,
// 2026-09-29: vktp0 still there after native_client died) — and wireguard-go
// refuses to create an interface whose name exists.
func (freebsdCmds) destroy(ifname string) []string { return []string{"ifconfig", ifname, "destroy"} }

type linuxCmds struct{}

func (linuxCmds) addrUp(ifname, cidr string, mtu int) [][]string {
	return [][]string{
		{"ip", "-4", "address", "add", cidr, "dev", ifname},
		{"ip", "link", "set", "dev", ifname, "mtu", fmt.Sprint(mtu), "up"},
	}
}

func (linuxCmds) subnetRoute(string, string) (add, del []string) { return nil, nil }

func (linuxCmds) splitRoutes(ifname string) []routeChange {
	var out []routeChange
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out = append(out, routeChange{key: half,
			add: []string{"ip", "-4", "route", "add", half, "dev", ifname},
			del: []string{"ip", "-4", "route", "del", half, "dev", ifname}})
	}
	return out
}

func (linuxCmds) ipv6Block(ifname string) []routeChange {
	var out []routeChange
	for _, half := range []string{"::/1", "8000::/1"} {
		out = append(out, routeChange{key: half,
			add: []string{"ip", "-6", "route", "add", half, "dev", ifname},
			del: []string{"ip", "-6", "route", "del", half, "dev", ifname}})
	}
	return out
}

func (linuxCmds) viaTunnel(ifname, ip string) (add, del []string) {
	return []string{"ip", "-4", "route", "add", ip + "/32", "dev", ifname},
		[]string{"ip", "-4", "route", "del", ip + "/32", "dev", ifname}
}

func linuxHop(gw gateway) []string {
	if gw.IP == "" {
		return []string{"dev", gw.Iface}
	}
	return []string{"via", gw.IP, "dev", gw.Iface}
}

func (linuxCmds) pin(ip string, gw gateway) (add, del []string) {
	return append([]string{"ip", "-4", "route", "add", ip + "/32"}, linuxHop(gw)...),
		[]string{"ip", "-4", "route", "del", ip + "/32"}
}

func (linuxCmds) repin(ip string, gw gateway) []string {
	return append([]string{"ip", "-4", "route", "replace", ip + "/32"}, linuxHop(gw)...)
}

func (linuxCmds) destroy(string) []string { return nil } // a tun without TUNSETPERSIST goes with its descriptor
