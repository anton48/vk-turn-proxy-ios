// SPDX-License-Identifier: MIT

package main

// Which DNS servers the proxy's own resolver asks, and which the system is
// pointed at, when the network's servers and the tunnel's overlap.
//
// The proxy resolves VK through the NETWORK's servers, pinned around the
// tunnel, so that a tunnel whose sessions are dead can still mint its way
// back. The tunnel's servers are never pinned: a pin would take everyone's
// DNS around the tunnel. A server that is BOTH (the network hands out
// 1.1.1.1 and the profile names it too) is the crossing: unpinned, the
// proxy's queries to it went into the tunnel once the default route did —
// recovery depended on the tunnel it was to recover. The rule:
//
//  1. the proxy asks the network's servers that are not the tunnel's;
//  2. with none left, it asks the shared ones, pinned — and the system is
//     pointed at the tunnel's OTHER servers, so nothing of it goes around;
//  3. with no other tunnel server either, the shared ones are pinned all the
//     same and that is said: the system's queries to them go around the
//     tunnel too (the recovery's price, chosen by the user, 2026-10-18).

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type dnsSplit struct {
	proxy  []string // the proxy's resolver asks these, in turn (none: the system's configuration)
	system []string // the system is pointed at these (nil: the system's DNS is not managed)
	never  []string // the tunnel's servers the pinner must not pin
	note   string   // said when the crossing changed the plain split
}

func crossDNS(network, tunnel []string) dnsSplit {
	if len(tunnel) == 0 {
		return dnsSplit{proxy: dedupe(network)}
	}
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	var other, shared, rest []string
	for _, s := range dedupe(network) {
		if in(tunnel, s) {
			shared = append(shared, s)
		} else {
			other = append(other, s)
		}
	}
	for _, s := range dedupe(tunnel) {
		if !in(shared, s) {
			rest = append(rest, s)
		}
	}
	switch {
	case len(other) > 0 || len(shared) == 0:
		sp := dnsSplit{proxy: other, system: dedupe(tunnel), never: dedupe(tunnel)}
		if len(shared) > 0 {
			sp.note = fmt.Sprintf("dns: %s is the network's and the tunnel's both — the proxy asks the network's others (%s)", strings.Join(shared, ", "), strings.Join(other, ", "))
		}
		return sp
	case len(rest) > 0:
		return dnsSplit{proxy: shared, system: rest, never: rest,
			note: fmt.Sprintf("dns: the network's only server(s) %s are the tunnel's too — the proxy asks them pinned around the tunnel, and the system is pointed at the tunnel's others (%s)", strings.Join(shared, ", "), strings.Join(rest, ", "))}
	default:
		return dnsSplit{proxy: shared, system: dedupe(tunnel),
			note: fmt.Sprintf("dns: the network's only server(s) %s are the tunnel's only ones too — pinned for the proxy's own lookups, so the system's queries to them go AROUND the tunnel (give -dns a server of the tunnel's own to keep them inside)", strings.Join(shared, ", "))}
	}
}

func dedupe(list []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range list {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tunnelDNS is the tunnel's servers the console points the system at — none
// when it leaves the system's DNS alone.
func (c *console) tunnelDNS() []string {
	if !c.dnsPlan.managed {
		return nil
	}
	return c.dnsPlan.servers
}

// applyDNSSplit takes the network's servers as they are now: the proxy's
// resolver, the pinner's never-set and — once the system's DNS is applied and
// the split asks for another list — the system's DNS follow.
func (c *console) applyDNSSplit(network []string) {
	sp := crossDNS(network, c.tunnelDNS())
	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()
	c.pin.setNever(sp.never)
	c.src.set(sp.proxy)
	if sp.note != c.dnsNote {
		if sp.note != "" {
			log.Print(sp.note)
		}
		c.dnsNote = sp.note
	}
	if local := localResolverNote(network, c.pin.on()); local != c.localNote {
		if local != "" {
			log.Print(local)
		}
		c.localNote = local
	}
	if c.dnsApplied && !sameList(sp.system, c.dnsSystem) {
		if err := c.dns.apply(c.tun, sp.system); err != nil {
			log.Printf("dns: %v", err)
			return
		}
		log.Printf("dns: the system pointed at %s now", strings.Join(sp.system, ", "))
		c.dnsSystem = sp.system
	}
}

// applySystemDNS points the system at the split's list (activate).
func (c *console) applySystemDNS() (string, error) {
	sp := crossDNS(c.dns.originals(), c.tunnelDNS())
	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()
	if err := c.dns.apply(c.tun, sp.system); err != nil {
		return "", err
	}
	c.dnsApplied, c.dnsSystem = true, sp.system
	return strings.Join(sp.system, ", "), nil
}

// localResolverNote: the network's DNS is a resolver on this machine itself
// (a cache or a recursor on a loopback address — local_unbound, dnsmasq).
// The console cannot keep ITS path around the tunnel: it may forward to
// servers the console does not know, or recurse to the root and every
// authority — none of it can be pinned. So it is said, in the default-route
// mode, once per change: with every session lost, the proxy's lookups of VK
// wait on the tunnel (or on what the cache still holds). A whole answer
// needs the lookups not to need DNS — VK's addresses resolved ahead (the
// app's pre-resolution, extended to the console) — the user's direction,
// 2026-10-18; not done here.
func localResolverNote(network []string, defaultRoute bool) string {
	if !defaultRoute {
		return ""
	}
	var local []string
	for _, s := range dedupe(network) {
		if ip := net.ParseIP(s); ip != nil && ip.IsLoopback() {
			local = append(local, s)
		}
	}
	if len(local) == 0 {
		return ""
	}
	return fmt.Sprintf("dns: the network's DNS is a resolver on this machine (%s) — its own queries leave by the default route, so with the default route in the tunnel the proxy's lookups of VK depend on the tunnel: should every session be lost, new credentials wait on it (or on what that resolver has cached)", strings.Join(local, ", "))
}
