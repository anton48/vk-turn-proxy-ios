// SPDX-License-Identifier: MIT

package main

// The process's own DNS — the proxy's lookups of VK's API and captcha hosts —
// goes to the NETWORK's DNS servers, read before the console points the
// system at the tunnel's, and pinned around the tunnel like any other
// destination of the proxy. A tunnel whose sessions are dead must still be
// able to resolve VK to mint its way back after a network change.
//
// Go's own resolver (PreferGo) with a Dial of ours: the query goes to the
// network's servers in turn; with none known it goes where the system's
// configuration says — through the tunnel while it works.

import (
	"context"
	"net"
	"sync"
)

type dnsSource struct {
	mu      sync.Mutex
	servers []string
	next    int
}

func (d *dnsSource) set(servers []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.servers = append([]string(nil), servers...)
	d.next = 0
}

func (d *dnsSource) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.servers...)
}

// pick returns the next server in turn: Go asks again, server by server, on
// a timeout, and each ask lands on the next one.
func (d *dnsSource) pick() (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.servers) == 0 {
		return "", false
	}
	s := d.servers[d.next%len(d.servers)]
	d.next++
	return s, true
}

// resolverDial is net.Resolver.Dial: the network's server in turn (pinned
// first), or the address the system configuration named.
func resolverDial(src *dnsSource, pin func(ip string) error) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		if s, ok := src.pick(); ok {
			_ = pin(s) // a failed pin is logged by the pinner; the query tries anyway
			return d.DialContext(ctx, network, net.JoinHostPort(s, "53"))
		}
		return d.DialContext(ctx, network, address)
	}
}

// installResolver makes every lookup of the process use resolverDial.
func installResolver(src *dnsSource, pin func(ip string) error) {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = resolverDial(src, pin)
}
