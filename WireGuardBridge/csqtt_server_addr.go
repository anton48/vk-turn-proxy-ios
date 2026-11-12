package main

// What the csqtt server's name became.
//
// A csqtt profile names its server by a name or by an address, and the bridge
// resolves it ONCE, at the tunnel's start, on the network the phone is on at
// that moment. Everything a stream sends through its relay goes to that one
// address — and a relay grants a permission for ANY address. So a name that
// became the wrong one (a router's local override, a filtering resolver that
// answers with a zero or a private address, a stale record) reads in a log
// exactly like a server that is down, or like a path that drops the data: the
// relay accepts the allocation and nothing answers. The log could not tell
// these apart, because it said the name and never the address.
//
// So the start says it:
//
//   - the address the name became, and how long the lookup took — the lookup
//     stands between the start and the first relay lease, so a slow resolver
//     is a slow start;
//   - for a server given by address, that there was nothing to resolve;
//   - and, either way, when the address is of a kind no relay on the internet
//     can deliver to — then the silence that follows needs no other cause.
//
// The address is the user's own server's, in the user's own log, beside the
// relays' addresses and the server's name that the log has always held.

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// csqttResolveUDP is net.ResolveUDPAddr — a variable so that a test answers
// for the resolver.
var csqttResolveUDP = net.ResolveUDPAddr

// csqttCarrierNAT is the shared address space of carrier-grade NAT (RFC 6598),
// which net.IP.IsPrivate does not count.
var csqttCarrierNAT = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// csqttResolveServer resolves tunnel id's csqtt server — to an IPv4 address,
// what a relay's peer is — and says what it became. A lookup that fails is
// the caller's to report: nothing is said here.
func csqttResolveServer(id int32, server string) (*net.UDPAddr, error) {
	began := time.Now()
	addr, err := csqttResolveUDP("udp4", server)
	if err != nil {
		return nil, err
	}
	log.Print(csqttServerAddrLine(id, server, addr, time.Since(began)))
	return addr, nil
}

// csqttServerAddrLine is the start's word on the server's address: what the
// configured name became and in what time (to the millisecond), or that the
// server was given by address; and the address's kind when it is not a public
// one.
func csqttServerAddrLine(id int32, server string, addr *net.UDPAddr, took time.Duration) string {
	host, _, _ := net.SplitHostPort(server)
	if host == "" {
		host = server // no port in it: the whole of it is the name
	}
	var b strings.Builder
	fmt.Fprintf(&b, "csqttStart: tunnel %d: ", id)
	if net.ParseIP(host) != nil {
		fmt.Fprintf(&b, "the server is given by address %s — nothing to resolve", addr)
	} else {
		fmt.Fprintf(&b, "the server's name %s resolved to %s in %v", host, addr, took.Round(time.Millisecond))
	}
	if kind := csqttNotPublic(addr.IP); kind != "" {
		fmt.Fprintf(&b, " — %s, not a public one: a relay on the internet cannot deliver to it, so the server will not answer", kind)
	}
	return b.String()
}

// csqttNotPublic names the kind of an address that a relay on the internet
// cannot deliver to, and is empty for a public address.
func csqttNotPublic(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "the UNSPECIFIED address"
	case ip.IsLoopback():
		return "a LOOPBACK address"
	case ip.IsPrivate():
		return "a PRIVATE address"
	case ip.IsLinkLocalUnicast():
		return "a LINK-LOCAL address"
	case csqttCarrierNAT.Contains(ip):
		return "a CARRIER-NAT address"
	}
	return ""
}
