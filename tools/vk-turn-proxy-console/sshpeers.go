// SPDX-License-Identifier: MIT

package main

// The SSH sessions this host serves are pinned around the tunnel: with the
// default route in the tunnel, a reply to an SSH client would leave through
// WireGuard with the host's physical address as its source, and the server's
// WireGuard drops a packet whose source is not the peer's tunnel address —
// the session hangs, and a remote machine is lost until someone reaches it
// another way. $SSH_CLIENT alone is not enough: sudo resets the environment
// (env_reset) and drops it. So the peers of the ESTABLISHED connections to
// the local port 22 are read from the OS's socket table as well — every
// session, the one that started the console and any other.

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const sshPort = "22"

// procNetTCP are the socket tables Linux keeps: a dual-stack listener (a
// systemd socket bound to [::]:22 with IPv6-only off) shows an IPv4 client in
// the IPv6 one, as ::ffff:a.b.c.d.
var procNetTCP = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// procPeers reads every table in procNetTCP; a missing one (no IPv6) is skipped.
func procPeers(read func(string) ([]byte, error)) []string {
	var out []string
	for _, path := range procNetTCP {
		b, err := read(path)
		if err != nil {
			continue
		}
		for _, ip := range parseProcNetTCP(string(b)) {
			out = appendUnique(out, ip)
		}
	}
	return out
}

// parseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 (Linux): the remote
// address of every ESTABLISHED (state 01) connection whose local port is 22.
// The addresses are hex, every 32-bit word in the kernel's (little-endian)
// byte order — an IPv4 in 8 digits, an IPv6 in 32.
//
//	sl  local_address rem_address   st ...
//	 0: 0501A8C0:0016 0900A8C0:D431 01 ...
func parseProcNetTCP(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "01" {
			continue
		}
		_, lport, ok1 := strings.Cut(f[1], ":")
		rip, _, ok2 := strings.Cut(f[2], ":")
		if !ok1 || !ok2 || !strings.EqualFold(lport, "0016") {
			continue
		}
		if ip := procAddr(rip); ip != nil {
			out = appendUnique(out, ip.String())
		}
	}
	return out
}

// procAddr decodes one of /proc's hex addresses: each 32-bit word's bytes
// reversed.
func procAddr(h string) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != net.IPv4len && len(b) != net.IPv6len) {
		return nil
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return peerIP(net.IP(b))
}

// sockstatArgs: both families (FreeBSD).
var sockstatArgs = []string{"sockstat", "-4", "-6", "-c"}

// parseSockstat reads `sockstat -4 -6 -c` (FreeBSD); an IPv6 address is
// written without brackets, the port after its last colon:
//
//	USER COMMAND PID FD PROTO LOCAL ADDRESS  FOREIGN ADDRESS
//	root sshd    812 4  tcp4  192.0.2.5:22   203.0.113.9:51234
//	root sshd    815 5  tcp6  2001:db8::5:22 2001:db8::9:51234
func parseSockstat(out string) []string {
	var peers []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || !strings.HasPrefix(f[4], "tcp") {
			continue
		}
		_, lport, ok1 := cutPort(f[5], ":")
		rhost, _, ok2 := cutPort(f[6], ":")
		if !ok1 || !ok2 || lport != sshPort {
			continue
		}
		if ip := parsePeer(rhost); ip != nil {
			peers = appendUnique(peers, ip.String())
		}
	}
	return peers
}

// netstatArgs: -W, or a long IPv6 address is cut to fit its column (macOS).
var netstatArgs = []string{"netstat", "-W", "-anp", "tcp"}

// parseNetstatDarwin reads `netstat -W -anp tcp` (macOS): every address ends
// in ".port".
//
//	tcp4  0  0  192.168.1.5.22  203.0.113.9.51234  ESTABLISHED
//	tcp6  0  0  2001:db8::5.22  2001:db8::9.51234  ESTABLISHED
func parseNetstatDarwin(out string) []string {
	var peers []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[5] != "ESTABLISHED" {
			continue
		}
		_, lport, ok1 := cutPort(f[3], ".")
		rhost, _, ok2 := cutPort(f[4], ".")
		if !ok1 || !ok2 || lport != sshPort {
			continue
		}
		if ip := parsePeer(rhost); ip != nil {
			peers = appendUnique(peers, ip.String())
		}
	}
	return peers
}

// cutPort splits "host<sep>port" at the LAST sep (an IPv6 host has colons of
// its own); brackets around the host are dropped.
func cutPort(s, sep string) (host, port string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]"), s[i+1:], true
}

// parsePeer reads a peer's address; a zone ("%em0") is dropped, a wildcard is
// no peer.
func parsePeer(s string) net.IP {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return peerIP(net.ParseIP(s))
}

// peerIP: nil for no address or a wildcard. An IPv4-mapped IPv6 (a
// dual-stack socket's IPv4 client) prints as the IPv4 it is — net.IP's
// String does that — and byFamily counts it as one: it is pinned like any
// other client.
func peerIP(ip net.IP) net.IP {
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}

// byFamily splits the peers: the IPv4 ones are pinned around the tunnel; the
// IPv6 ones go around it anyway — unless -block-ipv6 sends IPv6 into it.
func byFamily(peers []string) (v4, v6 []string) {
	for _, p := range peers {
		ip := net.ParseIP(p)
		switch {
		case ip == nil:
		case ip.To4() != nil:
			v4 = append(v4, ip.To4().String())
		default:
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// v6BlockRefusal: why -block-ipv6 must not start, or "". The block routes
// ::/1 and 8000::/1 into the tunnel, which carries IPv4 only — the reply to an
// SSH client connected over IPv6 goes in and is dropped, and a remote machine
// is lost until someone reaches it another way. A client on one of this
// host's own IPv6 networks (a link-local one too) is reached by its more
// specific on-link route and keeps its session. There is no IPv6 pin: the
// console has no IPv6 gateway to pin through — so it refuses, before any
// change, and says what to do.
func v6BlockRefusal(blockIPv6, defaultRoute bool, peers []string, onlink []*net.IPNet) string {
	if !blockIPv6 || !defaultRoute {
		return ""
	}
	_, v6 := byFamily(peers)
	var cut []string
	for _, p := range v6 {
		ip := net.ParseIP(p)
		if ip.IsLinkLocalUnicast() || inAny(ip, onlink) {
			continue
		}
		cut = append(cut, p)
	}
	if len(cut) == 0 {
		return ""
	}
	return fmt.Sprintf("-block-ipv6: %d SSH session(s) to this host run over IPv6 (%s), and the block would cut them — their replies would go into the tunnel, which carries IPv4 only; connect over IPv4, or run without -block-ipv6",
		len(cut), strings.Join(cut, ", "))
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
