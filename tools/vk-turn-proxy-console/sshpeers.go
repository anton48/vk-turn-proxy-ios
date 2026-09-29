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
	"net"
	"strings"
)

const sshPort = "22"

// parseProcNetTCP reads /proc/net/tcp (Linux): the remote IPv4 of every
// ESTABLISHED (state 01) connection whose local port is 22. The addresses are
// hex, the IPv4 in the kernel's (little-endian) byte order.
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
		lip, lport, ok1 := strings.Cut(f[1], ":")
		rip, _, ok2 := strings.Cut(f[2], ":")
		if !ok1 || !ok2 || !strings.EqualFold(lport, "0016") || len(lip) != 8 {
			continue
		}
		b, err := hex.DecodeString(rip)
		if err != nil || len(b) != 4 {
			continue
		}
		out = appendUnique(out, net.IPv4(b[3], b[2], b[1], b[0]).String())
	}
	return out
}

// parseSockstat reads `sockstat -4 -c` (FreeBSD):
//
//	USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
//	root sshd    812 4  tcp4  192.0.2.5:22  203.0.113.9:51234
func parseSockstat(out string) []string {
	var peers []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || !strings.HasPrefix(f[4], "tcp") {
			continue
		}
		_, lport, err1 := net.SplitHostPort(f[5])
		rhost, _, err2 := net.SplitHostPort(f[6])
		if err1 != nil || err2 != nil || lport != sshPort {
			continue
		}
		if ip := net.ParseIP(rhost); ip != nil && ip.To4() != nil {
			peers = appendUnique(peers, ip.String())
		}
	}
	return peers
}

// parseNetstatDarwin reads `netstat -anp tcp` (macOS): addresses end in
// ".port".
//
//	tcp4  0  0  192.168.1.5.22  203.0.113.9.51234  ESTABLISHED
func parseNetstatDarwin(out string) []string {
	var peers []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != "tcp4" || f[5] != "ESTABLISHED" {
			continue
		}
		li, ri := strings.LastIndex(f[3], "."), strings.LastIndex(f[4], ".")
		if li < 0 || ri < 0 || f[3][li+1:] != sshPort {
			continue
		}
		if ip := net.ParseIP(f[4][:ri]); ip != nil && ip.To4() != nil {
			peers = appendUnique(peers, ip.String())
		}
	}
	return peers
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
