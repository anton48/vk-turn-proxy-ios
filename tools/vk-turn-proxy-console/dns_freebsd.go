// SPDX-License-Identifier: MIT

//go:build freebsd

package main

// FreeBSD: /etc/resolv.conf itself. resolvconf(8) is not used: on a host whose
// file is not managed by it, `resolvconf -d` would leave an EMPTY file behind.

func newSystemDNS(j *journal, _ func([]string) (string, error), logf func(string, ...any)) systemDNS {
	return newResolvConfDNS(resolvConfPath, j, logf)
}
