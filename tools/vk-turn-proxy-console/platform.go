// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// runCmd runs an OS tool and returns its combined output. The commands carry
// addresses and interface names, never a secret.
func runCmd(argv []string) (string, error) {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runAll runs commands in order and stops at the first failure.
func runAll(cmds [][]string) error {
	for _, c := range cmds {
		if _, err := runCmd(c); err != nil {
			return err
		}
	}
	return nil
}

// interfaceSubnets are the IPv4 networks on an interface: hosts there are
// reached by the connected route, never pinned.
func interfaceSubnets(name string) []*net.IPNet {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			out = append(out, n)
		}
	}
	return out
}

// ipv6Networks: the IPv6 networks of every interface that is up — the
// clients reached on-link, whatever the routes to ::/1 and 8000::/1 say.
func ipv6Networks() []*net.IPNet {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

// networkIdentity is what makes a network another one: the next hop, the
// interface and the interface's own IPv4 addresses (the same router address
// on a new Wi-Fi is still a new network).
func networkIdentity(g gateway, up bool) string {
	if !up {
		return "down"
	}
	var addrs []string
	for _, n := range interfaceSubnets(g.Iface) {
		addrs = append(addrs, n.String())
	}
	return g.String() + " " + strings.Join(addrs, ",")
}
