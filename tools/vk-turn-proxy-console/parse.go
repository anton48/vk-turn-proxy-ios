// SPDX-License-Identifier: MIT

package main

// Parsers for what the OS tools print, pure so that every family is tested on
// any machine.

import (
	"net"
	"strconv"
	"strings"
)

// parseBSDRouteGet reads `route -n get default` (darwin, FreeBSD):
//
//	   route to: default
//	destination: default
//	       mask: default
//	    gateway: 192.0.2.1
//	  interface: en0
//
// A point-to-point default names no gateway, or a "link#N" one.
func parseBSDRouteGet(out string) (gateway, bool) {
	var g gateway
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "gateway":
			if ip := net.ParseIP(v); ip != nil && ip.To4() != nil {
				g.IP = v
			}
		case "interface":
			g.Iface = v
		}
	}
	return g, g.Iface != ""
}

// parseLinuxDefaultRoutes reads `ip -4 route show default` and picks the route
// the kernel uses: the lowest metric (none = 0).
//
//	default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.5 metric 100
//	default dev ppp0 scope link
func parseLinuxDefaultRoutes(out string) (gateway, bool) {
	best, bestMetric, found := gateway{}, int64(1<<62), false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		var g gateway
		metric := int64(0)
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				if ip := net.ParseIP(f[i+1]); ip != nil && ip.To4() != nil {
					g.IP = f[i+1]
				}
			case "dev":
				g.Iface = f[i+1]
			case "metric":
				if m, err := strconv.ParseInt(f[i+1], 10, 64); err == nil {
					metric = m
				}
			}
		}
		if g.Iface == "" {
			continue
		}
		if !found || metric < bestMetric {
			best, bestMetric, found = g, metric, true
		}
	}
	return best, found
}

// parseResolvConf lists the IPv4 nameservers of a resolv.conf.
func parseResolvConf(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// parseNetworkServices reads `networksetup -listallnetworkservices`: the first
// line is a legend, a leading "*" marks a disabled service.
func parseNetworkServices(out string) []string {
	var svcs []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if i == 0 || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs
}

// parseGetDNSServers reads `networksetup -getdnsservers <service>`: one address
// per line, or a sentence saying there are none (nil: the service follows DHCP).
func parseGetDNSServers(out string) []string {
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if net.ParseIP(line) != nil {
			servers = append(servers, line)
		}
	}
	return servers
}

// parseIpconfigPacket reads the DHCP option of `ipconfig getpacket <if>`
// (darwin): "domain_name_server (ip_mult): {192.0.2.53, 198.51.100.53}" — the
// network's own DNS, whatever a manual override on the service says.
func parseIpconfigPacket(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "domain_name_server") {
			continue
		}
		i, j := strings.Index(line, "{"), strings.LastIndex(line, "}")
		if i < 0 || j < i {
			return nil
		}
		var out []string
		for _, f := range strings.Split(line[i+1:j], ",") {
			if ip := net.ParseIP(strings.TrimSpace(f)); ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
		return out
	}
	return nil
}

// parseResolvectlDNS reads `resolvectl dns <link>`: "Link 2 (eth0): a b c".
func parseResolvectlDNS(out string) []string {
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		_, rest, ok := strings.Cut(line, "):")
		if !ok {
			continue
		}
		for _, f := range strings.Fields(rest) {
			// resolvectl may append "%ifindex" or "#name" to a server.
			if i := strings.IndexAny(f, "%#"); i > 0 {
				f = f[:i]
			}
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				servers = append(servers, ip.String())
			}
		}
	}
	return servers
}

// sshClientIP is the first field of $SSH_CLIENT / $SSH_CONNECTION.
func sshClientIP(env string) string {
	f := strings.Fields(env)
	if len(f) == 0 {
		return ""
	}
	if ip := net.ParseIP(f[0]); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	return ""
}
