//go:build freebsd || darwin

package main

import (
	"fmt"
	"runtime"
	"strings"
)

// A bare clone prefix ("tun") panics FreeBSD's cloner in this library; a
// numbered utun is what macOS takes.
var defaultTunName = map[string]string{"freebsd": "csqtt0", "darwin": "utun"}[runtime.GOOS]

// configureTUN gives the interface its address and brings it up. UNTESTED
// on these systems in this tool: the stand runs were made on Linux.
func configureTUN(name, ip string, mtu int) error {
	gw := ip[:strings.LastIndex(ip, ".")+1] + "1"
	if runtime.GOOS == "darwin" {
		return run("ifconfig", name, "inet", ip, gw, "netmask", "255.255.255.0", "mtu", fmt.Sprint(mtu), "up")
	}
	return run("ifconfig", name, "inet", ip+"/24", "mtu", fmt.Sprint(mtu), "up")
}

// routeVia sends a host or a prefix through the tunnel. The route is the
// interface's and goes with it; nothing is deleted by hand (a delete of a
// route that is not there rewrites another on macOS).
func routeVia(name, dest, gateway string) error {
	kind := "-host"
	if strings.Contains(dest, "/") {
		kind = "-net"
	}
	if runtime.GOOS == "darwin" {
		return run("route", "-q", "-n", "add", kind, dest, "-interface", name)
	}
	return run("route", "-q", "add", kind, dest, gateway)
}

// On FreeBSD a tun outlives its descriptor.
func destroyTUN(name string) {
	if runtime.GOOS == "freebsd" {
		_ = run("ifconfig", name, "destroy")
	}
}
