// SPDX-License-Identifier: MIT

//go:build freebsd

package main

// The tun and the routing table on the FreeBSD stand. wireguard-go's own tun
// package is the device WireGuard drives (the bridge builds one from the
// extension's fd; here it is created by name); ifconfig/route do the rest.

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// openTUN creates the interface and returns it with the name the kernel
// actually gave it. The requested name must never be the bare clone prefix
// "tun" — see the flag comment in main.go.
func openTUN(name string, mtu int) (tun.Device, string, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("create tun: %w", err)
	}
	real, err := dev.Name()
	if err != nil {
		real = name
	}
	return dev, real, nil
}

// configureTUN gives the interface its address and MTU. wireguard-go's tun
// is a BROADCAST-type interface on FreeBSD, not point-to-point, so the
// "inet a b" peer syntax is silently ignored and nothing routes to the
// gateway; a prefix (10.10.0.2/24) puts the server's WireGuard subnet
// on-link instead, which is what the /24 in -address is for.
func configureTUN(name, cidr string, mtu int) error {
	return execCmd("ifconfig", name, "inet", cidr, "mtu", fmt.Sprint(mtu), "up")
}

func addHostRoute(host, gw string) error { return execCmd("route", "-q", "add", "-host", host, gw) }
func deleteHostRoute(host string) error  { return execCmd("route", "-q", "delete", "-host", host) }

// defaultGateway reads the current IPv4 default gateway.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get default: %v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("route get default: no gateway in %q", strings.TrimSpace(string(out)))
}

// setDefaultGateway points the default route at gw.
func setDefaultGateway(gw string) error { return execCmd("route", "-q", "change", "default", gw) }

func execCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
