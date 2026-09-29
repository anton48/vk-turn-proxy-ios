// SPDX-License-Identifier: MIT

//go:build freebsd

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

var hostCmds netCmds = freebsdCmds{}

const defaultTunName = "vktp0"

// openTUN: 🚨 never the bare clone prefix "tun" — wireguard-go creates tun0
// and RENAMES it, and renaming to "tun" double-faulted a FreeBSD 15.1 kernel
// (2026-09-04, the whole host rebooted).
func openTUN(name string, mtu int) (tun.Device, string, error) {
	if name == "tun" {
		return nil, "", fmt.Errorf("-tun-name %q: never the bare clone prefix on FreeBSD", name)
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("create %s: %w", name, err)
	}
	real, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, "", err
	}
	return dev, real, nil
}

func readDefaultRoute() (gateway, bool) {
	out, err := runCmd([]string{"route", "-n", "get", "default"})
	if err != nil {
		return gateway{}, false
	}
	return parseBSDRouteGet(out)
}
