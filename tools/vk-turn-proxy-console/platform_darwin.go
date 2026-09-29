// SPDX-License-Identifier: MIT

//go:build darwin

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

var hostCmds netCmds = darwinCmds{}

// defaultTunName: macOS numbers utun interfaces itself.
const defaultTunName = "utun"

func openTUN(name string, mtu int) (tun.Device, string, error) {
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

// sshPeers: the clients of this host's established SSH sessions.
func sshPeers() []string {
	out, err := runCmd([]string{"netstat", "-anp", "tcp"})
	if err != nil {
		return nil
	}
	return parseNetstatDarwin(out)
}

func readDefaultRoute() (gateway, bool) {
	out, err := runCmd([]string{"route", "-n", "get", "default"})
	if err != nil {
		return gateway{}, false
	}
	return parseBSDRouteGet(out)
}
