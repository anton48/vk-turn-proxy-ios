// SPDX-License-Identifier: MIT

//go:build linux

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

var hostCmds netCmds = linuxCmds{}

const defaultTunName = "vktp0"

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

func readDefaultRoute() (gateway, bool) {
	out, err := runCmd([]string{"ip", "-4", "route", "show", "default"})
	if err != nil {
		return gateway{}, false
	}
	return parseLinuxDefaultRoutes(out)
}
