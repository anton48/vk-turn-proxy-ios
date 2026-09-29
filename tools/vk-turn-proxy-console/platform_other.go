// SPDX-License-Identifier: MIT

//go:build !darwin && !linux && !freebsd

package main

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// The console runs on macOS, Linux and FreeBSD; elsewhere it builds, vets and
// says so.

var errUnsupportedOS = errors.New("vk-turn-proxy-console runs on macOS, Linux and FreeBSD")

var hostCmds netCmds = linuxCmds{}

const defaultTunName = "vktp0"

func openTUN(string, int) (tun.Device, string, error) { return nil, "", errUnsupportedOS }
func readDefaultRoute() (gateway, bool)               { return gateway{}, false }
func sshPeers() []string                              { return nil }

func newSystemDNS(j *journal, _ func([]string) (string, error), logf func(string, ...any)) systemDNS {
	return newResolvConfDNS(resolvConfPath, j, logf)
}
