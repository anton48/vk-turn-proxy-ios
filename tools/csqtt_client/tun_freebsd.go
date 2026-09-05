// SPDX-License-Identifier: MIT

//go:build freebsd

package main

// A real tun on FreeBSD, through wireguard-go's tun package (already a
// dependency of the app). That package handles the BSD 4-byte address-family
// header itself and asks for an offset of at least 4 on both Read and Write.

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const tunOffset = 16

type tunDev struct {
	dev   tun.Device
	name  string
	rbuf  [][]byte
	sizes []int
	wbuf  []byte
}

func openTUN(name string, mtu int) (*tunDev, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	real, err := dev.Name()
	if err != nil {
		real = name
	}
	return &tunDev{
		dev:   dev,
		name:  real,
		rbuf:  [][]byte{make([]byte, tunOffset+65536)},
		sizes: make([]int, 1),
		wbuf:  make([]byte, tunOffset+65536),
	}, nil
}

func (t *tunDev) Name() string { return t.name }

// ReadPacket returns the next IP packet as a slice into an internal buffer,
// valid until the next call.
func (t *tunDev) ReadPacket() ([]byte, error) {
	for {
		n, err := t.dev.Read(t.rbuf, t.sizes, tunOffset)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		return t.rbuf[0][tunOffset : tunOffset+t.sizes[0]], nil
	}
}

// WritePacket hands one IP packet to the kernel.
func (t *tunDev) WritePacket(p []byte) error {
	if len(p) > len(t.wbuf)-tunOffset {
		return fmt.Errorf("packet %d B exceeds tun buffer", len(p))
	}
	copy(t.wbuf[tunOffset:], p)
	_, err := t.dev.Write([][]byte{t.wbuf[:tunOffset+len(p)]}, tunOffset)
	return err
}

func (t *tunDev) Close() error { return t.dev.Close() }

// configure gives the interface its address and MTU. wireguard-go's tun is
// a BROADCAST-type interface on FreeBSD, not point-to-point, so the
// "inet a b" peer syntax is silently ignored and nothing routes to the
// gateway; a /24 puts the server's TUN subnet on-link instead (the server
// hands out 10.66.67.x/24 and sits at .1).
func (t *tunDev) configure(ip, gw string, mtu int) error {
	_ = gw
	return run("ifconfig", t.name, "inet", ip+"/24", "mtu", fmt.Sprint(mtu), "up")
}

func addHostRoute(host, gw string) error { return run("route", "-q", "add", "-host", host, gw) }
func deleteHostRoute(host string) error  { return run("route", "-q", "delete", "-host", host) }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

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
func setDefaultGateway(gw string) error { return run("route", "-q", "change", "default", gw) }
