//go:build linux

package main

import "fmt"

const defaultTunName = "csqtt0"

// configureTUN gives the interface its address and brings it up.
func configureTUN(name, ip string, mtu int) error {
	if err := run("ip", "addr", "add", ip+"/24", "dev", name); err != nil {
		return err
	}
	return run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up")
}

// routeVia sends a host or a prefix through the tunnel. The route lives on
// the interface and goes with it; nothing is deleted by hand.
func routeVia(name, dest, gateway string) error {
	return run("ip", "route", "add", dest, "dev", name)
}

// On Linux the interface goes when its descriptor is closed.
func destroyTUN(string) {}
