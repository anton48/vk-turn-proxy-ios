//go:build !linux && !freebsd && !darwin

package main

import "errors"

const defaultTunName = "csqtt0"

func configureTUN(string, string, int) error {
	return errors.New("-tun is not available on this system")
}
func routeVia(string, string, string) error {
	return errors.New("-tun is not available on this system")
}
func destroyTUN(string) {}
