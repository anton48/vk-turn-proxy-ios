// SPDX-License-Identifier: MIT

//go:build !freebsd

package main

import "errors"

// The tun path is written for the FreeBSD test host; elsewhere the tool
// still builds and offers the ICMP smoke test.

type tunDev struct{}

func openTUN(string, int) (*tunDev, error) {
	return nil, errors.New("-tun is available on FreeBSD only in this tool")
}
func (*tunDev) Name() string                        { return "" }
func (*tunDev) ReadPacket() ([]byte, error)         { return nil, errors.New("no tun") }
func (*tunDev) WritePacket([]byte) error            { return errors.New("no tun") }
func (*tunDev) Close() error                        { return nil }
func (*tunDev) configure(string, string, int) error { return errors.New("no tun") }
func addHostRoute(string, string) error             { return errors.New("no tun") }
func deleteHostRoute(string) error                  { return errors.New("no tun") }
