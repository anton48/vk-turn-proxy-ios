// SPDX-License-Identifier: GPL-3.0-only

//go:build darwin || linux

package main

import (
	"syscall"
)

// reusePort lets two client sockets share one local port toward two
// destinations (SO_REUSEADDR and SO_REUSEPORT), for the tests that need one
// client port on two listeners.
func reusePort(_, _ string, c syscall.RawConn) error {
	var opt error
	err := c.Control(func(fd uintptr) {
		if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
			opt = e
			return
		}
		opt = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return opt
}
