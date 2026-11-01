// SPDX-License-Identifier: GPL-3.0-only

//go:build darwin || linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePort lets two client sockets share one local port toward two
// destinations (SO_REUSEADDR and SO_REUSEPORT), for the tests that need one
// client port on two listeners. Through x/sys/unix: the Mac's syscall
// package names SO_REUSEPORT, Linux/amd64's does not (the user's review of
// 8052720 — the tests did not compile for the stands).
func reusePort(_, _ string, c syscall.RawConn) error {
	var opt error
	err := c.Control(func(fd uintptr) {
		if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
			opt = e
			return
		}
		opt = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return opt
}
