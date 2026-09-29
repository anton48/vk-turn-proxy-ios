// SPDX-License-Identifier: MIT

//go:build !unix

package main

func consoleRunning(int) bool { return false }
