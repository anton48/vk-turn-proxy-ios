// SPDX-License-Identifier: MIT

//go:build !unix

package main

type pidFile struct{}

func takePidFile(string) (*pidFile, error) { return &pidFile{}, nil }
func (*pidFile) release()                  {}
