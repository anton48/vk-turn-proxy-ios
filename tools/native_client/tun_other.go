// SPDX-License-Identifier: MIT

//go:build !freebsd

package main

// The tun and routing paths are written for the FreeBSD test host; elsewhere
// the tool still builds and vets, and says so at runtime.

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

var errFreeBSDOnly = errors.New("this tool's tun path is written for the FreeBSD stand")

func openTUN(string, int) (tun.Device, string, error) { return nil, "", errFreeBSDOnly }
func configureTUN(string, string, int) error          { return errFreeBSDOnly }
func addHostRoute(string, string) error               { return errFreeBSDOnly }
func deleteHostRoute(string) error                    { return errFreeBSDOnly }
func defaultGateway() (string, error)                 { return "", errFreeBSDOnly }
func setDefaultGateway(string) error                  { return errFreeBSDOnly }
