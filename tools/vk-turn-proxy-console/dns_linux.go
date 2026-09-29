// SPDX-License-Identifier: MIT

//go:build linux

package main

// Linux: with systemd-resolved in charge (/etc/resolv.conf names its stub),
// the tunnel interface gets its own DNS servers and the "~." routing domain —
// every name goes to them — the way wg-quick does it through resolvconf; the
// settings go with the interface. Without resolved, /etc/resolv.conf itself.

import (
	"os"
	"strings"
)

type resolvedDNS struct {
	j    *journal
	run  func([]string) (string, error)
	logf func(string, ...any)
	tun  string
	orig []string
}

func resolvedInCharge() bool {
	b, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "127.0.0.53") || strings.Contains(s, "127.0.0.54")
}

func newSystemDNS(j *journal, run func([]string) (string, error), logf func(string, ...any)) systemDNS {
	if !resolvedInCharge() {
		return newResolvConfDNS(resolvConfPath, j, logf)
	}
	d := &resolvedDNS{j: j, run: run, logf: logf}
	if b, err := os.ReadFile("/run/systemd/resolve/resolv.conf"); err == nil {
		d.orig = parseResolvConf(string(b)) // the upstream servers, not the stub
	}
	return d
}

func (d *resolvedDNS) originals() []string { return d.orig }

func (d *resolvedDNS) apply(tun string, servers []string) error {
	d.tun = tun
	if err := d.j.add(undoStep{Key: "dns resolvectl " + d.tun, Argv: []string{"resolvectl", "revert", d.tun}}); err != nil {
		return err
	}
	if _, err := d.run(append([]string{"resolvectl", "dns", d.tun}, servers...)); err != nil {
		return err
	}
	if _, err := d.run([]string{"resolvectl", "domain", d.tun, "~."}); err != nil {
		return err
	}
	_, _ = d.run([]string{"resolvectl", "default-route", d.tun, "true"}) // older resolvectl lacks it; "~." already routes every name
	return nil
}

func (d *resolvedDNS) refresh(gw gateway) []string {
	if gw.Iface == "" {
		return d.orig
	}
	if out, err := d.run([]string{"resolvectl", "dns", gw.Iface}); err == nil {
		if s := parseResolvectlDNS(out); len(s) > 0 {
			d.orig = s
		}
	}
	return d.orig
}
