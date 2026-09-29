// SPDX-License-Identifier: MIT

//go:build darwin

package main

// macOS: the DNS of every enabled network service set with networksetup —
// wg-quick's darwin way — and put back as it was (a list, or "Empty": DHCP's).
// 🚨 networksetup's setting PERSISTS across a reboot: the state file carries
// the undo, and a start after a crash (or -cleanup) puts it back.
//
// The network's own servers: /etc/resolv.conf before anything changes, then
// the DHCP option of the default interface (`ipconfig getpacket`), which a
// manual override on the service does not hide.

import (
	"os"
	"os/exec"
)

type darwinDNS struct {
	j    *journal
	run  func([]string) (string, error)
	logf func(string, ...any)
	orig []string
}

func newSystemDNS(j *journal, run func([]string) (string, error), logf func(string, ...any)) systemDNS {
	d := &darwinDNS{j: j, run: run, logf: logf}
	if b, err := os.ReadFile(resolvConfPath); err == nil {
		d.orig = parseResolvConf(string(b))
	}
	return d
}

func (d *darwinDNS) originals() []string { return d.orig }

func (d *darwinDNS) apply(_ string, servers []string) error {
	out, err := d.run([]string{"networksetup", "-listallnetworkservices"})
	if err != nil {
		return err
	}
	for _, svc := range parseNetworkServices(out) {
		cur, err := d.run([]string{"networksetup", "-getdnsservers", svc})
		if err != nil {
			d.logf("dns: %s: %v", svc, err)
			continue
		}
		back := parseGetDNSServers(cur)
		undo := append([]string{"networksetup", "-setdnsservers", svc}, back...)
		if len(back) == 0 {
			undo = append(undo, "Empty")
		}
		if err := d.j.add(undoStep{Key: "dns networksetup " + svc, Argv: undo}); err != nil {
			return err
		}
		if _, err := d.run(append([]string{"networksetup", "-setdnsservers", svc}, servers...)); err != nil {
			d.logf("dns: %s: %v", svc, err)
		}
	}
	afterDNSChange()
	return nil
}

func (d *darwinDNS) refresh(gw gateway) []string {
	if gw.Iface == "" {
		return d.orig
	}
	if out, err := d.run([]string{"ipconfig", "getpacket", gw.Iface}); err == nil {
		if s := parseIpconfigPacket(out); len(s) > 0 {
			d.orig = s
		}
	}
	return d.orig
}

func init() { afterDNSChange = flushDarwinDNSCache }

// flushDarwinDNSCache: best effort, as after any DNS change on macOS.
func flushDarwinDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
