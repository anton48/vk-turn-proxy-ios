// SPDX-License-Identifier: MIT

package main

// The system's DNS while the default route is in the tunnel: the tunnel's
// servers (the config's dnsServers, or -dns), put back on exit; -dns=false
// leaves the system alone. Separately, the NETWORK's own servers are read
// before anything changes and after every network change — the proxy's
// resolver uses them (resolver.go).
//
// Three shapes: macOS — networksetup per network service (dns_darwin.go);
// Linux with systemd-resolved — per-link DNS on the tunnel interface with the
// "~." routing domain, wg-quick's way (dns_linux.go); everything else — the
// file /etc/resolv.conf, its old content in the state file (this file).

import (
	"os"
	"strings"
)

type systemDNS interface {
	// originals: the network's own servers.
	originals() []string
	// apply points the system at servers (the undo journaled first); tun is
	// the tunnel interface (systemd-resolved keeps the setting on it).
	apply(tun string, servers []string) error
	// refresh after a network change or on a tick: the network's servers now,
	// and the tunnel's put back where something else replaced them.
	refresh(gw gateway) []string
}

const resolvConfPath = "/etc/resolv.conf"

// afterDNSChange runs after the system's DNS changed (macOS flushes its cache).
var afterDNSChange = func() {}

// resolvConfDNS rewrites /etc/resolv.conf: nameserver lines of the tunnel's,
// the file's other lines (search, options) kept.
type resolvConfDNS struct {
	path    string
	j       *journal
	logf    func(string, ...any)
	orig    string // the content before the console wrote it
	perm    os.FileMode
	ours    string // what the console wrote
	servers []string
	applied bool
}

func newResolvConfDNS(path string, j *journal, logf func(string, ...any)) *resolvConfDNS {
	d := &resolvConfDNS{path: path, j: j, logf: logf, perm: 0o644}
	if b, err := os.ReadFile(path); err == nil {
		d.orig = string(b)
	}
	if fi, err := os.Stat(path); err == nil {
		d.perm = fi.Mode().Perm()
	}
	return d
}

func (d *resolvConfDNS) originals() []string { return parseResolvConf(d.orig) }

// resolvConfWith is content with its nameservers replaced by servers.
func resolvConfWith(content string, servers []string) string {
	var b strings.Builder
	b.WriteString("# written by vk-turn-proxy-console: the tunnel's DNS; the previous content comes back on exit\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "nameserver" || strings.HasPrefix(f[0], "#") {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (d *resolvConfDNS) apply(_ string, servers []string) error {
	if err := d.j.add(undoStep{Key: "dns " + d.path, File: d.path, Content: d.orig, Perm: uint32(d.perm)}); err != nil {
		return err
	}
	d.servers = servers
	d.ours = resolvConfWith(d.orig, servers)
	if err := os.WriteFile(d.path, []byte(d.ours), d.perm); err != nil {
		return err
	}
	d.applied = true
	return nil
}

// refresh: a DHCP client or a network manager that rewrote the file has given
// the network's servers — they become the originals (and the content to put
// back), and the tunnel's are written again.
func (d *resolvConfDNS) refresh(gateway) []string {
	if !d.applied {
		return d.originals()
	}
	b, err := os.ReadFile(d.path)
	if err != nil || string(b) == d.ours {
		return d.originals()
	}
	d.logf("dns: %s was rewritten by something else — its servers are the network's now; the tunnel's written back", d.path)
	d.orig = string(b)
	_ = d.j.done("dns " + d.path)
	if err := d.apply("", d.servers); err != nil {
		d.logf("dns: %v", err)
	}
	return d.originals()
}
