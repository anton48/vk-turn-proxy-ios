// SPDX-License-Identifier: MIT

package main

// The pinner: pkg/proxy's dial hook (proxy.SetDialHook). Every destination the
// proxy is about to send to — a TURN relay, VK's API host, the captcha's hosts,
// the network's DNS server — gets a /32 via the PHYSICAL gateway before the
// first packet, so that with the default route in the tunnel the proxy's own
// traffic still goes around it. The user's routing-table variant (09-29): one
// logic on every OS, visible in `netstat -rn`, no socket binding, no FIB; and
// pinned at DIAL time because a static list cannot know VK's next address
// (its DNS rotates; the mint and the captcha touch more hosts than any list).
//
// 🚫 Never pinned: loopback and link-local; the tunnel's own subnet; a host on
// the physical interface's own subnets (the connected route already carries
// it); and the TUNNEL's DNS servers — a pin would send every program's DNS
// around the tunnel. A route that exists before the console asked is left as
// it is: the console takes back only what it made.

import (
	"errors"
	"net"
	"strings"
	"sync"
)

var errIPv6Blocked = errors.New("IPv6 is blocked (-block-ipv6); the proxy dials over IPv4")

type pinner struct {
	mu      sync.Mutex
	cmds    netCmds
	run     func(argv []string) (string, error)
	j       *journal
	logf    func(string, ...any)
	enabled bool // the default route is (or is about to be) in the tunnel
	blockV6 bool

	gw     gateway
	hasGW  bool
	onlink []*net.IPNet
	tunnel *net.IPNet
	never  map[string]bool // the tunnel's DNS servers

	wanted  map[string]bool    // every address ever asked for, pinned or not yet
	pinned  map[string]gateway // pinned by us, and via which gateway: re-pointed when it changes, deleted on exit
	foreign map[string]bool    // a route existed already: not ours, left alone
}

func newPinner(cmds netCmds, run func([]string) (string, error), j *journal, logf func(string, ...any)) *pinner {
	return &pinner{cmds: cmds, run: run, j: j, logf: logf, never: map[string]bool{},
		wanted: map[string]bool{}, pinned: map[string]gateway{}, foreign: map[string]bool{}}
}

// hook is proxy.SetDialHook's function.
func (p *pinner) hook(network, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.To4() == nil {
		p.mu.Lock()
		blocked := p.blockV6
		p.mu.Unlock()
		if blocked {
			return errIPv6Blocked // the dialer tries the host's IPv4 address next
		}
		return nil // IPv6 is not in the tunnel: it goes out the physical way as it is
	}
	return p.ensure(ip.String())
}

func pinKey(ip string) string { return "pin " + ip }

// skipLocked says why an address is not pinned, "" when it is to be.
func (p *pinner) skipLocked(ip net.IP) string {
	switch {
	case ip.IsLoopback(), ip.IsUnspecified(), ip.IsMulticast(), ip.IsLinkLocalUnicast():
		return "not routed"
	case p.tunnel != nil && p.tunnel.Contains(ip):
		return "the tunnel's own subnet"
	case p.never[ip.String()]:
		return "one of the tunnel's DNS servers"
	}
	for _, n := range p.onlink {
		if n.Contains(ip) {
			return "on the physical link"
		}
	}
	return ""
}

// ensure pins ip via the physical gateway unless it needs none or has one.
func (p *pinner) ensure(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled || p.wanted[ip] {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil
	}
	if why := p.skipLocked(parsed); why != "" {
		if why == "one of the tunnel's DNS servers" {
			p.logf("pin %s: not pinned — %s (a pin would take everyone's DNS around the tunnel)", ip, why)
		}
		p.wanted[ip] = true
		return nil
	}
	p.wanted[ip] = true
	if !p.hasGW {
		return nil // no network now: pinned when a gateway appears (setGateway)
	}
	return p.addLocked(ip)
}

func (p *pinner) addLocked(ip string) error {
	add, del := p.cmds.pin(ip, p.gw)
	if err := p.j.add(undoStep{Key: pinKey(ip), Argv: del}); err != nil {
		return err
	}
	out, err := p.run(add)
	if err != nil {
		_ = p.j.done(pinKey(ip))
		if strings.Contains(out+err.Error(), "File exists") {
			p.foreign[ip] = true
			p.logf("pin %s: a route to it exists already — not ours, left as it is", ip)
			return nil
		}
		p.logf("pin %s via %s: %v", ip, p.gw, err)
		return err
	}
	p.pinned[ip] = p.gw
	return nil
}

// setGateway records the physical default route (none: the network is down)
// and the interface's own subnets; every pin follows it — re-pointed where it
// points elsewhere (a pin keeps its old gateway through a spell without a
// network), or made now for an address asked while there was no gateway.
func (p *pinner) setGateway(gw gateway, up bool, onlink []*net.IPNet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gw, p.hasGW, p.onlink = gw, up, onlink
	if !up || !p.enabled {
		return
	}
	for ip := range p.wanted {
		via, ours := p.pinned[ip]
		switch {
		case ours && via != gw:
			if _, err := p.run(p.cmds.repin(ip, gw)); err != nil {
				p.logf("re-pin %s via %s: %v", ip, gw, err)
				continue
			}
			p.pinned[ip] = gw
		case !ours && !p.foreign[ip]:
			if parsed := net.ParseIP(ip); parsed != nil && p.skipLocked(parsed) == "" {
				_ = p.addLocked(ip)
			}
		}
	}
}

// enable turns pinning on (the default-route mode) and pins what is known.
func (p *pinner) enable(on bool) {
	p.mu.Lock()
	p.enabled = on
	p.mu.Unlock()
}

// removeAll deletes every pin the console made.
func (p *pinner) removeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip := range p.pinned {
		_, del := p.cmds.pin(ip, p.gw)
		if _, err := p.run(del); err != nil {
			p.logf("unpin %s: %v", ip, err)
			continue
		}
		_ = p.j.done(pinKey(ip))
		delete(p.pinned, ip)
	}
}

// count is how many pins the console holds.
func (p *pinner) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pinned)
}
