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

	// wanted is only what was ASKED — the addresses setGateway follows; it
	// says nothing about the routing table. What the table holds is pinned
	// (a route of ours, confirmed by its command) and foreign (one that was
	// there already); a pin that failed is in neither and is tried again.
	wanted  map[string]bool    // every address ever asked for, pinned or not
	pinned  map[string]gateway // pinned by us, and via which gateway: re-pointed when it changes, deleted on exit
	foreign map[string]bool    // a route existed already: not ours, left alone
	lost    bool               // the path was lost since the pins were last confirmed: an interface that went took its routes with it
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

// ensure pins ip via the physical gateway unless it needs none or has one —
// on every call until the routing table has it: a pin whose command failed,
// or a re-point that failed at a gateway change, is tried again here, and its
// error goes back to the dial (which then does not go into the tunnel).
func (p *pinner) ensure(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil
	}
	first := !p.wanted[ip]
	p.wanted[ip] = true
	if via, ours := p.pinned[ip]; ours {
		if !p.hasGW || via == p.gw {
			return nil
		}
		return p.repinLocked(ip) // still via a gateway that is gone: its re-point failed
	}
	if p.foreign[ip] {
		return nil
	}
	if why := p.skipLocked(parsed); why != "" {
		if first && why == "one of the tunnel's DNS servers" {
			p.logf("pin %s: not pinned — %s (a pin would take everyone's DNS around the tunnel)", ip, why)
		}
		return nil
	}
	if !p.hasGW {
		return nil // no network now: pinned when a gateway appears (setGateway)
	}
	return p.addLocked(ip)
}

// repinLocked points a pin at the current gateway — or, when its route is
// gone (it went with the old interface), makes it anew: a re-point of a route
// that is not there is no re-point (hostRouteQuery says why).
func (p *pinner) repinLocked(ip string) error {
	if q := p.cmds.hostRouteQuery(ip); q != nil {
		if out, err := p.run(q); err != nil || !isOwnHostRoute(out, ip) {
			return p.remakeLocked(ip)
		}
	}
	if _, err := p.run(p.cmds.repin(ip, p.gw)); err != nil {
		if routeNotFound(err) { // gone between the query and the change
			return p.remakeLocked(ip)
		}
		p.logf("re-pin %s via %s: %v", ip, p.gw, err)
		return err
	}
	p.pinned[ip] = p.gw
	return nil
}

// recheckLocked confirms a pin after the path was lost, the gateway the same:
// the routing table is asked (the BSDs), and a pin that went with the
// interface is made again; Linux's re-point (ip route replace) makes a route
// that is gone and leaves one that is there. A pin that cannot be confirmed
// is no pin: out of pinned, made at the next ask.
func (p *pinner) recheckLocked(ip string) error {
	if q := p.cmds.hostRouteQuery(ip); q != nil {
		if out, err := p.run(q); err == nil && isOwnHostRoute(out, ip) {
			return nil
		}
		return p.remakeLocked(ip)
	}
	if _, err := p.run(p.cmds.repin(ip, p.gw)); err != nil {
		p.logf("pin %s: not confirmed after the path came back via %s: %v", ip, p.gw, err)
		delete(p.pinned, ip)
		return err
	}
	return nil
}

// remakeLocked: the pin's route is gone — it is no longer ours to re-point,
// and it is made again via the current gateway (a failure is tried again at
// the next ask, as any pin's).
func (p *pinner) remakeLocked(ip string) error {
	delete(p.pinned, ip)
	p.logf("pin %s: its route is gone (with the old interface) — made again via %s", ip, p.gw)
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
	if !up {
		p.lost = true // the interface may have gone, and with it every route through it — the pins too
		return
	}
	if !p.enabled {
		return
	}
	recheck := p.lost // back after a loss: a pin recorded via THIS gateway may be gone all the same
	p.lost = false
	for ip := range p.wanted {
		via, ours := p.pinned[ip]
		switch {
		case ours && via != gw:
			_ = p.repinLocked(ip) // a failure stays via the old gateway: ensure tries again
		case ours && recheck:
			_ = p.recheckLocked(ip)
		case !ours && !p.foreign[ip]:
			if parsed := net.ParseIP(ip); parsed != nil && p.skipLocked(parsed) == "" {
				_ = p.addLocked(ip)
			}
		}
	}
}

// setNever replaces the tunnel's servers that must not be pinned. One that is
// pinned now (it was the crossing's, asked by the proxy) is unpinned: with the
// system pointed at it, the pin would take everyone's DNS around the tunnel.
func (p *pinner) setNever(list []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.never = map[string]bool{}
	for _, s := range list {
		p.never[s] = true
		if _, ours := p.pinned[s]; ours {
			_, del := p.cmds.pin(s, p.gw)
			if _, err := p.run(del); err != nil && !alreadyGone(err) {
				p.logf("unpin %s: %v", s, err)
				continue
			}
			_ = p.j.done(pinKey(s))
			delete(p.pinned, s)
			p.logf("pin %s: removed — it is one of the tunnel's DNS servers again", s)
		}
	}
}

// on reports the default-route mode (pinning on).
func (p *pinner) on() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

// enable turns pinning on (the default-route mode) and pins what is known.
func (p *pinner) enable(on bool) {
	p.mu.Lock()
	p.enabled = on
	p.mu.Unlock()
}

// removeAll deletes every pin the console made and turns pinning off.
func (p *pinner) removeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = false // from here on nothing pins: a late dial or a gateway change must not put one back
	for ip := range p.pinned {
		_, del := p.cmds.pin(ip, p.gw)
		if _, err := p.run(del); err != nil && !alreadyGone(err) {
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
