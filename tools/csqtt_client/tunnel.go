// SPDX-License-Identifier: MIT

package main

// Stage 3: a real tunnel. N workers through pkg/csqtt, a tun on this host,
// host routes for whatever the test wants sent through it, and a stats
// line every so often. The client package does the striping, framing and
// repair; this file is plumbing.

import (
	"context"
	"log"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

type tunnelOptions struct {
	server        *net.UDPAddr
	password      string
	deviceID      string
	generation    uint64
	salt          string
	mode          csqtt.Mode
	revision      string
	workers       int
	turnTransport string
	turnDebug     bool
	vkLink        string
	manualCreds   *proxy.TURNCreds
	allocsPerCred int
	tunName       string
	mtu           int
	routes        []string
	duration      time.Duration
	statsEvery    time.Duration
	chunks        [3]int
	dupTCP        bool
	relayPolicy   string        // "first": every worker on Addresses[0], as the app does anonymously; "rotate": spread over what VK returned
	faultWorker   int           // fault injection: blackhole this worker…
	faultAfter    time.Duration // …this long after the tunnel is up (0 = no fault)
	defaultRoute  bool          // send the DEFAULT route through the tunnel (host routes keep the relay and the SSH sources reachable)
	keepHosts     []string      // hosts that must stay on the old default gateway when defaultRoute is on
}

// credPool mints a VK credential and reuses it for allocsPerCred workers,
// then mints the next one. Which of the relay addresses VK returned a worker
// gets is the relay policy: "first" keeps every allocation on ONE relay host
// (the app's anonymous mode — the ~10-per-identity quota is per relay, and a
// fresh identity every allocsPerCred workers keeps under it), "rotate" spreads
// them over both, which the reference client does and which puts two relay
// hosts' latency skew between a flow's own packets.
type credPool struct {
	mu            sync.Mutex
	link          string
	manual        *proxy.TURNCreds
	allocsPerCred int
	policy        string
	cur           *proxy.TURNCreds
	used          int
	next          int
	minted        int
	hosts         map[string]bool
}

func (p *credPool) creds(ctx context.Context, workerID int) (csqtt.TURNCredentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == nil || p.used >= p.allocsPerCred {
		if p.manual != nil {
			p.cur = p.manual
		} else {
			linkID := path.Base(mustURL(p.link).Path)
			c, err := proxy.GetVKCreds(linkID, nil, "", "", 0, 0, "", "")
			if err != nil {
				return csqtt.TURNCredentials{}, err
			}
			p.cur = c
			p.minted++
			log.Printf("creds: minted set %d for worker %d: %s (+%d more)", p.minted, workerID, c.Address, len(c.Addresses)-1)
		}
		p.used = 0
	}
	addr := p.cur.Address
	if p.policy == "rotate" && len(p.cur.Addresses) > 0 {
		addr = p.cur.Addresses[p.next%len(p.cur.Addresses)]
		p.next++
	}
	p.used++
	if host, _, err := net.SplitHostPort(addr); err == nil {
		p.hosts[host] = true
	}
	return csqtt.TURNCredentials{Username: p.cur.Username, Password: p.cur.Password, Address: addr}, nil
}

// relayHosts lists every relay host handed to a worker so far.
func (p *credPool) relayHosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return keys(p.hosts)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func runTunnel(ctx context.Context, o tunnelOptions) int {
	pool := &credPool{link: o.vkLink, manual: o.manualCreds, allocsPerCred: o.allocsPerCred, policy: o.relayPolicy, hosts: map[string]bool{}}
	lvl := logging.LogLevelWarn
	if o.turnDebug {
		lvl = logging.LogLevelTrace
	}
	t0 := time.Now()
	client, err := csqtt.Dial(ctx, csqtt.Config{
		Server: o.server, Password: o.password,
		DeviceID: o.deviceID, Generation: o.generation, Salt: o.salt,
		Workers: o.workers, Mode: o.mode, Revision: o.revision, Chunks: o.chunks,
		Creds: pool.creds, TURNTransport: o.turnTransport, TURNLogLevel: lvl,
		DuplicateTCP: o.dupTCP,
		Logf:         log.Printf,
	})
	if err != nil {
		log.Printf("dial: %v", err)
		return 1
	}
	defer client.Close()
	conf := client.Config()
	log.Printf("tunnel up in %d ms: ip %s dns %s frames=%v workers=%d chunks=%v dup-tcp=%v relay=%s", time.Since(t0).Milliseconds(), conf.TunnelIP, conf.DNS, conf.FramesData(), o.workers, o.chunks, o.dupTCP, o.relayPolicy)

	dev, err := openTUN(o.tunName, o.mtu)
	if err != nil {
		log.Printf("tun: %v", err)
		return 1
	}
	defer dev.Close()
	gw := gatewayOf(net.ParseIP(conf.TunnelIP).To4()).String()
	if err := dev.configure(conf.TunnelIP, gw, o.mtu); err != nil {
		log.Printf("tun configure: %v", err)
		return 1
	}
	log.Printf("tun: %s %s → %s mtu %d", dev.Name(), conf.TunnelIP, gw, o.mtu)
	var added []string
	defer func() {
		for _, h := range added {
			_ = deleteHostRoute(h)
		}
	}()
	for _, h := range o.routes {
		if h == "" {
			continue
		}
		if err := addHostRoute(h, gw); err != nil {
			log.Printf("route %s: %v", h, err)
			continue
		}
		added = append(added, h)
	}
	if len(added) > 0 {
		log.Printf("routes via %s: %s", gw, strings.Join(added, ", "))
	}
	if o.defaultRoute {
		// The order matters: pin everything that must NOT go through the tunnel
		// to the old gateway first — every relay host the workers use, and the
		// SSH sources — then move the default. Undone in reverse on exit.
		oldGW, err := defaultGateway()
		if err != nil {
			log.Printf("default route: %v — not changing it", err)
		} else {
			pinned := map[string]bool{}
			pin := func(h string) {
				if h == "" || pinned[h] {
					return
				}
				if err := addHostRoute(h, oldGW); err != nil {
					log.Printf("pin %s via %s: %v", h, oldGW, err)
					return
				}
				pinned[h] = true
			}
			for _, h := range pool.relayHosts() {
				pin(h)
			}
			for _, h := range o.keepHosts {
				pin(h)
			}
			if sc := os.Getenv("SSH_CLIENT"); sc != "" {
				pin(strings.Fields(sc)[0])
			}
			if err := setDefaultGateway(gw); err != nil {
				log.Printf("default route → %s: %v", gw, err)
			} else {
				log.Printf("DEFAULT ROUTE → %s (old %s); pinned to the old gateway: %v", gw, oldGW, keys(pinned))
				defer func() {
					if err := setDefaultGateway(oldGW); err != nil {
						log.Printf("RESTORE default route → %s FAILED: %v", oldGW, err)
					} else {
						log.Printf("default route restored → %s", oldGW)
					}
					for h := range pinned {
						_ = deleteHostRoute(h)
					}
				}()
			}
		}
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if o.duration > 0 {
		rctx, cancel = context.WithTimeout(rctx, o.duration)
		defer cancel()
	}

	// tun → tunnel
	var tunRx, tunTx, tunErr int64
	go func() {
		for {
			p, err := dev.ReadPacket()
			if err != nil {
				if rctx.Err() == nil {
					log.Printf("tun read: %v", err)
				}
				return
			}
			tunRx++
			if err := client.WritePacket(p); err != nil {
				tunErr++
			}
		}
	}()
	// tunnel → tun
	go func() {
		for {
			p, err := client.ReadPacket(rctx)
			if err != nil {
				return
			}
			if err := dev.WritePacket(p); err != nil {
				log.Printf("tun write: %v", err)
				return
			}
			tunTx++
		}
	}()

	if o.faultWorker > 0 && o.faultAfter > 0 {
		go func() {
			select {
			case <-rctx.Done():
			case <-time.After(o.faultAfter):
				log.Printf("FAULT: blackholing worker %d (inbound dropped until it is restarted)", o.faultWorker)
				client.Blackhole(o.faultWorker, true)
			}
		}()
	}
	tick := time.NewTicker(o.statsEvery)
	defer tick.Stop()
	for {
		select {
		case <-rctx.Done():
			printStats(client, tunRx, tunTx, tunErr)
			if err := client.Err(); err != nil {
				log.Printf("client stopped: %v", err)
				return 1
			}
			return 0
		case <-client.Done():
			printStats(client, tunRx, tunTx, tunErr)
			log.Printf("client stopped: %v", client.Err())
			return 1
		case <-tick.C:
			printStats(client, tunRx, tunTx, tunErr)
		}
	}
}

func printStats(client *csqtt.Client, tunRx, tunTx, tunErr int64) {
	s := client.Stats()
	ready := 0
	var tx, rx, restarts int64
	var dead []int
	for _, w := range s.Workers {
		if w.Ready {
			ready++
		} else {
			dead = append(dead, w.ID)
		}
		tx += w.TxPkts
		rx += w.RxPkts
		restarts += w.Restarts
	}
	log.Printf("stats: workers %d/%d ready%s · relay tx=%d rx=%d restarts=%d repairs=%d · tun in=%d out=%d senderr=%d · framed=%d dup=%d reassembled=%d dropped=%d noworker=%d · probes=%d descheduled=%d lost=%d",
		ready, len(s.Workers), deadList(dead), tx, rx, restarts, s.Repairs, tunRx, tunTx, tunErr, s.FramedTx, s.DupTx, s.Reassembled, s.Dropped, s.NoWorker, s.Probes, s.Descheduled, s.LostWorkers)
}

func deadList(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return " (down: " + strings.Join(parts, ",") + ")"
}
