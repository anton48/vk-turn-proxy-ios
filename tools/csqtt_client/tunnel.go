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
	"path"
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
}

// credPool mints a VK credential and reuses it for allocsPerCred workers,
// alternating the relay addresses VK returned, then mints the next one.
type credPool struct {
	mu            sync.Mutex
	link          string
	manual        *proxy.TURNCreds
	allocsPerCred int
	cur           *proxy.TURNCreds
	used          int
	next          int
	minted        int
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
	if len(p.cur.Addresses) > 0 {
		addr = p.cur.Addresses[p.next%len(p.cur.Addresses)]
		p.next++
	}
	p.used++
	return csqtt.TURNCredentials{Username: p.cur.Username, Password: p.cur.Password, Address: addr}, nil
}

func runTunnel(ctx context.Context, o tunnelOptions) int {
	pool := &credPool{link: o.vkLink, manual: o.manualCreds, allocsPerCred: o.allocsPerCred}
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
		Logf: log.Printf,
	})
	if err != nil {
		log.Printf("dial: %v", err)
		return 1
	}
	defer client.Close()
	conf := client.Config()
	log.Printf("tunnel up in %d ms: ip %s dns %s frames=%v workers=%d chunks=%v", time.Since(t0).Milliseconds(), conf.TunnelIP, conf.DNS, conf.FramesData(), o.workers, o.chunks)

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
	log.Printf("stats: workers %d/%d ready%s · relay tx=%d rx=%d restarts=%d repairs=%d · tun in=%d out=%d senderr=%d · framed=%d reassembled=%d dropped=%d noworker=%d",
		ready, len(s.Workers), deadList(dead), tx, rx, restarts, s.Repairs, tunRx, tunTx, tunErr, s.FramedTx, s.Reassembled, s.Dropped, s.NoWorker)
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
