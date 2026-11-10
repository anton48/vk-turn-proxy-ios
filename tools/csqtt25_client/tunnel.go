package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// The -tun mode: N workers over VK's relay, a TUN interface with the
// address the server assigned, and the named hosts or prefixes routed
// through it. The default route is never touched.

type tunnelOptions struct {
	link          csqtt25.Link
	peer          *net.UDPAddr
	linkID        string
	workers       int
	keys          csqtt25.KeyMode
	mode          csqtt25.Mode
	turnTransport string
	allocsPerCred int
	tunName       string
	mtu           int
	routes        []string
	duration      time.Duration
	statsEvery    time.Duration
}

// credSource mints a VK credential for every allocsPerCred workers (one VK
// identity carries ten allocations on a relay) and hands every worker the
// credential's first relay, as the app does in anonymous mode.
type credSource struct {
	mu            sync.Mutex
	linkID        string
	allocsPerCred int
	cur           *proxy.TURNCreds
	used          int
	minted        atomic.Int64 // read by the stats line from another goroutine
}

func (p *credSource) next() (*proxy.TURNCreds, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == nil || p.used >= p.allocsPerCred {
		c, err := proxy.GetVKCreds(p.linkID, nil, "", "", 0, 0, "", "")
		if err != nil {
			return nil, err
		}
		p.cur, p.used = c, 0
		say("creds: set %d minted", p.minted.Add(1))
	}
	p.used++
	return p.cur, nil
}

var ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// maskLine hides every public address in a line of the engine's log.
func maskLine(s string) string {
	return ipv4Re.ReplaceAllStringFunc(s, func(a string) string {
		if ip := net.ParseIP(a); ip != nil && !isPrivate(ip) {
			return "<public>"
		}
		return a
	})
}

func runTunnel(ctx context.Context, o tunnelOptions) int {
	creds := &credSource{linkID: o.linkID, allocsPerCred: o.allocsPerCred}
	var allocs atomic.Int64
	dial := func(ctx context.Context, workerID int) (net.PacketConn, net.Addr, func(), error) {
		c, err := creds.next()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("VK credentials: %s", scrub(err.Error()))
		}
		relay, err := csqtt.DialRelay(csqtt.TURNCredentials{Username: c.Username, Password: c.Password, Address: c.Address},
			o.peer, o.turnTransport, logging.LogLevelError, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("TURN allocation: %s", scrub(err.Error()))
		}
		allocs.Add(1)
		return relay.Conn, o.peer, relay.Close, nil
	}

	var dev atomic.Pointer[tunDev]
	var tunTx, tunRx, tunErr, early atomic.Int64
	deliver := func(pkt []byte) {
		d := dev.Load()
		if d == nil {
			early.Add(1) // before the interface is up
			return
		}
		if err := d.write(pkt); err != nil {
			tunErr.Add(1)
			return
		}
		tunRx.Add(1)
	}

	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	t0 := time.Now()
	client, err := csqtt25.Dial(dctx, csqtt25.ClientConfig{
		Password: o.link.Password, Workers: o.workers, Mode: o.mode, Keys: o.keys, Dial: dial, Deliver: deliver,
		Logf: func(format string, args ...any) { say("%s", maskLine(fmt.Sprintf(format, args...))) },
	})
	cancel()
	if err != nil {
		say("FAILED: no session: %s", maskLine(err.Error()))
		return 1
	}
	defer client.Close()
	conf := client.Config()
	say("tunnel: configured in %d ms — address %s, workers=%d", time.Since(t0).Milliseconds(), conf.TunnelIP, conf.Workers)

	t, err := openTUN(o.tunName, o.mtu)
	if err != nil {
		say("FAILED: %v", err)
		return 1
	}
	defer t.close()
	if err := configureTUN(t.name, conf.TunnelIP, o.mtu); err != nil {
		say("FAILED: %s", maskLine(err.Error()))
		return 1
	}
	gateway := conf.TunnelIP[:strings.LastIndex(conf.TunnelIP, ".")+1] + "1"
	for _, r := range o.routes {
		if err := routeVia(t.name, r, gateway); err != nil {
			say("FAILED: route: %s", maskLine(err.Error()))
			return 1
		}
	}
	dev.Store(t)
	say("tun: %s up, mtu %d, %d route(s) through it", t.name, o.mtu, len(o.routes))

	// TUN → the server.
	readErr := make(chan error, 1)
	var noStream atomic.Int64
	go func() {
		for {
			pkts, err := t.read()
			if err != nil {
				readErr <- err
				return
			}
			for _, p := range pkts {
				tunTx.Add(1)
				if err := client.Send(p); err != nil {
					if errors.Is(err, csqtt25.ErrNoStream) {
						noStream.Add(1)
					} else {
						tunErr.Add(1)
					}
				}
			}
		}
	}()

	var end <-chan time.Time
	if o.duration > 0 {
		end = time.After(o.duration)
	}
	tick := time.NewTicker(o.statsEvery)
	defer tick.Stop()
	prev, prevAt := client.Stats(), time.Now()
	line := func(label string) {
		s, now := client.Stats(), time.Now()
		dt := now.Sub(prevAt).Seconds()
		if dt <= 0 {
			dt = 1
		}
		say("%s: ready %d/%d (asked %d) | up %.2f Mbit/s, down %.2f Mbit/s | pkts tx %d rx %d | frags tx %d rx %d | sessions %d, ended %d, allocations %d, creds %d | dtls %d, fallbacks %d | probes %d, repairs %d, server restarts %d | no-stream %d, auth-fail %d, tun-err %d, early %d",
			label, s.Ready, s.Target, s.Workers,
			float64(s.TxBytes-prev.TxBytes)*8/dt/1e6, float64(s.RxBytes-prev.RxBytes)*8/dt/1e6,
			s.TxPackets, s.RxPackets, s.FragsTx, s.FragsRx, s.Sessions, s.Restarts, allocs.Load(), creds.minted.Load(),
			s.Handshakes, s.Fallbacks, s.Probes, s.Repairs, s.PanelRestarts, s.NoStream, s.AuthFailures, tunErr.Load(), early.Load())
		prev, prevAt = s, now
	}
	code := 0
loop:
	for {
		select {
		case <-ctx.Done():
			say("stopping: signal")
			break loop
		case <-end:
			say("stopping: -duration over")
			break loop
		case <-client.Done():
			say("FAILED: the client ended: %v", client.Err())
			code = 1
			break loop
		case err := <-readErr:
			say("FAILED: tun read: %v", err)
			code = 1
			break loop
		case <-tick.C:
			line("stats")
		}
	}
	line("final")
	return code
}
