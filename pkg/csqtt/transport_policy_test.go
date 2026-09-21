// SPDX-License-Identifier: MIT
package csqtt

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
)

func TestTransportPolicyCooldownAndPathEpoch(t *testing.T) {
	var p transportPolicy
	now := time.Unix(1000, 0)
	name, epoch := p.pick(now)
	if name != "udp" {
		t.Fatal(name)
	}
	p.failure(epoch, name, now)
	if name, _ = p.pick(now.Add(time.Second)); name != "tcp" {
		t.Fatal(name)
	}
	p.success(epoch, "tcp", 50*time.Millisecond, now.Add(time.Second))
	if name, _ = p.pick(now.Add(2 * time.Second)); name != "tcp" {
		t.Fatal(name)
	}
	p.reset()
	p.failure(epoch, "udp", now) // late result from the previous network
	p.success(epoch, "tcp", time.Millisecond, now)
	if name, _ = p.pick(now); name != "udp" {
		t.Fatal("stale result contaminated new path", name)
	}
}

func TestTransportPolicyExploresWithoutFlapping(t *testing.T) {
	var p transportPolicy
	now := time.Now()
	_, e := p.pick(now)
	p.success(e, "udp", 100*time.Millisecond, now)
	if n, _ := p.pick(now); n != "tcp" {
		t.Fatal("missing alternate sample", n)
	}
	p.success(e, "tcp", 90*time.Millisecond, now)
	if n, _ := p.pick(now); n != "udp" {
		t.Fatal("10% difference switched preference", n)
	}
	p.success(e, "tcp", time.Millisecond, now)
	if n, _ := p.pick(now); n != "tcp" {
		t.Fatal("material improvement ignored", n)
	}
	if n, _ := p.pick(now.Add(transportSampleAge)); n != "udp" {
		t.Fatal("stale alternate never retried", n)
	}
}

func TestAutoTransportFallsBackAndResetsOnPathChange(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	prev := dialRelayContext
	var mu sync.Mutex
	var attempted []string
	dialRelayContext = func(ctx context.Context, cred TURNCredentials, peer *net.UDPAddr, transport string, level logging.LogLevel, allocated func()) (*Relay, error) {
		mu.Lock()
		attempted = append(attempted, transport)
		mu.Unlock()
		if transport == "udp" {
			return nil, &net.OpError{Op: "dial", Net: "udp", Err: context.DeadlineExceeded}
		}
		return dialRelay(cred, peer, transport, level, allocated)
	}
	t.Cleanup(func() { dialRelayContext = prev })
	cfg := testConfig(srv, 1, (&lease{}).creds)
	cfg.TURNTransport = "auto"
	c := dialReady(t, cfg)
	defer c.Close()
	if got := c.Stats().Workers[0].Transport; got != "tcp" {
		t.Fatal(got)
	}
	c.OnPathChange()
	waitFor(t, "UDP retried on the new network", func() bool { mu.Lock(); defer mu.Unlock(); return len(attempted) >= 3 })
	mu.Lock()
	defer mu.Unlock()
	if attempted[0] != "udp" || attempted[1] != "tcp" || attempted[2] != "udp" {
		t.Fatal(attempted)
	}
}

func TestDialRelayContextCancelsSilentTURN(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	r, err := DialRelayContext(ctx, TURNCredentials{Address: conn.LocalAddr().String(), Username: "u", Password: "p"}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}, "udp", logging.LogLevelDisabled, nil)
	if r != nil {
		r.Close()
		t.Fatal("allocation returned after cancellation")
	}
	if err == nil || ctx.Err() == nil {
		t.Fatal("silent TURN did not time out", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation did not interrupt Allocate")
	}
}

func TestManualTransportDoesNotUseAutoDial(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	prev := dialRelayContext
	dialRelayContext = func(context.Context, TURNCredentials, *net.UDPAddr, string, logging.LogLevel, func()) (*Relay, error) {
		return nil, errors.New("auto dial must not be used")
	}
	t.Cleanup(func() { dialRelayContext = prev })
	for _, transport := range []string{"udp", "tcp"} {
		cfg := testConfig(srv, 1, (&lease{}).creds)
		cfg.TURNTransport = transport
		c := dialReady(t, cfg)
		if c.Stats().Workers[0].Transport != transport {
			t.Fatal("manual mode changed")
		}
		c.Close()
	}
}
