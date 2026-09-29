package main

// The process resolver. Sabotage seen red: the network's servers not used in
// turn; no fallback to the system's configuration when none is known; a DNS
// server not pinned before the query.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTheProxysLookupsGoToTheNetworksServersInTurn(t *testing.T) {
	// Two loopback addresses stand in for the network's DNS servers (a UDP
	// "dial" sends nothing, it only fixes the far end); the resolver's Dial
	// must reach them in turn and pin each first.
	src := &dnsSource{}
	var pinned []string
	src.set([]string{"127.0.0.1", "127.0.0.2"})
	dial := resolverDial(src, func(ip string) error { pinned = append(pinned, ip); return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var remotes []string
	for i := 0; i < 3; i++ {
		c, err := dial(ctx, "udp", "192.0.2.53:53")
		if err != nil {
			t.Fatal(err)
		}
		remotes = append(remotes, c.RemoteAddr().String())
		c.Close()
	}
	if strings.Join(remotes, ",") != "127.0.0.1:53,127.0.0.2:53,127.0.0.1:53" {
		t.Fatalf("queries went to %q — the network's servers, in turn", remotes)
	}
	if strings.Join(pinned, ",") != "127.0.0.1,127.0.0.2,127.0.0.1" {
		t.Fatalf("pinned %q — each server before its query", pinned)
	}
	src.set(nil)
	c, err := dial(ctx, "udp", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != "192.0.2.53:53" {
		t.Fatalf("with no network servers known the query went to %s, want the system's", c.RemoteAddr())
	}
}
