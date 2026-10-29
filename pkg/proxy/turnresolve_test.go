package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Issue #105 (1): a DNS name in the TURN override list. The name reached the
// pool as it was, the dial resolved it, and the host published for the
// tunnel's remote address was the NAME — iOS refused the settings ("Invalid
// NETunnelNetworkSettings tunnelRemoteAddress") and the tunnel stopped; the
// first dial also lost 5 s to a lookup that timed out in the extension. Names
// are resolved to IPs BEFORE the pool sees the list — from the app's
// pre-resolved map, else a bounded lookup — and only an IP is ever published.

const (
	nameRelay = "relay.example:19302"
	nameHost  = "relay.example"
	ipR1      = "203.0.113.21"
	ipR2      = "203.0.113.22"
)

func TestResolveTURNServersExpandsNamesToIPs(t *testing.T) {
	pre := func(host string) []string {
		if host == nameHost {
			return []string{ipR1, ipR2}
		}
		return nil
	}
	got := ResolveTURNServers(context.Background(), []string{nameRelay, "203.0.113.5:19302", nameRelay}, pre)
	want := []string{ipR1 + ":19302", ipR2 + ":19302", "203.0.113.5:19302"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the list with a name: %v, want %v (the name's IPs in its place, the IP entry kept, duplicates dropped)", got, want)
	}
	// Not pre-resolved: a bounded lookup; it fails → the name stays (the dial
	// resolves it later, and no name is published as the tunnel's address).
	old := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = old })
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "other.example" {
			return []net.IP{net.ParseIP("203.0.113.30"), net.ParseIP("2001:db8::1")}, nil
		}
		return nil, errors.New("no such host")
	}
	got = ResolveTURNServers(context.Background(), []string{"other.example:3478", "dead.example:3478"}, nil)
	want = []string{"203.0.113.30:3478", "dead.example:3478"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the lookup path: %v, want %v (IPv4 only; a name that does not resolve stays)", got, want)
	}
}

func TestNewProxyResolvesTheOverrideNamesBeforeThePool(t *testing.T) {
	SetVKHostIPs(map[string][]string{nameHost: {ipR1, ipR2}})
	t.Cleanup(func() { SetVKHostIPs(nil) })
	p := NewProxy(Config{VKLink: "https://vk.ru/call/join/abc123", PeerAddr: "127.0.0.1:1", TurnServers: []string{nameRelay, "203.0.113.5:19302"}})
	t.Cleanup(p.Stop)
	p.credPool.mu.Lock()
	servers := strings.Join(p.credPool.override.servers, ",")
	p.credPool.mu.Unlock()
	if servers != ipR1+":19302,"+ipR2+":19302,203.0.113.5:19302" {
		t.Fatalf("the pool's override list: %s — want the name expanded to the app's pre-resolved IPs", servers)
	}
	// The console's pool the same.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 1, TurnServers: []string{nameRelay},
		Fetch: func(bool, int) (string, *TURNCreds, error) { return "", nil, errors.New("no") }})
	defer cp.Close()
	cp.cp.mu.Lock()
	servers = strings.Join(cp.cp.override.servers, ",")
	cp.cp.mu.Unlock()
	if servers != ipR1+":19302,"+ipR2+":19302" {
		t.Fatalf("the CredPool's override list: %s — want the name expanded", servers)
	}
}

func TestTheRelayHostPublishedIsAnIPOrNothing(t *testing.T) {
	p := &Proxy{}
	creds := &TURNCreds{Username: futureUser("x"), Password: "p", Address: nameRelay, Addresses: []string{nameRelay}}
	p.relayAllocatedAt(0, creds, nameRelay, time.Now())
	if got := p.TURNServerIP(); got != "" {
		t.Fatalf("a relay dialled by NAME published %q as the tunnel's remote address — iOS takes an IP only", got)
	}
	p.relayAllocatedAt(0, creds, "203.0.113.9:19302", time.Now())
	if got := p.TURNServerIP(); got != "203.0.113.9" {
		t.Fatalf("an IP relay: %q", got)
	}
	p.relayAllocatedAt(0, creds, nameRelay, time.Now())
	if got := p.TURNServerIP(); got != "203.0.113.9" {
		t.Fatalf("a later name must not replace the last IP: %q", got)
	}
	// The console's / csqtt's pool publishes the same way.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 1, Fetch: func(bool, int) (string, *TURNCreds, error) { return "", nil, errors.New("no") }})
	defer cp.Close()
	cp.NoteAllocatedAt(0, creds, nameRelay, time.Now())
	if got := cp.RelayIP(); got != "" {
		t.Fatalf("CredPool published a name: %q", got)
	}
	cp.NoteAllocatedAt(0, creds, "203.0.113.9:19302", time.Now())
	if got := cp.RelayIP(); got != "203.0.113.9" {
		t.Fatalf("CredPool with an IP relay: %q", got)
	}
}
