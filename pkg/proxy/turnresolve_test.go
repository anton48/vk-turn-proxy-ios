package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
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

// The user's review of 453, (1): RelayIP's fallback — the first host the pool
// holds — bypassed the IP-only guard: in cookie mode a credential's address
// stays a name when its resolution failed, and csqttGetRelayIP carried the
// name into iOS's settings again.
func TestRelayIPNeverFallsBackToAName(t *testing.T) {
	cookieTestMode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 1, Fetch: func(bool, int) (string, *TURNCreds, error) { return "", nil, errors.New("no") }})
	defer cp.Close()
	cp.cp.seedSlot(0, nameRelay, &TURNCreds{Username: futureUser("named"), Password: "p", Address: nameRelay, Addresses: []string{nameRelay}})
	if got := cp.RelayIP(); got != "" {
		t.Fatalf("RelayIP fell back to a NAME: %q — an IP or nothing, the fallback included", got)
	}
	cp.cp.seedSlot(1, "203.0.113.9:19302", &TURNCreds{Username: futureUser("ip"), Password: "p", Address: "203.0.113.9:19302", Addresses: []string{"203.0.113.9:19302"}})
	if got := cp.RelayIP(); got != "203.0.113.9" {
		t.Fatalf("RelayIP's fallback skips the name and takes the IP the pool holds: %q", got)
	}
}

// (2): the pool got the resolved list while the cookie minter was still handed
// the ORIGINAL one — a name resolving to two IPs made two pool slots but the
// minter knew one relay: slot 1 "unfilled" with the second IP in the pool.
// One resolved list for both, in both constructors.
func TestTheCookieMinterUsesThePoolsResolvedList(t *testing.T) {
	links := []string{"https://vk.ru/call/join/abcdef"}
	cookieTestMode(t, links...)
	cookieMu.Lock()
	cookieCache[cookieLinkID(links[0])] = &cookieCachedCred{creds: &TURNCreds{Username: futureUser("link1"), Password: "p", Address: relayA, Addresses: []string{relayA, relayB}}}
	cookieMu.Unlock()
	SetVKHostIPs(map[string][]string{nameHost: {ipR1, ipR2}})
	t.Cleanup(func() { SetVKHostIPs(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 20, TurnServers: []string{nameRelay}})
	defer cp.Close()
	if addr, _, _, err := cp.Acquire(10); err != nil || addr != ipR2+":19302" {
		t.Fatalf("CredPool, conn 10 (slot 1) under a name that resolves to two IPs: addr %q err %v — want the second IP (the minter's list is the pool's)", addr, err)
	}
	p := NewProxy(Config{VKLink: links[0], PeerAddr: "127.0.0.1:1", NumConns: 20, TurnServers: []string{nameRelay}})
	t.Cleanup(p.Stop)
	if addr, _, _, err := p.credPool.get(10, false); err != nil || addr != ipR2+":19302" {
		t.Fatalf("Proxy, conn 10 (slot 1): addr %q err %v — want the second IP", addr, err)
	}
}

// (3): a name was resolved once for the pool's whole life — a DNS change to a
// new relay never reached the client. The list is resolved again when its
// relays are exhausted (every entry marked), at a path change and on an
// invalidate; a lookup that fails keeps the list as it was.
func TestTheOverrideIsReResolvedWhenItsRelaysAreExhausted(t *testing.T) {
	old := lookupTURNHost
	t.Cleanup(func() { lookupTURNHost = old })
	var answer atomic.Value
	answer.Store("203.0.113.41")
	var lookups atomic.Int32
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP(answer.Load().(string))}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp := NewCredPool(ctx, CredPoolConfig{NumConns: 2, TurnServers: []string{nameRelay},
		Fetch: func(_ bool, slot int) (string, *TURNCreds, error) {
			return relayA, &TURNCreds{Username: futureUser("vk"), Password: "p", Address: relayA, Addresses: []string{relayA}}, nil
		}})
	defer cp.Close()
	addr, creds, slot, err := cp.Acquire(0)
	if err != nil || addr != "203.0.113.41:19302" {
		t.Fatalf("the first hand-out: %q %v", addr, err)
	}
	// DNS moves the name; the old relay goes silent with evidence → marked →
	// every relay of the list marked → the list is resolved again.
	answer.Store("203.0.113.42")
	cp.Release(slot, creds)
	cp.cp.health.answered("", time.Time{})
	cp.NoteRelayUnanswered(0, slot, creds, "203.0.113.41:19302", time.Now())
	// The resolution runs off the lock (DNS I/O): the list follows within a
	// lookup's time — a hand-out before that may still name the old relay.
	waitFor := func(want string, what string) {
		deadline := time.Now().Add(3 * time.Second)
		var last string
		var lastErr error
		for {
			a, c, s, err := cp.Acquire(1)
			if err == nil {
				cp.Release(s, c)
				if a == want {
					return
				}
				last, lastErr = a, nil
			} else {
				last, lastErr = "", err
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: after 3 s the hand-out is %q / %v, want %q (lookups %d)", what, last, lastErr, want, lookups.Load())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor("203.0.113.42:19302", "after the exhaustion")
	// A path change resolves again (the network may have another DNS view).
	answer.Store("203.0.113.43")
	cp.OnPathChange()
	waitFor("203.0.113.43:19302", "after the path change")
	// An invalidate too.
	answer.Store("203.0.113.44")
	cp.Invalidate()
	waitFor("203.0.113.44:19302", "after the invalidate")
	// A lookup that fails keeps the list.
	lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) { return nil, errors.New("no such host") }
	cp.OnPathChange()
	time.Sleep(200 * time.Millisecond) // the lookup has failed by now; the pool's post-path-change pause may still stand
	deadline := time.Now().Add(3 * time.Second)
	for {
		a, c, s, err := cp.Acquire(1)
		if err == nil {
			cp.Release(s, c)
			if a != "203.0.113.44:19302" {
				t.Fatalf("a failed lookup must keep the list: handed out %q", a)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the failed lookup: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
