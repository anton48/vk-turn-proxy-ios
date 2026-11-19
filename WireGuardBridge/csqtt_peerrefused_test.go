package main

// A relay that REFUSES the permission for the csqtt server — an own relay
// started with an allow-list of peers that does not name it — is left at the
// worker's next lease. The whole chain, nothing faked: csqtt's own relay dial
// of each generation, the pool adapter, the pool, and a pion TURN server on
// loopback whose permission handler refuses the peer (the answer with no error
// code that proxy's peerrefused.go reads). The other arm is a permission
// answered 400 — a changed mapping, no verdict on the relay.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

func TestCsqttARelayThatRefusesThePeerIsLeftAtTheNextLease(t *testing.T) {
	const other = "203.0.113.50:19302" // VK's second relay with the same credential; never dialled here
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	dials := []struct {
		generation string
		dial       func(creds csqtt.TURNCredentials, allocated func()) error
	}{
		{"2.1.9", func(creds csqtt.TURNCredentials, allocated func()) error {
			r, err := csqtt.DialRelay(creds, peer, "udp", logging.LogLevelError, allocated)
			if err == nil {
				r.Close()
			}
			return err
		}},
		{"2.5", func(creds csqtt.TURNCredentials, allocated func()) error {
			_, err := csqtt25DialRelay(context.Background(), creds, peer, "udp", allocated)
			return err
		}},
	}
	for _, d := range dials {
		for _, c := range []struct {
			name   string
			refuse bool
		}{
			{"the relay refuses the peer: the next lease names the other relay", true},
			{"the permission is answered 400: no verdict, the same relay again", false},
		} {
			t.Run(d.generation+"/"+c.name, func(t *testing.T) {
				relay := newSeatRelay(t, 0, c.refuse)
				user := freshUsername("refused")
				var mints atomic.Int32
				fetch := func(bool, int) (string, *proxy.TURNCreds, error) {
					mints.Add(1)
					return relay.addr, &proxy.TURNCreds{Username: user, Password: "pw", Address: relay.addr, Addresses: []string{relay.addr, other}}, nil
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				pool := proxy.NewCredPool(ctx, proxy.CredPoolConfig{VKLink: "abc", NumConns: 10, Fetch: fetch})
				defer pool.Close()
				a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { t.Errorf("fatal: %v", err) }}

				lease, err := a.creds(ctx, 1)
				if err != nil || lease.Address != relay.addr {
					t.Fatalf("fixture: the first lease: %v (the stand's relay: %v)", err, err == nil && lease.Address == relay.addr)
				}
				began := time.Now()
				accepted := false
				derr := d.dial(lease.TURNCredentials, func() { accepted = true; lease.Allocated(began) })
				if derr == nil || !accepted {
					t.Fatalf("fixture: the dial returned %v with the allocation accepted: %v — want a failure behind an accepted allocation", derr, accepted)
				}
				if got := proxy.IsPeerRefused(derr); got != c.refuse {
					t.Fatalf("the dial's error is read as a refusal of the peer: %v, want %v", got, c.refuse)
				}
				lease.Failed(derr, began)
				lease.Release()

				next, err := a.creds(ctx, 1)
				if err != nil {
					t.Fatalf("the next lease: %v", err)
				}
				defer next.Release()
				want := relay.addr
				if c.refuse {
					want = other
				}
				if next.Address != want {
					t.Fatalf("the next lease names the refusing relay: %v, the other: %v — want %s", next.Address == relay.addr, next.Address == other,
						map[bool]string{true: "the other relay (this one will not relay to the server)", false: "the same relay (a 400 says nothing about it)"}[c.refuse])
				}
				if n := mints.Load(); n != 1 {
					t.Fatalf("%d credential(s) minted, want the first alone", n)
				}
			})
		}
	}
}
