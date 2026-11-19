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
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
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

// A review of the first cut: the adapter told the pool of a refusal and had no
// word for a session that came UP, so a relay it had marked stayed marked — a
// recovery check came up through it and the next worker was still sent to the
// spare relay. The lease's Established — the session READY, the server
// answering through the relay — clears the mark. An accepted allocation and a
// granted permission are not that word.
func TestCsqttAnEstablishedSessionClearsTheRefusalsMark(t *testing.T) {
	const other = "203.0.113.50:19302"
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	dials := map[string]func(creds csqtt.TURNCredentials, allocated func()) (func(), error){
		"2.1.9": func(creds csqtt.TURNCredentials, allocated func()) (func(), error) {
			r, err := csqtt.DialRelay(creds, peer, "udp", logging.LogLevelError, allocated)
			if err != nil {
				return nil, err
			}
			return func() { r.Close() }, nil
		},
		"2.5": func(creds csqtt.TURNCredentials, allocated func()) (func(), error) {
			r, err := csqtt25DialRelay(context.Background(), creds, peer, "udp", allocated)
			if err != nil {
				return nil, err
			}
			return func() { r.Close() }, nil
		},
	}
	for generation, dial := range dials {
		t.Run(generation, func(t *testing.T) {
			relay := newPermissionRefusingRelay(t, 0)
			user := freshUsername("mended")
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
			// A path event stands behind every real start: the pool judges a
			// session's word by when its dial BEGAN against it, so the lease has to
			// say that moment (an unset one reads as a session of the old network).
			pool.OnPathChange()
			leaseOn := func(worker int, want, why string) csqtt.Credential {
				t.Helper()
				c, err := a.creds(ctx, worker)
				if err != nil {
					t.Fatalf("worker %d's lease: %v", worker, err)
				}
				if c.Address != want {
					t.Fatalf("worker %d was leased the refusing relay: %v, the other: %v — %s", worker, c.Address == relay.addr, c.Address == other, why)
				}
				return c
			}
			// Worker 2 holds a lease on the relay from BEFORE the mark.
			early := leaseOn(2, relay.addr, "fixture: the first relay VK names")
			first := leaseOn(1, relay.addr, "fixture: the first relay VK names")
			began := time.Now()
			_, derr := dial(first.TURNCredentials, func() { first.Allocated(began) })
			if !proxy.IsPeerRefused(derr) {
				t.Fatalf("fixture: the relay did not refuse the peer (%v)", derr)
			}
			first.Failed(derr, began)
			first.Release()
			leaseOn(3, other, "the relay refused the peer: it is marked").Release()

			// The relay's list is mended; worker 2's session comes up through it.
			relay.refusing.Store(false)
			began = time.Now()
			closeRelay, derr := dial(early.TURNCredentials, func() { early.Allocated(began) })
			if derr != nil {
				t.Fatalf("fixture: the mended relay failed the dial: %v", derr)
			}
			defer closeRelay()
			leaseOn(4, other, "an accepted allocation and a granted permission are not the session's word: the mark stands").Release()
			early.Established()
			leaseOn(5, relay.addr, "a session came up through the relay: its mark is cleared and it is handed out again").Release()
			if n := mints.Load(); n != 1 {
				t.Fatalf("%d credential(s) minted, want the first alone", n)
			}
		})
	}
}

// The wiring of 2.5: the dialer hands the lease's Established to the conn, and
// the conn the engine is handed (a csqtt25.ReadyNoter) calls it when the engine
// says its stream is ready.
type readyHookConn struct {
	net.PacketConn
	hooks []func()
}

func (c *readyHookConn) onReady(f func()) { c.hooks = append(c.hooks, f) }

func TestCsqtt25TheLeaseHearsThatItsStreamIsReady(t *testing.T) {
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for _, withWord := range []bool{true, false} {
		conn := &readyHookConn{}
		prev := csqtt25OpenRelay
		csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
			return conn, func() {}, nil
		}
		established := 0
		lease := func(context.Context, int) (csqtt.Credential, error) {
			c := csqtt.Credential{Allocated: func(time.Time) {}, Failed: func(error, time.Time) {}, Release: func() {}}
			if withWord {
				c.Established = func() { established++ }
			}
			return c, nil
		}
		_, _, closer, err := (&csqtt25Client{}).dialer(server, "udp", lease)(context.Background(), 1)
		csqtt25OpenRelay = prev
		if err != nil {
			t.Fatal(err)
		}
		closer()
		if !withWord {
			if len(conn.hooks) != 0 {
				t.Fatal("a lease with no Established was handed to the conn as a hook")
			}
			continue
		}
		if len(conn.hooks) != 1 || established != 0 {
			t.Fatalf("the dialer handed the conn %d hook(s) and the lease heard %d — want one hook, nothing said before the stream is ready", len(conn.hooks), established)
		}
		conn.hooks[0]()
		if established != 1 {
			t.Fatalf("the hook is not the lease's Established (%d)", established)
		}
	}

	// The real conn: the engine's word reaches the dialer's hook.
	r := &csqtt25Relay{}
	var noter csqtt25.ReadyNoter = csqtt25RelayConn{r: r}
	noter.StreamReady() // no hook: nothing to do, nothing to break
	said := 0
	csqtt25RelayConn{r: r}.onReady(func() { said++ })
	noter.StreamReady()
	if said != 1 {
		t.Fatalf("the engine's word reached the dialer's hook %d time(s), want once", said)
	}
}
