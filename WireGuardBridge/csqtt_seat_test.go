package main

// A seat a csqtt session USED — its Allocate accepted by the relay — and gave
// back stays counted through the relay's second, WHATEVER ended the session: a
// CreatePermission that fails right behind the Allocate too (the user's review of
// build 430). The whole chain, nothing faked: csqtt.Dial's own worker and
// DialRelay, the pool adapter, the pool — and a pion TURN server on loopback that
// accepts the Allocate, refuses the permission, and keeps a deallocated seat on
// the quota for a while, as the VK relay does.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// permissionRefusingRelay: ONE seat per identity, held `lag` behind its
// deallocate; every Allocate within the quota accepted, every permission refused.
type permissionRefusingRelay struct {
	addr     string
	accepted atomic.Int32
	refused  atomic.Int32
}

func newPermissionRefusingRelay(t *testing.T, lag time.Duration) *permissionRefusingRelay {
	t.Helper()
	r := &permissionRefusingRelay{}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		srvRef  atomic.Pointer[turn.Server]
		mu      sync.Mutex
		deleted []time.Time
	)
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
		},
		QuotaHandler: func(string, string, net.Addr) bool {
			s := srvRef.Load()
			if s == nil {
				return true
			}
			held := 0
			mu.Lock()
			for _, at := range deleted {
				if time.Since(at) < lag {
					held++
				}
			}
			mu.Unlock()
			if s.AllocationCount()+held < 1 {
				r.accepted.Add(1)
				return true
			}
			r.refused.Add(1)
			return false
		},
		EventHandler: turn.EventHandler{
			OnAllocationDeleted: func(net.Addr, net.Addr, string, string, string) {
				mu.Lock()
				deleted = append(deleted, time.Now())
				mu.Unlock()
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
			PermissionHandler:     func(net.Addr, net.IP) bool { return false },
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srvRef.Store(srv)
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
	})
	r.addr = pc.LocalAddr().String()
	return r
}

func TestCsqttASeatUsedBehindAFailedPermissionStaysCountedForTheRelaysSecond(t *testing.T) {
	relay := newPermissionRefusingRelay(t, 400*time.Millisecond)
	user := freshUsername("seat")
	fetch := func(bool, int) (string, *proxy.TURNCreds, error) {
		return relay.addr, &proxy.TURNCreds{Username: user, Password: "pw", Address: relay.addr, Addresses: []string{relay.addr}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := proxy.NewCredPool(ctx, proxy.CredPoolConfig{VKLink: "abc", NumConns: 10, Fetch: fetch})
	defer pool.Close()
	a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { t.Errorf("fatal: %v", err) }}
	prevBackstop := csqttAcquireBackstop
	csqttAcquireBackstop, csqttAcquireBackstopMax = time.Hour, time.Hour
	defer func() { csqttAcquireBackstop, csqttAcquireBackstopMax = prevBackstop, 5*time.Second }()

	// Nine seats of the identity are out; the client's one worker takes the tenth.
	for k := 2; k <= 10; k++ {
		if _, err := a.creds(ctx, k); err != nil {
			t.Fatalf("lease %d: %v", k, err)
		}
	}
	var (
		mu       sync.Mutex
		calls    []string
		said     []string // the client's own log lines
		failure  error
		released = make(chan time.Time, 1)
		leased   = make(chan struct{})
	)
	note := func(what string) { mu.Lock(); calls = append(calls, what); mu.Unlock() }
	first := true
	clientCreds := func(cctx context.Context, workerID int) (csqtt.Credential, error) {
		if !first {
			<-cctx.Done() // one session is the whole experiment: the worker's retry parks here
			return csqtt.Credential{}, cctx.Err()
		}
		first = false
		c, err := a.creds(cctx, workerID)
		if err != nil {
			return c, err
		}
		close(leased)
		allocated, failed, release := c.Allocated, c.Failed, c.Release
		c.Allocated = func() { note("allocated"); allocated() }
		c.Failed = func(err error) { note("failed"); mu.Lock(); failure = err; mu.Unlock(); failed(err) }
		c.Release = func() {
			note("release")
			release()
			select {
			case released <- time.Now():
			default:
			}
		}
		return c, nil
	}
	gen, salt := csqtt.NewIdentity(0)
	dialCtx, stopDial := context.WithCancel(ctx)
	defer stopDial()
	dialed := make(chan struct{})
	go func() {
		defer close(dialed)
		c, err := csqtt.Dial(dialCtx, csqtt.Config{
			Server: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, Password: "stand", DeviceID: "stand-device",
			Generation: gen, Salt: salt, Workers: 1, Creds: clientCreds, TURNTransport: "udp",
			StartPacing: 5 * time.Millisecond, TURNLogLevel: logging.LogLevelError,
			Logf: func(format string, args ...any) {
				mu.Lock()
				said = append(said, fmt.Sprintf(format, args...))
				mu.Unlock()
			},
		})
		if err == nil {
			_ = c.Close()
		} else if dialCtx.Err() == nil {
			t.Errorf("fixture: csqtt.Dial ended by itself: %v", err)
		}
	}()
	t.Cleanup(func() { stopDial(); <-dialed })

	// The eleventh taker parks: the identity is full by the pool's count — once the
	// client's worker holds the tenth seat.
	select {
	case <-leased:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: the client's worker never took its lease")
	}
	type seat struct {
		at    time.Time
		lease csqtt.Credential
	}
	seated := make(chan seat, 1)
	go func() {
		if c, err := a.creds(ctx, 11); err == nil {
			seated <- seat{time.Now(), c}
		}
	}()

	var at time.Time
	select {
	case at = <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture: the client's session never gave its lease back")
	}
	mu.Lock()
	order, err := strings.Join(calls, " → "), failure
	mu.Unlock()
	if relay.accepted.Load() != 1 || err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("fixture: the relay accepted %d Allocate(s) and the session failed with %v — want ONE accepted Allocate and a permission error behind it", relay.accepted.Load(), err)
	}
	mu.Lock()
	lines := 0
	for _, l := range said {
		if strings.Contains(l, "the relay ACCEPTED the allocation and a step behind it failed") {
			lines++
		}
	}
	mu.Unlock()
	if lines != 1 {
		t.Errorf("the client said %d time(s) that a seat was used by a session that never came up, want once — a log that shows a cooled lease has to say why", lines)
	}
	if order != "allocated → failed → release" {
		t.Errorf("the lease heard %q, want %q: the relay ACCEPTED the Allocate — the seat was used and given back, and the pool is not told", order, "allocated → failed → release")
	}
	var next seat
	select {
	case next = <-seated:
		if took := next.at.Sub(at); took < time.Second {
			t.Errorf("the next taker was seated %s after the release of a seat the relay still holds for a second", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next taker was still parked five seconds after the release")
	}
	// …and what the next taker then meets at the relay, as its worker would: the
	// Allocate (the permission fails behind it here too — that is not the point).
	if r, err := csqtt.DialRelay(next.lease.TURNCredentials, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, "udp", logging.LogLevelError, next.lease.Allocated); err != nil {
		next.lease.Failed(err)
	} else {
		r.Close()
	}
	next.lease.Release()
	if n := relay.refused.Load(); n != 0 {
		t.Errorf("the relay REFUSED %d Allocate(s) with 486 — the next taker's reached it inside the second it still held the seat", n)
	}
	if st := pool.Stats(); st.Saturated != 0 || st.QuotaRefusals != 0 {
		t.Errorf("%d slot(s) benched as VK-saturated, %d quota refusal(s) told to the pool — want none: a good identity lost for eleven minutes over a second of the relay's own", st.Saturated, st.QuotaRefusals)
	}
}
