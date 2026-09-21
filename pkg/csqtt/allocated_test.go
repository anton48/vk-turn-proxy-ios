package csqtt

// The lease hears of its allocation the moment the relay ACCEPTS it — before
// the permission, from DialRelay itself — and exactly once (the user's review of
// build 430). A session whose permission fails behind an accepted Allocate has
// USED its seat and gives it back on the way out; the VK relay keeps a
// deallocated seat on the quota for a second more, so a pool that was told
// nothing handed that seat to the next taker at once — 486, and the slot benched.

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// dialRelayStand is a pion TURN server on loopback, UDP and TCP, that accepts or
// refuses the Allocate and the permission as told, and says what it was asked.
type dialRelayStand struct {
	udp, tcp    string
	permissions atomic.Int32 // CreatePermission requests that reached the permission handler
	onPermit    func()       // called as the permission is asked, before it is answered
}

func newDialRelayStand(t *testing.T, acceptAllocate, permit bool) *dialRelayStand {
	t.Helper()
	s := &dialRelayStand{}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gen := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	permission := func(net.Addr, net.IP) bool {
		s.permissions.Add(1)
		if s.onPermit != nil {
			s.onPermit()
		}
		return permit
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
		},
		QuotaHandler:      func(string, string, net.Addr) bool { return acceptAllocate },
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: gen, PermissionHandler: permission}},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: ln, RelayAddressGenerator: gen, PermissionHandler: permission}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // the server goes only after its allocations have
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
	})
	s.udp, s.tcp = pc.LocalAddr().String(), ln.Addr().String()
	return s
}

func (s *dialRelayStand) addr(transport string) string {
	if transport == "tcp" {
		return s.tcp
	}
	return s.udp
}

func TestDialRelayReportsTheAllocationTheMomentTheRelayAcceptsIt(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport+": the permission fails BEHIND an accepted Allocate — the allocation is reported, and before the permission was asked", func(t *testing.T) {
			s := newDialRelayStand(t, true, false)
			var reported atomic.Int32
			var reportedWhenAsked atomic.Int32
			s.onPermit = func() { reportedWhenAsked.Store(reported.Load()) }
			relay, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: s.addr(transport)}, peer, transport, logging.LogLevelError, func() { reported.Add(1) })
			if err == nil {
				relay.Close()
				t.Fatal("fixture: DialRelay succeeded against a relay that refuses every permission")
			}
			if !strings.Contains(err.Error(), "create permission") || s.permissions.Load() == 0 {
				t.Fatalf("fixture: DialRelay failed with %v after %d permission request(s) — want the permission's failure", err, s.permissions.Load())
			}
			if n := reported.Load(); n != 1 {
				t.Errorf("the allocation was reported %d time(s), want 1: the relay ACCEPTED the Allocate — the seat was used, is given back on the way out, and the pool is not told", n)
			}
			if n := reportedWhenAsked.Load(); n != 1 {
				t.Errorf("%d allocation(s) reported by the time the permission was asked, want 1 — the fact is reported where it becomes true, not from a successful return", n)
			}
		})
		t.Run(transport+": the control — the Allocate is refused: nothing is reported", func(t *testing.T) {
			s := newDialRelayStand(t, false, true)
			var reported atomic.Int32
			relay, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: s.addr(transport)}, peer, transport, logging.LogLevelError, func() { reported.Add(1) })
			if err == nil {
				relay.Close()
				t.Fatal("fixture: DialRelay succeeded against a relay that refuses every Allocate")
			}
			if !strings.Contains(err.Error(), "turn allocate") {
				t.Fatalf("fixture: DialRelay failed with %v — want the Allocate's refusal", err)
			}
			if n := reported.Load(); n != 0 {
				t.Errorf("an allocation the relay REFUSED was reported %d time(s): a seat nobody used would be cooled", n)
			}
		})
		t.Run(transport+": the relay comes up — reported once, and a nil callback is no bookkeeping", func(t *testing.T) {
			s := newDialRelayStand(t, true, true)
			var reported atomic.Int32
			relay, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: s.addr(transport)}, peer, transport, logging.LogLevelError, func() { reported.Add(1) })
			if err != nil {
				t.Fatalf("DialRelay: %v", err)
			}
			relay.Close()
			if n := reported.Load(); n != 1 {
				t.Errorf("the allocation was reported %d time(s), want 1", n)
			}
			relay, err = DialRelay(TURNCredentials{Username: "u2", Password: "pw", Address: s.addr(transport)}, peer, transport, logging.LogLevelError, nil)
			if err != nil {
				t.Fatalf("DialRelay with no callback: %v", err)
			}
			relay.Close()
		})
	}
}

// Through the worker: a session's lease hears of its allocation ONCE — from
// DialRelay, which the worker hands the lease's callback to — not once more from
// the worker itself.
func TestALeaseHearsOfItsAllocationExactlyOncePerSession(t *testing.T) {
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	l := &lease{}
	c := dialReady(t, testConfig(srv, 3, l.creds))
	defer c.Close()
	heard := func() (acquires, allocated int) {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.acquires, l.allocated
	}
	if acq, alloc := heard(); acq != 3 || alloc != 3 {
		t.Fatalf("three sessions up: %d lease(s) taken, %d allocation(s) heard of — want 3 and 3", acq, alloc)
	}
	before, _, _ := srv.counts()
	c.OnPathChange()
	waitFor(t, "every worker re-announced after the path change", func() bool {
		g, _, _ := srv.counts()
		return g >= before+3 && c.Stats().Ready == 3
	})
	if acq, alloc := heard(); alloc != acq {
		t.Errorf("after the path change: %d lease(s) taken, %d allocation(s) heard of — want one per session", acq, alloc)
	}
}
