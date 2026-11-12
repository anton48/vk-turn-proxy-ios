package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
)

// Each mark closes the stretch that began at the mark before it.
func TestCsqtt25StageClockClosesEachStretchAtItsMark(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	c := csqtt25StageClock{from: t0}
	c.mark("connect", t0.Add(10*time.Millisecond))
	c.mark("allocation", t0.Add(50*time.Millisecond))
	c.mark("permission", t0.Add(55*time.Millisecond))
	want := []csqtt25.Stage{{Name: "connect", Took: 10 * time.Millisecond}, {Name: "allocation", Took: 40 * time.Millisecond}, {Name: "permission", Took: 5 * time.Millisecond}}
	if len(c.list) != len(want) {
		t.Fatalf("got %v, want %v", c.list, want)
	}
	for i := range want {
		if c.list[i] != want[i] {
			t.Fatalf("stretch %d: got %v, want %v", i, c.list[i], want[i])
		}
	}
}

func stageNames(st []csqtt25.Stage) (names []string, sum time.Duration) {
	for _, s := range st {
		names = append(names, s.Name)
		sum += s.Took
	}
	return names, sum
}

// 🚨 The real stack: the conn the dial hands the engine says what the dial was
// made of — the connect over TCP, the allocation, the permission, in that
// order, adding up to the dial — and, once the dialer has said it, the wait for
// the credential in front of them.
func TestCsqtt25DialRelaySaysWhatItsDialWasMadeOf(t *testing.T) {
	for transport, want := range map[string][]string{"tcp": {"connect", "allocation", "permission"}, "udp": {"allocation", "permission"}} {
		t.Run(transport, func(t *testing.T) {
			relayAddr := relayTURN(t, transport)
			server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
			from := time.Now()
			r, err := csqtt25DialRelay(context.Background(), csqtt.TURNCredentials{Username: "u", Password: "pw", Address: relayAddr}, server, transport, nil)
			wall := time.Since(from)
			if err != nil {
				t.Fatalf("the dial: %v", err)
			}
			defer r.Close()
			stager, ok := r.packetConn().(csqtt25.DialStager)
			if !ok {
				t.Fatal("the conn the engine is handed does not say what its dial was made of")
			}
			names, sum := stageNames(stager.DialStages())
			if len(names) != len(want) {
				t.Fatalf("the dial's stretches are %v, want %v", names, want)
			}
			for i := range want {
				if names[i] != want[i] {
					t.Fatalf("the dial's stretches are %v, want %v", names, want)
				}
			}
			if sum > wall || wall-sum > 100*time.Millisecond {
				t.Fatalf("the stretches add up to %v, the dial took %v", sum, wall)
			}
			r.packetConn().(interface{ noteLease(time.Duration) }).noteLease(70 * time.Millisecond)
			st := stager.DialStages()
			if len(st) != len(want)+1 || st[0] != (csqtt25.Stage{Name: "lease", Took: 70 * time.Millisecond}) || st[1].Name != want[0] {
				t.Fatalf("the wait for the credential is not the first stretch: %v", st)
			}
		})
	}
}

// A slow step is booked under its OWN name: a relay whose first permission
// request is lost answers the repeat two tenths of a second later — that is the
// permission's time, not the allocation's.
func TestCsqtt25DialRelayBooksASlowPermissionUnderThePermission(t *testing.T) {
	relayAddr := relayTURN(t, "udp")
	tap := newPermTap(t, relayAddr)
	tap.drop.Store(true)
	go func() { // the first request is lost, the repeat goes through
		deadline := time.Now().Add(5 * time.Second)
		for tap.dropped.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		tap.drop.Store(false)
	}()
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	r, err := csqtt25DialRelay(context.Background(), csqtt.TURNCredentials{Username: "u", Password: "pw", Address: tap.front.LocalAddr().String()}, server, "udp", nil)
	if err != nil {
		t.Fatalf("the dial: %v", err)
	}
	defer r.Close()
	st := r.packetConn().(csqtt25.DialStager).DialStages()
	if len(st) != 2 || st[0].Name != "allocation" || st[1].Name != "permission" {
		t.Fatalf("the dial's stretches are %v", st)
	}
	if st[1].Took < 150*time.Millisecond {
		t.Fatalf("the permission waited for its repeat and is booked at %v: %v", st[1].Took, st)
	}
	if st[0].Took >= 150*time.Millisecond {
		t.Fatalf("the allocation was answered at once and is booked at %v: %v", st[0].Took, st)
	}
}

// leaseConn is a relay conn as the dialer sees it: it takes the lease's wait.
type leaseConn struct {
	net.PacketConn
	leased []time.Duration
}

func (c *leaseConn) noteLease(d time.Duration) { c.leased = append(c.leased, d) }

// The dialer says how long the stream waited for its credential — from before
// the lease is asked to the moment it is had, not the dial behind it.
func TestCsqtt25DialerSaysHowLongTheLeaseWasWaitedFor(t *testing.T) {
	conn := &leaseConn{}
	prev := csqtt25OpenRelay
	csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
		time.Sleep(200 * time.Millisecond) // the dial behind the lease: not the lease's time
		return conn, func() {}, nil
	}
	t.Cleanup(func() { csqtt25OpenRelay = prev })
	lease := func(context.Context, int) (csqtt.Credential, error) {
		time.Sleep(80 * time.Millisecond) // a pool's pause, a park
		return csqtt.Credential{
			Allocated: func(time.Time) {},
			Failed:    func(error, time.Time) {},
			Release:   func() {},
		}, nil
	}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	_, _, closer, err := (&csqtt25Client{}).dialer(server, "udp", lease)(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if len(conn.leased) != 1 {
		t.Fatalf("the lease's wait was said %d times, want once", len(conn.leased))
	}
	if d := conn.leased[0]; d < 80*time.Millisecond || d >= 200*time.Millisecond {
		t.Fatalf("the lease was waited for 80 ms and the dial behind it took 200: said %v", d)
	}
}
