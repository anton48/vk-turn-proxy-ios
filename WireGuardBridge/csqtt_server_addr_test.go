package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
)

// The line says what the server's name became and how long the lookup took;
// an address given as such is said to be one; and an address no relay on the
// internet can deliver to is called by its kind. Every fixture address is a
// documentation, private, loopback, link-local or carrier-NAT one; the range
// boundaries are built from numbers, so that no real address stands here.
func TestCsqttServerAddrLineSaysWhatTheNameBecame(t *testing.T) {
	udp := func(ip net.IP, port int) *net.UDPAddr { return &net.UDPAddr{IP: ip, Port: port} }
	lit := func(s string) net.IP { return net.ParseIP(s) }
	const head = "csqttStart: tunnel 3: "
	const tail = ", not a public one: a relay on the internet cannot deliver to it, so the server will not answer"
	for _, tc := range []struct {
		name, server string
		addr         *net.UDPAddr
		took         time.Duration
		want         string
	}{
		{"a name", "srv.example.org:56004", udp(lit("203.0.113.7"), 56004), 1234567 * time.Microsecond,
			head + "the server's name srv.example.org resolved to 203.0.113.7:56004 in 1.235s"},
		{"a quick lookup, to the millisecond", "srv.example.org:56004", udp(lit("198.51.100.20"), 56004), 4400 * time.Microsecond,
			head + "the server's name srv.example.org resolved to 198.51.100.20:56004 in 4ms"},
		{"an address given as such", "203.0.113.7:56004", udp(lit("203.0.113.7"), 56004), 5 * time.Second,
			head + "the server is given by address 203.0.113.7:56004 — nothing to resolve"},
		{"a name without a port", "srv.example.org", udp(lit("203.0.113.7"), 0), time.Millisecond,
			head + "the server's name srv.example.org resolved to 203.0.113.7:0 in 1ms"},
		{"a name that became a private address", "srv.example.org:56004", udp(lit("192.168.1.10"), 56004), 20 * time.Millisecond,
			head + "the server's name srv.example.org resolved to 192.168.1.10:56004 in 20ms — a PRIVATE address" + tail},
		{"10/8", "srv.example.org:1", udp(lit("10.1.2.3"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 10.1.2.3:1 in 1ms — a PRIVATE address" + tail},
		{"172.16/12", "srv.example.org:1", udp(lit("172.31.255.254"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 172.31.255.254:1 in 1ms — a PRIVATE address" + tail},
		{"just above 172.16/12 is public", "srv.example.org:1", udp(net.IPv4(172, 32, 0, 1), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to " + net.IPv4(172, 32, 0, 1).String() + ":1 in 1ms"},
		{"a private address given as such", "192.168.1.10:56004", udp(lit("192.168.1.10"), 56004), 0,
			head + "the server is given by address 192.168.1.10:56004 — nothing to resolve — a PRIVATE address" + tail},
		{"a filtering resolver's zero address", "srv.example.org:1", udp(lit("0.0.0.0"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 0.0.0.0:1 in 1ms — the UNSPECIFIED address" + tail},
		{"loopback", "srv.example.org:1", udp(lit("127.0.0.1"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 127.0.0.1:1 in 1ms — a LOOPBACK address" + tail},
		{"link-local", "srv.example.org:1", udp(lit("169.254.1.1"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 169.254.1.1:1 in 1ms — a LINK-LOCAL address" + tail},
		{"carrier NAT, its first address", "srv.example.org:1", udp(lit("100.64.0.1"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 100.64.0.1:1 in 1ms — a CARRIER-NAT address" + tail},
		{"carrier NAT, its last", "srv.example.org:1", udp(lit("100.127.255.254"), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to 100.127.255.254:1 in 1ms — a CARRIER-NAT address" + tail},
		{"just below carrier NAT is public", "srv.example.org:1", udp(net.IPv4(100, 63, 255, 1), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to " + net.IPv4(100, 63, 255, 1).String() + ":1 in 1ms"},
		{"just above carrier NAT is public", "srv.example.org:1", udp(net.IPv4(100, 128, 0, 1), 1), time.Millisecond,
			head + "the server's name srv.example.org resolved to " + net.IPv4(100, 128, 0, 1).String() + ":1 in 1ms"},
	} {
		if got := csqttServerAddrLine(3, tc.server, tc.addr, tc.took); got != tc.want {
			t.Errorf("%s:\n got  %q\n want %q", tc.name, got, tc.want)
		}
	}
}

// The one body asks once, for an IPv4 address of the server as configured,
// hands back exactly what it was answered, and says it — with the time the
// lookup really took.
func TestCsqttResolveServerSaysTheAddressAndTheLookupsTime(t *testing.T) {
	prev := csqttResolveUDP
	t.Cleanup(func() { csqttResolveUDP = prev })
	want := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 56004}
	var asked atomic.Int32
	var network, name atomic.Value
	csqttResolveUDP = func(n, s string) (*net.UDPAddr, error) {
		asked.Add(1)
		network.Store(n)
		name.Store(s)
		time.Sleep(60 * time.Millisecond)
		return want, nil
	}
	var out lockedLog
	prevW := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prevW) })

	got, err := csqttResolveServer(7, "srv.example.org:56004")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || !got.IP.Equal(want.IP) || got.Port != want.Port {
		t.Fatalf("handed back %v, want %v", got, want)
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("the resolver was asked %d times, want once", n)
	}
	if network.Load() != "udp4" || name.Load() != "srv.example.org:56004" {
		t.Fatalf("the resolver was asked (%v, %v), want (udp4, the server as configured)", network.Load(), name.Load())
	}
	said := serverAddrLines(&out)
	if len(said) != 1 {
		t.Fatalf("%d lines about the server's address, want one:\n%s", len(said), strings.Join(out.lines(), "\n"))
	}
	m := regexp.MustCompile(`tunnel 7: the server's name srv\.example\.org resolved to 203\.0\.113\.7:56004 in ([0-9.]+m?s)$`).FindStringSubmatch(said[0])
	if m == nil {
		t.Fatalf("the line does not say the name, the address and a time: %q", said[0])
	}
	took, err := time.ParseDuration(m[1])
	if err != nil || took < 60*time.Millisecond || took > 2*time.Second {
		t.Fatalf("the line says the lookup took %q; it took at least 60ms", m[1])
	}
}

// A lookup that failed is the caller's to report: its error comes back as it
// is and nothing is said about an address.
func TestCsqttResolveServerSaysNothingOfAFailedLookup(t *testing.T) {
	prev := csqttResolveUDP
	t.Cleanup(func() { csqttResolveUDP = prev })
	boom := errors.New("no such host")
	csqttResolveUDP = func(string, string) (*net.UDPAddr, error) { return nil, boom }
	var out lockedLog
	prevW := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prevW) })

	got, err := csqttResolveServer(7, "srv.example.org:56004")
	if !errors.Is(err, boom) || got != nil {
		t.Fatalf("got (%v, %v), want (nil, the lookup's own error)", got, err)
	}
	if said := serverAddrLines(&out); len(said) != 0 {
		t.Fatalf("a failed lookup was said as an address: %q", said)
	}
}

// The tunnel's start resolves its server through that one body: the line is in
// the log, under the tunnel's own number, by the time the client is dialled —
// and the client is dialled to the address the line names.
func TestCsqttStartSaysWhatItsServerBecameBeforeItDials(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	fc := newFakeClient()
	csqttSeededSettle = 0
	var out lockedLog
	prevW := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prevW) })

	prevR := csqttResolveUDP
	t.Cleanup(func() { csqttResolveUDP = prevR })
	want := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 56002}
	var asked atomic.Int32
	csqttResolveUDP = func(string, string) (*net.UDPAddr, error) { asked.Add(1); return want, nil }

	type dialled struct {
		server *net.UDPAddr
		said   []string
	}
	captured := make(chan dialled, 1)
	prevD := csqttDial
	csqttDial = func(_ context.Context, cfg csqtt.Config) (csqttClient, error) {
		captured <- dialled{cfg.Server, serverAddrLines(&out)}
		return fc, nil
	}
	t.Cleanup(func() { csqttDial = prevD })

	h := startCsqtt(t, "")
	select {
	case d := <-captured:
		if n := asked.Load(); n != 1 {
			t.Fatalf("the start asked the one body's resolver %d times, want once", n)
		}
		if d.server == nil || !d.server.IP.Equal(want.IP) || d.server.Port != want.Port {
			t.Fatalf("the client was dialled to %v, want the resolved %v", d.server, want)
		}
		if len(d.said) != 1 {
			t.Fatalf("%d lines about the server's address by the dial, want one", len(d.said))
		}
		if !strings.Contains(d.said[0], fmt.Sprintf("csqttStart: tunnel %d: ", h)) || !strings.Contains(d.said[0], "198.51.100.20:56002") {
			t.Fatalf("the line is not this tunnel's or names another address: %q", d.said[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the client was never dialled")
	}
}

// serverAddrLines are the log's lines about what the server's address is.
func serverAddrLines(out *lockedLog) []string {
	var said []string
	for _, l := range out.lines() {
		if strings.Contains(l, "the server's name ") || strings.Contains(l, "the server is given by address ") {
			said = append(said, l)
		}
	}
	return said
}
