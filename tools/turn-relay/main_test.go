// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// testRelay: the relay on 127.0.0.1 with ephemeral ports, every peer allowed
// being 127.0.0.1 unless told otherwise.
func testRelay(t *testing.T, maxAllocs int64, peers ...string) *relay {
	t.Helper()
	if len(peers) == 0 {
		peers = []string{"127.0.0.1"}
	}
	cfg, err := parseConfig("127.0.0.1:0", "", strings.Join(peers, ","), maxAllocs, "40000-40100", "vk-turn-relay", false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	return r
}

// vkClient: a pion client as the app's — the credentials VK's shape, a
// password this relay does not know.
func vkClient(t *testing.T, addr string, conn net.PacketConn) *turn.Client {
	t.Helper()
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr, TURNServerAddr: addr, Conn: conn,
		Username: "1793400000:1125900188966338", Password: "a-password-the-relay-never-saw", Realm: "vk-turn-relay",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestTheRelayAcceptsCredentialsItCannotVerify(t *testing.T) {
	r := testRelay(t, 8)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := vkClient(t, r.udp[0].String(), conn)
	relayConn, err := c.Allocate()
	if err != nil {
		t.Fatalf("Allocate with credentials the relay cannot verify: %v — the fork's point", err)
	}
	defer relayConn.Close()
	if host, _, _ := net.SplitHostPort(relayConn.LocalAddr().String()); host != "127.0.0.1" {
		t.Fatalf("the relay address %s — want the public IP (the listen IP here)", relayConn.LocalAddr())
	}
	// The relay socket behind it is bound on every interface (0.0.0.0), not
	// on the loopback listener's address: the peers are elsewhere.
	_, port, _ := net.SplitHostPort(relayConn.LocalAddr().String())
	if out, err := exec.Command("lsof", "-nP", "-iUDP:"+port).Output(); err == nil && !strings.Contains(string(out), "*:"+port) {
		t.Fatalf("the relay socket on port %s is not bound on every interface:\n%s", port, out)
	}
	if r.active.Load() != 1 {
		t.Fatalf("allocations held: %d, want 1", r.active.Load())
	}
	// Data goes through to an allowed peer and comes back.
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := peer.ReadFrom(buf)
		if err == nil {
			_, _ = peer.WriteTo(buf[:n], from)
		}
	}()
	if _, err := relayConn.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo the allowed peer: %v", err)
	}
	buf := make([]byte, 1500)
	_ = relayConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := relayConn.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("the echo through the relay: %q %v", buf[:n], err)
	}
	// A peer not in -peer: the permission is refused (403) — the relay is no
	// open one.
	_ = relayConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := relayConn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 9}); err == nil {
		t.Fatal("WriteTo a peer outside -peer went through — an open relay")
	}
	relayConn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for r.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r.active.Load() != 0 {
		t.Fatalf("allocations held after the close: %d", r.active.Load())
	}
}

func TestTheRelayCapsTheAllocations(t *testing.T) {
	r := testRelay(t, 1)
	var conns []net.PacketConn
	for i := 0; i < 2; i++ {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		defer conn.Close()
	}
	first, err := vkClient(t, r.udp[0].String(), conns[0]).Allocate()
	if err != nil {
		t.Fatalf("the first allocation: %v", err)
	}
	defer first.Close()
	if _, err := vkClient(t, r.udp[0].String(), conns[1]).Allocate(); err == nil || !strings.Contains(err.Error(), "486") {
		t.Fatalf("the second allocation over -max-allocs 1: %v — want 486", err)
	}
}

func TestTheRelayListensOnTCPToo(t *testing.T) {
	r := testRelay(t, 8)
	tcp, err := net.Dial("tcp", r.tcp[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	c := vkClient(t, r.tcp[0].String(), turn.NewSTUNConn(tcp))
	relayConn, err := c.Allocate()
	if err != nil {
		t.Fatalf("Allocate over TCP: %v", err)
	}
	relayConn.Close()
}

// allocatePort takes one allocation over UDP or TCP, says its relay port and
// gives it back.
func allocatePort(t *testing.T, r *relay, overTCP bool) int {
	t.Helper()
	var c *turn.Client
	if overTCP {
		tcp, err := net.Dial("tcp", r.tcp[0].String())
		if err != nil {
			t.Fatal(err)
		}
		defer tcp.Close()
		c = vkClient(t, r.tcp[0].String(), turn.NewSTUNConn(tcp))
	} else {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		c = vkClient(t, r.udp[0].String(), conn)
	}
	relayConn, err := c.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer relayConn.Close()
	return relayConn.LocalAddr().(*net.UDPAddr).Port
}

func rangeRelay(t *testing.T, ports string) *relay {
	t.Helper()
	cfg, err := parseConfig("127.0.0.1:0", "", "127.0.0.1", 64, ports, "vk-turn-relay", false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	return r
}

// The server names a session by the address it arrives from: a relay port
// handed out again while the server still holds the session that had it is the
// old session to the server, and the new one's handshake goes unanswered (the
// stand of 2026-10-30: 12 of 17 such sessions timed out, 3 of 95 others). Every
// port of the range is used before one comes back, over UDP and TCP listeners
// alike.
func TestTheRelayDoesNotReissueAPortUntilTheRangeIsWalked(t *testing.T) {
	r := rangeRelay(t, "40200-40209")
	seen := map[int]int{}
	for i := 0; i < 10; i++ {
		port := allocatePort(t, r, i%2 == 1)
		if port < 40200 || port > 40209 {
			t.Fatalf("allocation %d on port %d, outside the range", i, port)
		}
		if at, again := seen[port]; again {
			t.Fatalf("allocation %d got port %d again, allocation %d's, with the range not walked: %v", i, port, at, seen)
		}
		seen[port] = i
	}
}

// A port something else holds is passed over, not fatal.
func TestTheRelaySkipsABusyPort(t *testing.T) {
	r := rangeRelay(t, "40220-40223")
	first := allocatePort(t, r, false)
	next := 40220 + (first-40220+1)%4
	busy, err := net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(next)))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if got := allocatePort(t, r, false); got == next || got == first {
		t.Fatalf("port %d with %d busy and %d just used", got, next, first)
	}
}

func TestTheConfigIsChecked(t *testing.T) {
	for _, tc := range []struct{ listen, pub, peers, ports, want string }{
		{"0.0.0.0:3478", "", "203.0.113.5", "49152-49352", "-public-ip is required"},
		{"127.0.0.1:3478", "", "", "49152-49352", "-peer is required"},
		{"127.0.0.1:3478", "", "not-an-ip", "49152-49352", "not an IP"},
		{"127.0.0.1:3478", "", "203.0.113.5", "49352-49152", "-relay-ports"},
		{"nonsense", "", "203.0.113.5", "49152-49352", "-listen"},
	} {
		_, err := parseConfig(tc.listen, tc.pub, tc.peers, 8, tc.ports, "r", false, t.Logf)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc, err, tc.want)
		}
	}
	cfg, err := parseConfig("0.0.0.0:3478,[::]:3478", "198.51.100.7", "203.0.113.5, 203.0.113.6", 8, "49152-49352", "r", false, t.Logf)
	if err != nil || len(cfg.listen) != 2 || cfg.publicIP.String() != "198.51.100.7" || len(cfg.peers) != 2 || cfg.minPort != 49152 || cfg.maxPort != 49352 {
		t.Fatalf("%+v %v", cfg, err)
	}
	var nilErr error
	if !errors.Is(nilErr, nil) {
		t.Fatal("unreachable")
	}
}
