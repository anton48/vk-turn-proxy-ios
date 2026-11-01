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

	"github.com/pion/stun/v3"
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
	if r.seats.count() != 1 {
		t.Fatalf("allocations held: %d, want 1", r.seats.count())
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
	for r.seats.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if r.seats.count() != 0 {
		t.Fatalf("allocations held after the close: %d", r.seats.count())
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

// allocateAll: n pion clients over TCP ask the relay for an allocation at the
// same moment; the allocations granted are returned open (the caller closes them).
func allocateAll(t *testing.T, r *relay, n int) (granted []net.PacketConn, refused486 int) {
	t.Helper()
	type res struct {
		pc  net.PacketConn
		err error
	}
	results := make(chan res, n)
	gate := make(chan struct{})
	for i := 0; i < n; i++ {
		// Over TCP: the server serves every connection on a goroutine of its
		// own, so the Allocates really run side by side (one UDP socket is
		// read by one loop — its requests never overlap).
		c := tcpClient(t, r.tcp[0].String())
		go func() {
			<-gate
			pc, err := c.Allocate()
			results <- res{pc, err}
		}()
	}
	close(gate)
	for i := 0; i < n; i++ {
		x := <-results
		switch {
		case x.err == nil:
			granted = append(granted, x.pc)
		case strings.Contains(x.err.Error(), "486"):
			refused486++
		default:
			t.Errorf("an allocation failed with neither success nor 486: %v", x.err)
		}
	}
	return granted, refused486
}

// The user's review of the tool (2026-10-31): the quota check read the count
// that OnAllocationCreated moves later — several Allocates in flight all
// passed the check before any of them was counted, and -max-allocs 1 held
// 2–6 allocations at once. The seat is reserved where the check is made.
func TestTheRelayNeverExceedsMaxAllocsUnderParallelAllocates(t *testing.T) {
	r := testRelay(t, 1)
	granted, refused := allocateAll(t, r, 12)
	for _, pc := range granted {
		defer pc.Close()
	}
	if len(granted) != 1 || refused != 11 {
		t.Fatalf("-max-allocs 1 under 12 parallel Allocates: %d granted, %d refused with 486 — want 1 and 11", len(granted), refused)
	}
	if peak := r.seats.highWater(); peak > 1 {
		t.Fatalf("the relay held %d allocations at once over -max-allocs 1", peak)
	}
}

// A reservation whose allocation then FAILED (no relay port left: the one
// port of the range is held) is given back at once — pion's error event says
// so, over either transport; a leaked reservation would refuse the next
// Allocate with 486 although only one allocation is held under -max-allocs 2.
func TestAFailedAllocationGivesItsSeatBack(t *testing.T) {
	cfg, err := parseConfig("127.0.0.1:0", "", "127.0.0.1", 2, "40070-40070", "vk-turn-relay", false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	var conns []net.PacketConn
	for i := 0; i < 3; i++ {
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
	if _, err := vkClient(t, r.udp[0].String(), conns[1]).Allocate(); err == nil || strings.Contains(err.Error(), "486") {
		t.Fatalf("the second allocation with the one relay port held: %v — want a failure that is not 486", err)
	}
	if held := r.seats.count(); held != 1 {
		t.Fatalf("after a failed allocation the relay counts %d held — want 1 (the reservation given back)", held)
	}
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for r.seats.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	third, err := vkClient(t, r.udp[0].String(), conns[2]).Allocate()
	if err != nil {
		t.Fatalf("the third allocation after the first was given back: %v — want granted", err)
	}
	third.Close()
}

// tcpClient: vkClient over a TCP connection to the relay.
func tcpClient(t *testing.T, addr string) *turn.Client {
	t.Helper()
	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	return vkClient(t, addr, turn.NewSTUNConn(tcp))
}

// requestedUDP is the REQUESTED-TRANSPORT attribute for UDP (RFC 5766 §14.7:
// the protocol number, three bytes reserved) — pion keeps its type internal.
var requestedUDP = stun.RawAttribute{Type: stun.AttrType(0x0019), Value: []byte{17, 0, 0, 0}}

// rawAllocate asks `to` for an allocation from conn the way the client does —
// an unauthenticated ask, then the ask with the realm and nonce answered — and
// says whether it was granted, else the error code. One socket, any listener.
func rawAllocate(t *testing.T, conn net.PacketConn, to net.Addr) (granted bool, code stun.ErrorCode) {
	t.Helper()
	ask := func(m *stun.Message) *stun.Message {
		if _, err := conn.WriteTo(m.Raw, to); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no answer from %s: %v", to, err)
		}
		res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := res.Decode(); err != nil {
			t.Fatal(err)
		}
		return res
	}
	first := stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest), requestedUDP, stun.Fingerprint)
	res := ask(first)
	var realm stun.Realm
	var nonce stun.Nonce
	if err := realm.GetFrom(res); err != nil {
		t.Fatalf("the first answer carries no realm: %v", err)
	}
	if err := nonce.GetFrom(res); err != nil {
		t.Fatalf("the first answer carries no nonce: %v", err)
	}
	const user = "1793400000:1125900188966338"
	second := stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest), requestedUDP,
		stun.NewUsername(user), realm, nonce, stun.NewLongTermIntegrity(user, realm.String(), "a-password-the-relay-never-saw"), stun.Fingerprint)
	res = ask(second)
	if res.Type.Class == stun.ClassSuccessResponse {
		return true, 0
	}
	var ec stun.ErrorCodeAttribute
	if err := ec.GetFrom(res); err != nil {
		t.Fatalf("an answer that is neither a success nor an error: %v", res.Type)
	}
	return false, ec.Code
}

// The user's review of 461 (3): a reservation keyed by the client's source
// let one socket's Allocates to two listeners share ONE seat — sixteen
// listeners under -max-allocs 1 held up to fifteen allocations. Every
// Allocate is its own seat: the second listener answers 486.
func TestTheLimitHoldsAcrossListeners(t *testing.T) {
	cfg, err := parseConfig("127.0.0.1:0,127.0.0.1:0", "", "127.0.0.1", 1, "40110-40130", "vk-turn-relay", false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	if len(r.udp) != 2 {
		t.Fatalf("%d UDP listeners, want 2", len(r.udp))
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if granted, code := rawAllocate(t, conn, r.udp[0]); !granted {
		t.Fatalf("the first listener refused the first allocation: %d", code)
	}
	granted, code := rawAllocate(t, conn, r.udp[1])
	if granted || code != stun.CodeAllocQuotaReached {
		t.Fatalf("the second listener under -max-allocs 1, the same source: granted %v, code %d — want 486 (one seat, not shared by source)", granted, code)
	}
	if held, peak := r.seats.count(), r.seats.highWater(); held != 1 || peak != 1 {
		t.Fatalf("held %d, high-water %d — want 1 and 1", held, peak)
	}
}

// The seats themselves: two Allocates in flight from ONE source — one socket
// asking two listeners, served by two read loops at once — are two seats, not
// a retransmit sharing one (the user's review of 461: sixteen listeners under
// -max-allocs 1 held up to fifteen allocations).
func TestTwoAllocatesInFlightFromOneSourceAreTwoSeats(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40200}
	s := newSeats(1)
	if held, ok := s.reserve(src, time.Now()); !ok || held != 1 {
		t.Fatalf("the first reservation: ok %v, held %d — want granted, 1", ok, held)
	}
	if held, ok := s.reserve(src, time.Now()); ok || held != 1 {
		t.Fatalf("a second reservation from the same source with the first still in flight under -max-allocs 1: ok %v, held %d — want refused, 1 (its own seat, not the first's)", ok, held)
	}
	s2 := newSeats(2)
	s2.reserve(src, time.Now())
	s2.reserve(src, time.Now())
	if held := s2.created(src); held != 2 {
		t.Fatalf("after the first creation: held %d, want 2 (two reservations, one confirmed)", held)
	}
	if held, ok := s2.failed(src); !ok || held != 1 {
		t.Fatalf("the second Allocate failed: ok %v, held %d — want its seat given back, 1", ok, held)
	}
	if held := s2.deleted(); held != 0 {
		t.Fatalf("after the allocation is gone: held %d, want 0", held)
	}
}

// The user's review of 462 (2): pion raises OnAllocationError for EVERY
// handling error of a source — a malformed packet on another listener from
// the same socket — and the handler gave back any pending reservation of that
// source, freeing the limit under an Allocate still in flight. Only a failed
// creation (this relay's port generator) gives a seat back.
func TestAnErrorOfAnotherPacketDoesNotGiveAReservationBack(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40300}
	r := &relay{seats: newSeats(1)}
	if _, ok := r.seats.reserve(src, time.Now()); !ok {
		t.Fatal("the reservation")
	}
	if held, back := r.allocationError(src, "failed to decode STUN message: unexpected EOF"); back || held != 1 {
		t.Fatalf("an error of another packet from the same source: given back %v, held %d — want the reservation kept, 1", back, held)
	}
	if held, back := r.allocationError(src, "allocation mismatch: 127.0.0.1:40300"); back || held != 1 {
		t.Fatalf("an Allocate refused before the quota check: given back %v, held %d — want the reservation kept, 1", back, held)
	}
	if held, back := r.allocationError(src, relayPortErr+" in 40000-40000: bind: address already in use"); !back || held != 0 {
		t.Fatalf("the creation failed in the port generator: given back %v, held %d — want the seat back, 0", back, held)
	}
}
