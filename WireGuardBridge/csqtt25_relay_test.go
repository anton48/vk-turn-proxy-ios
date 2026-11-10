package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
)

// deadlineConn records the write deadlines it is given and the writes made
// through it; nothing else of a PacketConn is used by the tests that hold one.
type deadlineConn struct {
	net.PacketConn
	mu        sync.Mutex
	deadlines []time.Time
	writes    int
}

func (d *deadlineConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadlines = append(d.deadlines, t)
	return nil
}

func (d *deadlineConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes++
	return len(p), nil
}

func (d *deadlineConn) got() ([]time.Time, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.deadlines...), d.writes
}

// The engine's socket: datagrams go through the relayed conn, the write
// deadline goes on the CONTROL socket — the relayed conn's own is a stub, and
// a bound set on it bounds nothing.
func TestCsqtt25RelayPutsTheWriteDeadlineOnTheControlSocket(t *testing.T) {
	relayed, ctl := &deadlineConn{}, &deadlineConn{}
	r := &csqtt25Relay{relayed: relayed, ctl: ctl, close: func() {}}
	pc := r.packetConn()
	at := time.Now().Add(time.Second)
	if err := pc.SetWriteDeadline(at); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	onCtl, ctlWrites := ctl.got()
	onRelayed, relayedWrites := relayed.got()
	if len(onCtl) != 2 || !onCtl[0].Equal(at) || !onCtl[1].IsZero() || len(onRelayed) != 0 {
		t.Fatalf("deadlines on the control socket %v, on the relayed conn %v; want the bound and its clearing on the control socket, none on the relayed conn", onCtl, onRelayed)
	}
	if relayedWrites != 1 || ctlWrites != 0 {
		t.Fatalf("writes: %d through the relayed conn, %d on the control socket; want 1 and 0", relayedWrites, ctlWrites)
	}
}

// 🚨 Clearing the deadline while the allocation is being closed leaves the
// close's own budget in place: the deallocate that the close writes must not
// be left unbounded on a socket that is stuck.
func TestCsqtt25RelayClearingTheDeadlineUnderACloseKeepsTheClosesBudget(t *testing.T) {
	relayed, ctl := &deadlineConn{}, &deadlineConn{}
	r := &csqtt25Relay{relayed: relayed, ctl: ctl, close: func() {}}
	pc := r.packetConn()
	r.Close()
	before := time.Now()
	if err := pc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	onCtl, _ := ctl.got()
	if len(onCtl) != 1 || onCtl[0].IsZero() {
		t.Fatalf("a clearing under a close left the control socket with %v — want the close's budget, not no deadline", onCtl)
	}
	if d := onCtl[0].Sub(before); d < csqtt25RelayCloseBudget-50*time.Millisecond || d > csqtt25RelayCloseBudget+time.Second {
		t.Fatalf("the deadline put back is %s away, want the close's budget (%s)", d, csqtt25RelayCloseBudget)
	}
	at := time.Now().Add(3 * time.Second) // a real deadline under a close is set as asked
	_ = pc.SetWriteDeadline(at)
	if onCtl, _ = ctl.got(); len(onCtl) != 2 || !onCtl[1].Equal(at) {
		t.Fatalf("a deadline set under a close: %v, want it as asked", onCtl)
	}
}

// The close: its budget on the control socket FIRST, then the relayed conn
// (the deallocate), the TURN client, the control socket — and once.
func TestCsqtt25RelayClosesInOrderUnderItsBudgetAndOnce(t *testing.T) {
	var order []string
	ctl := &closeRecorder{name: "ctl", order: &order}
	relayed := &closeRecorder{name: "relayed", order: &order}
	closes := 0
	r := &csqtt25Relay{relayed: relayed, ctl: ctl}
	r.close = func() {
		closes++
		csqtt25CloseRelay(ctl, relayed, func() { order = append(order, "client") })
	}
	before := time.Now()
	r.Close()
	r.Close()
	want := []string{"ctl deadline", "relayed close", "client", "ctl close"}
	if closes != 1 || len(order) != len(want) {
		t.Fatalf("closed %d time(s), steps %v; want once: %v", closes, order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("the close's steps %v, want %v", order, want)
		}
	}
	if d := ctl.deadline.Sub(before); d < csqtt25RelayCloseBudget-50*time.Millisecond || d > csqtt25RelayCloseBudget+time.Second {
		t.Fatalf("the close's write budget is %s, want %s", d, csqtt25RelayCloseBudget)
	}
}

type closeRecorder struct {
	net.PacketConn
	name     string
	order    *[]string
	deadline time.Time
}

func (c *closeRecorder) SetWriteDeadline(t time.Time) error {
	c.deadline = t
	*c.order = append(*c.order, c.name+" deadline")
	return nil
}

func (c *closeRecorder) Close() error {
	*c.order = append(*c.order, c.name+" close")
	return nil
}

// relayTURN is a pion TURN server on loopback, TCP and UDP, that knows one
// credential (u / pw in realm okcdn.ru); it returns the address for the
// transport asked. It is closed only after its connections have released
// their allocations (pion/turn v5.0.2's server races itself otherwise).
func relayTURN(t *testing.T, transport string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gen := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == "u" {
				return "u", key, true
			}
			return "", nil, false
		},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: ln, RelayAddressGenerator: gen}},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: gen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n := srv.AllocationCount(); n != 0 {
			t.Errorf("relayTURN: %d allocation(s) still held as the server closes", n)
		}
		_ = srv.Close()
	})
	if transport == "udp" {
		return pc.LocalAddr().String()
	}
	return ln.Addr().String()
}

// 🚨 The real stack, over TCP (what the app ships on) and over UDP: the
// bridge's own dial allocates, says so the moment the relay accepts, carries a
// datagram to the server's address through the relay — and a write deadline
// set on the conn it hands out is REAL: with one already past the write fails
// as a write past its deadline, where pion's relayed conn, asked the same,
// writes on.
func TestCsqtt25DialRelayAllocatesCarriesAndBounds(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) { dialCarryAndBound(t, transport) })
	}
}

func dialCarryAndBound(t *testing.T, transport string) {
	relayAddr := relayTURN(t, transport)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	allocated := 0
	r, err := csqtt25DialRelay(csqtt.TURNCredentials{Username: "u", Password: "pw", Address: relayAddr},
		server.LocalAddr().(*net.UDPAddr), transport, func() { allocated++ })
	if err != nil {
		t.Fatalf("the dial: %v", err)
	}
	defer r.Close()
	if allocated != 1 {
		t.Fatalf("the relay's acceptance was told %d time(s), want once", allocated)
	}
	pc := r.packetConn()
	if _, err := pc.WriteTo([]byte("through the relay"), server.LocalAddr()); err != nil {
		t.Fatalf("a write through the allocation: %v", err)
	}
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := server.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "through the relay" {
		t.Fatalf("the server got %q (%v), want the datagram", buf[:n], err)
	}
	// A deadline already past: the write must not go out.
	if err := pc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = pc.WriteTo([]byte("too late"), server.LocalAddr())
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write past its deadline returned %v, want the deadline's own error — the deadline did not reach the socket the write waits on", err)
	}
	// Cleared, the allocation carries again.
	_ = pc.SetWriteDeadline(time.Time{})
	if _, err := pc.WriteTo([]byte("again"), server.LocalAddr()); err != nil {
		t.Fatalf("a write behind the cleared deadline: %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err = server.ReadFromUDP(buf); err != nil || string(buf[:n]) != "again" {
		t.Fatalf("behind the cleared deadline the server got %q (%v)", buf[:n], err)
	}
}

// A dial's failures are worded as csqtt.DialRelay words them, and what was
// opened is given back.
func TestCsqtt25DialRelaySaysItsFailuresAsThe219DialDoes(t *testing.T) {
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if _, err := csqtt25DialRelay(csqtt.TURNCredentials{}, server, "sctp", nil); err == nil || err.Error() != `unknown TURN transport "sctp"` {
		t.Fatalf("an unknown transport: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close() // nobody listens there now
	_, err = csqtt25DialRelay(csqtt.TURNCredentials{Username: "u", Password: "pw", Address: dead}, server, "tcp", nil)
	if err == nil || len(err.Error()) < 18 || err.Error()[:18] != "dial tcp to relay:" {
		t.Fatalf("a relay that refuses the connection: %v", err)
	}
	// A credential the relay does not know: refused at the Allocate, and the acceptance is never told.
	told := 0
	_, err = csqtt25DialRelay(csqtt.TURNCredentials{Username: "nobody", Password: "x", Address: relayTURN(t, "tcp")}, server, "tcp", func() { told++ })
	if err == nil || len(err.Error()) < 14 || err.Error()[:14] != "turn allocate:" || told != 0 {
		t.Fatalf("a refused Allocate: %v (the acceptance told %d time(s))", err, told)
	}
}

// What the dial owes whoever leases it a credential and the relay it talks
// to, read off the source — none of it shows in a run against a relay that
// accepts everything: the acceptance is told BEFORE the permission (a
// permission that fails behind an accepted Allocate used a seat all the
// same), and the local socket's and the allocation's address family are
// STATED (inferred from a dual-stack socket, pion asks VK's relay for IPv6
// and is answered with silence).
func TestCsqtt25DialRelayTellsTheAcceptanceFirstAndStatesItsFamily(t *testing.T) {
	src, err := os.ReadFile("csqtt25_relay.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	alloc, told, perm := strings.Index(s, "relayed, err := tc.Allocate()"), strings.Index(s, "		allocated()\n"), strings.Index(s, "tc.CreatePermission(server)")
	if alloc < 0 || told < 0 || perm < 0 || !(alloc < told && told < perm) {
		t.Fatalf("the Allocate at %d, the acceptance told at %d, the permission at %d — want them in that order", alloc, told, perm)
	}
	for _, want := range []string{`net.ListenUDP("udp4",`, `.Dial("tcp4", creds.Address)`, "RequestedAddressFamily: family,"} {
		if !strings.Contains(s, want) {
			t.Errorf("the dial does not state its address family: %s is gone", want)
		}
	}
}

// pipeCtl is a control socket that really blocks: one end of a net.Pipe that
// nobody reads, so a write waits until its deadline — the TCP connection to a
// relay that stopped taking bytes. The FIRST clearing of the write deadline is
// held at the socket's door until the test lets it through.
type pipeCtl struct {
	net.Conn
	entered chan struct{} // closed when the first clearing has arrived
	pass    chan struct{} // closed to let it through
	once    sync.Once
	mu      sync.Mutex
	set     []time.Time
}

func (p *pipeCtl) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		first := false
		p.once.Do(func() { first = true })
		if first {
			close(p.entered)
			<-p.pass
		}
	}
	p.mu.Lock()
	p.set = append(p.set, t)
	p.mu.Unlock()
	return p.Conn.SetWriteDeadline(t)
}

func (p *pipeCtl) WriteTo(b []byte, _ net.Addr) (int, error) { return p.Conn.Write(b) }

func (p *pipeCtl) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Conn.Read(b)
	return n, nil, err
}

func (p *pipeCtl) deadlines() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Time(nil), p.set...)
}

// deallocOnClose is a relayed conn whose Close writes on the control socket,
// as pion's does (the deallocate).
type deallocOnClose struct {
	net.PacketConn
	ctl   net.PacketConn
	began chan struct{}
	err   error
}

func (d *deallocOnClose) Close() error {
	close(d.began)
	_, d.err = d.ctl.WriteTo([]byte("deallocate"), nil)
	return nil
}

// 🚨 The clearing and the close do not take turns. A clearing that has looked
// — no close under way — and reaches the socket only AFTER the close has set
// its deadline there must not leave the socket without one: the deallocate
// would wait on a relay that takes no bytes for ever, and with it the
// session's end, its allocation and its lease.
func TestCsqtt25RelayAClearingThatLandsBehindTheClosesDeadlineLeavesTheCloseBounded(t *testing.T) {
	near, far := net.Pipe()
	defer far.Close()
	ctl := &pipeCtl{Conn: near, entered: make(chan struct{}), pass: make(chan struct{})}
	relayed := &deallocOnClose{ctl: ctl, began: make(chan struct{})}
	r := &csqtt25Relay{relayed: relayed, ctl: ctl}
	r.close = func() { csqtt25CloseRelay(ctl, relayed, nil) }
	pc := r.packetConn()

	cleared := make(chan struct{})
	go func() { // the engine, behind a write of its own
		_ = pc.SetWriteDeadline(time.Time{})
		close(cleared)
	}()
	<-ctl.entered // it has looked: no close under way — and stands at the socket's door

	closed := make(chan struct{})
	began := time.Now()
	go func() {
		r.Close()
		close(closed)
	}()
	<-relayed.began // the close has set its deadline and is writing the deallocate
	close(ctl.pass) // … and only now does the clearing land

	select {
	case <-closed:
	case <-time.After(csqtt25RelayCloseBudget + 3*time.Second):
		near.Close() // let the stuck write go: nothing may outlive the test
		<-closed
		t.Fatalf("the close had not returned %s after it began (its budget is %s): the clearing wiped the close's deadline and the deallocate was left unbounded",
			time.Since(began).Round(100*time.Millisecond), csqtt25RelayCloseBudget)
	}
	<-cleared
	if !errors.Is(relayed.err, os.ErrDeadlineExceeded) {
		t.Fatalf("the deallocate's write ended with %v, want the deadline's own error", relayed.err)
	}
	set := ctl.deadlines()
	if len(set) == 0 || set[len(set)-1].IsZero() {
		t.Fatalf("the last write deadline put on the control socket is none (%d set): the close's budget has to stand there", len(set))
	}
}
