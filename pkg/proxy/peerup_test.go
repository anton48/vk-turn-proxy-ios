package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
)

// A review of the refusal's mark, the third finding: WRAP-A and the direct
// session SET the peer mark — the relay's refusal reaches them inside the
// first write to the peer — and had no word for the session that then came UP
// through the relay. The DTLS and SRTP sessions clear the mark from their
// handshake, csqtt from its lease; these two discarded the hand-out's stamp
// and told the pool nothing. A recovery check through the mended relay came
// up, the mark stood, and the next connection was sent to the spare relay —
// the relay left to the rare checks, each of which came up and changed nothing.
//
// The stands run the session functions against a real pion relay whose
// refusal of the peer can be lifted, and a real far end: WRAP-A's obfuscation,
// DTLS and GETCONF; a peer that answers the direct session's datagram.

// switchedPermissionRelay is permissionRelay with a refusal that can be lifted
// while the stand runs.
func switchedPermissionRelay(t *testing.T, allow *atomic.Bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, "okcdn.ru", "pw"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
			PermissionHandler:     func(net.Addr, net.IP) bool { return allow.Load() },
		}},
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
	return pc.LocalAddr().String()
}

// firstDatagram hands a server-side stand the datagram it had to read to learn
// who is calling, ahead of everything that follows on the socket.
type firstDatagram struct {
	net.PacketConn
	from  net.Addr
	first []byte
}

func (c *firstDatagram) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.first != nil {
		n := copy(b, c.first)
		c.first = nil
		return n, c.from, nil
	}
	return c.PacketConn.ReadFrom(b)
}

// wrapAPeer is the far end of ONE WRAP-A session: the obfuscation, a pion DTLS
// server with the transport's one cipher, and reply as its answer to GETCONF.
func wrapAPeer(t *testing.T, key []byte, reply string) *net.UDPAddr {
	t.Helper()
	addr, _ := wrapAPeerHeld(t, key, reply, nil)
	return addr
}

// wrapAPeerHeld is wrapAPeer that says when GETCONF has been asked and, given a
// hold, answers only once it is released.
func wrapAPeerHeld(t *testing.T, key []byte, reply string, hold <-chan struct{}) (*net.UDPAddr, <-chan struct{}) {
	t.Helper()
	asked := make(chan struct{})
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var up atomic.Pointer[dtls.Conn]
	t.Cleanup(func() {
		cancel()
		if c := up.Load(); c != nil {
			_ = c.Close()
		}
		_ = pc.Close()
	})
	go func() {
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		base := &firstDatagram{PacketConn: pc, from: from, first: append([]byte(nil), buf[:n]...)}
		wpc, err := newWrapAPacketConn(base, from, key)
		if err != nil {
			return
		}
		dc, err := dtls.Server(wpc, from, &dtls.Config{
			Certificates:         []tls.Certificate{cert},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		})
		if err != nil {
			return
		}
		up.Store(dc)
		hs, done := context.WithTimeout(ctx, 5*time.Second)
		err = dc.HandshakeContext(hs)
		done()
		if err != nil {
			return
		}
		for {
			n, err := dc.Read(buf)
			if err != nil {
				return
			}
			if strings.HasPrefix(string(buf[:n]), "GETCONF:") {
				close(asked) // one session a stand: asked once
				if hold != nil {
					select {
					case <-hold:
					case <-ctx.Done():
						return
					}
				}
				_, _ = dc.Write([]byte(reply))
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr), asked
}

// wrapAConfig is a GETCONF answer the client accepts.
func wrapAConfig() string {
	k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return "[Interface]\nPrivateKey = " + k + "\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = " + k + "\n"
}

// udpPeer is the direct session's far end: it counts what reaches it, remembers
// where the last datagram came from (the relay's relayed address), and sends
// each one back while echo is on.
type udpPeer struct {
	addr *net.UDPAddr
	echo atomic.Bool
	got  atomic.Int32
	from atomic.Pointer[net.UDPAddr]
}

func newUDPPeer(t *testing.T) *udpPeer {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	peer := &udpPeer{addr: pc.LocalAddr().(*net.UDPAddr)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peer.from.Store(from)
			peer.got.Add(1)
			if peer.echo.Load() {
				_, _ = pc.WriteToUDP(buf[:n], from)
			}
		}
	}()
	return peer
}

// startSession runs one session function; the returned stop ends it and hands
// back what it returned.
func startSession(t *testing.T, run func(context.Context) error) (done <-chan struct{}, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	var result error
	go func() {
		result = run(ctx)
		close(ended)
	}()
	stop = func() error {
		cancel()
		select {
		case <-ended:
		case <-time.After(15 * time.Second):
			t.Fatal("the session did not return")
		}
		return result
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-ended:
		case <-time.After(15 * time.Second):
		}
	})
	return ended, stop
}

func peerMarked(p *Proxy, relay string) bool {
	p.credPool.mu.Lock()
	defer p.credPool.mu.Unlock()
	return p.credPool.health.isPeerFailed(relay)
}

// peerCheckDue makes the mark's next recovery check due now and reports how
// many checks have been handed out so far.
func peerCheckDue(t *testing.T, p *Proxy, relay string) int {
	t.Helper()
	p.credPool.mu.Lock()
	defer p.credPool.mu.Unlock()
	mark, ok := p.credPool.health.peerFailed[relay]
	if !ok {
		t.Fatal("fixture: the relay carries no peer mark")
	}
	mark.next = time.Now()
	p.credPool.health.peerFailed[relay] = mark
	return mark.retries
}

func peerChecksHandedOut(p *Proxy, relay string) int {
	p.credPool.mu.Lock()
	defer p.credPool.mu.Unlock()
	return p.credPool.health.peerFailed[relay].retries
}

// checksSaid counts the recovery checks of relay the pool has handed to conn 0,
// by its own line — a cleared mark keeps no count.
func checksSaid(log, relay string) int {
	return strings.Count(log, "credpool: conn 0: checking peer handshake recovery via relay "+relay+"\n")
}

// received takes the next packet the session delivered, within d.
func received(t *testing.T, p *Proxy, d time.Duration) string {
	t.Helper()
	giveUp := make(chan struct{})
	timer := time.AfterFunc(d, func() { close(giveUp) })
	defer timer.Stop()
	buf := make([]byte, 2048)
	n, err := p.ReceivePacketUntil(giveUp, buf)
	if err != nil {
		t.Fatalf("no packet came back through the relay within %s: %v", d, err)
	}
	return string(buf[:n])
}

func theRelay(got, relay, spare string) string {
	switch got {
	case relay:
		return "the relay under test"
	case spare:
		return "the spare relay"
	}
	return "another address"
}

const clearedLine = "passed its peer handshake recovery check — the mark is cleared"

func TestAWrapASessionThatComesUpClearsTheMark(t *testing.T) {
	allow := &atomic.Bool{}
	relay, spare := switchedPermissionRelay(t, allow), permissionRelay(t, true)
	p := NewProxy(Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand", UseUDP: true, NumConns: 1,
		PeerAddr:   silentPeer(t).String(),
		SeededTURN: &TURNCreds{Username: futureUser("wrapa-up"), Password: "pw", Address: relay, Addresses: []string{relay, spare}}})
	t.Cleanup(p.cancel)
	session := func(ctx context.Context) error { s := false; return p.runWrapASession(ctx, "", nil, &s, 0) }

	// The relay refuses the peer: marked from inside the first write.
	p.peer = silentPeer(t)
	_, stop := startSession(t, session)
	waitUntil(t, "the relay that refuses the peer is marked", 10*time.Second, func() bool { return peerMarked(p, relay) })
	if err := stop(); err == nil {
		t.Fatal("fixture: a session came up through a relay that refuses the peer")
	}

	// Its list is mended. A recovery check whose DTLS completes and whose
	// GETCONF the server DENIES has not come up: the mark stands.
	allow.Store(true)
	peerCheckDue(t, p, relay)
	logged := captureLog(t)
	p.peer = wrapAPeer(t, p.wrapAKey, "NOCONF")
	done, stop := startSession(t, session)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("fixture: the session against a server that denies GETCONF did not end")
	}
	if err := stop(); err == nil || !strings.Contains(err.Error(), "getconf") {
		t.Fatalf("fixture: the session against a server that denies GETCONF ended with %v", err)
	}
	if n := checksSaid(logged(), relay); n != 1 {
		t.Fatalf("fixture: %d recovery check(s) handed out, want the one", n)
	}
	if !peerMarked(p, relay) {
		t.Fatal("a session whose GETCONF was denied cleared the mark — it never came up")
	}

	// The next check comes up: DTLS, GETCONF, the session established.
	peerCheckDue(t, p, relay)
	p.peer = wrapAPeer(t, p.wrapAKey, wrapAConfig())
	_, stop = startSession(t, session)
	waitUntil(t, "the session is established", 20*time.Second, func() bool {
		return strings.Contains(logged(), "WRAP-A+TURN session established")
	})
	if n := checksSaid(logged(), relay); n != 2 {
		t.Fatalf("fixture: the session did not come up through the relay under test (%d checks handed out)", n)
	}
	time.Sleep(50 * time.Millisecond) // the report stands beside the line just seen
	if peerMarked(p, relay) {
		t.Fatal("a WRAP-A session came up through the marked relay — DTLS, GETCONF, established — and its mark stands: the relay is left to the rare checks")
	}
	if n := strings.Count(logged(), clearedLine); n != 1 {
		t.Fatalf("the clearing was said %d time(s), want once", n)
	}
	if err := stop(); err != nil {
		t.Fatalf("the established session returned %v", err)
	}
	next, creds, slot, err := p.credPool.get(0, false)
	if err != nil || next != relay {
		t.Fatalf("the next connection is handed %s (err %v) — want the relay that carries the peer again", theRelay(next, relay, spare), err)
	}
	p.credPool.release(slot, creds, next)
}

func TestADirectSessionThatHearsThePeerClearsTheMark(t *testing.T) {
	allow := &atomic.Bool{}
	relay, spare := switchedPermissionRelay(t, allow), permissionRelay(t, true)
	peer := newUDPPeer(t)
	p := NewProxy(Config{UseUDP: true, NumConns: 1, PeerAddr: peer.addr.String(),
		SeededTURN: &TURNCreds{Username: futureUser("direct-up"), Password: "pw", Address: relay, Addresses: []string{relay, spare}}})
	p.peer = peer.addr
	t.Cleanup(p.cancel)
	if !p.directMode() {
		t.Fatal("fixture: not the direct transport")
	}
	session := func(ctx context.Context) error { s := false; return p.runDirectSession(ctx, "", nil, &s, 0) }
	send := func(s string) {
		t.Helper()
		if err := p.SendPacket([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}

	// The relay refuses the peer: marked from inside the first write.
	_, stop := startSession(t, session)
	send("refused")
	waitUntil(t, "the relay that refuses the peer is marked", 10*time.Second, func() bool { return peerMarked(p, relay) })
	_ = stop()
	if peer.got.Load() != 0 {
		t.Fatalf("fixture: %d datagram(s) reached the peer past a refused permission", peer.got.Load())
	}

	// Its list is mended; the recovery check is handed out, the relay accepts
	// the allocation, grants the permission and carries our datagram to the
	// peer — which says nothing. None of that is the peer's answer.
	allow.Store(true)
	peerCheckDue(t, p, relay)
	logged := captureLog(t)
	_, stop = startSession(t, session)
	send("unanswered")
	waitUntil(t, "the datagram reaches the peer", 10*time.Second, func() bool { return peer.got.Load() == 1 })
	if n := checksSaid(logged(), relay); n != 1 {
		t.Fatalf("fixture: the session did not go through the relay under test (%d checks handed out)", n)
	}
	time.Sleep(50 * time.Millisecond)
	if !peerMarked(p, relay) {
		t.Fatal("an accepted allocation and a granted permission cleared the mark — the peer has not answered")
	}

	// A datagram through the relay from ANOTHER socket of the peer's host (a
	// permission is the host's) is not the peer's answer either.
	stranger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	if _, err := stranger.WriteToUDP([]byte("a stranger"), peer.from.Load()); err != nil {
		t.Fatal(err)
	}
	if got := received(t, p, 5*time.Second); got != "a stranger" {
		t.Fatalf("fixture: the session delivered %q, want the stranger's datagram", got)
	}
	if !peerMarked(p, relay) {
		t.Fatal("a datagram from another address than the peer's cleared the mark")
	}

	// The peer answers through the relay: the mark is cleared, once.
	peer.echo.Store(true)
	send("answered")
	if got := received(t, p, 5*time.Second); got != "answered" {
		t.Fatalf("fixture: the session delivered %q, want the peer's answer", got)
	}
	waitUntil(t, "the mark is cleared behind the peer's answer", 5*time.Second, func() bool { return !peerMarked(p, relay) })
	told := func() time.Time {
		p.credPool.mu.Lock()
		defer p.credPool.mu.Unlock()
		return p.credPool.peerHandshakes[0].window.ended
	}
	first := told()
	send("again")
	if got := received(t, p, 5*time.Second); got != "again" {
		t.Fatalf("fixture: the session delivered %q, want the peer's second answer", got)
	}
	time.Sleep(50 * time.Millisecond)
	if first.IsZero() || !told().Equal(first) {
		t.Fatalf("the pool was told again at a later datagram of the same relay leg (first %v, now %v) — once a leg, not once a packet", first, told())
	}
	if n := strings.Count(logged(), clearedLine); n != 1 {
		t.Fatalf("the clearing was said %d time(s), want once", n)
	}
	_ = stop()
	next, creds, slot, err := p.credPool.get(0, false)
	if err != nil || next != relay {
		t.Fatalf("the next connection is handed %s (err %v) — want the relay that carries the peer again", theRelay(next, relay, spare), err)
	}
	p.credPool.release(slot, creds, next)
}

// The first datagram from the peer is the DIRECT session's word alone: the
// DTLS family has a handshake above the relay and tells the pool from there —
// a datagram that is no handshake leaves the mark where it is.
func TestADatagramFromThePeerIsNotTheDTLSFamilysWord(t *testing.T) {
	relay, spare := permissionRelay(t, true), permissionRelay(t, true)
	peer := newUDPPeer(t)
	peer.echo.Store(true) // every flight comes straight back: datagrams, and no handshake
	p := NewProxy(Config{UseDTLS: true, UseUDP: true, NumConns: 1, PeerAddr: peer.addr.String(),
		SeededTURN: &TURNCreds{Username: futureUser("dtls-echo"), Password: "pw", Address: relay, Addresses: []string{relay, spare}}})
	p.peer = peer.addr
	p.dtlsHandshakeTimeout = 1500 * time.Millisecond
	t.Cleanup(p.cancel)
	p.credPool.notePeerRefused(0, relay, time.Now())
	peerCheckDue(t, p, relay)
	done, stop := startSession(t, func(ctx context.Context) error {
		s := false
		return p.runDTLSSession(ctx, "", make(chan struct{}, 1), &s, 0)
	})
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("fixture: the DTLS session against an echo did not end")
	}
	if err := stop(); err == nil {
		t.Fatal("fixture: a DTLS session came up against a peer that only echoes")
	}
	if peerChecksHandedOut(p, relay) != 1 || peer.got.Load() == 0 {
		t.Fatalf("fixture: %d check(s) handed out, %d datagram(s) at the peer — want the check through the relay under test and its flights echoed",
			peerChecksHandedOut(p, relay), peer.got.Load())
	}
	if !peerMarked(p, relay) {
		t.Fatal("a datagram from the peer cleared the mark for a DTLS session whose handshake never completed")
	}
}

// The word is ONE hand-out's and ONE attempt's: another hand-out's stamp, a
// set-up without a lease, another connection, a session that has ended and an
// attempt begun before the last path change clear nothing.
func TestTheWordThatARelayCarriedThePeerIsOneHandOutsAndOneAttempts(t *testing.T) {
	p := NewProxy(Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand", UseUDP: true, NumConns: 2, PeerAddr: "127.0.0.1:9",
		SeededTURN: &TURNCreds{Username: futureUser("word"), Password: "pw", Address: relayA, Addresses: []string{relayA, relayB}}})
	t.Cleanup(p.cancel)
	ctx := context.Background()
	p.credPool.notePeerRefused(0, relayA, time.Now())
	peerCheckDue(t, p, relayA)
	if a, creds, slot, _, err := p.resolveTURNAddr(ctx, 0, false); err != nil || a != relayA {
		t.Fatalf("fixture: the due check was not handed out (%v, %v)", a == relayA, err)
	} else {
		p.credPool.release(slot, creds, a) // an earlier hand-out of this connection
	}
	peerCheckDue(t, p, relayA)
	addr, creds, slot, gen, err := p.resolveTURNAddr(ctx, 0, false)
	if err != nil || addr != relayA || gen < 2 {
		t.Fatalf("fixture: the second check: on the marked relay %v, stamp %d, err %v", addr == relayA, gen, err)
	}
	defer p.credPool.release(slot, creds, addr)
	attempt := time.Now()
	ended, cancel := context.WithCancel(ctx)
	cancel()
	for _, c := range []struct {
		name string
		tell func()
	}{
		{"an earlier hand-out's stamp", func() { p.relayCarriedPeer(ctx, 0, gen-1, relayA, attempt) }},
		{"a set-up without a lease", func() { p.relayCarriedPeer(ctx, 0, 0, relayA, attempt) }},
		{"another connection", func() { p.relayCarriedPeer(ctx, 1, gen, relayA, attempt) }},
		{"a session that has ended", func() { p.relayCarriedPeer(ended, 0, gen, relayA, attempt) }},
	} {
		if c.tell(); !peerMarked(p, relayA) {
			t.Fatalf("the mark was cleared on the word of %s", c.name)
		}
	}
	oldNetworkThenMarked(p, relayA)
	if p.relayCarriedPeer(ctx, 0, gen, relayA, attempt); !peerMarked(p, relayA) {
		t.Fatal("an attempt begun before the path change cleared a mark set behind it")
	}
	if p.relayCarriedPeer(ctx, 0, gen, relayA, time.Now()); peerMarked(p, relayA) {
		t.Fatal("the connection's own hand-out, an attempt of this network, the session alive — and the mark stands")
	}
}

// oldNetworkThenMarked: the path changes (every mark is cleared with it) and
// relay refuses the peer on the new network.
func oldNetworkThenMarked(p *Proxy, relay string) {
	p.credPool.mu.Lock()
	p.credPool.pathChangedHealthLocked()
	p.credPool.mu.Unlock()
	p.credPool.notePeerRefused(0, relay, time.Now())
}

// Through the sessions: the relay leg, or the WRAP-A attempt, began on the old
// network — the peer's answer that arrives behind a path change is no word
// about a mark set on the new one. The attempt's start is the one the session
// took when it began, not the moment of the answer.
func TestAnAnswerToAnAttemptOfTheOldNetworkClearsNothing(t *testing.T) {
	t.Run("direct: the peer's datagram", func(t *testing.T) {
		relay := permissionRelay(t, true)
		peer := newUDPPeer(t)
		p := NewProxy(Config{UseUDP: true, NumConns: 1, PeerAddr: peer.addr.String(),
			SeededTURN: &TURNCreds{Username: futureUser("direct-old"), Password: "pw", Address: relay, Addresses: []string{relay}}})
		p.peer = peer.addr
		t.Cleanup(p.cancel)
		_, stop := startSession(t, func(ctx context.Context) error { s := false; return p.runDirectSession(ctx, "", nil, &s, 0) })
		if err := p.SendPacket([]byte("before")); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "the leg is up and its datagram at the peer", 10*time.Second, func() bool { return peer.got.Load() == 1 })
		oldNetworkThenMarked(p, relay)
		peer.echo.Store(true)
		if err := p.SendPacket([]byte("after")); err != nil {
			t.Fatal(err)
		}
		if got := received(t, p, 5*time.Second); got != "after" {
			t.Fatalf("fixture: the session delivered %q, want the peer's answer", got)
		}
		time.Sleep(50 * time.Millisecond)
		if !peerMarked(p, relay) {
			t.Fatal("the peer's answer on a leg begun before the path change cleared a mark set behind it")
		}
		_ = stop()
	})
	t.Run("WRAP-A: the GETCONF answer", func(t *testing.T) {
		relay := permissionRelay(t, true)
		p := NewProxy(Config{UseWrapA: true, WrapAPassword: "stand", DeviceID: "stand", UseUDP: true, NumConns: 1,
			PeerAddr:   silentPeer(t).String(),
			SeededTURN: &TURNCreds{Username: futureUser("wrapa-old"), Password: "pw", Address: relay, Addresses: []string{relay}}})
		t.Cleanup(p.cancel)
		hold := make(chan struct{})
		peer, asked := wrapAPeerHeld(t, p.wrapAKey, wrapAConfig(), hold)
		p.peer = peer
		logged := captureLog(t)
		_, stop := startSession(t, func(ctx context.Context) error { s := false; return p.runWrapASession(ctx, "", nil, &s, 0) })
		select {
		case <-asked:
		case <-time.After(20 * time.Second):
			t.Fatal("fixture: GETCONF never reached the server")
		}
		oldNetworkThenMarked(p, relay)
		close(hold)
		waitUntil(t, "the session is established", 20*time.Second, func() bool {
			return strings.Contains(logged(), "WRAP-A+TURN session established")
		})
		time.Sleep(50 * time.Millisecond)
		if !peerMarked(p, relay) {
			t.Fatal("a GETCONF answered on an attempt begun before the path change cleared a mark set behind it")
		}
		_ = stop()
	})
}

// The direct session starts a relay leg per hand-out: the leg that follows a
// refused one tells the pool on ITS hand-out's stamp — the session's first
// stamp is no longer the connection's. The stand's pool clock runs an hour on
// at every reading, so the mark's check is due at every hand-out: the sole
// relay is handed out again as often as it refuses, and the leg that begins
// behind the mended list is the one that comes up.
func TestADirectSessionsLaterLegTellsThePoolOnItsOwnHandOut(t *testing.T) {
	allow := &atomic.Bool{}
	relay := switchedPermissionRelay(t, allow)
	peer := newUDPPeer(t)
	peer.echo.Store(true)
	p := NewProxy(Config{UseUDP: true, NumConns: 1, PeerAddr: peer.addr.String(),
		SeededTURN: &TURNCreds{Username: futureUser("direct-leg"), Password: "pw", Address: relay, Addresses: []string{relay}}})
	p.peer = peer.addr
	t.Cleanup(p.cancel)
	var readings atomic.Int64
	base := time.Now()
	p.credPool.mu.Lock()
	p.credPool.health.now = func() time.Time { return base.Add(time.Duration(readings.Add(1)) * time.Hour) }
	p.credPool.mu.Unlock()
	stamp := func() (handOut, told uint64) {
		p.credPool.mu.Lock()
		defer p.credPool.mu.Unlock()
		return p.credPool.handStamp[0], p.credPool.peerHandshakes[0].generation
	}

	_, stop := startSession(t, func(ctx context.Context) error { s := false; return p.runDirectSession(ctx, "", nil, &s, 0) })
	quit := make(chan struct{})
	defer close(quit)
	go func() { // something to write on every leg, and nothing left in the way back
		buf := make([]byte, 2048)
		for {
			if _, err := p.ReceivePacketUntil(quit, buf); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-quit:
				return
			case <-time.After(20 * time.Millisecond):
				_ = p.SendPacket([]byte("ping"))
			}
		}
	}()
	waitUntil(t, "the first leg's relay refuses the peer and is marked", 10*time.Second, func() bool { return peerMarked(p, relay) })
	first, _ := stamp()
	allow.Store(true)
	waitUntil(t, "a later leg comes up through the mended relay and the mark is cleared", 15*time.Second, func() bool { return !peerMarked(p, relay) })
	handOut, told := stamp()
	if handOut <= first || told != handOut {
		t.Fatalf("the pool was told on stamp %d; the session's first hand-out was %d, the leg that came up is %d", told, first, handOut)
	}
	_ = stop()
}

// The relay delivers whatever the permitted HOST sends; the peer is one address.
func TestOnlyThePeersOwnAddressIsThePeer(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 51820}
	for _, c := range []struct {
		name string
		from net.Addr
		want bool
	}{
		{"the peer's address", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 51820}, true},
		{"the same address in its 4-byte form", &net.UDPAddr{IP: net.IP{192, 0, 2, 7}, Port: 51820}, true},
		{"another port of the peer's host", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 51821}, false},
		{"the peer's port on another host", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 8), Port: 51820}, false},
		{"an address of another kind", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 51820}, false},
	} {
		got, trapped := func() (got, trapped bool) {
			defer func() { trapped = recover() != nil }()
			return isFromPeer(c.from, peer), false
		}()
		if trapped || got != c.want {
			t.Errorf("%s: from the peer %v (trapped %v), want %v", c.name, got, trapped, c.want)
		}
	}
}
