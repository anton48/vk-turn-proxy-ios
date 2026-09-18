// SPDX-License-Identifier: MIT

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// fakeRelay is a UDP socket on loopback that COUNTS every datagram an arm's
// socket sends it and answers the requests the probe makes: Binding with the
// address it saw, everything else with success (a Refresh with refreshCode
// when that is set). Counting is the point: the inbound question is honest
// only if nothing left the arm's socket before it.
type fakeRelay struct {
	conn        *net.UDPConn
	mu          sync.Mutex
	got         int
	refreshCode int
	lastData    []byte // the payload of the last ChannelData frame an arm sent
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{conn: conn}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.got++
			code := r.refreshCode
			if kind, payload, err := parseDatagram(buf[:n]); err == nil && kind == frameChannelData {
				r.lastData = append([]byte(nil), payload...)
			}
			r.mu.Unlock()
			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if buf[0]&0xC0 != 0 || req.Decode() != nil || req.Type.Class != stun.ClassRequest {
				continue
			}
			setters := []stun.Setter{stun.NewTransactionIDSetter(req.TransactionID)}
			switch {
			case req.Type.Method == stun.MethodRefresh && code != 0:
				setters = append(setters, stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse),
					stun.ErrorCodeAttribute{Code: stun.ErrorCode(code), Reason: []byte("refused")})
			case req.Type.Method == stun.MethodBinding:
				setters = append(setters, stun.BindingSuccess, stun.XORMappedAddress{IP: from.IP, Port: from.Port})
			default:
				setters = append(setters, stun.NewType(req.Type.Method, stun.ClassSuccessResponse), lifetimeAttr(10*time.Minute))
			}
			if res, err := stun.Build(append(setters, stun.Fingerprint)...); err == nil {
				_, _ = conn.WriteToUDP(res.Raw, from)
			}
		}
	}()
	return r
}

func (r *fakeRelay) received() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got
}

func (r *fakeRelay) deliverChannelData(to *net.UDPAddr, payload []byte) {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], firstChannel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	_, _ = r.conn.WriteToUDP(frame, to)
}

func (r *fakeRelay) deliverIndication(to *net.UDPAddr, payload []byte) {
	m, err := stun.Build(stun.TransactionID, stun.NewType(stun.MethodData, stun.ClassIndication),
		stun.RawAttribute{Type: stun.AttrData, Value: payload}, stun.Fingerprint)
	if err == nil {
		_, _ = r.conn.WriteToUDP(m.Raw, to)
	}
}

// armAt is a UDP session whose "relay" is r, as it stands after an Allocate.
func armAt(t *testing.T, r *fakeRelay) (*session, *net.UDPAddr) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, r.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	local := conn.LocalAddr().(*net.UDPAddr)
	return &session{conn: conn, udp: true, mapped: local, relayed: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 50000},
		permittedAt: time.Now()}, local
}

func shorten(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

// A peer stub: what it does when asked, and what the relay had received from
// the arm's socket at that moment.
type askStub struct {
	relay    *fakeRelay
	arm      *net.UDPAddr
	deliver  string // "channel", "indication" or "" (nothing arrives)
	acked    bool
	err      error
	calls    int
	sawAtAsk int
}

func (a *askStub) ask(dst *net.UDPAddr) (nonce [8]byte, acked bool, err error) {
	a.calls++
	a.sawAtAsk = a.relay.received()
	copy(nonce[:], "nonce-42")
	switch a.deliver {
	case "channel":
		a.relay.deliverChannelData(a.arm, buildProbe(nonce, 0))
	case "indication":
		a.relay.deliverIndication(a.arm, buildProbe(nonce, 0))
	case "rtp-shaped":
		a.relay.deliverChannelData(a.arm, rtpShaped(buildProbe(nonce, 0), 0, 7))
	case "another ask's":
		a.relay.deliverChannelData(a.arm, buildProbe([8]byte{1}, 0))
	case "another ask's, rtp-shaped":
		a.relay.deliverChannelData(a.arm, rtpShaped(buildProbe([8]byte{1}, 0), 0, 7))
	}
	return nonce, a.acked, a.err
}

// The inbound question asks whether the OLD mapping still lets the relay in.
// Any packet from the arm's socket re-opens the mapping, so the question must
// leave nothing through it: the ask goes through the peer client's socket and
// the arm only listens. The count is read behind a barrier (a Binding round
// trip: the relay handles datagrams in order), so a stray packet cannot hide
// behind the fake's goroutine. Sabotages seen red: a datagram written through
// the arm's socket after the ask; a payload of another ask taken for ours; the
// RTP header not looked behind.
func TestTheInboundQuestionLeavesNothingThroughTheArmsSocket(t *testing.T) {
	shorten(t, &inboundWait, 150*time.Millisecond)
	for _, c := range []struct {
		name               string
		deliver            string
		acked              bool
		err                error
		wantArrived, wantA bool
	}{
		{"the peer's datagram arrives as ChannelData", "channel", true, nil, true, true},
		{"… as a Data indication", "indication", true, nil, true, true},
		{"… shaped as RTP", "rtp-shaped", true, nil, true, true},
		{"a shaped datagram of ANOTHER ask is not ours", "another ask's, rtp-shaped", true, nil, false, true},
		{"it arrives although the ack was lost", "channel", false, nil, true, false},
		{"the peer sent and nothing came", "", true, nil, false, true},
		{"the peer never acknowledged", "", false, nil, false, false},
		{"a datagram of ANOTHER ask is not ours", "another ask's", true, nil, false, true},
		{"the ask failed", "", false, errors.New("connection refused"), false, false},
	} {
		relay := newFakeRelay(t)
		s, arm := armAt(t, relay)
		stub := &askStub{relay: relay, arm: arm, deliver: c.deliver, acked: c.acked, err: c.err}
		s.ask = stub.ask
		arrived, acked, err := s.inboundArrives()
		if (err != nil) != (c.err != nil) || arrived != c.wantArrived || acked != c.wantA {
			t.Fatalf("%s: arrived %v, acked %v, err %v — want %v, %v", c.name, arrived, acked, err, c.wantArrived, c.wantA)
		}
		if _, err := s.mappingNow(); err != nil { // the barrier
			t.Fatalf("%s: the barrier's Binding: %v", c.name, err)
		}
		if got := relay.received(); got != 1 {
			t.Fatalf("%s: %d datagram(s) left the ARM's socket during the inbound question — it re-opened the mapping it was asking about", c.name, got-1)
		}
	}
}

// after() folds three answers into a verdict. What it must get right: the
// inbound question comes before ANYTHING leaves the socket (the Binding and the
// Refresh re-open the mapping); and only a datagram the peer CONFIRMED sending,
// missing while the permission was within its lifetime, condemns the mapping —
// an unacknowledged ask is the path to the peer, an old permission is the
// relay's own refusal. Sabotages seen red: a Binding before the question; "not
// acknowledged" folded into a loss; the permission's age ignored.
func TestAfterAsksInboundFirstAndCondemnsTheMappingOnlyOnAConfirmedLoss(t *testing.T) {
	shorten(t, &inboundWait, 150*time.Millisecond)
	for _, c := range []struct {
		name          string
		deliver       string
		acked         bool
		permissionAge time.Duration
		refreshCode   int
		verdict, says string
	}{
		{"delivered", "channel", true, time.Minute, 0, "ALIVE", "INBOUND delivered through the old mapping"},
		{"the peer sent, nothing came, the permission fresh", "", true, time.Minute, 0, "INBOUND DEAD", "INBOUND NOT delivered"},
		{"the ask was never acknowledged", "", false, time.Minute, 0, "ALIVE", "inbound UNKNOWN: the peer did not acknowledge"},
		{"the peer sent, nothing came, the permission past its lifetime", "", true, 6 * time.Minute, 0, "ALIVE", "inbound UNKNOWN: the peer sent and nothing arrived, but the permission was 6m0s old"},
		{"delivered even with an old permission", "channel", true, 6 * time.Minute, 0, "ALIVE", "INBOUND delivered"},
		{"… and a confirmed loss inside a lifetime raised by -permission-lifetime counts", "", true, 6 * time.Minute, -7, "INBOUND DEAD", "INBOUND NOT delivered"},
		{"delivered, and the allocation is gone", "channel", true, time.Minute, 437, "ALLOCATION GONE", "refused with error 437"},
	} {
		relay := newFakeRelay(t)
		trusted := 5 * time.Minute
		if c.refreshCode < 0 { // a negative "code" is this table's way to raise the trusted lifetime, in minutes
			trusted, c.refreshCode = time.Duration(-c.refreshCode)*time.Minute, 0
		}
		shorten(t, &permissionLifetime, trusted)
		relay.refreshCode = c.refreshCode
		s, arm := armAt(t, relay)
		stub := &askStub{relay: relay, arm: arm, deliver: c.deliver, acked: c.acked}
		s.ask, s.canAskIn, s.permittedAt = stub.ask, true, time.Now().Add(-c.permissionAge)
		verdict, detail := s.after()
		if stub.calls != 1 || stub.sawAtAsk != 0 {
			t.Fatalf("%s: the peer was asked %d time(s), and %d datagram(s) had left the arm's socket BEFORE the inbound question", c.name, stub.calls, stub.sawAtAsk)
		}
		if verdict != c.verdict || !strings.Contains(detail, c.says) {
			t.Fatalf("%s: verdict %q, detail %q — want %q saying %q", c.name, verdict, detail, c.verdict, c.says)
		}
		if c.refreshCode == 0 && (!strings.Contains(detail, "mapping unchanged") || !strings.Contains(detail, "Refresh answered")) {
			t.Fatalf("%s: the other two questions are missing from %q", c.name, detail)
		}
	}

	relay := newFakeRelay(t)
	s, arm := armAt(t, relay)
	stub := &askStub{relay: relay, arm: arm, deliver: "channel", acked: true}
	s.ask, s.canAskIn, s.whyNotIn = stub.ask, false, "preflight: the peer did not acknowledge the ask"
	if verdict, detail := s.after(); stub.calls != 0 || verdict != "ALIVE" || !strings.Contains(detail, "inbound not asked — preflight") {
		t.Fatalf("a failed preflight: asked %d time(s), verdict %q, detail %q", stub.calls, verdict, detail)
	}
}

// The preflight decides whether a missing datagram after the silence can mean
// anything: if the peer's datagram does not arrive with everything fresh, the
// question is not asked and the reason is kept. Sabotages seen red: the
// preflight's outcome ignored; the arm's own datagram left bare.
func TestThePreflightDecidesWhetherTheQuestionIsAsked(t *testing.T) {
	shorten(t, &inboundWait, 150*time.Millisecond)
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 47000}
	for _, c := range []struct {
		name    string
		stub    *askStub
		whyNo   string
		canAsk  bool
		because string
	}{
		{"the datagram arrives", &askStub{deliver: "channel", acked: true}, "", true, ""},
		{"the peer sent, nothing arrived", &askStub{acked: true}, "", false, "nothing arrived even with a fresh permission"},
		{"the peer did not acknowledge", &askStub{}, "", false, "did not acknowledge"},
		{"the ask failed", &askStub{err: errors.New("connection refused")}, "", false, "connection refused"},
		{"nobody to ask", nil, "no -peer-token-file: the peer cannot be asked to send", false, "no -peer-token-file"},
	} {
		relay := newFakeRelay(t)
		s, arm := armAt(t, relay)
		var ask askFunc
		if c.stub != nil {
			c.stub.relay, c.stub.arm = relay, arm
			ask = c.stub.ask
		}
		if err := s.warmUp(peer, ask, c.whyNo); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s.canAskIn != c.canAsk || !strings.Contains(s.whyNotIn, c.because) {
			t.Fatalf("%s: canAskIn %v, whyNotIn %q — want %v because %q", c.name, s.canAskIn, s.whyNotIn, c.canAsk, c.because)
		}
		if s.permittedAt.IsZero() || !s.peerAddr.IP.Equal(peer.IP) {
			t.Fatalf("%s: the permission was not installed for the peer (at %v, for %v)", c.name, s.permittedAt, s.peerAddr)
		}
	}

	// What the arm itself sends to the peer takes the shape too: the relay
	// dropped the bare datagram on its way OUT as well.
	for _, rtp := range []bool{true, false} {
		relay := newFakeRelay(t)
		s, _ := armAt(t, relay)
		s.rtp = rtp
		if err := s.warmUp(peer, nil, "nobody to ask"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.mappingNow(); err != nil { // the barrier: the relay has handled the datagram before it
			t.Fatal(err)
		}
		relay.mu.Lock()
		sent := relay.lastData
		relay.mu.Unlock()
		if isMedia := sent[0] == 0x80 && sent[1] == rtpPayload; isMedia != rtp || len(sent) != rtpHeaderLen+12 || !strings.HasPrefix(string(unshaped(sent)), "idle-probe") {
			t.Fatalf("rtp=%v: the arm's datagram to the peer went out as % x — want 24 bytes in either shape", rtp, sent)
		}
	}
}

// The silence an arm reports is the gap in what LEFT its socket, so it is
// counted from the last write — the preflight listens for seconds without
// sending, and those seconds are silence too. Sabotages seen red: the wait
// counted from now; a write that does not stamp.
func TestTheSilenceIsCountedFromTheLastThingThatLeftTheSocket(t *testing.T) {
	relay := newFakeRelay(t)
	s, _ := armAt(t, relay)
	if err := s.write([]byte{0x40, 0, 0, 0}, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if since := time.Since(s.lastOut); since < 0 || since > 100*time.Millisecond {
		t.Fatalf("a write left lastOut %s away from now", since)
	}
	s.lastOut = time.Now().Add(-350 * time.Millisecond)
	t0 := time.Now()
	if _, how := s.stayQuiet(400 * time.Millisecond); how != "" {
		t.Fatalf("the quiet ended by itself: %s", how)
	}
	if took := time.Since(t0); took > 200*time.Millisecond {
		t.Fatalf("350 ms of a 400-ms silence had passed, and the wait still took %s", took.Round(time.Millisecond))
	}
}

var testToken = []byte("a-token-of-32-bytes-for-the-test")

// An ask is believed only after its MAC, and then still has to be fresh and
// within bounds. Sabotages seen red: the MAC check dropped; the freshness
// check dropped; the count's bound dropped; an unknown shape accepted.
func TestAnAskIsHonouredOnlyWithTheTokenFreshAndInBounds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dst := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 50000}
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	ask := func(token []byte, at time.Time, count int) []byte {
		b, err := buildAsk(token, at, nonce, dst, count, true)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	gotNonce, gotDst, gotCount, gotRTP, err := parseAsk(testToken, now, ask(testToken, now, 3))
	if err != nil || gotNonce != nonce || !gotDst.IP.Equal(dst.IP) || gotDst.Port != dst.Port || gotCount != 3 || !gotRTP {
		t.Fatalf("a good ask: %v %v %d rtp=%v, %v", gotNonce, gotDst, gotCount, gotRTP, err)
	}
	if plain, _ := buildAsk(testToken, now, nonce, dst, 3, false); true {
		if _, _, _, rtp, err := parseAsk(testToken, now, plain); err != nil || rtp {
			t.Fatalf("an ask for plain datagrams: rtp=%v, %v", rtp, err)
		}
	}
	flipped := ask(testToken, now, 3)
	flipped[25] ^= 1 // one bit of the destination
	shape2 := ask(testToken, now, 3)
	shape2[6] = 2
	copy(shape2[32:], peerMAC(testToken, shape2[:32])) // a well-signed ask for a shape that does not exist
	for name, c := range map[string]struct {
		b    []byte
		want error
	}{
		"another token":                {ask([]byte("some-other-token-of-32-bytes-xxx"), now, 3), errBadMAC},
		"one bit of the destination":   {flipped, errBadMAC},
		"31 s old":                     {ask(testToken, now.Add(-31*time.Second), 3), errStaleAsk},
		"31 s ahead":                   {ask(testToken, now.Add(31*time.Second), 3), errStaleAsk},
		"a count of 0":                 {ask(testToken, now, 0), errBadCount},
		"a count of 4":                 {ask(testToken, now, 4), errBadCount},
		"a shape that does not exist":  {shape2, errBadShape},
		"one byte short":               {ask(testToken, now, 3)[:peerAskLen-1], errNotAnAsk},
		"an ack is not an ask":         {append(buildAck(testToken, nonce), make([]byte, peerAskLen-peerAckLen)...), errNotAnAsk},
		"a warm-up datagram":           {[]byte("idle-probe\x00\x00"), errNotAnAsk},
		"29 s old is still fresh":      {ask(testToken, now.Add(-29*time.Second), 3), nil},
		"a count of 1 is within bound": {ask(testToken, now, 1), nil},
	} {
		if _, _, _, _, err := parseAsk(testToken, now, c.b); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v — want %v", name, err, c.want)
		}
	}
}

func readFor(conn *net.UDPConn, wait time.Duration) (datagrams [][]byte, from []*net.UDPAddr) {
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return datagrams, from
		}
		datagrams, from = append(datagrams, append([]byte(nil), buf[:n]...)), append(from, addr)
	}
}

// The peer end to end on loopback. An honoured ask: its datagrams — all of
// them, with the ask's nonce — come FROM THE LISTENING SOCKET (the address an
// arm's permission and channel name; the relay forwards from no other), and
// the asker gets an ack. The same ask again: another ack and nothing sent. A
// stranger's datagram, and an ask for a destination outside the rule: NOTHING,
// to anyone. And the SHAPE is the ask's: RTP when asked for (the VK relay
// forwards nothing else), bare otherwise. Sabotages seen red: a replay sent
// again; the datagrams sent from a socket of their own; the destination rule
// dropped; a refusal answered; the shape ignored; the plain control shorter
// than the RTP shape (the two must differ in shape ALONE).
func TestThePeerSendsOncePerAskFromItsListeningSocketAndAnswersNoStranger(t *testing.T) {
	shorten(t, &peerSpacing, 10*time.Millisecond)
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	srvConn, dest, asker := listen(), listen(), listen()
	allow, err := allowRule("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	srv := newPeerServer(srvConn, testToken, allow)
	go srv.serve(time.Now().Add(time.Minute))
	srvAddr, destAddr := srvConn.LocalAddr().(*net.UDPAddr), dest.LocalAddr().(*net.UDPAddr)

	nonce := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	good, _ := buildAsk(testToken, time.Now(), nonce, destAddr, 3, false)
	if _, err := asker.WriteToUDP(good, srvAddr); err != nil {
		t.Fatal(err)
	}
	got, from := readFor(dest, 300*time.Millisecond)
	if len(got) != 3 {
		t.Fatalf("an honoured ask for 3 datagrams delivered %d", len(got))
	}
	for i, b := range got {
		if !isProbeFor(nonce, b) || int(b[5]) != i {
			t.Fatalf("datagram %d is not this ask's probe number %d: % x", i, i, b)
		}
		if from[i].Port != srvAddr.Port {
			t.Fatalf("datagram %d came from port %d, the peer listens on %d — a relay forwards only from the address the permission names", i, from[i].Port, srvAddr.Port)
		}
	}
	if acks, _ := readFor(asker, 100*time.Millisecond); len(acks) != 1 || !isAckFor(testToken, nonce, acks[0]) {
		t.Fatalf("the asker got %d datagram(s), want this ask's ack", len(acks))
	}

	if _, err := asker.WriteToUDP(good, srvAddr); err != nil { // the ack was "lost": the same ask again
		t.Fatal(err)
	}
	if again, _ := readFor(dest, 200*time.Millisecond); len(again) != 0 {
		t.Fatalf("the same ask sent %d more datagram(s) — a nonce is honoured once", len(again))
	}
	if acks, _ := readFor(asker, 100*time.Millisecond); len(acks) != 1 || !isAckFor(testToken, nonce, acks[0]) {
		t.Fatalf("the repeated ask got %d datagram(s), want its ack again", len(acks))
	}

	shapedNonce := [8]byte{0xa, 0xb, 0xc, 0xd, 1, 2, 3, 4}
	shaped, _ := buildAsk(testToken, time.Now(), shapedNonce, destAddr, 2, true)
	if _, err := asker.WriteToUDP(shaped, srvAddr); err != nil {
		t.Fatal(err)
	}
	media, _ := readFor(dest, 200*time.Millisecond)
	if len(media) != 2 {
		t.Fatalf("an ask for 2 rtp-shaped datagrams delivered %d", len(media))
	}
	for i, b := range media {
		if len(b) != rtpHeaderLen+peerProbeLen || b[0] != 0x80 || b[1] != rtpPayload || !isProbeFor(shapedNonce, b) {
			t.Fatalf("datagram %d of a shaped ask is not an RTP-shaped probe of it: % x", i, b)
		}
	}
	for i, b := range got { // … and the plain ask's were plain — and as long, so that only the shape differs
		if len(b) != rtpHeaderLen+peerProbeLen || b[0]&0xC0 == 0x80 {
			t.Fatalf("datagram %d of a plain ask: %d bytes starting %#02x — want %d bytes that are no RTP", i, len(b), b[0], rtpHeaderLen+peerProbeLen)
		}
	}
	readFor(asker, 50*time.Millisecond) // its ack

	stranger, _ := buildAsk([]byte("not-the-token-not-the-token-xxxx"), time.Now(), [8]byte{1}, destAddr, 3, false)
	outside, _ := buildAsk(testToken, time.Now(), [8]byte{2}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: destAddr.Port}, 3, false)
	for name, b := range map[string][]byte{"a stranger's ask": stranger, "an ask for a destination outside the rule": outside, "noise": []byte("hello")} {
		if _, err := asker.WriteToUDP(b, srvAddr); err != nil {
			t.Fatal(err)
		}
		if sent, _ := readFor(dest, 150*time.Millisecond); len(sent) != 0 {
			t.Fatalf("%s made the peer send %d datagram(s)", name, len(sent))
		}
		if back, _ := readFor(asker, 50*time.Millisecond); len(back) != 0 {
			t.Fatalf("%s was ANSWERED (%d datagram(s)) — a refusal is silent", name, len(back))
		}
	}
	if c := srv.counters(); !strings.Contains(c, "honoured 2") || !strings.Contains(c, "bad MAC 1") ||
		!strings.Contains(c, "destination not allowed 1") || !strings.Contains(c, "not an ask 1") {
		t.Fatalf("the counters: %q", c)
	}
}

// Without -peer-allow the peer sends only to a public unicast address and an
// unprivileged port. Sabotage seen red: private networks let through.
func TestTheDefaultDestinationRuleIsPublicUnicastOnly(t *testing.T) {
	for addr, want := range map[string]bool{
		"95.163.34.180:50000": true, "8.8.8.8:1024": true,
		"8.8.8.8:1023": false, "8.8.8.8:53": false,
		"10.129.0.27:50000": false, "172.16.0.1:50000": false, "192.168.1.1:50000": false, "127.0.0.1:50000": false,
		"169.254.1.1:50000": false, "100.64.0.1:50000": false, "100.127.255.255:50000": false, "100.128.0.1:50000": true,
		"224.0.0.1:50000": false, "240.0.0.1:50000": false, "255.255.255.255:50000": false, "0.0.0.0:50000": false,
	} {
		a, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := publicUnicast(a.IP, a.Port); got != want {
			t.Fatalf("%s: allowed %v, want %v", addr, got, want)
		}
	}
	if publicUnicast(net.ParseIP("2001:db8::1"), 50000) {
		t.Fatal("an IPv6 destination passed a rule written for IPv4")
	}
	rule, err := allowRule("95.163.0.0/16, 90.156.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if !rule(net.IPv4(90, 156, 1, 1), 50000) || rule(net.IPv4(8, 8, 8, 8), 50000) {
		t.Fatal("-peer-allow does not bound the destinations to its networks")
	}
	if _, err := allowRule("not-a-network"); err == nil {
		t.Fatal("a malformed -peer-allow was accepted")
	}
}

// The probe's side of an ask: repeated with the SAME nonce until acknowledged
// (the peer sends once per nonce), and only an ack carrying that nonce under
// the token's MAC counts. Sabotages seen red: the ack's MAC unchecked; the
// ack's nonce unchecked; a repeat under a new nonce.
func TestThePeerClientRepeatsAnAskAndTrustsOnlyItsOwnAck(t *testing.T) {
	shorten(t, &peerAskRTO, 60*time.Millisecond)
	dst := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 50000}
	for _, c := range []struct {
		name      string
		answer    func(try int, nonce [8]byte) []byte
		wantAcked bool
		wantAsks  int
	}{
		{"the first ask is lost, the second acknowledged", func(try int, nonce [8]byte) []byte {
			if try == 0 {
				return nil
			}
			return buildAck(testToken, nonce)
		}, true, 2},
		{"an ack under another token", func(_ int, nonce [8]byte) []byte { return buildAck([]byte("some-other-token-of-32-bytes-xxx"), nonce) }, false, peerAskTries},
		{"an ack for another nonce", func(_ int, _ [8]byte) []byte { return buildAck(testToken, [8]byte{7}) }, false, peerAskTries},
		{"silence", func(int, [8]byte) []byte { return nil }, false, peerAskTries},
	} {
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var nonces [][8]byte
		go func() {
			buf := make([]byte, 512)
			for try := 0; ; try++ {
				n, from, err := peer.ReadFromUDP(buf)
				if err != nil {
					return
				}
				nonce, _, _, _, err := parseAsk(testToken, time.Now(), buf[:n])
				if err != nil {
					continue
				}
				mu.Lock()
				nonces = append(nonces, nonce)
				mu.Unlock()
				if b := c.answer(try, nonce); b != nil {
					_, _ = peer.WriteToUDP(b, from)
				}
			}
		}()
		pc, err := newPeerClient(peer.LocalAddr().(*net.UDPAddr), testToken, true)
		if err != nil {
			t.Fatal(err)
		}
		nonce, acked, err := pc.ask(dst)
		time.Sleep(20 * time.Millisecond)
		peer.Close()
		pc.conn.Close()
		mu.Lock()
		if err != nil || acked != c.wantAcked || len(nonces) != c.wantAsks {
			t.Fatalf("%s: acked %v after %d ask(s), err %v — want %v after %d", c.name, acked, len(nonces), err, c.wantAcked, c.wantAsks)
		}
		for _, n := range nonces {
			if n != nonce {
				t.Fatalf("%s: a repeated ask changed its nonce — the peer would send again", c.name)
			}
		}
		mu.Unlock()
	}
}

// The token is all that stands between the peer and a stranger. Sabotage seen
// red: the mode check dropped.
func TestATokenOthersCanReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // WriteFile's mode is cut by the umask; this is not
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadToken(write("open", string(testToken)+"\n", 0o644)); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("a 0644 token: %v", err)
	}
	if _, err := loadToken(write("short", "too-short\n", 0o600)); err == nil {
		t.Fatal("a nine-byte token was accepted")
	}
	if _, err := loadToken(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing token file was accepted")
	}
	token, err := loadToken(write("good", "  "+string(testToken)+"\n", 0o600))
	if err != nil || string(token) != string(testToken) {
		t.Fatalf("a good token: %q, %v", token, err)
	}
}
