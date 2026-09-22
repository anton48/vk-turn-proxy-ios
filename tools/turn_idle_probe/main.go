// SPDX-License-Identifier: MIT

// turn_idle_probe answers one question about a path to the VK TURN relay: what
// happens to an allocation whose client has gone SILENT?
//
// Why: an iOS extension is frozen for a minute at a time, now and then for
// minutes. While it is frozen nothing is sent — no keepalive, no TURN Refresh —
// and once, after a 208-second freeze, a client found all fifty of its relay
// connections dropped by the far side although every TURN lifetime was still
// running. Whether the RELAY does that to a silent client, or a box on the
// path does, cannot be read from a phone log; it can be measured.
//
// How: TURN spoken by hand (pion/stun for the messages only). pion's TURN
// client refreshes on its own timers, and silence is the whole point: each arm
// allocates, installs a permission and a channel and sends one datagram (what
// a real connection has done before it goes quiet), then sends NOTHING for its
// silence, and then asks what is left.
//
//   - Over TCP the far side's FIN or RST is watched for during the silence,
//     and one Refresh afterwards says whether the allocation still lives.
//   - Over UDP there is no connection to close; what dies silently is the NAT
//     mapping between this host and the relay, and the router's timers decide
//     when. Three questions, in this order — the first must come before ANY
//     packet leaves this socket, because an outbound packet re-opens the
//     mapping it would be asking about:
//     1. INBOUND: a PEER ON ANOTHER HOST (this tool run with -peer-listen; see
//     peer.go) is asked — through a socket of the probe's own, never the arm's
//     — to send a datagram to this allocation's relayed address; the relay
//     forwards it to the address it knows us by. Delivered = the old mapping
//     still lets the relay in. (Another host, because the VK relay forwards
//     neither a datagram from the client's OWN public address nor one from
//     another allocation on the relay — both seen on the wire. The answer is
//     a verdict on the mapping only while the permission lives, nominally
//     300 s; past that a missing datagram is reported without one. A
//     PREFLIGHT before the silence says whether the question can be asked on
//     this path at all, and a peer that does not acknowledge an ask is a
//     failed instrument, not a dead mapping.)
//     2. MAPPING: a Binding request — is the address the relay sees us from the
//     one the allocation was made from? A NAT that kept the port hides an
//     expiry here, which is why (1) exists.
//     3. ALLOCATION: a Refresh — 437 means the relay has no allocation for the
//     5-tuple it now sees.
//
// Two arms keep a run honest: a CONTROL that refreshes (allocation AND
// permission) every 25 s for the longest silence — it must stay alive and its
// inbound datagram must arrive — and a silence LONGER than the allocation's
// lifetime, which must come back dead.
//
// Nothing secret is printed: not the link, not the credential; of the relay
// and of this host's public address only the first two octets.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/pion/stun/v3"
)

// osKeepalive: whether the arms' TCP sockets keep Go's default keepalive (-os-keepalive). Off, so that a
// silence is a silence on the wire and whatever zero-length segment arrives during it is the far side's.
var osKeepalive bool

// dialerFor builds the arms' dialer: over TCP with the OS keepalive DISABLED unless asked for — Go's net.Dialer
// enables it with a 15-s period by default, and a probe every 15 s from this host is exactly what a measurement of
// the far side's keepalive must not send.
func dialerFor(transport string, noKeepalive bool) *net.Dialer {
	d := &net.Dialer{Timeout: requestTimeout}
	if transport == "tcp" && noKeepalive {
		d.KeepAlive = -1
	}
	return d
}

const (
	requestTimeout = 5 * time.Second
	firstRTO       = 500 * time.Millisecond // UDP only: a lost request is sent again
	controlEvery   = 25 * time.Second
	firstChannel   = 0x4000
)

// permissionLifetime bounds what a MISSING inbound datagram may mean: past it
// the relay itself may have refused the peer. RFC 8656 §9 says five minutes;
// the VK relay was seen to forward through a permission 6m40s old (2026-09-19,
// from ya2) — -permission-lifetime says what to trust.
var permissionLifetime = 5 * time.Minute

// inboundWait is how long an arm listens for the peer's datagrams (three
// copies, peerSpacing apart). A var: the tests shorten it.
var inboundWait = 3 * time.Second

type frameKind int

const (
	frameSTUN frameKind = iota
	frameChannelData
)

// readFrame reads one frame of a TURN-over-TCP STREAM: a STUN message, or a
// ChannelData frame — which on a stream is PADDED to a multiple of four bytes
// (RFC 8656 §12.5); skipping the padding wrongly desynchronises everything
// after it.
func readFrame(r io.Reader) (frameKind, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	switch hdr[0] & 0xC0 {
	case 0x40: // channel numbers 0x4000–0x7FFF
		body := make([]byte, (n+3)&^3)
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
		return frameChannelData, body[:n], nil
	case 0x00: // a STUN message: n is the length after the 20-byte header
		msg := make([]byte, 20+n)
		copy(msg, hdr[:])
		if _, err := io.ReadFull(r, msg[4:]); err != nil {
			return 0, nil, err
		}
		return frameSTUN, msg, nil
	}
	return 0, nil, fmt.Errorf("neither STUN nor ChannelData: first byte %#02x", hdr[0])
}

// parseDatagram classifies one UDP datagram. A datagram IS its frame: the
// ChannelData padding a stream needs is optional here and a relay may omit it,
// so the length field bounds the payload and nothing is read beyond it.
func parseDatagram(b []byte) (frameKind, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("a %d-byte datagram is no frame", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	switch b[0] & 0xC0 {
	case 0x40:
		if 4+n > len(b) {
			return 0, nil, fmt.Errorf("ChannelData announces %d bytes, the datagram holds %d", n, len(b)-4)
		}
		return frameChannelData, b[4 : 4+n], nil
	case 0x00:
		if 20+n != len(b) {
			return 0, nil, fmt.Errorf("a STUN header announcing %d bytes in a %d-byte datagram", n, len(b)-20)
		}
		return frameSTUN, append([]byte(nil), b...), nil
	}
	return 0, nil, fmt.Errorf("neither STUN nor ChannelData: first byte %#02x", b[0])
}

type xorPeer struct{ addr *net.UDPAddr }

func (p xorPeer) AddTo(m *stun.Message) error {
	return stun.XORMappedAddress{IP: p.addr.IP, Port: p.addr.Port}.AddToAs(m, stun.AttrXORPeerAddress)
}

func lifetimeAttr(d time.Duration) stun.RawAttribute {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(d/time.Second))
	return stun.RawAttribute{Type: stun.AttrLifetime, Value: v}
}

// session is one TURN allocation over one TCP connection or one UDP socket.
type session struct {
	conn        net.Conn
	udp         bool
	user, pass  string
	realm       string
	nonce       string
	mapped      *net.UDPAddr // how the relay saw us when it allocated
	relayed     *net.UDPAddr // the allocation's relayed address
	strayFrames int          // frames that answered nothing we asked
	ask         askFunc      // has the peer on another host send to an address; nil = nobody to ask
	rtp         bool         // what the arm itself sends to the peer is shaped as RTP (see peer.go)
	peerAddr    *net.UDPAddr // the peer the permission and the channel name
	permittedAt time.Time    // when the permission was last installed — it bounds what a missing datagram means
	lastOut     time.Time    // the last time anything left conn: the silence is counted from here
	canAskIn    bool         // the peer's datagram was SEEN to arrive before the silence
	whyNotIn    string       // … or why the inbound question cannot be asked on this path
	inbox       [][]byte     // payloads the relay delivered to us (Data indications, ChannelData)
}

// askFunc has the peer send its datagrams to dst — through a socket that is
// NOT the arm's. acked: the peer confirmed the ask (see peerClient.ask).
type askFunc func(dst *net.UDPAddr) (nonce [8]byte, acked bool, err error)

// write is the ONE way anything leaves conn, so that lastOut is the truth.
func (s *session) write(b []byte, deadline time.Time) error {
	_ = s.conn.SetWriteDeadline(deadline)
	_, err := s.conn.Write(b)
	s.lastOut = time.Now()
	return err
}

// recv reads ONE frame, whatever the transport, by the deadline.
func (s *session) recv(deadline time.Time) (frameKind, []byte, error) {
	_ = s.conn.SetReadDeadline(deadline)
	if !s.udp {
		return readFrame(s.conn)
	}
	buf := make([]byte, 2048)
	n, err := s.conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	return parseDatagram(buf[:n])
}

// note files a frame that is not the answer being waited for: a payload the
// relay delivered goes to the inbox, anything else is counted.
func (s *session) note(kind frameKind, raw []byte) {
	if kind == frameChannelData {
		s.inbox = append(s.inbox, raw)
		return
	}
	m := &stun.Message{Raw: raw}
	if m.Decode() == nil && m.Type.Method == stun.MethodData && m.Type.Class == stun.ClassIndication {
		if data, err := m.Get(stun.AttrData); err == nil {
			s.inbox = append(s.inbox, data)
			return
		}
	}
	s.strayFrames++
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var errStaleNonce = errors.New("stale nonce")

// roundTrip sends one request and waits for ITS answer; over UDP the request
// is sent again (same transaction) at a doubling interval until the timeout.
func (s *session) roundTrip(typ stun.MessageType, auth bool, attrs ...stun.Setter) (*stun.Message, int, error) {
	setters := append([]stun.Setter{stun.TransactionID, typ}, attrs...)
	if auth {
		setters = append(setters, stun.NewUsername(s.user), stun.NewRealm(s.realm), stun.NewNonce(s.nonce),
			stun.NewLongTermIntegrity(s.user, s.realm, s.pass))
	}
	setters = append(setters, stun.Fingerprint)
	req, err := stun.Build(setters...)
	if err != nil {
		return nil, 0, err
	}
	defer s.conn.SetDeadline(time.Time{})
	end := time.Now().Add(requestTimeout)
	for rto := firstRTO; ; rto *= 2 {
		if err := s.write(req.Raw, end); err != nil {
			return nil, 0, fmt.Errorf("write: %w", err)
		}
		wait := end
		if s.udp && time.Now().Add(rto).Before(end) {
			wait = time.Now().Add(rto)
		}
		for {
			kind, raw, err := s.recv(wait)
			if err != nil {
				if isTimeout(err) && wait.Before(end) {
					break // UDP: nothing yet — send it again
				}
				if isTimeout(err) {
					return nil, 0, fmt.Errorf("no answer within %s", requestTimeout)
				}
				return nil, 0, fmt.Errorf("read: %w", err)
			}
			res := &stun.Message{Raw: raw}
			if kind != frameSTUN || res.Decode() != nil || res.TransactionID != req.TransactionID {
				s.note(kind, raw)
				continue
			}
			if res.Type.Class != stun.ClassErrorResponse {
				return res, 0, nil
			}
			var ec stun.ErrorCodeAttribute
			_ = ec.GetFrom(res)
			var realm stun.Realm
			var nonce stun.Nonce
			if realm.GetFrom(res) == nil {
				s.realm = realm.String()
			}
			if nonce.GetFrom(res) == nil {
				s.nonce = nonce.String()
			}
			if ec.Code == stun.CodeStaleNonce {
				return res, int(ec.Code), errStaleNonce
			}
			return res, int(ec.Code), nil
		}
	}
}

// do is an authenticated roundTrip with the one retry a stale nonce is owed.
func (s *session) do(method stun.Method, attrs ...stun.Setter) (*stun.Message, int, error) {
	typ := stun.NewType(method, stun.ClassRequest)
	res, code, err := s.roundTrip(typ, true, attrs...)
	if errors.Is(err, errStaleNonce) {
		res, code, err = s.roundTrip(typ, true, attrs...)
	}
	return res, code, err
}

func lifetimeOf(m *stun.Message) time.Duration {
	if v, err := m.Get(stun.AttrLifetime); err == nil && len(v) == 4 {
		return time.Duration(binary.BigEndian.Uint32(v)) * time.Second
	}
	return 0
}

func addrOf(m *stun.Message, attr stun.AttrType) *net.UDPAddr {
	var a stun.XORMappedAddress
	if a.GetFromAs(m, attr) != nil {
		return nil
	}
	return &net.UDPAddr{IP: a.IP, Port: a.Port}
}

// allocate runs the 401 challenge and the authenticated Allocate, and keeps
// the two addresses the answer carries.
func (s *session) allocate() (time.Duration, error) {
	udp := stun.RawAttribute{Type: stun.AttrRequestedTransport, Value: []byte{17, 0, 0, 0}}
	_, code, err := s.roundTrip(stun.NewType(stun.MethodAllocate, stun.ClassRequest), false, udp)
	if err != nil {
		return 0, err
	}
	if code != int(stun.CodeUnauthorized) || s.realm == "" || s.nonce == "" {
		return 0, fmt.Errorf("the unauthenticated Allocate was answered with code %d, want a 401 carrying a realm and a nonce", code)
	}
	res, code, err := s.do(stun.MethodAllocate, udp)
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("Allocate refused: error %d", code)
	}
	s.mapped, s.relayed = addrOf(res, stun.AttrXORMappedAddress), addrOf(res, stun.AttrXORRelayedAddress)
	if s.mapped == nil || s.relayed == nil {
		return 0, errors.New("the Allocate answer carries no mapped or no relayed address")
	}
	return lifetimeOf(res), nil
}

// permit installs (or refreshes) the permission for peer's IP.
func (s *session) permit(peer *net.UDPAddr) error {
	if _, code, err := s.do(stun.MethodCreatePermission, xorPeer{peer}); err != nil || code != 0 {
		return fmt.Errorf("CreatePermission: code %d, %v", code, err)
	}
	return nil
}

// warmUp does what a real connection has done before it goes quiet — a
// permission, a channel, a datagram — with the peer as their address. Over UDP
// it is also the inbound question's PREFLIGHT: if the peer's datagram does not
// arrive now, with everything fresh, then one that fails to arrive after the
// silence would say nothing about the mapping, and the question is not asked
// (whyNotIn says why).
func (s *session) warmUp(peer *net.UDPAddr, ask askFunc, whyNoAsk string) error {
	if peer == nil {
		peer = &net.UDPAddr{IP: s.mapped.IP, Port: 9} // a permission and a channel need SOME peer; nobody answers here
	}
	s.ask, s.whyNotIn = ask, whyNoAsk
	if err := s.warmUpPeer(peer); err != nil {
		return err
	}
	if s.udp && s.ask != nil { // over TCP the connection itself is the question
		switch arrived, acked, err := s.inboundArrives(); {
		case err != nil:
			s.whyNotIn = "preflight: " + err.Error()
		case !arrived && !acked:
			s.whyNotIn = "preflight: the peer did not acknowledge the ask"
		case !arrived:
			s.whyNotIn = "preflight: the peer sent, and nothing arrived even with a fresh permission and channel"
		}
	}
	s.canAskIn = s.udp && s.ask != nil && s.whyNotIn == ""
	return nil
}

// refreshPeer installs or refreshes what lets the peer's datagrams through:
// the permission (5 min) and the channel (10 min).
func (s *session) refreshPeer() error {
	if err := s.permit(s.peerAddr); err != nil {
		return err
	}
	s.permittedAt = time.Now()
	ch := stun.RawAttribute{Type: stun.AttrChannelNumber, Value: []byte{firstChannel >> 8, firstChannel & 0xff, 0, 0}}
	if _, code, err := s.do(stun.MethodChannelBind, ch, xorPeer{s.peerAddr}); err != nil || code != 0 {
		return fmt.Errorf("ChannelBind: code %d, %v", code, err)
	}
	return nil
}

func (s *session) warmUpPeer(peer *net.UDPAddr) error {
	s.peerAddr = peer
	if err := s.refreshPeer(); err != nil {
		return err
	}
	payload := plainShaped([]byte("idle-probe\x00\x00")) // 24 bytes either way: only the shape differs
	if s.rtp {
		payload = rtpShaped([]byte("idle-probe\x00\x00"), 0, 0x1d1e9a0b)
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], firstChannel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	err := s.write(frame, time.Now().Add(requestTimeout))
	_ = s.conn.SetWriteDeadline(time.Time{})
	return err
}

// stayQuiet sends nothing until d has passed since the last thing that left
// the socket, and listens. Over TCP the far side's FIN or RST is reported with
// the moment it came; over UDP only an ICMP error can end the wait early.
// Unasked frames are filed, not answered.
func (s *session) stayQuiet(d time.Duration) (closedAfter time.Duration, how string) {
	start := s.lastOut
	if start.IsZero() {
		start = time.Now()
	}
	defer s.conn.SetReadDeadline(time.Time{})
	for {
		kind, raw, err := s.recv(start.Add(d))
		switch {
		case err == nil:
			s.note(kind, raw)
		case isTimeout(err):
			return 0, ""
		case errors.Is(err, io.EOF):
			return time.Since(start), "FIN (the far side closed)"
		default:
			return time.Since(start), err.Error()
		}
	}
}

// inboundArrives asks whether the relay can still reach this socket through
// the mapping the allocation was made from: the peer is asked to send to this
// allocation's relayed address, and the arm only LISTENS. 🚨 Nothing may leave
// s.conn before or during this — an outbound packet would re-open the very
// mapping under question; the ask travels through the peer client's socket.
// acked without arrived = the peer sent and nothing came; neither = the ask
// itself was lost, which says nothing about the mapping.
func (s *session) inboundArrives() (arrived, acked bool, err error) {
	s.inbox = nil
	nonce, acked, err := s.ask(s.relayed)
	if err != nil {
		return false, false, err
	}
	defer s.conn.SetReadDeadline(time.Time{})
	for end := time.Now().Add(inboundWait); time.Now().Before(end); {
		kind, raw, err := s.recv(end)
		if err == nil {
			s.note(kind, raw)
		} else if !isTimeout(err) {
			return false, acked, err
		}
		for _, got := range s.inbox {
			if isProbeFor(nonce, got) {
				return true, acked, nil
			}
		}
	}
	return false, acked, nil
}

// mappingNow asks the relay, with a Binding request, where it sees us from.
func (s *session) mappingNow() (*net.UDPAddr, error) {
	res, code, err := s.roundTrip(stun.BindingRequest, false)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("Binding refused: error %d", code)
	}
	if a := addrOf(res, stun.AttrXORMappedAddress); a != nil {
		return a, nil
	}
	return nil, errors.New("the Binding answer carries no mapped address")
}

type result struct {
	name      string
	transport string
	silence   time.Duration
	control   bool
	allocated time.Duration // the lifetime the relay granted
	verdict   string
	detail    string
}

type arm struct {
	name      string
	transport string
	silence   time.Duration
	control   bool // refresh every controlEvery instead of staying silent
}

// after asks the three questions once the quiet is over, in the order that
// keeps the first one honest, and folds the answers into a verdict. Only a
// datagram the peer CONFIRMED sending, missing while the permission was still
// within its lifetime, is a verdict on the mapping; an unacknowledged ask or a
// permission past its lifetime is reported as what it is.
func (s *session) after() (verdict, detail string) {
	var notes []string
	inbound := "n/a"
	if s.udp {
		if !s.canAskIn {
			notes = append(notes, "inbound not asked — "+s.whyNotIn)
		} else {
			permissionAge := time.Since(s.permittedAt)
			arrived, acked, err := s.inboundArrives()
			switch {
			case err != nil:
				notes = append(notes, "inbound UNKNOWN: "+err.Error())
			case arrived:
				inbound = "yes"
				notes = append(notes, "INBOUND delivered through the old mapping")
			case !acked:
				notes = append(notes, "inbound UNKNOWN: the peer did not acknowledge the ask — the path to the peer, not the mapping")
			case permissionAge >= permissionLifetime:
				notes = append(notes, fmt.Sprintf("inbound UNKNOWN: the peer sent and nothing arrived, but the permission was %s old (trusted for %s) — the relay may have refused it",
					permissionAge.Round(time.Second), permissionLifetime))
			default:
				inbound = "no"
				notes = append(notes, fmt.Sprintf("INBOUND NOT delivered within %s although the peer sent — the mapping no longer lets the relay in", inboundWait))
			}
		}
		if now, err := s.mappingNow(); err != nil {
			notes = append(notes, "mapping: "+err.Error())
		} else if now.IP.Equal(s.mapped.IP) && now.Port == s.mapped.Port {
			notes = append(notes, fmt.Sprintf("mapping unchanged (port %d)", now.Port))
		} else {
			notes = append(notes, fmt.Sprintf("mapping CHANGED: port %d → %d%s", s.mapped.Port, now.Port,
				map[bool]string{true: "", false: ", and the address"}[now.IP.Equal(s.mapped.IP)]))
		}
	}
	t1 := time.Now()
	r, code, err := s.do(stun.MethodRefresh, lifetimeAttr(10*time.Minute))
	switch {
	case err != nil:
		return "DEAD", strings.Join(append(notes, fmt.Sprintf("the Refresh failed: %v", err)), "; ")
	case code != 0:
		return "ALLOCATION GONE", strings.Join(append(notes, fmt.Sprintf("the Refresh is refused with error %d", code)), "; ")
	}
	notes = append(notes, fmt.Sprintf("Refresh answered in %s, lifetime %s", time.Since(t1).Round(time.Millisecond), lifetimeOf(r)))
	if inbound == "no" {
		return "INBOUND DEAD", strings.Join(notes, "; ")
	}
	return "ALIVE", strings.Join(notes, "; ")
}

func runArm(a arm, relay string, creds *proxy.TURNCreds, peer *net.UDPAddr, ask askFunc, whyNoAsk string, rtp bool) result {
	res := result{name: a.name, transport: a.transport, silence: a.silence, control: a.control}
	fail := func(err error) result { res.verdict, res.detail = "NOT RUN", err.Error(); return res }
	conn, err := dialerFor(a.transport, !osKeepalive).Dial(a.transport+"4", relay)
	if err != nil {
		return fail(fmt.Errorf("dial: %w", err))
	}
	defer conn.Close()
	s := &session{conn: conn, udp: a.transport == "udp", user: creds.Username, pass: creds.Password, rtp: rtp}
	t0 := time.Now()
	if res.allocated, err = s.allocate(); err != nil {
		return fail(err)
	}
	if err := s.warmUp(peer, ask, whyNoAsk); err != nil {
		return fail(err)
	}
	lport := 0
	switch la := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		lport = la.Port
	case *net.TCPAddr:
		lport = la.Port
	}
	log.Printf("[%s] allocated in %s, lifetime %s; local port %d → seen by the relay as %s (port %s) — now %s", a.name,
		time.Since(t0).Round(time.Millisecond), res.allocated, lport, maskIP(s.mapped.IP),
		map[bool]string{true: "kept", false: fmt.Sprintf("translated to %d", s.mapped.Port)}[lport == s.mapped.Port],
		map[bool]string{true: fmt.Sprintf("a Refresh + CreatePermission + ChannelBind every %s for %s", controlEvery, a.silence), false: fmt.Sprintf("SILENT for %s", a.silence)}[a.control])

	if a.control {
		rounds := 0
		for end := time.Now().Add(a.silence); time.Now().Before(end); {
			if closed, how := s.stayQuiet(controlEvery); how != "" {
				res.verdict, res.detail = "DEAD", fmt.Sprintf("ended %s into a quiet stretch after %d rounds: %s", closed.Round(time.Second), rounds, how)
				return res
			}
			if _, code, err := s.do(stun.MethodRefresh, lifetimeAttr(10*time.Minute)); err != nil || code != 0 {
				res.verdict, res.detail = "DEAD", fmt.Sprintf("refresh %d: code %d, %v", rounds+1, code, err)
				return res
			}
			if err := s.refreshPeer(); err != nil {
				res.verdict, res.detail = "DEAD", fmt.Sprintf("round %d: %v", rounds+1, err)
				return res
			}
			rounds++
		}
		res.verdict, res.detail = s.after()
		res.detail = fmt.Sprintf("%d rounds answered; %s", rounds, res.detail)
	} else {
		if closed, how := s.stayQuiet(a.silence); how != "" {
			res.verdict, res.detail = "DEAD", fmt.Sprintf("the connection ended %s into the silence: %s", closed.Round(100*time.Millisecond), how)
			return res
		}
		res.verdict, res.detail = s.after()
		if !s.udp {
			res.detail = "no FIN/RST during the silence; " + res.detail
		}
	}
	if s.strayFrames > 0 {
		res.detail += fmt.Sprintf("; %d unasked frame(s) from the relay", s.strayFrames)
	}
	if res.verdict == "ALIVE" || res.verdict == "INBOUND DEAD" {
		_, _, _ = s.do(stun.MethodRefresh, lifetimeAttr(0)) // give the allocation back
	}
	return res
}

func maskIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.x.x", v4[0], v4[1])
	}
	return "v6"
}

func maskHost(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "?"
	}
	if ip := net.ParseIP(host); ip != nil {
		return maskIP(ip) + ":" + port
	}
	return "host:" + port
}

func main() {
	linkFile := flag.String("vk-link-file", "", "file holding the VK call link (kept out of the command line and of this tool's output)")
	transports := flag.String("transport", "tcp", "tcp, udp or tcp,udp — each gets its own credential (an identity carries ten allocations)")
	silences := flag.String("silence", "70s,130s,220s,400s,650s", "comma-separated silences; include one LONGER than the allocation lifetime — it must come back dead")
	peerFlag := flag.String("peer", "", "host:port of the PEER — this tool run with -peer-listen on ANOTHER host; the arms' permission and channel name it, and with -peer-token-file it is asked to send the UDP inbound question's datagrams")
	tokenFile := flag.String("peer-token-file", "", "file (mode 0600) holding the secret shared with the peer")
	peerListen := flag.String("peer-listen", "", "run as the PEER on this UDP address (e.g. :47000) instead of probing; needs -peer-token-file")
	peerAllow := flag.String("peer-allow", "", "peer mode: comma-separated networks the peer may be asked to send to (default: any public unicast address, unprivileged ports)")
	peerFor := flag.Duration("peer-for", time.Hour, "peer mode: stop by itself after this long")
	flag.DurationVar(&permissionLifetime, "permission-lifetime", permissionLifetime, "how old a permission may be for a missing inbound datagram to still count against the mapping (RFC: 5m; the VK relay was seen to honour one 6m40s old)")
	peerShape := flag.String("peer-shape", "rtp", "rtp or plain: what travels through the relay to and from the peer — the VK relay forwards nothing that is not shaped as media, so plain is the arm that must fail")
	noControl := flag.Bool("no-control", false, "skip the control arm (a Refresh + CreatePermission every 25 s for the longest silence)")
	flag.BoolVar(&osKeepalive, "os-keepalive", false, "leave Go's default TCP keepalive on the arms' sockets (a probe from THIS host every 15 s of idleness). Off by default: with it on, the far side is never idle and a measurement of ITS keepalive sees only our own probes and its answers — seen on the wire 2026-09-23")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *peerListen != "" {
		if err := runPeer(*peerListen, *tokenFile, *peerAllow, *peerFor); err != nil {
			log.Fatal(err)
		}
		return
	}

	raw, err := os.ReadFile(*linkFile)
	if err != nil {
		log.Fatalf("-vk-link-file: %v", err)
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || path.Base(u.Path) == "" || path.Base(u.Path) == "." {
		log.Fatal("-vk-link-file does not hold a call link")
	}
	if *peerShape != "rtp" && *peerShape != "plain" {
		log.Fatalf("-peer-shape: %q is neither rtp nor plain", *peerShape)
	}
	rtp := *peerShape == "rtp"
	var peer *net.UDPAddr
	if *peerFlag != "" {
		if peer, err = net.ResolveUDPAddr("udp4", *peerFlag); err != nil {
			log.Fatalf("-peer: %v", err)
		}
	}
	var quiet []time.Duration
	var longest time.Duration
	for _, f := range strings.Split(*silences, ",") {
		d, err := time.ParseDuration(strings.TrimSpace(f))
		if err != nil || d <= 0 {
			log.Fatalf("-silence: %q is not a duration", f)
		}
		quiet = append(quiet, d)
		if d > longest {
			longest = d
		}
	}

	var ask askFunc
	whyNoAsk := "no -peer: nobody on another host to send the datagram"
	switch {
	case peer != nil && *tokenFile != "":
		token, err := loadToken(*tokenFile)
		if err != nil {
			log.Fatalf("-peer-token-file: %v", err)
		}
		pc, err := newPeerClient(peer, token, rtp)
		if err != nil {
			log.Fatalf("-peer: %v", err)
		}
		ask, whyNoAsk = pc.ask, ""
		log.Printf("the peer is %s, asked through a socket of its own; datagrams through the relay are %s", maskHost(peer.String()), *peerShape)
	case peer != nil:
		whyNoAsk = "no -peer-token-file: the peer cannot be asked to send"
	}

	var results []result
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, tr := range strings.Split(*transports, ",") {
		tr = strings.TrimSpace(tr)
		if tr != "tcp" && tr != "udp" {
			log.Fatalf("-transport: %q is neither tcp nor udp", tr)
		}
		var arms []arm
		for _, d := range quiet {
			arms = append(arms, arm{name: tr + " silent " + d.String(), transport: tr, silence: d})
		}
		if !*noControl {
			arms = append(arms, arm{name: tr + " control", transport: tr, silence: longest, control: true})
		}
		if len(arms) > 10 {
			log.Fatalf("%d arms on %s: one credential carries ten allocations", len(arms), tr)
		}
		log.Printf("minting a TURN credential for the %s arms (the captcha-free path)…", tr)
		creds, err := proxy.GetVKCreds(path.Base(u.Path), nil, "", "", 0, 0, "", "")
		if err != nil {
			log.Fatalf("credentials: %v", err)
		}
		log.Printf("relay %s over %s, %d arm(s) on one credential, the longest %s", maskHost(creds.Address), strings.ToUpper(tr), len(arms), longest)
		for i, a := range arms {
			wg.Add(1)
			go func(i int, a arm, creds *proxy.TURNCreds) {
				defer wg.Done()
				time.Sleep(time.Duration(i) * 300 * time.Millisecond) // not one burst of Allocates
				r := runArm(a, creds.Address, creds, peer, ask, whyNoAsk, rtp)
				log.Printf("[%s] %s — %s", a.name, r.verdict, r.detail)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(i, a, creds)
		}
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.transport != b.transport {
			return a.transport < b.transport
		}
		if a.control != b.control {
			return !a.control
		}
		return a.silence < b.silence
	})
	fmt.Println()
	fmt.Printf("%-20s %-9s %-16s %s\n", "arm", "lifetime", "verdict", "detail")
	for _, r := range results {
		fmt.Printf("%-20s %-9s %-16s %s\n", r.name, r.allocated, r.verdict, r.detail)
	}
}
