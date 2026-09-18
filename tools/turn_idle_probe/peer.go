// SPDX-License-Identifier: MIT

package main

// The PEER — the second host of the UDP inbound question.
//
// A TURN relay forwards to its client only what a PEER sends to the
// allocation's relayed address, and the VK relay forwards nothing that comes
// from the client's own public address, nor from another allocation on the
// relay (both seen on the wire) — as in production, the peer lives on another
// host. This file is that peer and the probe's way of asking it:
//
//	probe (a socket of its OWN — a different NAT mapping than any arm's)
//	   ── ask: "send to <relayed ip:port>", HMAC over a shared token ──▶ peer
//	   ◀── ack (only an ask that was honoured is answered) ──
//	peer ── 3 small datagrams, from its LISTENING socket ──▶ relayed address
//	relay ── ChannelData / Data indication ──▶ the arm, through the old mapping
//
// What travels through the relay is SHAPED AS RTP (version 2, payload type 100
// — what the production transport's packets look like): with a bare payload
// the VK relay accepted the permission and the channel and then forwarded
// nothing, in either direction (seen on the wire at the peer: the arm's own
// datagram never came, the peer's three left and none arrived). -peer-shape
// plain keeps that arm runnable — the same bytes and the SAME LENGTH without
// the header in front, so that only the shape differs: it must fail where rtp
// passes.
//
// The peer is a UDP sender that strangers can reach, so it is built to be
// useless to them: nothing is sent and nothing is answered without a valid MAC
// over a fresh timestamp; a nonce is honoured once; the destination must be a
// public unicast address and an unprivileged port (or inside -peer-allow); an
// honoured ask costs the peer fewer bytes than it took to make; and the
// process ends by itself after -peer-for.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	peerMagic    = "TIP1"
	peerAskLen   = 64
	peerAckLen   = 48
	peerProbeLen = 16 // a multiple of four: the same bytes padded or not
	rtpHeaderLen = 12
	rtpPayload   = 100 // the production wrapper's payload type
	peerMaxCount = 3
	peerSkew     = 30 * time.Second
	peerMaxSeen  = 256 // nonces remembered at once — also the ceiling on honoured asks per window
	peerSenders  = 16
	peerAskTries = 3
	minTokenLen  = 16
)

// Vars: the tests shorten them.
var (
	peerSpacing = 300 * time.Millisecond // between the copies of one answer
	peerAskRTO  = 400 * time.Millisecond // an unacknowledged ask is repeated after this
)

const (
	peerAsk byte = iota + 1
	peerAck
	peerProbe
)

var (
	errNotAnAsk = errors.New("not an ask")
	errBadMAC   = errors.New("bad MAC")
	errStaleAsk = errors.New("stale timestamp")
	errBadCount = errors.New("bad count")
	errBadShape = errors.New("bad shape")
)

// rtpShaped puts payload behind a minimal RTP header.
func rtpShaped(payload []byte, seq uint16, ssrc uint32) []byte {
	b := make([]byte, rtpHeaderLen+len(payload))
	b[0], b[1] = 0x80, rtpPayload
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], uint32(seq)*960)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	copy(b[rtpHeaderLen:], payload)
	return b
}

// plainShaped is the control's shape: the payload first and rtpHeaderLen zero
// bytes after it — as long as the RTP shape, and nothing like media.
func plainShaped(payload []byte) []byte {
	return append(append([]byte(nil), payload...), make([]byte, rtpHeaderLen)...)
}

// unshaped is the payload behind an RTP header, or b itself when it has none.
func unshaped(b []byte) []byte {
	if len(b) >= rtpHeaderLen && b[0]&0xC0 == 0x80 {
		return b[rtpHeaderLen:]
	}
	return b
}

func peerMAC(token, b []byte) []byte {
	m := hmac.New(sha256.New, token)
	m.Write(b)
	return m.Sum(nil)
}

// buildAsk: magic, type, count, shape (1 = RTP), 0, unix seconds, nonce, IPv4,
// port, 2 × 0 — thirty-two bytes — and the MAC over them.
func buildAsk(token []byte, now time.Time, nonce [8]byte, dst *net.UDPAddr, count int, rtp bool) ([]byte, error) {
	ip := dst.IP.To4()
	if ip == nil {
		return nil, errors.New("the peer protocol carries IPv4 destinations only")
	}
	b := make([]byte, peerAskLen)
	copy(b, peerMagic)
	b[4], b[5] = peerAsk, byte(count)
	if rtp {
		b[6] = 1
	}
	binary.BigEndian.PutUint64(b[8:16], uint64(now.Unix()))
	copy(b[16:24], nonce[:])
	copy(b[24:28], ip)
	binary.BigEndian.PutUint16(b[28:30], uint16(dst.Port))
	copy(b[32:], peerMAC(token, b[:32]))
	return b, nil
}

// parseAsk believes nothing in a datagram before its MAC has been checked, and
// then still wants the timestamp fresh and the count within bounds. Replays and
// the destination rule are the server's, which holds the state for them.
func parseAsk(token []byte, now time.Time, b []byte) (nonce [8]byte, dst *net.UDPAddr, count int, rtp bool, err error) {
	if len(b) != peerAskLen || string(b[:4]) != peerMagic || b[4] != peerAsk {
		return nonce, nil, 0, false, errNotAnAsk
	}
	if !hmac.Equal(b[32:], peerMAC(token, b[:32])) {
		return nonce, nil, 0, false, errBadMAC
	}
	if age := now.Sub(time.Unix(int64(binary.BigEndian.Uint64(b[8:16])), 0)); age > peerSkew || age < -peerSkew {
		return nonce, nil, 0, false, errStaleAsk
	}
	if count = int(b[5]); count < 1 || count > peerMaxCount {
		return nonce, nil, 0, false, errBadCount
	}
	if b[6] > 1 {
		return nonce, nil, 0, false, errBadShape
	}
	copy(nonce[:], b[16:24])
	dst = &net.UDPAddr{IP: net.IP(append([]byte(nil), b[24:28]...)), Port: int(binary.BigEndian.Uint16(b[28:30]))}
	return nonce, dst, count, b[6] == 1, nil
}

func buildAck(token []byte, nonce [8]byte) []byte {
	b := make([]byte, peerAckLen)
	copy(b, peerMagic)
	b[4] = peerAck
	copy(b[8:16], nonce[:])
	copy(b[16:], peerMAC(token, b[:16]))
	return b
}

func isAckFor(token []byte, nonce [8]byte, b []byte) bool {
	return len(b) == peerAckLen && string(b[:4]) == peerMagic && b[4] == peerAck &&
		string(b[8:16]) == string(nonce[:]) && hmac.Equal(b[16:], peerMAC(token, b[:16]))
}

func buildProbe(nonce [8]byte, seq int) []byte {
	b := make([]byte, peerProbeLen)
	copy(b, peerMagic)
	b[4], b[5] = peerProbe, byte(seq)
	copy(b[8:], nonce[:])
	return b
}

// isProbeFor: is payload one of the datagrams the peer sent for THIS ask — in
// either shape?
func isProbeFor(nonce [8]byte, payload []byte) bool {
	payload = unshaped(payload)
	return len(payload) >= peerProbeLen && string(payload[:4]) == peerMagic && payload[4] == peerProbe &&
		string(payload[8:peerProbeLen]) == string(nonce[:])
}

// publicUnicast is the default rule for where the peer may be asked to send: a
// public IPv4 unicast address and an unprivileged port — never this host, its
// LAN, a carrier's inside, or a service port.
func publicUnicast(ip net.IP, port int) bool {
	v4 := ip.To4()
	if v4 == nil || port < 1024 {
		return false
	}
	if !v4.IsGlobalUnicast() || v4.IsPrivate() || v4[0] == 0 || v4[0] >= 224 {
		return false
	}
	return !(v4[0] == 100 && v4[1]&0xC0 == 64) // 100.64.0.0/10
}

// allowRule: the default, or "inside one of these networks" when -peer-allow
// names any.
func allowRule(csv string) (func(net.IP, int) bool, error) {
	if strings.TrimSpace(csv) == "" {
		return publicUnicast, nil
	}
	var nets []*net.IPNet
	for _, f := range strings.Split(csv, ",") {
		_, n, err := net.ParseCIDR(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return func(ip net.IP, port int) bool {
		for _, n := range nets {
			if port > 0 && n.Contains(ip) {
				return true
			}
		}
		return false
	}, nil
}

// loadToken reads the shared secret. A token that others on the host can read
// is refused: it is all that stands between the peer and a stranger.
func loadToken(file string) ([]byte, error) {
	st, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o) — chmod 600", file, st.Mode().Perm())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	token := []byte(strings.TrimSpace(string(raw)))
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("%s holds %d bytes, want at least %d", file, len(token), minTokenLen)
	}
	return token, nil
}

type peerServer struct {
	conn  *net.UDPConn
	token []byte
	allow func(net.IP, int) bool
	now   func() time.Time

	mu      sync.Mutex
	seen    map[[8]byte]time.Time
	refused map[string]int
	asks    int
	senders chan struct{}
}

func newPeerServer(conn *net.UDPConn, token []byte, allow func(net.IP, int) bool) *peerServer {
	return &peerServer{conn: conn, token: token, allow: allow, now: time.Now,
		seen: map[[8]byte]time.Time{}, refused: map[string]int{}, senders: make(chan struct{}, peerSenders)}
}

func (p *peerServer) refuse(why string) {
	p.mu.Lock()
	p.refused[why]++
	p.mu.Unlock()
}

// handle answers one datagram. Whatever is refused is refused in SILENCE — no
// reply to learn from or to aim at someone else — and only counted.
func (p *peerServer) handle(b []byte, from *net.UDPAddr) {
	now := p.now()
	nonce, dst, count, rtp, err := parseAsk(p.token, now, b)
	if err != nil {
		p.refuse(err.Error())
		return
	}
	if !p.allow(dst.IP, dst.Port) {
		p.refuse("destination not allowed")
		return
	}
	p.mu.Lock()
	for n, t := range p.seen {
		if now.Sub(t) > 3*peerSkew { // an ask older than this no longer passes the timestamp check
			delete(p.seen, n)
		}
	}
	_, replay := p.seen[nonce]
	full := !replay && len(p.seen) >= peerMaxSeen
	if !replay && !full {
		p.seen[nonce] = now
		p.asks++
	}
	p.mu.Unlock()
	switch {
	case full:
		p.refuse("too many asks")
		return
	case !replay: // the same ask again (its ack was lost) is acknowledged again, not sent again
		select {
		case p.senders <- struct{}{}:
			go func() {
				defer func() { <-p.senders }()
				p.send(nonce, dst, count, rtp)
			}()
			log.Printf("peer: an ask from %s honoured → %d datagram(s) (%s) to %s:%d", maskIP(from.IP), count,
				map[bool]string{true: "rtp-shaped", false: "plain"}[rtp], maskIP(dst.IP), dst.Port)
		default:
			p.refuse("all senders busy")
			return
		}
	}
	_, _ = p.conn.WriteToUDP(buildAck(p.token, nonce), from)
}

// send goes out through the LISTENING socket: its address is the one the arm's
// permission and channel name, and the relay forwards from no other.
func (p *peerServer) send(nonce [8]byte, dst *net.UDPAddr, count int, rtp bool) {
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(peerSpacing)
		}
		b := plainShaped(buildProbe(nonce, i))
		if rtp {
			b = rtpShaped(buildProbe(nonce, i), uint16(i), binary.BigEndian.Uint32(nonce[:4]))
		}
		_, _ = p.conn.WriteToUDP(b, dst)
	}
}

func (p *peerServer) counters() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	parts := []string{fmt.Sprintf("honoured %d", p.asks)}
	var whys []string
	for why := range p.refused {
		whys = append(whys, why)
	}
	sort.Strings(whys)
	for _, why := range whys {
		parts = append(parts, fmt.Sprintf("%s %d", why, p.refused[why]))
	}
	return strings.Join(parts, ", ")
}

// serve runs until the deadline — the peer is up for a test, not for good.
func (p *peerServer) serve(until time.Time) error {
	buf := make([]byte, 512)
	last, nextReport := "", time.Now().Add(time.Minute)
	for time.Now().Before(until) {
		wake := nextReport
		if until.Before(wake) {
			wake = until
		}
		_ = p.conn.SetReadDeadline(wake)
		n, from, err := p.conn.ReadFromUDP(buf)
		switch {
		case err == nil:
			p.handle(append([]byte(nil), buf[:n]...), from)
		case !isTimeout(err):
			return err
		}
		if !time.Now().Before(nextReport) {
			if c := p.counters(); c != last {
				log.Printf("peer: %s", c)
				last = c
			}
			nextReport = time.Now().Add(time.Minute)
		}
	}
	log.Printf("peer: done — %s", p.counters())
	return nil
}

func runPeer(listen, tokenFile, allowCSV string, upFor time.Duration) error {
	token, err := loadToken(tokenFile)
	if err != nil {
		return fmt.Errorf("-peer-token-file: %w", err)
	}
	allow, err := allowRule(allowCSV)
	if err != nil {
		return fmt.Errorf("-peer-allow: %w", err)
	}
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return fmt.Errorf("-peer-listen: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("peer: listening on %s for %s; an ask needs the token, a fresh timestamp, a new nonce and %s",
		conn.LocalAddr(), upFor, map[bool]string{true: "a public unicast destination on an unprivileged port", false: "a destination inside -peer-allow"}[allowCSV == ""])
	return newPeerServer(conn, token, allow).serve(time.Now().Add(upFor))
}

// peerClient asks the peer from a socket of its OWN: an ask that left through
// an arm's socket would re-open the very mapping the arm is asking about.
type peerClient struct {
	mu    sync.Mutex
	conn  *net.UDPConn
	token []byte
	rtp   bool // the shape asked for
}

func newPeerClient(peer *net.UDPAddr, token []byte, rtp bool) (*peerClient, error) {
	conn, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		return nil, err
	}
	return &peerClient{conn: conn, token: token, rtp: rtp}, nil
}

// ask has the peer send its datagrams to dst. acked says the peer CONFIRMED —
// it answers only an ask it honours — so "not acked" is a verdict on the path
// to the peer and never on the arm's mapping. An ask is repeated with the same
// nonce (the peer sends once per nonce) and a fresh timestamp.
func (c *peerClient) ask(dst *net.UDPAddr) (nonce [8]byte, acked bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err = rand.Read(nonce[:]); err != nil {
		return nonce, false, err
	}
	defer c.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 512)
	for try := 0; try < peerAskTries; try++ {
		req, err := buildAsk(c.token, time.Now(), nonce, dst, peerMaxCount, c.rtp)
		if err != nil {
			return nonce, false, err
		}
		if _, err := c.conn.Write(req); err != nil {
			return nonce, false, fmt.Errorf("the ask to the peer: %w", err)
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(peerAskRTO))
		for {
			n, err := c.conn.Read(buf)
			if err != nil {
				if isTimeout(err) {
					break
				}
				return nonce, false, fmt.Errorf("the peer's answer: %w", err) // ICMP unreachable: nobody listens there
			}
			if isAckFor(c.token, nonce, buf[:n]) {
				return nonce, true, nil
			}
		}
	}
	return nonce, false, nil
}
