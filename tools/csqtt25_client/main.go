// csqtt25_client is the first console stage of a csqtt 2.5 client: ONE
// worker, no TUN. It answers one question — does a 2.5 server take a client
// that never speaks DTLS, on keys derived from the password alone (the WRAP
// schedule)? — and exercises the rest of the wire on the way: GETCONF and
// TUNCONF, READY, GETWORKERS, raw IP packets both ways (ICMP, a DNS query),
// a packet large enough to travel as fragments, DISCONNECT.
//
// -keys chooses what the datagrams are sealed with: wrap (the schedule under
// test), raw (the wrap key itself — the server's last resort) or wrong (the
// schedule of ANOTHER password: the arm that must be refused, with silence).
//
// Everything this tool prints starts with "c25:" and carries no password, no
// TURN username, no link and no public address; the libraries' own lines go
// to stderr.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

func say(format string, a ...any) { fmt.Printf("c25: "+format+"\n", a...) }

func fail(format string, a ...any) {
	say("FAILED: "+format, a...)
	os.Exit(1)
}

func readSecret(file, what string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		fail("%s: cannot read the file", what)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	fail("%s: the file is empty", what)
	return ""
}

func main() {
	linkFile := flag.String("link-file", "", "file holding the csqtt:// link of a 2.5 server (host, port, password)")
	vkLinkFile := flag.String("vk-link-file", "", "file holding the VK call link the TURN credentials are minted from (default: the link's first hash)")
	keysArm := flag.String("keys", "wrap", "wrap (password-derived, no handshake), dtls (a DTLS 1.2 handshake, keys from its exporter), auto (dtls, then wrap — the reference's default), raw (the wrap key itself), wrong (another password's keys — must be refused) or dtls-wrong (a handshake, then one flipped key bit — must be refused)")
	modeName := flag.String("mode", "unified", "sender shaping: unified, audio or video")
	workers := flag.Int("workers", 18, "desired worker count announced in GETCONF and GETWORKERS (this stage runs worker 1 only)")
	pings := flag.Int("pings", 3, "small ICMP echoes to send through the tunnel")
	pingTarget := flag.String("ping", "", "ICMP echo target (default: .1 of the tunnel's /24)")
	bigSize := flag.Int("big", 1400, "size of one large ICMP echo (IP packet bytes; above 1280 it travels as fragments; 0 = skip)")
	dnsName := flag.String("dns-name", "example.com", "name asked of the tunnel's DNS server in one UDP query (empty = skip)")
	stay := flag.Duration("stay", 0, "keep the session open this long before DISCONNECT, answering nothing but keepalives")
	turnTransport := flag.String("turn-transport", "udp", "control transport to the VK relay: udp or tcp")
	flag.Parse()
	if *linkFile == "" {
		fail("-link-file is required")
	}
	mode, err := csqtt25.ParseMode(*modeName)
	if err != nil {
		fail("%v", err)
	}

	link, err := csqtt25.DecodeLink(readSecret(*linkFile, "-link-file"))
	if err != nil {
		fail("the link: %v", err)
	}
	say("link: decoded (2.5 form), port %d, password %d chars, %d call hash(es), token %v", link.Port, len(link.Password), len(link.Hashes), link.Token != "")
	ips, err := net.LookupIP(link.Host)
	if err != nil || len(ips) == 0 {
		fail("the link's host does not resolve")
	}
	var peer *net.UDPAddr
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			peer = &net.UDPAddr{IP: v4, Port: link.Port}
			break
		}
	}
	if peer == nil {
		fail("the link's host has no IPv4 address")
	}

	linkID := ""
	if *vkLinkFile != "" {
		u, err := url.Parse(readSecret(*vkLinkFile, "-vk-link-file"))
		if err != nil {
			fail("-vk-link-file does not hold a URL")
		}
		linkID = path.Base(u.Path)
	} else if len(link.Hashes) > 0 {
		linkID = link.Hashes[0]
	}
	if linkID == "" || linkID == "." || linkID == "/" {
		fail("no VK call link: give -vk-link-file")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── credentials and the allocation ───────────────────────────────────
	t0 := time.Now()
	creds, err := proxy.GetVKCreds(linkID, nil, "", "", 0, 0, "", "")
	if err != nil {
		fail("VK credentials: %s", scrub(err.Error()))
	}
	say("vk: credentials minted in %d ms (%d relay address(es))", time.Since(t0).Milliseconds(), len(creds.Addresses))
	t0 = time.Now()
	relay, err := csqtt.DialRelay(csqtt.TURNCredentials{Username: creds.Username, Password: creds.Password, Address: creds.Address},
		peer, *turnTransport, logging.LogLevelError, nil)
	if err != nil {
		fail("TURN allocation: %s", scrub(err.Error()))
	}
	defer relay.Close()
	say("turn: allocated and permitted in %d ms (%s to the relay)", time.Since(t0).Milliseconds(), *turnTransport)

	// ── keys ─────────────────────────────────────────────────────────────
	wrapKey, err := csqtt25.WrapKey(link.Password)
	if err != nil {
		fail("%v", err)
	}
	split := csqtt25.NewSplitter(relay.Conn, peer)
	var keys csqtt25.Keys
	handshake := "NO DTLS handshake"
	switch *keysArm {
	case "wrap":
		keys = csqtt25.WrapKeys(wrapKey)
	case "dtls", "auto", "dtls-wrong":
		t0 = time.Now()
		keys, err = csqtt25.Handshake(ctx, split)
		switch {
		case err == nil:
			handshake = fmt.Sprintf("DTLS handshake done in %d ms, keys from its exporter", time.Since(t0).Milliseconds())
			if *keysArm == "dtls-wrong" {
				keys.Client[0] ^= 1 // the handshake's key, one bit off: the arm that must be refused
				handshake += ", then ONE BIT of the sending key flipped"
			}
		case *keysArm == "auto":
			handshake = fmt.Sprintf("DTLS handshake FAILED after %d ms (%s) — fell back to password-derived keys", time.Since(t0).Milliseconds(), scrub(err.Error()))
			keys = csqtt25.WrapKeys(wrapKey)
		default:
			fail("DTLS handshake after %d ms: %s", time.Since(t0).Milliseconds(), scrub(err.Error()))
		}
	case "raw":
		keys = csqtt25.RawKeys(wrapKey)
	case "wrong":
		other, _ := csqtt25.WrapKey(link.Password + "-not-the-password")
		keys = csqtt25.WrapKeys(other)
	default:
		fail("-keys must be wrap, dtls, auto, raw, wrong or dtls-wrong")
	}
	split.Seal() // only the wrapper speaks from here on
	sendC, err := csqtt25.NewCipher(keys.Client)
	if err != nil {
		fail("%v", err)
	}
	recvC, _ := csqtt25.NewCipher(keys.Server)
	wrapper, err := csqtt25.NewWrapper(sendC, mode)
	if err != nil {
		fail("%v", err)
	}
	say("keys: arm %q, mode %s, %s", *keysArm, *modeName, handshake)
	s := &session{relay: relay.Conn, peer: peer, wrapper: wrapper, recv: recvC, inbound: make(chan []byte, 512), reasm: csqtt25.NewReassembler()}
	go s.readLoop(split.Media())

	// ── GETCONF ──────────────────────────────────────────────────────────
	generation := uint64(time.Now().UnixMilli())
	salt := randomHex(16)
	req := csqtt25.ConfigRequest("9000", link.Password, generation, salt, 1, *workers)
	var conf csqtt25.ConfigResponse
	got := false
	t0 = time.Now()
	for attempt, wait := range []time.Duration{400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3000 * time.Millisecond} {
		// The reference sends each GETCONF twice.
		for i := 0; i < 2; i++ {
			if err := s.send([]byte(req)); err != nil {
				fail("GETCONF send: %s", scrub(err.Error()))
			}
		}
		if p := s.waitFor(ctx, wait, csqtt25.IsConfigResponse); p != nil {
			conf, err = csqtt25.ParseConfigResponse(p)
			if err != nil {
				s.stats()
				fail("GETCONF answered: %v", err)
			}
			say("GETCONF: answered on attempt %d after %d ms", attempt+1, time.Since(t0).Milliseconds())
			got = true
			break
		}
	}
	if !got {
		s.stats()
		if *keysArm == "wrong" || *keysArm == "dtls-wrong" {
			say("RESULT: the wrong keys were answered with SILENCE over %d ms — the refused arm is refused", time.Since(t0).Milliseconds())
			return
		}
		fail("no answer to GETCONF in %d ms (silence is what a server gives to keys it cannot use)", time.Since(t0).Milliseconds())
	}
	src := net.ParseIP(conf.TunnelIP).To4()
	if src == nil {
		fail("TUNCONF carries no IPv4 tunnel address")
	}
	say("TUNCONF: tunnel %s, dns %s, stream %q, workers=%d", conf.TunnelIP, maskPublic(conf.DNS), conf.Stream, conf.Workers)
	if *keysArm == "wrong" || *keysArm == "dtls-wrong" {
		fail("the WRONG keys were accepted — the refused arm was not refused")
	}

	// ── READY, GETWORKERS ────────────────────────────────────────────────
	t0 = time.Now()
	if err := s.send([]byte(csqtt25.ReadyRequest)); err != nil {
		fail("READY send: %s", scrub(err.Error()))
	}
	if p := s.waitFor(ctx, 3*time.Second, func(p []byte) bool { return string(p) == csqtt25.ReadyOK }); p != nil {
		say("READY: READY_OK in %d ms", time.Since(t0).Milliseconds())
	} else {
		say("READY: no READY_OK within 3 s")
	}
	t0 = time.Now()
	if err := s.send([]byte(csqtt25.WorkersRequest(link.Password, *workers))); err == nil {
		if p := s.waitFor(ctx, 3*time.Second, func(p []byte) bool { _, _, ok := csqtt25.ParseWorkers(p); return ok }); p != nil {
			agreed, limit, _ := csqtt25.ParseWorkers(p)
			say("GETWORKERS: asked %d, agreed %d, server limit %d (0 = none), in %d ms", *workers, agreed, limit, time.Since(t0).Milliseconds())
		} else {
			say("GETWORKERS: no answer within 3 s")
		}
	}

	// ── raw IP through the tunnel ────────────────────────────────────────
	dst := append(net.IP(nil), src...)
	dst[3] = 1
	if *pingTarget != "" {
		if dst = net.ParseIP(*pingTarget).To4(); dst == nil {
			fail("-ping is not IPv4")
		}
	}
	id := binary.BigEndian.Uint16(randomBytes(2))
	echo := func(seq uint16, size int, label string) bool {
		pkt := icmpEcho(src, dst, id, seq, size-28)
		t := time.Now()
		frags, err := s.sendPacket(pkt)
		if err != nil {
			say("%s: send failed: %s", label, scrub(err.Error()))
			return false
		}
		reply := s.waitFor(ctx, 2*time.Second, func(p []byte) bool {
			rid, rseq, ok := icmpEchoReply(p, dst, src)
			return ok && rid == id && rseq == seq
		})
		if reply == nil {
			say("%s: %d B out in %d datagram(s), NO reply within 2 s", label, len(pkt), frags)
			return false
		}
		intact := len(reply) == len(pkt) && string(reply[28:]) == string(pkt[28:])
		say("%s: %d B out in %d datagram(s), reply %d B in %.1f ms, payload intact %v", label, len(pkt), frags, len(reply), float64(time.Since(t).Microseconds())/1000, intact)
		return intact
	}
	okSmall := 0
	for i := 1; i <= *pings && ctx.Err() == nil; i++ {
		if echo(uint16(i), 84, fmt.Sprintf("icmp %d to %s", i, maskPublic(dst.String()))) {
			okSmall++
		}
		time.Sleep(200 * time.Millisecond)
	}
	okBig := false
	if *bigSize > 0 && ctx.Err() == nil {
		before := s.fragsIn.Load()
		okBig = echo(1000, *bigSize, fmt.Sprintf("icmp large to %s", maskPublic(dst.String())))
		say("fragments: %d received and reassembled for the large reply", s.fragsIn.Load()-before)
	}
	okDNS := false
	if *dnsName != "" && ctx.Err() == nil {
		if dnsIP := net.ParseIP(strings.Split(conf.DNS, ",")[0]).To4(); dnsIP != nil {
			port := 40000 + binary.BigEndian.Uint16(randomBytes(2))%20000
			qid := binary.BigEndian.Uint16(randomBytes(2))
			t := time.Now()
			if _, err := s.sendPacket(udpPacket(src, dnsIP, port, 53, dnsQuery(qid, *dnsName))); err == nil {
				reply := s.waitFor(ctx, 3*time.Second, func(p []byte) bool {
					payload, ok := udpReply(p, dnsIP, src, 53, port)
					return ok && len(payload) >= 12 && binary.BigEndian.Uint16(payload[0:2]) == qid
				})
				if reply != nil {
					payload, _ := udpReply(reply, dnsIP, src, 53, port)
					answers := binary.BigEndian.Uint16(payload[6:8])
					okDNS = payload[3]&0x0f == 0
					say("dns: %q asked of %s through the tunnel — rcode %d, %d answer(s), %d B, in %.1f ms", *dnsName, maskPublic(dnsIP.String()), payload[3]&0x0f, answers, len(reply), float64(time.Since(t).Microseconds())/1000)
				} else {
					say("dns: no reply within 3 s")
				}
			}
		}
	}

	if *stay > 0 {
		say("staying %s…", *stay)
		s.idle(ctx, *stay)
	}

	// ── DISCONNECT ───────────────────────────────────────────────────────
	t0 = time.Now()
	if err := s.send([]byte(csqtt25.DisconnectRequest(link.Password, salt))); err == nil {
		if p := s.waitFor(context.Background(), 2*time.Second, func(p []byte) bool {
			return string(p) == csqtt25.DisconnectedResponse || strings.HasPrefix(string(p), "DENIED:")
		}); p != nil {
			say("DISCONNECT: %s in %d ms", csqtt25.ControlName(p), time.Since(t0).Milliseconds())
		} else {
			say("DISCONNECT: no answer within 2 s")
		}
	}
	s.stats()
	say("RESULT: arm %q — TUNCONF yes, small echoes %d/%d, large echo %v, dns %v", *keysArm, okSmall, *pings, okBig, okDNS)
	if okSmall == 0 && !okDNS {
		os.Exit(1)
	}
}

// ─── session ─────────────────────────────────────────────────────────────

type session struct {
	relay   net.PacketConn
	peer    *net.UDPAddr
	wrapper *csqtt25.Wrapper
	recv    *csqtt25.Cipher
	inbound chan []byte
	reasm   *csqtt25.Reassembler
	fragID  uint16
	wireBuf []byte

	sent, rx, nonRTP, unwrapErr, control, data, fragsIn atomic.Int64
	names                                               [16]atomic.Int64
	kinds                                               [8]atomic.Int64 // what the data plaintexts were (kindNames)
}

var kindNames = []string{"icmp", "udp", "tcp", "ipv4-other", "ipv6", "0xff-unknown", "other"}

// kindOf sorts a data plaintext for the stats line.
func kindOf(p []byte) int {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		switch p[9] {
		case 1:
			return 0
		case 17:
			return 1
		case 6:
			return 2
		}
		return 3
	case len(p) >= 40 && p[0]>>4 == 6:
		return 4
	case len(p) > 0 && p[0] == 0xff:
		return 5
	}
	return 6
}

var controlNames = []string{"TUNCONF", "NOCONF", "DENIED", "READY_OK", "OK:disconnected", "ROUTING", "TUNWORKERS", "WORKERS", "PANEL_RESTART", "STREAM_REPAIR", "STREAM_ALIVE", "PATH_ECHO", "KEEPALIVE"}

// send wraps one plaintext and writes it. Main goroutine only.
func (s *session) send(plain []byte) error {
	wire, err := s.wrapper.Wrap(s.wireBuf, plain)
	if err != nil {
		return err
	}
	if _, err := s.relay.WriteTo(wire, s.peer); err != nil {
		return err
	}
	s.sent.Add(1)
	return nil
}

// sendPacket sends one IP packet: whole up to WholeMax, else as fragments.
func (s *session) sendPacket(pkt []byte) (datagrams int, err error) {
	if len(pkt) <= csqtt25.WholeMax {
		return 1, s.send(pkt)
	}
	s.fragID++
	frags := csqtt25.Fragment(s.fragID, pkt)
	if frags == nil {
		return 0, errors.New("the packet cannot be fragmented")
	}
	for _, f := range frags {
		if err := s.send(f); err != nil {
			return 0, err
		}
	}
	return len(frags), nil
}

// readLoop turns the socket's non-DTLS datagrams into plaintexts.
func (s *session) readLoop(media <-chan []byte) {
	defer close(s.inbound)
	for wire := range media {
		s.rx.Add(1)
		if !csqtt25.IsRTP(wire) {
			s.nonRTP.Add(1)
			continue
		}
		plain, _, err := s.recv.Unwrap(wire)
		if err != nil {
			s.unwrapErr.Add(1)
			continue
		}
		if name := csqtt25.ControlName(plain); name != "" && (csqtt25.IsControl(plain) || csqtt25.IsIdleKeepalive(plain)) {
			s.control.Add(1)
			for i, n := range controlNames {
				if n == name {
					s.names[i].Add(1)
				}
			}
		} else if csqtt25.IsFragment(plain) {
			s.fragsIn.Add(1)
			whole, done := s.reasm.Push(plain, time.Now())
			if !done {
				continue
			}
			plain = whole
			s.data.Add(1)
			s.kinds[kindOf(plain)].Add(1)
		} else {
			s.data.Add(1)
			s.kinds[kindOf(plain)].Add(1)
		}
		select {
		case s.inbound <- plain:
		default:
		}
	}
}

func (s *session) waitFor(ctx context.Context, timeout time.Duration, match func([]byte) bool) []byte {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case p, ok := <-s.inbound:
			if !ok {
				return nil
			}
			if match(p) {
				return p
			}
		}
	}
}

func (s *session) idle(ctx context.Context, d time.Duration) {
	end := time.NewTimer(d)
	defer end.Stop()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-end.C:
			return
		case <-tick.C:
			_ = s.send(csqtt25.IdleKeepalive)
		case _, ok := <-s.inbound:
			if !ok {
				return
			}
		}
	}
}

func (s *session) stats() {
	var parts []string
	for i, n := range controlNames {
		if c := s.names[i].Load(); c > 0 {
			parts = append(parts, fmt.Sprintf("%s×%d", n, c))
		}
	}
	var kinds []string
	for i, n := range kindNames {
		if c := s.kinds[i].Load(); c > 0 {
			kinds = append(kinds, fmt.Sprintf("%s×%d", n, c))
		}
	}
	say("stats: sent %d, received %d (not RTP %d, failed authentication %d, control %d, data %d, fragments %d); control seen: %s; data by kind: %s",
		s.sent.Load(), s.rx.Load(), s.nonRTP.Load(), s.unwrapErr.Load(), s.control.Load(), s.data.Load(), s.fragsIn.Load(), strings.Join(parts, " "), strings.Join(kinds, " "))
}

// ─── packets ─────────────────────────────────────────────────────────────

func ipHeader(pkt []byte, proto byte, src, dst net.IP, id uint16) {
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
}

func icmpEcho(src, dst net.IP, id, seq uint16, payloadLen int) []byte {
	if payloadLen < 0 {
		payloadLen = 0
	}
	pkt := make([]byte, 20+8+payloadLen)
	ipHeader(pkt, 1, src, dst, id)
	icmp := pkt[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	for i := 8; i < len(icmp); i++ {
		icmp[i] = byte(i * 7)
	}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return pkt
}

func icmpEchoReply(p []byte, from, to net.IP) (id, seq uint16, ok bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 {
		return 0, 0, false
	}
	hl := int(p[0]&0x0f) * 4
	if hl != 20 || !net.IP(p[12:16]).Equal(from) || !net.IP(p[16:20]).Equal(to) || p[hl] != 0 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(p[hl+4 : hl+6]), binary.BigEndian.Uint16(p[hl+6 : hl+8]), true
}

func udpPacket(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	ipHeader(pkt, 17, src, dst, binary.BigEndian.Uint16(randomBytes(2)))
	u := pkt[20:]
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	copy(u[8:], payload)
	// The UDP checksum over the pseudo-header.
	pseudo := make([]byte, 12, 12+len(u)+1)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(u)))
	sum := checksum(append(pseudo, u...))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], sum)
	return pkt
}

func udpReply(p []byte, from, to net.IP, sport, dport uint16) ([]byte, bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 || int(p[0]&0x0f)*4 != 20 {
		return nil, false
	}
	if !net.IP(p[12:16]).Equal(from) || !net.IP(p[16:20]).Equal(to) {
		return nil, false
	}
	u := p[20:]
	if binary.BigEndian.Uint16(u[0:2]) != sport || binary.BigEndian.Uint16(u[2:4]) != dport {
		return nil, false
	}
	return u[8:], true
}

func dnsQuery(id uint16, name string) []byte {
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[0:2], id)
	q[2] = 0x01 // recursion desired
	q[5] = 1    // one question
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1) // root, type A, class IN
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ─── keeping addresses and secrets out of the output ─────────────────────

func isPrivate(ip net.IP) bool { return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() }

// maskPublic leaves a private address readable and hides a public one.
func maskPublic(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil && !isPrivate(ip) {
			parts[i] = "<public>"
		}
	}
	return strings.Join(parts, ",")
}

// scrub drops everything address- or identity-shaped from a library's error.
func scrub(s string) string {
	var out []string
	for _, w := range strings.Fields(s) {
		if strings.ContainsAny(w, "0123456789") || len(w) > 24 {
			out = append(out, "…")
			continue
		}
		out = append(out, w)
	}
	return strings.Join(out, " ")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fail("no randomness")
	}
	return b
}

func randomHex(n int) string { return hex.EncodeToString(randomBytes(n)) }
