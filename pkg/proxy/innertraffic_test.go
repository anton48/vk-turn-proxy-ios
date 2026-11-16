package proxy

import (
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Packets by hand. The phone is 10.0.0.2 / fd00::2, the far side a
// documentation address.
var (
	innerPhone4 = []byte{10, 0, 0, 2}
	innerFar4   = []byte{203, 0, 113, 7}
	innerFar4b  = []byte{203, 0, 113, 8}
	innerPhone6 = append([]byte{0xfd, 0}, append(make([]byte, 13), 2)...)
	innerFar6   = append([]byte{0x20, 0x01, 0x0d, 0xb8}, append(make([]byte, 11), 7)...)
	// innerFar6twin: an IPv6 address whose first four bytes are innerFar4's and
	// the rest zero — the same sixteen bytes a table keeps for the IPv4 host.
	innerFar6twin = append([]byte{203, 0, 113, 7}, make([]byte, 12)...)
)

func ip4(proto byte, src, dst, l4 []byte) []byte {
	p := make([]byte, 20, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(20+len(l4)))
	p[8], p[9] = 64, proto
	copy(p[12:16], src)
	copy(p[16:20], dst)
	return append(p, l4...)
}

func ip6(next byte, src, dst, l4 []byte) []byte {
	p := make([]byte, 40, 40+len(l4))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(l4)))
	p[6], p[7] = next, 64
	copy(p[8:24], src)
	copy(p[24:40], dst)
	return append(p, l4...)
}

func tcpSeg(sport, dport uint16, flags byte) []byte {
	s := make([]byte, 20)
	binary.BigEndian.PutUint16(s[0:2], sport)
	binary.BigEndian.PutUint16(s[2:4], dport)
	s[12], s[13] = 5<<4, flags
	return s
}

func udpSeg(sport, dport uint16, payload []byte) []byte {
	s := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(s[0:2], sport)
	binary.BigEndian.PutUint16(s[2:4], dport)
	binary.BigEndian.PutUint16(s[4:6], uint16(8+len(payload)))
	return append(s, payload...)
}

func dnsMsg(id uint16) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:2], id)
	return m
}

func syn(port uint16) []byte { return ip4(protoTCP, innerPhone4, innerFar4, tcpSeg(port, 443, tcpSYN)) }
func synAck(port uint16) []byte {
	return ip4(protoTCP, innerFar4, innerPhone4, tcpSeg(443, port, tcpSYN|tcpACK))
}

// synTo: a connection asked of `far` on `dport`, over the family the address has.
func synTo(port uint16, far []byte, dport uint16) []byte {
	if len(far) == 16 {
		return ip6(protoTCP, innerPhone6, far, tcpSeg(port, dport, tcpSYN))
	}
	return ip4(protoTCP, innerPhone4, far, tcpSeg(port, dport, tcpSYN))
}
func rstTo(port uint16) []byte {
	return ip4(protoTCP, innerFar4, innerPhone4, tcpSeg(443, port, tcpRST|tcpACK))
}
func dnsAsk(port, id uint16) []byte {
	return ip4(protoUDP, innerPhone4, innerFar4, udpSeg(port, 53, dnsMsg(id)))
}
func dnsReply(port, id uint16) []byte {
	return ip4(protoUDP, innerFar4, innerPhone4, udpSeg(53, port, dnsMsg(id)))
}
func quicOut(port uint16) []byte {
	return ip4(protoUDP, innerPhone4, innerFar4, udpSeg(port, 443, make([]byte, 30)))
}
func quicIn(port uint16) []byte {
	return ip4(protoUDP, innerFar4, innerPhone4, udpSeg(443, port, make([]byte, 30)))
}

// listen adds whole seconds of on-time steps to the listening clock.
func listen(t *InnerTraffic, seconds int) {
	for i := 0; i < seconds; i++ {
		t.Step(time.Second, time.Second)
	}
}

func TestParseInnerReadsTheHeadersItCountsBy(t *testing.T) {
	pk, ok := parseInner(syn(50000))
	if !ok || !pk.l4 || pk.v6 || pk.proto != protoTCP || pk.sport != 50000 || pk.dport != 443 || pk.flags != tcpSYN {
		t.Fatalf("an IPv4 SYN: %+v ok=%v", pk, ok)
	}
	if string(pk.src[:4]) != string(innerPhone4) || string(pk.dst[:4]) != string(innerFar4) {
		t.Fatalf("an IPv4 packet's addresses: %v → %v", pk.src, pk.dst)
	}
	// IPv4 options move the transport header.
	opt := ip4(protoTCP, innerPhone4, innerFar4, nil)
	opt[0] = 0x46
	opt = append(opt, 1, 1, 1, 1)
	opt = append(opt, tcpSeg(50001, 80, tcpSYN|tcpACK)...)
	if pk, ok := parseInner(opt); !ok || pk.sport != 50001 || pk.dport != 80 || pk.flags != tcpSYN|tcpACK {
		t.Fatalf("an IPv4 header with options: %+v ok=%v", pk, ok)
	}
	// A later fragment has no transport header: counted as a packet, read as nothing.
	frag := syn(50000)
	binary.BigEndian.PutUint16(frag[6:8], 185)
	if pk, ok := parseInner(frag); !ok || pk.l4 {
		t.Fatalf("a later fragment must carry no transport reading: %+v ok=%v", pk, ok)
	}
	// IPv6, plain and behind an extension header.
	six := ip6(protoUDP, innerPhone6, innerFar6, udpSeg(40000, 53, dnsMsg(0x1234)))
	if pk, ok := parseInner(six); !ok || !pk.v6 || !pk.l4 || pk.proto != protoUDP || pk.dport != 53 || !pk.hasID || pk.dnsID != 0x1234 {
		t.Fatalf("an IPv6 DNS question: %+v ok=%v", pk, ok)
	}
	ext := append([]byte{protoTCP, 0, 0, 0, 0, 0, 0, 0}, tcpSeg(40001, 443, tcpSYN)...)
	if pk, ok := parseInner(ip6(60, innerPhone6, innerFar6, ext)); !ok || !pk.l4 || pk.proto != protoTCP || pk.sport != 40001 {
		t.Fatalf("an IPv6 packet behind a destination-options header: %+v ok=%v", pk, ok)
	}
	laterFrag := append([]byte{protoUDP, 0, 0, 8, 0, 0, 0, 1}, udpSeg(1, 2, nil)...)
	if pk, ok := parseInner(ip6(44, innerPhone6, innerFar6, laterFrag)); !ok || pk.l4 {
		t.Fatalf("a later IPv6 fragment must carry no transport reading: %+v ok=%v", pk, ok)
	}
	// What is not an IP packet, and what is cut short.
	for name, p := range map[string][]byte{
		"empty": nil, "version 5": {0x50, 0, 0, 0}, "a short IPv4 header": syn(1)[:19], "a short IPv6 header": six[:39],
		"an IPv4 header length below five words": append([]byte{0x44}, syn(1)[1:]...),
	} {
		if _, ok := parseInner(p); ok {
			t.Errorf("%s was read as an IP packet", name)
		}
	}
	if pk, ok := parseInner(syn(1)[:30]); !ok || pk.l4 {
		t.Fatalf("a TCP header cut short must carry no transport reading: %+v ok=%v", pk, ok)
	}
}

func TestATCPConnectionIsAskedOnceAndAnsweredRefusedOrSilent(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(syn(50000))
	tr.Out(syn(50000)) // the same connection asking again
	tr.Out(syn(50001))
	tr.Out(syn(50002))
	tr.Out(syn(50003))
	tr.In(synAck(50000))
	tr.In(synAck(50000)) // a repeated answer is not a second connection
	tr.In(rstTo(50001))
	tr.In(rstTo(60000)) // a reset of something nobody asked for here
	// The phone answering a connection made TO it, and an ordinary segment: no asks.
	tr.Out(ip4(protoTCP, innerPhone4, innerFar4, tcpSeg(50010, 443, tcpSYN|tcpACK)))
	tr.Out(ip4(protoTCP, innerPhone4, innerFar4, tcpSeg(50011, 443, tcpACK)))
	listen(tr, 9)
	line := tr.Take(60 * time.Second)
	want := "tcp: 4 asked (5 SYN), 1 answered, 1 refused, 0 silent 10s+, 2 RST in"
	if !strings.Contains(line, want) {
		t.Fatalf("after 9 s of listening\n got %q\nwant it to hold %q", line, want)
	}
	// One more second of listening: the two nobody answered are silent — said once.
	listen(tr, 1)
	if line := tr.Take(60 * time.Second); !strings.Contains(line, "tcp: 0 asked (0 SYN), 0 answered, 0 refused, 2 silent 10s+ (1 host(s); 2 v4 / 0 v6; 2 https / 0 http / 0 other), 0 RST in") {
		t.Fatalf("at 10 s of listening the two unanswered asks must be silent: %q", line)
	}
	tr.Out(syn(50002)) // still asking — a repeat, a packet, not a new connection
	listen(tr, 30)
	if line := tr.Take(60 * time.Second); !strings.Contains(line, "tcp: 0 asked (1 SYN), 0 answered, 0 refused, 0 silent 10s+") {
		t.Fatalf("a silent ask is said once and its repeats are not new connections: %q", line)
	}
	// An answer that comes after the ask was called silent is counted, and said late.
	tr.In(synAck(50003))
	if line := tr.Take(60 * time.Second); !strings.Contains(line, "1 answered (1 late), 0 refused") {
		t.Fatalf("a late answer: %q", line)
	}
}

func TestSilenceIsCountedInListeningNotOnTheWallClock(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(syn(50000))
	tr.Out(dnsAsk(40000, 7))
	tr.Out(quicOut(41000))
	// A suspension: one step five minutes late, then the line. Nothing was listened to.
	tr.Step(5*time.Minute, time.Second)
	line := tr.Take(5*time.Minute + time.Second)
	for _, want := range []string{"0 silent 10s+, 0 RST in", "0 silent 5s+", "udp: 1 flows sent, 0 heard, 0 never answered 10s+"} {
		if !strings.Contains(line, want) {
			t.Fatalf("across a suspension nothing may be called silent\n got %q\nwant it to hold %q", line, want)
		}
	}
	if !strings.Contains(line, "the last 5m1s (awake 0s)") {
		t.Fatalf("the line must say how much of its span the process ran: %q", line)
	}
	// A step of exactly twice the grain is still listening; anything longer is not.
	tr.Step(2*time.Second, time.Second)
	tr.Step(2*time.Second+time.Millisecond, time.Second)
	tr.Step(-time.Second, time.Second)
	if tr.listened != 2*time.Second {
		t.Fatalf("listening after an on-time, a late and a backward step: %v, want 2s", tr.listened)
	}
	listen(tr, 3)
	if line := tr.Take(time.Minute); !strings.Contains(line, "dns: 0 asked (0 sent), 0 answered, 1 silent 5s+") || !strings.Contains(line, "0 silent 10s+, 0 RST in") {
		t.Fatalf("at 5 s of listening the question is silent and the connection is not yet: %q", line)
	}
	listen(tr, 5)
	if line := tr.Take(time.Minute); !strings.Contains(line, "tcp: 0 asked (0 SYN), 0 answered, 0 refused, 1 silent 10s+") || !strings.Contains(line, "udp: 0 flows sent, 0 heard, 1 never answered 10s+ (quic 0 / 0 / 1)") {
		t.Fatalf("at 10 s of listening the connection is silent and the flow never answered: %q", line)
	}
}

func TestADNSQuestionIsMatchedByItsPortItsServerAndItsID(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(dnsAsk(40000, 1))
	tr.Out(dnsAsk(40000, 1)) // sent again
	tr.Out(dnsAsk(40000, 2))
	tr.Out(dnsAsk(40001, 1))
	tr.In(dnsReply(40000, 1))
	tr.In(dnsReply(40000, 9))                                                   // another id
	tr.In(dnsReply(40002, 2))                                                   // another port
	tr.In(ip4(protoUDP, innerFar4b, innerPhone4, udpSeg(53, 40001, dnsMsg(1)))) // another server
	listen(tr, 5)
	line := tr.Take(time.Minute)
	if want := "dns: 3 asked (4 sent), 1 answered, 2 silent 5s+"; !strings.Contains(line, want) {
		t.Fatalf("\n got %q\nwant it to hold %q", line, want)
	}
	if !strings.Contains(line, "udp: 0 flows sent, 0 heard, 0 never answered 10s+ (quic 0 / 0 / 0)") {
		t.Fatalf("a DNS question is not one of the other UDP flows: %q", line)
	}
}

func TestOtherUDPFlowsSentHeardAndNeverAnswered(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(quicOut(41000))
	tr.Out(quicOut(41000))
	tr.Out(quicOut(41001))
	tr.Out(ip4(protoUDP, innerPhone4, innerFar4, udpSeg(42000, 3478, make([]byte, 20))))
	tr.In(quicIn(41000))
	tr.In(quicIn(49999)) // for a flow that never sent: not a flow of ours
	listen(tr, 9)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 3 flows sent, 1 heard, 0 never answered 10s+ (quic 2 / 1 / 0)") {
		t.Fatalf("at 9 s of listening no flow is given up on yet: %q", line)
	}
	listen(tr, 1)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 0 flows sent, 0 heard, 2 never answered 10s+ (quic 0 / 0 / 1)") {
		t.Fatalf("at 10 s of listening since their first packet the two that heard nothing: %q", line)
	}
	// Said once, however long the flow goes on sending into silence.
	tr.Out(ip4(protoUDP, innerPhone4, innerFar4, udpSeg(42000, 3478, make([]byte, 20))))
	listen(tr, 30)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 1 flows sent, 0 heard, 0 never answered 10s+") {
		t.Fatalf("a flow nobody answers is said once: %q", line)
	}
	// An answer alone is no flow that sent.
	tr.In(quicIn(41001))
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 0 flows sent, 0 heard, 0 never answered 10s+") {
		t.Fatalf("an answer alone is no flow that sent: %q", line)
	}
}

// 🚨 The ordinary life of a flow: it opens, exchanges, and ENDS with a packet of
// the phone's that nobody answers (an acknowledgement, a close). That is not a
// flow nobody answered — on a phone it was seven of ten flows of a healthy run.
func TestAFlowThatHeardAnAnswerIsNeverSaidUnanswered(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(quicOut(43000))
	tr.In(quicIn(43000))
	tr.Out(quicOut(43000))
	tr.In(quicIn(43000))
	tr.Out(quicOut(43000)) // its last word: the phone's
	tr.Out(quicOut(43000))
	listen(tr, 60)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 1 flows sent, 1 heard, 0 never answered 10s+ (quic 1 / 1 / 0)") {
		t.Fatalf("a flow that ended the ordinary way was called unanswered: %q", line)
	}
	// Minutes later it speaks again into silence: still a flow that was answered.
	tr.Out(quicOut(43000))
	listen(tr, 60)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 1 flows sent, 0 heard, 0 never answered 10s+ (quic 1 / 0 / 0)") {
		t.Fatalf("a flow that was answered once is not «never answered» later: %q", line)
	}
	// The ten seconds run from the flow's FIRST packet, not from its latest.
	tr.Out(quicOut(44000))
	listen(tr, 6)
	tr.Out(quicOut(44000))
	listen(tr, 3)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 1 flows sent, 0 heard, 0 never answered 10s+") {
		t.Fatalf("nine seconds of listening since a flow's first packet is too early to give it up: %q", line)
	}
	listen(tr, 1)
	if line := tr.Take(time.Minute); !strings.Contains(line, "1 never answered 10s+ (quic 0 / 0 / 1)") {
		t.Fatalf("ten seconds of listening since a flow's first packet with nothing heard: %q", line)
	}
	// A flow nobody used for two minutes is forgotten: the same ports later are a
	// new flow, and a new flow nobody answers is said.
	listen(tr, 120)
	tr.Take(time.Minute)
	tr.Out(quicOut(44000))
	listen(tr, 10)
	if line := tr.Take(time.Minute); !strings.Contains(line, "1 never answered 10s+ (quic 1 / 0 / 1)") {
		t.Fatalf("a forgotten flow's ports are a new flow: %q", line)
	}
}

// 🚨 Whom the silent connections were asked of — as counts: one dead host and a
// deaf path read the same in «N silent» and apart here.
func TestSilentConnectionsAreSplitByHostFamilyAndPortClass(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(synTo(50000, innerFar4, 443))
	tr.Out(synTo(50001, innerFar4, 443))
	tr.Out(synTo(50002, innerFar4, 443))
	tr.Out(synTo(50003, innerFar4b, 80))
	tr.Out(synTo(50004, innerFar4b, 8080))
	tr.Out(synTo(50005, innerFar6, 443))
	tr.Out(synTo(50006, innerFar6twin, 443))
	tr.In(synAck(50000)) // one of the seven is answered
	listen(tr, 10)
	line := tr.Take(time.Minute)
	want := "tcp: 7 asked (7 SYN), 1 answered, 0 refused, 6 silent 10s+ (4 host(s); 4 v4 / 2 v6; 4 https / 1 http / 1 other), 0 RST in"
	if !strings.Contains(line, want) {
		t.Fatalf("\n got %q\nwant it to hold %q", line, want)
	}
	for _, leak := range []string{"203.0.113", "2001:", "50003", "8080", "443", ":80"} {
		if strings.Contains(line, leak) {
			t.Fatalf("the split carries %q — it must say counts only: %q", leak, line)
		}
	}
	// The split is of the asks found silent in THIS line: said once, like them.
	tr.Out(synTo(50007, innerFar4b, 80))
	listen(tr, 10)
	if line := tr.Take(time.Minute); !strings.Contains(line, "1 silent 10s+ (1 host(s); 1 v4 / 0 v6; 0 https / 1 http / 0 other), 0 RST in") {
		t.Fatalf("the next line's split is its own: %q", line)
	}
	// No silent connection, no split — and a DNS question going silent adds
	// nothing to the connections' split.
	tr.Out(dnsAsk(40000, 1))
	listen(tr, 5)
	if line := tr.Take(time.Minute); !strings.Contains(line, "0 silent 10s+, 0 RST in; tcp established: 0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent; dns: 1 asked (1 sent), 0 answered, 1 silent 5s+;") {
		t.Fatalf("a silent question is no silent connection: %q", line)
	}
}

func TestTheLineByteForByte(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(syn(50000))
	tr.In(synAck(50000))
	tr.Out(segOut(50000, tcpACK, 4000001, 120))
	tr.In(segIn(50000, tcpACK, 7000001, 700))
	tr.Out(dnsAsk(40000, 1))
	tr.In(dnsReply(40000, 1))
	tr.Out(quicOut(41000))
	tr.In(quicIn(41000))
	tr.In(ip4(protoICMP, innerFar4, innerPhone4, []byte{3, 1, 0, 0}))
	tr.In(ip4(protoICMP, innerFar4, innerPhone4, []byte{0, 0, 0, 0}))
	tr.In(ip6(protoICMPv6, innerFar6, innerPhone6, []byte{1, 0, 0, 0}))
	tr.Out(ip4(47, innerPhone4, innerFar4, make([]byte, 8))) // neither tcp, udp nor icmp
	tr.Out([]byte{0x00, 1, 2})                               // not an IP packet
	listen(tr, 60)
	got := tr.Take(60 * time.Second)
	want := "inner, the last 1m0s: 6 pkt out / 7 in; tcp: 1 asked (1 SYN), 1 answered, 0 refused, 0 silent 10s+, 0 RST in; " +
		"tcp established: 1 sent data, 1 heard (1 with data), 0 stalled 10s+, 0 segment(s) re-sent; " +
		"dns: 1 asked (1 sent), 1 answered, 0 silent 5s+; udp: 1 flows sent, 1 heard, 0 never answered 10s+ (quic 1 / 1 / 0); " +
		"icmp in: 3 (2 unreachable); other: 2"
	if got != want {
		t.Fatalf("the line\n got %q\nwant %q", got, want)
	}
	// 🚨 Counts only: no address and no port of a packet may reach the line.
	for _, leak := range []string{"203.0.113", "10.0.0.2", "2001:", "50000", "40000", "41000", "4000001", "7000001", "120", "700"} {
		if strings.Contains(got, leak) {
			t.Fatalf("the line carries %q — it must say counts only: %q", leak, got)
		}
	}
	// A period is its own: the next line starts from nothing.
	tr.Out(syn(50009))
	listen(tr, 2)
	if got := tr.Take(2 * time.Second); !strings.HasPrefix(got, "inner, the last 2s: 1 pkt out / 0 in; tcp: 1 asked (1 SYN), 0 answered, 0 refused, 0 silent 10s+, 0 RST in; tcp established: 0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent; dns: 0 asked") || strings.Contains(got, "icmp in: 3") || strings.Contains(got, "other:") {
		t.Fatalf("a new period carried the last one's counts: %q", got)
	}
}

func TestAQuietTunnelIsSaidOnce(t *testing.T) {
	tr := newInnerTraffic()
	listen(tr, 60)
	if got := tr.Take(time.Minute); got != "inner, the last 1m0s: no packet either way" {
		t.Fatalf("the first quiet period: %q", got)
	}
	if got := tr.Take(time.Minute); got != "" {
		t.Fatalf("a second quiet period must say nothing: %q", got)
	}
	tr.Out(syn(50000))
	if got := tr.Take(time.Minute); !strings.Contains(got, "1 pkt out / 0 in") {
		t.Fatalf("a packet ends the quiet: %q", got)
	}
	listen(tr, 10)
	// No packet, but an ask just turned silent: that is news, not quiet.
	if got := tr.Take(time.Minute); !strings.Contains(got, "0 pkt out / 0 in") || !strings.Contains(got, "1 silent 10s+") {
		t.Fatalf("an ask turning silent in a period without packets must be said: %q", got)
	}
	listen(tr, 60)
	if got := tr.Take(time.Minute); got != "inner, the last 1m0s: no packet either way" {
		t.Fatalf("quiet again after traffic is said again: %q", got)
	}
}

func TestTheTablesAreBoundedAndForget(t *testing.T) {
	tr := newInnerTraffic()
	for i := 0; i < innerMaxPending+3; i++ {
		tr.Out(syn(uint16(1000 + i)))
	}
	if len(tr.tcp) != innerMaxPending {
		t.Fatalf("pending connections: %d, want the bound %d", len(tr.tcp), innerMaxPending)
	}
	for i := 0; i < innerMaxFlows+2; i++ {
		tr.Out(quicOut(uint16(1000 + i)))
	}
	if len(tr.udp) != innerMaxFlows {
		t.Fatalf("udp flows: %d, want the bound %d", len(tr.udp), innerMaxFlows)
	}
	line := tr.Take(time.Minute)
	if !strings.Contains(line, "tcp: 2051 asked (2051 SYN)") || !strings.HasSuffix(line, "; not tracked: 5 (a table is full)") {
		t.Fatalf("past the bound an ask is still asked, and said as not tracked: %q", line)
	}
	// What nobody answered and nobody used is forgotten after two minutes of listening.
	listen(tr, 119)
	tr.Take(time.Minute)
	if len(tr.tcp) == 0 || len(tr.udp) == 0 {
		t.Fatalf("forgotten too early: %d pending, %d flows at 119 s", len(tr.tcp), len(tr.udp))
	}
	listen(tr, 1)
	tr.Take(time.Minute)
	if len(tr.tcp) != 0 || len(tr.udp) != 0 {
		t.Fatalf("not forgotten: %d pending, %d flows at 120 s of listening", len(tr.tcp), len(tr.udp))
	}
}

// fakeInnerTUN hands out and takes packets as wireguard-go's device does: at an
// offset inside each buffer.
type fakeInnerTUN struct {
	tun.Device
	reads   [][]byte
	written [][]byte
}

func (f *fakeInnerTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for ; n < len(f.reads) && n < len(bufs); n++ {
		copy(bufs[n][offset:], f.reads[n])
		sizes[n] = len(f.reads[n])
	}
	return n, nil
}

func (f *fakeInnerTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeInnerTUN) File() *os.File { return nil }

func TestTheWrapperShowsEveryPacketAndChangesNone(t *testing.T) {
	SetInnerTrafficLog(true)
	defer SetInnerTrafficLog(false)
	tr := innerNow.Load()
	if tr == nil {
		t.Fatal("the switch is on and there is no counter")
	}
	fake := &fakeInnerTUN{reads: [][]byte{syn(50000), dnsAsk(40000, 1)}}
	dev := WrapTUNForInner(fake)
	const offset = 4
	bufs := [][]byte{make([]byte, 2000), make([]byte, 2000), make([]byte, 2000)}
	sizes := make([]int, 3)
	n, err := dev.Read(bufs, sizes, offset)
	if n != 2 || err != nil || string(bufs[0][offset:offset+sizes[0]]) != string(syn(50000)) {
		t.Fatalf("the wrapper changed what Read returns: n=%d err=%v", n, err)
	}
	down := append(make([]byte, offset), synAck(50000)...)
	if n, err := dev.Write([][]byte{down}, offset); n != 1 || err != nil || len(fake.written) != 1 || string(fake.written[0]) != string(synAck(50000)) {
		t.Fatalf("the wrapper changed what Write passes on: n=%d err=%v", n, err)
	}
	if dev.File() != nil {
		t.Fatal("File must be the device's own")
	}
	line := tr.Take(time.Minute)
	if !strings.Contains(line, "2 pkt out / 1 in; tcp: 1 asked (1 SYN), 1 answered") || !strings.Contains(line, "dns: 1 asked (1 sent)") {
		t.Fatalf("the packets that passed the wrapper were not counted as they are: %q", line)
	}
}

func TestOffNothingIsCountedAndTheRunnerIsGone(t *testing.T) {
	SetInnerTrafficLog(false)
	if innerNow.Load() != nil {
		t.Fatal("off by default")
	}
	ObserveInnerOut(syn(50000)) // must not touch anything
	ObserveInnerIn(synAck(50000))
	SetInnerTrafficLog(true)
	first := innerNow.Load()
	SetInnerTrafficLog(true) // a second «on» starts no second runner and keeps the counter
	if innerNow.Load() != first {
		t.Fatal("a second «on» replaced the counter — and left the first runner behind")
	}
	ObserveInnerOut(syn(50000))
	ObserveInnerIn(synAck(50000))
	if first == nil || first.pktOutIn() != [2]uint64{1, 1} {
		t.Fatalf("on, the packets are counted once: %v", first)
	}
	innerRun.mu.Lock()
	done := innerRun.done
	innerRun.mu.Unlock()
	SetInnerTrafficLog(false)
	select {
	case <-done:
	default:
		t.Fatal("turning the line off must wait for its runner to end")
	}
	ObserveInnerOut(syn(50001))
	if innerNow.Load() != nil || first.pktOutIn() != [2]uint64{1, 1} {
		t.Fatal("off, a packet reaches no counter")
	}
	SetInnerTrafficLog(true)
	defer SetInnerTrafficLog(false)
	if fresh := innerNow.Load(); fresh == nil || fresh == first || fresh.pktOutIn() != [2]uint64{0, 0} {
		t.Fatal("on again the counting starts from nothing")
	}
}

func (t *InnerTraffic) pktOutIn() [2]uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return [2]uint64{t.pktOut, t.pktIn}
}

func TestTheBridgesViewOfTheCounter(t *testing.T) {
	SetInnerTrafficLog(false)
	if out, in, on := InnerTrafficCounts(); out != 0 || in != 0 || on {
		t.Fatalf("off: %d / %d on=%v", out, in, on)
	}
	SetInnerTrafficLog(true)
	defer SetInnerTrafficLog(false)
	ObserveInnerOut(syn(50000))
	ObserveInnerOut(syn(50001))
	ObserveInnerIn(synAck(50000))
	if out, in, on := InnerTrafficCounts(); out != 2 || in != 1 || !on {
		t.Fatalf("on, two out and one in: %d / %d on=%v", out, in, on)
	}
}

func TestTheRunnerListensInStepsAndSaysTheLine(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(syn(50000))
	var mu sync.Mutex
	var lines []string
	stop, done := make(chan struct{}), make(chan struct{})
	go runInnerTraffic(tr, 5*time.Millisecond, 40*time.Millisecond, stop, done, func(line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not end with its stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) < 2 {
		t.Fatalf("the runner said %d line(s) in five seconds, want the traffic's and the quiet one", len(lines))
	}
	if !regexp.MustCompile(`^inner, the last \d+s: 1 pkt out / 0 in; tcp: 1 asked \(1 SYN\)`).MatchString(lines[0]) {
		t.Fatalf("the first line: %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], ": no packet either way") {
		t.Fatalf("the second line: %q", lines[1])
	}
	if tr.listened <= 0 {
		t.Fatal("the runner's steps added no listening")
	}
}

// ── the connections past their handshake ──────────────────────────────────

// tcpData: a segment with a sequence number and `n` bytes of payload.
func tcpData(sport, dport uint16, flags byte, seq uint32, n int) []byte {
	s := tcpSeg(sport, dport, flags)
	binary.BigEndian.PutUint32(s[4:8], seq)
	return append(s, make([]byte, n)...)
}

// segOut / segIn: a segment between the phone's `port` and the far side's 443.
func segOut(port uint16, flags byte, seq uint32, n int) []byte {
	return ip4(protoTCP, innerPhone4, innerFar4, tcpData(port, 443, flags, seq, n))
}
func segIn(port uint16, flags byte, seq uint32, n int) []byte {
	return ip4(protoTCP, innerFar4, innerPhone4, tcpData(443, port, flags, seq, n))
}

// estPart: what a line says of the established connections.
func estPart(line string) string {
	const head = "; tcp established: "
	i := strings.Index(line, head)
	if i < 0 {
		return "(no such part in: " + line + ")"
	}
	rest := line[i+len(head):]
	if j := strings.Index(rest, "; dns:"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// estSays takes the period's line and compares its established part.
func estSays(t *testing.T, tr *InnerTraffic, when, want string) {
	t.Helper()
	if got := estPart(tr.Take(time.Minute)); got != want {
		t.Fatalf("%s\n got %q\nwant %q", when, got, want)
	}
}

// openConn: the handshake of a connection the phone makes, as it passes.
func openConn(tr *InnerTraffic, port uint16) {
	tr.Out(syn(port))
	tr.In(synAck(port))
	tr.Out(segOut(port, tcpACK, 1, 0))
}

func TestParseInnerMeasuresATCPSegmentsPayloadByTheHeaders(t *testing.T) {
	read := func(name string, p []byte, seq uint32, payload int) {
		t.Helper()
		pk, ok := parseInner(p)
		if !ok || !pk.l4 || !pk.hasSeq || pk.seq != seq || pk.payload != payload {
			t.Fatalf("%s: seq %d payload %d hasSeq=%v l4=%v ok=%v, want seq %d payload %d", name, pk.seq, pk.payload, pk.hasSeq, pk.l4, ok, seq, payload)
		}
	}
	read("a bare acknowledgement", segOut(50000, tcpACK, 0x01020304, 0), 0x01020304, 0)
	read("a segment with data", segOut(50000, tcpACK, 0x01020304, 37), 0x01020304, 37)
	// TCP options are header, not payload.
	withOpts := tcpData(50000, 443, tcpACK, 77, 12+5)
	withOpts[12] = 8 << 4
	read("twelve bytes of TCP options and five of data", ip4(protoTCP, innerPhone4, innerFar4, withOpts), 77, 5)
	bareOpts := tcpData(50000, 443, tcpACK, 78, 12)
	bareOpts[12] = 8 << 4
	read("an acknowledgement with twelve bytes of options carries no data", ip4(protoTCP, innerPhone4, innerFar4, bareOpts), 78, 0)
	// IP options too.
	ipOpts := ip4(protoTCP, innerPhone4, innerFar4, nil)
	ipOpts[0] = 0x46
	ipOpts = append(ipOpts, 1, 1, 1, 1)
	ipOpts = append(ipOpts, tcpData(50000, 443, tcpACK, 79, 9)...)
	binary.BigEndian.PutUint16(ipOpts[2:4], uint16(len(ipOpts)))
	read("an IPv4 header with options", ipOpts, 79, 9)
	// What lies in the buffer behind the packet's own length is no payload.
	read("an IPv4 acknowledgement with six bytes behind its end", append(segOut(50000, tcpACK, 80, 0), 1, 2, 3, 4, 5, 6), 80, 0)
	six := ip6(protoTCP, innerPhone6, innerFar6, tcpData(50000, 443, tcpACK, 81, 21))
	read("an IPv6 segment with data", six, 81, 21)
	read("an IPv6 acknowledgement with six bytes behind its end", append(ip6(protoTCP, innerPhone6, innerFar6, tcpData(50000, 443, tcpACK, 82, 0)), 1, 2, 3, 4, 5, 6), 82, 0)
	ext := append([]byte{protoTCP, 0, 0, 0, 0, 0, 0, 0}, tcpData(50000, 443, tcpACK, 83, 4)...)
	read("an IPv6 segment behind a destination-options header", ip6(60, innerPhone6, innerFar6, ext), 83, 4)
	// A header whose own length cannot be: its flags are read as before, no payload is.
	for name, hdr := range map[string]byte{"a data offset below five words": 4 << 4, "a data offset beyond the packet": 15 << 4} {
		bad := tcpData(50000, 443, tcpACK, 84, 10)
		bad[12] = hdr
		if pk, ok := parseInner(ip4(protoTCP, innerPhone4, innerFar4, bad)); !ok || !pk.l4 || pk.flags != tcpACK || pk.hasSeq || pk.payload != 0 {
			t.Fatalf("%s: %+v ok=%v", name, pk, ok)
		}
	}
	// A packet cut short of the length its header states is read as far as it goes.
	cut6 := ip6(protoTCP, innerPhone6, innerFar6, tcpData(50000, 443, tcpACK, 85, 21))[:40+16]
	if pk, ok := parseInner(cut6); !ok || !pk.l4 || pk.flags != tcpACK || pk.hasSeq || pk.payload != 0 {
		t.Fatalf("an IPv6 packet cut short inside its TCP header: %+v ok=%v", pk, ok)
	}
	cut4 := segOut(50000, tcpACK, 86, 21)[:20+16]
	if pk, ok := parseInner(cut4); !ok || !pk.l4 || pk.flags != tcpACK || pk.hasSeq || pk.payload != 0 {
		t.Fatalf("an IPv4 packet cut short inside its TCP header: %+v ok=%v", pk, ok)
	}
	short := ip4(protoTCP, innerPhone4, innerFar4, tcpSeg(50000, 443, tcpACK)[:16])
	if pk, ok := parseInner(short); !ok || !pk.l4 || pk.flags != tcpACK || pk.hasSeq || pk.payload != 0 {
		t.Fatalf("sixteen bytes of a TCP header: the flags and nothing more: %+v ok=%v", pk, ok)
	}
}

// 🚨 The ordinary life of a connection — it opens, asks, is answered, idles, is
// kept alive, closes; it only downloads; it is dropped by either side — must
// read «0 stalled» and «0 re-sent» in every line.
func TestAnEstablishedConnectionsOrdinaryLifeIsNeverStalled(t *testing.T) {
	tr := newInnerTraffic()
	const quiet = "inner, the last 1m0s: no packet either way"
	idle := func(when string) {
		t.Helper()
		listen(tr, 60)
		if got := tr.Take(time.Minute); got != quiet {
			t.Fatalf("%s: an idle minute must be quiet: %q", when, got)
		}
		listen(tr, 60)
		if got := tr.Take(time.Minute); got != "" {
			t.Fatalf("%s: a second idle minute must say nothing: %q", when, got)
		}
	}
	// A request and its answer; the phone's bare acknowledgement is its last word.
	const p = 51000
	openConn(tr, p)
	tr.Out(segOut(p, tcpACK, 1, 300))
	tr.In(segIn(p, tcpACK, 1, 0))
	tr.In(segIn(p, tcpACK, 1, 1200))
	tr.Out(segOut(p, tcpACK, 301, 0))
	listen(tr, 60)
	estSays(t, tr, "a request and its answer", "1 sent data, 1 heard (1 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	idle("behind the answer")
	// A keepalive of the phone's — no data, an old sequence number — and its answer.
	tr.Out(segOut(p, tcpACK, 300, 0))
	tr.In(segIn(p, tcpACK, 1201, 0))
	listen(tr, 60)
	estSays(t, tr, "a keepalive", "0 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// A keepalive nobody answers is no data either: nothing waits behind it.
	tr.Out(segOut(p, tcpACK, 300, 0))
	listen(tr, 60)
	estSays(t, tr, "a keepalive nobody answered", "0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// It closes: the phone's last data with its FIN, the far side's acknowledgement and FIN, the last acknowledgement.
	tr.Out(segOut(p, tcpACK|tcpFIN, 301, 24))
	tr.In(segIn(p, tcpACK, 1201, 0))
	tr.In(segIn(p, tcpACK|tcpFIN, 1201, 0))
	tr.Out(segOut(p, tcpACK, 326, 0))
	listen(tr, 60)
	estSays(t, tr, "the close", "1 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	idle("behind the close")

	// A download: the phone only acknowledges.
	const q = 51001
	openConn(tr, q)
	for i := 0; i < 5; i++ {
		tr.In(segIn(q, tcpACK, uint32(1+1000*i), 1000))
		tr.Out(segOut(q, tcpACK, 1, 0))
	}
	listen(tr, 60)
	estSays(t, tr, "a download", "0 sent data, 1 heard (1 with data), 0 stalled 10s+, 0 segment(s) re-sent")

	// The phone drops a connection of its own: data, its reset, and nothing ever comes back.
	const r = 51002
	openConn(tr, r)
	tr.Out(segOut(r, tcpACK, 1, 40))
	tr.Out(segOut(r, tcpRST|tcpACK, 41, 0))
	listen(tr, 60)
	estSays(t, tr, "a connection the phone reset behind its own data", "1 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	idle("behind the phone's reset")

	// The far side resets one — and a segment the phone had sent before it learnt of
	// that passes behind the reset.
	const s = 51003
	openConn(tr, s)
	tr.Out(segOut(s, tcpACK, 1, 40))
	tr.In(segIn(s, tcpRST, 1, 0))
	tr.Out(segOut(s, tcpACK, 41, 40))
	listen(tr, 60)
	estSays(t, tr, "a connection the far side reset", "1 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// A minute on — the connection is still remembered as reset — one more of the
	// phone's and a straggler of the far side's: neither is read.
	tr.Out(segOut(s, tcpACK, 41, 40))
	tr.In(segIn(s, tcpACK, 1, 9))
	if c := tr.est[innerKey{remote: [16]byte{203, 0, 113, 7}, local: s, rport: 443}]; c == nil || !c.reset {
		t.Fatalf("a reset connection must be remembered as reset for two minutes: %+v", c)
	}
	listen(tr, 30)
	estSays(t, tr, "stragglers on a reset connection", "0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
}

func TestDataSentIntoSilenceOnAnEstablishedConnectionIsStalledOnce(t *testing.T) {
	tr := newInnerTraffic()
	const p = 52000
	openConn(tr, p)
	listen(tr, 30) // an idle connection waits for nothing
	tr.Take(time.Minute)
	tr.Out(segOut(p, tcpACK, 1, 200)) // the request nobody answers
	listen(tr, 9)
	estSays(t, tr, "nine seconds of listening behind the data", "1 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// The phone's stack sends it again, twice. The ten seconds run from the FIRST segment.
	tr.Out(segOut(p, tcpACK, 1, 200))
	tr.Out(segOut(p, tcpACK, 1, 200))
	listen(tr, 1)
	estSays(t, tr, "ten seconds of listening behind the first unanswered segment", "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 2 segment(s) re-sent")
	// Said once, however long it goes on.
	tr.Out(segOut(p, tcpACK, 1, 200))
	listen(tr, 30)
	estSays(t, tr, "a stalled connection is said once", "1 sent data, 0 heard (0 with data), 0 stalled 10s+, 1 segment(s) re-sent")
	// It hears again — a bare acknowledgement is enough: late.
	tr.In(segIn(p, tcpACK, 1, 0))
	estSays(t, tr, "an answer behind a stall", "0 sent data, 1 heard (0 with data) (1 late), 0 stalled 10s+, 0 segment(s) re-sent")
	// A new wait is a new one: said again, and its ten seconds are its own.
	tr.Out(segOut(p, tcpACK, 201, 100))
	listen(tr, 6)
	tr.In(segIn(p, tcpACK, 1, 0)) // answered inside its ten seconds
	tr.Out(segOut(p, tcpACK, 301, 100))
	listen(tr, 9)
	estSays(t, tr, "a wait that was answered, and nine seconds of the next", "1 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// No packet in this period — and a connection turns stalled in it: news, not quiet.
	listen(tr, 1)
	if line := tr.Take(time.Minute); !strings.Contains(line, "0 pkt out / 0 in") || estPart(line) != "0 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent" {
		t.Fatalf("a connection turning stalled in a period without packets must be said: %q", line)
	}
	// Data with the FIN, unanswered: closing does not end the wait.
	const q = 52001
	openConn(tr, q)
	tr.Out(segOut(q, tcpACK|tcpFIN, 1, 50))
	listen(tr, 10)
	estSays(t, tr, "the last data with a FIN, never acknowledged", "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent")
}

// 🚨 A wait that lasted its ten seconds is a stall wherever the lines fall: one
// that ends BETWEEN two lines — answered late, or given up by the phone — is
// counted in the line that follows, not lost.
func TestAStallThatEndsBetweenTwoLinesIsStillCounted(t *testing.T) {
	tr := newInnerTraffic()
	// Answered after thirty seconds, before any line saw it standing.
	const p = 52600
	openConn(tr, p)
	tr.Out(segOut(p, tcpACK, 1, 200))
	listen(tr, 30)
	tr.In(segIn(p, tcpACK, 1, 0))
	estSays(t, tr, "answered after thirty seconds, inside one line", "1 sent data, 1 heard (0 with data) (1 late), 1 stalled 10s+, 0 segment(s) re-sent")
	if line := tr.Take(time.Minute); strings.Contains(line, "stalled") || strings.Contains(line, "late") {
		t.Fatalf("a stall counted once is not said again in a period without packets: %q", line)
	}
	// Answered at nine seconds: no stall, nothing late.
	tr.Out(segOut(p, tcpACK, 201, 200))
	listen(tr, 9)
	tr.In(segIn(p, tcpACK, 1, 0))
	estSays(t, tr, "answered at nine seconds", "1 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// The phone gives one up after twelve seconds of silence: a stall, and no late answer.
	const q = 52601
	openConn(tr, q)
	tr.Out(segOut(q, tcpACK, 1, 200))
	listen(tr, 12)
	tr.Out(segOut(q, tcpRST|tcpACK, 201, 0))
	estSays(t, tr, "given up by the phone after twelve seconds", "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent")
	// …and one it gives up after nine: none.
	const r = 52602
	openConn(tr, r)
	tr.Out(segOut(r, tcpACK, 1, 200))
	listen(tr, 9)
	tr.Out(segOut(r, tcpRST|tcpACK, 201, 0))
	listen(tr, 60)
	estSays(t, tr, "given up by the phone after nine seconds", "1 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// The same ports asked anew behind twelve seconds of silence: the old connection's stall.
	const s = 52603
	openConn(tr, s)
	tr.Out(segOut(s, tcpACK, 1, 200))
	listen(tr, 12)
	tr.Out(syn(s))
	estSays(t, tr, "replaced after twelve seconds of silence", "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent")
	// A stall a line has already said, then given up or replaced: not said twice, and nothing late.
	const u = 52604
	openConn(tr, u)
	tr.Out(segOut(u, tcpACK, 1, 200))
	listen(tr, 10)
	estSays(t, tr, "said standing", "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent")
	tr.Out(segOut(u, tcpRST|tcpACK, 201, 0))
	estSays(t, tr, "then given up", "0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
}

func TestAStallIsCountedInListeningNotOnTheWallClock(t *testing.T) {
	tr := newInnerTraffic()
	const p = 52500
	openConn(tr, p)
	tr.Out(segOut(p, tcpACK, 1, 200))
	tr.Step(5*time.Minute, time.Second) // a suspension
	estSays(t, tr, "across a suspension", "1 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	listen(tr, 9)
	tr.Step(10*time.Minute, time.Second)
	if line := tr.Take(time.Minute); strings.Contains(line, "stalled") {
		t.Fatalf("nine seconds of listening and two suspensions are not ten seconds: %q", line)
	}
	listen(tr, 1)
	if line := tr.Take(time.Minute); estPart(line) != "0 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent" {
		t.Fatalf("at ten seconds of listening: %q", line)
	}
}

func TestADataSegmentThatBeginsBelowWhatWasSentIsCountedAgain(t *testing.T) {
	tr := newInnerTraffic()
	resent := func() uint64 {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.resent
	}
	run := func(port uint16, steps []struct {
		name string
		seq  uint32
		n    int
		want uint64
	}) {
		t.Helper()
		before := resent()
		for _, st := range steps {
			tr.Out(segOut(port, tcpACK, st.seq, st.n))
			if got := resent() - before; got != st.want {
				t.Fatalf("%s (seq %d, %d bytes): %d counted as sent again, want %d", st.name, st.seq, st.n, got, st.want)
			}
		}
	}
	type step = struct {
		name string
		seq  uint32
		n    int
		want uint64
	}
	const p = 53000
	openConn(tr, p)
	run(p, []step{
		{"a connection's first data", 1000, 100, 0},
		{"the bytes that follow", 1100, 100, 0},
		{"a bare acknowledgement at an old sequence number", 1000, 0, 0},
		{"the same bytes again", 1100, 100, 1},
		{"the first bytes again", 1000, 100, 2},
		{"a segment that begins inside what was sent and runs past it", 1150, 100, 3},
		{"the bytes that follow that", 1250, 50, 3},
		{"one byte below the end", 1299, 1, 4},
		{"the byte at the end", 1300, 1, 4},
	})
	// The sequence numbers wrap: below and above are read around the wrap.
	const w = 53001
	openConn(tr, w)
	run(w, []step{
		{"before the wrap", 0xfffffe00, 0x100, 0},
		{"across the wrap", 0xffffff00, 0x200, 0},
		{"behind the wrap", 0x100, 16, 0},
		{"behind the wrap, again", 0x100, 16, 1},
		{"from before the wrap, again", 0xffffff80, 16, 2},
		{"the bytes that follow", 0x110, 16, 2},
	})
	// A connection taken up in its middle: its first segment seen is not «again».
	run(53002, []step{
		{"the first segment seen of a connection already open", 900000, 100, 0},
		{"the same again", 900000, 100, 1},
	})
	// One connection's sequence numbers say nothing of another's.
	const o = 53003
	openConn(tr, o)
	run(o, []step{{"another connection's first data at a low number", 10, 100, 0}})
	// The line says the period's count and starts the next from nothing.
	if got := estPart(tr.Take(time.Minute)); !strings.HasSuffix(got, ", 7 segment(s) re-sent") {
		t.Fatalf("the period's count: %q", got)
	}
	tr.Out(segOut(o, tcpACK, 110, 100))
	if got := estPart(tr.Take(time.Minute)); !strings.HasSuffix(got, ", 0 segment(s) re-sent") {
		t.Fatalf("a new period carried the last one's count: %q", got)
	}
}

func TestAConnectionAlreadyOpenIsTakenUpAtThePhonesFirstSegment(t *testing.T) {
	tr := newInnerTraffic()
	// A segment FOR the phone on a connection it has not spoken on here: not ours.
	tr.In(segIn(54000, tcpACK, 1, 500))
	if len(tr.est) != 0 {
		t.Fatalf("a segment for the phone alone opened a connection: %d", len(tr.est))
	}
	estSays(t, tr, "a segment for the phone alone", "0 sent data, 0 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// The line came on in a connection's middle: no handshake was seen.
	tr.Out(segOut(54001, tcpACK, 9000, 100))
	listen(tr, 10)
	if line := tr.Take(time.Minute); !strings.Contains(line, "tcp: 0 asked (0 SYN)") || estPart(line) != "1 sent data, 0 heard (0 with data), 1 stalled 10s+, 0 segment(s) re-sent" {
		t.Fatalf("a connection taken up at its first segment: %q", line)
	}
	// The phone's reset of a connection never seen opens nothing.
	tr.Out(segOut(54002, tcpRST, 1, 0))
	if len(tr.est) != 1 {
		t.Fatalf("a reset opened a connection: %d", len(tr.est))
	}
}

func TestTheSamePortsAskedAnewAreANewConnection(t *testing.T) {
	tr := newInnerTraffic()
	const p = 54100
	openConn(tr, p)
	tr.Out(segOut(p, tcpACK, 5000, 100)) // unanswered
	listen(tr, 5)
	tr.Out(syn(p)) // the phone asks the same ports anew
	tr.In(synAck(p))
	tr.Out(segOut(p, tcpACK, 100, 100)) // below the old connection's numbers: not «again»
	tr.In(segIn(p, tcpACK, 1, 0))
	listen(tr, 10)
	// Both connections sent data in this period; the old one's wait is gone with it.
	estSays(t, tr, "what the old connection owed is gone with it", "2 sent data, 1 heard (0 with data), 0 stalled 10s+, 0 segment(s) re-sent")
	// And a connection the far side reset is open again behind a new handshake;
	// what the old one heard in this period — data, then the reset — stays counted.
	tr.In(segIn(p, tcpACK, 1, 30))
	tr.In(segIn(p, tcpRST, 31, 0))
	tr.Out(syn(p))
	tr.In(synAck(p))
	tr.Out(segOut(p, tcpACK, 1, 10))
	listen(tr, 10)
	estSays(t, tr, "a new connection on a reset one's ports", "1 sent data, 1 heard (1 with data), 1 stalled 10s+, 0 segment(s) re-sent")
}

func TestEstablishedConnectionsAreBoundedAndForgotten(t *testing.T) {
	tr := newInnerTraffic()
	for i := 0; i < innerMaxConns+3; i++ {
		tr.Out(segOut(uint16(1000+i), tcpACK, 1, 10))
	}
	if len(tr.est) != innerMaxConns {
		t.Fatalf("established connections: %d, want the bound %d", len(tr.est), innerMaxConns)
	}
	openConn(tr, 60000) // and one accepted past the bound: said at its first segment
	line := tr.Take(time.Minute)
	if !strings.Contains(line, "tcp established: 1024 sent data") || !strings.HasSuffix(line, "; not tracked: 4 (a table is full)") {
		t.Fatalf("past the bound a connection is said as not tracked: %q", line)
	}
	listen(tr, 119)
	tr.Take(time.Minute)
	if len(tr.est) != innerMaxConns {
		t.Fatalf("forgotten too early: %d at 119 s", len(tr.est))
	}
	// One of them speaks at 119 s: its two minutes start again.
	tr.Out(segOut(1000, tcpACK, 11, 10))
	listen(tr, 1)
	tr.Take(time.Minute)
	if len(tr.est) != 1 {
		t.Fatalf("at 120 s of listening since their last packet: %d left, want the one that spoke", len(tr.est))
	}
	listen(tr, 119)
	tr.In(segIn(1000, tcpACK, 1, 0)) // and a packet FOR it counts as its last too
	listen(tr, 1)
	tr.Take(time.Minute)
	if len(tr.est) != 1 {
		t.Fatalf("a packet for the phone must keep its connection: %d left", len(tr.est))
	}
	listen(tr, 120)
	tr.Take(time.Minute)
	if len(tr.est) != 0 {
		t.Fatalf("not forgotten: %d", len(tr.est))
	}
}
