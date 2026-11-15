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
	if line := tr.Take(60 * time.Second); !strings.Contains(line, "tcp: 0 asked (0 SYN), 0 answered, 0 refused, 2 silent 10s+, 0 RST in") {
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
	for _, want := range []string{"0 silent 10s+, 0 RST in", "0 silent 5s+", "udp: 1 flows sent, 0 heard, 0 silent 10s+"} {
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
	if line := tr.Take(time.Minute); !strings.Contains(line, "tcp: 0 asked (0 SYN), 0 answered, 0 refused, 1 silent 10s+") || !strings.Contains(line, "udp: 0 flows sent, 0 heard, 1 silent 10s+ (quic 0 / 0 / 1)") {
		t.Fatalf("at 10 s of listening the connection and the flow are silent: %q", line)
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
	if !strings.Contains(line, "udp: 0 flows sent, 0 heard, 0 silent 10s+ (quic 0 / 0 / 0)") {
		t.Fatalf("a DNS question is not one of the other UDP flows: %q", line)
	}
}

func TestOtherUDPFlowsSentHeardAndSilent(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(quicOut(41000))
	tr.Out(quicOut(41000))
	tr.Out(quicOut(41001))
	tr.Out(ip4(protoUDP, innerPhone4, innerFar4, udpSeg(42000, 3478, make([]byte, 20))))
	tr.In(quicIn(41000))
	tr.In(quicIn(49999)) // for a flow that never sent: not a flow of ours
	listen(tr, 10)
	line := tr.Take(time.Minute)
	if want := "udp: 3 flows sent, 1 heard, 2 silent 10s+ (quic 2 / 1 / 1)"; !strings.Contains(line, want) {
		t.Fatalf("\n got %q\nwant it to hold %q", line, want)
	}
	// Heard at last: no longer owed; sending again starts a new wait.
	tr.In(quicIn(41001))
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 0 flows sent, 0 heard, 0 silent 10s+") {
		t.Fatalf("an answer alone is no flow that sent: %q", line)
	}
	tr.Out(quicOut(41001))
	listen(tr, 9)
	if line := tr.Take(time.Minute); !strings.Contains(line, "udp: 1 flows sent, 0 heard, 0 silent 10s+") {
		t.Fatalf("an answer ends the wait, a new packet begins another: %q", line)
	}
	listen(tr, 1)
	if line := tr.Take(time.Minute); !strings.Contains(line, "0 flows sent, 0 heard, 1 silent 10s+ (quic 0 / 0 / 1)") {
		t.Fatalf("the new wait runs out by itself: %q", line)
	}
}

func TestTheLineByteForByte(t *testing.T) {
	tr := newInnerTraffic()
	tr.Out(syn(50000))
	tr.In(synAck(50000))
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
	want := "inner, the last 1m0s: 5 pkt out / 6 in; tcp: 1 asked (1 SYN), 1 answered, 0 refused, 0 silent 10s+, 0 RST in; " +
		"dns: 1 asked (1 sent), 1 answered, 0 silent 5s+; udp: 1 flows sent, 1 heard, 0 silent 10s+ (quic 1 / 1 / 0); " +
		"icmp in: 3 (2 unreachable); other: 2"
	if got != want {
		t.Fatalf("the line\n got %q\nwant %q", got, want)
	}
	// 🚨 Counts only: no address and no port of a packet may reach the line.
	for _, leak := range []string{"203.0.113", "10.0.0.2", "2001:", "50000", "40000", "41000"} {
		if strings.Contains(got, leak) {
			t.Fatalf("the line carries %q — it must say counts only: %q", leak, got)
		}
	}
	// A period is its own: the next line starts from nothing.
	tr.Out(syn(50009))
	listen(tr, 2)
	if got := tr.Take(2 * time.Second); !strings.HasPrefix(got, "inner, the last 2s: 1 pkt out / 0 in; tcp: 1 asked (1 SYN), 0 answered, 0 refused, 0 silent 10s+, 0 RST in; dns: 0 asked") || strings.Contains(got, "icmp in: 3") || strings.Contains(got, "other:") {
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
