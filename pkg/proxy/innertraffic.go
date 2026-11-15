package proxy

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// WHAT THE PHONE'S OWN TRAFFIC MEETS INSIDE THE TUNNEL — once a minute, one line.
//
// Why it exists (2026-11-15): on a csqtt 2.5 tunnel over a cellular path the
// requests of iOS's own daemons were found timing out for hours while every
// stream of the tunnel read ready and heard. A transport's liveness asks the
// transport's server; it says nothing of what lies behind it. The first answer
// to that — sockets the extension opens through its own tunnel — cannot work:
// with includeAllNetworks iOS does not let a provider's connection through the
// provider's interface. So nothing is ASKED here. Every inner packet already
// passes through this process on its way into the tunnel and out of it, and
// this counts what the phone itself asked and what came back:
//
//	tcp  — connections asked (a first SYN), answered (a SYN-ACK), refused (an
//	       RST to the SYN), silent (asked, and nothing for 10 s of listening) —
//	       and of the silent ones: how many different hosts they were asked
//	       of, how many over IPv4 and IPv6, how many on the https port, the
//	       http port and any other;
//	dns  — questions asked over UDP 53, answered, silent (5 s);
//	udp  — every other UDP flow that sent, how many heard anything back in the
//	       period, how many were NEVER answered (10 s of listening since the
//	       flow's first packet and not one packet back); the flows to port 443
//	       (QUIC) apart;
//	icmp — what came in, the «unreachable» ones apart.
//
// 🚨 It reads headers only — the addresses and ports to tell one flow from
// another, never a payload beyond a DNS message's two-byte id — and it SAYS
// counts only: no address, no port, no name reaches the log. Whom the silent
// connections were asked of is said as counts too: one dead destination and a
// deaf path read alike in «N silent» and apart in «1 host(s)» / «40 host(s)».
//
// 🚨 A flow whose LAST packet was the phone's is an ordinary flow: nearly every
// QUIC connection ends with an acknowledgement or a close nobody answers. So
// a UDP flow is given up on only if nothing EVER came back on it — a flow
// that heard once is never «never answered», whatever it sends later (the
// first cut counted «sent and nothing heard since» and called seven of ten
// flows of a healthy run silent).
//
// 🚨 «Silent» is counted in LISTENING, never on the wall clock: a process that
// did not run heard nothing for a reason of its own. The runner steps once a
// second; a step that comes late is a suspension and adds no listening, so a
// connection asked right before a sleep is not «silent» at the thaw.
//
// 🚨 Three outcomes, never two: answered / asked and not answered / not yet
// known. A connection younger than its threshold is in none of the line's
// numbers but «asked»; it is judged by a later line.
//
// Off by default (Settings › Advanced). Off, a packet costs one atomic load.

const (
	// innerEvery: a line this often, in wall time.
	innerEvery = 60 * time.Second
	// innerStep: the runner's step — the grain of listening.
	innerStep = time.Second
	// innerTCPSilent / innerDNSSilent: listening after which an unanswered ask
	// is said to be silent. innerUDPSilent: listening since a flow's first
	// packet after which a flow nothing came back on is said never answered.
	innerTCPSilent = 10 * time.Second
	innerUDPSilent = 10 * time.Second
	innerDNSSilent = 5 * time.Second
	// innerForget: listening after which an entry nobody answered, or a flow
	// nobody used, is dropped from the tables.
	innerForget = 2 * time.Minute
	// innerMaxPending / innerMaxFlows bound the tables. Past the bound an ask is
	// still counted as asked, and said as not tracked.
	innerMaxPending = 2048
	innerMaxFlows   = 1024
)

// innerKey tells one flow from another: the phone's port, the far address and
// port, and for a DNS question its id.
type innerKey struct {
	remote [16]byte
	local  uint16
	rport  uint16
	id     uint16
	v6     bool
}

// innerPending is an ask nobody has answered yet.
type innerPending struct {
	asked time.Duration // the listening clock when it was asked
	said  bool          // already counted as silent
}

// innerFlow is a UDP flow that is neither a DNS question nor its answer.
type innerFlow struct {
	out, in uint32        // packets in the period under way
	seen    time.Duration // the listening clock at its last packet either way
	first   time.Duration // the listening clock at its first packet
	heard   bool          // a packet came back on it, at any time in its life
	said    bool          // already counted as never answered
}

// innerHost is a far host as the tables keep it.
type innerHost struct {
	addr [16]byte
	v6   bool
}

// innerSilentSplit says, in counts, whom the connections just found silent
// were asked of. Counts — never a host, never a port.
type innerSilentSplit struct {
	hosts              map[innerHost]struct{}
	v4, v6             uint64
	https, http, other uint64
}

func (s *innerSilentSplit) add(key innerKey) {
	if s.hosts == nil {
		s.hosts = map[innerHost]struct{}{}
	}
	s.hosts[innerHost{addr: key.remote, v6: key.v6}] = struct{}{}
	if key.v6 {
		s.v6++
	} else {
		s.v4++
	}
	switch key.rport {
	case 443:
		s.https++
	case 80:
		s.http++
	default:
		s.other++
	}
}

// String: the split as the line says it; nothing when no connection was found
// silent.
func (s *innerSilentSplit) String() string {
	if s.v4+s.v6 == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d host(s); %d v4 / %d v6; %d https / %d http / %d other)",
		len(s.hosts), s.v4, s.v6, s.https, s.http, s.other)
}

// innerPacket is what one inner packet's headers say.
type innerPacket struct {
	v6       bool
	proto    uint8
	src, dst [16]byte
	sport    uint16
	dport    uint16
	flags    uint8 // TCP
	dnsID    uint16
	hasID    bool
	icmpType uint8
	l4       bool // the transport header is in this packet (not a later fragment)
}

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// parseInner reads an IP packet's headers. False for what is not an IP packet.
func parseInner(p []byte) (pk innerPacket, ok bool) {
	if len(p) < 1 {
		return pk, false
	}
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return pk, false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return pk, false
		}
		pk.proto = p[9]
		copy(pk.src[:4], p[12:16])
		copy(pk.dst[:4], p[16:20])
		if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return pk, true // a later fragment: no transport header here
		}
		l4 = p[ihl:]
	case 6:
		if len(p) < 40 {
			return pk, false
		}
		pk.v6 = true
		copy(pk.src[:], p[8:24])
		copy(pk.dst[:], p[24:40])
		next, off := p[6], 40
	walk:
		for hop := 0; hop < 8; hop++ {
			switch next {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(p) < off+2 {
					pk.proto = next
					return pk, true
				}
				next, off = p[off], off+(int(p[off+1])+1)*8
			case 44: // fragment
				if len(p) < off+8 {
					pk.proto = next
					return pk, true
				}
				later := binary.BigEndian.Uint16(p[off+2:off+4])>>3 != 0
				next, off = p[off], off+8
				if later {
					pk.proto = next
					return pk, true
				}
			default:
				break walk
			}
		}
		pk.proto = next
		if len(p) < off {
			return pk, true
		}
		l4 = p[off:]
	default:
		return pk, false
	}
	switch pk.proto {
	case protoTCP:
		if len(l4) >= 14 {
			pk.sport, pk.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			pk.flags = l4[13]
			pk.l4 = true
		}
	case protoUDP:
		if len(l4) >= 8 {
			pk.sport, pk.dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			pk.l4 = true
			if len(l4) >= 10 {
				pk.dnsID, pk.hasID = binary.BigEndian.Uint16(l4[8:10]), true
			}
		}
	case protoICMP, protoICMPv6:
		if len(l4) >= 1 {
			pk.icmpType = l4[0]
			pk.l4 = true
		}
	}
	return pk, true
}

// InnerTraffic counts one tunnel's inner packets. Safe for the two pumps and
// the runner at once: one lock, held to the end of every call.
type InnerTraffic struct {
	mu sync.Mutex

	listened time.Duration // the listening clock: the runner's on-time steps
	lastTake time.Duration // its reading at the last line
	quiet    bool          // the «no packet» line has been said

	tcp map[innerKey]*innerPending
	dns map[innerKey]*innerPending
	udp map[innerKey]*innerFlow

	// the period under way
	pktOut, pktIn                           uint64
	syn, tcpAsked, tcpAnswered, tcpLate     uint64
	tcpRefused, rstIn                       uint64
	dnsSent, dnsAsked, dnsAnswered, dnsLate uint64
	icmpIn, icmpUnreach                     uint64
	other, untracked                        uint64
}

func newInnerTraffic() *InnerTraffic {
	return &InnerTraffic{
		tcp: map[innerKey]*innerPending{},
		dns: map[innerKey]*innerPending{},
		udp: map[innerKey]*innerFlow{},
	}
}

// Out: a packet the phone sent, on its way into the tunnel.
func (t *InnerTraffic) Out(p []byte) {
	pk, ok := parseInner(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pktOut++
	if !ok || !pk.l4 {
		t.other++
		return
	}
	key := innerKey{remote: pk.dst, local: pk.sport, rport: pk.dport, v6: pk.v6}
	switch pk.proto {
	case protoTCP:
		if pk.flags&tcpSYN == 0 || pk.flags&tcpACK != 0 {
			return
		}
		t.syn++
		if _, again := t.tcp[key]; again {
			return // the same connection asking again
		}
		t.tcpAsked++
		if len(t.tcp) >= innerMaxPending {
			t.untracked++
			return
		}
		t.tcp[key] = &innerPending{asked: t.listened}
	case protoUDP:
		if pk.dport == 53 {
			t.dnsSent++
			key.id = pk.dnsID
			if _, again := t.dns[key]; again {
				return
			}
			t.dnsAsked++
			if len(t.dns) >= innerMaxPending {
				t.untracked++
				return
			}
			t.dns[key] = &innerPending{asked: t.listened}
			return
		}
		f := t.udp[key]
		if f == nil {
			if len(t.udp) >= innerMaxFlows {
				t.untracked++
				return
			}
			f = &innerFlow{first: t.listened}
			t.udp[key] = f
		}
		f.out++
		f.seen = t.listened
	case protoICMP, protoICMPv6:
	default:
		t.other++
	}
}

// In: a packet for the phone, on its way out of the tunnel.
func (t *InnerTraffic) In(p []byte) {
	pk, ok := parseInner(p)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pktIn++
	if !ok || !pk.l4 {
		t.other++
		return
	}
	key := innerKey{remote: pk.src, local: pk.dport, rport: pk.sport, v6: pk.v6}
	switch pk.proto {
	case protoTCP:
		if pk.flags&tcpRST != 0 {
			t.rstIn++
		}
		ask := t.tcp[key]
		if ask == nil {
			return
		}
		switch {
		case pk.flags&tcpRST != 0:
			t.tcpRefused++
		case pk.flags&tcpSYN != 0 && pk.flags&tcpACK != 0:
			t.tcpAnswered++
			if ask.said {
				t.tcpLate++
			}
		default:
			return
		}
		delete(t.tcp, key)
	case protoUDP:
		if pk.sport == 53 {
			key.id = pk.dnsID
			if ask := t.dns[key]; ask != nil {
				t.dnsAnswered++
				if ask.said {
					t.dnsLate++
				}
				delete(t.dns, key)
			}
			return
		}
		if f := t.udp[key]; f != nil {
			f.in++
			f.seen = t.listened
			f.heard = true
		}
	case protoICMP:
		t.icmpIn++
		if pk.icmpType == 3 {
			t.icmpUnreach++
		}
	case protoICMPv6:
		t.icmpIn++
		if pk.icmpType == 1 {
			t.icmpUnreach++
		}
	default:
		t.other++
	}
}

// Step: the runner's word that `gap` has passed since its last step. A gap
// within twice the step is listening; a longer one is a suspension and counts
// for nothing.
func (t *InnerTraffic) Step(gap, step time.Duration) {
	if gap <= 0 || gap > 2*step {
		return
	}
	t.mu.Lock()
	t.listened += gap
	t.mu.Unlock()
}

// Take: the line of the period that ends now, `wall` long, and a fresh period.
// "" when there is nothing to say: no packet either way for a second period
// running.
func (t *InnerTraffic) Take(wall time.Duration) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	awake := t.listened - t.lastTake
	t.lastTake = t.listened

	silent := func(table map[innerKey]*innerPending, after time.Duration, each func(innerKey)) (n uint64) {
		for key, ask := range table {
			age := t.listened - ask.asked
			if !ask.said && age >= after {
				ask.said = true
				n++
				each(key)
			}
			if age >= innerForget {
				delete(table, key)
			}
		}
		return n
	}
	var split innerSilentSplit
	tcpSilent := silent(t.tcp, innerTCPSilent, split.add)
	dnsSilent := silent(t.dns, innerDNSSilent, func(innerKey) {})

	var sent, heard, udpSilent, quicSent, quicHeard, quicSilent uint64
	for key, f := range t.udp {
		quic := key.rport == 443
		if f.out > 0 {
			sent++
			if quic {
				quicSent++
			}
			if f.in > 0 {
				heard++
				if quic {
					quicHeard++
				}
			}
		}
		if !f.heard && !f.said && t.listened-f.first >= innerUDPSilent {
			f.said = true
			udpSilent++
			if quic {
				quicSilent++
			}
		}
		f.out, f.in = 0, 0
		if t.listened-f.seen >= innerForget {
			delete(t.udp, key)
		}
	}

	span := wall.Round(time.Second).String()
	if wall-awake > 2*time.Second {
		span += fmt.Sprintf(" (awake %s)", awake.Round(time.Second))
	}
	if t.pktOut == 0 && t.pktIn == 0 && tcpSilent+dnsSilent+udpSilent == 0 {
		if t.quiet {
			return ""
		}
		t.quiet = true
		return "inner, the last " + span + ": no packet either way"
	}
	t.quiet = false

	late := func(n uint64) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf(" (%d late)", n)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "inner, the last %s: %d pkt out / %d in", span, t.pktOut, t.pktIn)
	fmt.Fprintf(&b, "; tcp: %d asked (%d SYN), %d answered%s, %d refused, %d silent %s+%s, %d RST in",
		t.tcpAsked, t.syn, t.tcpAnswered, late(t.tcpLate), t.tcpRefused, tcpSilent, innerTCPSilent, split.String(), t.rstIn)
	fmt.Fprintf(&b, "; dns: %d asked (%d sent), %d answered%s, %d silent %s+",
		t.dnsAsked, t.dnsSent, t.dnsAnswered, late(t.dnsLate), dnsSilent, innerDNSSilent)
	fmt.Fprintf(&b, "; udp: %d flows sent, %d heard, %d never answered %s+ (quic %d / %d / %d)",
		sent, heard, udpSilent, innerUDPSilent, quicSent, quicHeard, quicSilent)
	fmt.Fprintf(&b, "; icmp in: %d", t.icmpIn)
	if t.icmpUnreach > 0 {
		fmt.Fprintf(&b, " (%d unreachable)", t.icmpUnreach)
	}
	if t.other > 0 {
		fmt.Fprintf(&b, "; other: %d", t.other)
	}
	if t.untracked > 0 {
		fmt.Fprintf(&b, "; not tracked: %d (a table is full)", t.untracked)
	}

	t.pktOut, t.pktIn = 0, 0
	t.syn, t.tcpAsked, t.tcpAnswered, t.tcpLate, t.tcpRefused, t.rstIn = 0, 0, 0, 0, 0, 0
	t.dnsSent, t.dnsAsked, t.dnsAnswered, t.dnsLate = 0, 0, 0, 0
	t.icmpIn, t.icmpUnreach, t.other, t.untracked = 0, 0, 0, 0
	return b.String()
}

// runInnerTraffic steps `t` and says its line until `stop` is closed, then
// closes `done`. Everything it needs is handed to it: it reads no package
// variable a test could change under it.
func runInnerTraffic(t *InnerTraffic, step, every time.Duration, stop <-chan struct{}, done chan<- struct{}, say func(string)) {
	defer close(done)
	tick := time.NewTicker(step)
	defer tick.Stop()
	prev := time.Now()
	lastLine := prev
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		now := time.Now()
		t.Step(now.Sub(prev), step)
		prev = now
		if wall := now.Sub(lastLine); wall >= every {
			lastLine = now
			if line := t.Take(wall); line != "" {
				say(line)
			}
		}
	}
}

// The process's one counter and its switch. There is one tunnel per extension
// process; a tunnel that starts while the switch is on goes on counting into
// the same tables, which forget what nobody answered.
var (
	// innerNow is the counter while the line is on, nil while it is off: the
	// one load a packet costs.
	innerNow atomic.Pointer[InnerTraffic]
	innerRun struct {
		mu   sync.Mutex
		stop chan struct{}
		done chan struct{}
	}
)

// SetInnerTrafficLog turns the once-a-minute line on or off in this process.
// Turning it off waits for the runner to end.
func SetInnerTrafficLog(on bool) {
	innerRun.mu.Lock()
	defer innerRun.mu.Unlock()
	if on == (innerRun.stop != nil) {
		return
	}
	if !on {
		close(innerRun.stop)
		<-innerRun.done
		innerRun.stop, innerRun.done = nil, nil
		innerNow.Store(nil)
		log.Printf("proxy: inner traffic line OFF")
		return
	}
	t := newInnerTraffic()
	stop, done := make(chan struct{}), make(chan struct{})
	innerRun.stop, innerRun.done = stop, done
	innerNow.Store(t)
	go runInnerTraffic(t, innerStep, innerEvery, stop, done, func(line string) { log.Printf("proxy: %s", line) })
	log.Printf("proxy: inner traffic line ON — once a minute, what the phone's own traffic meets in the tunnel (counts only)")
}

// InnerTrafficCounts: the packets counted either way in the period under way,
// and whether the line is on. For the bridge's own checks of its wiring.
func InnerTrafficCounts() (out, in uint64, on bool) {
	t := innerNow.Load()
	if t == nil {
		return 0, 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pktOut, t.pktIn, true
}

// ObserveInnerOut: a packet read from the TUN, about to enter the tunnel.
func ObserveInnerOut(p []byte) {
	if t := innerNow.Load(); t != nil {
		t.Out(p)
	}
}

// ObserveInnerIn: a packet out of the tunnel, about to be written to the TUN.
func ObserveInnerIn(p []byte) {
	if t := innerNow.Load(); t != nil {
		t.In(p)
	}
}

// innerTUN lets the counter see wireguard-go's packets where they pass the TUN.
type innerTUN struct {
	tun.Device
}

// WrapTUNForInner shows every packet the device reads and writes to the inner
// traffic counter. Transparent: the packets and the calls' results are the
// device's own.
func WrapTUNForInner(d tun.Device) tun.Device { return &innerTUN{Device: d} }

func (t *innerTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	if innerNow.Load() != nil {
		for i := 0; i < n && i < len(sizes) && i < len(bufs); i++ {
			if end := offset + sizes[i]; offset <= end && end <= len(bufs[i]) {
				ObserveInnerOut(bufs[i][offset:end])
			}
		}
	}
	return n, err
}

func (t *innerTUN) Write(bufs [][]byte, offset int) (int, error) {
	if innerNow.Load() != nil {
		for _, b := range bufs {
			if offset <= len(b) {
				ObserveInnerIn(b[offset:])
			}
		}
	}
	return t.Device.Write(bufs, offset)
}

// File is delegated explicitly, as statsTUN's is: a wireguard-go that widens
// tun.Device fails to build here instead of silently losing the wrapper.
func (t *innerTUN) File() *os.File { return t.Device.File() }
