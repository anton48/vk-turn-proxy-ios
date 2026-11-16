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
//	tcp established — of the connections past their handshake: how many the
//	       phone sent DATA on, how many heard anything back (and how many of
//	       those heard data, not a bare acknowledgement), how many are STALLED
//	       (data went out and not one packet has come in for 10 s of listening
//	       since), and how many of the phone's data segments were sent AGAIN;
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
// 🚨 «Answered» is a SYN-ACK and says nothing of what comes behind it: on the
// phone, new connections were answered while a daemon's requests timed out for
// a quarter of an hour. What becomes of a connection past its handshake is the
// «tcp established» part. Its words are named by what is seen on the wire:
// «sent data» — a segment of the phone's with payload; «heard» — any packet
// for the phone, «with data» — one with payload (a far side that acknowledges
// and never answers reads «heard» and not «with data»); «stalled» — payload
// out and no packet in for ten seconds of listening since the FIRST such
// segment, said once a wait — whether a line finds it standing or it ended
// between two lines, answered or given up; «re-sent» — a data segment that begins below
// what the connection had already sent. A bare acknowledgement, a keepalive
// without data and a FIN are no data: a connection whose last word is the
// phone's acknowledgement waits for nothing. A connection either side RESET
// is owed nothing more: the phone's own reset ends its wait — one it gives up
// inside ten seconds is in «sent data», not in «heard», and never «stalled»;
// its repeats are in «re-sent» all the same. Of what port class the stalled
// connections are — 443, 80, anything else — is said beside their count, as
// the silent connections' split says it: counts, never a port.
//
// 🚨 «Silent» is counted in LISTENING, never on the wall clock: a process that
// did not run heard nothing for a reason of its own. The runner steps once a
// second; a step that comes late is a suspension and adds no listening, so a
// connection asked right before a sleep is not «silent» at the thaw.
//
// 🚨 An ask that waited its threshold is silent WHEREVER THE LINES FALL: one
// that is answered — or refused — between two lines is counted silent in the
// line that follows, and its answer late. A line is taken once a minute; an
// answer that took half of one is not an ordinary answer.
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
	// innerTCPStalled: listening since the first data segment nothing has come
	// back behind, after which an established connection is said stalled.
	innerTCPStalled = 10 * time.Second
	// innerForget: listening after which an entry nobody answered, or a flow
	// nobody used, is dropped from the tables.
	innerForget = 2 * time.Minute
	// innerMaxPending / innerMaxFlows bound the tables. Past the bound an ask is
	// still counted as asked, and said as not tracked.
	innerMaxPending = 2048
	innerMaxFlows   = 1024
	innerMaxConns   = 1024
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

// innerConn is a TCP connection past its handshake.
type innerConn struct {
	seen time.Duration // the listening clock at its last packet either way

	// the period under way
	sentData bool // the phone sent a segment with payload
	heard    bool // a packet came in
	gotData  bool // a packet with payload came in

	// data of the phone's that nothing has come back behind
	waiting bool
	since   time.Duration // the listening clock at the first such segment
	said    bool          // this wait is already counted as stalled

	// the furthest byte the phone has sent: what begins below it is sent again
	end    uint32
	hasEnd bool

	// reset: the far side reset it. Nothing more is read of it; it stays until
	// forgotten, so that a segment of the phone's that passes behind the reset
	// — the two directions are seen by two pumps — does not open it anew.
	reset bool
}

// innerHost is a far host as the tables keep it.
type innerHost struct {
	addr [16]byte
	v6   bool
}

// innerSilentSplit says, in counts, whom the connections just found silent
// were asked of. Counts — never a host, never a port.
type innerSilentSplit struct {
	hosts  map[innerHost]struct{}
	v4, v6 uint64
	ports  innerPortClasses
}

// innerPortClasses counts connections by the class of their far port: 443,
// 80, anything else. Counts — never a port. The one place a port is classed:
// the silent connections' split and the stalled connections' both ask it.
type innerPortClasses struct{ https, http, other uint64 }

func (p *innerPortClasses) add(rport uint16) {
	switch rport {
	case 443:
		p.https++
	case 80:
		p.http++
	default:
		p.other++
	}
}

func (p innerPortClasses) total() uint64 { return p.https + p.http + p.other }

// String: the classes as the line says them.
func (p innerPortClasses) String() string {
	return fmt.Sprintf("%d https / %d http / %d other", p.https, p.http, p.other)
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
	s.ports.add(key.rport)
}

// String: the split as the line says it; nothing when no connection was found
// silent.
func (s *innerSilentSplit) String() string {
	if s.v4+s.v6 == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d host(s); %d v4 / %d v6; %s)", len(s.hosts), s.v4, s.v6, s.ports)
}

// innerPacket is what one inner packet's headers say.
type innerPacket struct {
	v6       bool
	proto    uint8
	src, dst [16]byte
	sport    uint16
	dport    uint16
	flags    uint8  // TCP
	seq      uint32 // TCP: the segment's sequence number
	payload  int    // TCP: its payload, in bytes — by the headers' own lengths
	hasSeq   bool   // TCP: the two above were read
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
		// The packet ends where its header says, not where the buffer does.
		end := int(binary.BigEndian.Uint16(p[2:4]))
		if end < ihl || end > len(p) {
			end = len(p)
		}
		p = p[:end]
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
		if end := 40 + int(binary.BigEndian.Uint16(p[4:6])); end <= len(p) {
			p = p[:end]
		}
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
			if hdr := int(l4[12]>>4) * 4; hdr >= 20 && hdr <= len(l4) {
				pk.seq, pk.payload, pk.hasSeq = binary.BigEndian.Uint32(l4[4:8]), len(l4)-hdr, true
			}
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
	est map[innerKey]*innerConn

	// the period under way
	pktOut, pktIn                           uint64
	syn, tcpAsked, tcpAnswered, tcpLate     uint64
	tcpRefused, rstIn                       uint64
	resent, estLate                         uint64
	stalled                                 innerPortClasses // established connections found stalled, by their far port's class
	tcpSilent, dnsSilent                    uint64           // asks whose wait ended, past its threshold, before a line saw it
	split                                   innerSilentSplit // …and whom those connections were asked of
	goneSent, goneHeard, goneData           uint64           // of connections that ended in the period
	dnsSent, dnsAsked, dnsAnswered, dnsLate uint64
	icmpIn, icmpUnreach                     uint64
	other, untracked                        uint64
}

func newInnerTraffic() *InnerTraffic {
	return &InnerTraffic{
		tcp: map[innerKey]*innerPending{},
		dns: map[innerKey]*innerPending{},
		udp: map[innerKey]*innerFlow{},
		est: map[innerKey]*innerConn{},
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
		if pk.flags&tcpSYN == 0 {
			t.estOut(key, pk)
		}
		if pk.flags&tcpSYN == 0 || pk.flags&tcpACK != 0 {
			return
		}
		t.estClose(key) // the same ports asked anew: a new connection
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
			t.estIn(key, pk)
			return
		}
		answered := false
		switch {
		case pk.flags&tcpRST != 0:
			t.tcpRefused++
		case pk.flags&tcpSYN != 0 && pk.flags&tcpACK != 0:
			t.tcpAnswered++
			answered = true
		default:
			return
		}
		if t.foundSilent(ask, innerTCPSilent) {
			t.tcpSilent++
			t.split.add(key)
		}
		if ask.said && answered {
			t.tcpLate++
		}
		delete(t.tcp, key)
	case protoUDP:
		if pk.sport == 53 {
			key.id = pk.dnsID
			if ask := t.dns[key]; ask != nil {
				t.dnsAnswered++
				if t.foundSilent(ask, innerDNSSilent) {
					t.dnsSilent++
				}
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

// foundSilent: whether the ask has waited `after` of listening and nobody has
// called it silent yet — it is called so here. Asked when a line is taken, and
// where an ask's wait ENDS: an ask answered between two lines is judged too.
func (t *InnerTraffic) foundSilent(ask *innerPending, after time.Duration) bool {
	if ask.said || t.listened-ask.asked < after {
		return false
	}
	ask.said = true
	return true
}

// estClose: the connection on these ports is over — the phone reset it, or
// asks a new one on them. What it did in the period under way stays counted.
func (t *InnerTraffic) estClose(key innerKey) {
	c := t.est[key]
	if c == nil {
		return
	}
	t.estWaitOver(key, c, false)
	if c.sentData {
		t.goneSent++
	}
	if c.heard {
		t.goneHeard++
		if c.gotData {
			t.goneData++
		}
	}
	delete(t.est, key)
}

// estWaitOver: the wait on c, if there is one, ends now — by a packet for the
// phone, or because the phone gave the connection up. A wait that lasted its
// ten seconds of listening is a stall whether or not a line saw it standing.
func (t *InnerTraffic) estWaitOver(key innerKey, c *innerConn, answered bool) {
	if !c.waiting {
		return
	}
	c.waiting = false
	stalled := c.said
	if !stalled && t.listened-c.since >= innerTCPStalled {
		stalled = true
		t.stalled.add(key.rport)
	}
	c.said = false
	if stalled && answered {
		t.estLate++
	}
}

// estOut: a segment of the phone's that is no SYN.
func (t *InnerTraffic) estOut(key innerKey, pk innerPacket) {
	if pk.flags&tcpRST != 0 {
		t.estClose(key) // the phone gave it up: nothing is owed on it any more
		return
	}
	c := t.est[key]
	if c == nil {
		// Its first segment behind the handshake — or a connection opened
		// before the line was on, or one the table forgot.
		if len(t.est) >= innerMaxConns {
			t.untracked++
			return
		}
		c = &innerConn{}
		t.est[key] = c
	}
	if c.reset {
		return
	}
	c.seen = t.listened
	if pk.payload == 0 {
		return // an acknowledgement, a keepalive, a bare FIN: no data
	}
	c.sentData = true
	if end := pk.seq + uint32(pk.payload); !c.hasEnd {
		c.end, c.hasEnd = end, true
	} else {
		// Sequence numbers wrap: below and beyond are read as a signed distance.
		if int32(pk.seq-c.end) < 0 {
			t.resent++
		}
		if int32(end-c.end) > 0 {
			c.end = end
		}
	}
	if !c.waiting {
		c.waiting, c.since = true, t.listened
	}
}

// estIn: a segment for the phone on a connection that is not being asked.
func (t *InnerTraffic) estIn(key innerKey, pk innerPacket) {
	c := t.est[key]
	if c == nil || c.reset {
		return
	}
	c.seen = t.listened
	c.heard = true
	if pk.payload > 0 {
		c.gotData = true
	}
	t.estWaitOver(key, c, true)
	if pk.flags&tcpRST != 0 {
		c.reset = true
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
			if t.foundSilent(ask, after) {
				n++
				each(key)
			}
			if t.listened-ask.asked >= innerForget {
				delete(table, key)
			}
		}
		return n
	}
	// What ended its wait between two lines was counted where it ended.
	split := t.split
	t.split = innerSilentSplit{}
	tcpSilent := t.tcpSilent + silent(t.tcp, innerTCPSilent, split.add)
	dnsSilent := t.dnsSilent + silent(t.dns, innerDNSSilent, func(innerKey) {})
	t.tcpSilent, t.dnsSilent = 0, 0

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

	estSent, estHeard, estData := t.goneSent, t.goneHeard, t.goneData
	t.goneSent, t.goneHeard, t.goneData = 0, 0, 0
	for key, c := range t.est {
		if c.sentData {
			estSent++
		}
		if c.heard {
			estHeard++
			if c.gotData {
				estData++
			}
		}
		if c.waiting && !c.said && t.listened-c.since >= innerTCPStalled {
			c.said = true
			t.stalled.add(key.rport)
		}
		c.sentData, c.heard, c.gotData = false, false, false
		if t.listened-c.seen >= innerForget {
			delete(t.est, key)
		}
	}
	stalled := t.stalled
	t.stalled = innerPortClasses{}
	estStalled, stalledOf := stalled.total(), ""
	if estStalled > 0 {
		stalledOf = " (" + stalled.String() + ")"
	}

	span := wall.Round(time.Second).String()
	if wall-awake > 2*time.Second {
		span += fmt.Sprintf(" (awake %s)", awake.Round(time.Second))
	}
	if t.pktOut == 0 && t.pktIn == 0 && tcpSilent+dnsSilent+udpSilent+estStalled == 0 {
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
	fmt.Fprintf(&b, "; tcp established: %d sent data, %d heard (%d with data)%s, %d stalled %s+%s, %d segment(s) re-sent",
		estSent, estHeard, estData, late(t.estLate), estStalled, innerTCPStalled, stalledOf, t.resent)
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
	t.resent, t.estLate = 0, 0
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
