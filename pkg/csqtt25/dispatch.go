package csqtt25

import (
	"encoding/binary"
	"time"
)

// The uplink dispatcher. A 2.5 server puts nothing back in order (2.1.9's
// flow frame is gone), so order is the sender's: a flow stays on one stream
// for a burst and moves only at a burst's end; a small-UDP flow (a game, a
// call) is pinned to one stream for as long as it fits in one. Streams are
// chosen by a token bucket each — a balance, not a pacer: nothing waits.
const (
	// The balance's bucket per stream.
	streamRate     = 247000.0 // bytes per second
	streamCapacity = 10500.0
	streamFloor    = -4500.0

	// FlowBurst is how much of a flow goes through one stream before the
	// flow may move.
	FlowBurst = 16 * 1024

	flowTableMax  = 1024
	flowEvictEach = 1024
	flowIdleTTL   = 30 * time.Second

	// A UDP packet up to smallUDPMax pins its flow for smallUDPSticky…
	smallUDPMax    = 300
	smallUDPSticky = time.Second
	// …unless the flow carries more than one stream takes: above
	// pinWindowMax bytes in a pinWindow it is bulk for bulkHold and moves in
	// bursts like any other (the fork's 2.5.1 rule: a pinned bulk flow ran
	// at one stream's rate).
	pinWindow    = 250 * time.Millisecond
	pinWindowMax = int(streamRate) * 3 / 4 / 4
	bulkHold     = 2 * time.Second

	// pathOverheadPerDatagram is what a datagram costs the balance beyond
	// its payload (the wrapper, the channel header, UDP, IP).
	pathOverheadPerDatagram = 66
)

type flowKey struct {
	v6       bool
	src, dst [16]byte
	proto    byte
	sport    uint16
	dport    uint16
}

type flowState struct {
	idx         int
	lastSeen    time.Time
	burstLeft   int
	stickyUntil time.Time
	windowStart time.Time
	windowBytes int
	bulkUntil   time.Time
}

// keepsPin counts the packet and says whether the flow stays pinned.
func (f *flowState) keepsPin(now time.Time, n int, smallUDP bool) bool {
	if now.Sub(f.windowStart) >= pinWindow {
		f.windowStart, f.windowBytes = now, 0
	}
	f.windowBytes += n
	if f.windowBytes > pinWindowMax {
		f.bulkUntil = now.Add(bulkHold)
		f.stickyUntil = time.Time{}
	}
	if smallUDP && !now.Before(f.bulkUntil) {
		f.stickyUntil = now.Add(smallUDPSticky)
	}
	return now.Before(f.stickyUntil)
}

// flowOf reads a packet's flow; ok is false for what is not IP.
func flowOf(pkt []byte) (k flowKey, ok bool) {
	if len(pkt) < 1 {
		return k, false
	}
	ports := func(off int) {
		if (k.proto == 6 || k.proto == 17) && len(pkt) >= off+4 {
			k.sport = binary.BigEndian.Uint16(pkt[off:])
			k.dport = binary.BigEndian.Uint16(pkt[off+2:])
		}
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 || len(pkt) < ihl {
			return k, false
		}
		k.proto = pkt[9]
		copy(k.src[:4], pkt[12:16])
		copy(k.dst[:4], pkt[16:20])
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0 { // only the first IP fragment has ports
			ports(ihl)
		}
		return k, true
	case 6:
		if len(pkt) < 40 {
			return k, false
		}
		k.v6 = true
		k.proto = pkt[6]
		copy(k.src[:], pkt[8:24])
		copy(k.dst[:], pkt[24:40])
		ports(40)
		return k, true
	}
	return k, false
}

// Dispatcher chooses the stream of every uplink packet. Not safe for
// concurrent use: the caller serialises Pick.
type Dispatcher struct {
	tokens  []float64
	updated time.Time
	cursor  int
	flows   map[flowKey]*flowState
	picks   int
}

// NewDispatcher balances n streams.
func NewDispatcher(n int) *Dispatcher {
	d := &Dispatcher{flows: map[flowKey]*flowState{}}
	d.Resize(n)
	return d
}

// Resize sets the stream count. Every flow's stream is forgotten: the
// indices mean other streams now.
func (d *Dispatcher) Resize(n int) {
	if n < 0 {
		n = 0
	}
	if len(d.tokens) == n {
		return
	}
	d.tokens = make([]float64, n)
	for i := range d.tokens {
		d.tokens[i] = streamCapacity
	}
	d.flows = map[flowKey]*flowState{}
	d.cursor, d.picks = 0, 0
	d.updated = time.Time{}
}

func (d *Dispatcher) refill(now time.Time) {
	if d.updated.IsZero() {
		d.updated = now
		return
	}
	el := now.Sub(d.updated).Seconds()
	if el <= 0 {
		return
	}
	d.updated = now
	for i := range d.tokens {
		if d.tokens[i] += el * streamRate; d.tokens[i] > streamCapacity {
			d.tokens[i] = streamCapacity
		}
	}
}

// choose is the usable stream with the most tokens, looking from the
// cursor; -1 when none is usable.
func (d *Dispatcher) choose(usable func(int) bool) int {
	n := len(d.tokens)
	best := -1
	for off := 0; off < n; off++ {
		i := (d.cursor + off) % n
		if !usable(i) {
			continue
		}
		if best < 0 || d.tokens[i] > d.tokens[best] {
			best = i
		}
	}
	if best >= 0 {
		d.cursor = (best + 1) % n
	}
	return best
}

func (d *Dispatcher) charge(i, cost int) {
	if d.tokens[i] -= float64(cost); d.tokens[i] < streamFloor {
		d.tokens[i] = streamFloor
	}
}

func (d *Dispatcher) evict(now time.Time) {
	d.picks++
	if d.picks%flowEvictEach != 0 && len(d.flows) < flowTableMax {
		return
	}
	for k, f := range d.flows {
		if now.Sub(f.lastSeen) >= flowIdleTTL {
			delete(d.flows, k)
		}
	}
	if len(d.flows) >= flowTableMax {
		d.flows = map[flowKey]*flowState{}
	}
}

// Pick returns the stream for pkt, which will travel as `datagrams`
// datagrams (more than one when it is fragmented — all on the one stream).
// usable says which streams can send now. ok is false when none can.
func (d *Dispatcher) Pick(pkt []byte, datagrams int, usable func(int) bool, now time.Time) (idx int, ok bool) {
	if len(d.tokens) == 0 {
		return 0, false
	}
	if datagrams < 1 {
		datagrams = 1
	}
	cost := len(pkt) + datagrams*pathOverheadPerDatagram
	d.refill(now)
	key, isFlow := flowOf(pkt)
	if !isFlow {
		i := d.choose(usable)
		if i < 0 {
			return 0, false
		}
		d.charge(i, cost)
		return i, true
	}
	d.evict(now)
	smallUDP := key.proto == 17 && len(pkt) <= smallUDPMax
	if f := d.flows[key]; f != nil {
		f.lastSeen = now
		sticky := f.keepsPin(now, cost, smallUDP)
		if f.idx < len(d.tokens) && usable(f.idx) && (sticky || f.burstLeft >= cost) {
			f.burstLeft -= cost
			if f.burstLeft < 0 {
				f.burstLeft = 0
			}
			d.charge(f.idx, cost)
			return f.idx, true
		}
		i := d.choose(usable)
		if i < 0 {
			return 0, false
		}
		f.idx, f.burstLeft = i, FlowBurst-cost
		if f.burstLeft < 0 {
			f.burstLeft = 0
		}
		d.charge(i, cost)
		return i, true
	}
	i := d.choose(usable)
	if i < 0 {
		return 0, false
	}
	f := &flowState{idx: i, lastSeen: now, burstLeft: FlowBurst - cost, windowStart: now, windowBytes: cost}
	if f.burstLeft < 0 {
		f.burstLeft = 0
	}
	if smallUDP {
		f.stickyUntil = now.Add(smallUDPSticky)
	}
	d.flows[key] = f
	d.charge(i, cost)
	return i, true
}
