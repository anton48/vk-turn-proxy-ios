// SPDX-License-Identifier: MIT

package csqtt

// Uplink striping. N workers are N TURN allocations; one TCP flow is spread
// over all of them and reassembled by CQF1 on the far side. The rule for
// WHICH worker takes a packet is class-aware round robin: small packets —
// the ones latency is made of — never queue behind bulk, and each class
// hands a worker a contiguous run (a chunk) before moving to the next, so a
// flow's segments mostly arrive in order without any per-flow pinning.

import "encoding/binary"

// PacketClass buckets a packet by what it costs to delay.
type PacketClass int

const (
	ClassSmall  PacketClass = iota // DNS, ICMP, TCP control, anything ≤ 164 B
	ClassMedium                    // 165–999 B
	ClassBulk                      // ≥ 1000 B
	numClasses
)

// DefaultChunks are the chunk lengths per class: how many consecutive
// packets one worker takes. The reference client uses 4/16/32; whether 32
// bulk packets back to back on one VK allocation survive its policer is an
// open question this knob exists to measure.
var DefaultChunks = [numClasses]int{4, 16, 32}

const (
	smallMaxLen = 164
	bulkMinLen  = 1000
)

// Classify inspects an IPv4/IPv6 packet. Length decides unless the packet
// is DNS or ICMP, which are Small regardless.
func Classify(pkt []byte) PacketClass {
	if len(pkt) <= smallMaxLen {
		return ClassSmall
	}
	if isControlLike(pkt) {
		return ClassSmall
	}
	if len(pkt) >= bulkMinLen {
		return ClassBulk
	}
	return ClassMedium
}

func isControlLike(pkt []byte) bool {
	var hl int
	var proto byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		hl, proto = int(pkt[0]&0x0f)*4, pkt[9]
	case 6:
		if len(pkt) < 40 {
			return false
		}
		hl, proto = 40, pkt[6]
	default:
		return false
	}
	if hl < 20 || len(pkt) < hl {
		return false
	}
	l4 := pkt[hl:]
	switch proto {
	case 1, 58: // ICMP, ICMPv6
		return true
	case 17: // UDP: port 53 either side
		if len(l4) < 8 {
			return false
		}
		return binary.BigEndian.Uint16(l4[0:2]) == 53 || binary.BigEndian.Uint16(l4[2:4]) == 53
	}
	// No TCP case: a segment without payload is at most 60 + 60 B of
	// headers, always under smallMaxLen, so the length rule above already
	// makes every SYN/FIN/RST/ACK Small. (A TCP branch here was sabotaged
	// away without a fixture able to notice — unreachable by arithmetic.)
	return false
}

// Striper hands out worker indices, one cursor per class.
type Striper struct {
	n      int
	chunk  [numClasses]int
	cursor [numClasses]struct{ worker, remaining int }
}

// NewStriper creates a striper over n workers (indices 0..n-1).
func NewStriper(n int) *Striper {
	s := &Striper{chunk: DefaultChunks}
	s.Resize(n)
	return s
}

// SetChunks overrides the per-class chunk lengths; values below 1 keep the
// default for that class.
func (s *Striper) SetChunks(chunks [numClasses]int) {
	for c, v := range chunks {
		if v >= 1 {
			s.chunk[c] = v
		}
	}
}

// Resize changes the worker count; cursors are clamped.
func (s *Striper) Resize(n int) {
	if n < 1 {
		n = 1
	}
	s.n = n
	for c := range s.cursor {
		if s.cursor[c].worker >= n {
			s.cursor[c].worker = 0
			s.cursor[c].remaining = 0
		}
	}
}

// Pick returns the worker for the next packet of class c, skipping workers
// for which alive returns false. It returns -1 when none is alive. A dead
// worker mid-chunk hands the rest of the chunk to the next live one.
func (s *Striper) Pick(c PacketClass, alive func(int) bool) int {
	cur := &s.cursor[c]
	if cur.remaining == 0 || !alive(cur.worker) {
		start := cur.worker
		for i := 1; i <= s.n; i++ {
			w := (start + i) % s.n
			if alive(w) {
				cur.worker = w
				cur.remaining = s.chunk[c]
				break
			}
			if i == s.n {
				return -1
			}
		}
	}
	cur.remaining--
	return cur.worker
}
