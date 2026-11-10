package csqtt25

import (
	"encoding/binary"
	"time"
)

// Fragmentation. A packet of at most WholeMax bytes travels whole; a larger
// one is cut into fragments that all go through ONE stream:
//
//	0xCF ‖ index ‖ count ‖ 0 ‖ packet id (u16 BE) ‖ total length (u16 BE) ‖ ≤ FragMax bytes
//
// Every fragment but the last carries exactly FragMax bytes.
const (
	FragMagic     byte = 0xcf
	FragHeaderLen      = 8
	FragMax            = 1272
	WholeMax           = 1280
	MaxPacket          = 2048
	maxFrags           = 32

	reassemblyTimeout = 300 * time.Millisecond
	reassemblySlots   = 512
)

// Fragment cuts pkt into fragments; nil when the packet cannot travel.
func Fragment(id uint16, pkt []byte) [][]byte {
	n := len(pkt)
	if n == 0 || n > MaxPacket {
		return nil
	}
	count := (n + FragMax - 1) / FragMax
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		part := pkt[i*FragMax:]
		if len(part) > FragMax {
			part = part[:FragMax]
		}
		f := make([]byte, FragHeaderLen+len(part))
		f[0], f[1], f[2] = FragMagic, byte(i), byte(count)
		binary.BigEndian.PutUint16(f[4:6], id)
		binary.BigEndian.PutUint16(f[6:8], uint16(n))
		copy(f[FragHeaderLen:], part)
		out = append(out, f)
	}
	return out
}

type fragHeader struct {
	index, count int
	id           uint16
	total        int
}

func parseFragHeader(p []byte) (fragHeader, bool) {
	if len(p) < FragHeaderLen || p[0] != FragMagic {
		return fragHeader{}, false
	}
	h := fragHeader{index: int(p[1]), count: int(p[2]), id: binary.BigEndian.Uint16(p[4:6]), total: int(binary.BigEndian.Uint16(p[6:8]))}
	if h.count == 0 || h.count > maxFrags || h.index >= h.count {
		return fragHeader{}, false
	}
	if h.total == 0 || h.total > MaxPacket || h.total <= (h.count-1)*FragMax || h.total > h.count*FragMax {
		return fragHeader{}, false
	}
	return h, true
}

// IsFragment reports whether a plaintext is a fragment.
func IsFragment(p []byte) bool { _, ok := parseFragHeader(p); return ok }

type partial struct {
	total, count, have int
	seen               uint32
	touched            time.Time
	buf                []byte
}

// Reassembler puts fragments back together. Not safe for concurrent use.
type Reassembler struct {
	parts map[uint16]*partial
}

// NewReassembler returns an empty reassembler.
func NewReassembler() *Reassembler { return &Reassembler{parts: map[uint16]*partial{}} }

// Push takes one fragment; it returns the whole packet when this fragment
// completed it. A packet left incomplete for reassemblyTimeout is dropped.
func (r *Reassembler) Push(frag []byte, now time.Time) ([]byte, bool) {
	h, ok := parseFragHeader(frag)
	if !ok {
		return nil, false
	}
	data := frag[FragHeaderLen:]
	off := h.index * FragMax
	want := h.total - off
	if want > FragMax {
		want = FragMax
	}
	if len(data) != want {
		return nil, false
	}
	p := r.parts[h.id]
	if p != nil && (p.total != h.total || p.count != h.count || now.Sub(p.touched) >= reassemblyTimeout) {
		p = nil
	}
	if p == nil {
		if len(r.parts) >= reassemblySlots {
			for id, old := range r.parts {
				if now.Sub(old.touched) >= reassemblyTimeout {
					delete(r.parts, id)
				}
			}
			if len(r.parts) >= reassemblySlots {
				return nil, false
			}
		}
		p = &partial{total: h.total, count: h.count, buf: make([]byte, h.total)}
		r.parts[h.id] = p
	}
	p.touched = now
	if bit := uint32(1) << uint(h.index); p.seen&bit == 0 {
		p.seen |= bit
		p.have++
		copy(p.buf[off:], data)
	}
	if p.have < p.count {
		return nil, false
	}
	delete(r.parts, h.id)
	return p.buf, true
}
