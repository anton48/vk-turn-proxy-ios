package device

// flowKeyOf hashes the inner packet's 5-tuple (src|dst|proto|sport|dport) to a
// stable 64-bit key for vk-turn-proxy's flow-local path set. Patched-in file,
// not part of upstream wireguard-go.
//
//   - TCP/UDP get the full 5-tuple; other protocols get the 3-tuple (host pair
//   - proto), so they are still sticky by host pair.
//   - Direction is NOT normalized: only the uplink (app->server) is made sticky;
//     the downlink is a different flow handled elsewhere.
//   - 0 is reserved for "unknown" (too short / unparseable / keepalive).
//
// FNV-1a/64, fixed for the process lifetime.
func flowKeyOf(pkt []byte) uint64 {
	const (
		fnvOffset uint64 = 1469598103934665603
		fnvPrime  uint64 = 1099511628211
	)
	if len(pkt) < 1 {
		return 0
	}
	h := fnvOffset
	mix := func(b []byte) {
		for _, c := range b {
			h ^= uint64(c)
			h *= fnvPrime
		}
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return 0
		}
		ihl := int(pkt[0]&0x0f) * 4
		proto := pkt[9]
		mix(pkt[12:20]) // src + dst
		mix([]byte{proto})
		if (proto == 6 || proto == 17) && len(pkt) >= ihl+4 {
			mix(pkt[ihl : ihl+4]) // sport + dport
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		proto := pkt[6] // next-header; assumes no extension headers (WG data path)
		mix(pkt[8:40])  // src + dst
		mix([]byte{proto})
		if (proto == 6 || proto == 17) && len(pkt) >= 44 {
			mix(pkt[40:44]) // sport + dport
		}
	default:
		return 0
	}
	if h == 0 {
		h = fnvPrime // never return the reserved "unknown" value for a real flow
	}
	return h
}

// isPureTCPAck reports whether a plaintext IP packet is a TCP segment carrying
// NO payload — i.e. a bare acknowledgement.
//
// 🎯 On the ciphertext side this could only ever be approximated by SIZE, and an
// aggregate counter built that way had to guess a byte range and still admitted
// background ACKs and DNS answers. Here the packet is in the clear, so the test
// is exact: total length minus the IP header minus the TCP data offset is zero.
//
// ⚠️ It therefore MISSES an ACK piggybacked on data, which is correct for the
// case under study (during an upload the return direction carries no data) and
// would under-count on a bidirectional flow. Said here rather than discovered
// later.
func isPureTCPAck(pkt []byte) bool {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		if pkt[9] != 6 { // not TCP
			return false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(pkt[2])<<8 | int(pkt[3])
		if ihl < 20 || total < ihl+20 || total > len(pkt) {
			return false
		}
		if len(pkt) < ihl+13 {
			return false
		}
		doff := int(pkt[ihl+12]>>4) * 4
		return doff >= 20 && ihl+doff == total
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		if pkt[6] != 6 { // next-header, no extension headers on the WG data path
			return false
		}
		payload := int(pkt[4])<<8 | int(pkt[5])
		if payload < 20 || 40+payload > len(pkt) || len(pkt) < 53 {
			return false
		}
		doff := int(pkt[52]>>4) * 4
		return doff >= 20 && doff == payload
	}
	return false
}

// tcpAckNumber returns the cumulative acknowledgement number of a plaintext TCP
// packet, and whether the ACK flag is actually set.
//
// 🚨 THIS IS THE QUANTITY THE RETRANSMISSION TIMER CARES ABOUT, and the reason a
// second counter exists. An RTO is reset by acknowledgements that ADVANCE the
// window. A first attempt counted ACK ARRIVALS instead, and the two diverge
// exactly when there is a hole: the receiver emits duplicate ACKs at full
// cadence — arrivals look perfectly healthy — while this number does not move
// and the sender's timer runs anyway.
//
// Any TCP packet with the ACK flag counts, not only a bare one: an
// acknowledgement piggybacked on data advances the window just as well.
func tcpAckNumber(pkt []byte) (uint32, bool) {
	var off int
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		if pkt[9] != 6 {
			return 0, false
		}
		off = int(pkt[0]&0x0f) * 4
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		if pkt[6] != 6 {
			return 0, false
		}
		off = 40
	default:
		return 0, false
	}
	if off < 20 || len(pkt) < off+20 {
		return 0, false
	}
	if pkt[off+13]&0x10 == 0 { // ACK flag clear: the field is undefined
		return 0, false
	}
	a := pkt[off+8:]
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]), true
}
