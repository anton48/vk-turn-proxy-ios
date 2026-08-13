package device

// flowKeyOf hashes the inner packet's 5-tuple (src|dst|proto|sport|dport) to a
// stable 64-bit key for vk-turn-proxy's flow-local path set. Patched-in file,
// not part of upstream wireguard-go.
//
//   - TCP/UDP get the full 5-tuple; other protocols get the 3-tuple (host pair
//     + proto), so they are still sticky by host pair.
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
