package device

import "testing"

// mkV4 builds a minimal IPv4 TCP/UDP packet header for flowKeyOf.
func mkV4(src, dst [4]byte, proto byte, sport, dport uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, IHL 5
	p[9] = proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	return p
}

func TestFlowKeyOfStableDistinctDirectional(t *testing.T) {
	a := mkV4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 1111, 5201)

	if flowKeyOf(a) == 0 {
		t.Fatal("real flow hashed to the reserved 0")
	}
	if flowKeyOf(a) != flowKeyOf(append([]byte(nil), a...)) {
		t.Fatal("not stable for identical packets")
	}
	// distinct on sport / dst
	if flowKeyOf(a) == flowKeyOf(mkV4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 2222, 5201)) {
		t.Fatal("sport change not distinguished")
	}
	if flowKeyOf(a) == flowKeyOf(mkV4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 3}, 6, 1111, 5201)) {
		t.Fatal("dst change not distinguished")
	}
	// direction is NOT normalized: swapped src/dst+ports is a different flow
	if flowKeyOf(a) == flowKeyOf(mkV4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 6, 5201, 1111)) {
		t.Fatal("direction should NOT be normalized (uplink only)")
	}
	// too short / non-IP → reserved 0
	if flowKeyOf([]byte{0x45, 0, 0}) != 0 {
		t.Fatal("short IPv4 packet should hash to 0")
	}
	if flowKeyOf(nil) != 0 {
		t.Fatal("nil should hash to 0")
	}
}
