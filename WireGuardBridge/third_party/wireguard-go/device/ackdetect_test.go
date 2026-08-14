package device

import "testing"

// mkAck builds an IPv4 TCP packet with the given payload length.
func mkAck(payload int, doffWords byte) []byte {
	ihl := 20
	tcp := int(doffWords) * 4
	total := ihl + tcp + payload
	p := make([]byte, total)
	p[0] = 0x45
	p[2] = byte(total >> 8)
	p[3] = byte(total)
	p[9] = 6 // TCP
	p[ihl+12] = doffWords << 4
	return p
}

func TestIsPureTCPAck(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"bare ACK, no options", mkAck(0, 5), true},
		{"bare ACK with timestamps (doff 8)", mkAck(0, 8), true},
		{"ACK carrying 1 byte", mkAck(1, 5), false},
		{"full data segment", mkAck(1368, 5), false},
		{"too short", []byte{0x45, 0, 0, 4}, false},
		{"not TCP (UDP)", func() []byte { p := mkAck(0, 5); p[9] = 17; return p }(), false},
		{"bogus data offset", func() []byte { p := mkAck(0, 5); p[20+12] = 0x30; return p }(), false},
	}
	for _, c := range cases {
		if got := isPureTCPAck(c.pkt); got != c.want {
			t.Errorf("%s: isPureTCPAck = %v, want %v", c.name, got, c.want)
		}
	}
}
