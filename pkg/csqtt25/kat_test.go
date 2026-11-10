package csqtt25

// Known answers of the two key schedules, taken from this implementation on
// 2026-11-10 — the day a live csqtt 2.5.3 server accepted its keys on both
// paths (password-derived and from a DTLS handshake's exporter). There is no
// published vector for either; these pin what that server agreed with. The
// password is the reference fixtures' dummy.
const (
	katWrapClient = "7b0a57a117a2db660aef7832a469960e8427ed634ff57b2c6e4e8ce4c5e30c8f"
	katWrapServer = "21b51439be5537125e987b3ff546bafb930a25ece710069eead83307e189c1b5"
	// The exporter block 00 01 … 3b.
	katExporterClient = "000102030405060708090a0b0c0d0e0f20299aa4aa0590d1ae65479035455fe4"
	katExporterServer = "101112131415161718191a1b1c1d1e1f50041e98bf78d49e914990f3753e2cd3"
)
