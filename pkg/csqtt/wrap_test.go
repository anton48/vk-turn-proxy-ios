// SPDX-License-Identifier: MIT

package csqtt

import (
	"bytes"
	"encoding/hex"
	mrand "math/rand"
	"testing"
	"time"
)

// Published vectors (reference_csqtt_protocol_v3.md §1, §3). These are the
// interop contract: a client that reproduces them byte for byte is speaking
// the server's language.
const (
	vectorKeyHex = "aa77380e1203f9e02b705efd192b19020c011619af3d70b03e70c13658e373f4"

	fixturePassword  = "wire-password"
	fixturePlaintext = "GETCONF:46000|wire-device|wire-password|7|wire-salt|1|27|CSQTT-WIRE-2"
	fixtureWireHex   = "b06f77881122334410203040bede0002325566775199aa009e2a813c2df794354293ade7b0b8ef4aa6297cf3cc8b0a372342fbd678c10260dc543f8338262292992b12600eaa12d0d3155fa7179b62cd34ac41afb32db0ab7f6dced9e1bb0620daa26d1743f2c25af6bd9ade9901"
)

func mustKey(t *testing.T, password string) []byte {
	t.Helper()
	key, err := DeriveKey(password)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustCipher(t *testing.T, password string) *Cipher {
	t.Helper()
	c, err := NewCipher(mustKey(t, password))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fixtureWrapper pins every source of variation the fixture depends on.
func fixtureWrapper(t *testing.T) *Wrapper {
	t.Helper()
	started := time.Unix(1_700_000_000, 0)
	w := newWrapper(mustCipher(t, fixturePassword), ModeAudio,
		0x1020_3040, 0x1122_3344, 0x0055_6677, 0x7788, 0x99aa, started, mrand.New(mrand.NewSource(1)))
	w.paddingMax = 0
	w.now = func() time.Time { return started } // elapsed 0
	return w
}

func TestDeriveKeyMatchesPublishedVector(t *testing.T) {
	got := hex.EncodeToString(mustKey(t, "test-password"))
	if got != vectorKeyHex {
		t.Fatalf("HKDF vector mismatch:\n got %s\nwant %s", got, vectorKeyHex)
	}
	if _, err := DeriveKey(""); err == nil {
		t.Fatal("empty password must be rejected")
	}
	if bytes.Equal(mustKey(t, "a"), mustKey(t, "b")) {
		t.Fatal("different passwords derived the same key")
	}
}

// The strongest check in the package: our wrap of the fixture plaintext,
// with every counter pinned, must equal the datagram the server's own tests
// accept. A header byte in the wrong place, the wrong AAD, the wrong nonce
// layout — each changes the output.
func TestWrapReproducesGetconfFixtureBitForBit(t *testing.T) {
	w := fixtureWrapper(t)
	wire, err := w.Wrap(nil, []byte(fixturePlaintext))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire); got != fixtureWireHex {
		t.Fatalf("fixture mismatch:\n got %s\nwant %s", got, fixtureWireHex)
	}
}

func TestUnwrapFixtureUnderMatchingPasswordOnly(t *testing.T) {
	wire, _ := hex.DecodeString(fixtureWireHex)

	plain, seq, err := mustCipher(t, fixturePassword).Unwrap(ModeAudio, append([]byte(nil), wire...))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != fixturePlaintext {
		t.Fatalf("plaintext %q", plain)
	}
	if seq != 0x7788 {
		t.Fatalf("seq %#x", seq)
	}

	if _, _, err := mustCipher(t, "wrong-password").Unwrap(ModeAudio, append([]byte(nil), wire...)); err == nil {
		t.Fatal("wrong password accepted")
	}
	// The mode is the session's, not guessed from the wire: the same bytes
	// under the video unwrapper must fail its HMAC, not decrypt.
	if _, _, err := mustCipher(t, fixturePassword).Unwrap(ModeVideo, append([]byte(nil), wire...)); err == nil {
		t.Fatal("audio datagram accepted by the video unwrapper")
	}
}

// Every single-bit change anywhere — header, ciphertext, tag, padding — must
// be refused. The header is covered because it is the AAD; the padding
// because the length byte then points somewhere else.
func TestUnwrapRejectsEverySingleBitMutation(t *testing.T) {
	wire, _ := hex.DecodeString(fixtureWireHex)
	c := mustCipher(t, fixturePassword)
	for i := range wire {
		for bit := 0; bit < 8; bit++ {
			m := append([]byte(nil), wire...)
			m[i] ^= 1 << bit
			if _, _, err := c.Unwrap(ModeAudio, m); err == nil {
				t.Fatalf("accepted mutation at byte %d bit %d", i, bit)
			}
		}
	}
}

func TestRoundTripBothModesWithPadding(t *testing.T) {
	for _, mode := range []Mode{ModeAudio, ModeVideo} {
		c := mustCipher(t, "round-trip")
		w := newWrapper(c, mode, 0xdead_beef, 1, 2, 3, 4, time.Now(), mrand.New(mrand.NewSource(7)))
		for _, size := range []int{1, 2, 15, 16, 17, 63, 64, 65, 500, 1300, 1400} {
			plain := make([]byte, size)
			for i := range plain {
				plain[i] = byte(i*7 + size)
			}
			wire, err := w.Wrap(make([]byte, 0, size+w.Overhead()), plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) > size+w.Overhead() {
				t.Fatalf("mode %v size %d: wire %d exceeds Overhead bound %d", mode, size, len(wire), size+w.Overhead())
			}
			if !IsRTP(wire) {
				t.Fatalf("mode %v: output is not RTP", mode)
			}
			if wire[0] != 0xb0 || wire[1]&0x7f != mode.payloadType() {
				t.Fatalf("mode %v: header %x %x", mode, wire[0], wire[1])
			}
			got, _, err := c.Unwrap(mode, wire)
			if err != nil {
				t.Fatalf("mode %v size %d: %v", mode, size, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("mode %v size %d: plaintext differs", mode, size)
			}
		}
	}
}

// Two packets from one session never share a nonce: the sequence advances
// per packet and the timestamp follows the clock.
func TestConsecutiveWrapsDifferAndAdvanceSequence(t *testing.T) {
	c := mustCipher(t, "seq")
	w := newWrapper(c, ModeAudio, 1, 2, 3, 100, 5, time.Now(), mrand.New(mrand.NewSource(1)))
	w.paddingMax = 0
	a, _ := w.Wrap(nil, []byte("same"))
	b, _ := w.Wrap(nil, []byte("same"))
	if bytes.Equal(a[hdrLen:], b[hdrLen:]) {
		t.Fatal("identical ciphertext for consecutive packets")
	}
	if seqA, seqB := uint16(a[2])<<8|uint16(a[3]), uint16(b[2])<<8|uint16(b[3]); seqB != seqA+1 {
		t.Fatalf("sequence did not advance: %d → %d", seqA, seqB)
	}
	if tA, tB := uint16(a[21])<<8|uint16(a[22]), uint16(b[21])<<8|uint16(b[22]); tB != tA+1 {
		t.Fatalf("transport-cc sequence did not advance: %d → %d", tA, tB)
	}
}

func TestTicksFollowMediaClock(t *testing.T) {
	if got := ticks(20*time.Millisecond, clockAudio); got != 960 {
		t.Fatalf("audio 20 ms = %d ticks", got)
	}
	if got := ticks(20*time.Millisecond, clockVideo); got != 1800 {
		t.Fatalf("video 20 ms = %d ticks", got)
	}
	if got := ticks(time.Second, clockAudio); got != 48_000 {
		t.Fatalf("1 s = %d ticks", got)
	}
}

// A datagram from a server that omits the extension (X=0) still parses:
// the header length comes from the X bit, never from a constant.
func TestUnwrapDerivesHeaderLengthFromXBit(t *testing.T) {
	c := mustCipher(t, "x-bit")
	// Build a 12-byte-header audio datagram by hand.
	hdr := []byte{0x80, PTAudio, 0, 9, 0, 0, 0, 5, 0, 0, 0, 1}
	nonce := aeadNonce(1, 9, 5)
	wire := append([]byte(nil), hdr...)
	wire = c.aead.Seal(wire, nonce[:], []byte("short header"), hdr)
	plain, seq, err := c.Unwrap(ModeAudio, wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "short header" || seq != 9 {
		t.Fatalf("plain %q seq %d", plain, seq)
	}
}

func TestIsRTPAndUnwrapPreFilters(t *testing.T) {
	c := mustCipher(t, "pre")
	for _, bad := range [][]byte{
		nil,
		{0xff, 0, 0, 0},                // the channel keepalive
		bytes.Repeat([]byte{0xb0}, 12), // too short
		{0x40, PTAudio, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // V=1
		{0x80, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},      // unknown PT
	} {
		if IsRTP(bad) {
			t.Fatalf("IsRTP accepted %x", bad)
		}
		if _, _, err := c.Unwrap(ModeAudio, append([]byte(nil), bad...)); err == nil {
			t.Fatalf("Unwrap accepted %x", bad)
		}
	}
}
