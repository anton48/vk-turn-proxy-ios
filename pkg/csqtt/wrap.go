// SPDX-License-Identifier: MIT

// Package csqtt implements the CSQTT wire protocol (github.com/amurcanov/csqtt,
// revision CSQTT-WIRE-3) so this client can reach a csqtt server over VK TURN.
//
// 🚨 CLEAN ROOM. That repository is PolyForm-Noncommercial, which is not
// GPL-compatible. Nothing in this package is ported from it: every constant,
// format and behaviour comes from our own specification,
// reference_csqtt_protocol_v3.md, written from studying the protocol, and the
// tests pin the contract with the vectors that repository PUBLISHES (a key
// derivation and one bit-exact GETCONF datagram). Facts, not code.
//
// The stack, outermost first: VK TURN (UDP) → this RTP-shaped obfuscation →
// plaintext, which is either a control string (GETCONF/TUNCONF/…, see
// control.go) or a raw IP packet from the TUN, TCP packets carrying a CQF1
// flow frame (frame.go). There is no DTLS and no WireGuard inside.
//
// ⚠️ Security shape, stated once: the whole session is protected by ONE key
// derived from the password — no key exchange, no forward secrecy. That is
// the protocol; it is not ours to fix here, and the UI must say so.
package csqtt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Wire constants. Every one is part of the contract with the server.
const (
	// KeyLen is the HKDF output: all 32 bytes key ChaCha20-Poly1305; the SRTP
	// mode splits them into an AES-128 key [0:16] and an HMAC-SHA1 key [16:32].
	KeyLen = 32

	// hdrLen is the RTP header this side always SENDS: 12 fixed bytes plus a
	// 2-word 0xBEDE extension (abs-send-time + transport-cc). On receive the
	// length is derived from the X bit and the extension length field.
	hdrLen = 24

	// PTAudio selects ChaCha20-Poly1305; PTVideo selects AES-128-CTR +
	// HMAC-SHA1-80. The server mirrors whichever the client used.
	PTAudio byte = 111
	PTVideo byte = 96
	// ptLegacy is accepted on receive only, for parity with the server's filter.
	ptLegacy byte = 6

	paddingMaxAudio = 24
	paddingMaxVideo = 60

	clockAudio      uint32 = 48_000
	clockVideo      uint32 = 90_000
	absSendTimeRate uint32 = 262_144

	aeadTagLen = 16
	srtpTagLen = 10

	hkdfSalt = "CSQTT-WRAP-v1"
	hkdfInfo = "rtp-obfs/chacha20poly1305"
)

// Mode is the obfuscation mode, selected by payload type on the wire.
type Mode int

const (
	ModeAudio Mode = iota // PT 111, ChaCha20-Poly1305 (the reference default)
	ModeVideo             // PT 96, AES-128-CTR + HMAC-SHA1-80
)

// ParseMode accepts the two names the reference client uses.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "audio":
		return ModeAudio, nil
	case "video":
		return ModeVideo, nil
	}
	return 0, fmt.Errorf("csqtt: unsupported obfuscation mode %q", s)
}

func (m Mode) payloadType() byte {
	if m == ModeVideo {
		return PTVideo
	}
	return PTAudio
}

func (m Mode) clock() uint32 {
	if m == ModeVideo {
		return clockVideo
	}
	return clockAudio
}

func (m Mode) paddingMax() int {
	if m == ModeVideo {
		return paddingMaxVideo
	}
	return paddingMaxAudio
}

// DeriveKey derives the 32-byte session key from the connection password:
// HKDF-SHA256 with the salt and info strings that are part of the wire
// contract. The same password also authenticates GETCONF.
func DeriveKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("csqtt: empty password")
	}
	key := make([]byte, KeyLen)
	r := hkdf.New(sha256.New, []byte(password), []byte(hkdfSalt), []byte(hkdfInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("csqtt: derive key: %w", err)
	}
	return key, nil
}

// Cipher holds the key material for both modes. It is safe for concurrent
// use; per-session sequence state lives in Wrapper.
type Cipher struct {
	aead    cipher.AEAD
	block   cipher.Block
	hmacKey []byte
}

// NewCipher builds the AEAD and SRTP primitives from a DeriveKey output.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("csqtt: key must be %d bytes, got %d", KeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("csqtt: chacha key: %w", err)
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, fmt.Errorf("csqtt: aes key: %w", err)
	}
	return &Cipher{aead: aead, block: block, hmacKey: append([]byte(nil), key[16:]...)}, nil
}

// Wrapper is one session's sender state: the RTP counters that make each
// datagram's nonce unique and the header look like a live media stream.
// One Wrapper per TURN allocation; not safe for concurrent Wrap calls.
type Wrapper struct {
	c          *Cipher
	mode       Mode
	pt         byte
	clock      uint32
	paddingMax int

	ssrc         uint32
	count        uint64
	initTS       uint32
	initAbs      uint32
	initSeq      uint16
	transportSeq uint16
	started      time.Time

	now func() time.Time
	rng *mrand.Rand
}

// NewWrapper seeds a session with random SSRC, sequence numbers and
// timestamps, as a real RTP sender would.
func NewWrapper(c *Cipher, mode Mode) (*Wrapper, error) {
	var seed [8 + 4 + 4 + 2 + 2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("csqtt: seed: %w", err)
	}
	now := time.Now()
	wallMs := uint64(now.UnixMilli())
	w := newWrapper(c, mode,
		binary.BigEndian.Uint32(seed[8:12]),  // ssrc
		binary.BigEndian.Uint32(seed[12:16]), // initial timestamp
		uint32((wallMs*uint64(absSendTimeRate)/1000)&0x00ff_ffff),
		binary.BigEndian.Uint16(seed[16:18]), // initial sequence
		binary.BigEndian.Uint16(seed[18:20]), // transport-cc sequence
		now,
		mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed[:8])))),
	)
	w.paddingMax = mode.paddingMax()
	return w, nil
}

// newWrapper is the deterministic constructor the vector tests use.
func newWrapper(c *Cipher, mode Mode, ssrc, initTS, initAbs uint32, initSeq, transportSeq uint16, started time.Time, rng *mrand.Rand) *Wrapper {
	return &Wrapper{
		c:            c,
		mode:         mode,
		pt:           mode.payloadType(),
		clock:        mode.clock(),
		paddingMax:   mode.paddingMax(),
		ssrc:         ssrc,
		initTS:       initTS,
		initAbs:      initAbs,
		initSeq:      initSeq,
		transportSeq: transportSeq,
		started:      started,
		now:          time.Now,
		rng:          rng,
	}
}

// Overhead is the most bytes Wrap adds to a payload in this mode.
func (w *Wrapper) Overhead() int {
	if w.mode == ModeVideo {
		return hdrLen + w.paddingMax + srtpTagLen
	}
	return hdrLen + aeadTagLen + w.paddingMax
}

// Wrap encrypts plain into an RTP-shaped datagram, reusing dst's storage when
// it is large enough. plain must not alias dst.
//
// Audio layout: header(24) ‖ ciphertext ‖ tag(16) ‖ pad ‖ padTotal.
// Video layout: header(24) ‖ ciphertext ‖ pad ‖ padTotal ‖ tag(10).
func (w *Wrapper) Wrap(dst, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("csqtt: empty payload")
	}
	count := w.count
	w.count++
	tseq := w.transportSeq
	w.transportSeq++

	seq := w.initSeq + uint16(count)
	elapsed := w.now().Sub(w.started)
	if elapsed < 0 {
		elapsed = 0
	}
	ts := w.initTS + ticks(elapsed, w.clock)
	abs := (w.initAbs + ticks(elapsed, absSendTimeRate)) & 0x00ff_ffff

	padRand := 0
	if w.paddingMax > 0 {
		padRand = w.rng.Intn(w.paddingMax)
	}
	padTotal := padRand + 1
	tail := padTotal + aeadTagLen
	if w.mode == ModeVideo {
		tail = padTotal + srtpTagLen
	}
	need := hdrLen + len(plain) + tail
	out := dst[:0]
	if cap(out) < need {
		out = make([]byte, 0, need)
	}
	out = out[:need]

	hdr := out[:hdrLen]
	clear(hdr)
	hdr[0] = 0xb0 // V=2, P=1, X=1, CC=0
	hdr[1] = w.pt & 0x7f
	if w.pt == PTVideo && w.rng.Intn(5) == 0 {
		hdr[1] |= 0x80 // a keyframe marker now and then
	}
	binary.BigEndian.PutUint16(hdr[2:4], seq)
	binary.BigEndian.PutUint32(hdr[4:8], ts)
	binary.BigEndian.PutUint32(hdr[8:12], w.ssrc)
	binary.BigEndian.PutUint16(hdr[12:14], 0xbede)
	binary.BigEndian.PutUint16(hdr[14:16], 2)
	hdr[16] = 0x32 // abs-send-time, id 3, 3 bytes
	hdr[17] = byte(abs >> 16)
	hdr[18] = byte(abs >> 8)
	hdr[19] = byte(abs)
	hdr[20] = 0x51 // transport-cc, id 5, 2 bytes
	binary.BigEndian.PutUint16(hdr[21:23], tseq)

	payloadEnd := hdrLen + len(plain)
	if w.mode == ModeVideo {
		iv := srtpIV(w.ssrc, seq, ts)
		cipher.NewCTR(w.c.block, iv[:]).XORKeyStream(out[hdrLen:payloadEnd], plain)
		if padRand > 0 {
			w.fillPadding(out[payloadEnd : payloadEnd+padRand])
		}
		out[payloadEnd+padTotal-1] = byte(padTotal)
		tagStart := payloadEnd + padTotal
		mac := hmac.New(sha1.New, w.c.hmacKey)
		mac.Write(out[:tagStart])
		copy(out[tagStart:tagStart+srtpTagLen], mac.Sum(nil)[:srtpTagLen])
		return out, nil
	}

	nonce := aeadNonce(w.ssrc, seq, ts)
	w.c.aead.Seal(out[hdrLen:hdrLen], nonce[:], plain, hdr)
	padStart := payloadEnd + aeadTagLen
	if padRand > 0 {
		w.fillPadding(out[padStart : padStart+padRand])
	}
	out[padStart+padTotal-1] = byte(padTotal)
	return out, nil
}

func (w *Wrapper) fillPadding(b []byte) {
	for i := range b {
		b[i] = byte(w.rng.Intn(256))
	}
}

// Unwrap authenticates and decrypts a datagram IN PLACE and returns the
// plaintext as a sub-slice of wire, plus the RTP sequence number. mode is the
// session's mode — the server mirrors the client's — and a datagram of the
// other mode is rejected rather than guessed at.
func (c *Cipher) Unwrap(mode Mode, wire []byte) ([]byte, uint16, error) {
	if len(wire) < 13 || wire[0]>>6 != 2 {
		return nil, 0, errors.New("csqtt: not RTP v2")
	}
	pt := wire[1] & 0x7f
	if pt != PTAudio && pt != PTVideo && pt != ptLegacy {
		return nil, 0, fmt.Errorf("csqtt: unsupported payload type %d", pt)
	}
	seq := binary.BigEndian.Uint16(wire[2:4])
	ts := binary.BigEndian.Uint32(wire[4:8])
	ssrc := binary.BigEndian.Uint32(wire[8:12])
	hl := 12
	if wire[0]&0x10 != 0 {
		if len(wire) < 16 {
			return nil, 0, errors.New("csqtt: short extension header")
		}
		hl += 4 + int(binary.BigEndian.Uint16(wire[14:16]))*4
	}
	if len(wire) < hl {
		return nil, 0, errors.New("csqtt: short RTP header")
	}

	if mode == ModeVideo {
		if len(wire) < hl+srtpTagLen {
			return nil, 0, errors.New("csqtt srtp: missing tag")
		}
		tagStart := len(wire) - srtpTagLen
		mac := hmac.New(sha1.New, c.hmacKey)
		mac.Write(wire[:tagStart])
		if !hmac.Equal(mac.Sum(nil)[:srtpTagLen], wire[tagStart:]) {
			return nil, 0, errors.New("csqtt srtp: authentication failed")
		}
		end := tagStart
		if wire[0]&0x20 != 0 {
			pad := int(wire[end-1])
			if pad == 0 || pad > end-hl {
				return nil, 0, fmt.Errorf("csqtt srtp: invalid padding %d", pad)
			}
			end -= pad
		}
		iv := srtpIV(ssrc, seq, ts)
		cipher.NewCTR(c.block, iv[:]).XORKeyStream(wire[hl:end], wire[hl:end])
		return wire[hl:end], seq, nil
	}

	if pt != PTAudio {
		return nil, 0, fmt.Errorf("csqtt audio: expected payload type %d, got %d", PTAudio, pt)
	}
	end := len(wire)
	if wire[0]&0x20 != 0 {
		pad := int(wire[end-1])
		if pad == 0 || pad > end-hl {
			return nil, 0, fmt.Errorf("csqtt: invalid padding %d", pad)
		}
		end -= pad
	}
	if end <= hl+aeadTagLen {
		return nil, 0, errors.New("csqtt: empty ciphertext or missing tag")
	}
	nonce := aeadNonce(ssrc, seq, ts)
	plain, err := c.aead.Open(wire[hl:hl], nonce[:], wire[hl:end], wire[:hl])
	if err != nil {
		return nil, 0, errors.New("csqtt: authentication failed (ChaCha20-Poly1305)")
	}
	return plain, seq, nil
}

// IsRTP is the cheap pre-filter both ends apply before any decryption: a
// datagram that is not RTP v2 with one of the three payload types is dropped
// without being counted against anything.
func IsRTP(wire []byte) bool {
	if len(wire) < 13 || wire[0]>>6 != 2 {
		return false
	}
	pt := wire[1] & 0x7f
	return pt == PTAudio || pt == PTVideo || pt == ptLegacy
}

// ticks converts elapsed media time to RTP clock ticks, wrapping at 2^32.
func ticks(elapsed time.Duration, rate uint32) uint32 {
	secs := uint64(elapsed / time.Second)
	nanos := uint64(elapsed % time.Second)
	r := uint64(rate)
	return uint32(secs*r + nanos*r/1_000_000_000)
}

// aeadNonce is SSRC ‖ seq ‖ 0x0000 ‖ ts — implicit, never on the wire.
func aeadNonce(ssrc uint32, seq uint16, ts uint32) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint32(n[0:4], ssrc)
	binary.BigEndian.PutUint16(n[4:6], seq)
	binary.BigEndian.PutUint32(n[8:12], ts)
	return n
}

// srtpIV is the same fields zero-extended to an AES block.
func srtpIV(ssrc uint32, seq uint16, ts uint32) [16]byte {
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], ssrc)
	binary.BigEndian.PutUint16(iv[4:6], seq)
	binary.BigEndian.PutUint32(iv[8:12], ts)
	return iv
}
