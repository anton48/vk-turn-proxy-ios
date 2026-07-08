// SPDX-License-Identifier: MIT

package proxy

// SRTP-WRAP-S obfuscation profile "rtpopus2" — rtpopus + an RFC 8285 one-byte
// RTP header extension (ssrc-audio-level + transport-wide-cc). Adds X=1, a
// marker bit on the first packet of the stream, and a fully-random SSRC, so the
// wire looks like modern WebRTC voice rather than the extension-less rtpopus.
// Wire-compatible with samosvalishe/free-turn-proxy internal/wire/rtpopus2
// (ported from its byte spec, no code copied — MIT). Obfuscation only; DTLS
// already provides confidentiality/integrity of the inner channel.
//
// Wire (HeaderLen=36, Overhead=52):
//
//	[12B RTP hdr(X=1) | 12B RFC8285 one-byte ext | 12B explicit nonce | AEAD ct | 16B tag]
//
//	byte 0    : 0x90                V=2, P=0, X=1, CC=0
//	byte 1    : M<<7 | 0x6F         M=1 on the first packet only; PT=111 (opus)
//	byte 2-3  : seq16 BE            monotonic, init random
//	byte 4-7  : ts32 BE            +960 per packet (20ms @ 48kHz)
//	byte 8-11 : SSRC               fully random per conn (no direction bit)
//	byte 12-13: 0xBE 0xDE          one-byte extension profile
//	byte 14-15: 0x0002             ext data length = 2 words (8 bytes)
//	byte 16   : 0x10               ssrc-audio-level: id=1, len=1
//	byte 17   : 0x80 | (seq & 0x3F) V=1 (voice), level varies
//	byte 18   : 0x21               transport-wide-cc: id=2, len=2
//	byte 19-20: tccSeq16           monotonic transport-cc sequence
//	byte 21-23: 0x00              padding to the 8-byte ext data boundary
//	byte 24-35: nonce = 4B sessionID (MSB=direction) || 8B counter (BE)
//	AAD = bytes[:36].

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	wrap2HeaderLen = 36
	wrap2Overhead  = 52
)

type wrap2Conn struct {
	aead      cipher.AEAD
	sessionID [4]byte // nonce prefix; MSB = direction
	ssrc      [4]byte // fully random (unlike rtpopus)
	counter   atomic.Uint64
	seq       atomic.Uint32 // RTP seq (uint16)
	timestamp atomic.Uint32
	tcc       atomic.Uint32 // transport-cc seq (uint16)
	firstPkt  atomic.Bool
}

func newWrap2Conn(key []byte, isServer bool) (*wrap2Conn, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap2: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap2: aead init: %w", err)
	}
	c := &wrap2Conn{aead: aead}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("wrap2: rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	if isServer {
		c.sessionID[0] |= 0x80
	} else {
		c.sessionID[0] &^= 0x80
	}
	c.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	c.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))
	c.tcc.Store(uint32(binary.BigEndian.Uint16(rnd[14:16])))
	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("wrap2: counter rand: %w", err)
	}
	c.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return c, nil
}

func (c *wrap2Conn) Overhead() int  { return wrap2Overhead }
func (c *wrap2Conn) HeaderLen() int { return wrap2HeaderLen }

func (c *wrap2Conn) WrapInto(dst, payload []byte) (int, error) {
	wireLen := wrap2Overhead + len(payload)
	if len(dst) < wireLen {
		return 0, errors.New("wrap2: dst buffer too small")
	}

	// RTP header (X=1).
	dst[0] = 0x90
	pt := wrapRTPPT
	if c.firstPkt.CompareAndSwap(false, true) {
		pt |= 0x80 // marker on the first packet
	}
	dst[1] = pt
	seq := uint16(c.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	ts := c.timestamp.Add(wrapTSStep) - wrapTSStep
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], c.ssrc[:])

	// RFC 8285 one-byte extension: audio-level + transport-cc.
	dst[12], dst[13] = 0xBE, 0xDE
	binary.BigEndian.PutUint16(dst[14:16], 2)
	dst[16] = 0x10
	dst[17] = 0x80 | byte(seq&0x3F)
	dst[18] = 0x21
	tcc := uint16(c.tcc.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[19:21], tcc)
	dst[21], dst[22], dst[23] = 0, 0, 0

	// Explicit nonce.
	copy(dst[24:28], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(dst[28:36], ctr)

	nonce := dst[24:36]
	aad := dst[:36]
	copy(dst[36:], payload)
	c.aead.Seal(dst[36:36], nonce, dst[36:36+len(payload)], aad)
	return wireLen, nil
}

func (c *wrap2Conn) UnwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < wrap2Overhead {
		return 0, errors.New("wrap2: packet too short")
	}
	nonce := wire[24:36]
	aad := wire[:36]
	ct := wire[36:]
	plain, err := c.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return 0, fmt.Errorf("wrap2: AEAD open: %w", err)
	}
	if len(plain) > len(dst) {
		return 0, errors.New("wrap2: dst buffer too small")
	}
	copy(dst, plain)
	return len(plain), nil
}
