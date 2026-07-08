// SPDX-License-Identifier: MIT

package proxy

// SRTP-WRAP-S obfuscation profile "rtpopus3" — rtpopus2 + an abs-send-time
// extension element and a full voice-mimicry model: a VAD silence/speech state
// machine (RTP marker on each silence->speech transition), a variable timestamp
// step (10/20/40 ms), and periodic sequence-number gaps that imitate packet
// loss. Closest of the three profiles to real WebRTC voice on the wire.
// Wire-compatible with samosvalishe/free-turn-proxy internal/wire/rtpopus3
// (ported from its byte spec, no code copied — MIT).
//
// Wire (HeaderLen=40, Overhead=56):
//
//	[12B RTP hdr(X=1) | 16B one-byte ext | 12B explicit nonce | AEAD ct | 16B tag]
//
//	byte 0    : 0x90               V=2, P=0, X=1, CC=0
//	byte 1    : M<<7 | 0x6F        M=1 on silence->speech; PT=111 (opus)
//	byte 2-3  : seq16 BE           monotonic with periodic gaps (loss mimicry)
//	byte 4-7  : ts32 BE           variable step 480/960/1920 (10/20/40ms)
//	byte 8-11 : SSRC              fully random per conn
//	byte 12-13: 0xBE 0xDE         one-byte extension profile
//	byte 14-15: 0x0003            ext data length = 3 words (12 bytes)
//	byte 16   : 0x10              ssrc-audio-level: id=1, len=1
//	byte 17   : 0x80|level        VAD + level (-dBov)
//	byte 18   : 0x21              transport-wide-cc: id=2, len=2
//	byte 19-20: tccSeq16          monotonic transport-cc sequence
//	byte 21   : 0x32              abs-send-time: id=3, len=2
//	byte 22-24: abs_send_time     24-bit NTP timestamp (mod 64s)
//	byte 25-27: 0x00             padding to the 12-byte ext data boundary
//	byte 28-39: nonce = 4B sessionID (MSB=direction) || 8B counter (BE)
//	AAD = bytes[:40].
//
// The nonce counter still increments by exactly one per packet — the seq gaps
// are cosmetic (RTP field only) and never affect nonce uniqueness.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	wrap3HeaderLen = 40
	wrap3Overhead  = 56

	wrap3SpeechMinPkts  = 30
	wrap3SpeechMaxPkts  = 200
	wrap3SilenceMinPkts = 5
	wrap3SilenceMaxPkts = 30
	wrap3GapIntervalMin = 50
	wrap3GapIntervalMax = 150
	wrap3GapSizeMin     = 1
	wrap3GapSizeMax     = 3
	wrap3Ts10ms         = 480
	wrap3Ts20ms         = 960
	wrap3Ts40ms         = 1920
)

type wrap3AudioState int

const (
	wrap3StateSilence wrap3AudioState = iota
	wrap3StateSpeech
)

type wrap3Conn struct {
	aead      cipher.AEAD
	sessionID [4]byte
	ssrc      [4]byte
	start     time.Time // base for abs-send-time; immutable after init

	// Send state is stateful (VAD / gaps), so unlike rtpopus/rtpopus2 the TX
	// fields live under mu rather than as atomics. UnwrapPacket is read-only.
	mu          sync.Mutex
	counter     uint64
	seq         uint16
	timestamp   uint32
	tcc         uint16
	state       wrap3AudioState
	pktsInState int
	nextSwitch  int
	nextGapAt   int
	gapSize     int
}

func newWrap3Conn(key []byte, isServer bool) (*wrap3Conn, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap3: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap3: aead init: %w", err)
	}
	c := &wrap3Conn{
		aead:       aead,
		start:      time.Now(),
		state:      wrap3StateSpeech,
		nextSwitch: wrap3SpeechMinPkts + wrap3Rand(wrap3SpeechMaxPkts-wrap3SpeechMinPkts+1),
		nextGapAt:  wrap3GapIntervalMin + wrap3Rand(wrap3GapIntervalMax-wrap3GapIntervalMin+1),
		gapSize:    wrap3GapSizeMin + wrap3Rand(wrap3GapSizeMax-wrap3GapSizeMin+1),
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("wrap3: rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	if isServer {
		c.sessionID[0] |= 0x80
	} else {
		c.sessionID[0] &^= 0x80
	}
	c.seq = binary.BigEndian.Uint16(rnd[8:10])
	c.timestamp = binary.BigEndian.Uint32(rnd[10:14])
	c.tcc = binary.BigEndian.Uint16(rnd[14:16])
	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("wrap3: counter rand: %w", err)
	}
	c.counter = binary.BigEndian.Uint64(cb[:])
	return c, nil
}

func (c *wrap3Conn) Overhead() int  { return wrap3Overhead }
func (c *wrap3Conn) HeaderLen() int { return wrap3HeaderLen }

// wrap3Rand returns a uniform int in [0,n) from crypto/rand (single byte).
func wrap3Rand(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("wrap3: rand: " + err.Error())
	}
	return int(b[0]) % n
}

func wrap3PickTsStep() uint32 {
	r := wrap3Rand(256)
	switch {
	case r < 10:
		return wrap3Ts10ms
	case r < 230:
		return wrap3Ts20ms
	default:
		return wrap3Ts40ms
	}
}

// updateState advances the VAD model; returns true on a silence->speech
// transition (RTP marker). Caller holds mu.
func (c *wrap3Conn) updateState() bool {
	c.pktsInState++
	if c.pktsInState < c.nextSwitch {
		return false
	}
	c.pktsInState = 0
	if c.state == wrap3StateSilence {
		c.state = wrap3StateSpeech
		c.nextSwitch = wrap3SpeechMinPkts + wrap3Rand(wrap3SpeechMaxPkts-wrap3SpeechMinPkts+1)
		return true
	}
	c.state = wrap3StateSilence
	c.nextSwitch = wrap3SilenceMinPkts + wrap3Rand(wrap3SilenceMaxPkts-wrap3SilenceMinPkts+1)
	return false
}

// level returns the ssrc-audio-level byte: speech carries the V bit + a low
// -dBov, silence the opposite. Caller holds mu (reads state).
func (c *wrap3Conn) level() byte {
	if c.state == wrap3StateSpeech {
		return 0x80 | byte(20+wrap3Rand(31)) // level 20..50
	}
	return byte(100 + wrap3Rand(28)) // level 100..127
}

// computeSeq returns the current seq, periodically skipping gapSize (loss
// mimicry). Caller holds mu.
func (c *wrap3Conn) computeSeq() uint16 {
	seq := c.seq
	c.seq++
	c.nextGapAt--
	if c.nextGapAt > 0 {
		return seq
	}
	c.seq += uint16(c.gapSize)
	c.nextGapAt = wrap3GapIntervalMin + wrap3Rand(wrap3GapIntervalMax-wrap3GapIntervalMin+1)
	c.gapSize = wrap3GapSizeMin + wrap3Rand(wrap3GapSizeMax-wrap3GapSizeMin+1)
	return seq
}

func (c *wrap3Conn) absSendTime() uint32 {
	ms := time.Since(c.start).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	sec := (ms / 1000) % 64
	frac := (ms % 1000) << 18 / 1000
	return uint32(sec)<<18 | uint32(frac)
}

func (c *wrap3Conn) WrapInto(dst, payload []byte) (int, error) {
	wireLen := wrap3Overhead + len(payload)
	if len(dst) < wireLen {
		return 0, errors.New("wrap3: dst buffer too small")
	}

	c.mu.Lock()
	marker := c.updateState()
	lvl := c.level()
	seq := c.computeSeq()
	ts := c.timestamp
	c.timestamp += wrap3PickTsStep()
	tcc := c.tcc
	c.tcc++
	ctr := c.counter
	c.counter++
	c.mu.Unlock()

	dst[0] = 0x90
	pt := wrapRTPPT
	if marker {
		pt |= 0x80
	}
	dst[1] = pt
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], c.ssrc[:])

	dst[12], dst[13] = 0xBE, 0xDE
	binary.BigEndian.PutUint16(dst[14:16], 3)
	dst[16] = 0x10
	dst[17] = lvl
	dst[18] = 0x21
	binary.BigEndian.PutUint16(dst[19:21], tcc)
	dst[21] = 0x32
	ast := c.absSendTime()
	dst[22], dst[23], dst[24] = byte(ast>>16), byte(ast>>8), byte(ast)
	dst[25], dst[26], dst[27] = 0, 0, 0

	copy(dst[28:32], c.sessionID[:])
	binary.BigEndian.PutUint64(dst[32:40], ctr)

	nonce := dst[28:40]
	aad := dst[:40]
	copy(dst[40:], payload)
	c.aead.Seal(dst[40:40], nonce, dst[40:40+len(payload)], aad)
	return wireLen, nil
}

func (c *wrap3Conn) UnwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < wrap3Overhead {
		return 0, errors.New("wrap3: packet too short")
	}
	nonce := wire[28:40]
	aad := wire[:40]
	ct := wire[40:]
	plain, err := c.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return 0, fmt.Errorf("wrap3: AEAD open: %w", err)
	}
	if len(plain) > len(dst) {
		return 0, errors.New("wrap3: dst buffer too small")
	}
	copy(dst, plain)
	return len(plain), nil
}
