package csqtt25

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"time"
)

// The RTP wrapper. One layout for every mode:
//
//	header(24) ‖ AES-CTR( payload ‖ pad ‖ padTotal(1) ) ‖ HMAC-SHA1-80
//
// The padding and its length byte are INSIDE the keystream; the tag covers
// everything before it. A mode only shapes what the sender emits (payload
// type, padding, the marker bit); a receiver takes every mode alike.
const (
	hdrLen = 24
	tagLen = 10

	PTAudio  byte = 111
	PTVideo  byte = 96
	ptLegacy byte = 6
)

// Mode is the sender's shaping.
type Mode int

const (
	ModeUnified Mode = iota // the reference client's default
	ModeAudio
	ModeVideo
)

// ParseMode accepts the reference client's names.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "unified", "":
		return ModeUnified, nil
	case "audio":
		return ModeAudio, nil
	case "video":
		return ModeVideo, nil
	}
	return 0, errors.New("csqtt25: unknown mode " + s)
}

// Cipher is one direction's key, ready for use.
type Cipher struct {
	block  cipher.Block
	macKey []byte
}

// NewCipher splits a direction's key into its AES and HMAC halves.
func NewCipher(key [KeyLen]byte) (*Cipher, error) {
	b, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return &Cipher{block: b, macKey: append([]byte(nil), key[16:]...)}, nil
}

// Wrapper is one session's sending state. Not safe for concurrent use.
type Wrapper struct {
	c            *Cipher
	mode         Mode
	ssrc         uint32
	initTS       uint32
	initAbs      uint32
	initSeq      uint16
	transportSeq uint16
	count        uint64
	started      time.Time
	rng          *mrand.Rand
	fixedPad     int              // > 0: every packet carries exactly this padTotal (the published vector)
	now          func() time.Time // the clock; a test pins it
}

// NewWrapper starts a session's sending state with fresh randoms.
func NewWrapper(c *Cipher, mode Mode) (*Wrapper, error) {
	var seed [20]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	wallMs := uint64(time.Now().UnixMilli())
	return &Wrapper{
		c: c, mode: mode,
		ssrc:         binary.BigEndian.Uint32(seed[0:4]),
		initTS:       binary.BigEndian.Uint32(seed[4:8]),
		initAbs:      uint32(wallMs*262144/1000) & 0xffffff,
		initSeq:      binary.BigEndian.Uint16(seed[8:10]),
		transportSeq: binary.BigEndian.Uint16(seed[10:12]),
		started:      time.Now(),
		rng:          mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed[12:20])))),
		now:          time.Now,
	}, nil
}

func ticks(elapsed time.Duration, rate uint32) uint32 {
	if elapsed < 0 {
		elapsed = 0
	}
	secs := uint64(elapsed / time.Second)
	nanos := uint64(elapsed % time.Second)
	return uint32(secs*uint64(rate) + nanos*uint64(rate)/1e9)
}

// shape picks the payload type, the padding (padTotal ≥ 1, the length byte
// included) and the marker bit for a payload of n bytes.
func (w *Wrapper) shape(n int) (pt byte, pad int, marker bool) {
	if w.fixedPad > 0 {
		pt = PTAudio
		if w.mode == ModeVideo {
			pt = PTVideo
		}
		return pt, w.fixedPad, false
	}
	between := func(lo, hi int) int { // inclusive
		if hi <= lo {
			return lo
		}
		return lo + w.rng.Intn(hi-lo+1)
	}
	const srtpOverhead = hdrLen + tagLen           // what the wrapper adds
	const pathOverhead = srtpOverhead + 4 + 8 + 20 // + channel data, UDP, IP
	wireMin := n + srtpOverhead
	small := func() int {
		p := between(100, 150) - wireMin
		if p < 1 {
			p = 1
		}
		return p
	}
	switch w.mode {
	case ModeAudio:
		switch {
		case wireMin < 100:
			return PTAudio, small(), false
		case n < 1000:
			return PTAudio, between(1, 24), false
		}
		return PTAudio, 1, false
	case ModeVideo:
		marker = w.rng.Intn(5) == 0
		if n < 1000 {
			return PTVideo, between(1, 48), marker
		}
		head := 1280 - (n + pathOverhead)
		if head > 32 {
			head = 32
		}
		return PTVideo, between(1, head), marker
	}
	switch {
	case wireMin < 100:
		return PTAudio, small(), false
	case n <= 350:
		return PTAudio, between(1, 2), false
	case n+pathOverhead <= 1050:
		head := 1050 - (n + pathOverhead)
		if head > 4 {
			head = 4
		}
		return PTVideo, between(1, head), true
	}
	head := 1350 - (n + pathOverhead)
	if head > 4 {
		head = 4
	}
	return PTVideo, between(1, head), w.rng.Intn(4) == 0
}

// Overhead is the most a Wrap can add to a payload.
func (w *Wrapper) Overhead() int { return hdrLen + 150 + tagLen }

// Wrap appends the wire form of plain to dst[:0].
func (w *Wrapper) Wrap(dst, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("csqtt25: empty payload")
	}
	pt, pad, marker := w.shape(len(plain))
	count := w.count
	w.count++
	seq := w.initSeq + uint16(count)
	tseq := w.transportSeq + uint16(count)
	elapsed := w.now().Sub(w.started)
	if elapsed < 0 {
		elapsed = 0
	}
	var ts uint32
	if pt == PTAudio {
		ts = w.initTS + uint32(elapsed/(20*time.Millisecond))*960
	} else {
		ts = w.initTS + ticks(elapsed, 90000)
	}
	abs := (w.initAbs + ticks(elapsed, 262144)) & 0xffffff

	need := hdrLen + len(plain) + pad + tagLen
	out := dst[:0]
	if cap(out) < need {
		out = make([]byte, need)
	}
	out = out[:need]
	h := out[:hdrLen]
	h[0] = 0xb0
	h[1] = pt & 0x7f
	if marker {
		h[1] |= 0x80
	}
	binary.BigEndian.PutUint16(h[2:4], seq)
	binary.BigEndian.PutUint32(h[4:8], ts)
	binary.BigEndian.PutUint32(h[8:12], w.ssrc)
	binary.BigEndian.PutUint16(h[12:14], 0xbede)
	binary.BigEndian.PutUint16(h[14:16], 2)
	h[16] = 0x32
	h[17], h[18], h[19] = byte(abs>>16), byte(abs>>8), byte(abs)
	h[20] = 0x51
	binary.BigEndian.PutUint16(h[21:23], tseq)
	h[23] = 0

	body := out[hdrLen : hdrLen+len(plain)+pad]
	copy(body, plain)
	padding := body[len(plain):]
	for i := 0; i < len(padding)-1; i++ {
		padding[i] = byte(w.rng.Intn(256))
	}
	padding[len(padding)-1] = byte(pad)
	iv := srtpIV(w.ssrc, seq, ts)
	cipher.NewCTR(w.c.block, iv[:]).XORKeyStream(body, body)

	mac := hmac.New(sha1.New, w.c.macKey)
	mac.Write(out[:need-tagLen])
	copy(out[need-tagLen:], mac.Sum(nil)[:tagLen])
	return out, nil
}

func srtpIV(ssrc uint32, seq uint16, ts uint32) [16]byte {
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], ssrc)
	binary.BigEndian.PutUint16(iv[4:6], seq)
	binary.BigEndian.PutUint32(iv[8:12], ts)
	return iv
}

// IsRTP reports whether a datagram can be one of the wrapper's.
func IsRTP(wire []byte) bool {
	if len(wire) < 13 || wire[0]>>6 != 2 {
		return false
	}
	pt := wire[1] & 0x7f
	return pt == PTAudio || pt == PTVideo || pt == ptLegacy
}

// Unwrap authenticates and decrypts one datagram IN PLACE and returns the
// payload (a slice of wire) and the RTP sequence number.
func (c *Cipher) Unwrap(wire []byte) ([]byte, uint16, error) {
	if !IsRTP(wire) {
		return nil, 0, errors.New("csqtt25: not an RTP datagram of ours")
	}
	seq := binary.BigEndian.Uint16(wire[2:4])
	ts := binary.BigEndian.Uint32(wire[4:8])
	ssrc := binary.BigEndian.Uint32(wire[8:12])
	hl := 12
	if wire[0]&0x10 != 0 {
		if len(wire) < 16 {
			return nil, 0, errors.New("csqtt25: short extension header")
		}
		hl += 4 + int(binary.BigEndian.Uint16(wire[14:16]))*4
	}
	if len(wire) < hl+tagLen {
		return nil, 0, errors.New("csqtt25: no room for the tag")
	}
	tagAt := len(wire) - tagLen
	mac := hmac.New(sha1.New, c.macKey)
	mac.Write(wire[:tagAt])
	if !hmac.Equal(mac.Sum(nil)[:tagLen], wire[tagAt:]) {
		return nil, 0, errors.New("csqtt25: authentication failed")
	}
	iv := srtpIV(ssrc, seq, ts)
	body := wire[hl:tagAt]
	cipher.NewCTR(c.block, iv[:]).XORKeyStream(body, body)
	if wire[0]&0x20 != 0 {
		if len(body) == 0 {
			return nil, 0, errors.New("csqtt25: padding bit on an empty body")
		}
		pad := int(body[len(body)-1])
		if pad == 0 || pad > len(body) {
			return nil, 0, errors.New("csqtt25: bad padding length")
		}
		body = body[:len(body)-pad]
	}
	return body, seq, nil
}
