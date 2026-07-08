// SPDX-License-Identifier: MIT

package proxy

// SRTP-WRAP-S (samosvalishe/free-turn-proxy interop) obfuscation foundation.
//
// SRTP-WRAP-S is a SEPARATE mode from the existing SRTP-WRAP (wrap.go / useWrap),
// which stays byte-for-byte unchanged (rtpopus, no client-id; compatible with
// samosvalishe/vk-turn-proxy + Moroka8/vk-turn-proxy). free-turn-proxy is the
// evolution and adds (a) a Client-ID record and (b) obf-profiles rtpopus2 /
// rtpopus3. This file provides the profile-agnostic codec contract + factory +
// the Client-ID record helper. The rtpopus profile REUSES the existing wrapConn
// so the two modes share one battle-tested rtpopus implementation.
//
// De-risked 2026-07-08 (tools/rtpopus_interop): all three profiles round-trip
// against a real free-turn-proxy server. See open_task_srtp_wrap_s_mode.

import (
	"fmt"
	"net"
)

// Obf-profile names — identical to free-turn-proxy's -obf-profile values.
const (
	ObfRTPOpus  = "rtpopus"
	ObfRTPOpus2 = "rtpopus2"
	ObfRTPOpus3 = "rtpopus3"
)

// WrapCodec is one per-stream obfuscation codec. WrapInto encodes a payload into
// dst (>= Overhead()+len(payload)); UnwrapPacket AEAD-opens a wire packet into
// dst. The RTP header/extension are AAD only (the peer authenticates but does
// not parse them), so on the receive side only Overhead()/HeaderLen() offsets
// matter. Concrete profiles live in wrap.go (rtpopus), wrap2.go, wrap3.go.
type WrapCodec interface {
	WrapInto(dst, payload []byte) (int, error)
	UnwrapPacket(wire, dst []byte) (int, error)
	Overhead() int
	HeaderLen() int
}

// NewWrapCodec builds the codec for an obf profile. isServer only flips the
// direction bit(s) in the RTP header / nonce. All profiles use the same 32-byte
// ChaCha20-Poly1305 key.
func NewWrapCodec(profile string, key []byte, isServer bool) (WrapCodec, error) {
	switch profile {
	case ObfRTPOpus:
		return newWrapConn(key, isServer)
	case ObfRTPOpus2:
		return newWrap2Conn(key, isServer)
	case ObfRTPOpus3:
		return newWrap3Conn(key, isServer)
	default:
		return nil, fmt.Errorf("wrap: unknown obf profile %q", profile)
	}
}

// --- rtpopus (existing wrapConn) adapts to WrapCodec without touching wrap.go ---

// WrapInto / UnwrapPacket / Overhead / HeaderLen satisfy WrapCodec for wrapConn.
// wrapConn already has wrapInto/unwrapPacket (unexported); these thin exported
// methods bridge to the interface. Behaviour is identical to SRTP-WRAP.
func (w *wrapConn) WrapInto(dst, payload []byte) (int, error)   { return w.wrapInto(dst, payload) }
func (w *wrapConn) UnwrapPacket(wire, dst []byte) (int, error)  { return w.unwrapPacket(wire, dst) }
func (w *wrapConn) Overhead() int                               { return wrapOverhead }
func (w *wrapConn) HeaderLen() int                              { return wrapHeaderLen }

// WriteClientID writes the free-turn-proxy Client-ID record — [1B len | id
// bytes] (id truncated to 255) — as the FIRST DTLS application record after the
// handshake. The server ALWAYS reads exactly one such record (its -clients-file
// flag only toggles the allowlist check); omitting it desyncs the stream. Call
// once per stream, immediately after the DTLS handshake completes, before any
// tunnel payload.
func WriteClientID(conn net.Conn, clientID string) error {
	b := []byte(clientID)
	if len(b) > 255 {
		b = b[:255]
	}
	rec := make([]byte, 1+len(b))
	rec[0] = byte(len(b))
	copy(rec[1:], b)
	_, err := conn.Write(rec)
	return err
}
