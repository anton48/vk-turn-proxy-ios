// Package csqtt25 holds the wire pieces of the csqtt 2.5 protocol — the
// SECOND protocol that carries the csqtt name; pkg/csqtt is 2.1.9 and stays
// as it is. Written from our own description of the 2.5 wire (the memory
// reference "csqtt 2.5 — what changed since 2.1.9"), which was made by
// reading the 2.5.0 / 2.5.3 sources: constants, formats and observed
// behaviour only. The csqtt sources are PolyForm-Noncommercial; no code of
// theirs is here.
//
// This file: the two things a key can come from without a DTLS handshake.
package csqtt25

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyLen is the size of a direction's cipher key: an AES-128 key followed by
// a 16-byte HMAC-SHA1 key.
const KeyLen = 32

// WrapKey is the password's wrap key — the same derivation as 2.1.9.
func WrapKey(password string) ([KeyLen]byte, error) {
	var key [KeyLen]byte
	if password == "" {
		return key, errors.New("csqtt25: empty password")
	}
	r := hkdf.New(sha256.New, []byte(password), []byte("CSQTT-WRAP-v1"), []byte("rtp-obfs/chacha20poly1305"))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// prf is the TLS 1.2 PRF with SHA-256: P_SHA256(secret, label ‖ seed).
func prf(secret []byte, label string, seed []byte, n int) []byte {
	ls := append([]byte(label), seed...)
	mac := func(parts ...[]byte) []byte {
		h := hmac.New(sha256.New, secret)
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)
	}
	out := make([]byte, 0, n+sha256.Size)
	a := mac(ls)
	for len(out) < n {
		out = append(out, mac(a, ls)...)
		a = mac(a)
	}
	return out[:n]
}

// Keys is the pair a session runs under: the client SENDS under Client and
// RECEIVES under Server.
type Keys struct {
	Client [KeyLen]byte
	Server [KeyLen]byte
}

// cipherKey turns one direction's SRTP master key and salt into its cipher
// key: the master key itself is the AES key, the HMAC key is a PRF keyed by
// the SALT over the master key.
func cipherKey(masterKey, masterSalt []byte) [KeyLen]byte {
	var k [KeyLen]byte
	copy(k[:16], masterKey)
	copy(k[16:], prf(masterSalt, "SRTP auth key", masterKey, 16))
	return k
}

// ExporterLabel and ExporterLen name the DTLS-SRTP keying material
// (RFC 5764): client key 16 ‖ server key 16 ‖ client salt 14 ‖ server salt 14.
const (
	ExporterLabel = "EXTRACTOR-dtls_srtp"
	ExporterLen   = 60
)

// KeysFromExporter turns the DTLS-SRTP exporter block into the session's
// pair. ok is false for a block of another length.
func KeysFromExporter(block []byte) (Keys, bool) {
	if len(block) != ExporterLen {
		return Keys{}, false
	}
	return Keys{
		Client: cipherKey(block[0:16], block[32:46]),
		Server: cipherKey(block[16:32], block[46:60]),
	}, true
}

// keysFromMaster cuts the exporter block out of a master secret and the two
// randoms, as a TLS 1.2 exporter without a context does.
func keysFromMaster(master, clientRandom, serverRandom []byte) Keys {
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	k, _ := KeysFromExporter(prf(master, ExporterLabel, seed, ExporterLen))
	return k
}

// WrapKeys is the WRAP schedule: the keys a client and a server reach with
// NO handshake, from the password's wrap key alone.
func WrapKeys(wrap [KeyLen]byte) Keys {
	premaster := prf(wrap[:], "csqtt-dtls-srtp-pms", []byte("csqtt-premaster"), 32)
	clientRandom := prf(wrap[:], "csqtt-dtls-random", []byte("client-random"), 32)
	serverRandom := prf(wrap[:], "csqtt-dtls-random", []byte("server-random"), 32)
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	master := prf(premaster, "master secret", seed, 48)
	return keysFromMaster(master, clientRandom, serverRandom)
}

// RawKeys is the server's last resort for a first datagram: the wrap key
// itself, one key for both directions.
func RawKeys(wrap [KeyLen]byte) Keys { return Keys{Client: wrap, Server: wrap} }
