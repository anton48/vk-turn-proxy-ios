// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

// TestWrapProfilesRoundTrip checks that each SRTP-WRAP-S obf profile encodes a
// payload the peer (opposite direction bit, same key) can AEAD-open back, and
// that the on-wire header markers / sizes match the free-turn-proxy spec.
func TestWrapProfilesRoundTrip(t *testing.T) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key: %v", err)
	}

	for _, tc := range []struct {
		profile  string
		overhead int
		hdrLen   int
	}{
		{ObfRTPOpus, 40, 24},
		{ObfRTPOpus2, 52, 36},
		{ObfRTPOpus3, 56, 40},
	} {
		cli, err := NewWrapCodec(tc.profile, key, false)
		if err != nil {
			t.Fatalf("%s: client codec: %v", tc.profile, err)
		}
		srv, err := NewWrapCodec(tc.profile, key, true)
		if err != nil {
			t.Fatalf("%s: server codec: %v", tc.profile, err)
		}
		if cli.Overhead() != tc.overhead || cli.HeaderLen() != tc.hdrLen {
			t.Fatalf("%s: overhead/hdr = %d/%d want %d/%d", tc.profile, cli.Overhead(), cli.HeaderLen(), tc.overhead, tc.hdrLen)
		}

		for _, n := range []int{1, 64, 512, 1200} {
			payload := make([]byte, n)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("payload: %v", err)
			}
			wire := make([]byte, cli.Overhead()+n)
			m, err := cli.WrapInto(wire, payload)
			if err != nil {
				t.Fatalf("%s: wrap n=%d: %v", tc.profile, n, err)
			}
			if m != tc.overhead+n {
				t.Fatalf("%s: wire len %d want %d", tc.profile, m, tc.overhead+n)
			}
			out := make([]byte, n)
			k, err := srv.UnwrapPacket(wire[:m], out)
			if err != nil {
				t.Fatalf("%s: unwrap n=%d: %v", tc.profile, n, err)
			}
			if k != n || !bytes.Equal(out[:k], payload) {
				t.Fatalf("%s: round-trip mismatch n=%d", tc.profile, n)
			}
		}

		// Header spec assertions on a fresh packet.
		wire := make([]byte, cli.Overhead()+8)
		if _, err := cli.WrapInto(wire, []byte("abcdefgh")); err != nil {
			t.Fatalf("%s: wrap: %v", tc.profile, err)
		}
		switch tc.profile {
		case ObfRTPOpus:
			if wire[0] != 0x80 {
				t.Fatalf("rtpopus byte0=%#x want 0x80", wire[0])
			}
		case ObfRTPOpus2:
			if wire[0] != 0x90 || wire[12] != 0xBE || wire[13] != 0xDE || wire[15] != 0x02 {
				t.Fatalf("rtpopus2 header wrong: %#x %#x %#x %#x", wire[0], wire[12], wire[13], wire[15])
			}
		case ObfRTPOpus3:
			if wire[0] != 0x90 || wire[15] != 0x03 || wire[21] != 0x32 {
				t.Fatalf("rtpopus3 header wrong: byte0=%#x extlen=%#x absSendId=%#x", wire[0], wire[15], wire[21])
			}
		}
	}
}

// TestWriteClientID checks the [1B len | id] record framing.
func TestWriteClientID(t *testing.T) {
	var buf bytesConn
	if err := WriteClientID(&buf, "abc"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := buf.b.Bytes()
	if len(got) != 4 || got[0] != 3 || string(got[1:]) != "abc" {
		t.Fatalf("record = %v want [3 'a' 'b' 'c']", got)
	}
	// >255 truncation.
	buf.b.Reset()
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	if err := WriteClientID(&buf, string(long)); err != nil {
		t.Fatalf("write long: %v", err)
	}
	got = buf.b.Bytes()
	if got[0] != 255 || len(got) != 256 {
		t.Fatalf("truncation wrong: len byte=%d total=%d", got[0], len(got))
	}
}

// bytesConn is a net.Conn stand-in capturing Write for WriteClientID. The
// embedded nil net.Conn supplies the rest of the interface; only Write is used.
type bytesConn struct {
	net.Conn
	b bytes.Buffer
}

func (c *bytesConn) Write(p []byte) (int, error) { return c.b.Write(p) }
