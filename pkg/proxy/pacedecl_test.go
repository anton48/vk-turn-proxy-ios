// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"bytes"
	"testing"
)

// 2026-11-07, the user's design: the pace of a relay reaches the SERVER's
// downlink pacer by the client's word — a sentinel of the hello's construction
// (0xff 'P' 'A' 'C' + the rate in KiB/s as two big-endian bytes, zero-padded
// to the hello's 20 bytes) written right behind the hello and the supersede
// sentinels on every session of a connection whose relay has the field
// (host:port:quota:pace). The server knows nothing of relays but the address
// a connection comes from; the client is the one party that knows which relay
// each of its connections rides and bears the whole cost of a wrong word (a
// VK relay declared unpaced loses ~10 % to VK's policer — its own loss, nobody
// else's). An old server forwards the sentinel to WireGuard, which drops it:
// one 20-byte packet per session, as the supersede sentinel since 434.

func TestThePaceDeclarationsConstruction(t *testing.T) {
	got := groupPaceBytes(500)
	if len(got) != groupHelloLen || !bytes.HasPrefix(got, groupPaceMagic) {
		t.Fatalf("the declaration is %d bytes starting %x; want the hello's %d bytes behind %x", len(got), got[:4], groupHelloLen, groupPaceMagic)
	}
	if got[4] != 0x01 || got[5] != 0xf4 {
		t.Fatalf("500 KiB/s encoded as %x %x, want 01 f4 (big-endian)", got[4], got[5])
	}
	for i, b := range got[6:] {
		if b != 0 {
			t.Fatalf("byte %d of the padding is %x, want 0", 6+i, b)
		}
	}
	if off := groupPaceBytes(0); off[4] != 0 || off[5] != 0 {
		t.Fatalf("no pacer (0) encoded as %x %x", off[4], off[5])
	}
	if big := groupPaceBytes(70000); big[4] != 0xff || big[5] != 0xff {
		t.Fatalf("a rate above the field's range encoded as %x %x, want it clamped to ff ff", big[4], big[5])
	}
	if isProbePacket(got) || bytes.HasPrefix(got, groupHelloMagic) || bytes.HasPrefix(got, groupSupersedeMagic) {
		t.Fatal("the declaration reads as a probe, a hello or a supersede sentinel")
	}
}

// Behind the hello: the server pairs the declaration with the connection the
// hello just grouped. A connection whose relay has no field declares nothing
// (the server's default stands); the probe path (connIdx -1) declares nothing.
//
// SABOTAGE SEEN TO FAIL: sendGroupHello writes the hello and the sentinels
// and never the declaration. Compiles; the buffer then ends at the hello.
func TestTheHelloIsFollowedByTheRelaysPaceDeclaration(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p := &Proxy{}
	p.initGroupHello(Config{})
	setConnRelayPace(2, 500, true)
	setConnRelayPace(3, 0, true)

	var buf bytes.Buffer
	p.sendGroupHello(&buf, 2)
	want := append(append([]byte(nil), p.groupHelloBytes()...), groupPaceBytes(500)...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("conn 2 wrote %x, want the hello then the declaration of 500: %x", buf.Bytes(), want)
	}

	buf.Reset()
	p.sendGroupHello(&buf, 3)
	want = append(append([]byte(nil), p.groupHelloBytes()...), groupPaceBytes(0)...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("conn 3 wrote %x, want the hello then the declaration of no pacer: %x", buf.Bytes(), want)
	}

	for _, idx := range []int{4, -1} {
		buf.Reset()
		p.sendGroupHello(&buf, idx)
		if !bytes.Equal(buf.Bytes(), p.groupHelloBytes()) {
			t.Fatalf("conn %d (no field) wrote %x, want the hello alone", idx, buf.Bytes())
		}
	}

	// Disabled hello (a third party's server): nothing, the declaration included.
	buf.Reset()
	(&Proxy{}).sendGroupHello(&buf, 2)
	if buf.Len() != 0 {
		t.Fatalf("a disabled hello still wrote %d bytes", buf.Len())
	}
}
