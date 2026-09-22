// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pion/stun/v3"
)

// A TURN-over-TCP stream mixes STUN messages with ChannelData frames, and a
// ChannelData frame on a stream is padded to four bytes. A reader that takes
// the length as it stands loses its place at the first odd-sized datagram and
// reads the NEXT frame from the middle of the padding — on a probe whose whole
// verdict is "did the Refresh get its answer", that reads as a dead relay.
// Sabotage seen red: the padding ignored.
func TestReadFrameSkipsTheChannelDataPadding(t *testing.T) {
	var stream bytes.Buffer
	for _, payload := range [][]byte{[]byte("12345"), []byte("1234"), []byte("1")} { // 5 → 8, 4 → 4, 1 → 4
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], firstChannel)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		stream.Write(hdr)
		stream.Write(payload)
		stream.Write(make([]byte, (4-len(payload)%4)%4))
	}
	msg, err := stun.Build(stun.TransactionID, stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), lifetimeAttr(600e9), stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	stream.Write(msg.Raw)

	for i, want := range []string{"12345", "1234", "1"} {
		kind, data, err := readFrame(&stream)
		if err != nil || kind != frameChannelData || string(data) != want {
			t.Fatalf("frame %d: kind %v, %q, %v — want ChannelData %q", i, kind, data, err, want)
		}
	}
	kind, raw, err := readFrame(&stream)
	if err != nil || kind != frameSTUN {
		t.Fatalf("the STUN message after three ChannelData frames: kind %v, %v", kind, err)
	}
	got := &stun.Message{Raw: raw}
	if err := got.Decode(); err != nil || got.TransactionID != msg.TransactionID || lifetimeOf(got) != lifetimeOf(msg) {
		t.Fatalf("the STUN message did not survive the stream: %v (lifetime %s, want %s)", err, lifetimeOf(got), lifetimeOf(msg))
	}
	if stream.Len() != 0 {
		t.Fatalf("%d bytes left in the stream", stream.Len())
	}
	if _, _, err := readFrame(bytes.NewReader([]byte{0x80, 0, 0, 0})); err == nil {
		t.Fatal("a first byte that is neither STUN nor ChannelData was accepted")
	}
}

// A UDP datagram IS its frame. ChannelData padding is optional there (a relay
// may send the bare payload), so the length field bounds the payload and
// nothing past it is wanted; a STUN message must fill its datagram exactly; a
// length that overruns the datagram is refused, not read. Sabotages seen red:
// the stream's padded read used on a datagram (the unpadded frame is refused);
// the overrun check dropped (a panic, caught as a failure).
func TestParseDatagramTakesTheFrameAsItComes(t *testing.T) {
	cd := func(payload string, pad int) []byte {
		b := make([]byte, 4, 4+len(payload)+pad)
		binary.BigEndian.PutUint16(b[0:2], firstChannel)
		binary.BigEndian.PutUint16(b[2:4], uint16(len(payload)))
		return append(append(b, payload...), make([]byte, pad)...)
	}
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"ChannelData without padding", cd("12345", 0), "12345"},
		{"ChannelData padded to four", cd("12345", 3), "12345"},
		{"an empty ChannelData", cd("", 0), ""},
	} {
		kind, data, err := parseDatagram(c.in)
		if err != nil || kind != frameChannelData || string(data) != c.want {
			t.Fatalf("%s: kind %v, %q, %v — want ChannelData %q", c.name, kind, data, err, c.want)
		}
	}
	msg, err := stun.Build(stun.TransactionID, stun.BindingSuccess, stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if kind, raw, err := parseDatagram(msg.Raw); err != nil || kind != frameSTUN || !bytes.Equal(raw, msg.Raw) {
		t.Fatalf("a STUN datagram: kind %v, %v", kind, err)
	}
	overrun := cd("12345", 0)
	binary.BigEndian.PutUint16(overrun[2:4], 500)
	for name, in := range map[string][]byte{
		"a ChannelData length past the datagram": overrun,
		"a STUN message with a trailing byte":    append(append([]byte(nil), msg.Raw...), 0),
		"three bytes":                            {0x40, 0, 0},
		"neither STUN nor ChannelData":           {0x80, 0, 0, 0},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: parseDatagram panicked: %v", name, r)
				}
			}()
			if _, _, err := parseDatagram(in); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		}()
	}
}

// The arms' TCP sockets send no keepalive of their own unless asked: Go's dialer would probe every 15 s and the
// far side, never idle, would never show its own keepalive — the measurement of 2026-09-23 saw exactly that.
func TestTheArmsSendNoKeepaliveOfTheirOwnUnlessAsked(t *testing.T) {
	if d := dialerFor("tcp", true); d.KeepAlive >= 0 {
		t.Fatalf("the TCP dialer keeps Go's default keepalive (KeepAlive %v): the far side is never idle", d.KeepAlive)
	}
	if d := dialerFor("tcp", false); d.KeepAlive != 0 {
		t.Fatal("-os-keepalive must leave the dialer at Go's default")
	}
	if d := dialerFor("udp", true); d.KeepAlive != 0 {
		t.Fatal("a UDP dialer has no keepalive to disable")
	}
	if osKeepalive {
		t.Fatal("the OS keepalive must be OFF by default")
	}
}
