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
