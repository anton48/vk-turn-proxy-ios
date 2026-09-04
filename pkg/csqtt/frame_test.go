// SPDX-License-Identifier: MIT

package csqtt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ipv4TCP builds a minimal IPv4/TCP packet: 20-byte IP header, 20-byte TCP
// header, payloadLen bytes of payload, the given flags and ports.
func ipv4TCP(payloadLen int, flags byte, sport, dport uint16) []byte {
	p := make([]byte, 40+payloadLen)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], []byte{10, 0, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	p[32] = 0x50 // data offset 5 words
	p[33] = flags
	return p
}

func ipv4UDP(payloadLen int) []byte {
	p := make([]byte, 28+payloadLen)
	p[0] = 0x45
	p[9] = 17
	return p
}

func TestFrameHeaderRoundTrip(t *testing.T) {
	h := FrameHeader{SenderID: 17, FlowID: 23, Sequence: 0xdeadbeef}
	buf := make([]byte, FrameLen+3)
	copy(buf[FrameLen:], "abc")
	if !h.Encode(buf) {
		t.Fatal("encode refused a big enough buffer")
	}
	if h.Encode(make([]byte, FrameLen-1)) {
		t.Fatal("encode accepted a short buffer")
	}
	got, payload, ok := DecodeFrame(buf)
	if !ok || got != h || string(payload) != "abc" {
		t.Fatalf("decode: ok=%v h=%+v payload=%q", ok, got, payload)
	}
	if !bytes.Equal(FramePayload(buf), []byte("abc")) {
		t.Fatal("FramePayload did not strip the frame")
	}
	raw := ipv4UDP(4)
	if _, _, ok := DecodeFrame(raw); ok {
		t.Fatal("an unframed packet decoded as a frame")
	}
	if !bytes.Equal(FramePayload(raw), raw) {
		t.Fatal("FramePayload altered an unframed packet")
	}
}

// Which packets are framed is part of the contract: TCP with payload, or a
// SYN/FIN; never a bare ACK, never UDP.
func TestTCPFlowIDSelectsWhatTravelsFramed(t *testing.T) {
	if _, ok := TCPFlowID(ipv4TCP(10, 0x18, 40000, 443)); !ok {
		t.Fatal("TCP with payload must be framed")
	}
	if _, ok := TCPFlowID(ipv4TCP(0, 0x02, 40000, 443)); !ok {
		t.Fatal("SYN must be framed")
	}
	if _, ok := TCPFlowID(ipv4TCP(0, 0x11, 40000, 443)); !ok {
		t.Fatal("FIN must be framed")
	}
	if _, ok := TCPFlowID(ipv4TCP(0, 0x10, 40000, 443)); ok {
		t.Fatal("a bare ACK must travel unframed")
	}
	if _, ok := TCPFlowID(ipv4UDP(100)); ok {
		t.Fatal("UDP must travel unframed")
	}
	if _, ok := TCPFlowID([]byte{0x45}); ok {
		t.Fatal("a truncated packet must not be framed")
	}

	a, _ := TCPFlowID(ipv4TCP(10, 0x18, 40000, 443))
	b, _ := TCPFlowID(ipv4TCP(500, 0x10, 40000, 443)) // same 5-tuple, different size/flags
	c, _ := TCPFlowID(ipv4TCP(10, 0x18, 40001, 443))  // different source port
	if a != b {
		t.Fatal("one flow hashed to two ids")
	}
	if a == c {
		t.Fatal("two flows hashed to one id")
	}
}

func TestSequencerNumbersPerFlowFromZero(t *testing.T) {
	s := NewSequencer(9)
	f1 := ipv4TCP(10, 0x18, 1, 2)
	f2 := ipv4TCP(10, 0x18, 3, 4)
	h1, ok := s.Next(f1)
	h2, _ := s.Next(f1)
	h3, _ := s.Next(f2)
	if !ok || h1.SenderID != 9 || h1.Sequence != 0 || h2.Sequence != 1 || h3.Sequence != 0 {
		t.Fatalf("sequencing: %+v %+v %+v", h1, h2, h3)
	}
	if h1.FlowID == h3.FlowID {
		t.Fatal("two flows share an id")
	}
	if _, ok := s.Next(ipv4UDP(10)); ok {
		t.Fatal("sequencer framed a UDP packet")
	}
	if NewSequencer(0).senderID == 0 {
		t.Fatal("random sender id must never be 0")
	}

	framed, ok := s.Frame(nil, f1)
	if !ok || len(framed) != FrameLen+len(f1) {
		t.Fatalf("Frame: ok=%v len=%d", ok, len(framed))
	}
	h, payload, _ := DecodeFrame(framed)
	if h.Sequence != 2 || !bytes.Equal(payload, f1) {
		t.Fatalf("Frame produced %+v", h)
	}
	if out, ok := s.Frame(nil, ipv4UDP(3)); ok || len(out) != 31 {
		t.Fatal("Frame must pass UDP through unchanged")
	}
}

func hdr(seq uint32) FrameHeader { return FrameHeader{SenderID: 17, FlowID: 23, Sequence: seq} }

func TestReassemblerDeliversInOrderAndHoldsGaps(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	r.PushAt(hdr(0), 0, 0, &out)
	r.PushAt(hdr(2), 2, 1, &out) // gap: 1 missing
	r.PushAt(hdr(3), 3, 2, &out)
	if len(out) != 1 || out[0] != 0 {
		t.Fatalf("delivered %v while a gap was open", out)
	}
	r.PushAt(hdr(1), 1, 3, &out)
	if want := []int{0, 1, 2, 3}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
	if r.pendingTotal != 0 {
		t.Fatalf("pendingTotal %d after drain", r.pendingTotal)
	}
}

// After gapRelease the receiver gives up on the missing packet: the lowest
// pending one is delivered and the sequence jumps past it.
func TestReassemblerReleasesAfterGapTimeout(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	r.PushAt(hdr(0), 0, 0, &out)
	r.PushAt(hdr(2), 2, 10, &out)
	r.PushAt(hdr(3), 3, 15, &out)
	if len(out) != 1 {
		t.Fatalf("released before the timeout: %v", out)
	}
	r.PushAt(hdr(5), 5, 23, &out) // 13 ms after the gap opened
	if want := []int{0, 2, 3}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
	// 4 is now the missing one; 1 arriving late is behind and dropped.
	r.PushAt(hdr(1), 1, 24, &out)
	r.PushAt(hdr(4), 4, 25, &out)
	if want := []int{0, 2, 3, 4, 5}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
}

// Once the gap has been released, the packet that was missing is behind the
// sequence and is dropped even though it would have been in order a moment
// earlier — the release happens BEFORE the new packet is looked at.
func TestReassemblerLateArrivalAfterReleaseIsDropped(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	r.PushAt(hdr(0), 0, 0, &out)
	r.PushAt(hdr(2), 2, 10, &out)
	r.PushAt(hdr(3), 3, 11, &out)
	r.PushAt(hdr(1), 1, 30, &out) // 20 ms late: 2 and 3 are released first
	if want := []int{0, 2, 3}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
}

func TestReassemblerDropsDuplicatesAndStragglers(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	r.PushAt(hdr(0), 0, 0, &out)
	r.PushAt(hdr(0), 0, 1, &out) // duplicate of a delivered one
	r.PushAt(hdr(2), 2, 2, &out)
	r.PushAt(hdr(2), 2, 3, &out) // duplicate of a pending one
	if r.pendingTotal != 1 {
		t.Fatalf("duplicate counted: pendingTotal %d", r.pendingTotal)
	}
	r.PushAt(hdr(1), 1, 4, &out)
	if want := []int{0, 1, 2}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
}

func TestReassemblerPerFlowCapReleasesLowest(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	r.PushAt(hdr(0), 0, 0, &out)
	for i := 2; i < 2+maxPendingPerFlow; i++ { // fill the per-flow cap, 1 missing
		r.PushAt(hdr(uint32(i)), i, 1, &out)
	}
	if len(out) != 1 {
		t.Fatalf("released early: %d", len(out))
	}
	r.PushAt(hdr(uint32(2+maxPendingPerFlow)), 2+maxPendingPerFlow, 1, &out)
	if len(out) < 2 || out[1] != 2 {
		t.Fatalf("cap did not release the lowest pending: %v", out[:min(len(out), 4)])
	}
}

// Independent flows do not block each other.
func TestReassemblerFlowsAreIndependent(t *testing.T) {
	r := NewReassembler[int]()
	var out []int
	other := FrameHeader{SenderID: 17, FlowID: 99, Sequence: 0}
	r.PushAt(hdr(1), 1, 0, &out) // flow 23 waits for 0
	r.PushAt(other, 100, 0, &out)
	if want := []int{100}; !equalInts(out, want) {
		t.Fatalf("got %v want %v", out, want)
	}
}

func TestIsForwardHalfSpace(t *testing.T) {
	if !isForward(1, 0) || isForward(0, 0) || isForward(0, 1) {
		t.Fatal("basic forward/backward")
	}
	if !isForward(5, 0xffff_fff0) { // wrapped ahead
		t.Fatal("wrap-around ahead must be forward")
	}
	if isForward(0x8000_0001, 0) { // beyond half space
		t.Fatal("beyond half the space must not be forward")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
