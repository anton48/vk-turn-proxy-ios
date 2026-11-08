// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// 2026-11-08, the failover run on 477 (Nov 8 §603): the forty sessions were back
// within 1.5 s of the mark, and the server kept the forty DEAD members for
// another minute — its downlink hub, a shared channel served longest-waiting
// first, fed them the next ≈40 packets while the live sessions got nothing.
// The client now names, behind the hello and behind every tick's ping, the
// connection a new session replaces: its own index.

func TestTheReplacementSentinelsConstruction(t *testing.T) {
	b := groupReplaceBytes(0x1234, 0x0102030405060708)
	if len(b) != groupHelloLen {
		t.Fatalf("length %d, want %d (the hello's construction)", len(b), groupHelloLen)
	}
	if !bytes.Equal(b[:4], groupReplaceMagic) || !bytes.Equal(b[:4], []byte{0xff, 'R', 'E', 'P'}) {
		t.Fatalf("magic %x", b[:4])
	}
	if binary.BigEndian.Uint16(b[4:6]) != 0x1234 {
		t.Fatalf("index bytes %x, want big-endian 0x1234", b[4:6])
	}
	if binary.BigEndian.Uint64(b[6:14]) != 0x0102030405060708 {
		t.Fatalf("generation bytes %x, want big-endian 0x0102030405060708", b[6:14])
	}
	for _, z := range b[14:] {
		if z != 0 {
			t.Fatalf("padding not zero: %x", b[14:])
		}
	}
	for _, idx := range []int{-1, 0x10000} {
		if groupReplaceBytes(idx, 1) != nil {
			t.Fatalf("an index the wire cannot carry (%d) made a sentinel", idx)
		}
	}
	// Never mistaken for the hello, the supersede or the pace sentinel.
	for i, m := range [][]byte{groupHelloMagic, groupSupersedeMagic, groupPaceMagic} {
		if bytes.Equal(m, groupReplaceMagic) {
			t.Fatalf("magic %d equals the replacement's", i)
		}
	}
}

// Behind the hello — after the pace declaration, where the relay has a field —
// and nothing for a connection without an index (the probe's −1), nothing with
// the hello disabled.
func TestTheHelloIsFollowedByTheReplacementSentinel(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p := &Proxy{}
	p.initGroupHello(Config{})
	var buf bytes.Buffer
	p.sendGroupHello(&buf, 7)
	if want := append(append([]byte(nil), p.groupHelloBytes()...), groupReplaceBytes(7, 0)...); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("hello for conn 7 is %x, want the hello and the replacement sentinel", buf.Bytes())
	}
	setConnRelayPace(8, 500, true)
	buf.Reset()
	p.sendGroupHello(&buf, 8)
	if want := append(append(append([]byte(nil), p.groupHelloBytes()...), groupPaceBytes(500)...), groupReplaceBytes(8, 0)...); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("hello for conn 8 is %x, want hello + pace + replacement", buf.Bytes())
	}
	buf.Reset()
	p.sendGroupHello(&buf, -1)
	if !bytes.Equal(buf.Bytes(), p.groupHelloBytes()) {
		t.Fatalf("the probe's hello carries %d bytes, want the hello alone", buf.Len())
	}
	buf.Reset()
	(&Proxy{}).sendGroupHello(&buf, 7)
	if buf.Len() != 0 {
		t.Fatal("a disabled hello wrote the replacement sentinel")
	}
}

// Behind every tick's ping, after the pace declaration; nothing behind a failed
// ping (the connection is being judged).
func TestTheReplacementGoesAgainWithEveryTicksPing(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p := &Proxy{}
	var seq uint64
	var lastPingAt time.Time
	send := func(uint64, time.Time) error { return nil }
	var buf bytes.Buffer
	for i := 0; i < 3; i++ {
		if err := p.tickPing(&seq, &lastPingAt, time.Now(), send, &buf, 9); err != nil {
			t.Fatal(err)
		}
	}
	if want := bytes.Repeat(groupReplaceBytes(9, 0), 3); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("three ticks wrote %x, want three replacement sentinels", buf.Bytes())
	}
	buf.Reset()
	failing := func(uint64, time.Time) error { return errors.New("the ping did not go") }
	if err := p.tickPing(&seq, &lastPingAt, time.Now(), failing, &buf, 9); err == nil || buf.Len() != 0 {
		t.Fatalf("a failed ping: err %v, %d bytes behind it — want the error and nothing written", err, buf.Len())
	}
}

// The user's review of b1372eb: the sentinel carries the session's GENERATION —
// the hand-out stamp the pool gave this session (recorded by recordHandOut),
// read under connMu — so that the server tells a late copy of the old session
// from the new session's claim. A connection without a hand-out sends 0.
func TestTheReplacementSentinelCarriesTheSessionsGeneration(t *testing.T) {
	resetPace()
	t.Cleanup(resetPace)
	p := &Proxy{connRelay: make([]string, 4), connRelaySeq: make([]uint64, 4)}
	p.initGroupHello(Config{})
	p.setConnRelay(2, relayA, 41) // the hand-out's stamp
	var buf bytes.Buffer
	p.sendGroupHello(&buf, 2)
	if want := append(append([]byte(nil), p.groupHelloBytes()...), groupReplaceBytes(2, 41)...); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("the hello's sentinel does not carry the hand-out's stamp 41: %x", buf.Bytes()[len(p.groupHelloBytes()):])
	}
	// The tick's repeat carries the same generation; a new hand-out moves it.
	var seq uint64
	var lastPingAt time.Time
	send := func(uint64, time.Time) error { return nil }
	buf.Reset()
	if err := p.tickPing(&seq, &lastPingAt, time.Now(), send, &buf, 2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), groupReplaceBytes(2, 41)) {
		t.Fatalf("the tick's sentinel carries %x, want generation 41", buf.Bytes())
	}
	p.endConnSession(2)
	p.setConnRelay(2, relayA, 57)
	buf.Reset()
	p.sendReplaceDeclaration(&buf, 2)
	if !bytes.Equal(buf.Bytes(), groupReplaceBytes(2, 57)) {
		t.Fatalf("after a new hand-out the sentinel carries %x, want generation 57", buf.Bytes())
	}
	// Another index: its own stamp (0 when none).
	buf.Reset()
	p.sendReplaceDeclaration(&buf, 3)
	if !bytes.Equal(buf.Bytes(), groupReplaceBytes(3, 0)) {
		t.Fatalf("an index without a hand-out carries %x, want generation 0", buf.Bytes())
	}
}
