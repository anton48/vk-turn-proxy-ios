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
	b := groupReplaceBytes(0x1234)
	if len(b) != groupHelloLen {
		t.Fatalf("length %d, want %d (the hello's construction)", len(b), groupHelloLen)
	}
	if !bytes.Equal(b[:4], groupReplaceMagic) || !bytes.Equal(b[:4], []byte{0xff, 'R', 'E', 'P'}) {
		t.Fatalf("magic %x", b[:4])
	}
	if binary.BigEndian.Uint16(b[4:6]) != 0x1234 {
		t.Fatalf("index bytes %x, want big-endian 0x1234", b[4:6])
	}
	for _, z := range b[6:] {
		if z != 0 {
			t.Fatalf("padding not zero: %x", b[6:])
		}
	}
	for _, idx := range []int{-1, 0x10000} {
		if groupReplaceBytes(idx) != nil {
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
	if want := append(append([]byte(nil), p.groupHelloBytes()...), groupReplaceBytes(7)...); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("hello for conn 7 is %x, want the hello and the replacement sentinel", buf.Bytes())
	}
	setConnRelayPace(8, 500, true)
	buf.Reset()
	p.sendGroupHello(&buf, 8)
	if want := append(append(append([]byte(nil), p.groupHelloBytes()...), groupPaceBytes(500)...), groupReplaceBytes(8)...); !bytes.Equal(buf.Bytes(), want) {
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
	if want := bytes.Repeat(groupReplaceBytes(9), 3); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("three ticks wrote %x, want three replacement sentinels", buf.Bytes())
	}
	buf.Reset()
	failing := func(uint64, time.Time) error { return errors.New("the ping did not go") }
	if err := p.tickPing(&seq, &lastPingAt, time.Now(), failing, &buf, 9); err == nil || buf.Len() != 0 {
		t.Fatalf("a failed ping: err %v, %d bytes behind it — want the error and nothing written", err, buf.Len())
	}
}
