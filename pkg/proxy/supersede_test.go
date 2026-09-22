package proxy

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// recorder keeps every write as its own packet.
type recorder struct{ pkts [][]byte }

func (r *recorder) Write(b []byte) (int, error) {
	r.pkts = append(r.pkts, append([]byte(nil), b...))
	return len(b), nil
}

// The server's contract for the sentinel (server/keepalive.go): the magic, the
// length of a hello, and the OLD group's id where the hello carries its own.
var serverSupersedeMagic = []byte{0xff, 'S', 'U', 'P'}

// A rotation names the group it leaves: from then on every session's hello is
// followed by the sentinel carrying the PREVIOUS hello's id — and the previous
// one only, so the server reaps the group the client actually left, not one it
// left earlier or the one it is in.
func TestARotationNamesTheGroupItLeaves(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	first := append([]byte(nil), p.groupHelloBytes()...)

	w := &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) != 1 || !bytes.Equal(w.pkts[0], first) {
		t.Fatalf("before any rotation a session must send the hello alone: %d packet(s)", len(w.pkts))
	}
	if p.supersedeBytes() != nil {
		t.Fatal("a sentinel exists before any rotation")
	}

	p.rotateGroupHello()
	second := append([]byte(nil), p.groupHelloBytes()...)
	if bytes.Equal(second, first) {
		t.Fatal("fixture: the rotation did not change the hello")
	}
	w = &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) != 2 {
		t.Fatalf("after a rotation a session must send the hello and the sentinel: %d packet(s)", len(w.pkts))
	}
	if !bytes.Equal(w.pkts[0], second) {
		t.Fatal("the hello must go first, and it must be the NEW one")
	}
	sup := w.pkts[1]
	if len(sup) != groupHelloLen || !bytes.HasPrefix(sup, serverSupersedeMagic) {
		t.Fatalf("the sentinel is not what the server parses: %d bytes, % x", len(sup), sup[:4])
	}
	if !bytes.Equal(sup[4:], first[4:]) {
		t.Fatal("the sentinel does not name the group the rotation left")
	}
	if bytes.Equal(sup[4:], second[4:]) {
		t.Fatal("the sentinel names the group the client is IN — the server would reap the live group")
	}
	if isProbePacket(sup) {
		t.Fatal("the sentinel was mistaken for a probe by the client's own recognizer")
	}

	// A second rotation names the second group, not the first.
	p.rotateGroupHello()
	w = &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) != 2 || !bytes.Equal(w.pkts[1][4:], second[4:]) {
		t.Fatal("after a second rotation the sentinel must name the group just left, not the original one")
	}
}

// With grouping off (a third party's server) nothing is built and nothing is
// sent — a sentinel there would be a packet into a server that never asked.
func TestNoSentinelWhenGroupingIsOff(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{UseWrapA: true})
	p.rotateGroupHello()
	if p.supersedeBytes() != nil {
		t.Fatal("a sentinel was built with grouping off")
	}
	w := &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) != 0 {
		t.Fatalf("%d packet(s) sent with grouping off", len(w.pkts))
	}
}

// The end of a "pong gap resolved" line: a count when the sequence moved on, a
// word when the pong is a repeat (the server's keepalive) — the count is
// unsigned, and without the branch a repeat printed a number near 2^64.
func TestPongGapTailAndTheRepeatRule(t *testing.T) {
	for _, c := range []struct {
		prev, seq uint64
		want      string
		repeat    bool
	}{
		{5, 9, "missed=3", false},
		{8, 9, "missed=0", false},
		{0, 1, "missed=0", false}, // a session's first pong: nothing missed, not a repeat
		{0, 0, "missed=0", false}, // the zero mark meets a zero seq: not a repeat, and no underflow
		{9, 9, "a repeat of seq 9", true},
		{9, 3, "a repeat of seq 3", true},
	} {
		if got := pongGapTail(c.prev, c.seq); !strings.HasPrefix(got, c.want) {
			t.Fatalf("pongGapTail(%d, %d) = %q, want a prefix %q", c.prev, c.seq, got, c.want)
		}
		if strings.Contains(pongGapTail(c.prev, c.seq), "1844674407") {
			t.Fatalf("pongGapTail(%d, %d) underflowed: %s", c.prev, c.seq, pongGapTail(c.prev, c.seq))
		}
		if got := pongIsRepeat(c.prev, c.seq); got != c.repeat {
			t.Fatalf("pongIsRepeat(%d, %d) = %v, want %v", c.prev, c.seq, got, c.repeat)
		}
	}
}

// Both read loops — DTLS and SRTP — end their gap line through pongGapTail and
// count a repeat through pongIsRepeat right behind the pong mark; a session
// kind that computes the tail by hand brings the underflow back.
func TestBothReadLoopsUseTheOnePongGapRule(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if n := strings.Count(s, "pong gap %ds resolved"); n != 2 {
		t.Fatalf("expected the two gap lines (DTLS, SRTP), found %d", n)
	}
	if n := strings.Count(s, "pongGapTail(prevPongSeq, pongSeq)"); n != 2 {
		t.Fatalf("the gap line goes through pongGapTail in both read loops, found %d", n)
	}
	if regexp.MustCompile(`missed=%d[^\n]*\n[^\n]*pongSeq-prevPongSeq-1`).MatchString(s) {
		t.Fatal("a gap line computes missed= by hand — the unsigned underflow is back")
	}
	if n := strings.Count(s, "if pongIsRepeat(prevPongSeq, pongSeq) {"); n != 2 {
		t.Fatalf("the repeat is counted in both read loops, found %d", n)
	}
	if n := strings.Count(s, "p.notePongSeq(connIdx, pongSeq)"); n != 2 {
		t.Fatalf("expected the two pong marks, found %d", n)
	}
}
