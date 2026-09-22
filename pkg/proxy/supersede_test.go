package proxy

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"sync"
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

// helloID is the 16-byte id inside a hello or a sentinel.
func helloID(pkt []byte) []byte { return pkt[len(groupHelloMagic):] }

// sentinels returns the ids named by the sentinels among the packets, in order,
// and checks each one's shape against the server's contract.
func sentinels(t *testing.T, pkts [][]byte) [][]byte {
	t.Helper()
	var ids [][]byte
	for _, pkt := range pkts {
		if !bytes.HasPrefix(pkt, serverSupersedeMagic) {
			continue
		}
		if len(pkt) != groupHelloLen {
			t.Fatalf("a sentinel of %d bytes — the server accepts exactly %d", len(pkt), groupHelloLen)
		}
		if isProbePacket(pkt) {
			t.Fatal("a sentinel was mistaken for a probe by the client's own recognizer")
		}
		ids = append(ids, helloID(pkt))
	}
	return ids
}

func containsID(ids [][]byte, id []byte) bool {
	for _, x := range ids {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

// A rotation names the group it leaves: the next hellos are followed by the
// sentinel naming the ANNOUNCED group left behind — the one the server can
// have — never the group the client is in, and for a bounded number of hellos.
func TestARotationNamesTheGroupItLeaves(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	first := append([]byte(nil), p.groupHelloBytes()...)

	w := &recorder{}
	p.sendGroupHello(w) // announces A
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
	if len(w.pkts) != 2 || !bytes.Equal(w.pkts[0], second) {
		t.Fatalf("after a rotation a session must send the NEW hello first and then the sentinel: %d packet(s)", len(w.pkts))
	}
	ids := sentinels(t, w.pkts[1:])
	if len(ids) != 1 || !bytes.Equal(ids[0], helloID(first)) {
		t.Fatal("the sentinel does not name the group the rotation left")
	}
	if containsID(ids, helloID(second)) {
		t.Fatal("the sentinel names the group the client is IN — the server would reap the live group")
	}

	// The sentinel rides the next hellos supersedeSends times in all, then the
	// group is forgotten: the copies go out on the first sessions to come up.
	for i := 1; i < supersedeSends; i++ {
		w = &recorder{}
		p.sendGroupHello(w)
		if !containsID(sentinels(t, w.pkts), helloID(first)) {
			t.Fatalf("hello %d after the rotation did not carry the sentinel (%d are due)", i+1, supersedeSends)
		}
	}
	w = &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) != 1 {
		t.Fatalf("after %d sentinels the group is still named: %d packet(s)", supersedeSends, len(w.pkts))
	}

	// A second rotation names the second group, which was announced.
	p.rotateGroupHello()
	w = &recorder{}
	p.sendGroupHello(w)
	ids = sentinels(t, w.pkts)
	if len(ids) != 1 || !bytes.Equal(ids[0], helloID(second)) {
		t.Fatal("after a second rotation the sentinel must name the group just left, not the original one")
	}
}

// THE REVIEW'S CASE. Path-ups in a cascade inside the debounce: A is at the
// server, then A → B → C before any connection of B ever came up. The server
// knows nothing of B; the sentinel behind C's hellos must name A — the group
// the server HAS — and not B, or A lives on until the backstop with the
// keepalive repeating into it.
func TestACascadeOfRotationsNamesTheGroupTheServerHas(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	p.sendGroupHello(&recorder{}) // A announced

	p.rotateGroupHello() // → B, no session comes up
	b := append([]byte(nil), p.groupHelloBytes()...)
	p.rotateGroupHello() // → C
	c := append([]byte(nil), p.groupHelloBytes()...)

	w := &recorder{}
	p.sendGroupHello(w)
	if len(w.pkts) < 2 || !bytes.Equal(w.pkts[0], c) {
		t.Fatalf("the hello must be C, first: %d packet(s)", len(w.pkts))
	}
	ids := sentinels(t, w.pkts)
	if !containsID(ids, helloID(a)) {
		t.Fatal("the sentinel does not name A — the group the server has — and A lives on until the backstop")
	}
	if containsID(ids, helloID(b)) {
		t.Fatal("the sentinel names B, which no connection ever announced: the server knows no such group")
	}
	if containsID(ids, helloID(c)) {
		t.Fatal("the sentinel names the group the client is in")
	}
	if len(ids) != 1 {
		t.Fatalf("%d sentinel(s), want exactly the one naming A", len(ids))
	}
}

// Two announced groups left in a row are BOTH named until each has had its
// sends: A announced → B announced (and A named once) → C: the hellos of C name
// B and, until its count is full, A too.
func TestEveryAnnouncedGroupLeftIsNamedUntilItsSends(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	p.sendGroupHello(&recorder{})
	p.rotateGroupHello()
	b := append([]byte(nil), p.groupHelloBytes()...)
	p.sendGroupHello(&recorder{}) // announces B, names A once
	p.rotateGroupHello()

	w := &recorder{}
	p.sendGroupHello(w)
	ids := sentinels(t, w.pkts)
	if !containsID(ids, helloID(b)) || !containsID(ids, helloID(a)) {
		t.Fatalf("the hellos of C must name B and A (A's sends are not full): named %d", len(ids))
	}
	for i := 0; i < supersedeSends; i++ {
		p.sendGroupHello(&recorder{})
	}
	w = &recorder{}
	p.sendGroupHello(w)
	if len(sentinels(t, w.pkts)) != 0 {
		t.Fatal("groups are still named after their sends")
	}
}

// A hello that was on its way out while its group rotated away announced that
// group: it is noted as left by the write itself (the rotation saw it
// unannounced and skipped it), or the server would keep it to the backstop.
func TestAHelloInFlightAcrossARotationLeavesAGroupTheServerHas(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	w := &rotatingRecorder{p: p}
	p.sendGroupHello(w) // the hello of A is written; the rotation lands inside the write
	if bytes.Equal(p.groupHelloBytes(), a) {
		t.Fatal("fixture: the rotation inside the write did not happen")
	}
	w2 := &recorder{}
	p.sendGroupHello(w2)
	if !containsID(sentinels(t, w2.pkts), helloID(a)) {
		t.Fatal("the group announced by a hello in flight across the rotation was not named — it lives on at the server")
	}
	// Both the rotation and the write can find A left (in the other order of
	// the race the rotation notes it first and the write finds it again): the
	// note is idempotent, and A is on the list ONCE.
	p.noteGroupLeft(helloID(a))
	p.noteGroupLeft(helloID(a))
	p.groupsLeftMu.Lock()
	n := 0
	for _, g := range p.groupsLeft {
		if bytes.Equal(g.sup[len(groupSupersedeMagic):], helloID(a)) {
			n++
		}
	}
	p.groupsLeftMu.Unlock()
	if n != 1 {
		t.Fatalf("the group left is on the list %d times, want once", n)
	}
}

// rotatingRecorder rotates the group hello from inside the first write, the
// way a path-up landing between a session's load of the hello and its write does.
type rotatingRecorder struct {
	p    *Proxy
	pkts [][]byte
}

func (r *rotatingRecorder) Write(b []byte) (int, error) {
	r.pkts = append(r.pkts, append([]byte(nil), b...))
	if len(r.pkts) == 1 {
		r.p.rotateGroupHello()
	}
	return len(b), nil
}

// A sentinel whose write failed was not sent: it counts for nothing, and the
// group stays named for the next hello.
func TestAFailedSentinelWriteCountsForNothing(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	p.sendGroupHello(&recorder{})
	p.rotateGroupHello()
	for i := 0; i < 2*supersedeSends; i++ {
		p.sendGroupHello(&failAfterFirst{})
	}
	w := &recorder{}
	p.sendGroupHello(w)
	if !containsID(sentinels(t, w.pkts), helloID(a)) {
		t.Fatal("failed writes were counted as sends: the group is no longer named")
	}
}

// failAfterFirst accepts the hello and fails every write behind it.
type failAfterFirst struct{ n int }

func (f *failAfterFirst) Write(b []byte) (int, error) {
	f.n++
	if f.n > 1 {
		return 0, os.ErrClosed
	}
	return len(b), nil
}

// The list of groups left is bounded: a rotation storm with no session ever
// coming up cannot grow it without limit; the oldest goes first.
func TestTheGroupsLeftAreBounded(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	for i := 0; i < groupsLeftCap+3; i++ {
		p.sendGroupHello(&failAfterFirst{}) // announce; the sentinels behind it fail, so nothing is ever counted
		p.rotateGroupHello()
	}
	p.groupsLeftMu.Lock()
	n := len(p.groupsLeft)
	p.groupsLeftMu.Unlock()
	if n != groupsLeftCap {
		t.Fatalf("%d groups kept, want the cap %d", n, groupsLeftCap)
	}
}

// hookedRecorder runs hook from inside the FIRST write — the hello's — the way
// events landing between a session's load of the hello and the write's return
// do; a rotation, another session's whole hello, whatever the case needs.
type hookedRecorder struct {
	hook func()
	pkts [][]byte
}

func (r *hookedRecorder) Write(b []byte) (int, error) {
	r.pkts = append(r.pkts, append([]byte(nil), b...))
	if len(r.pkts) == 1 && r.hook != nil {
		r.hook()
	}
	return len(b), nil
}

// THE REVIEW'S FIRST CASE (the review of 435). A hello of A is on its way out
// when the tunnel rotates to B; a session of B announces B; THEN the late
// hello of A completes. 435 kept one "last announced" pointer per tunnel, the
// late write overwrote it with A, and at the next rotation B looked
// unannounced and was never named — the server kept B to its backstop. The
// fact of an announcement belongs to the GENERATION: a late hello of A
// announces A and says nothing about B.
func TestALateHelloOfAnOldGroupDoesNotUnannounceTheNewOne(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	var b []byte
	w := &hookedRecorder{hook: func() {
		p.rotateGroupHello() // A → B while A's hello is in flight
		b = append([]byte(nil), p.groupHelloBytes()...)
		p.sendGroupHello(&recorder{}) // a session of B announces B, whole
	}}
	p.sendGroupHello(w) // A's hello completes last
	if bytes.Equal(b, a) || len(b) == 0 {
		t.Fatal("fixture: the rotation inside the write did not happen")
	}
	p.rotateGroupHello() // B → C: B was announced and must be named
	c := append([]byte(nil), p.groupHelloBytes()...)
	w2 := &recorder{}
	p.sendGroupHello(w2)
	ids := sentinels(t, w2.pkts)
	if !containsID(ids, helloID(b)) {
		t.Fatal("B — announced by a session of its own — is not named after the rotation away from it: the late hello of A un-announced it, and the server keeps B to its backstop")
	}
	if !containsID(ids, helloID(a)) {
		t.Fatal("A — announced by the late hello — is not named")
	}
	if containsID(ids, helloID(c)) {
		t.Fatal("the sentinel names the group the client is in")
	}
}

// The other direction of the same binding: a late hello of A announces A
// ALONE. With no session of B ever up, the rotation away from B names nothing
// — the server never had B — and A, which the late hello did announce, is
// named. Sabotage seen red: the flag set on the CURRENT generation instead of
// the one the hello belongs to.
func TestALateHelloAnnouncesItsOwnGroupOnly(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	var b []byte
	w := &hookedRecorder{hook: func() {
		p.rotateGroupHello() // A → B while A's hello is in flight; nobody announces B
		b = append([]byte(nil), p.groupHelloBytes()...)
	}}
	p.sendGroupHello(w)
	p.rotateGroupHello() // B → C
	w2 := &recorder{}
	p.sendGroupHello(w2)
	ids := sentinels(t, w2.pkts)
	if containsID(ids, helloID(b)) {
		t.Fatal("B named although no session ever announced it: the late hello of A announced the CURRENT group instead of its own")
	}
	if !containsID(ids, helloID(a)) {
		t.Fatal("A — announced by the late hello — is not named")
	}
	if len(ids) != 1 {
		t.Fatalf("%d sentinel(s), want exactly the one naming A", len(ids))
	}
}

// gatedRecorder holds the FIRST write — the hello's — until gate is closed,
// telling entered that the session is inside it: the hello it will write is
// the one it loaded before the gate, whatever the tunnel does meanwhile.
type gatedRecorder struct {
	gate    <-chan struct{}
	entered *sync.WaitGroup
	held    bool
	pkts    [][]byte
}

func (g *gatedRecorder) Write(b []byte) (int, error) {
	if !g.held {
		g.held = true
		g.entered.Done()
		<-g.gate
	}
	g.pkts = append(g.pkts, append([]byte(nil), b...))
	return len(b), nil
}

// THE REVIEW'S SECOND CASE. Three sessions loaded the hello of A before the
// rotation to B, and their writes complete after it. 435 excluded the tunnel's
// CURRENT group (B) from the sentinels, so each of the three wrote hello A +
// supersede A — a no-op at the server, where a group cannot supersede itself
// (old == by) — and counted it: A's three copies were spent on nothing, and
// the first real session of B no longer named A. A sentinel never names the
// group of the hello it rides behind, and such a self-supersede spends no
// copy.
func TestASelfSupersedeIsNeverWrittenAndSpendsNothing(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	a := append([]byte(nil), p.groupHelloBytes()...)
	p.sendGroupHello(&recorder{}) // A announced

	gate := make(chan struct{})
	var entered, done sync.WaitGroup
	ws := make([]*gatedRecorder, supersedeSends)
	for i := range ws {
		ws[i] = &gatedRecorder{gate: gate, entered: &entered}
		entered.Add(1)
		done.Add(1)
		go func(w *gatedRecorder) {
			defer done.Done()
			p.sendGroupHello(w)
		}(ws[i])
	}
	entered.Wait()       // the three are inside their hello's write: each loaded A
	p.rotateGroupHello() // → B
	b := append([]byte(nil), p.groupHelloBytes()...)
	close(gate) // the three hellos of A complete after the rotation
	done.Wait()
	for i, w := range ws {
		if len(w.pkts) < 1 || !bytes.Equal(w.pkts[0], a) {
			t.Fatalf("fixture: old session %d did not write the hello of A", i)
		}
		if ids := sentinels(t, w.pkts); len(ids) != 0 {
			t.Fatalf("old session %d wrote a sentinel behind its hello of A, naming %x — a group cannot supersede itself at the server", i, ids[0])
		}
	}
	// The sessions of B name A — all supersedeSends of them — and not one more.
	for i := 0; i < supersedeSends; i++ {
		w := &recorder{}
		p.sendGroupHello(w)
		if len(w.pkts) < 1 || !bytes.Equal(w.pkts[0], b) {
			t.Fatalf("fixture: session %d of B did not write the hello of B", i+1)
		}
		if !containsID(sentinels(t, w.pkts), helloID(a)) {
			t.Fatalf("session %d of B does not name A: the self-supersedes of the old sessions spent A's copies", i+1)
		}
	}
	w := &recorder{}
	p.sendGroupHello(w)
	if len(sentinels(t, w.pkts)) != 0 {
		t.Fatal("A is still named after its sends")
	}
}

// failEvery fails every write: a hello that never left.
type failEvery struct{}

func (failEvery) Write(b []byte) (int, error) { return 0, os.ErrClosed }

// A hello whose write failed announced nothing: the server never saw it, and
// the rotation away from that group names nothing.
func TestAFailedHelloAnnouncesNothing(t *testing.T) {
	p := &Proxy{}
	p.initGroupHello(Config{})
	p.sendGroupHello(failEvery{})
	p.rotateGroupHello()
	w := &recorder{}
	p.sendGroupHello(w)
	if len(sentinels(t, w.pkts)) != 0 {
		t.Fatal("a group whose hello never left is named — the server never had it")
	}
}

// The announcement and the rotation go under ONE lock — the announced flag
// set and the "has the tunnel rotated away from me" check on one side, the old
// generation's flag read and the replacement on the other — so that neither
// can slip between the other's two steps (a hello marked announced after the
// rotation read the flag and before it stored the new generation would be a
// group the server has and nobody names). A race test cannot pin that; the
// source can.
func TestTheAnnouncementAndTheRotationShareOneLock(t *testing.T) {
	body := func(file, fn string) string {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		i := strings.Index(s, "func (p *Proxy) "+fn+"(")
		if i < 0 {
			t.Fatalf("%s: no %s", file, fn)
		}
		j := strings.Index(s[i:], "\n}\n")
		return s[i : i+j]
	}
	underLock := func(fn, body string, stmts ...string) {
		lock := strings.Index(body, "p.groupsLeftMu.Lock()")
		if lock < 0 {
			t.Fatalf("%s does not take groupsLeftMu", fn)
		}
		unlock := strings.Index(body, "\tp.groupsLeftMu.Unlock()")
		if unlock < 0 {
			unlock = len(body) // deferred: held to the end
		}
		for _, s := range stmts {
			i := strings.Index(body, s)
			if i < 0 {
				t.Fatalf("%s: %q not found", fn, s)
			}
			if i < lock || i > unlock {
				t.Fatalf("%s: %q is outside the lock", fn, s)
			}
		}
	}
	underLock("rotateGroupHello", body("pathrestart.go", "rotateGroupHello"),
		"old := p.groupHello.Load()", "p.groupHello.Store(next)", "old.announced")
	underLock("announced", body("proxy.go", "announced"),
		"g.announced = true", "p.groupHello.Load() != g")
	send := body("proxy.go", "sendGroupHello")
	if strings.Contains(send, "announced = true") {
		t.Fatal("sendGroupHello sets the flag itself, outside announced's lock")
	}
	if i, j := strings.Index(send, "w.Write(g.hello)"), strings.Index(send, "p.announced(g)"); i < 0 || j < 0 || j < i {
		t.Fatal("the generation must be announced by the write of its hello, after it")
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
