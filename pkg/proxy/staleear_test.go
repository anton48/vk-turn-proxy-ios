package proxy

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// The direct session makes one relay leg after another under ONE note, and so
// under one allocLife. pion's Client.Close ends the client's transactions and
// waits for nothing: its reader — and its refresh timers — can still be on
// their way to the logger when the leg's teardown has returned and the next
// leg's client is up. A word of the client that is gone must not be taken for
// the new one's: the reader's end of the old leg ended the NEW leg (the
// session's cancel is one for all its legs).

// heldReaderEnd is a logger factory around the session's own: pion's line for
// the end of its read loop is HELD on its way to the session's ear until
// released — the order of the client's callback and the leg's teardown, set by
// the test.
type heldReaderEnd struct {
	inner   logging.LoggerFactory
	once    sync.Once
	arrived chan struct{} // the reader has its error and is about to say so
	release chan struct{} // let it
	through chan struct{} // it has said so, and the ear has returned
}

func newHeldReaderEnd(inner logging.LoggerFactory) *heldReaderEnd {
	return &heldReaderEnd{inner: inner, arrived: make(chan struct{}), release: make(chan struct{}), through: make(chan struct{})}
}

func (h *heldReaderEnd) NewLogger(scope string) logging.LeveledLogger {
	return &heldLogger{LeveledLogger: h.inner.NewLogger(scope), h: h}
}

type heldLogger struct {
	logging.LeveledLogger
	h *heldReaderEnd
}

func (l *heldLogger) Debugf(format string, args ...interface{}) {
	held := false
	if strings.HasSuffix(format, pionReaderExits) {
		l.h.once.Do(func() { held = true })
	}
	if !held {
		l.LeveledLogger.Debugf(format, args...)
		return
	}
	close(l.h.arrived)
	<-l.h.release
	l.LeveledLogger.Debugf(format, args...)
	close(l.h.through)
}

// nobodyListens is a loopback address a datagram is REFUSED at.
func nobodyListens(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	return a
}

// legClient is a relay leg's pion client as runTURN makes it: a CONNECTED UDP
// socket, the session's logger factory, Listen.
func legClient(t *testing.T, relay *net.UDPAddr, lf logging.LoggerFactory) (*turn.Client, *net.UDPConn) {
	t.Helper()
	sock, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: relay.String(), TURNServerAddr: relay.String(), Conn: &connectedUDPConn{sock}, LoggerFactory: lf})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	return c, sock
}

// refuseUntil sends datagrams into the address nobody listens at — the refusal
// comes back to the connected socket's reader — until cond holds.
func refuseUntil(t *testing.T, sock *net.UDPConn, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("fixture: %s — the refused datagram did not end pion's reader", what)
		}
		_, _ = sock.Write([]byte{0})
		time.Sleep(10 * time.Millisecond)
	}
}

// The reviewer's stand: a real pion client, its reader's callback held across
// the leg's teardown and the next leg's start.
func TestALateWordOfAnEndedClientDoesNotEndTheNextRelayLeg(t *testing.T) {
	var gave gaveBack
	var kills atomic.Int32
	gave.watch(func() { kills.Add(1) }, 7, true)
	life := gave.lifeOf()
	nobody := nobodyListens(t)
	logged := captureLog(t)

	// Leg 1, in runTURN's order: the client's ear, the client, Listen, fresh.
	held := newHeldReaderEnd(&turnLoggerFactory{slot: 0, ear: life.newEar()})
	c1, sock1 := legClient(t, nobody, held)
	life.fresh()
	refuseUntil(t, sock1, "leg 1", func() bool { return isClosed(held.arrived) })
	// The leg ends — runTURN's teardown: the client's Close, which waits for no
	// reader, then the join of what the allocation's life had begun.
	c1.Close()
	life.wait()
	_ = sock1.Close()
	if kills.Load() != 0 {
		t.Fatal("fixture: the session was ended before the old reader's word was let through")
	}

	// Leg 2 — the direct session's next, under the same note.
	c2, sock2 := legClient(t, nobody, &turnLoggerFactory{slot: 0, ear: life.newEar()})
	life.fresh()

	// Only now does the OLD client's reader get its word through.
	close(held.release)
	select {
	case <-held.through:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: the held line never came through")
	}
	if n := kills.Load(); n != 0 {
		t.Fatalf("the reader of a client whose leg is over ended the session %d time(s) under its NEXT leg — a word is its own client's, never the next one's", n)
	}
	if strings.Contains(logged(), readerEndedLine) {
		t.Error("the old client's reader end was said as the new leg's")
	}

	// The control: the new leg's OWN reader ending still ends the session, once.
	refuseUntil(t, sock2, "leg 2", func() bool { return kills.Load() > 0 })
	c2.Close()
	life.wait()
	if n := kills.Load(); n != 1 {
		t.Errorf("the new leg's own reader ended and the session was ended %d time(s), want once", n)
	}
	if n := strings.Count(logged(), "proxy: [conn 7] "+readerEndedLine); n != 1 {
		t.Errorf("the new leg's reader end was said %d time(s), want once", n)
	}
}

// The tests that speak into a session's life directly speak as the client it
// listens to NOW.
func (l *allocLife) nowEar() *lifeEar {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return &lifeEar{life: l, gen: l.hears}
}

func (l *allocLife) heardDebug(msg string) { l.nowEar().heardDebug(msg) }
func (l *allocLife) heardError(msg string) { l.nowEar().heardError(msg) }

// Every word the ear takes, said by a client whose leg is over while the next
// leg's client is up: nothing of the session's life moves. The same word said by
// the client listened to moves something — or the row would be blind.
func TestNoWordOfAClientThatIsGoneReachesTheNextOne(t *testing.T) {
	const (
		readerEnd  = "Failed to read: read udp 192.0.2.1:50000->192.0.2.2:3478: read: connection refused. Exiting loop"
		refused400 = "Fail to refresh permissions: CreatePermission error response (error 400: Bad Request)"
	)
	asked := func(cur *lifeEar) { cur.heardDebug(pionRefreshSent) }
	for _, c := range []struct {
		name   string
		before func(cur *lifeEar) // what the client listened to has said already
		say    func(e *lifeEar)
	}{
		{"the end of its read loop", nil, func(e *lifeEar) { e.heardDebug(readerEnd) }},
		{"a permission refresh answered 400 (pion says it in two lines)", nil, func(e *lifeEar) { e.heardError(refused400); e.heardError(refused400) }},
		{"a lifetime granted", nil, func(e *lifeEar) { e.heardDebug("Updated lifetime: 5 seconds") }},
		{"a refresh sent", nil, func(e *lifeEar) { e.heardDebug(pionRefreshSent) }},
		{"a refresh answered", asked, func(e *lifeEar) { e.heardDebug(pionRefreshAnswered) }},
		{"a refresh that came back with no answer", asked, func(e *lifeEar) { e.heardError(pionRefreshFailed + "all retransmissions failed") }},
	} {
		for _, gone := range []bool{true, false} {
			var gave gaveBack
			var kills atomic.Int32
			gave.watch(func() { kills.Add(1) }, 7, false)
			l := gave.lifeOf()
			old := l.newEar() // the leg before: its client's ear…
			l.fresh()
			l.wait()          // …and its teardown
			cur := l.newEar() // the next leg's client
			l.fresh()
			if c.before != nil {
				c.before(cur)
			}
			t0 := time.Now()
			type state struct {
				kills       int32
				gone        bool
				soon, later int64
			}
			snap := func() state {
				return state{kills.Load(), l.isGone(), l.expiry(t0).UnixNano(), l.expiry(t0.Add(time.Hour)).UnixNano()}
			}
			was := snap()
			who := "the client listened to"
			if gone {
				who = "a client whose leg is over"
				c.say(old)
			} else {
				c.say(cur)
			}
			joinLife(t, l) // whatever the word began has run
			is := snap()
			if gone && is != was {
				t.Errorf("%s, said by %s, moved the next leg's life: %+v → %+v", c.name, who, was, is)
			}
			if !gone && is == was {
				t.Errorf("fixture: %s, said by %s, moved nothing — the row cannot see a word that gets through", c.name, who)
			}
		}
	}
	var none *allocLife
	if e := none.newEar(); e != nil {
		t.Error("a nil life made an ear")
	}
	(*lifeEar)(nil).heardDebug(readerEnd) // no bookkeeping: nothing to trap on
	(*lifeEar)(nil).heardError(refused400)
}
