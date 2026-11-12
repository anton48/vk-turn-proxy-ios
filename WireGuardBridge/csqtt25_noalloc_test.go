package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
)

// What pion says when the relay answers a permission refresh 400 — the line the
// field shows at a thaw behind a changed mapping (its wording is pinned in pion's
// source by pkg/proxy's TestPionStillSaysWhatThisBuildListensFor).
const noAllocLine = "Fail to refresh permissions: CreatePermission error response (error 400: Bad Request)"

// earRelay is a relay with nothing under it: its close is seen, the word said
// for it counted.
func earRelay() (r *csqtt25Relay, ear *csqtt25RelayEar, closed chan struct{}, said *atomic.Int32) {
	closed, said = make(chan struct{}, 4), new(atomic.Int32)
	r = &csqtt25Relay{}
	r.close = func() { closed <- struct{}{} }
	csqtt25RelayConn{r: r}.onNoAllocation(func() { said.Add(1) })
	ear = csqtt25NewRelayEar()
	ear.relay.Store(r)
	return r, ear, closed, said
}

func stillOpen(t *testing.T, closed chan struct{}, what string) {
	t.Helper()
	select {
	case <-closed:
		t.Fatalf("the relay was closed on %s", what)
	case <-time.After(60 * time.Millisecond):
	}
}

// The ear ends its relay on ONE line — a permission refresh the relay answered
// 400 — said at Warn or Error, formatted or not; once; and on nothing else: a
// refresh that got no answer, an allocation refresh refused, the 400 without
// pion's prefix, a bare «400» in another refusal, the same words below Warn.
func TestCsqtt25RelayEarEndsItsRelayOnAPermissionRefreshAnswered400AndOnNothingElse(t *testing.T) {
	if got := fmt.Sprintf("Fail to refresh permissions: %s", errors.New("CreatePermission error response (error 400: Bad Request)")); got != noAllocLine {
		t.Fatalf("the test's line is not what pion's format makes of the relay's answer: %q", got)
	}
	says := []struct {
		name string
		say  func(l logging.LeveledLogger, msg string)
	}{
		{"Warn", func(l logging.LeveledLogger, m string) { l.Warn(m) }},
		{"Warnf", func(l logging.LeveledLogger, m string) { l.Warnf("%s", m) }},
		{"Error", func(l logging.LeveledLogger, m string) { l.Error(m) }},
		{"Errorf", func(l logging.LeveledLogger, m string) { l.Errorf("%s", m) }},
	}
	for _, s := range says {
		t.Run(s.name, func(t *testing.T) {
			_, ear, closed, said := earRelay()
			l := ear.NewLogger("turnc")
			for _, quiet := range []string{
				"Fail to refresh permissions: all retransmissions failed for the request",
				"Failed to refresh allocation: Refresh error response (error 437: Allocation Mismatch)",
				"CreatePermission error response (error 400: Bad Request)",
				"Fail to refresh permissions: CreatePermission error response (error 403: Forbidden), port 400",
			} {
				s.say(l, quiet)
				stillOpen(t, closed, "«"+quiet+"»")
			}
			l.Debug(noAllocLine)
			l.Info(noAllocLine)
			stillOpen(t, closed, "the line said below Warn")
			if said.Load() != 0 {
				t.Fatalf("the word was said %d times before the relay said anything", said.Load())
			}

			s.say(l, noAllocLine)
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("the relay said it has no allocation for this socket and the relay was not closed")
			}
			if said.Load() != 1 {
				t.Fatalf("the word was said %d times, want once", said.Load())
			}
			s.say(l, noAllocLine) // pion says it again at every refresh that fails
			time.Sleep(60 * time.Millisecond)
			if said.Load() != 1 {
				t.Fatalf("a second such line was said again: %d times", said.Load())
			}
		})
	}
}

// An ear that has no relay yet ends nothing and breaks nothing; and a relay
// whose close is already under way — the stream ended for a reason of its own —
// is told nothing: no word in the log for a stream that is gone.
func TestCsqtt25RelayEarWithoutARelayAndARelayAlreadyClosingAreLeftAlone(t *testing.T) {
	csqtt25NewRelayEar().NewLogger("turnc").Error(noAllocLine)

	r, ear, closed, said := earRelay()
	r.Close()
	<-closed
	ear.NewLogger("turnc").Error(noAllocLine)
	time.Sleep(60 * time.Millisecond)
	if said.Load() != 0 {
		t.Fatalf("a relay that was closing was told it has no allocation (%d words)", said.Load())
	}
}

// The relay is told ONCE even while its word is still being said: pion says the
// line again at the next refresh that fails, and two lines can come before the
// close the first began has started — one word in the log, one close.
func TestCsqtt25RelayIsToldOnceEvenWhileItsWordIsBeingSaid(t *testing.T) {
	closed, gate := make(chan struct{}, 4), make(chan struct{})
	var said atomic.Int32
	r := &csqtt25Relay{}
	r.close = func() { closed <- struct{}{} }
	csqtt25RelayConn{r: r}.onNoAllocation(func() {
		said.Add(1)
		<-gate // the word is being said: the close has not begun
	})
	r.noAllocation()
	deadline := time.Now().Add(2 * time.Second)
	for said.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	r.noAllocation()
	time.Sleep(60 * time.Millisecond)
	if n := said.Load(); n != 1 {
		t.Fatalf("the word was begun %d times, want once", n)
	}
	close(gate)
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the relay was not closed behind its word")
	}
	stillOpen(t, closed, "a second word")
}

// WHERE it is wired: the bridge's TURN client is made with the dial's ear for
// its logger factory — pion's lines reach the ear and nothing else is handed to
// the client (no test can ask pion's client whose logger it holds; its permission
// refresh comes two minutes into an allocation).
func TestCsqtt25DialRelayHandsItsTURNClientTheEar(t *testing.T) {
	b, err := os.ReadFile("csqtt25_relay.go")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code = append(code, line)
	}
	src := strings.Join(code, "\n")
	if !regexp.MustCompile(`ear\s*:=\s*csqtt25NewRelayEar\(\)`).MatchString(src) {
		t.Fatal("the dial makes no ear")
	}
	handed := regexp.MustCompile(`LoggerFactory:\s*([^,\n]+),`).FindAllStringSubmatch(src, -1)
	if len(handed) != 1 || strings.TrimSpace(handed[0][1]) != "ear" {
		t.Fatalf("the TURN client's logger factory is not the dial's ear: %v", handed)
	}
	if strings.Contains(src, "NewDefaultLoggerFactory") {
		t.Fatal("the relay's dial makes a logger factory of its own beside the ear")
	}
}

// 🚨 The real stack, over TCP and over UDP: the dial's ear knows the relay the
// dial returned — so the line pion would say ends THIS stream: a read parked on the stream's
// conn ends, a write fails, the owner's word is said once, and the close is the
// ordinary close (over UDP the relay is asked about the deallocate and its
// answer kept for the lease; over TCP nothing is asked).
func TestCsqtt25RelayToldItHasNoAllocationEndsItsStreamsSocketOnTheRealStack(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			relayAddr := relayTURN(t, transport)
			server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
			var ears []*csqtt25RelayEar
			prev := csqtt25NewRelayEar
			csqtt25NewRelayEar = func() *csqtt25RelayEar {
				e := prev()
				ears = append(ears, e)
				return e
			}
			t.Cleanup(func() { csqtt25NewRelayEar = prev })

			r, err := csqtt25DialRelay(context.Background(), csqtt.TURNCredentials{Username: "u", Password: "pw", Address: relayAddr}, server, transport, nil)
			if err != nil {
				t.Fatalf("the dial: %v", err)
			}
			defer r.Close()
			if len(ears) != 1 {
				t.Fatalf("the dial made %d ear(s), want one", len(ears))
			}
			if ears[0].relay.Load() != r {
				t.Fatal("the dial's ear does not know the relay the dial returned")
			}
			pc := r.packetConn()
			var said atomic.Int32
			pc.(interface{ onNoAllocation(func()) }).onNoAllocation(func() { said.Add(1) })
			readErr := make(chan error, 1)
			go func() {
				_, _, err := pc.ReadFrom(make([]byte, 64))
				readErr <- err
			}()
			select {
			case err := <-readErr:
				t.Fatalf("the read ended by itself: %v", err)
			case <-time.After(100 * time.Millisecond):
			}

			ears[0].NewLogger("turnc").Errorf("Fail to refresh permissions: %s", errors.New("CreatePermission error response (error 400: Bad Request)"))
			select {
			case err := <-readErr:
				if err == nil {
					t.Fatal("the parked read returned a datagram, not its end")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the relay said it has no allocation and the stream's read is still parked")
			}
			r.Close() // returns behind the close the word began
			if said.Load() != 1 {
				t.Fatalf("the owner's word was said %d times, want once", said.Load())
			}
			if _, err := pc.WriteTo([]byte("x"), server); err == nil {
				t.Fatal("a write through the closed allocation went out")
			}
			v, asked := r.deallocated()
			if transport == "udp" {
				if !asked || v != csqtt.DeallocateConfirmed {
					t.Fatalf("over UDP the close did not ask the relay as any close does: asked %v, word %v", asked, v)
				}
			} else if asked {
				t.Fatalf("over TCP the close asked the relay: word %v", v)
			}
		})
	}
}

// noAllocConn is a relay conn as the dialer sees it: it takes the owner's word.
type noAllocConn struct {
	net.PacketConn
	say func()
}

func (c *noAllocConn) onNoAllocation(f func()) { c.say = f }

// The dialer gives the relay its word — and the word names the WORKER whose
// stream it is, which the relay itself does not know.
func TestCsqtt25DialerSaysWhoseRelayHasNoAllocation(t *testing.T) {
	conn := &noAllocConn{}
	prev := csqtt25OpenRelay
	csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
		return conn, func() {}, nil
	}
	t.Cleanup(func() { csqtt25OpenRelay = prev })
	lease := func(context.Context, int) (csqtt.Credential, error) {
		return csqtt.Credential{
			Allocated: func(time.Time) {},
			Failed:    func(error, time.Time) {},
			Release:   func() {},
		}, nil
	}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	_, _, closer, err := (&csqtt25Client{}).dialer(server, "udp", lease)(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if conn.say == nil {
		t.Fatal("the dialer gave the relay no word to say")
	}
	var out bytes.Buffer
	prevW := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prevW) })
	conn.say()
	if got := out.String(); !strings.Contains(got, "csqtt25: worker 7:") || !strings.Contains(got, "NO allocation") {
		t.Fatalf("the word does not name the worker and what the relay said: %q", got)
	}
}
