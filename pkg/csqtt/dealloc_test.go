// SPDX-License-Identifier: MIT

package csqtt

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// refreshAnswer is a relay's answer to a Refresh: a success, or an error with
// code — a challenge (401 / 438) carries the realm and a nonce unless bare.
func refreshAnswer(t *testing.T, code stun.ErrorCode, bare bool) *stun.Message {
	t.Helper()
	setters := []stun.Setter{stun.TransactionID}
	switch {
	case code == 0:
		setters = append(setters, stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse))
	default:
		setters = append(setters, stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse), code)
		if (code == stun.CodeUnauthorized || code == stun.CodeStaleNonce) && !bare {
			setters = append(setters, stun.NewRealm("okcdn.ru"), stun.NewNonce("n"))
		}
	}
	m, err := stun.Build(setters...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The conversation with the relay, answer by answer: an unauthenticated
// Refresh(0), the challenge, the authenticated one — and what each answer
// makes of the allocation.
func TestConfirmDeallocateReadsTheRelaysAnswer(t *testing.T) {
	boom := errors.New("write: network is unreachable")
	cases := []struct {
		name     string
		answers  []stun.ErrorCode // 0 = success; -1 = no answer (nil); -2 = the round trip fails
		bare     bool             // the challenge carries no realm / nonce
		want     Deallocate
		wantCode int
		requests int
	}{
		{"the challenge, then released", []stun.ErrorCode{stun.CodeUnauthorized, 0}, false, DeallocateConfirmed, 0, 2},
		{"released at once", []stun.ErrorCode{0}, false, DeallocateConfirmed, 0, 1},
		{"the challenge, then 437: no allocation for this socket", []stun.ErrorCode{stun.CodeUnauthorized, stun.CodeAllocMismatch}, false, DeallocateGone, 437, 2},
		{"437 at once", []stun.ErrorCode{stun.CodeAllocMismatch}, false, DeallocateGone, 437, 1},
		{"a stale nonce is owed one more try", []stun.ErrorCode{stun.CodeUnauthorized, stun.CodeStaleNonce, 0}, false, DeallocateConfirmed, 0, 3},
		{"challenged for ever", []stun.ErrorCode{stun.CodeUnauthorized, stun.CodeStaleNonce, stun.CodeStaleNonce}, false, DeallocateRefused, 438, 3},
		{"a challenge that cannot be answered", []stun.ErrorCode{stun.CodeUnauthorized}, true, DeallocateRefused, 401, 1},
		{"another error", []stun.ErrorCode{stun.CodeUnauthorized, stun.CodeBadRequest}, false, DeallocateRefused, 400, 2},
		{"nothing comes back", []stun.ErrorCode{-1}, false, DeallocateUnanswered, 0, 1},
		{"the request cannot be written", []stun.ErrorCode{-2}, false, DeallocateUnanswered, 0, 1},
		{"silence behind the challenge", []stun.ErrorCode{stun.CodeUnauthorized, -1}, false, DeallocateUnanswered, 0, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var reqs []*stun.Message
			do := func(req *stun.Message) (*stun.Message, error) {
				reqs = append(reqs, req)
				if len(reqs) > len(c.answers) {
					t.Fatalf("request %d: the conversation should have ended behind %d", len(reqs), len(c.answers))
				}
				switch a := c.answers[len(reqs)-1]; a {
				case -1:
					return nil, nil
				case -2:
					return nil, boom
				default:
					return refreshAnswer(t, a, c.bare), nil
				}
			}
			v, code, _ := confirmDeallocate(do, "u", "pw")
			if v != c.want || code != c.wantCode || len(reqs) != c.requests {
				t.Fatalf("verdict %d code %d after %d request(s), want %d / %d / %d", v, code, len(reqs), c.want, c.wantCode, c.requests)
			}
			for i, req := range reqs {
				if req.Type != stun.NewType(stun.MethodRefresh, stun.ClassRequest) {
					t.Fatalf("request %d is not a Refresh request", i+1)
				}
				if lt, err := req.Get(stun.AttrLifetime); err != nil || !reflect.DeepEqual(lt, []byte{0, 0, 0, 0}) {
					t.Fatalf("request %d asks for lifetime %v (%v), want 0 — a deallocate", i+1, lt, err)
				}
				// The first request cannot carry credentials (the nonce is the
				// relay's to give); every one behind a challenge must.
				if signed := req.Contains(stun.AttrMessageIntegrity) && req.Contains(stun.AttrUsername) && req.Contains(stun.AttrNonce); signed != (i > 0) {
					t.Fatalf("request %d signed: %v, want %v", i+1, signed, i > 0)
				}
			}
		})
	}
}

// A relay that says nothing costs the close its budget and no more: the pending
// round trip is aborted and JOINED — nothing runs on behind a close.
func TestTheConfirmedDeallocateEndsAtItsBudget(t *testing.T) {
	aborted := make(chan struct{})
	var aborts, running atomic.Int32
	do := func(*stun.Message) (*stun.Message, error) {
		running.Add(1)
		defer running.Add(-1)
		select {
		case <-aborted:
		case <-time.After(3 * time.Second): // a test of a bound is bounded itself
		}
		return nil, errors.New("transaction closed")
	}
	abort := func() {
		if aborts.Add(1) == 1 {
			close(aborted)
		}
	}
	t0 := time.Now()
	v, _, err := boundedDeallocate(do, abort, "u", "pw", 80*time.Millisecond)
	took := time.Since(t0)
	if v != DeallocateUnanswered || err == nil {
		t.Fatalf("verdict %d (%v), want unanswered with the budget named", v, err)
	}
	if took < 80*time.Millisecond || took > time.Second {
		t.Fatalf("returned after %v, want its 80ms budget", took.Round(time.Millisecond))
	}
	if aborts.Load() != 1 || running.Load() != 0 {
		t.Fatalf("aborted %d time(s), %d round trip(s) still running behind the return — want 1 and 0", aborts.Load(), running.Load())
	}
	// Answered inside the budget, nothing is aborted.
	aborts.Store(0)
	v, _, _ = boundedDeallocate(func(*stun.Message) (*stun.Message, error) { return refreshAnswer(t, 0, false), nil },
		func() { aborts.Add(1) }, "u", "pw", time.Second)
	if v != DeallocateConfirmed || aborts.Load() != 0 {
		t.Fatalf("an answered deallocate: verdict %d, aborted %d time(s)", v, aborts.Load())
	}
}

// Out of reach is the relay disowning the socket (437) or saying nothing — the
// two answers behind which the allocation may live on. A confirmation is the
// opposite; another refusal is about the request.
func TestOutOfReachIsTheRelaysDisowningOrItsSilence(t *testing.T) {
	want := map[Deallocate]bool{DeallocateConfirmed: false, DeallocateGone: true, DeallocateRefused: false, DeallocateUnanswered: true, DeallocateNotAwaited: true}
	said := map[string]Deallocate{}
	for v, out := range want {
		if v.OutOfReach() != out {
			t.Errorf("verdict %d out of reach: %v, want %v", v, v.OutOfReach(), out)
		}
		if other, dup := said[v.Why()]; dup || v.Why() == "" {
			t.Errorf("verdict %d is worded as verdict %d is (%q): a log could not tell them apart", v, other, v.Why())
		}
		said[v.Why()] = v
	}
}

// closeStep records what a close does to the control socket and in what order.
type closeStep struct {
	net.PacketConn
	name  string
	order *[]string
}

func (c *closeStep) SetWriteDeadline(time.Time) error {
	*c.order = append(*c.order, c.name+" deadline")
	return nil
}

func (c *closeStep) Close() error {
	*c.order = append(*c.order, c.name+" close")
	return nil
}

// The close asks the relay IN FRONT of the relayed conn's own close (whose
// deallocate nobody listens to), behind the write deadline, and sets the
// deadline anew behind the wait; with nothing to ask it is the old close.
func TestTheCloseAsksTheRelayBeforeItClosesTheAllocation(t *testing.T) {
	var order []string
	ctl := &closeStep{name: "ctl", order: &order}
	relayed := &closeStep{name: "relayed", order: &order}
	closeRelayBounded(ctl, relayed, func() { order = append(order, "client") }, func() { order = append(order, "ask") })
	want := []string{"ctl deadline", "ask", "ctl deadline", "relayed close", "client", "ctl close"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("the close ran %v, want %v", order, want)
	}
	order = nil
	closeRelayBounded(ctl, relayed, func() { order = append(order, "client") }, nil)
	want = []string{"ctl deadline", "relayed close", "client", "ctl close"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("a close with nothing to ask ran %v, want %v", order, want)
	}
}

// ─── the real stack ────────────────────────────────────────────────────────

// loopbackTURNUDP is loopbackTURN over UDP: a pion TURN server that knows
// u / pw, and its allocation count.
func loopbackTURNUDP(t *testing.T) (addr string, allocations func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "okcdn.ru",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == "u" {
				return "u", key, true
			}
			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n := srv.AllocationCount(); n != 0 {
			t.Errorf("%d allocation(s) left on the loopback relay at the test's end", n)
		}
		_ = srv.Close()
	})
	return pc.LocalAddr().String(), srv.AllocationCount
}

// udpTap stands between one client socket and the relay and can stop passing
// the relay's answers down — a relay this side no longer hears: at once (deaf),
// or behind the first deafAfter answers.
type udpTap struct {
	front, back *net.UDPConn
	deaf        atomic.Bool
	deafAfter   atomic.Int32 // > 0: pass this many answers down, then no more
	down        atomic.Int32
	mu          sync.Mutex
	client      *net.UDPAddr
}

func newUDPTap(t *testing.T, relay string) *udpTap {
	t.Helper()
	to, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, to)
	if err != nil {
		t.Fatal(err)
	}
	p := &udpTap{front: front, back: back}
	t.Cleanup(func() { front.Close(); back.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.client = from
			p.mu.Unlock()
			_, _ = back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			to := p.client
			p.mu.Unlock()
			if after := p.deafAfter.Load(); after > 0 && p.down.Add(1) > after {
				continue
			}
			if to != nil && !p.deaf.Load() {
				_, _ = front.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return p
}

func loopbackPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr)
}

// Over UDP the close ASKS and the relay confirms: the allocation is gone from
// the relay when Close returns, and the relay's word is kept.
func TestARelayOverUDPConfirmsItsDeallocate(t *testing.T) {
	addr, allocations := loopbackTURNUDP(t)
	r, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: addr}, loopbackPeer(t), "udp", logging.LogLevelError, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := allocations(); n != 1 {
		t.Fatalf("fixture: %d allocation(s) behind the dial, want 1", n)
	}
	if _, asked := r.Deallocate(); asked {
		t.Fatalf("the relay's word on a deallocate is there before the close asked for it")
	}
	r.Close()
	v, asked := r.Deallocate()
	if !asked || v != DeallocateConfirmed {
		t.Fatalf("the close over UDP: asked %v, verdict %d — want the relay's confirmation", asked, v)
	}
	if n := allocations(); n != 0 {
		t.Fatalf("%d allocation(s) at the relay when the confirmed close returned, want 0", n)
	}
}

// A relay this side no longer hears: the close waits its budget, no longer, and
// says the deallocate was not answered — out of reach.
func TestARelayOverUDPThatDoesNotAnswerIsOutOfReach(t *testing.T) {
	old := DeallocateConfirmBudget
	DeallocateConfirmBudget = 150 * time.Millisecond
	t.Cleanup(func() { DeallocateConfirmBudget = old })
	addr, _ := loopbackTURNUDP(t)
	tap := newUDPTap(t, addr)
	r, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: tap.front.LocalAddr().String()}, loopbackPeer(t), "udp", logging.LogLevelError, nil)
	if err != nil {
		t.Fatal(err)
	}
	tap.deaf.Store(true)
	t0 := time.Now()
	r.Close()
	took := time.Since(t0)
	v, asked := r.Deallocate()
	if !asked || v != DeallocateUnanswered || !v.OutOfReach() {
		t.Fatalf("the close over a relay that says nothing: asked %v, verdict %d — want unanswered, out of reach", asked, v)
	}
	// The BUDGET ends the wait, not the write deadline on the control socket
	// (500 ms: pion's next repeat behind it fails, some 600 ms in) — the two are
	// told apart by a budget well under that deadline.
	if took < 150*time.Millisecond || took > 450*time.Millisecond {
		t.Fatalf("the close took %v, want the confirm's 150ms budget — not the write deadline's 600ms", took.Round(time.Millisecond))
	}
}

// Over TCP nothing is asked: the connection's own close frees the allocation.
func TestARelayOverTCPAsksNothing(t *testing.T) {
	addr := loopbackTURN(t)
	r, err := DialRelay(TURNCredentials{Username: "u", Password: "pw", Address: addr}, loopbackPeer(t), "tcp", logging.LogLevelError, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if v, asked := r.Deallocate(); asked {
		t.Fatalf("a TCP relay's close asked the relay about its deallocate (verdict %d)", v)
	}
}

// The worker tells its lease that the allocation is out of reach BEFORE it
// releases it — and only then: a confirmed or a refused deallocate, and a close
// that asked nothing, say nothing.
func TestAWorkerTellsItsLeaseOfAnAllocationOutOfReachBeforeItsRelease(t *testing.T) {
	cases := []struct {
		name string
		said int32 // Relay.dealloc as the close leaves it: 0 = nothing asked
		want []string
	}{
		{"answered 437", int32(DeallocateGone) + 1, []string{"out of reach: its deallocate was answered 437", "released"}},
		{"not answered", int32(DeallocateUnanswered) + 1, []string{"out of reach: its deallocate was not answered", "released"}},
		{"confirmed", int32(DeallocateConfirmed) + 1, []string{"released"}},
		{"refused", int32(DeallocateRefused) + 1, []string{"released"}},
		{"nothing asked", 0, []string{"released"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newFakeServer(t)
			prev := dialRelay
			dialRelay = func(_ TURNCredentials, _ *net.UDPAddr, _ string, _ logging.LogLevel, allocated func()) (*Relay, error) {
				uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					return nil, err
				}
				if allocated != nil {
					allocated()
				}
				r := &Relay{Conn: uc, Local: uc.LocalAddr()}
				r.close = func() { r.dealloc.Store(c.said); uc.Close() } // what the relay said to the close
				return r, nil
			}
			t.Cleanup(func() { dialRelay = prev })
			var mu sync.Mutex
			var events []string
			note := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
			creds := func(context.Context, int) (Credential, error) {
				return Credential{
					TURNCredentials: TURNCredentials{Username: "u", Password: "p", Address: "127.0.0.1:1"},
					Release:         func() { note("released") },
					OutOfReach:      func(why string) { note("out of reach: " + why) },
				}, nil
			}
			c2 := dialReady(t, testConfig(srv, 1, creds))
			c2.Close()
			waitFor(t, "the lease given back", func() bool {
				mu.Lock()
				defer mu.Unlock()
				return len(events) > 0 && events[len(events)-1] == "released"
			})
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(events, c.want) {
				t.Fatalf("the lease heard %v, want %v", events, c.want)
			}
		})
	}
}

// refusingTURN is a pion TURN server (u / pw) that accepts every Allocate and
// refuses every permission — over UDP and over TCP.
func refusingTURN(t *testing.T) (udp, tcp string, allocations func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gen := &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	no := func(net.Addr, net.IP) bool { return false }
	key := turn.GenerateAuthKey("u", "okcdn.ru", "pw")
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:             "okcdn.ru",
		AuthHandler:       func(*turn.RequestAttributes) (string, []byte, bool) { return "u", key, true },
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: gen, PermissionHandler: no}},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: ln, RelayAddressGenerator: gen, PermissionHandler: no}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for srv.AllocationCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = srv.Close()
	})
	return pc.LocalAddr().String(), ln.Addr().String(), srv.AllocationCount
}

// A dial that fails BEHIND an accepted allocation gives that allocation back —
// and over UDP it ASKS the relay too, as a close does: confirmed, the failure is
// the plain one and the allocation is gone when the dial returns; not answered,
// the failure says so (an UnreleasedError, worded as the failure it wraps) for
// the lease to hear. Over TCP nothing is asked.
func TestADialThatFailsBehindItsAllocationAsksTheRelayOverUDP(t *testing.T) {
	old := DeallocateConfirmBudget
	DeallocateConfirmBudget = 150 * time.Millisecond
	t.Cleanup(func() { DeallocateConfirmBudget = old })
	creds := func(addr string) TURNCredentials {
		return TURNCredentials{Username: "u", Password: "pw", Address: addr}
	}

	t.Run("udp: the relay confirms", func(t *testing.T) {
		udp, _, allocations := refusingTURN(t)
		accepted := false
		_, err := DialRelay(creds(udp), loopbackPeer(t), "udp", logging.LogLevelError, func() { accepted = true })
		if err == nil || !accepted {
			t.Fatalf("fixture: the dial returned %v with the allocation accepted: %v — want a permission refused behind an accepted allocation", err, accepted)
		}
		var left *UnreleasedError
		if errors.As(err, &left) {
			t.Fatalf("a release the relay confirmed was called unconfirmed (%s)", left.Deallocate.Why())
		}
		if n := allocations(); n != 0 {
			t.Fatalf("%d allocation(s) at the relay when the failed dial returned, want 0 — its release was not waited for", n)
		}
	})
	t.Run("udp: the relay does not answer the deallocate", func(t *testing.T) {
		udp, _, _ := refusingTURN(t)
		plain := ""
		if _, err := DialRelay(creds(udp), loopbackPeer(t), "udp", logging.LogLevelError, nil); err != nil {
			plain = err.Error()
		}
		tap := newUDPTap(t, udp)
		tap.deafAfter.Store(3) // the challenge, the allocation, the permission's refusal — and no more
		_, err := DialRelay(creds(tap.front.LocalAddr().String()), loopbackPeer(t), "udp", logging.LogLevelError, nil)
		var left *UnreleasedError
		if !errors.As(err, &left) || left.Deallocate != DeallocateUnanswered || !left.Deallocate.OutOfReach() {
			t.Fatalf("the dial failed with %T (%v), want an UnreleasedError whose deallocate was not answered", err, err)
		}
		if err.Error() != plain || plain == "" {
			t.Fatalf("the unreleased failure reads %q, the plain one %q — the pool reads a failed dial by its text", err.Error(), plain)
		}
		if !errors.Is(err, left.Err) || errors.Unwrap(left.Err) == nil {
			t.Fatalf("the unreleased failure does not unwrap to the dial's own failure and its cause — whoever asks what the socket said is answered by the label")
		}
	})
	t.Run("tcp: nothing is asked", func(t *testing.T) {
		_, tcp, _ := refusingTURN(t)
		_, err := DialRelay(creds(tcp), loopbackPeer(t), "tcp", logging.LogLevelError, nil)
		var left *UnreleasedError
		if err == nil || errors.As(err, &left) {
			t.Fatalf("a TCP dial that failed behind its allocation returned %v (unreleased: %v) — want the plain failure", err, left != nil)
		}
	})
}

// The worker hands an unreleased failure's word to its lease — behind Failed and
// BEFORE the release; a plain failure says nothing.
func TestAWorkerTellsItsLeaseOfAnAllocationLeftBehindAFailedDial(t *testing.T) {
	failure := errors.New("turn create permission: refused")
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"unreleased", &UnreleasedError{Err: failure, Deallocate: DeallocateUnanswered},
			[]string{"allocated", "failed: turn create permission: refused", "out of reach: its deallocate was not answered", "released"}},
		{"plain", failure, []string{"allocated", "failed: turn create permission: refused", "released"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newFakeServer(t)
			prev := dialRelay
			var dials atomic.Int32
			dialRelay = func(_ TURNCredentials, _ *net.UDPAddr, _ string, _ logging.LogLevel, allocated func()) (*Relay, error) {
				if allocated != nil {
					allocated()
				}
				if dials.Add(1) == 1 {
					return nil, c.err // the first dial fails behind its allocation
				}
				uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					return nil, err
				}
				return &Relay{Conn: uc, Local: uc.LocalAddr(), close: func() { uc.Close() }}, nil
			}
			t.Cleanup(func() { dialRelay = prev })
			var mu sync.Mutex
			var events []string
			leases := 0
			creds := func(context.Context, int) (Credential, error) {
				mu.Lock()
				leases++
				first := leases == 1
				mu.Unlock()
				note := func(s string) {
					if first {
						mu.Lock()
						events = append(events, s)
						mu.Unlock()
					}
				}
				return Credential{
					TURNCredentials: TURNCredentials{Username: "u", Password: "p", Address: "127.0.0.1:1"},
					Allocated:       func(time.Time) { note("allocated") },
					Failed:          func(err error, _ time.Time) { note("failed: " + err.Error()) },
					OutOfReach:      func(why string) { note("out of reach: " + why) },
					Release:         func() { note("released") },
				}, nil
			}
			c2 := dialReady(t, testConfig(srv, 1, creds))
			defer c2.Close()
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(events, c.want) {
				t.Fatalf("the first lease heard %v, want %v", events, c.want)
			}
		})
	}
}
