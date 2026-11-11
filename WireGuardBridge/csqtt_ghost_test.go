package main

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// The sleep watch: a gap between two looks at the wall clock of a lifetime and
// a step is a sleep no allocation survived; it speaks only for an allocation
// made BEFORE it ended; and a question is a look itself — right behind a thaw
// the ticker may not have fired yet.
func TestCsqttSleepWatchKnowsASleepLongerThanAnAllocationLives(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	limit := (csqttGhostHold + csqttSleepStep).Seconds() // 605 s

	t.Run("awake: looks a step apart", func(t *testing.T) {
		var w csqttSleepWatch
		for s := 0.0; s <= 3600; s += csqttSleepStep.Seconds() {
			w.look(at(s))
		}
		if w.outlived(at(0), at(3601)) {
			t.Fatal("an hour of looks a step apart read as a sleep longer than an allocation lives")
		}
	})
	t.Run("a sleep just short of the limit is none", func(t *testing.T) {
		var w csqttSleepWatch
		w.look(at(0))
		w.look(at(limit - 1))
		if w.outlived(at(0), at(limit)) {
			t.Fatalf("a gap of %.0fs read as a sleep no allocation survived (the limit is %.0fs)", limit-1, limit)
		}
	})
	t.Run("a sleep of the limit is one", func(t *testing.T) {
		var w csqttSleepWatch
		w.look(at(0))
		w.look(at(limit))
		if !w.outlived(at(0), at(limit+1)) {
			t.Fatalf("a gap of %.0fs was not read as a sleep no allocation survived", limit)
		}
	})
	t.Run("it judges only what was there before it", func(t *testing.T) {
		var w csqttSleepWatch
		for s := 0.0; s <= 100; s += 5 {
			w.look(at(s))
		}
		w.look(at(800)) // the gap 100 → 800: the sleep lies somewhere inside it
		if !w.outlived(at(50), at(805)) {
			t.Fatal("the sleep was not held against an allocation made before it")
		}
		if w.outlived(at(801), at(805)) {
			t.Fatal("a sleep that was over before the allocation was made was held against it")
		}
		// Made inside the gap: before the sleep or behind the thaw — the watch
		// cannot tell, and must not call it expired.
		if w.outlived(at(103), at(805)) || w.outlived(at(799), at(805)) {
			t.Fatal("an allocation made inside the gap was called expired — it may have been made behind the thaw")
		}
	})
	t.Run("the question is a look", func(t *testing.T) {
		var w csqttSleepWatch
		w.look(at(0))
		if !w.outlived(at(0), at(700)) { // no tick between: the question itself sees the gap
			t.Fatal("asked right behind a long sleep, before any tick, the watch saw none")
		}
	})
	t.Run("no watch, no sleep", func(t *testing.T) {
		var w *csqttSleepWatch
		if w.outlived(at(0), at(10000)) {
			t.Fatal("a nil watch claimed a sleep")
		}
	})
}

// ghostPool records what the rule asks of the pool.
type ghostPool struct {
	calls []string
	until time.Time
	why   string
}

func (g *ghostPool) Release(int, string, string) { g.calls = append(g.calls, "release") }
func (g *ghostPool) ReleaseHeld(_ int, _ string, _ string, until time.Time, why string) {
	g.calls, g.until, g.why = append(g.calls, "held"), until, why
}

// The rule itself: a seat out of reach is held one allocation lifetime from
// now, with the reason passed on — unless the process slept a lifetime through
// since the allocation was made: then it has expired and the seat is free.
func TestCsqttASeatOutOfReachIsHeldALifetimeUnlessTheProcessSleptOneThrough(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)

	var awake csqttSleepWatch
	awake.look(now.Add(-2 * time.Second))
	g := &ghostPool{}
	csqttReleaseOutOfReach[string](g, &awake, 7, 3, "creds", "relay", now.Add(-200*time.Second), now, csqttGhostHold, "its deallocate was answered 437")
	if !reflect.DeepEqual(g.calls, []string{"held"}) || !g.until.Equal(now.Add(csqttGhostHold)) || g.why != "its deallocate was answered 437" {
		t.Fatalf("awake: the pool was asked %v until +%v (%q), want held until +%v with the reason", g.calls, g.until.Sub(now), g.why, csqttGhostHold)
	}

	var slept csqttSleepWatch
	slept.look(now.Add(-700 * time.Second)) // …and nothing since: the process slept 700 s
	g = &ghostPool{}
	csqttReleaseOutOfReach[string](g, &slept, 7, 3, "creds", "relay", now.Add(-900*time.Second), now, csqttGhostHold, "its deallocate was not answered")
	if !reflect.DeepEqual(g.calls, []string{"release"}) {
		t.Fatalf("slept a lifetime through: the pool was asked %v, want a plain release — the allocation has expired", g.calls)
	}

	// The same sleep, an allocation made behind it: held.
	g = &ghostPool{}
	csqttReleaseOutOfReach[string](g, &slept, 7, 3, "creds", "relay", now.Add(-time.Second), now, csqttGhostHold, "its deallocate was not answered")
	if !reflect.DeepEqual(g.calls, []string{"held"}) {
		t.Fatalf("an allocation made behind the sleep: the pool was asked %v, want held", g.calls)
	}
}

// Through the real pool: a lease whose allocation is out of reach keeps its
// seat counted for the hold — longer than the relay's second — the next worker
// parks that long; one never allocated goes back at once even if called out of
// reach; and one whose allocation the process slept through goes back at once.
func TestCsqttLeaseOutOfReachKeepsItsSeatForTheHold(t *testing.T) {
	const hold = 2500 * time.Millisecond // above the relay's second (1.2 s): the two cannot be confused
	fetch := func(_ bool, slot int) (string, *proxy.TURNCreds, error) {
		addr := "198.51.100.7:3478"
		return addr, &proxy.TURNCreds{Username: freshUsername("ghost"), Password: "p", Address: addr, Addresses: []string{addr}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := proxy.NewCredPool(ctx, proxy.CredPoolConfig{VKLink: "abc", NumConns: 10, Fetch: fetch})
	defer pool.Close()
	var skew atomic.Int64 // how far this adapter's wall clock runs ahead: a sleep
	a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { t.Errorf("fatal: %v", err) }, sleep: &csqttSleepWatch{}, hold: hold,
		clock: func() time.Time { return time.Now().Round(0).Add(time.Duration(skew.Load())) }}
	prevBackstop := csqttAcquireBackstop
	csqttAcquireBackstop, csqttAcquireBackstopMax = time.Hour, time.Hour
	defer func() { csqttAcquireBackstop, csqttAcquireBackstopMax = prevBackstop, 5*time.Second }()
	var leases []csqtt.Credential
	for k := 1; k <= 10; k++ {
		c, err := a.creds(ctx, k)
		if err != nil {
			t.Fatalf("lease %d: %v", k, err)
		}
		leases = append(leases, c)
	}
	seated := func(worker int) <-chan error {
		done := make(chan error, 1)
		go func() { _, err := a.creds(ctx, worker); done <- err }()
		time.Sleep(100 * time.Millisecond) // parked
		return done
	}
	waited := func(what string, done <-chan error, since time.Time, limit time.Duration) time.Duration {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			return time.Since(since)
		case <-time.After(limit):
			t.Fatalf("%s: the parked worker was not seated within %v", what, limit)
			return 0
		}
	}

	// Never allocated: nothing to hold, whatever it is called.
	done := seated(11)
	leases[0].OutOfReach("its deallocate was not answered")
	t0 := time.Now()
	leases[0].Release()
	if took := waited("a lease that held no allocation", done, t0, 3*time.Second); took > 700*time.Millisecond {
		t.Errorf("a lease that held no allocation kept its seat %v", took.Round(time.Millisecond))
	}

	// Allocated and out of reach: held for the hold, not for the relay's second.
	leases[1].Allocated(time.Now())
	done = seated(12)
	leases[1].OutOfReach("its deallocate was answered 437")
	t0 = time.Now()
	leases[1].Release()
	if took := waited("a lease out of reach", done, t0, 8*time.Second); took < 2400*time.Millisecond {
		t.Errorf("a lease whose allocation is out of reach gave its seat back after %v, want the hold (%v) — the relay's second is not enough", took.Round(time.Millisecond), hold)
	}

	// Allocated, out of reach, and slept through: expired — free at once.
	leases[2].Allocated(time.Now())
	a.sleep.look(a.wallNow()) // the last look before the sleep: the allocation is there by then
	done = seated(13)
	skew.Store(int64(csqttGhostHold + csqttSleepStep + time.Second)) // the process slept a lifetime and more
	leases[2].OutOfReach("its deallocate was answered 437")
	t0 = time.Now()
	leases[2].Release()
	if took := waited("a lease slept through", done, t0, 3*time.Second); took > 700*time.Millisecond {
		t.Errorf("a lease whose allocation expired in a sleep kept its seat %v", took.Round(time.Millisecond))
	}

	// An allocation made BEHIND that sleep is not judged by it: held. (The
	// adapter's clock is put back in step with the pool's, which never slept:
	// the hold's moment is read by the pool's own clock.)
	skew.Store(0)
	leases[3].Allocated(time.Now())
	done = seated(14)
	leases[3].OutOfReach("its deallocate was not answered")
	t0 = time.Now()
	leases[3].Release()
	if took := waited("a lease made behind the sleep", done, t0, 8*time.Second); took < 2400*time.Millisecond {
		t.Errorf("a lease whose allocation was made behind the sleep gave its seat back after %v, want the hold (%v)", took.Round(time.Millisecond), hold)
	}
}

// The watch looks at the clock BY ITSELF, step by step, until its context ends:
// without those looks a long awake stretch between two questions would read as
// a sleep and a live ghost's seat would be given away.
func TestCsqttSleepWatchLooksAtTheClockByItself(t *testing.T) {
	var w csqttSleepWatch
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.run(ctx, 10*time.Millisecond); close(done) }()
	seen := map[int64]bool{}
	deadline := time.Now().Add(2 * time.Second)
	for len(seen) < 4 && time.Now().Before(deadline) {
		if v := w.last.Load(); v != 0 {
			seen[v] = true
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(seen) < 4 {
		t.Fatalf("the running watch took %d look(s) at the clock in two seconds, want one every 10ms", len(seen))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watch did not stop with its context")
	}
}

// Where the adapter is made it gets a watch, and the watch is run under the
// tunnel's context — a scan: the start itself needs a whole tunnel.
func TestTheCsqttAdapterIsMadeWithARunningSleepWatch(t *testing.T) {
	src, err := os.ReadFile("csqtt_bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"adapter := &csqttPoolAdapter{pool: pool, fatal: e.fail, sleep: &csqttSleepWatch{}}",
		"go adapter.sleep.run(ctx, csqttSleepStep)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("csqtt_bridge.go lacks %q", want)
		}
	}
}

// The 2.5 close asks the relay IN FRONT of the relayed conn's own close, behind
// the write budget, and sets the budget anew behind the wait — csqtt's close,
// step for step.
func TestCsqtt25CloseAsksTheRelayBeforeItClosesTheAllocation(t *testing.T) {
	var order []string
	ctl := &closeRecorder{name: "ctl", order: &order}
	relayed := &closeRecorder{name: "relayed", order: &order}
	csqtt25CloseRelay(ctl, relayed, func() { order = append(order, "client") }, func() { order = append(order, "ask") })
	want := []string{"ctl deadline", "ask", "ctl deadline", "relayed close", "client", "ctl close"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("the close ran %v, want %v", order, want)
	}
}

// ghostTap stands between one client socket and the relay and can stop passing
// the relay's answers down — a relay this side no longer hears.
type ghostTap struct {
	front, back *net.UDPConn
	deaf        atomic.Bool
	deafAfter   atomic.Int32 // > 0: pass this many answers down, then no more
	down        atomic.Int32
	mu          sync.Mutex
	client      *net.UDPAddr
}

func newGhostTap(t *testing.T, relay string) *ghostTap {
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
	p := &ghostTap{front: front, back: back}
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

func ghostPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr)
}

// The 2.5 relay on the real stack: over UDP its close asks and the relay
// confirms — the word is on the relay and on the conn the engine holds; a relay
// this side no longer hears is out of reach after the confirm's budget; over
// TCP nothing is asked.
func TestCsqtt25RelayAsksTheRelayAboutItsDeallocateOverUDPOnly(t *testing.T) {
	word := func(conn net.PacketConn) (csqtt.Deallocate, bool) {
		d, ok := conn.(interface {
			deallocated() (csqtt.Deallocate, bool)
		})
		if !ok {
			t.Fatal("the conn handed to the engine does not carry the relay's word on its deallocate")
		}
		return d.deallocated()
	}
	creds := func(addr string) csqtt.TURNCredentials {
		return csqtt.TURNCredentials{Username: "u", Password: "pw", Address: addr}
	}
	t.Run("udp: confirmed", func(t *testing.T) {
		r, err := csqtt25DialRelay(context.Background(), creds(relayTURN(t, "udp")), ghostPeer(t), "udp", nil)
		if err != nil {
			t.Fatal(err)
		}
		conn := r.packetConn()
		if _, asked := word(conn); asked {
			t.Fatal("the relay's word is there before the close asked for it")
		}
		r.Close()
		if v, asked := word(conn); !asked || v != csqtt.DeallocateConfirmed {
			t.Fatalf("the close over UDP: asked %v, verdict %d — want the relay's confirmation", asked, v)
		}
	})
	t.Run("udp: a relay that does not answer", func(t *testing.T) {
		old := csqtt.DeallocateConfirmBudget
		csqtt.DeallocateConfirmBudget = 150 * time.Millisecond
		t.Cleanup(func() { csqtt.DeallocateConfirmBudget = old })
		tap := newGhostTap(t, relayTURN(t, "udp"))
		r, err := csqtt25DialRelay(context.Background(), creds(tap.front.LocalAddr().String()), ghostPeer(t), "udp", nil)
		if err != nil {
			t.Fatal(err)
		}
		tap.deaf.Store(true)
		t0 := time.Now()
		r.Close()
		took := time.Since(t0)
		if v, asked := r.deallocated(); !asked || v != csqtt.DeallocateUnanswered || !v.OutOfReach() {
			t.Fatalf("asked %v, verdict %d — want unanswered, out of reach", asked, v)
		}
		if took < 150*time.Millisecond || took > 450*time.Millisecond {
			t.Fatalf("the close took %v, want the confirm's 150ms budget — not the write deadline's 600ms", took.Round(time.Millisecond))
		}
	})
	t.Run("tcp: nothing asked", func(t *testing.T) {
		r, err := csqtt25DialRelay(context.Background(), creds(relayTURN(t, "tcp")), ghostPeer(t), "tcp", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		if v, asked := r.deallocated(); asked {
			t.Fatalf("a TCP relay's close asked the relay about its deallocate (verdict %d)", v)
		}
	})
}

// A dial that is ENDED behind an accepted allocation gives it back without
// asking for the relay's word: an ended dial waits for no answer — on a path
// that is gone none would come, and the confirm's budget is half a second.
func TestCsqtt25DialRelayEndedBehindAnAllocationWaitsForNoAnswer(t *testing.T) {
	tap := newGhostTap(t, relayTURN(t, "udp"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ended time.Time
	_, err := csqtt25DialRelay(ctx, csqtt.TURNCredentials{Username: "u", Password: "pw", Address: tap.front.LocalAddr().String()}, ghostPeer(t), "udp", func() {
		tap.deaf.Store(true) // the path is gone the moment the relay has accepted
		ended = time.Now()
		cancel()
	})
	if err == nil {
		t.Fatal("an ended dial returned a relay")
	}
	// …and it SAYS that the allocation it gave back was not confirmed released:
	// the deallocate left through a path that is gone, the relay may hold the
	// allocation on, and the lease has to hear it.
	var left *csqtt.UnreleasedError
	if !errors.As(err, &left) || left.Deallocate != csqtt.DeallocateNotAwaited || !left.Deallocate.OutOfReach() {
		t.Fatalf("the ended dial failed with %T, want an UnreleasedError whose deallocate's answer was not waited for", err)
	}
	if took := time.Since(ended); took > 300*time.Millisecond {
		t.Fatalf("the ended dial returned %v behind its end: it waited for the relay's word on the deallocate (budget %v)", took.Round(time.Millisecond), csqtt.DeallocateConfirmBudget)
	}
}

// wordConn is a relay conn as the 2.5 closer sees it: its close leaves a word.
type wordConn struct {
	net.PacketConn
	v     csqtt.Deallocate
	asked bool
}

func (w *wordConn) deallocated() (csqtt.Deallocate, bool) { return w.v, w.asked }

// The 2.5 closer hands the relay's word to the lease behind the relay's close
// and BEFORE the lease's release — and only a word that says out of reach.
func TestCsqtt25CloserTellsTheLeaseOfAnAllocationOutOfReachBeforeItsRelease(t *testing.T) {
	cases := []struct {
		name  string
		v     csqtt.Deallocate
		asked bool
		want  []string
	}{
		{"answered 437", csqtt.DeallocateGone, true, []string{"closed", "out of reach: its deallocate was answered 437", "released"}},
		{"not answered", csqtt.DeallocateUnanswered, true, []string{"closed", "out of reach: its deallocate was not answered", "released"}},
		{"confirmed", csqtt.DeallocateConfirmed, true, []string{"closed", "released"}},
		{"refused", csqtt.DeallocateRefused, true, []string{"closed", "released"}},
		{"nothing asked", csqtt.Deallocate(-1), false, []string{"closed", "released"}}, // what deallocated() says before any ask
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var events []string
			prev := csqtt25OpenRelay
			csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
				return &wordConn{v: c.v, asked: c.asked}, func() { events = append(events, "closed") }, nil
			}
			t.Cleanup(func() { csqtt25OpenRelay = prev })
			lease := func(context.Context, int) (csqtt.Credential, error) {
				return csqtt.Credential{
					Allocated:  func(time.Time) {},
					Failed:     func(error, time.Time) {},
					Release:    func() { events = append(events, "released") },
					OutOfReach: func(why string) { events = append(events, "out of reach: "+why) },
				}, nil
			}
			server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
			_, _, closer, err := (&csqtt25Client{}).dialer(server, "udp", lease)(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			closer()
			if !reflect.DeepEqual(events, c.want) {
				t.Fatalf("the closer did %v, want %v", events, c.want)
			}
		})
	}
}

// A 2.5 dial that fails BEHIND its allocation — the permission refused — asks
// the relay as a close does: confirmed, the failure is the plain one; not
// answered, it says so; and a permission wait that was ENDED waits for no
// answer and says that its release was not confirmed.
func TestCsqtt25DialRelayThatFailsBehindItsAllocationSaysWhatBecameOfIt(t *testing.T) {
	old := csqtt.DeallocateConfirmBudget
	csqtt.DeallocateConfirmBudget = 150 * time.Millisecond
	t.Cleanup(func() { csqtt.DeallocateConfirmBudget = old })
	creds := func(addr string) csqtt.TURNCredentials {
		return csqtt.TURNCredentials{Username: "u", Password: "pw", Address: addr}
	}
	t.Run("the relay confirms", func(t *testing.T) {
		relay := newPermissionRefusingRelay(t, 0)
		accepted := false
		_, err := csqtt25DialRelay(context.Background(), creds(relay.addr), ghostPeer(t), "udp", func() { accepted = true })
		var left *csqtt.UnreleasedError
		if err == nil || !accepted || errors.As(err, &left) {
			t.Fatalf("the dial returned %v (accepted %v, unreleased %v) — want the plain failure behind an accepted allocation", err, accepted, left != nil)
		}
	})
	t.Run("the relay does not answer the deallocate", func(t *testing.T) {
		relay := newPermissionRefusingRelay(t, 0)
		tap := newGhostTap(t, relay.addr)
		tap.deafAfter.Store(3) // the challenge, the allocation, the permission's refusal — and no more
		_, err := csqtt25DialRelay(context.Background(), creds(tap.front.LocalAddr().String()), ghostPeer(t), "udp", nil)
		var left *csqtt.UnreleasedError
		if !errors.As(err, &left) || left.Deallocate != csqtt.DeallocateUnanswered {
			t.Fatalf("the dial failed with %T, want an UnreleasedError whose deallocate was not answered", err)
		}
	})
	t.Run("tcp: an ended dial is the plain failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := csqtt25DialRelay(ctx, creds(relayTURN(t, "tcp")), ghostPeer(t), "tcp", func() { cancel() })
		var left *csqtt.UnreleasedError
		if err == nil || errors.As(err, &left) {
			t.Fatalf("a TCP dial ended behind its allocation returned %v (unreleased: %v) — over TCP the connection's close frees the allocation", err, left != nil)
		}
	})
	t.Run("a permission wait that is ended", func(t *testing.T) {
		tap := newGhostTap(t, relayTURN(t, "udp"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var ended time.Time
		_, err := csqtt25DialRelay(ctx, creds(tap.front.LocalAddr().String()), ghostPeer(t), "udp", func() {
			tap.deaf.Store(true) // accepted — and nothing more is heard: the permission's answer never comes
			time.AfterFunc(100*time.Millisecond, func() { ended = time.Now(); cancel() })
		})
		took := time.Since(ended)
		var left *csqtt.UnreleasedError
		if !errors.As(err, &left) || left.Deallocate != csqtt.DeallocateNotAwaited {
			t.Fatalf("the ended dial failed with %T, want an UnreleasedError whose deallocate's answer was not waited for", err)
		}
		if took > 300*time.Millisecond {
			t.Fatalf("the ended dial returned %v behind its end: it waited for the relay", took.Round(time.Millisecond))
		}
	})
}

// The 2.5 dialer hands a failed dial's word on its allocation to the lease —
// behind Failed and BEFORE the release, and for an ENDED dial too (which tells
// the lease of no failure).
func TestCsqtt25DialerTellsTheLeaseOfAnAllocationLeftBehindAFailedDial(t *testing.T) {
	failure := errors.New("turn create permission: refused")
	unreleased := &csqtt.UnreleasedError{Err: failure, Deallocate: csqtt.DeallocateNotAwaited}
	cases := []struct {
		name  string
		err   error
		ended bool
		want  []string
	}{
		{"unreleased", unreleased, false, []string{"failed", "out of reach: its deallocate's answer was not waited for", "released"}},
		{"unreleased, the dial ended", unreleased, true, []string{"out of reach: its deallocate's answer was not waited for", "released"}},
		{"plain", failure, false, []string{"failed", "released"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var events []string
			prev := csqtt25OpenRelay
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
				if c.ended {
					cancel()
				}
				return nil, nil, c.err
			}
			t.Cleanup(func() { csqtt25OpenRelay = prev })
			lease := func(context.Context, int) (csqtt.Credential, error) {
				return csqtt.Credential{
					Allocated:  func(time.Time) {},
					Failed:     func(error, time.Time) { events = append(events, "failed") },
					Release:    func() { events = append(events, "released") },
					OutOfReach: func(why string) { events = append(events, "out of reach: "+why) },
				}, nil
			}
			server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
			if _, _, _, err := (&csqtt25Client{}).dialer(server, "udp", lease)(ctx, 1); err == nil {
				t.Fatal("the failed dial returned a stream")
			}
			if !reflect.DeepEqual(events, c.want) {
				t.Fatalf("the lease heard %v, want %v", events, c.want)
			}
		})
	}
}

// Through the real dial and a real pool: a dial ENDED behind an accepted
// allocation, its deallocate's answer never heard — the seat stays counted for
// the hold, not for the relay's second (the review of the ghost rule: the pool
// handed that seat out again 1.2 s later, with a hold of three seconds set).
func TestCsqtt25AnEndedDialBehindItsAllocationKeepsItsSeatForTheHold(t *testing.T) {
	const hold = 2500 * time.Millisecond
	tap := newGhostTap(t, relayTURN(t, "udp"))
	addr := tap.front.LocalAddr().String()
	fetch := func(bool, int) (string, *proxy.TURNCreds, error) {
		return addr, &proxy.TURNCreds{Username: "u", Password: "pw", Address: addr, Addresses: []string{addr}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := proxy.NewCredPool(ctx, proxy.CredPoolConfig{VKLink: "abc", NumConns: 10, Fetch: fetch})
	defer pool.Close()
	a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { t.Errorf("fatal: %v", err) }, sleep: &csqttSleepWatch{}, hold: hold}
	for k := 1; k <= 9; k++ { // nine seats of the identity are out
		if _, err := a.creds(ctx, k); err != nil {
			t.Fatalf("lease %d: %v", k, err)
		}
	}
	// The tenth goes through the dial — which is ended the moment the relay has
	// accepted its allocation, on a path that passes nothing back any more.
	dctx, end := context.WithCancel(ctx)
	defer end()
	lease := func(cctx context.Context, workerID int) (csqtt.Credential, error) {
		c, err := a.creds(cctx, workerID)
		if err != nil {
			return c, err
		}
		allocated := c.Allocated
		c.Allocated = func(began time.Time) {
			allocated(began)
			tap.deaf.Store(true)
			end()
		}
		return c, nil
	}
	if _, _, _, err := (&csqtt25Client{}).dialer(ghostPeer(t), "udp", lease)(dctx, 10); err == nil {
		t.Fatal("the ended dial returned a stream")
	}
	// The pool is asked for that identity's seat again, over and over (asked
	// directly: what is under test is WHEN the pool lets the seat go, not how a
	// parked worker is woken).
	released := time.Now()
	for {
		_, _, _, err := pool.Acquire(9)
		took := time.Since(released)
		if err == nil {
			if took < 2400*time.Millisecond {
				t.Fatalf("the seat of an allocation left behind an ended dial was handed out again after %v, want the hold (%v) — the relay may still hold that allocation", took.Round(10*time.Millisecond), hold)
			}
			return
		}
		if took > 8*time.Second {
			t.Fatal("the held seat was never let go")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
