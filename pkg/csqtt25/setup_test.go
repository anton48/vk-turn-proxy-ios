package csqtt25

import (
	"sync"
	"testing"
	"time"
)

// 🚨 A path change does not wait for a set-up begun on the path that is gone.
// A worker that stands in its DIAL when the path changes again — a relay that
// will not answer there — is ended at once and dials anew; and that is an
// ended dial, not a failed one: no failure wait stands in front of the next.
func TestAPathChangeEndsADialUnderWayAtOnce(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 3*time.Second, 3*time.Second // a FAILED dial would wait this long
	srv := newFakeServer(t, "pw-setup-dial")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })

	never := make(chan struct{}) // each worker's second dial is never let through
	t.Cleanup(func() { close(never) })
	d.setHold(func(_, nth int) <-chan struct{} {
		if nth == 2 {
			return never
		}
		return nil
	})
	c.OnPathChange() // every worker dials again — and stands in its dial
	eventually(t, "both second dials begun", func() bool { return d.begun(1) >= 2 && d.begun(2) >= 2 })

	began := time.Now()
	c.OnPathChange() // the path changes again under those dials
	eventually(t, "both streams ready again behind the second path change, their held dials never let through", func() bool {
		return c.Stats().Ready == 2 && d.begun(1) >= 3 && d.begun(2) >= 3
	})
	if took := time.Since(began); took > time.Second {
		t.Fatalf("ready again %s after the path changed under the dials — want at once: an ended dial is not a failed one (the failure wait is %s)", took.Round(10*time.Millisecond), backoffBase)
	}
	if st := c.Stats(); st.PathChanges != 2 {
		t.Fatalf("path changes %d, want 2", st.PathChanges)
	}
}

// 🚨 The same of a worker in its HANDSHAKE: it is ended at once — not left to
// run to its bound — and an ended handshake is not a failed one: it does not
// fall back to the password's keys on a socket of the path that is gone.
func TestAPathChangeEndsAHandshakeUnderWayAtOnce(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 3*time.Second, 3*time.Second
	srv := newFakeServer(t, "pw-setup-handshake") // it answers no handshake: every one runs to its bound
	c, d, _ := startClient(t, srv, 2, KeysAuto)
	eventually(t, "both streams ready on the password's keys", func() bool { return c.Stats().Ready == 2 })
	handshakeTimeout = 4 * time.Second // from here a handshake nobody answers lasts this long

	c.OnPathChange()
	eventually(t, "both workers dialled again and stand in their handshakes", func() bool { return d.count(1) >= 2 && d.count(2) >= 2 })
	fallbacks := c.Stats().Fallbacks

	began := time.Now()
	c.OnPathChange()
	eventually(t, "both workers dialled anew behind the second path change", func() bool { return d.count(1) >= 3 && d.count(2) >= 3 })
	if took := time.Since(began); took > time.Second {
		t.Fatalf("dialled anew %s after the path changed under the handshakes (their bound is %s) — want at once", took.Round(10*time.Millisecond), handshakeTimeout)
	}
	if got := c.Stats().Fallbacks; got != fallbacks {
		t.Fatalf("an ended handshake fell back to the password's keys: fallbacks %d, were %d", got, fallbacks)
	}
}

// Only an ENDED set-up is free of the failure wait. A dial that fails by
// itself — the relay said no — is a failure like before, path change or not:
// the next dial waits.
func TestADialThatFailsByItselfStillWaits(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 500*time.Millisecond, 500*time.Millisecond
	srv := newFakeServer(t, "pw-setup-failed")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })
	d.mu.Lock()
	d.refuse = map[int]int{2: 1}
	d.mu.Unlock()
	c.OnPathChange() // both dial again; worker 2's dial is refused
	eventually(t, "worker 2's refused dial", func() bool { return d.begun(2) >= 2 })
	refused := time.Now()
	eventually(t, "worker 2 dialling again", func() bool { return d.begun(2) >= 3 })
	if waited := time.Since(refused); waited < 400*time.Millisecond {
		t.Fatalf("worker 2 dialled again %s after a dial that failed by itself, want the failure wait (%s)", waited.Round(10*time.Millisecond), backoffBase)
	}
	eventually(t, "both streams ready again", func() bool { return c.Stats().Ready == 2 })
}

// An ended dial is not a failure in the run's count either. The path change
// that ends a dial would end a failure's wait as well, so the wait right
// behind it does not tell the two apart — the wait behind the NEXT failure
// does: it is the first of its run, not one a failure before it had doubled.
func TestAnEndedDialDoesNotLengthenTheNextFailuresWait(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 500*time.Millisecond, 5*time.Second
	srv := newFakeServer(t, "pw-setup-count")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })

	never := make(chan struct{}) // worker 2's second dial is never let through
	t.Cleanup(func() { close(never) })
	d.setHold(func(id, nth int) <-chan struct{} {
		if id == 2 && nth == 2 {
			return never
		}
		return nil
	})
	c.OnPathChange() // worker 2 dials again — and stands in its dial
	eventually(t, "worker 2 in its second dial", func() bool { return d.begun(2) >= 2 })
	d.mu.Lock()
	d.refuse = map[int]int{2: 1} // the dial behind the ended one fails by itself
	d.mu.Unlock()
	c.OnPathChange() // ends the dial under way
	eventually(t, "worker 2's third dial, the refused one", func() bool { return d.begun(2) >= 3 })
	refused := time.Now()
	eventually(t, "worker 2's fourth dial", func() bool { return d.begun(2) >= 4 })
	if waited := time.Since(refused); waited > 850*time.Millisecond {
		t.Fatalf("worker 2 dialled again %v after its first failure, want the first wait of a run (%v): the ended dial was counted as a failure before it",
			waited.Round(10*time.Millisecond), backoffBase)
	}
	eventually(t, "both streams ready again", func() bool { return c.Stats().Ready == 2 })
}

// 🚨 Ending a set-up gives its socket back THEN. A handshake stands on a
// socket the dial has already returned, and its write can be parked in it —
// through a relay the first write asks for a permission of its own and waits
// for the answer. Nothing but the socket's close ends such a write (the DTLS
// side takes no write deadline), and the handshake waits for its writer: with
// the close left to the client's stop, the path change ended nothing — the
// worker stayed on the path that was gone.
func TestAPathChangeEndsAHandshakeWhoseWriteIsParked(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 3*time.Second, 3*time.Second
	srv := newFakeServer(t, "pw-setup-parked") // it answers no handshake
	c, d, _ := startClient(t, srv, 2, KeysAuto)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })
	handshakeTimeout = 4 * time.Second
	parked := func() (n int) {
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, g := range d.gates {
			if g.parked.Load() > 0 {
				n++
			}
		}
		return n
	}
	d.mu.Lock()
	d.gated, d.parkAt = true, true // the next sockets park their first write
	d.mu.Unlock()
	c.OnPathChange()
	eventually(t, "both handshakes parked in their first write", func() bool { return parked() == 2 })
	fallbacks := c.Stats().Fallbacks
	d.mu.Lock()
	d.parkAt = false
	d.mu.Unlock()

	began := time.Now()
	c.OnPathChange() // the path changes again under those handshakes
	eventually(t, "both workers dial anew", func() bool { return d.count(1) >= 3 && d.count(2) >= 3 })
	if took := time.Since(began); took > time.Second {
		t.Fatalf("the workers dialled anew %v after the path change, want at once", took.Round(10*time.Millisecond))
	}
	if got := c.Stats().Fallbacks; got != fallbacks {
		t.Fatalf("an ended handshake fell back to the password's keys: fallbacks %d, were %d", got, fallbacks)
	}
}

// A dial that comes back WITH its stream as the set-up is ended — it had its
// answer the moment it was told — is an ended set-up all the same: the stream
// is given back there, and nothing is asked on it. Not a failure either: the
// wait behind the next failure is the first of its run.
func TestADialThatComesBackAsItsSetUpEndsIsEndedNotFailed(t *testing.T) {
	quickClocks(t)
	backoffBase, backoffMax = 500*time.Millisecond, 5*time.Second
	srv := newFakeServer(t, "pw-setup-late")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })

	release := make(chan struct{})
	var once sync.Once
	let := func() { once.Do(func() { close(release) }) }
	t.Cleanup(let)
	d.mu.Lock()
	d.deaf = true // a held dial does not hear its context
	d.mu.Unlock()
	d.setHold(func(id, nth int) <-chan struct{} {
		if id == 2 && nth == 2 {
			return release
		}
		return nil
	})
	c.OnPathChange()
	eventually(t, "worker 2 in its second dial", func() bool { return d.begun(2) >= 2 })
	asks := func() int {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.getconfs[2]
	}
	asked := asks()
	d.mu.Lock()
	d.refuse = map[int]int{2: 1} // the dial behind it fails by itself
	d.mu.Unlock()
	c.OnPathChange() // ends the set-up; the dial does not hear it
	let()            // …and comes back with its stream
	eventually(t, "worker 2's third dial, the refused one", func() bool { return d.begun(2) >= 3 })
	refused := time.Now()
	if got := asks(); got != asked {
		t.Fatalf("the stream of an ended set-up asked for a configuration: %d request(s), were %d", got, asked)
	}
	eventually(t, "worker 2's fourth dial", func() bool { return d.begun(2) >= 4 })
	if waited := time.Since(refused); waited > 850*time.Millisecond {
		t.Fatalf("worker 2 dialled again %v after its first failure, want the first wait of a run (%v): the ended set-up was counted as a failure before it",
			waited.Round(10*time.Millisecond), backoffBase)
	}
}

// Once a stream has its keys its set-up is over, and ending it then ends
// nothing: the socket is the session's until the session's own end. A stream
// past its set-up goes by the path change's NOTICE — a socket closed under it
// beside the notice would make its end a failure whenever the close was seen
// first.
func TestEndingASetUpThatIsOverEndsNothing(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-setup-over")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "both streams ready", func() bool { return c.Stats().Ready == 2 })
	closes := func() int {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.closes
	}
	closed, begun := closes(), d.begun(1)+d.begun(2)
	for _, w := range c.workers {
		w.endSetup()
	}
	time.Sleep(200 * time.Millisecond)
	if got := closes(); got != closed {
		t.Fatalf("ending a set-up that was over closed %d socket(s) of ready streams", got-closed)
	}
	if got := d.begun(1) + d.begun(2); got != begun || c.Stats().Ready != 2 {
		t.Fatalf("ending a set-up that was over restarted streams: %d dial(s) more, ready %d", got-begun, c.Stats().Ready)
	}
}
