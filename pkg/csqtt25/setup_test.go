package csqtt25

import (
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
