package csqtt25

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// longBackOff makes a failure's wait long enough to tell «at once» from it.
func longBackOff(t *testing.T) {
	t.Helper()
	oldBase, oldMax := backoffBase, backoffMax
	backoffBase, backoffMax = 3*time.Second, 3*time.Second
	t.Cleanup(func() { backoffBase, backoffMax = oldBase, oldMax })
}

func oneIdentity(t *testing.T, what string, ids map[int]string, workers int) (gen uint64, salt string) {
	t.Helper()
	if len(ids) != workers {
		t.Fatalf("%s: %d worker(s) asked, want %d", what, len(ids), workers)
	}
	first := ids[1]
	for id, v := range ids {
		if v != first {
			t.Fatalf("%s: worker %d asked under another identity than worker 1", what, id)
		}
	}
	f := strings.SplitN(first, "|", 2)
	gen, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil || len(f) != 2 || f[1] == "" {
		t.Fatalf("%s: an identity the server cannot read", what)
	}
	return gen, f[1]
}

// The network under the streams changed: every worker starts over at once —
// an asked restart waits for nothing — and all of them under ONE new
// identity, a later generation and another salt, so that the server drops
// the sessions of the path that is gone with the first one that registers.
func TestAPathChangeStartsEveryWorkerOverUnderANewIdentity(t *testing.T) {
	quickClocks(t)
	longBackOff(t)
	srv := newFakeServer(t, "pw-path-1")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	gen0, salt0 := oneIdentity(t, "before the change", srv.identities(), 3)

	c.OnPathChange()
	t0 := time.Now()
	eventually(t, "every worker dialling again", func() bool { return d.count(1) == 2 && d.count(2) == 2 && d.count(3) == 2 })
	if took := time.Since(t0); took > time.Second {
		t.Fatalf("the workers dialled again %v after the path change: an asked restart waits for nothing (a failure waits %v)", took.Round(time.Millisecond), backoffBase)
	}
	eventually(t, "three workers ready again", func() bool { return c.Stats().Ready == 3 })
	eventually(t, "every worker asking under the new identity", func() bool {
		for _, v := range srv.identities() {
			if strings.HasSuffix(v, "|"+salt0) {
				return false
			}
		}
		return true
	})
	gen1, salt1 := oneIdentity(t, "after the change", srv.identities(), 3)
	if gen1 <= gen0 || salt1 == salt0 {
		t.Fatalf("the identity after a path change: generation moved %d → %d (want later), the salt changed: %v", gen0, gen1, salt1 != salt0)
	}
	if st := c.Stats(); st.PathChanges != 1 {
		t.Fatalf("path changes counted: %d, want 1", st.PathChanges)
	}
	time.Sleep(200 * time.Millisecond)
	if d.count(1) != 2 || d.count(2) != 2 || d.count(3) != 2 {
		t.Fatalf("one path change restarted the workers %d, %d and %d times, want once each", d.count(1)-1, d.count(2)-1, d.count(3)-1)
	}
}

// A worker that is waiting out a failure when the path changes does not sit
// the rest of its wait out: the wait was earned on the path that is gone.
func TestAPathChangeEndsAWaitBetweenSessions(t *testing.T) {
	quickClocks(t)
	longBackOff(t)
	srv := newFakeServer(t, "pw-path-2")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	srv.repair(1, 1, 2) // worker 2's session ends on the server's word; a failure's wait follows
	eventually(t, "worker 2 between sessions", func() bool { return c.Stats().Ready == 2 })
	time.Sleep(100 * time.Millisecond)
	if d.begun(2) != 1 {
		t.Fatalf("fixture: worker 2 dialled again inside its wait")
	}
	c.OnPathChange()
	t0 := time.Now()
	eventually(t, "worker 2 dialling again", func() bool { return d.count(2) == 2 })
	if took := time.Since(t0); took > time.Second {
		t.Fatalf("worker 2 dialled again %v after the path change: it sat its wait (%v) out", took.Round(time.Millisecond), backoffBase)
	}
}

// A notice of the server's that is still waiting for a worker in its set-up
// must not turn the path change into a failure: the path change takes its
// place, and the worker starts over at once.
//
// The dial here is one the path change cannot end — it comes back with its
// stream all the same, as a dial does that had its answer the moment it was
// told (a dial that CAN be ended returns the path change by itself and never
// looks at the notice: setup_test.go). Then the notice is all the session has
// to go by, in its configuration wait, and it has to be the path change.
func TestAPathChangeOutranksAnOlderNoticeStillPending(t *testing.T) {
	quickClocks(t)
	longBackOff(t)
	srv := newFakeServer(t, "pw-path-3")
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}, deaf: true}
	release := make(chan struct{})
	var once sync.Once
	let := func() { once.Do(func() { close(release) }) }
	d.setHold(func(id, nth int) <-chan struct{} {
		if id == 2 && nth == 1 {
			return release
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: 2, Keys: KeysWrap, Dial: d.dial})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(c.Close)
	// Registered behind Close, so it runs BEFORE it: a test that fails with the
	// dial still held must let the worker go first, or Close gives up on it and
	// the worker outlives the test — into the next one's clocks.
	t.Cleanup(let)
	eventually(t, "worker 2 inside its first dial", func() bool { return d.begun(2) == 1 })
	// The server can say the notice only down a stream it knows as ready, and
	// worker 1's READY is still on its way when Dial returns.
	eventually(t, "the server seeing worker 1 ready", func() bool { return srv.knowsReady(1) })
	srv.say(1, panelRestartNotice) // the older notice: it waits for worker 2
	eventually(t, "the restart notice acted on", func() bool { return c.Stats().PanelRestarts == 1 })
	c.OnPathChange()
	let()
	t0 := time.Now()
	eventually(t, "worker 2 dialling again", func() bool { return d.begun(2) == 2 })
	if took := time.Since(t0); took > time.Second {
		t.Fatalf("worker 2 dialled again %v after its dial came back: the older notice made the path change a failure (it waits %v)", took.Round(time.Millisecond), backoffBase)
	}
}

// Live is the ready streams heard from lately, not the ready ones: a stream
// stays ready on a socket that carries nothing until something replaces it.
func TestLiveCountsTheReadyStreamsHeardFromLately(t *testing.T) {
	quickClocks(t)
	old := liveWindow
	liveWindow = 150 * time.Millisecond
	t.Cleanup(func() { liveWindow = old })
	srv := newFakeServer(t, "pw-live")
	c, _, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	eventually(t, "three ready, nobody heard from lately", func() bool { st := c.Stats(); return st.Ready == 3 && st.Live == 0 })
	srv.say(2, IdleKeepalive)
	eventually(t, "three ready, one heard from", func() bool { st := c.Stats(); return st.Ready == 3 && st.Live == 1 })
	eventually(t, "three ready, nobody heard from lately again", func() bool { st := c.Stats(); return st.Ready == 3 && st.Live == 0 })
}

// The server takes a pair as newer by its generation: two path changes inside
// one tick of the clock — or a clock that stepped back — must still move it
// forward.
func TestTheGenerationOnlyMovesForward(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-path-gen")
	c, _, _ := startClient(t, srv, 1, KeysWrap)
	prev, _ := c.identity()
	for i := 1; i <= 200; i++ {
		c.OnPathChange()
		gen, _ := c.identity()
		if gen <= prev {
			t.Fatalf("path change %d left the generation at %d after %d: the server would not take the pair as newer", i, gen, prev)
		}
		prev = gen
	}
}

// A notice that came while a worker was PARKED above the agreed count is
// older than the session it begins when the count rises: that session must
// not end on it. (A notice during a wait between sessions is taken there;
// the look at a session's start is what covers a worker that was not
// waiting.)
func TestANoticeThatCameWhileAWorkerWasParkedDoesNotEndItsFirstSession(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-parked")
	srv.set(func() { srv.limit = 2 })
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "two of three ready, the third parked", func() bool { return c.Stats().Ready == 2 && c.Stats().Target == 2 })
	if d.begun(3) != 0 {
		t.Fatalf("fixture: the parked worker dialled")
	}
	srv.set(func() { srv.limit = 3 }) // the next TUNCONF agrees to three
	srv.say(1, panelRestartNotice)    // every worker is told, the parked one too
	eventually(t, "three ready", func() bool { return c.Stats().Ready == 3 })
	time.Sleep(300 * time.Millisecond)
	if n := d.begun(3); n != 1 {
		t.Fatalf("the worker that was parked dialled %d times: its first session ended on a notice older than itself", n)
	}
}
