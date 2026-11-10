package csqtt

import (
	"sync/atomic"
	"testing"
	"time"
)

// shortHold shortens the pause behind a restart notice for a test.
func shortHold(t *testing.T, d time.Duration) {
	t.Helper()
	prev := panelRestartHold
	panelRestartHold = d
	t.Cleanup(func() { panelRestartHold = prev })
}

// workerAsks counts the GETCONFs the server has seen from a worker.
func workerAsks(srv *fakeServer, worker string) int {
	n := 0
	for _, g := range srv.seen() {
		if g.worker == worker {
			n++
		}
	}
	return n
}

// The server says it is restarting and goes on answering until it is gone
// (three quarters of a second on the real one). A worker that asks for its
// configuration inside that moment is taken back by the server that is
// about to go and forgotten with it: ready here, unknown to the server that
// came back, until a REPAIR or the liveness rule finds it half a minute
// later. So nobody asks while the old server can still answer.
func TestNobodyAsksTheServerThatSaidItIsRestarting(t *testing.T) {
	shortHold(t, 400*time.Millisecond)
	srv := newFakeServer(t)
	srv.mu.Lock()
	srv.strict = true // the loop is already reading
	srv.mu.Unlock()
	loopbackRelay(t, nil)
	l := &lease{}
	c := dialReady(t, testConfig(srv, 3, l.creds))
	defer c.Close()

	before, _, _ := srv.counts()
	srv.sayTo(PanelRestartNotice) // …and it goes on answering
	time.Sleep(150 * time.Millisecond)
	inItsLastMoments, _, _ := srv.counts()
	srv.forget() // the server that came back knows none of the three
	went := time.Now()
	if n := inItsLastMoments - before; n != 0 {
		t.Errorf("%d GETCONF(s) reached the server in the 150 ms behind its restart notice: those streams go with it", n)
	}
	for {
		k := srv.knows("1", "2", "3")
		if k["1"] && k["2"] && k["3"] && c.Stats().Ready == 3 {
			break
		}
		if time.Since(went) > 2*time.Second {
			t.Fatalf("%v after the old server went: ready here %d of 3, known to the server that came back: %v, %v, %v",
				time.Since(went).Round(10*time.Millisecond), c.Stats().Ready, k["1"], k["2"], k["3"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A kick that lands while a worker waits the hold out — a path change, the
// notice said again — is older than the allocation that follows: the worker
// dials once. Left in its buffer through the wait it would end the fresh
// session at its first look, an allocation spent for nothing.
func TestAKickDuringTheHoldIsOlderThanTheAllocation(t *testing.T) {
	shortHold(t, 300*time.Millisecond)
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	l := &lease{}
	c := dialReady(t, testConfig(srv, 3, l.creds))
	defer c.Close()
	srv.sayTo(PanelRestartNotice)
	waitFor(t, "every worker out of its session", func() bool { return c.Stats().Ready == 0 })
	time.Sleep(50 * time.Millisecond) // one worker is inside the hold, the others behind the gate
	c.OnPathChange()                  // kicks all three
	waitFor(t, "three workers ready again", func() bool { return c.Stats().Ready == 3 })
	time.Sleep(100 * time.Millisecond)
	if dials, _ := l.get(); dials != 6 || c.Stats().Ready != 3 {
		t.Fatalf("%d dials for three workers and one restart, want 6 (ready %d): a kick outlived the hold", dials, c.Stats().Ready)
	}
}

// A stop does not wait the hold out, and a worker that leaves the hold on a
// stop gives the start gate back — the others stand behind it.
func TestAStopDoesNotWaitOutTheHold(t *testing.T) {
	shortHold(t, 5*time.Second)
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	l := &lease{}
	c := dialReady(t, testConfig(srv, 3, l.creds))
	srv.sayTo(PanelRestartNotice)
	waitFor(t, "every worker out of its session", func() bool { return c.Stats().Ready == 0 })
	time.Sleep(50 * time.Millisecond) // one of them is inside the hold, the others behind the gate
	done := make(chan struct{})
	began := time.Now()
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("Close did not return in 4 s")
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("Close took %v with the workers inside the hold behind a restart notice", took.Round(10*time.Millisecond))
	}
}

// The notice may come down the very stream that is still waiting for its
// configuration — the only stream there is while the first worker dials,
// every stream when all of them start over together. It is the same notice:
// every worker starts over, the ready ones that did not hear it too.
func TestARestartNoticeInAConfigurationWaitIsHeard(t *testing.T) {
	shortHold(t, 50*time.Millisecond)
	prev := getconfSchedule
	getconfSchedule = []time.Duration{3 * time.Second}
	t.Cleanup(func() { getconfSchedule = prev })
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	l := &lease{}
	c := dialReady(t, testConfig(srv, 2, l.creds))
	defer c.Close()

	srv.withholdTUNCONF("2", 1)
	c.workers[1].restart("the test")
	waitFor(t, "worker 2 waiting for a configuration", func() bool { return workerAsks(srv, "2") == 2 && c.Stats().Ready == 1 })
	one, two := workerAsks(srv, "1"), workerAsks(srv, "2")
	said := time.Now()
	srv.sayTo(PanelRestartNotice, "2") // heard by nobody but the worker in its wait
	for workerAsks(srv, "1") == one || workerAsks(srv, "2") == two {
		if time.Since(said) > time.Second {
			t.Fatalf("a second after the notice: worker 1 asked again: %v, worker 2 asked again: %v — the notice was passed over in the wait",
				workerAsks(srv, "1") > one, workerAsks(srv, "2") > two)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "both workers ready again", func() bool { return c.Stats().Ready == 2 })
}

// The fixture's own promise: dialReady hands a client over only when every
// worker has heard the answer to its READY. Returned earlier, the last
// READY_OK is still in the read loop and answers the next round a test asks
// of deafened workers.
func TestDialReadyWaitsForTheLastAnswer(t *testing.T) {
	hold := make(chan struct{})
	var seen atomic.Int32
	hook := func(w *worker) {
		if w.id == 2 && seen.Add(1) == 2 { // worker 2's second inbound: its READY_OK
			<-hold
		}
	}
	readLoopStamped.Store(&hook)
	t.Cleanup(func() { readLoopStamped.Store(nil) })
	srv := newFakeServer(t)
	loopbackRelay(t, nil)
	cfg := testConfig(srv, 2, (&lease{}).creds)
	back := make(chan *Client, 1)
	go func() { back <- dialReady(t, cfg) }()
	select {
	case c := <-back:
		close(hold)
		c.Close()
		t.Fatal("dialReady returned while worker 2's READY_OK was still inside its read loop")
	case <-time.After(300 * time.Millisecond):
	}
	close(hold)
	select {
	case c := <-back:
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("dialReady did not return once the READY_OK was heard")
	}
}
