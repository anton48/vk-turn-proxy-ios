package proxy

import (
	"context"
	mathrand "math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Build 422 — the post-wake probe (wakeprobe.go). The thresholds in the rule's
// tests are LITERALS on purpose: a test that derives them from the constants
// stays green when a constant is halved.

func TestWakeProbeStepIsFactsAndListening(t *testing.T) {
	const ms = time.Millisecond
	t.Run("any pong of the probe's own pings answers it — the first one's too, not only the last", func(t *testing.T) {
		for _, pong := range []uint64{46, 47, 50} {
			s := wakeProbeState{first: 46, resends: 3}
			if v := s.step(100*ms, pong); v != wakeProbeEchoed {
				t.Errorf("pong %d against a probe whose first ping was 46: verdict %d, want echoed", pong, v)
			}
		}
	})
	t.Run("a mark below the probe's first ping answers nothing", func(t *testing.T) {
		s := wakeProbeState{first: 46}
		if v := s.step(100*ms, 45); v != wakeProbeWait {
			t.Errorf("pong 45 against first 46: verdict %d, want wait", v)
		}
	})
	t.Run("asked again after one second of listening", func(t *testing.T) {
		s := wakeProbeState{first: 1}
		for i := 1; i <= 9; i++ {
			if v := s.step(100*ms, 0); v != wakeProbeWait {
				t.Fatalf("step %d (%.1f s listened): verdict %d, want wait", i, s.listened.Seconds(), v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeResend {
			t.Fatalf("at 1.0 s of listening: verdict %d, want a re-send", v)
		}
		if s.resends != 1 || s.sinceSend != 0 {
			t.Errorf("after the re-send: resends %d sinceSend %s, want 1 and 0", s.resends, s.sinceSend)
		}
	})
	t.Run("a frozen step is not listening, and is followed by a ping at once", func(t *testing.T) {
		s := wakeProbeState{first: 1, listened: 2 * time.Second, sinceSend: 400 * ms}
		if v := s.step(57*time.Second, 0); v != wakeProbeResend {
			t.Fatalf("a 57-s step: verdict %d, want a re-send", v)
		}
		if s.listened != 2*time.Second {
			t.Errorf("listened %s after a frozen step, want it unchanged at 2s — the process could not hear", s.listened)
		}
		if s.freezes != 1 || s.sinceSend != 0 {
			t.Errorf("freezes %d sinceSend %s, want 1 and 0", s.freezes, s.sinceSend)
		}
	})
	t.Run("the verdict takes thirty seconds of LISTENING — not one step sooner", func(t *testing.T) {
		s := wakeProbeState{first: 1}
		for i := 1; i <= 299; i++ {
			if v := s.step(100*ms, 0); v == wakeProbeDead || v == wakeProbeEchoed {
				t.Fatalf("step %d (%.1f s listened): verdict %d before thirty seconds", i, s.listened.Seconds(), v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeDead {
			t.Fatalf("at 30.0 s of listening with nothing heard: verdict %d, want dead", v)
		}
		if s.resends != 29 {
			t.Errorf("asked again %d times in thirty seconds, want 29 (once a second)", s.resends)
		}
	})
	t.Run("the last look: an answer that is in when the verdict is due wins", func(t *testing.T) {
		s := wakeProbeState{first: 7, listened: 29900 * ms, sinceSend: 900 * ms}
		if v := s.step(100*ms, 7); v != wakeProbeEchoed {
			t.Errorf("verdict %d, want echoed — the mark is read before the verdict", v)
		}
	})
	t.Run("no verdict before the latest ping has had its second", func(t *testing.T) {
		// A thaw at 29.95 s of listening: asked again at once — and judged only a second later.
		s := wakeProbeState{first: 1, listened: 29950 * ms, sinceSend: 950 * ms}
		if v := s.step(90*time.Second, 0); v != wakeProbeResend {
			t.Fatalf("the frozen step: verdict %d, want a re-send", v)
		}
		for i := 1; i <= 9; i++ {
			if v := s.step(100*ms, 0); v != wakeProbeWait {
				t.Fatalf("%d00 ms after the thaw's ping: verdict %d, want wait", i, v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeDead {
			t.Errorf("a full second after the thaw's ping, thirty seconds listened: verdict %d, want dead", v)
		}
	})
}

// The night of 2026-09-19: the process runs about two seconds per wake and is
// frozen for minutes in between. The rule up to 421 — a wall-clock deadline —
// killed at the first thaw; this one counts only what it could hear.
func TestANightOfShortWakesKillsNobodyWhoCouldNotHear(t *testing.T) {
	const ms = time.Millisecond
	s := wakeProbeState{first: 1}
	var wall time.Duration
	wake := func(pongAtEnd uint64) wakeProbeVerdict {
		for i := 0; i < 20; i++ { // two seconds awake
			wall += 100 * ms
			if v := s.step(100*ms, 0); v == wakeProbeDead || v == wakeProbeEchoed {
				return v
			}
		}
		wall += 140 * time.Second // frozen
		return s.step(140*time.Second, pongAtEnd)
	}
	for n := 1; n <= 10; n++ {
		if v := wake(0); v != wakeProbeResend {
			t.Fatalf("wake %d (wall %s, listened %s): verdict %d at the thaw, want a re-send", n, wall, s.listened, v)
		}
	}
	if wall < 20*time.Minute {
		t.Fatalf("the fixture is wrong: wall %s", wall)
	}
	if s.listened != 20*time.Second {
		t.Errorf("listened %s over ten two-second wakes, want 20s", s.listened)
	}
	if v := wake(3); v != wakeProbeEchoed {
		t.Errorf("the pong of a later ping at last: verdict %d, want echoed", v)
	}
	// The control: a connection that never answers IS killed — after thirty seconds it could hear.
	s = wakeProbeState{first: 1}
	wakes := 0
	for {
		wakes++
		if v := wake(0); v == wakeProbeDead {
			break
		} else if v == wakeProbeEchoed || wakes > 40 {
			t.Fatalf("wake %d: verdict %d — a silent connection must end dead", wakes, v)
		}
	}
	if wakes != 15 || s.listened != 30*time.Second {
		t.Errorf("dead at wake %d with %s listened, want wake 15 and exactly 30s — fifteen two-second wakes", wakes, s.listened)
	}
}

func shrinkWakeProbe(t *testing.T) {
	t.Helper()
	w, r, po, f, a, c, j := wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt, wakeProbeClock, wakeProbeJitter
	wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt, wakeProbeJitter = 300*time.Millisecond, 30*time.Millisecond, 3*time.Millisecond, 10*time.Second, 50*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt, wakeProbeClock, wakeProbeJitter = w, r, po, f, a, c, j
	})
}

func probeProxy() *Proxy {
	return &Proxy{credPool: &credPool{}, lastPongSeq: make([]atomic.Uint64, 1), lastPingSeq: make([]atomic.Uint64, 1), lastActiveProbeAt: make([]atomic.Int64, 1),
		lastTxAt: make([]atomic.Int64, 1), lastRxAt: make([]atomic.Int64, 1), wakeCh: make(chan struct{})}
}

type sentPings struct {
	mu   sync.Mutex
	seqs []uint64
}

func (s *sentPings) add(seq uint64) { s.mu.Lock(); s.seqs = append(s.seqs, seq); s.mu.Unlock() }
func (s *sentPings) all() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.seqs...)
}

// 2026-09-20, both fatal wakes: the ping never left the phone. It is asked again.
func TestALostPingIsAskedAgain(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	var sent sentPings
	var seq uint64
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		if s >= 2 { // the first ping is lost on the way out; the far side answers from the second on
			go func() { time.Sleep(time.Millisecond); p.notePongSeq(0, s) }()
		}
		return nil
	})
	if err != nil || !alive {
		t.Fatalf("alive %v err %v — a connection whose first ping was lost must live (pings sent: %v)", alive, err, sent.all())
	}
	if got := sent.all(); len(got) < 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("pings sent %v, want 1 and then 2", got)
	}
}

// The pong of the probe's FIRST ping answers it, however many were sent after.
func TestAPongOfTheFirstPingAnswersAfterLaterPings(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	var sent sentPings
	var seq uint64
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		if s == 3 { // the pong of ping ONE arrives late — after two re-sends, none of which is ever answered
			go func() { time.Sleep(time.Millisecond); p.notePongSeq(0, 1) }()
		}
		return nil
	})
	if err != nil || !alive {
		t.Fatalf("alive %v err %v — pong 1 answers a probe whose first ping was 1 (pings sent: %v)", alive, err, sent.all())
	}
}

// 2026-09-20 16:03:57, the 22: the overdue tick's ping had just gone out and
// its pong came back in four milliseconds; the wake's second ping was lost.
func TestTheTicksPingIsTheProbesFirst(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	p.notePongSeq(0, 45)
	var sent sentPings
	seq := uint64(46)
	lastPingAt := time.Now().Add(-5 * time.Millisecond) // the tick's ping, a moment ago
	go func() { time.Sleep(4 * time.Millisecond); p.notePongSeq(0, 46) }()
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		return nil
	})
	if err != nil || !alive {
		t.Fatalf("alive %v err %v — the tick's pong answers the probe", alive, err)
	}
	if got := sent.all(); len(got) != 0 || seq != 46 {
		t.Errorf("the probe sent %v (seq now %d): nothing more goes into the thaw's burst when the tick has just pinged", got, seq)
	}
	// The control: a ping sent long ago is not adopted — the probe sends its own, and the old pong answers nothing.
	p = probeProxy()
	p.notePongSeq(0, 46)
	sent = sentPings{}
	seq = 46
	lastPingAt = time.Now().Add(-2 * time.Second)
	alive, err = p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		return nil
	})
	if err != nil || alive {
		t.Fatalf("alive %v err %v — pong 46 does not answer a probe whose first ping is 47", alive, err)
	}
	if got := sent.all(); len(got) == 0 || got[0] != 47 {
		t.Errorf("pings sent %v, want the probe's own, starting at 47", got)
	}
}

// 2026-09-19 §213: the process running, thirty seconds listened, nothing heard — killed, as before.
func TestARealNoEchoIsStillKilled(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	var sent sentPings
	var seq uint64
	var lastPingAt time.Time
	t0 := time.Now()
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		return nil
	})
	if err != nil || alive {
		t.Fatalf("alive %v err %v — nothing ever answered", alive, err)
	}
	if el := time.Since(t0); el < 300*time.Millisecond {
		t.Errorf("killed after %s, before the window (300ms here) had been listened through", el)
	}
	if n := len(sent.all()); n < 5 {
		t.Errorf("%d pings in the window, want the probe asked again and again", n)
	}
}

// A freeze inside the wait: the wall clock leaps ninety seconds — far past any
// deadline — and the connection lives, asked again at the thaw.
func TestAFreezeInsideTheWaitIsNotListening(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeFreezeStep = 5 * time.Second
	var leap atomic.Int64
	wakeProbeClock = func() time.Time { return time.Now().Add(time.Duration(leap.Load())) }
	p := probeProxy()
	var sent sentPings
	var seq uint64
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		sent.add(s)
		switch s {
		case 1: // the process freezes a moment AFTER its first ping has been written — inside a poll step, not inside the write
			go func() { time.Sleep(5 * time.Millisecond); leap.Store(int64(90 * time.Second)) }()
		case 2:
			go func() { time.Sleep(time.Millisecond); p.notePongSeq(0, 2) }() // the thaw's ping is answered
		}
		return nil
	})
	if err != nil || !alive {
		t.Fatalf("alive %v err %v — ninety frozen seconds are not thirty seconds of listening (pings: %v)", alive, err, sent.all())
	}
	if got := sent.all(); len(got) != 2 {
		t.Errorf("pings sent %v, want exactly two: the first, and one at the thaw", got)
	}
}

// fakeProbeClock: every reading moves it on by tick — one poll step — and a
// test's send moves it further: a write that takes time.
type fakeProbeClock struct {
	mu   sync.Mutex
	t    time.Time
	tick time.Duration
}

func (c *fakeProbeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.tick)
	return c.t
}

func (c *fakeProbeClock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// The review of 422: the step's clock was restarted BEFORE the ping was
// written, so the time the write took was counted as the ping's listening — a
// slow write left the latest ping less than its second.
func TestTheTimeAWriteTakesIsNotThePingsListening(t *testing.T) {
	shrinkWakeProbe(t) // the window 300 ms, a re-send after 30 ms of listening
	clk := &fakeProbeClock{t: time.Unix(1_700_000_000, 0), tick: 10 * time.Millisecond}
	wakeProbeClock = clk.now
	const write = 20 * time.Millisecond
	type span struct{ start, end time.Time }
	var writes []span
	p := probeProxy()
	var seq uint64
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(_ uint64, now time.Time) error {
		writes = append(writes, span{now, clk.add(write)}) // the write takes 20 ms
		return nil
	})
	if err != nil || alive {
		t.Fatalf("alive %v err %v — nothing ever answered", alive, err)
	}
	for k := 1; k < len(writes); k++ {
		if got := writes[k].start.Sub(writes[k-1].end); got < 30*time.Millisecond {
			t.Errorf("ping %d had %s between the end of its write and the next ping, want its full 30ms of listening — the time a write takes is not listening", k, got)
		}
	}
	verdictAt := clk.add(0)
	if listened := verdictAt.Sub(writes[0].end) - time.Duration(len(writes)-1)*write; listened < 300*time.Millisecond {
		t.Errorf("dead after %s outside the writes (%d pings), want the whole 300ms window listened", listened, len(writes))
	}
	if !lastPingAt.Equal(writes[len(writes)-1].end) && lastPingAt.Before(writes[len(writes)-1].end) {
		t.Errorf("lastPingAt %s lies before the end of the last write %s — a ping is sent when its write is over", lastPingAt.Format("05.000"), writes[len(writes)-1].end.Format("05.000"))
	}
}

// …and a write slower than a freeze step was taken for a FREEZE: nothing was
// ever listened, the probe asked again at once, and an unanswered probe never
// reached its verdict.
func TestWritesSlowerThanAFreezeStepStillEndInAVerdict(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeFreezeStep = 50 * time.Millisecond
	clk := &fakeProbeClock{t: time.Unix(1_700_000_000, 0), tick: 10 * time.Millisecond}
	wakeProbeClock = clk.now
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sends := 0
	p := probeProxy()
	var seq uint64
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(ctx, 0, 0, "", &seq, &lastPingAt, func(uint64, time.Time) error {
		sends++
		clk.add(120 * time.Millisecond) // every write takes longer than a freeze step
		if sends > 100 {
			cancel() // the guard: on 422 the loop never ends by itself
		}
		return nil
	})
	if err != nil {
		t.Fatalf("after %d pings the probe had reached no verdict (%v): a slow write was taken for a freeze, so nothing was ever listened", sends, err)
	}
	if alive {
		t.Fatalf("alive — nothing ever answered")
	}
	if sends > 15 {
		t.Errorf("%d pings for a 300-ms window asked again every 30 ms, want about ten", sends)
	}
}

// Build 424. The wake used to be an EDGE — a channel closed and replaced — and a
// goroutine that was in its tick branch at that instant never saw it.
func TestAWakeBroadcastDuringATickBranchIsNotLost(t *testing.T) {
	p := probeProxy()
	w := p.newWakeWatch()
	if w.pending() {
		t.Fatal("a fresh watch has nothing pending")
	}
	// The goroutine is in its tick branch — not parked in its select — when the wake is broadcast…
	p.broadcastWake()
	// …and then comes round to the top of its loop:
	ch := p.wakeChannel()
	select {
	case <-ch:
		t.Fatal("the fixture is wrong: the channel read AFTER the broadcast is the new, open one")
	default: // the channel alone has lost this wake
	}
	if !w.pending() {
		t.Fatal("the wake broadcast during the tick branch is lost: nothing pending at the top of the loop")
	}
	alive, probed, err := w.serve(context.Background(), 0, 0, "", new(uint64), new(time.Time), nil) // the server does not echo: no probe is due
	if err != nil || !alive || probed {
		t.Fatalf("alive %v probed %v err %v", alive, probed, err)
	}
	if w.pending() {
		t.Error("a wake that needed no probe is still pending — the loop would spin on it")
	}
	// A goroutine PARKED in its select is reached by the channel, as ever.
	ch = p.wakeChannel()
	go p.broadcastWake()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("a parked goroutine was not woken")
	}
	if !w.pending() {
		t.Error("…and the watch says so too")
	}
}

// Eight loops shaped like the probe goroutine's — a fast ticker with a busy
// tick branch — against three hundred broadcasts at random moments: every one
// of them must come to serve the LAST wake, wherever it was caught.
func TestNoWakeIsLostWhereverTheGoroutineIsCaught(t *testing.T) {
	for round := 0; round < 5; round++ {
		p := probeProxy()
		var final atomic.Uint64
		var wg sync.WaitGroup
		stop := make(chan struct{})
		var lost atomic.Int32
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w := p.newWakeWatch()
				tick := time.NewTicker(200 * time.Microsecond)
				defer tick.Stop()
				for {
					if f := final.Load(); f != 0 && w.served == f {
						return
					}
					ch := p.wakeChannel()
					if w.pending() {
						ch = closedWakeCh
					}
					select {
					case <-tick.C:
						time.Sleep(50 * time.Microsecond) // the tick branch: busy, away from the select
					case <-ch:
						w.served = p.wakeEpoch.Load()
					case <-stop:
						lost.Add(1)
						return
					}
				}
			}()
		}
		for i := 0; i < 300; i++ {
			time.Sleep(time.Duration(mathrand.Intn(300)) * time.Microsecond)
			p.broadcastWake()
		}
		final.Store(p.wakeEpoch.Load())
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			close(stop)
			<-done
		}
		if n := lost.Load(); n != 0 {
			t.Fatalf("round %d: %d of 8 loops never came to serve the last wake — it was broadcast while they were in their tick branch", round, n)
		}
	}
}

func TestServeProbesAndMarksWhatWokeThePhoneMeanwhile(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	p.serverProbeable.Store(true)
	w := p.newWakeWatch()
	p.broadcastWake()
	var seq uint64
	var lastPingAt time.Time
	alive, probed, err := w.serve(context.Background(), 0, 0, "", &seq, &lastPingAt, func(s uint64, _ time.Time) error {
		p.broadcastWake() // the phone sleeps and wakes again while the probe runs: the probe asks again at every thaw by itself
		go func() { time.Sleep(time.Millisecond); p.notePongSeq(0, s) }()
		return nil
	})
	if err != nil || !alive || !probed {
		t.Fatalf("alive %v probed %v err %v", alive, probed, err)
	}
	if w.pending() {
		t.Error("a wake broadcast while the probe ran is still pending: a second probe would follow the echo at once")
	}
	// Less than thirty seconds later the next wake needs no probe — and is served all the same.
	p.broadcastWake()
	if _, probed, _ = w.serve(context.Background(), 0, 0, "", &seq, &lastPingAt, nil); probed || w.pending() {
		t.Errorf("probed %v pending %v, want a throttled wake served without a probe", probed, w.pending())
	}
}

func TestTheEchosTimeCountsTheStepThatHeardIt(t *testing.T) {
	for _, c := range []struct{ listened, took, want time.Duration }{
		{0, 100 * time.Millisecond, 100 * time.Millisecond}, // an answer inside the first poll step: never "0s" — the old false echo's wording
		{2 * time.Second, 100 * time.Millisecond, 2100 * time.Millisecond},
		{2 * time.Second, 57 * time.Second, 2 * time.Second}, // heard right after a freeze: the frozen step is not listening
	} {
		if got := echoAfter(c.listened, c.took); got != c.want {
			t.Errorf("echoAfter(%s, %s) = %s, want %s", c.listened, c.took, got, c.want)
		}
	}
}

// N2: the previous session's mark answers nothing in the next one.
func TestAnOlderSessionsMarkAnswersNothing(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	p.notePongSeq(0, 40) // the session that died had been answered up to 40
	p.lastPingSeq[0].Store(41)
	p.resetProbeMarks(0) // a new session starts on this connection index
	if pong, ping := p.lastPongSeq[0].Load(), p.lastPingSeq[0].Load(); pong != 0 || ping != 0 {
		t.Fatalf("marks after the reset: pong %d ping %d, want 0 and 0", pong, ping)
	}
	var seq uint64 // the new session's pings start again from 1
	var lastPingAt time.Time
	alive, err := p.runWakeProbe(context.Background(), 0, 0, "", &seq, &lastPingAt, func(uint64, time.Time) error { return nil })
	if err != nil || alive {
		t.Errorf("alive %v err %v — nobody answered the new session; up to 421 the old mark did (\"echo received in 0s (sentSeq=1)\")", alive, err)
	}
}

func TestThePongMarkMovesForwardOnly(t *testing.T) {
	p := probeProxy()
	for _, c := range []struct{ in, want uint64 }{{5, 5}, {3, 5}, {5, 5}, {7, 7}, {6, 7}} {
		p.notePongSeq(0, c.in)
		if got := p.lastPongSeq[0].Load(); got != c.want {
			t.Errorf("after pong %d the mark reads %d, want %d", c.in, got, c.want)
		}
	}
	p.notePongSeq(3, 9) // out of range: ignored, no panic
	p.resetProbeMarks(3)
}

// The probe has ONE body. Both session kinds call it, keep no wait of their
// own, record pongs through the forward-only mark and reset the marks before
// their probe goroutine starts.
func TestBothSessionKindsRunTheOneWakeProbe(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return stripComments(string(b))
	}
	src := read("proxy.go")
	for what, want := range map[string]int{"wake.serve(": 2, "p.newWakeWatch()": 2, "if wake.pending() {": 2, "p.notePongSeq(": 2, "p.resetProbeMarks(": 2, "time.NewTicker(probeInterval)": 2} {
		if got := strings.Count(src, what); got != want {
			t.Errorf("proxy.go holds %d × %q, want %d — one per session kind", got, what, want)
		}
	}
	for _, gone := range []string{"lastPongSeq[connIdx].Store(", ">= sentSeq", "probeStart", "sentSeq :=", "lastActiveProbeAt[connIdx]", "p.runWakeProbe("} {
		if strings.Contains(src, gone) {
			t.Errorf("proxy.go still holds %q — a session kind keeps a probe wait or a mark write of its own", gone)
		}
	}
	// Each probe goroutine starts AFTER its session's marks were reset.
	rest := src
	for k := 1; k <= 2; k++ {
		tick := strings.Index(rest, "time.NewTicker(probeInterval)")
		if tick < 0 {
			t.Fatalf("probe goroutine %d not found", k)
		}
		// the nearest "session established" line before this ticker
		before := rest[:tick]
		est := strings.LastIndex(before, "+TURN session established\", connIdx, credSlot)")
		if est < 0 || !strings.Contains(before[est:], "p.resetProbeMarks(connIdx)") {
			t.Errorf("probe goroutine %d: no p.resetProbeMarks(connIdx) between its session's \"established\" line and its ticker", k)
		}
		rest = rest[tick+len("time.NewTicker(probeInterval)"):]
	}
	// The tick's ping is stamped when its write is OVER (the probe adopts a ping "sent" a moment ago).
	stamps := 0
	for at := 0; ; {
		k := strings.Index(src[at:], "lastPingAt = ")
		if k < 0 {
			break
		}
		k += at
		at = k + 1
		stamps++
		line := src[k:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if strings.TrimSpace(strings.TrimPrefix(line, "lastPingAt = ")) == "now" {
			t.Errorf("proxy.go: %q — the tick's ping is stamped with the time taken BEFORE its write", line)
		}
		if w, n := strings.LastIndex(src[:k], ".Write(pingPkt)"), strings.LastIndex(src[:k], "now := time.Now()"); w < n {
			t.Errorf("proxy.go: %q does not follow the tick's Write", line)
		}
	}
	if stamps != 2 {
		t.Errorf("proxy.go stamps lastPingAt %d times, want 2 — once per session kind's tick", stamps)
	}
	// The wake is a level: each loop asks its watch right after it has read the channel, before its select…
	for at, k := 0, 0; ; k++ {
		i := strings.Index(src[at:], "wakeCh := p.wakeChannel()")
		if i < 0 {
			if k != 2 {
				t.Errorf("proxy.go reads the wake channel in %d probe loops, want 2", k)
			}
			break
		}
		i += at
		at = i + 1
		sel := strings.Index(src[i:], "select {")
		if sel < 0 || !strings.Contains(src[i:i+sel], "if wake.pending() {") || !strings.Contains(src[i:i+sel], "wakeCh = closedWakeCh") {
			t.Errorf("probe loop %d: the watch is not asked between reading the wake channel and the select — a wake broadcast during the tick branch is lost", k+1)
		}
	}
	// …and the epoch is bumped BEFORE the channel is swapped, under the same lock.
	if b := strings.Index(src, "func (p *Proxy) broadcastWake() {"); b < 0 {
		t.Error("broadcastWake not found")
	} else {
		fn := src[b : b+strings.Index(src[b:], "\n}\n")]
		lock, add, cl, unlock := strings.Index(fn, "p.wakeMu.Lock()"), strings.Index(fn, "p.wakeEpoch.Add(1)"), strings.Index(fn, "close(p.wakeCh)"), strings.Index(fn, "p.wakeMu.Unlock()")
		if !(lock >= 0 && lock < add && add < cl && cl < unlock) {
			t.Errorf("broadcastWake: want Lock, wakeEpoch.Add(1), close, …, Unlock in that order — got offsets %d %d %d %d", lock, add, cl, unlock)
		}
	}
	body := read("wakeprobe.go")
	i := strings.Index(body, "func (p *Proxy) runWakeProbe(")
	j := strings.Index(body, "func wakeProbeDetail(")
	if i < 0 || j < i {
		t.Fatal("runWakeProbe not found in wakeprobe.go")
	}
	for _, wall := range []string{".Before(", "Add(wakeProbeWindow)", "time.After(wakeProbeWindow)", "WithTimeout(", "WithDeadline("} {
		if strings.Contains(body[i:j], wall) {
			t.Errorf("runWakeProbe holds %q — its wait is LISTENING counted step by step, never a wall-clock deadline", wall)
		}
	}
	if n := strings.Count(body, ".Store("); n != 3 {
		t.Errorf("wakeprobe.go stores %d times, want 3: the two marks' reset and the probe's stamp — the pong mark is otherwise moved by CompareAndSwap alone", n)
	}
}
