package proxy

import (
	"context"
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
	w, r, po, f, a, c := wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt, wakeProbeClock
	wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt = 300*time.Millisecond, 30*time.Millisecond, 3*time.Millisecond, 10*time.Second, 50*time.Millisecond
	t.Cleanup(func() {
		wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeAdopt, wakeProbeClock = w, r, po, f, a, c
	})
}

func probeProxy() *Proxy {
	return &Proxy{credPool: &credPool{}, lastPongSeq: make([]atomic.Uint64, 1), lastPingSeq: make([]atomic.Uint64, 1), lastActiveProbeAt: make([]atomic.Int64, 1)}
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
		case 1:
			leap.Store(int64(90 * time.Second)) // the process freezes right after its first ping
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
	for what, want := range map[string]int{"p.runWakeProbe(": 2, "p.notePongSeq(": 2, "p.resetProbeMarks(": 2, "time.NewTicker(probeInterval)": 2} {
		if got := strings.Count(src, what); got != want {
			t.Errorf("proxy.go holds %d × %q, want %d — one per session kind", got, what, want)
		}
	}
	for _, gone := range []string{"lastPongSeq[connIdx].Store(", ">= sentSeq", "probeStart", "sentSeq :="} {
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
