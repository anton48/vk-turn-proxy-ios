package csqtt25

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jumpClock is the serve clock with a hand to move it: jump(d) is what a
// suspension of the process for d looks like to a serve loop — the next tick
// comes d late. The streams' own sockets and the far side go on in real time.
type jumpClock struct{ ahead atomic.Int64 }

func (j *jumpClock) jump(d time.Duration) { j.ahead.Add(int64(d)) }

// useJumpClock must be called BEFORE the client is started: a watch takes its
// clock when its stream becomes ready, and the cleanup that puts the real
// clock back has to run after the client's own.
func useJumpClock(t *testing.T) *jumpClock {
	t.Helper()
	j := &jumpClock{}
	prev := serveNow
	serveNow = func() time.Time { return time.Now().Add(time.Duration(j.ahead.Load())).Round(0) }
	t.Cleanup(func() { serveNow = prev })
	return j
}

// wakeClocks shortens the window behind a boundary.
func wakeClocks(t *testing.T, deaf, ask, floor time.Duration) {
	t.Helper()
	old := []time.Duration{wakeDeafAfter, wakeAskEvery, wakeAnswerFloor}
	wakeDeafAfter, wakeAskEvery, wakeAnswerFloor = deaf, ask, floor
	t.Cleanup(func() { wakeDeafAfter, wakeAskEvery, wakeAnswerFloor = old[0], old[1], old[2] })
}

func (s *fakeServer) readyCount(worker int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readys[worker]
}

// 🚨 A suspension of the process is not silence. Ten frozen minutes — far
// past the sixty seconds that replace a silent stream — replace NOBODY: every
// stream is asked afresh at the thaw, answers, and stays.
func TestAFreezeReplacesNoStreamThatAnswers(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 20*time.Second, 60*time.Second
	wakeClocks(t, 400*time.Millisecond, 60*time.Millisecond, 10*time.Millisecond)
	clock := useJumpClock(t)
	srv := newFakeServer(t, "pw-freeze")
	c, d, _ := startClient(t, srv, 3, KeysWrap)
	eventually(t, "three workers ready", func() bool { return c.Stats().Ready == 3 })
	before := []int{srv.readyCount(1), srv.readyCount(2), srv.readyCount(3)}

	clock.jump(10 * time.Minute)

	eventually(t, "every stream asked afresh behind the freeze", func() bool {
		return srv.readyCount(1) > before[0] && srv.readyCount(2) > before[1] && srv.readyCount(3) > before[2]
	})
	time.Sleep(700 * time.Millisecond) // past the window and well past any verdict a clock would give
	st := c.Stats()
	if d.count(1) != 1 || d.count(2) != 1 || d.count(3) != 1 || st.Ready != 3 {
		t.Fatalf("behind a ten-minute freeze: dials %d, %d, %d and %d ready — want every stream kept (1, 1, 1 and 3 ready): the frozen minutes were read as silence",
			d.count(1), d.count(2), d.count(3), st.Ready)
	}
	if st.Freezes != 1 || st.WakeDeaf != 0 {
		t.Fatalf("freezes %d (want 1: one suspension, said once whatever the number of streams), silent behind it %d (want 0)", st.Freezes, st.WakeDeaf)
	}
}

// 🚨 Behind a freeze a stream that does NOT answer is replaced within the
// window — asked again and again in it — while the ordinary rule would have
// asked it after twenty seconds and kept it for sixty; the streams that
// answer stay.
func TestBehindAFreezeASilentStreamIsReplacedWithinTheWindow(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 20*time.Second, 60*time.Second
	wakeClocks(t, 300*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond)
	clock := useJumpClock(t)
	srv := newFakeServer(t, "pw-wake-deaf")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	srv.set(func() { srv.mute[2] = true })
	asked := srv.readyCount(2)

	clock.jump(10 * time.Minute)
	began := time.Now()

	eventually(t, "the silent stream replaced", func() bool { return d.count(2) >= 2 })
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("the silent stream was replaced %s behind the thaw; the window is 300 ms of listening", took)
	}
	if n := srv.readyCount(2) - asked; n < 3 {
		t.Fatalf("the silent stream was asked %d time(s) in its window, want it asked again and again (at least 3)", n)
	}
	if d.count(1) != 1 {
		t.Fatalf("the stream that answered was dialled %d times, want 1", d.count(1))
	}
	if st := c.Stats(); st.WakeDeaf != 1 {
		t.Fatalf("streams replaced for their silence behind the freeze: %d, want 1", st.WakeDeaf)
	}
}

// The caller's wake word asks every ready stream AT ONCE — not at the next
// tick — and a stream that stays silent behind it is replaced like one behind
// a freeze. It is not a path change: who answers stays.
func TestTheWakeWordAsksEveryReadyStreamAtOnce(t *testing.T) {
	quickClocks(t)
	serveTick = 3 * time.Second // nothing but the word can ask inside this test
	probeAfter, deafAfter = 20*time.Second, 60*time.Second
	srv := newFakeServer(t, "pw-wake")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	before := []int{srv.readyCount(1), srv.readyCount(2)}
	c.Wake()
	began := time.Now()
	eventually(t, "both streams asked behind the word", func() bool {
		return srv.readyCount(1) > before[0] && srv.readyCount(2) > before[1]
	})
	if took := time.Since(began); took > time.Second {
		t.Fatalf("the streams were asked %s behind the word — it waited for a tick", took)
	}
	if st := c.Stats(); st.Wakes != 1 || st.PathChanges != 0 || d.count(1) != 1 || d.count(2) != 1 {
		t.Fatalf("wakes %d, path changes %d, dials %d and %d; want 1, 0, 1 and 1", st.Wakes, st.PathChanges, d.count(1), d.count(2))
	}
}

func TestBehindTheWakeWordASilentStreamIsReplaced(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 20*time.Second, 60*time.Second
	wakeClocks(t, 300*time.Millisecond, 50*time.Millisecond, 10*time.Millisecond)
	srv := newFakeServer(t, "pw-wake-silent")
	c, d, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	srv.set(func() { srv.mute[2] = true })
	c.Wake()
	eventually(t, "the silent stream replaced behind the word", func() bool { return d.count(2) >= 2 })
	if st := c.Stats(); d.count(1) != 1 || st.WakeDeaf != 1 || st.Freezes != 0 {
		t.Fatalf("dials of the answering stream %d (want 1), silent behind the word %d (want 1), freezes %d (want 0)", d.count(1), st.WakeDeaf, st.Freezes)
	}
}

// Behind a freeze every ready stream is asked AT ONCE — at the tick that sees
// the freeze, not when the window's first second of listening is over: the
// answer is what tells a live stream from a dead one, and a phone picked up
// is waiting for it.
func TestBehindAFreezeEveryStreamIsAskedAtOnce(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 20*time.Second, 60*time.Second
	wakeClocks(t, 30*time.Second, 10*time.Second, 10*time.Millisecond) // the window's own asks are far away
	clock := useJumpClock(t)
	srv := newFakeServer(t, "pw-freeze-at-once")
	c, _, _ := startClient(t, srv, 2, KeysWrap)
	eventually(t, "two workers ready", func() bool { return c.Stats().Ready == 2 })
	before := []int{srv.readyCount(1), srv.readyCount(2)}
	clock.jump(10 * time.Minute)
	began := time.Now()
	eventually(t, "both streams asked behind the freeze", func() bool {
		return srv.readyCount(1) > before[0] && srv.readyCount(2) > before[1]
	})
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("the streams were asked %s behind the thaw — not at the tick that saw it", took)
	}
}

// handClock is the serve clock entirely in the test's hand: it stands still
// until moved, so a watch counts no listening the test did not give it.
// arm(step, during): the NEXT reading runs during and returns a time step
// later than the one before it. A serve loop's pass reads the clock BEHIND its
// look at the wake epoch and IN FRONT of whatever it does with the rule's
// answer — so during runs exactly between the two.
type handClock struct {
	mu     sync.Mutex
	at     time.Time
	armed  bool
	step   time.Duration
	during func()
	fired  chan struct{}
}

// useHandClock must be called before the client is started (see useJumpClock).
func useHandClock(t *testing.T) *handClock {
	t.Helper()
	h := &handClock{at: time.Unix(1_800_300_000, 0)}
	prev := serveNow
	serveNow = h.now
	t.Cleanup(func() { serveNow = prev })
	return h
}

func (h *handClock) now() time.Time {
	h.mu.Lock()
	var during func()
	var fired chan struct{}
	if h.armed {
		h.armed = false
		h.at = h.at.Add(h.step)
		during, fired = h.during, h.fired
	}
	at := h.at
	h.mu.Unlock()
	if during != nil {
		during()
	}
	if fired != nil {
		close(fired)
	}
	return at
}

func (h *handClock) arm(t *testing.T, step time.Duration, during func()) {
	t.Helper()
	h.mu.Lock()
	fired := make(chan struct{})
	h.armed, h.step, h.during, h.fired = true, step, during, fired
	h.mu.Unlock()
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("no serve loop read the clock within 3s")
	}
}

func mergeClock(t *testing.T, d time.Duration) {
	t.Helper()
	old := wakeMerge
	wakeMerge = d
	t.Cleanup(func() { wakeMerge = old })
}

// oneMutedStream is a client with ONE stream, ready and then deaf to the far
// side, on a clock that stands still.
func oneMutedStream(t *testing.T, password string) (*Client, *dialer, *fakeServer, *handClock) {
	t.Helper()
	clock := useHandClock(t)
	srv := newFakeServer(t, password)
	c, d, _ := startClient(t, srv, 1, KeysWrap)
	eventually(t, "the stream ready", func() bool { return c.Stats().Ready == 1 })
	srv.set(func() { srv.mute[1] = true })
	time.Sleep(60 * time.Millisecond) // what the server said before it fell silent has been read
	return c, d, srv, clock
}

// 🚨 A verdict is about the time BEFORE the wake epoch it was reached under.
// The wake word said while a pass is reaching one — behind its look at the
// epoch, in front of the session's end — takes it back: the stream is not
// replaced on the old window, it is asked afresh and given the word's own
// window; and that window, left without an answer, is a verdict of its own.
func TestAWakeWordSaidWhileAVerdictIsReachedTakesItBack(t *testing.T) {
	quickClocks(t)
	wakeClocks(t, 200*time.Millisecond, time.Hour, 10*time.Millisecond) // only a boundary asks
	mergeClock(t, 50*time.Millisecond)                                  // as in the field: shorter than the window
	c, d, srv, clock := oneMutedStream(t, "pw-void-wake")

	asked := srv.readyCount(1)
	c.Wake() // the first word: a window
	eventually(t, "the stream asked behind the first word", func() bool { return srv.readyCount(1) > asked })

	// The window's listening runs out in ONE reading of the clock — and in
	// that same pass, behind its look at the epoch, the word is said again.
	asked = srv.readyCount(1)
	clock.arm(t, 200*time.Millisecond, c.Wake)
	time.Sleep(300 * time.Millisecond)
	if st := c.Stats(); d.count(1) != 1 || st.WakeDeaf != 0 || st.Wakes != 2 {
		t.Fatalf("a second wake word said before the session's end: dialled %d time(s), silent-behind-a-wake verdicts %d, wake words %d — want 1 dial and no verdict: the verdict was reached under the first word",
			d.count(1), st.WakeDeaf, st.Wakes)
	}
	if n := srv.readyCount(1) - asked; n < 1 {
		t.Fatalf("the stream was asked %d time(s) behind the second word, want it asked afresh", n)
	}

	// The second word's window is a real one.
	clock.arm(t, 200*time.Millisecond, nil)
	eventually(t, "the stream replaced behind the second word's own window", func() bool { return d.count(1) >= 2 })
	if st := c.Stats(); st.WakeDeaf != 1 {
		t.Fatalf("silent-behind-a-wake verdicts %d, want 1", st.WakeDeaf)
	}
}

// The same of a stream that fell silent while the process ran: its sixty
// seconds are a verdict about the time before the word too.
func TestAWakeWordTakesBackAnOrdinaryVerdictToo(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = time.Hour, 300*time.Millisecond
	wakeClocks(t, 200*time.Millisecond, time.Hour, 10*time.Millisecond)
	mergeClock(t, 0) // no two boundaries are ever one: the word must be ONE by itself
	c, d, srv, clock := oneMutedStream(t, "pw-void-deaf")

	asked, probes := srv.readyCount(1), c.Stats().Probes
	clock.arm(t, 300*time.Millisecond, c.Wake)
	eventually(t, "the stream asked behind the word", func() bool { return srv.readyCount(1) > asked })
	time.Sleep(300 * time.Millisecond)
	if st := c.Stats(); d.count(1) != 1 || st.WakeDeaf != 0 || st.Wakes != 1 {
		t.Fatalf("a wake word said while the ordinary verdict was reached: dialled %d time(s), silent-behind-a-wake verdicts %d, wake words %d — want 1 dial and no verdict",
			d.count(1), st.WakeDeaf, st.Wakes)
	}
	// One word, one boundary: the pass that follows finds the word's epoch
	// already acted on and does not open the window — and ask — again. (The
	// engine's own count of its asks says so: a second ask a moment behind the
	// first is not written twice, so the far side cannot tell.)
	if n, p := srv.readyCount(1)-asked, c.Stats().Probes-probes; n != 1 || p != 1 {
		t.Fatalf("behind ONE wake word the stream was asked %d time(s) by the engine's count, %d reached the far side — want once", p, n)
	}
	clock.arm(t, 200*time.Millisecond, nil)
	eventually(t, "the stream replaced behind the word's own window", func() bool { return d.count(1) >= 2 })
	if st := c.Stats(); st.WakeDeaf != 1 {
		t.Fatalf("silent-behind-a-wake verdicts %d, want 1: the word opened a window, not another sixty seconds", st.WakeDeaf)
	}
}
