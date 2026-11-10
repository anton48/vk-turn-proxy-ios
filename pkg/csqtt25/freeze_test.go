package csqtt25

import (
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
