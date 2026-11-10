package csqtt25

import (
	"strings"
	"testing"
	"time"
)

// A watch on the field's clocks, started at t0.
func fieldWatch(t0 time.Time) *streamWatch {
	return &streamWatch{watchClocks: watchClocks{
		late: 3 * time.Second, ask: 20 * time.Second, deaf: 60 * time.Second,
		settleAsk: 2 * time.Second, settleDeaf: 5 * time.Second,
		wakeDeaf: 5 * time.Second, wakeAsk: time.Second,
		answerFloor: 250 * time.Millisecond, merge: 2 * time.Second, idle: 10 * time.Second,
	}, prev: t0}
}

// run ticks the watch once a second n times from *at and returns what it did
// at each tick.
func run(s *streamWatch, at *time.Time, n int, epoch uint64, unsettled bool) []watchAction {
	out := make([]watchAction, 0, n)
	for i := 0; i < n; i++ {
		*at = at.Add(time.Second)
		act, _ := s.tick(*at, epoch, unsettled)
		out = append(out, act)
	}
	return out
}

// asks is the 1-based ticks of acts at which the watch asked; end the tick at
// which it gave its verdict (0: none) and what the verdict was.
func asks(acts []watchAction) (asked []int, end int, verdict watchAction) {
	for i, a := range acts {
		switch a {
		case watchAsk:
			asked = append(asked, i+1)
		case watchDeaf, watchUnsettled, watchWakeDeaf:
			if end == 0 {
				end, verdict = i+1, a
			}
		}
	}
	return
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A stream that falls silent while the process runs is asked after twenty
// seconds of it, again every ten, and replaced at sixty.
func TestSilenceWhileTheProcessRunsIsAskedAndThenAVerdict(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	asked, end, verdict := asks(run(s, &at, 60, 0, false))
	if !sameInts(asked, []int{20, 30, 40, 50}) || end != 60 || verdict != watchDeaf {
		t.Fatalf("asked at %v, verdict %d at %d; want asks at 20 30 40 50 and deaf at 60", asked, verdict, end)
	}
}

// 🚨 A tick that comes late is a freeze, and a freeze is not silence: the
// stream is not replaced for the minutes the process did not run — it is
// asked afresh, at once, and judged on the listening that follows.
func TestALateTickIsABoundaryNotSilence(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	run(s, &at, 15, 0, false) // fifteen seconds of silence so far
	at = at.Add(10 * time.Minute)
	act, gap := s.tick(at, 0, false)
	if act != watchFroze || gap != 10*time.Minute {
		t.Fatalf("a tick ten minutes late: action %d with a gap of %s; want a freeze (%d) of 10m0s — not a verdict on ten minutes of «silence»", act, gap, watchFroze)
	}
	if s.quiet != 0 {
		t.Fatalf("the silence counted before the freeze is still %s behind it", s.quiet)
	}
	// Behind the boundary: asked again every second of listening, replaced at five.
	asked, end, verdict := asks(run(s, &at, 5, 0, false))
	if !sameInts(asked, []int{1, 2, 3, 4}) || end != 5 || verdict != watchWakeDeaf {
		t.Fatalf("behind the freeze: asked at %v, verdict %d at %d; want asks at 1 2 3 4 and the wake's verdict (%d) at 5", asked, verdict, end, watchWakeDeaf)
	}
}

// 🚨 A freeze inside the window starts it over: what was not heard across the
// next sleep proves nothing either.
func TestAFreezeInsideTheWakeWindowStartsItOver(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	at = at.Add(5 * time.Minute)
	s.tick(at, 0, false)                                       // the boundary
	if _, end, _ := asks(run(s, &at, 4, 0, false)); end != 0 { // four seconds of listening
		t.Fatalf("a verdict after four seconds of listening (at %d)", end)
	}
	at = at.Add(2 * time.Minute)
	if act, _ := s.tick(at, 0, false); act != watchFroze {
		t.Fatalf("a second freeze inside the window: action %d, want a freeze (%d)", act, watchFroze)
	}
	asked, end, verdict := asks(run(s, &at, 5, 0, false))
	if !sameInts(asked, []int{1, 2, 3, 4}) || end != 5 || verdict != watchWakeDeaf {
		t.Fatalf("behind the second freeze: asked at %v, verdict %d at %d; want a whole window again — the four seconds before it do not count", asked, verdict, end)
	}
}

// An answer ends the window — but not one read in the first instant behind
// the boundary: that one waited in the socket through the freeze.
func TestWhatEndsAWakeWindow(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	at = at.Add(5 * time.Minute)
	s.tick(at, 0, false)
	s.heard(at.Add(100 * time.Millisecond)) // inside the floor
	if !s.wake {
		t.Fatal("an inbound read 100 ms behind the boundary ended the window: it cannot be the answer to the boundary's ask")
	}
	if _, end, verdict := asks(run(s, &at, 5, 0, false)); end != 5 || verdict != watchWakeDeaf {
		t.Fatalf("with nothing but that stale inbound: verdict %d at %d, want the wake's at 5", verdict, end)
	}

	at = time.Unix(1_800_100_000, 0)
	s = fieldWatch(at)
	at = at.Add(5 * time.Minute)
	s.tick(at, 0, false)
	run(s, &at, 1, 0, false)
	s.heard(at.Add(300 * time.Millisecond)) // an answer: 1.3 s behind the boundary
	if s.wake {
		t.Fatal("an answer 1.3 s behind the boundary did not end the window")
	}
	// From here the stream is an ordinary one: twenty seconds to the next ask.
	asked, end, _ := asks(run(s, &at, 25, 0, false))
	if !sameInts(asked, []int{20}) || end != 0 {
		t.Fatalf("after the answer: asked at %v, a verdict at %d; want one ask at 20 and no verdict", asked, end)
	}
}

// 🚨 What is read across a freeze the loop has not seen yet changes nothing:
// the datagram waited in the socket, and the late tick that follows makes the
// boundary.
func TestAnInboundReadAcrossAFreezeIsNoAnswer(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	run(s, &at, 15, 0, false)
	s.heard(at.Add(10 * time.Minute)) // read at the thaw, before the tick
	if s.quiet != 15*time.Second {
		t.Fatalf("an inbound read ten minutes behind the last tick reset the silence (%s, want the 15s counted)", s.quiet)
	}
	at = at.Add(10*time.Minute + 5*time.Millisecond)
	if act, _ := s.tick(at, 0, false); act != watchFroze {
		t.Fatalf("the tick behind it: action %d, want the freeze (%d)", act, watchFroze)
	}
	// …and inside a window that stands: frozen again, a stale read, the window stays.
	run(s, &at, 2, 0, false)
	s.heard(at.Add(3 * time.Minute))
	if !s.wake {
		t.Fatal("an inbound read across a second freeze ended the window")
	}
}

// The caller's wake word is the same boundary without a late tick — and the
// word that comes with a freeze the watch has just seen is that same wake.
func TestTheWakeWordIsABoundary(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	run(s, &at, 15, 0, false)
	at = at.Add(time.Second)
	if act, _ := s.tick(at, 1, false); act != watchWoke || s.quiet != 0 || !s.wake {
		t.Fatalf("the wake word at an on-time tick: action %d, quiet %s, window %v; want a boundary (%d)", act, s.quiet, s.wake, watchWoke)
	}
	asked, end, verdict := asks(run(s, &at, 5, 1, false))
	if !sameInts(asked, []int{1, 2, 3, 4}) || end != 5 || verdict != watchWakeDeaf {
		t.Fatalf("behind the word: asked at %v, verdict %d at %d", asked, verdict, end)
	}

	// A freeze, and the app's word a second later: one wake, not two.
	at = time.Unix(1_800_100_000, 0)
	s = fieldWatch(at)
	at = at.Add(5 * time.Minute)
	s.tick(at, 0, false)
	at = at.Add(time.Second)
	if act, _ := s.tick(at, 1, false); act != watchAsk || s.listened != time.Second {
		t.Fatalf("the word one second behind a freeze: action %d, listened %s; want the window's own ask (%d) with its second kept", act, s.listened, watchAsk)
	}
	// The word alone, later than that, is a wake of its own.
	run(s, &at, 2, 1, false)
	at = at.Add(time.Second)
	if act, _ := s.tick(at, 2, false); act != watchWoke || s.listened != 0 {
		t.Fatalf("the word four seconds behind the boundary: action %d, listened %s; want a new boundary", act, s.listened)
	}
	// A late tick is a freeze whatever the word says.
	at = at.Add(time.Minute)
	if act, _ := s.tick(at, 3, false); act != watchFroze {
		t.Fatalf("a late tick with the word: action %d, want the freeze", act)
	}
}

// Behind a restart notice a stream not yet known to be on the server that
// came back runs on its short times — of listening, like the long ones.
func TestAnUnsettledStreamsShortTimesAreListening(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	asked, end, verdict := asks(run(s, &at, 5, 0, true))
	if !sameInts(asked, []int{2, 3, 4}) || end != 5 || verdict != watchUnsettled {
		t.Fatalf("unsettled: asked at %v, verdict %d at %d; want asks at 2 3 4 and unsettled (%d) at 5", asked, verdict, end, watchUnsettled)
	}
	// A freeze in it is a boundary there too.
	at = time.Unix(1_800_100_000, 0)
	s = fieldWatch(at)
	run(s, &at, 3, 0, true)
	at = at.Add(time.Minute)
	if act, _ := s.tick(at, 0, true); act != watchFroze {
		t.Fatalf("a late tick on an unsettled stream: action %d, want the freeze", act)
	}
}

// An answer ends the silence and its asking; a wall clock set back adds
// nothing to it.
func TestAnAnswerEndsTheSilenceAndAClockSetBackAddsNone(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	s := fieldWatch(at)
	run(s, &at, 22, 0, false)
	s.heard(at.Add(500 * time.Millisecond))
	asked, end, _ := asks(run(s, &at, 25, 0, false))
	if !sameInts(asked, []int{20}) || end != 0 {
		t.Fatalf("after an answer: asked at %v, verdict at %d; want twenty seconds to the next ask", asked, end)
	}
	before := s.quiet
	back := at.Add(-time.Hour)
	if act, _ := s.tick(back, 0, false); act != watchNone || s.quiet != before {
		t.Fatalf("a tick whose clock went back an hour: action %d, quiet %s (was %s)", act, s.quiet, before)
	}
	// From the set-back clock on, a second is a second again.
	if act, _ := s.tick(back.Add(time.Second), 0, false); act != watchNone || s.quiet != before+time.Second {
		t.Fatalf("the tick a second behind the set-back one: action %d, quiet %s (want %s)", act, s.quiet, before+time.Second)
	}
}

// The watch a stream is given holds the package's clocks as they stand when
// the stream becomes ready — its own copy.
func TestAWatchHoldsItsOwnCopyOfTheClocks(t *testing.T) {
	quickClocks(t)
	s := newStreamWatch(7)
	if s.late != serveTick+freezeSlack || s.ask != probeAfter || s.deaf != deafAfter || s.settleAsk != settleProbeAfter ||
		s.settleDeaf != settleDeafAfter || s.wakeDeaf != wakeDeafAfter || s.wakeAsk != wakeAskEvery ||
		s.answerFloor != wakeAnswerFloor || s.merge != wakeMerge || s.idle != keepaliveEvery || s.now == nil || s.epoch != 7 || s.prev.IsZero() {
		t.Fatalf("a new watch's clocks: %+v", s.watchClocks)
	}
	if freezeSlack < time.Second || wakeDeafAfter != 5*time.Second || wakeAskEvery != time.Second || wakeAnswerFloor <= 0 || wakeMerge < time.Second {
		t.Fatalf("the field's wake clocks: slack %s, deaf %s, ask %s, floor %s, merge %s", freezeSlack, wakeDeafAfter, wakeAskEvery, wakeAnswerFloor, wakeMerge)
	}
}

// The serve clock is WALL time: on a runtime whose monotonic clock stands
// still while the machine sleeps, a reading that carried it would make the
// tick behind a sleep look on time — the very gap the watch is there to see.
func TestTheServeClockIsWallTime(t *testing.T) {
	a := serveNow()
	if strings.Contains(a.String(), " m=") {
		t.Fatalf("the serve clock's reading carries a monotonic part: %s", a)
	}
}

// Which of the rule's answers end a session.
func TestWhichAnswersAreVerdicts(t *testing.T) {
	for act, want := range map[watchAction]bool{
		watchNone: false, watchAsk: false, watchFroze: false, watchWoke: false,
		watchDeaf: true, watchUnsettled: true, watchWakeDeaf: true,
	} {
		if act.ends() != want {
			t.Errorf("action %d ends a session: %v, want %v", act, act.ends(), want)
		}
	}
}

// 🚨 A verdict taken back by the wake word (the serve loop found the epoch
// moved before it carried the verdict out): the word is a boundary of its own
// — a fresh window, however short ago the voided one began — and ONE wake: the
// tick that follows does not open the window again for the same word.
func TestAVoidedVerdictOpensTheWordsOwnWindow(t *testing.T) {
	for _, merge := range []time.Duration{time.Hour, 0} { // whatever the merge time
		at := time.Unix(1_800_200_000, 0)
		s := fieldWatch(at)
		s.merge = merge
		at = at.Add(time.Second)
		s.tick(at, 1, false) // the first word
		if _, end, verdict := asks(run(s, &at, 5, 1, false)); end != 5 || verdict != watchWakeDeaf {
			t.Fatalf("merge %s: the first window's verdict %d at tick %d, want %d at 5", merge, verdict, end, watchWakeDeaf)
		}
		s.void(at, 2)
		if !s.wake || s.listened != 0 || s.quiet != 0 || !s.since.Equal(at) {
			t.Fatalf("merge %s: after the void wake=%v listened=%s quiet=%s — want a window that begins now", merge, s.wake, s.listened, s.quiet)
		}
		asked, end, verdict := asks(run(s, &at, 5, 2, false))
		if !sameInts(asked, []int{1, 2, 3, 4}) || end != 5 || verdict != watchWakeDeaf {
			t.Fatalf("merge %s: behind the void asked at %v, verdict %d at tick %d — want asked at 1–4 and silent-behind-a-wake at 5: the word's own five seconds, once",
				merge, asked, verdict, end)
		}
	}

	// An ordinary verdict voided: a window, not another sixty seconds.
	at := time.Unix(1_800_210_000, 0)
	s := fieldWatch(at)
	if _, end, verdict := asks(run(s, &at, 60, 0, false)); end != 60 || verdict != watchDeaf {
		t.Fatalf("the ordinary verdict %d at tick %d, want %d at 60", verdict, end, watchDeaf)
	}
	s.void(at, 1)
	if _, end, verdict := asks(run(s, &at, 5, 1, false)); end != 5 || verdict != watchWakeDeaf {
		t.Fatalf("behind a voided ordinary verdict: %d at tick %d, want silent-behind-a-wake at 5", verdict, end)
	}
}
