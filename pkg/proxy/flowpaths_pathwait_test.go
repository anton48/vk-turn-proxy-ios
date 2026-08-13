package proxy

import (
	"strings"
	"testing"
	"time"
)

// The route a packet took to reach a writer must survive to the point where its
// residence is filed, or `pathq-own` and `pathq-steal` silently report on the
// wrong population — and the failure mode is the worst kind: an EMPTY field,
// which reads as "nothing took that route" rather than as a broken instrument.
//
// 🎯 WHY THIS MEASUREMENT EXISTS. On 2026-08-13, four flows took 3.0 s to open
// with k=5 armed, and the trace showed the stall ending in a 3 ms burst of
// fifteen steals onto one connection that was in none of those flows' sets. Two
// readings fit that equally — the packets sat in preferred queues nobody
// drained, or the whole writer pool was busy and that connection freed up first
// — and they differ only in how long a path-queued packet had been waiting.
// These fields are that difference, so a stamp that goes missing takes the
// discriminator with it.
func TestDispatchStampsItsRoute(t *testing.T) {
	armFlowPaths(t, 5)
	done := make(chan struct{})

	t.Run("own", func(t *testing.T) {
		p, cancel := newFlowProxy(t, 30)
		defer cancel()
		p.pathQ[7] <- sendItem{buf: []byte{1}}
		item, ok := p.nextSendItem(done, 7)
		if !ok || item.via != viaOwn {
			t.Fatalf("via = %d, want viaOwn (%d) — a packet taken from a writer's OWN "+
				"queue would be filed as shared, and pathq-own would read empty while "+
				"the queues were in fact being used", item.via, viaOwn)
		}
	})

	t.Run("steal", func(t *testing.T) {
		p, cancel := newFlowProxy(t, 30)
		defer cancel()
		p.pathQ[5] <- sendItem{buf: []byte{2}}
		item, ok := p.nextSendItem(done, 7)
		if !ok || item.via != viaSteal {
			t.Fatalf("via = %d, want viaSteal (%d) — the rescue path would report no "+
				"residence at all, which is exactly the number the stall question "+
				"turns on", item.via, viaSteal)
		}
	})

	t.Run("shared", func(t *testing.T) {
		p, cancel := newFlowProxy(t, 30)
		defer cancel()
		p.sendCh <- sendItem{buf: []byte{3}}
		item, ok := p.nextSendItem(done, 7)
		if !ok || item.via != viaShared {
			t.Fatalf("via = %d, want viaShared (%d)", item.via, viaShared)
		}
	})
}

// The stamp must reach the histogram. This drives the real writeChunk, because
// the split lives there and a test that called observe directly would guard
// nothing.
//
// 🚨 The assertion is on WHICH field is populated, not on the value: a residence
// is a duration and any threshold on it would be a second thing to be wrong
// about. `sendch-wait` must ALSO be populated — it stays a total over every
// packet, so the three series are views, not a partition, and a reading of it
// remains comparable with every number recorded since build 229.
func TestPathResidenceIsFiledAgainstItsRoute(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	stale := time.Now().Add(-40 * time.Millisecond).UnixNano()
	noop := func(pkt []byte, now time.Time) error { return nil }

	if err := p.writeChunk(sendItem{buf: []byte{1}, at: stale, via: viaOwn}, -1, noop); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	own := p.pathWaitOwn.summaryAs("pathq-own")
	steal := p.pathWaitSteal.summaryAs("pathq-steal")
	total := p.sendWait.summary()
	if own == "" {
		t.Fatal("pathq-own is EMPTY after dispatching an own-queue packet — the field " +
			"would read as 'no packet ever came from a path queue' on a device where " +
			"they all did")
	}
	if steal != "" {
		t.Fatalf("pathq-steal = %q after an own-queue packet — the routes are crossed "+
			"and every conclusion drawn from them would be inverted", steal)
	}
	if !strings.Contains(total, "sendch-wait") {
		t.Fatalf("sendch-wait = %q — the split must not have stopped the total from "+
			"counting, or the historical series breaks silently", total)
	}

	if err := p.writeChunk(sendItem{buf: []byte{2}, at: stale, via: viaSteal}, -1, noop); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	if p.pathWaitSteal.summaryAs("pathq-steal") == "" {
		t.Fatal("pathq-steal is EMPTY after dispatching a stolen packet")
	}
	if s := p.pathWaitOwn.summaryAs("pathq-own"); s != "" {
		t.Fatalf("pathq-own = %q after a stolen packet — crossed routes", s)
	}
}

// qpeak is printed, and it must be printed as a fraction of the cap: a bare "2"
// says nothing without "of 2", and this queue is deep enough to saturate under
// any real load. The field is a companion to the residence, never a substitute
// — depth at the producer cannot separate "deep because bursty" from "deep
// because nothing drains", which is build 223's mistake and cost a device run.
func TestSummaryCarriesQueuePeakAgainstItsCap(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	if !p.enqueueFlowPath(sendItem{buf: []byte{1}, at: time.Now().UnixNano()}, 0xabc) {
		t.Fatal("enqueueFlowPath refused a packet with an armed set and empty queues")
	}
	s := p.flowPathStats.summary(p.flows)
	want := "qpeak=1/" + itoaDepth(flowPathsQueueDepth())
	if !strings.Contains(s, want) {
		t.Fatalf("summary = %q, want it to contain %q", s, want)
	}
	// Read-and-reset, like every other field on that line.
	if s2 := p.flowPathStats.summary(p.flows); !strings.Contains(s2, "qpeak=0/") {
		t.Fatalf("second summary = %q, want qpeak reset to 0 — a peak that accumulates "+
			"across ticks reports the worst moment of the session on every line", s2)
	}
}

func itoaDepth(d int) string {
	if d < 10 {
		return string(rune('0' + d))
	}
	return "?"
}

// A writer that parked while the lever was OFF must serve its path queue as soon
// as the lever is turned ON — without waiting for a packet on the shared channel
// to send it round the outside of the loop.
//
// 🚨 THIS IS A REGRESSION TEST FOR A MEASURED DEVICE DEFECT, not a hypothetical.
// nextSendItem used to read k once, above its loop. Every idle writer therefore
// held `own = nil` and `sticky = false` from before the flip, and `continue` on
// the wake hint returned to a top of loop that never re-read them — so it skipped
// its own queue and skipped the steal sweep and blocked again. On 2026-08-13,
// four flows opened 5.2 s after a 0→5 flip while the extension logged tx-pkt
// 5-6/s in, pref=100%, qpeak=2/2 and NOT ONE dequeue by any route.
//
// The sabotage is to hoist the two reads back above the loop: it compiles, and
// this test then times out with the packet still in the queue.
func TestFlipReachesAWriterThatIsAlreadyParked(t *testing.T) {
	armFlowPaths(t, FlowPathsOff) // parked while the lever is OFF
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})
	defer close(done)

	got := make(chan sendItem, 1)
	go func() {
		if item, ok := p.nextSendItem(done, 7); ok {
			got <- item
		}
	}()
	// Let it reach the blocking select with the lever still off.
	time.Sleep(50 * time.Millisecond)

	SetFlowPathsK(5)
	// Exactly what enqueueFlowPath does: place, then hint once, non-blocking.
	p.pathQ[7] <- sendItem{buf: []byte{7}}
	select {
	case p.stealHint <- struct{}{}:
	default:
	}

	select {
	case item := <-got:
		if len(item.buf) != 1 || item.buf[0] != 7 {
			t.Fatalf("got %v, want the queued packet", item.buf)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a writer parked before the flip never took the packet from its OWN " +
			"path queue — every idle writer is holding pre-flip state, so a queued " +
			"packet is unreachable until a SHARED-channel packet happens to send one " +
			"of them round the loop. That is the 5.2 s connect measured on device.")
	}
}

// `budget-cov` must count EVERY dispatch route and EVERY writer, because the
// whole point of the field is to say how the pool's load is spread.
//
// 🚨 The dangerous failure is silent and one-sided: stamp it after any of
// noteDispatch's trace filters and it counts only keyed packets with trace budget
// left — a handful per flow — so a fully-loaded pool reads as a collapse and any
// controller steering on it would spill traffic it did not need to.
func TestBudgetCoverageCountsEveryDispatchRoute(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})

	if s := p.budgetCoverageSummary(); s != "" {
		t.Fatalf("budget-cov = %q on an idle pool, want silence — a 0/30 printed "+
			"forever would later pass for a measured collapse", s)
	}

	// One equal-sized packet down each route, onto three different connections.
	// The keepalive (flow 0) is the case that matters most: it takes the shared
	// channel BY DESIGN and is filtered out of the trace, so if the stamp sits
	// behind that filter this is the dispatch that vanishes.
	p.pathQ[7] <- sendItem{buf: make([]byte, 100), flow: 0xaa}
	if _, ok := p.nextSendItem(done, 7); !ok { // own
		t.Fatal("own dispatch failed")
	}
	p.pathQ[5] <- sendItem{buf: make([]byte, 100), flow: 0xbb}
	if _, ok := p.nextSendItem(done, 9); !ok { // steal: lands on 9, not 5
		t.Fatal("steal dispatch failed")
	}
	p.sendCh <- sendItem{buf: make([]byte, 100)} // flow 0 = a keepalive
	if _, ok := p.nextSendItem(done, 21); !ok {  // shared
		t.Fatal("shared dispatch failed")
	}

	if s := p.budgetCoverageSummary(); s != " budget-cov=3/30=10%" {
		t.Fatalf("budget-cov = %q, want ' budget-cov=3/30=10%%' — the three routes "+
			"are own(7), steal(9, the STEALER not the owner) and shared(21, a "+
			"keepalive the trace filters out)", s)
	}

	// Read-and-reset: the next tick starts empty, or the field reports the
	// session's worst moment on every line forever.
	if s := p.budgetCoverageSummary(); s != "" {
		t.Fatalf("budget-cov = %q on the second read, want silence", s)
	}
}

// 🎯 THE PREDICATE ITSELF, and it is the reason this field was rewritten.
//
// Build 255 asked "did this connection carry ANYTHING in the last second" and
// read 100% in every arm on device — k=0 and k=5, F=4/8/16 — against a
// set-membership bound of 52% at F=4/k=5, because spill and steal keep every
// connection technically non-idle while it carries a fraction of its share. The
// question that is about BUDGET is "did it carry at least half of an even
// share", and these cases pin it, including the boundary.
func TestBudgetCoverageUsesHalfAnEvenShare(t *testing.T) {
	armFlowPaths(t, 5)
	feed := func(p *Proxy, perConn map[int]int) {
		for idx, n := range perConn {
			p.noteDispatch(sendItem{buf: make([]byte, n)}, idx, "own")
		}
	}

	t.Run("even pool reads 100%", func(t *testing.T) {
		p, cancel := newFlowProxy(t, 30)
		defer cancel()
		m := map[int]int{}
		for i := 0; i < 30; i++ {
			m[i] = 100
		}
		feed(p, m)
		if s := p.budgetCoverageSummary(); s != " budget-cov=30/30=100%" {
			t.Fatalf("budget-cov = %q, want 100%% — an evenly loaded pool is the "+
				"definition of full coverage", s)
		}
	})

	t.Run("half the pool carrying everything reads 50%", func(t *testing.T) {
		p, cancel := newFlowProxy(t, 30)
		defer cancel()
		m := map[int]int{}
		for i := 0; i < 15; i++ {
			m[i] = 200
		}
		feed(p, m)
		if s := p.budgetCoverageSummary(); s != " budget-cov=15/30=50%" {
			t.Fatalf("budget-cov = %q, want 50%% — this is the shape the old field "+
				"could not see at all", s)
		}
	})

	// The boundary: 29 conns at 100 B, one at X. A conn counts when
	// 2*N*bytes >= total, so with total = 2900+X the cut is X = 50.
	for _, tc := range []struct {
		x    int
		want string
	}{{49, " budget-cov=29/30=97%"}, {50, " budget-cov=30/30=100%"}} {
		t.Run("boundary", func(t *testing.T) {
			p, cancel := newFlowProxy(t, 30)
			defer cancel()
			m := map[int]int{29: tc.x}
			for i := 0; i < 29; i++ {
				m[i] = 100
			}
			feed(p, m)
			if s := p.budgetCoverageSummary(); s != tc.want {
				t.Fatalf("x=%d: budget-cov = %q, want %q — half an even share is "+
					"an exact integer test, not a float comparison", tc.x, s, tc.want)
			}
		})
	}
}

// The second way the stamp can be put in the wrong place: behind the trace
// BUDGET. Each flow gets flowTraceBudget lines, so a stamp below that check
// counts a flow's first three packets and nothing after — under a bulk transfer
// the field would decay while the pool was fully loaded.
func TestBudgetCoverageSurvivesTheTraceBudget(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})

	const flow = uint64(0xc0ffee)
	for i := 0; i < flowTraceBudget+2; i++ {
		p.pathQ[3] <- sendItem{buf: make([]byte, 100), flow: flow}
		if _, ok := p.nextSendItem(done, 3); !ok {
			t.Fatalf("dispatch %d failed", i)
		}
	}
	// Same flow, budget long spent, onto a connection not yet seen. It carries
	// 100 of 600 bytes over 30 conns — an even share is 20, so it counts.
	p.pathQ[17] <- sendItem{buf: make([]byte, 100), flow: flow}
	if _, ok := p.nextSendItem(done, 17); !ok {
		t.Fatal("dispatch onto the fresh conn failed")
	}

	if s := p.budgetCoverageSummary(); s != " budget-cov=2/30=7%" {
		t.Fatalf("budget-cov = %q, want ' budget-cov=2/30=7%%' — a flow whose trace "+
			"budget is spent still carries traffic, and the pool it loads must "+
			"still be counted", s)
	}
}
