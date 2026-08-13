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
