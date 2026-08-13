package proxy

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// armFlowPaths sets the process-global lever for one test and restores it after.
// The globals are shared, so without this one test's k leaks into the next —
// the trap the chunking tests already paid for.
func armFlowPaths(t *testing.T, k int) {
	t.Helper()
	prevK := flowPathsK.Load()
	prevHealth := flowPathsHealth.Load()
	t.Cleanup(func() {
		flowPathsK.Store(prevK)
		flowPathsHealth.Store(prevHealth)
	})
	SetFlowPathsK(k)
}

func newFlowProxy(t *testing.T, numConns int) (*Proxy, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		ctx:       ctx,
		sendCh:    make(chan sendItem, 8),
		pathQ:     newPathQueues(numConns),
		flows:     newFlowTable(numConns),
		stealHint: make(chan struct{}, 1),
		// Sized exactly as NewProxy sizes it. Without this the coverage stamp is
		// skipped and the field reads empty — which is what an idle pool also
		// looks like, so a harness that omits it would make the coverage tests
		// pass for the wrong reason.
		dispatchBytes: make([]atomic.Int64, numConns),
	}
	return p, cancel
}

// 🚨 k=1 is not a supported setting, it is a MEASURED failure: one flow on one
// connection got 1.69 Mbit/s against 8.14 on thirty, i.e. -79%. A config that
// asks for it must be clamped UP, never honoured and never clamped down to off.
func TestClampRefusesK1AndK2(t *testing.T) {
	cases := map[int]int{
		-5: FlowPathsOff, 0: FlowPathsOff,
		1: FlowPathsMin, 2: FlowPathsMin,
		3: 3, 5: 5, 8: 8,
		9: FlowPathsMax, 99: FlowPathsMax,
	}
	for in, want := range cases {
		if got := ClampFlowPathsK(in); got != want {
			t.Errorf("ClampFlowPathsK(%d) = %d, want %d", in, got, want)
		}
	}
}

// The set must be k DISTINCT paths. k copies of one index is k=1 wearing a
// costume, and it would reproduce the -79% while the log still read "k=5".
func TestAssignPathsAreDistinctAndInRange(t *testing.T) {
	const numPaths = 30
	for k := FlowPathsMin; k <= FlowPathsMax; k++ {
		for key := uint64(1); key < 500; key++ {
			paths := assignPaths(key, k, numPaths)
			if len(paths) != k {
				t.Fatalf("k=%d key=%d: got %d paths", k, key, len(paths))
			}
			seen := map[int32]bool{}
			for _, p := range paths {
				if p < 0 || int(p) >= numPaths {
					t.Fatalf("k=%d key=%d: path %d out of range", k, key, p)
				}
				if seen[p] {
					t.Fatalf("k=%d key=%d: duplicate path %d in %v", k, key, p, paths)
				}
				seen[p] = true
			}
		}
	}
}

// Stickiness is the treatment. If a flow got a fresh set per packet this would
// be work-stealing with extra steps.
func TestFlowSetIsStickyAcrossLookups(t *testing.T) {
	tbl := newFlowTable(30)
	first := tbl.paths(0xdeadbeef, 5)
	for i := 0; i < 100; i++ {
		again := tbl.paths(0xdeadbeef, 5)
		if again != first {
			t.Fatalf("lookup %d returned a different entry — the flow lost its set", i)
		}
	}
	if got := tbl.size(); got != 1 {
		t.Fatalf("table size %d, want 1: one flow must not create many entries", got)
	}
}

// A live k change must re-assign rather than serve a stale-width set.
func TestChangingKReassigns(t *testing.T) {
	tbl := newFlowTable(30)
	if got := len(tbl.paths(42, 3).paths); got != 3 {
		t.Fatalf("k=3 gave %d paths", got)
	}
	if got := len(tbl.paths(42, 8).paths); got != 8 {
		t.Fatalf("after raising k to 8 the flow still had %d paths", got)
	}
}

// With the lever off nothing may touch a path queue: that is what makes k=0 the
// byte-for-byte control arm of the A/B.
func TestOffKeepsLegacySharedPath(t *testing.T) {
	armFlowPaths(t, FlowPathsOff)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	if p.enqueueFlowPath(sendItem{buf: []byte{1}}, 0x1234) {
		t.Fatal("k=0 placed a packet on a path queue")
	}
	for i, q := range p.pathQ {
		if len(q) != 0 {
			t.Fatalf("path queue %d has %d items with the lever off", i, len(q))
		}
	}
}

// flowKey 0 means "no inner flow" — a WireGuard keepalive or handshake. Those
// must stay on the shared fan-out: they belong to no flow, and pinning them
// would put control traffic behind one connection's queue.
func TestKeepaliveGoesToSharedPath(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	if p.enqueueFlowPath(sendItem{buf: []byte{1}}, 0) {
		t.Fatal("a keyless packet (keepalive/handshake) was pinned to a path")
	}
}

// 🎯 THE TEST THIS PR EXISTS FOR. A flow fills its own k queues and then SPILLS
// instead of waiting. Without the spill this design is mini-k1 — the -79%
// result — so the assertion is not "it fits" but "it overflows outward".
func TestPreferredSetFillsThenSpills(t *testing.T) {
	armFlowPaths(t, 3)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	const key = 0xabcdef
	depth := flowPathsQueueDepth()
	capacity := 3 * depth

	for i := 0; i < capacity; i++ {
		if !p.enqueueFlowPath(sendItem{buf: []byte{byte(i)}}, key) {
			t.Fatalf("packet %d of %d spilled before the set was full", i, capacity)
		}
	}
	// One more than the set can hold: it must NOT be placed, so the caller
	// sends it down the shared channel where any of the 30 writers can take it.
	if p.enqueueFlowPath(sendItem{buf: []byte{99}}, key) {
		t.Fatal("the set was full yet the packet was still placed on it — the queue is " +
			"deeper than advertised, or the try is blocking")
	}
	if got := p.flowPathStats.spill.Load(); got != 1 {
		t.Fatalf("spill counter = %d, want 1 — the instrument that decides whether a run "+
			"tested anything is not counting", got)
	}

	// And the packets really did land on the flow's own paths, not anywhere.
	set := p.flows.paths(key, 3)
	placed := 0
	for _, idx := range set.paths {
		placed += len(p.pathQ[idx])
	}
	if placed != capacity {
		t.Fatalf("%d packets on the flow's own paths, want %d", placed, capacity)
	}
}

// Within the set the packets must spread, or k=5 degenerates into k=1 whenever
// the first path keeps up.
func TestRoundRobinSpreadsWithinSet(t *testing.T) {
	armFlowPaths(t, 4)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	const key = 0x5150
	for i := 0; i < 4; i++ {
		if !p.enqueueFlowPath(sendItem{buf: []byte{byte(i)}}, key) {
			t.Fatalf("packet %d was not placed", i)
		}
	}
	set := p.flows.paths(key, 4)
	used := 0
	for _, idx := range set.paths {
		if len(p.pathQ[idx]) > 0 {
			used++
		}
	}
	if used != 4 {
		t.Fatalf("4 packets used %d of 4 paths — round-robin is not spreading", used)
	}
}

// The writer side of "soft": its own queue first, but the shared channel is
// always live. A writer that only drained its own queue would strand every
// spilled packet and every keepalive.
func TestWriterTakesOwnQueueThenShared(t *testing.T) {
	armFlowPaths(t, 3)
	p, cancel := newFlowProxy(t, 4)
	defer cancel()
	done := make(chan struct{})

	p.pathQ[2] <- sendItem{buf: []byte{7}}
	item, ok := p.nextSendItem(done, 2)
	if !ok || len(item.buf) != 1 || item.buf[0] != 7 {
		t.Fatalf("writer 2 did not take its own queued packet (ok=%v item=%v)", ok, item.buf)
	}

	p.sendCh <- sendItem{buf: []byte{9}}
	item, ok = p.nextSendItem(done, 2)
	if !ok || item.buf[0] != 9 {
		t.Fatalf("writer 2 did not fall through to the shared channel (ok=%v)", ok)
	}

	close(done)
	if _, ok := p.nextSendItem(done, 2); ok {
		t.Fatal("nextSendItem ignored a cancelled context")
	}
}

// With the lever off the writer must still be served by the shared channel —
// the control arm has to keep working.
func TestWriterServedWhenLeverOff(t *testing.T) {
	armFlowPaths(t, FlowPathsOff)
	p, cancel := newFlowProxy(t, 4)
	defer cancel()
	done := make(chan struct{})

	p.sendCh <- sendItem{buf: []byte{3}}
	item, ok := p.nextSendItem(done, 1)
	if !ok || item.buf[0] != 3 {
		t.Fatalf("k=0 writer was not served from sendCh (ok=%v)", ok)
	}
}

// The table must stay bounded: this device's jetsam ceiling is ~50 MB and its
// history includes a GC death spiral, so an unbounded flow map is a crash.
func TestTableIsBounded(t *testing.T) {
	tbl := newFlowTable(30)
	for i := uint64(0); i < flowPathsMaxFlows*2; i++ {
		tbl.paths(i, 5)
	}
	if got := tbl.size(); got > flowPathsMaxFlows {
		t.Fatalf("table grew to %d entries, cap is %d", got, flowPathsMaxFlows)
	}
}

// The summary is the "did the treatment apply" instrument. Silent when off (a
// line of zeros forever is noise); present the moment the lever is armed (a
// silent line while armed would be a lie).
func TestSummarySilentWhenOffLoudWhenArmed(t *testing.T) {
	p, cancel := newFlowProxy(t, 30)
	defer cancel()

	armFlowPaths(t, FlowPathsOff)
	if s := p.flowPathStats.summary(p.flows); s != "" {
		t.Fatalf("summary printed %q with the lever off", s)
	}

	armFlowPaths(t, 5)
	p.enqueueFlowPath(sendItem{buf: []byte{1}}, 0x77)
	s := p.flowPathStats.summary(p.flows)
	if s == "" {
		t.Fatal("summary is silent while the lever is armed — a null from this run " +
			"could not be told apart from a run that never engaged")
	}
	for _, want := range []string{"k=5", "pref=", "spill=", "flows="} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q is missing %q", s, want)
		}
	}
}

// 🎯 THE TEST THE THIRD DEVICE SESSION PAID FOR. A packet sitting in one
// connection's path queue must be reachable by every other writer. Without this
// the packet waits for its owner, and a flow whose entire progress is ONE packet
// — a SYN — waits with it: measured at 26-39 s to open a flow with a set armed,
// against 0.5-1.9 s without, six times out of six.
func TestStrandedPacketIsStolen(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})

	// Connection 5 owns a packet and (as far as this test is concerned) is stuck
	// inside conn.Write and will never come back for it.
	p.pathQ[5] <- sendItem{buf: []byte{42}}

	item, ok := p.nextSendItem(done, 7)
	if !ok || len(item.buf) != 1 || item.buf[0] != 42 {
		t.Fatalf("writer 7 did not rescue the packet stranded on writer 5 (ok=%v) — a "+
			"queued packet is unreachable again, which is the defect that took 26-39s "+
			"to open a TCP flow on device", ok)
	}
	if n := p.flowPathStats.stolen.Load(); n != 1 {
		t.Fatalf("stolen counter = %d, want 1 — the instrument that shows whether the "+
			"rescue path is being used at all is not counting", n)
	}
}

// Stealing must be the LAST resort: a writer takes its own packet first, or the
// preference the whole design expresses is destroyed by its own repair.
func TestOwnQueueBeatsSteal(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})

	p.pathQ[3] <- sendItem{buf: []byte{9}} // someone else's
	p.pathQ[7] <- sendItem{buf: []byte{7}} // our own
	item, _ := p.nextSendItem(done, 7)
	if item.buf[0] != 7 {
		t.Fatalf("writer 7 took %d, want its own packet 7 — stealing has overtaken the "+
			"preference it exists to protect", item.buf[0])
	}
	if n := p.flowPathStats.stolen.Load(); n != 0 {
		t.Fatalf("stole %d packets while it had its own to send", n)
	}
}

// The shared channel carries spilled packets AND every keepalive and handshake.
// It must be served before another connection's queue is raided.
func TestSharedBeatsSteal(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})

	p.pathQ[3] <- sendItem{buf: []byte{9}}
	p.sendCh <- sendItem{buf: []byte{1}}
	item, _ := p.nextSendItem(done, 7)
	if item.buf[0] != 1 {
		t.Fatalf("writer 7 took %d, want the shared-channel packet 1 — keepalives and "+
			"spilled packets would queue behind a raid", item.buf[0])
	}
}

// A writer with nothing anywhere must still block rather than spin, and must
// still honour cancellation.
func TestStealSweepDoesNotSpin(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(done) }()
	if _, ok := p.nextSendItem(done, 2); ok {
		t.Fatal("nextSendItem returned an item from an empty proxy")
	}
}
