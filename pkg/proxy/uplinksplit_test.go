package proxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Each of these was SEEN to fail under a sabotage that still COMPILES; the
// sabotage is named above the test.

func splitTestProxy() (*Proxy, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		ctx:     ctx,
		sendCh:  make(chan sendItem, 8),
		synthCh: make(chan sendItem, 8),
	}, cancel
}

func resetSplit() {
	SetUplinkSplitN(UplinkSplitOff)
	SplitStatsAndReset()
}

// OFF IS BYTE-FOR-BYTE THE OLD BEHAVIOUR: the generator's packet goes to the
// shared channel and any writer may take it, including one whose index would
// have belonged to the synthetic's group had the split been armed.
//
// SABOTAGE SEEN TO FAIL: drop the `&& synth` from the enqueue's split condition
// in sendPacketMarked, so the synthetic always uses synthCh. Compiles; the
// packet then never appears on the shared channel and this test times out.
func TestSplitOffKeepsOneSharedQueue(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	p, cancel := splitTestProxy()
	defer cancel()

	if err := p.SendPacketSynth([]byte("synthetic")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(p.synthCh) != 0 {
		t.Fatalf("with the split off nothing may reach synthCh, got %d", len(p.synthCh))
	}
	done := make(chan struct{})
	item, ok := p.nextSendItem(done, 0)
	if !ok || string(item.buf) != "synthetic" {
		t.Fatalf("writer 0 must serve the shared queue when the split is off (ok=%v)", ok)
	}
}

// 🚨 THE PROPERTY THE WHOLE LEVER EXISTS FOR: with the pool split, a WireGuard
// packet must NEVER be handed to a writer in the synthetic's group. If it can,
// the two streams still share allocations and the experiment measures nothing —
// while looking exactly like a null.
//
// SABOTAGE SEEN TO FAIL: make the split branch in nextSendItem select over BOTH
// channels (`case item := <-p.sendCh:` beside the synth one). Compiles; this
// test then receives the WireGuard packet on writer 0.
func TestSplitKeepsWireGuardOffTheSyntheticGroup(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := splitTestProxy()
	defer cancel()

	if err := p.SendPacketFlow([]byte("wireguard"), 0); err != nil {
		t.Fatalf("send: %v", err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); close(done) }()
	if item, ok := p.nextSendItem(done, 0); ok {
		t.Fatalf("a synthetic-group writer took a WireGuard packet: %q", item.buf)
	}
	// …and the packet is still there for a writer that IS allowed to have it.
	if item, ok := p.nextSendItem(make(chan struct{}), 20); !ok || string(item.buf) != "wireguard" {
		t.Fatalf("writer 20 must get the WireGuard packet (ok=%v)", ok)
	}
}

// The mirror image, and it fails differently: if the synthetic could be served
// by a WireGuard-group writer, its packets would land on the very allocations
// the split is trying to keep them off.
//
// SABOTAGE SEEN TO FAIL: invert splitOwnsSynth to `connIdx >= uplinkSplit()`.
// Compiles; writer 20 then takes the synthetic packet.
func TestSplitKeepsTheSyntheticOffTheWireGuardGroup(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := splitTestProxy()
	defer cancel()

	if err := p.SendPacketSynth([]byte("synthetic")); err != nil {
		t.Fatalf("send: %v", err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); close(done) }()
	if item, ok := p.nextSendItem(done, 20); ok {
		t.Fatalf("a WireGuard-group writer took a synthetic packet: %q", item.buf)
	}
	if item, ok := p.nextSendItem(make(chan struct{}), 3); !ok || string(item.buf) != "synthetic" {
		t.Fatalf("writer 3 must get the synthetic packet (ok=%v)", ok)
	}
}

// 🚨 THE ENGAGEMENT WITNESS. A split armed while one group carried nothing tested
// NOTHING, and that failure has already cost this project nine runs in another
// knob's shape. The line must therefore report both counts — and stay silent
// when the lever is off, so a zero can never be mistaken for a measurement.
//
// SABOTAGE SEEN TO FAIL: return the summary unconditionally (drop the
// `if n <= UplinkSplitOff` guard). Compiles; the off case then prints a row of
// zeroes and this test finds it.
func TestSplitSummaryCountsBothGroupsAndIsSilentWhenOff(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	if s := splitSummary(); s != "" {
		t.Fatalf("the split is off; the field must be absent, got %q", s)
	}

	SetUplinkSplitN(15)
	p, cancel := splitTestProxy()
	defer cancel()
	_ = p.SendPacketSynth([]byte("s"))
	_ = p.SendPacketFlow([]byte("w"), 0)
	_, _ = p.nextSendItem(make(chan struct{}), 0)
	_, _ = p.nextSendItem(make(chan struct{}), 20)

	s := splitSummary()
	// 🚨 The cross terms are the point: synth→B and wg→A must be ZERO and must be
	// PRINTED, so the disjointness is observed on every run rather than merely
	// guaranteed by the code.
	for _, want := range []string{"split=15", "synth→A=1", "synth→B=0", "wg→A=0", "wg→B=1", "wrong=0"} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %q in %q", want, s)
		}
	}
	if strings.Contains(s, "WRONG-GROUP") {
		t.Fatalf("nothing crossed groups; the alarm must be silent: %q", s)
	}
	if again := splitSummary(); !strings.Contains(again, "synth→A=0") {
		t.Fatalf("the counters must read and reset, got %q", again)
	}
}

// 🚨 AND THE ALARM MUST FIRE. A packet that crossed groups means the two streams
// shared allocations after all and the arm measured the thing it was built to
// remove — that has to shout, not appear as a small number among others.
//
// SABOTAGE SEEN TO FAIL: drop the `if wrong > 0` note from splitSummary and
// leave `_ = wrong`. Compiles; this test then finds no warning.
func TestSplitShoutsWhenAPacketCrossedGroups(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	noteSplitDispatch(true, false) // a synthetic packet served by group B
	s := splitSummary()
	if !strings.Contains(s, "wrong=1") || !strings.Contains(s, "WRONG-GROUP") {
		t.Fatalf("a cross-group dispatch must void the arm loudly, got %q", s)
	}
}

// A split that leaves either side without a writer is not a split. 0 is off.
//
// SABOTAGE SEEN TO FAIL: raise the upper clamp to 30. Compiles; the WireGuard
// group is then empty at N=30 and this test says so.
func TestClampUplinkSplitN(t *testing.T) {
	for _, c := range []struct{ in, want int }{
		{-5, 0}, {0, 0}, {1, 1}, {15, 15}, {29, 29}, {30, 29}, {1000, 29},
	} {
		if got := ClampUplinkSplitN(c.in); got != c.want {
			t.Fatalf("clamp(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// 🚨🚨 THE DEFECT THE USER CAUGHT BEFORE THE FIRST RUN, and it would have been
// silent. A writer PARKED on a channel does not re-read the mode. With the split
// armed, group-A writers block on `synthCh`; if the split is then turned off
// they are still blocked there, on a queue nothing will ever fill again — so the
// arm runs with HALF THE POOL and no counter says so. The 8-second gap between
// arms guarantees they are parked at exactly the moment the mode changes,
// because the load is zero for the whole gap.
//
// SABOTAGE SEEN TO FAIL: remove the `case <-splitWakeCh(): continue` from the
// split branch in nextSendItem. Compiles; the parked writer then never wakes and
// this test times out at `done`.
func TestParkedWriterWakesWhenTheSplitIsTurnedOff(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	p, cancel := splitTestProxy()
	defer cancel()

	done := make(chan struct{})
	got := make(chan sendItem, 1)
	go func() {
		// Parks on synthCh, which stays empty for the whole test.
		if item, ok := p.nextSendItem(done, 0); ok {
			got <- item
		}
	}()
	time.Sleep(50 * time.Millisecond) // let it park

	SetUplinkSplitN(UplinkSplitOff)
	_ = p.SendPacketFlow([]byte("after the flip"), 0)

	select {
	case item := <-got:
		if string(item.buf) != "after the flip" {
			t.Fatalf("woke with the wrong packet: %q", item.buf)
		}
	case <-time.After(2 * time.Second):
		close(done)
		t.Fatal("a writer parked on synthCh never woke after the split was turned off — " +
			"that arm would have run with half the pool")
	}
}

// The mirror: parked with the split OFF, on the shared channel, when the split is
// turned ON. Without a wake it would go on taking WireGuard packets from the
// shared queue — landing them on the synthetic's own allocations, which is the
// exact contamination the split exists to remove.
//
// SABOTAGE SEEN TO FAIL: remove the `case <-splitWakeCh(): continue` from the
// legacy blocking select. Compiles; this test then times out.
func TestParkedWriterWakesWhenTheSplitIsTurnedOn(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	p, cancel := splitTestProxy()
	defer cancel()

	done := make(chan struct{})
	got := make(chan sendItem, 1)
	go func() {
		if item, ok := p.nextSendItem(done, 0); ok {
			got <- item
		}
	}()
	time.Sleep(50 * time.Millisecond) // parks on the shared channel

	SetUplinkSplitN(15)
	_ = p.SendPacketSynth([]byte("synthetic after the flip"))

	select {
	case item := <-got:
		if string(item.buf) != "synthetic after the flip" {
			t.Fatalf("woke with the wrong packet: %q", item.buf)
		}
	case <-time.After(2 * time.Second):
		close(done)
		t.Fatal("a writer parked on the shared channel never learned the pool had been split")
	}
}

// 🚨🚨 THE LOST WAKE-UP THE USER FOUND, and the reason the state and the wake
// live in ONE struct. The failing interleave the previous design allowed:
//
//  1. a writer reads n=15 and picks synthCh;
//  2. SetUplinkSplitN(0) stores the new size, installs a fresh wake and closes
//     the old one;
//  3. only NOW does the writer evaluate the wake channel — and gets the NEW,
//     still-open one;
//  4. it parks on {old synthCh, new wake} and sleeps through the whole arm.
//
// This test states the invariant that makes that impossible, and states it
// DETERMINISTICALLY rather than by racing: whatever snapshot a reader holds, the
// change that supersedes it closes THAT snapshot's channel.
//
// SABOTAGE SEEN TO FAIL: in SetUplinkSplitN close `next.wake` instead of
// `old.wake`. Compiles; the snapshot a reader is holding then never closes.
func TestTheSnapshotYouHoldIsTheOneTheNextChangeCloses(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)

	// A writer would load this and THEN decide — the whole race window.
	st := splitNow()
	if st.n != 15 {
		t.Fatalf("snapshot should read 15, got %d", st.n)
	}

	SetUplinkSplitN(UplinkSplitOff) // the change that happens "in between"

	select {
	case <-st.wake: // closed ⇒ a reader holding this snapshot cannot miss it
	default:
		t.Fatal("the superseded snapshot's wake was not closed — a writer holding it " +
			"would park on the old queue and sleep through the arm")
	}
	// And the fresh snapshot must NOT be closed, or every park would spin.
	select {
	case <-splitNow().wake:
		t.Fatal("the current snapshot's wake must stay open")
	default:
	}
}

// The producer half of the same race: `sendPacketMarked` picks its queue by the
// mode too, and if the split is turned OFF while it is blocked on a full
// synthCh, nothing will ever drain that queue again — the paced generator would
// freeze for the rest of the run.
//
// SABOTAGE SEEN TO FAIL: drop the `case <-st.wake:` from the blocking select in
// sendPacketMarked. Compiles; this test then times out.
func TestBlockedProducerRePicksTheQueueWhenTheSplitChanges(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	SetUplinkSplitN(15)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 4), synthCh: make(chan sendItem, 1)}

	// Fill the synthetic queue so the next send must block.
	if err := p.SendPacketSynth([]byte("first")); err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := make(chan error, 1)
	go func() { sent <- p.SendPacketSynth([]byte("blocked")) }()
	time.Sleep(50 * time.Millisecond) // it is now parked on a full synthCh

	SetUplinkSplitN(UplinkSplitOff) // no reader will ever serve synthCh again

	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("the producer should have re-picked the shared queue, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the producer stayed blocked on a queue nothing will drain — " +
			"the generator would have frozen for the rest of the run")
	}
}

// 🚨🚨 THE STRICT BOUNDARY, and Go's `select` is what breaks it: it picks
// UNIFORMLY AT RANDOM among ready cases, so when the split is armed while a
// writer is parked on the shared channel, a WireGuard packet and the closed wake
// can be ready together — and about half the time the writer takes the packet
// and sends it under the SUPERSEDED mode, onto an allocation that now belongs to
// the synthetic. Real for arms 2-5, where the synthetic is silent in the gap
// while TCP keeps filling the shared queue.
//
// The check therefore happens on the packet, AFTER the dequeue.
//
// SABOTAGE SEEN TO FAIL: delete the `if !splitAdmits(...)` block from the
// non-blocking shared-channel case in nextSendItem. Compiles; writer 0 then
// returns the WireGuard packet it must not send.
func TestAWriterWillNotSendAPacketOfTheSupersededMode(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	p, cancel := splitTestProxy()
	defer cancel()

	// A WireGuard packet queued while the pool is whole…
	if err := p.SendPacketFlow([]byte("queued while shared"), 0); err != nil {
		t.Fatalf("send: %v", err)
	}
	// …and the split armed before any writer picked it up.
	SetUplinkSplitN(15)

	// Writer 0 is now group A. It must NOT hand back that packet, however the
	// runtime happens to schedule it.
	done := make(chan struct{})
	go func() { time.Sleep(300 * time.Millisecond); close(done) }()
	if item, ok := p.nextSendItem(done, 0); ok {
		t.Fatalf("a synthetic-group writer sent a WireGuard packet from the old mode: %q", item.buf)
	}
	// The packet is not lost: a group-B writer still gets it.
	if item, ok := p.nextSendItem(make(chan struct{}), 20); !ok || string(item.buf) != "queued while shared" {
		t.Fatalf("the packet must still be deliverable by group B (ok=%v)", ok)
	}
}

// The post-dequeue half of the same guarantee, made DETERMINISTIC. The race
// itself — the mode flipping between a writer's snapshot and its dequeue —
// cannot be produced on demand, but its CONSEQUENCE can: a packet of the wrong
// kind sitting in the queue a writer serves, which is exactly what a flip
// leaves behind. The writer must return it rather than send it.
//
// SABOTAGE SEEN TO FAIL: delete the `if !splitAdmits(...)` block from the split
// branch's dequeue in nextSendItem. Compiles; writer 20 then sends a synthetic
// packet off the shared queue, onto a WireGuard-group allocation.
func TestAWriterReturnsAPacketThatIsNotItsGroups(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	p, cancel := splitTestProxy()
	defer cancel()
	SetUplinkSplitN(15)

	// A SYNTHETIC packet on the SHARED queue — the leftover shape a mode change
	// produces. Writer 20 serves the shared queue and must not send it.
	p.sendCh <- sendItem{buf: []byte("synthetic on the shared queue"), synth: true}

	done := make(chan struct{})
	go func() { time.Sleep(300 * time.Millisecond); close(done) }()
	if item, ok := p.nextSendItem(done, 20); ok {
		t.Fatalf("a WireGuard-group writer sent a synthetic packet: %q", item.buf)
	}
	// It was moved to the queue its group actually reads, not dropped.
	if got := len(p.synthCh); got != 1 {
		t.Fatalf("the packet should have been requeued to synthCh, found %d there", got)
	}
	if s := splitSummary(); !strings.Contains(s, "requeued=1") || !strings.Contains(s, "leaked=0") {
		t.Fatalf("the rescue must be counted and no leak reported: %q", s)
	}
}

// 🚨🚨 THE LOSSLESS UN-SPLIT, and it is lossless because NOTHING IS TRANSFERRED.
//
// The first design copied the leftovers into the shared queue with a timeout and
// dropped them if it expired — and its put-back could fail too, because the drain
// itself frees the slot a blocked producer immediately takes. A packet the
// generator has already NUMBERED then vanished with no counter, which the server
// reads as network loss.
//
// ⚠️ Waiting was no better: while a leftover sits, the other arm sends thousands
// of newer sequence numbers, and past the receiver's 8128-counter window the
// packet arrives `stale` and the loss never recovers.
//
// ⇒ With the split off a synthetic packet is legal for ANY writer, so the
// ordinary path serves `synthCh` directly. This test states the conservation
// that follows, WITH a concurrent producer competing for the same slots — the
// case the old test never built.
//
// SABOTAGE SEEN TO FAIL: delete the `if len(p.synthCh) > 0` block from
// nextSendItem's step 1b (and the `case item := <-p.synthCh:` from the blocking
// select). Compiles; the leftover is then never delivered and this test times
// out with it still queued.
func TestLeftoversAreDeliveredByTheOrdinaryPathAfterAnUnSplit(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A deliberately tight shared queue, so a producer really does compete.
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 2), synthCh: make(chan sendItem, 8)}

	SetUplinkSplitN(15)
	for _, b := range []string{"leftover-1", "leftover-2", "leftover-3"} {
		if err := p.SendPacketSynth([]byte(b)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	// A producer hammering the shared queue across the switch — the interleave
	// that made the old transfer lose packets.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = p.SendPacketFlow([]byte("wg"), 0)
			}
		}
	}()

	SetUplinkSplitN(UplinkSplitOff)

	got := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(got) < 3 {
		select {
		case <-deadline:
			close(stop)
			t.Fatalf("only %d of 3 leftovers were delivered; %d still queued", len(got), len(p.synthCh))
		default:
		}
		item, ok := p.nextSendItem(make(chan struct{}), 7)
		if !ok {
			continue
		}
		if s := string(item.buf); strings.HasPrefix(s, "leftover-") {
			got[s] = true
		}
	}
	close(stop)

	if s := splitSummary(); !strings.Contains(s, "leftover-sent=3") {
		t.Fatalf("the leftovers served by the ordinary path must be counted: %q", s)
	}
}

// 🚨 A QUEUE THAT SURVIVES AN UN-SPLIT VOIDS THE ARM, and the line has to say so
// where the run is read. The transition is lossless by construction — the
// un-split wakes every writer and they serve `synthCh` on their next loop — but
// if a packet ever DID survive, it would age past the receiver's 8128-counter
// window while the other arm sends newer ones, and become loss that never
// recovers. Silence there would be indistinguishable from success.
//
// SABOTAGE SEEN TO FAIL: drop the `if depth := synthQueueDepth(); depth > 0`
// branch from splitSummary. Compiles; the queue then goes unreported.
func TestASurvivingSyntheticQueueVoidsTheArmLoudly(t *testing.T) {
	resetSplit()
	t.Cleanup(resetSplit)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 4), synthCh: make(chan sendItem, 4)}
	synthDepthHook.Store(func() int { return len(p.synthCh) })
	t.Cleanup(func() { synthDepthHook.Store((func() int)(nil)) })

	SetUplinkSplitN(15)
	_ = p.SendPacketSynth([]byte("stuck"))
	SetUplinkSplitN(UplinkSplitOff) // nobody is running a writer in this test

	s := splitSummary()
	if !strings.Contains(s, "leftover-QUEUED=1") || !strings.Contains(s, "VOID") {
		t.Fatalf("a queue surviving the un-split must void the arm loudly, got %q", s)
	}
}

// 🚨 THE OTHER HALF OF THE WIRING. The test above passes while registering the
// probe itself — which is exactly the trap this project has already paid for
// once: a guard on one half of a two-part hookup buys a green suite and an empty
// log. The field can only appear on a device if NewProxy registers the probe, so
// that is asserted separately.
//
// SABOTAGE SEEN TO FAIL: delete the `synthDepthHook.Store(...)` line from
// NewProxy. Compiles; the summary then never reports a surviving queue on any
// real run.
func TestNewProxyRegistersTheSynthDepthProbe(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("reading proxy.go: %v", err)
	}
	// The declaration lives in uplinksplit.go, so a hit here is a CALL — no
	// risk of matching the symbol's own definition.
	if !strings.Contains(string(src), "synthDepthHook.Store(") {
		t.Fatal("NewProxy no longer registers the synthetic-queue depth probe — " +
			"the summary would never report a queue surviving an un-split")
	}
}
