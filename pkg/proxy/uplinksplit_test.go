package proxy

import (
	"context"
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
	if !strings.Contains(s, "split=15") || !strings.Contains(s, "synth-pkts=1") ||
		!strings.Contains(s, "wg-pkts=1") {
		t.Fatalf("both groups must be reported, got %q", s)
	}
	if again := splitSummary(); !strings.Contains(again, "synth-pkts=0 wg-pkts=0") {
		t.Fatalf("the counters must read and reset, got %q", again)
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
