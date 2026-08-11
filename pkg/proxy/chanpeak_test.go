package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// notePeak is a high-water mark, so it must rise and never fall — and it must
// survive concurrent producers, which is the only reason it is a CAS loop.
func TestNotePeakKeepsTheMaximum(t *testing.T) {
	var m atomic.Int64
	for _, d := range []int{3, 7, 2, 7, 1, 11, 0, 5} {
		notePeak(&m, d)
	}
	if got := m.Load(); got != 11 {
		t.Fatalf("peak = %d, want 11 — a high-water mark that falls back reports "+
			"the last sample, which is the very thing this replaces", got)
	}

	var c atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= 64; i++ {
		wg.Add(1)
		go func(d int) { defer wg.Done(); notePeak(&c, d) }(i)
	}
	wg.Wait()
	if got := c.Load(); got != 64 {
		t.Fatalf("concurrent peak = %d, want 64 — a lost update dropped the max", got)
	}
}

// THE POINT OF THE WHOLE CHANGE. The old diagnostic sampled len(sendCh) every
// few seconds; these queues drain in microseconds, so it read 0 during every
// loaded period we ever measured and told us nothing. The peak must catch a
// backlog that exists only between two samples.
func TestSendChPeakCatchesABacklogAnInstantaneousSampleWouldMiss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8)}

	// Fill the queue without draining — a producer burst with no consumer.
	for i := 0; i < 5; i++ {
		if err := p.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	}
	// ...then drain it completely, so an observer sampling NOW sees an empty
	// queue. This is exactly the situation the old heartbeat was in.
	for len(p.sendCh) > 0 {
		<-p.sendCh
	}
	if len(p.sendCh) != 0 {
		t.Fatal("test setup: the queue should be empty at the sampling moment")
	}

	peak := p.sendChPeak.Load()
	if peak != 5 {
		t.Fatalf("peak = %d, want 5. The queue held 5 packets and is empty now; "+
			"an instantaneous sample would report 0 and be read as 'the uplink "+
			"never backs up'", peak)
	}

	// Read-and-reset: the next interval must start clean, or one early burst
	// would mark every later line as backed up.
	if got := p.sendChPeak.Swap(0); got != 5 {
		t.Fatalf("Swap returned %d, want 5", got)
	}
	if got := p.sendChPeak.Load(); got != 0 {
		t.Fatalf("peak did not reset: %d", got)
	}
}

// The counter must track the SEND path only — a receive-side backlog attributed
// to the uplink would send the next investigation in the wrong direction.
func TestSendAndRecvPeaksAreSeparate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 4), recvCh: make(chan []byte, 4)}

	for i := 0; i < 3; i++ {
		if err := p.SendPacket([]byte{1}); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	}
	if p.recvChPeak.Load() != 0 {
		t.Fatalf("uplink traffic moved the RECEIVE peak to %d", p.recvChPeak.Load())
	}
	if p.sendChPeak.Load() != 3 {
		t.Fatalf("send peak = %d, want 3", p.sendChPeak.Load())
	}
}

// Blocked time is the number that closes the question the peak could only hint
// at, so it has to be exactly zero when nothing waited and clearly non-zero
// when something did.
func TestSendBlockedTimeIsZeroWhenThereIsRoom(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8)}

	for i := 0; i < 8; i++ {
		if err := p.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	}
	// The queue is now exactly full, but no send ever had to wait for room.
	if n := p.sendChBlockCount.Load(); n != 0 {
		t.Fatalf("%d sends recorded as blocked while the queue always had room — "+
			"a false positive here would invent a bottleneck that is not there", n)
	}
	if ns := p.sendChBlockNs.Load(); ns != 0 {
		t.Fatalf("blocked time %dns with nothing to wait for", ns)
	}
}

func TestSendBlockedTimeMeasuresARealWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 1)}

	if err := p.SendPacket([]byte{1}); err != nil { // fills it
		t.Fatalf("SendPacket: %v", err)
	}
	// Free a slot only after a delay; the next send must wait for it.
	const wait = 40 * time.Millisecond
	go func() { time.Sleep(wait); <-p.sendCh }()

	if err := p.SendPacket([]byte{2}); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	if n := p.sendChBlockCount.Load(); n != 1 {
		t.Fatalf("blocked count = %d, want 1", n)
	}
	if ns := p.sendChBlockNs.Load(); ns < int64(wait/2) {
		t.Fatalf("blocked time %v, want at least ~%v — the counter is not "+
			"measuring the wait it exists for", time.Duration(ns), wait/2)
	}
}

// A cancelled context must not be charged as queue pressure, or a teardown
// would look like a bottleneck.
func TestSendBlockedTimeOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 1)}
	if err := p.SendPacket([]byte{1}); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if err := p.SendPacket([]byte{2}); err == nil {
		t.Fatal("SendPacket returned nil after its context was cancelled")
	}
	if n := p.sendChBlockCount.Load(); n != 0 {
		t.Fatalf("a cancelled send was counted as %d blocked write(s)", n)
	}
}

// The receive side gets the same treatment, and must not charge a cancelled
// enqueue either — the caller still owns the packet in that case.
func TestEnqueueRecvBlockedTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 1)}

	if !p.enqueueRecv(ctx, []byte{1}) {
		t.Fatal("first enqueue failed with room available")
	}
	if p.recvChBlockCount.Load() != 0 {
		t.Fatal("an unblocked enqueue was counted as blocked")
	}

	go func() { time.Sleep(30 * time.Millisecond); <-p.recvCh }()
	if !p.enqueueRecv(ctx, []byte{2}) {
		t.Fatal("second enqueue failed")
	}
	if p.recvChBlockCount.Load() != 1 {
		t.Fatalf("blocked count = %d, want 1", p.recvChBlockCount.Load())
	}

	dead, stop := context.WithCancel(context.Background())
	stop()
	if p.enqueueRecv(dead, []byte{3}) {
		t.Fatal("enqueueRecv reported success on a dead context — the caller " +
			"would then not return the packet to the pool")
	}
}
