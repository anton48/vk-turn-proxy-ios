package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
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
	p := &Proxy{ctx: ctx, sendCh: make(chan []byte, 8)}

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
	p := &Proxy{ctx: ctx, sendCh: make(chan []byte, 4), recvCh: make(chan []byte, 4)}

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
