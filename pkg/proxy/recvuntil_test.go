package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// ReceivePacketUntil returns net.ErrClosed when `done` is closed — the one
// error wireguard-go's receive routine exits on — without a proxy stop, and
// a nil `done` changes nothing: a queued packet is still delivered. This is
// what lets turnbind's Close wake a receiver parked on a live proxy (build
// 386); before it, only the proxy's stop could. Sabotage seen red: the
// `case <-done` dropped from the select — the receiver stays parked and the
// test fails at its 2-second guard.
func TestReceivePacketUntilReturnsErrClosedWhenDoneCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 4)}

	// A nil done never fires: a queued packet arrives as through ReceivePacket.
	if !p.enqueueRecv(ctx, []byte{1, 2, 3}) {
		t.Fatal("enqueueRecv failed with room available")
	}
	buf := make([]byte, 64)
	if n, err := p.ReceivePacketUntil(nil, buf); err != nil || n != 3 {
		t.Fatalf("ReceivePacketUntil(nil) = (%d, %v), want (3, nil)", n, err)
	}

	// Parked on an empty queue, released by done alone — the context is live.
	done := make(chan struct{})
	type result struct {
		n   int
		err error
	}
	got := make(chan result, 1)
	go func() {
		n, err := p.ReceivePacketUntil(done, buf)
		got <- result{n, err}
	}()
	select {
	case r := <-got:
		t.Fatalf("ReceivePacketUntil returned (%d, %v) with nothing queued and done open", r.n, r.err)
	case <-time.After(100 * time.Millisecond):
	}
	started := time.Now()
	close(done)
	select {
	case r := <-got:
		if r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("after close(done): (%d, %v), want (0, net.ErrClosed)", r.n, r.err)
		}
		if took := time.Since(started); took > 100*time.Millisecond {
			t.Fatalf("the receiver took %s to wake on done", took)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReceivePacketUntil did not return within 2 s of close(done) — the done case is missing from its select")
	}
	if ctx.Err() != nil {
		t.Fatal("the proxy context was cancelled — the wake must not come from a stop")
	}
}
