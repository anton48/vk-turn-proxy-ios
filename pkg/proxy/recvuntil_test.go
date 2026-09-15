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

// A closed `done` takes precedence over a queued packet. The select in
// ReceivePacketUntil picks at random among ready cases, so without the
// non-blocking check of `done` first, a call made after Close could still
// return data — the user's reproduction on build 386: 40 of 100 calls after
// Close returned a packet. Every one of 100 calls must be net.ErrClosed and
// the queue must be left exactly as it was: the packets belong to whoever
// receives next with a live bind. Sabotage seen red: the preliminary select
// on `done` dropped — a fraction of the 100 calls returns data.
func TestReceivePacketUntilPrefersAClosedDoneOverAQueuedPacket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 8)}
	for i := 0; i < 8; i++ {
		if !p.enqueueRecv(ctx, []byte{byte(i), 1, 2, 3}) {
			t.Fatal("enqueueRecv failed with room available")
		}
	}
	done := make(chan struct{})
	close(done)
	buf := make([]byte, 64)
	for i := 0; i < 100; i++ {
		n, err := p.ReceivePacketUntil(done, buf)
		if n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("call %d on a closed done with 8 packets queued = (%d, %v), want (0, net.ErrClosed) — a closed bind returned data", i, n, err)
		}
	}
	if got := len(p.recvCh); got != 8 {
		t.Fatalf("the queue holds %d packets after 100 closed calls, want 8 untouched", got)
	}
}

// The re-open pair: after BindUpdate's close+open the OLD ReceiveFunc (its
// done closed) and the NEW one (its done open) share the proxy's queue.
// The user's reproduction on build 386: the old callback returned data in 54
// of 100 calls — packets the new routine never saw. The old must answer
// net.ErrClosed every time without touching the queue; the new must then
// receive every queued packet. Sabotage seen red: the preliminary select
// on `done` dropped.
func TestReceivePacketUntilOldDoneNeverStealsFromTheNewReceiver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, recvCh: make(chan []byte, 8)}
	for i := 0; i < 8; i++ {
		if !p.enqueueRecv(ctx, []byte{byte(i), 9, 9}) {
			t.Fatal("enqueueRecv failed with room available")
		}
	}
	oldDone := make(chan struct{})
	close(oldDone)
	newDone := make(chan struct{})
	buf := make([]byte, 64)
	for i := 0; i < 100; i++ {
		if n, err := p.ReceivePacketUntil(oldDone, buf); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("old receiver call %d = (%d, %v), want (0, net.ErrClosed) — the old bind stole a packet from the new one", i, n, err)
		}
	}
	for i := 0; i < 8; i++ {
		n, err := p.ReceivePacketUntil(newDone, buf)
		if err != nil || n != 3 || buf[0] != byte(i) {
			t.Fatalf("new receiver packet %d = (%d, %v, first byte %d), want (3, nil, %d) — the queue was not left intact and in order", i, n, err, buf[0], i)
		}
	}
}
