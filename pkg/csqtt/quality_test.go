// SPDX-License-Identifier: MIT
package csqtt

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
)

func TestWeightedStriperReducesSlowShareWithoutStarving(t *testing.T) {
	s := NewStriper(2)
	counts := [2]int{}
	for i := 0; i < 720; i++ {
		counts[s.PickWeighted(ClassBulk, func(int) bool { return true }, func(i int) int64 { return [2]int64{1, 8}[i] })]++
	}
	if counts[0] != 640 || counts[1] != 80 {
		t.Fatal(counts)
	}
	a, b := NewStriper(3), NewStriper(3)
	for i := 0; i < 1000; i++ {
		class := PacketClass(i % 3)
		alive := func(i int) bool { return i != 1 }
		if a.Pick(class, alive) != b.PickWeighted(class, alive, func(int) int64 { return 100 }) {
			t.Fatal("equal quality changed legacy schedule")
		}
	}
}

func TestQualitySignalsExpireAndCountQueuePressure(t *testing.T) {
	var q qualityState
	now := time.Now()
	base := q.cost(now)
	q.observe(1024, time.Millisecond, nil, now)
	if q.cost(now) <= base {
		t.Fatal("slow write not observed")
	}
	before := q.cost(now)
	q.pending.Store(16 * 1024)
	if q.cost(now) <= before {
		t.Fatal("in-flight queue pressure ignored")
	}
	q.pending.Store(0)
	if q.cost(now.Add(31*time.Second)) != base {
		t.Fatal("stale measurement never expired")
	}
	q.observe(100, 0, errors.New("write"), now)
	if q.cost(now) < int64(time.Second) {
		t.Fatal("failed write not penalized")
	}
}

func TestWorkerQueueBoundsOwnsBytesAndDropsOldEpoch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{ctx: ctx}
	w := newWorker(c, 1, nil)
	w.ready.Store(true)
	w.sessionEpoch.Store(1)
	p := bytes.Repeat([]byte{42}, workerQueueBytes)
	if err := w.queuePacket(p); err != nil {
		t.Fatal(err)
	}
	p[0] = 99
	if err := w.queuePacket([]byte{1}); !errors.Is(err, errWorkerQueueFull) {
		t.Fatal(err)
	}
	queued := <-w.queue
	if queued.data[0] != 42 {
		t.Fatal("queue retained the caller's buffer")
	}
	w.queue <- queued
	w.sessionEpoch.Store(2)
	c.wg.Add(1)
	go w.writeQueued()
	waitFor(t, "stale packet dropped", func() bool { return c.queueDrops.Load() == 1 })
	cancel()
	c.wg.Wait()
	if w.quality.pending.Load() != 0 {
		t.Fatal("queue accounting leaked")
	}
	if err := w.queuePacket(p); !errors.Is(err, errNoWorker) {
		t.Fatal("closed queue accepted packet", err)
	}
}

func TestWorkerQueuePacketLimit(t *testing.T) {
	w := newWorker(&Client{ctx: context.Background()}, 1, nil)
	w.ready.Store(true)
	w.sessionEpoch.Store(1)
	for i := 0; i < workerQueuePackets; i++ {
		if err := w.queuePacket([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.queuePacket([]byte{1}); !errors.Is(err, errWorkerQueueFull) {
		t.Fatal("packet cap not enforced", err)
	}
	if w.quality.pending.Load() != workerQueuePackets {
		t.Fatal("failed enqueue leaked budget")
	}
}

type gatedWriteConn struct {
	net.PacketConn
	block   atomic.Bool
	entered chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (c *gatedWriteConn) WriteTo(p []byte, to net.Addr) (int, error) {
	if c.block.Load() {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		<-c.unblock
	}
	return c.PacketConn.WriteTo(p, to)
}

func (c *gatedWriteConn) Close() error {
	c.once.Do(func() { close(c.unblock) })
	return c.PacketConn.Close()
}

func TestQualitySchedulingBlockedWriterDoesNotBlockHealthyRelay(t *testing.T) {
	srv := newFakeServer(t)
	prev := dialRelay
	var calls atomic.Int32
	var slow atomic.Pointer[gatedWriteConn]
	dialRelay = func(TURNCredentials, *net.UDPAddr, string, logging.LogLevel) (*Relay, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		if calls.Add(1) == 2 {
			g := &gatedWriteConn{PacketConn: pc, entered: make(chan struct{}, 1), unblock: make(chan struct{})}
			slow.Store(g)
			pc = g
		}
		return &Relay{Conn: pc, Local: pc.LocalAddr(), close: func() { pc.Close() }}, nil
	}
	t.Cleanup(func() { dialRelay = prev })
	cfg := testConfig(srv, 2, (&lease{}).creds)
	cfg.QualityScheduling = true
	c := dialReady(t, cfg)
	defer c.Close()
	slow.Load().block.Store(true)
	packet := ipv4UDP(1200)
	if err := c.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-slow.Load().entered:
	case <-time.After(time.Second):
		t.Fatal("slow relay was not exercised")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = c.WritePacket(packet)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("one blocked relay stalled the TUN writer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := c.ReadPacket(ctx)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatal("healthy relay stopped delivering", err)
	}
	for _, ws := range c.Stats().Workers {
		if ws.QueuedBytes > workerQueueBytes {
			t.Fatal("unbounded queue", ws)
		}
	}
	start := time.Now()
	c.Close()
	if time.Since(start) > 3*time.Second {
		t.Fatal("blocked writer prevented shutdown")
	}
}
