// SPDX-License-Identifier: MIT
package csqtt

import (
	"errors"
	"sync/atomic"
	"time"
)

const workerQueuePackets = 32
const workerQueueBytes = 64 * 1024

var errWorkerQueueFull = errors.New("csqtt: worker queue full")

type queuedPacket struct {
	data  []byte
	epoch uint64
}

// qualityState measures LOCAL write backpressure, not end-to-end delivery or
// inferred loss from tx/rx ratios (traffic may legitimately be one-way).
type qualityState struct {
	pending     atomic.Int64 // bytes, including the in-flight write
	writeCost   atomic.Int64 // EWMA nanoseconds per KiB
	sampledAt   atomic.Int64
	failedUntil atomic.Int64
}

func (q *qualityState) observe(size int, elapsed time.Duration, err error, now time.Time) {
	if err != nil {
		q.failedUntil.Store(now.Add(time.Second).UnixNano())
		return
	}
	if size < 1 {
		return
	}
	cost := int64(elapsed) * 1024 / int64(size)
	if cost < int64(100*time.Microsecond) {
		cost = int64(100 * time.Microsecond)
	}
	if cost > int64(time.Second) {
		cost = int64(time.Second)
	}
	for {
		old := q.writeCost.Load()
		next := cost
		if old != 0 {
			next = (old*7 + cost) / 8
		}
		if q.writeCost.CompareAndSwap(old, next) {
			break
		}
	}
	q.sampledAt.Store(now.UnixNano())
}

func (q *qualityState) cost(now time.Time) int64 {
	cost := q.writeCost.Load()
	if cost == 0 || now.UnixNano()-q.sampledAt.Load() > int64(30*time.Second) {
		cost = int64(100 * time.Microsecond)
	}
	// Queue pressure matters before a slow WriteTo has even completed.
	cost *= 1 + q.pending.Load()/(8*1024)
	if now.UnixNano() < q.failedUntil.Load() {
		cost += int64(time.Second)
	}
	return cost
}

func (w *worker) queuePacket(p []byte) error {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	epoch := w.sessionEpoch.Load()
	if w.queueClosed || !w.ready.Load() || w.c.ctx.Err() != nil {
		return errNoWorker
	}
	if len(p) > workerQueueBytes {
		return errWorkerQueueFull
	}
	for {
		used := w.quality.pending.Load()
		if used+int64(len(p)) > workerQueueBytes {
			return errWorkerQueueFull
		}
		if w.quality.pending.CompareAndSwap(used, used+int64(len(p))) {
			break
		}
	}
	packet := queuedPacket{data: append([]byte(nil), p...), epoch: epoch}
	select {
	case w.queue <- packet:
		return nil
	default:
		w.quality.pending.Add(-int64(len(p)))
		return errWorkerQueueFull
	}
}

func (w *worker) writeQueued() {
	defer w.c.wg.Done()
	defer func() {
		w.queueMu.Lock()
		defer w.queueMu.Unlock()
		w.queueClosed = true
		for {
			select {
			case p := <-w.queue:
				w.quality.pending.Add(-int64(len(p.data)))
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-w.c.ctx.Done():
			return
		case p := <-w.queue:
			start := time.Now()
			err := w.sendEpoch(p.data, p.epoch)
			w.quality.pending.Add(-int64(len(p.data)))
			if errors.Is(err, errNoWorker) {
				w.c.queueDrops.Add(1)
				continue // old session: never deliver its packets in a new one
			}
			if err != nil {
				w.c.queueDrops.Add(1)
			}
			w.mu.Lock()
			// A delayed write result must not penalize or restart a replacement
			// allocation. Session installation uses the same mutex.
			if p.epoch == w.sessionEpoch.Load() && w.ready.Load() {
				w.quality.observe(len(p.data), time.Since(start), err, time.Now())
				if err != nil {
					w.ready.Store(false)
					w.restart("write error")
				}
			}
			w.mu.Unlock()
		}
	}
}

func (c *Client) workerCost(i int) int64 { return c.workers[i].quality.cost(time.Now()) }

// dispatchPacket only falls back when a queue has NOT accepted the packet.
// Never replay a failed WriteTo: it may already have reached the server.
func (c *Client) dispatchPacket(first int, p []byte) error {
	if !c.cfg.QualityScheduling {
		return c.workers[first].send(p)
	}
	for offset := 0; offset < len(c.workers); offset++ {
		w := c.workers[(first+offset)%len(c.workers)]
		if w.queuePacket(p) == nil {
			return nil
		}
	}
	c.queueDrops.Add(1)
	return errWorkerQueueFull
}
