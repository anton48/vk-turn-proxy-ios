// SPDX-License-Identifier: MIT

package csqtt

// The bounded write queue (build 437, 2026-09-23): one goroutine per worker
// writes that worker's data packets from a queue the TUN pump fills WITHOUT
// waiting. Before it, WritePacket wrote synchronously under w.mu and the TUN
// pump — its ONE caller — stood behind whichever WriteTo was blocked: on the
// TCP transport a relay that stops taking bytes fills its socket buffer and
// then holds the whole uplink, every allocation behind one, until the
// liveness rule restarts that worker (35–60 s; noted 2026-09-06 and left).
// Now a stuck writer holds its own queue and nothing else.
//
// 🚫 What the queue does NOT do, on purpose — the measurement behind
// DefaultChunks (2026-09-04, tcp8/tcp9): it never moves a packet to another
// worker. The csqtt server reassembles a flow's CQF1 frames with a 12-ms gap
// window, and consecutive packets of one flow on DIFFERENT allocations are
// what collapsed TCP upload 5–6×. So a worker whose queue has no room is
// passed over where a NEW chunk begins — the striper's boundary, where the
// schedule moves on anyway — and inside a chunk a packet that finds its queue
// full is DROPPED, never handed to a neighbour; a failed write is never
// written again (it may have reached the server).
//
// A queued packet belongs to the session it was queued under: the item
// carries the worker's session epoch and the writer drops what predates the
// current one — the packets of a dead allocation must not go out through its
// replacement as a burst of seconds-old segments.
//
// With Config.WriteQueue = 0 none of this exists: WritePacket writes
// synchronously, as every build before 437 did.

import (
	"errors"
	"sync"
	"sync/atomic"
)

// DefaultWriteQueue is the depth of a worker's write queue, in packets, when
// the queue is on. At least the bulk chunk, so a chunk that starts on an
// empty queue fits whole; 64 packets × 30 workers × ≤ 2 KiB is under 4 MiB
// with EVERY queue full at once, which only a dead path produces.
const DefaultWriteQueue = 64

var (
	errQueueFull    = errors.New("csqtt: the worker's write queue is full")
	errStaleSession = errors.New("csqtt: queued under a session that has ended")
)

// outItem is one queued packet: its bytes (a pooled buffer the writer gives
// back after the write) and the session epoch it was queued under.
type outItem struct {
	buf   *[]byte
	epoch uint64
}

// outPool holds the queued packets' buffers. A packet is COPIED into one at
// the enqueue: the TUN pump reuses its read buffer, and the CQF1 frame lives
// in the worker's frameBuf — neither may be aliased by a queue the pump has
// already moved on from.
var outPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 2048)
	return &b
}}

// queueRoom is how many free slots a worker's queue must have where a chunk
// of class c BEGINS on it: the chunk, or half the queue when the chunk is
// larger — so a bulk chunk (64 = the depth) starts on a queue at most half
// full and is dropped only if the writer drains NOTHING while it arrives.
func queueRoom(chunk, depth int) int {
	if half := depth / 2; chunk > half {
		return half
	}
	return chunk
}

// roomFor is the striper's boundary predicate: worker i is ready and its
// queue has room for a chunk of class c. With the queue off there is no
// queue to fill, and every ready worker has room.
func (c *Client) roomFor(i int, class PacketClass) bool {
	w := c.workers[i]
	if !w.ready.Load() {
		return false
	}
	if w.outQ == nil {
		return true
	}
	return cap(w.outQ)-len(w.outQ) >= queueRoom(c.striper.Chunk(class), cap(w.outQ))
}

// dispatch hands one packet to worker w — synchronously with the queue off,
// through the queue with it on.
func (c *Client) dispatch(w *worker, p []byte) error {
	if w.outQ == nil {
		return w.send(p)
	}
	return w.enqueue(p)
}

// enqueue copies p into the worker's queue, or drops it: a full queue is a
// dropped packet — as a NIC's queue drops — never a wait (the wait is what
// held the whole uplink behind one relay) and never a move to another
// worker (the reorder the server punishes).
func (w *worker) enqueue(p []byte) error {
	b := outPool.Get().(*[]byte)
	*b = append((*b)[:0], p...)
	select {
	case w.outQ <- outItem{buf: b, epoch: w.epoch.Load()}:
		return nil
	default:
		outPool.Put(b)
		w.queueFull.Add(1)
		w.c.queueFull.Add(1)
		return errQueueFull
	}
}

// writeLoop is the worker's writer: it writes the queue's packets one after
// another, for the worker's whole life. A WriteTo that blocks blocks this
// goroutine and nothing else; the session's teardown closes the relay, which
// frees it, and what was queued under that session is then dropped as stale.
func (w *worker) writeLoop() {
	defer w.c.wg.Done()
	for {
		if w.c.ctx.Err() != nil {
			return
		}
		select {
		case <-w.c.ctx.Done():
			return
		case it := <-w.outQ:
			if hook := writeLoopTook.Load(); hook != nil {
				(*hook)(w)
			}
			err := w.sendData(*it.buf, it.epoch)
			outPool.Put(it.buf)
			switch {
			case errors.Is(err, errStaleSession):
				w.c.queueStale.Add(1)
			case err != nil:
				w.c.writeErrs.Add(1)
			}
		}
	}
}

// writeLoopTook is a test's window INSIDE the writer, between the dequeue and
// the write — where a writer descheduled across a restart (an iOS freeze in
// the middle of one) holds a packet of the old session while the new one is
// installed. nil in production.
var writeLoopTook atomic.Pointer[func(*worker)]

// sendData writes one queued packet, under the session it was queued for:
// a packet of an older session — or of none, the relay gone — is stale and
// is not written. The lock and the write are send's.
func (w *worker) sendData(plain []byte, epoch uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.relay == nil || w.wrapper == nil || epoch != w.epoch.Load() {
		return errStaleSession
	}
	return w.writeLocked(plain)
}

// anyReady says whether any worker is ready — with the queue on, a Pick that
// found nobody then found the queues without room, not the pool without a
// worker.
func (c *Client) anyReady() bool {
	for _, w := range c.workers {
		if w.ready.Load() {
			return true
		}
	}
	return false
}

// queued is what the worker's queue holds now (0 with the queue off).
func (w *worker) queued() int {
	if w.outQ == nil {
		return 0
	}
	return len(w.outQ)
}
