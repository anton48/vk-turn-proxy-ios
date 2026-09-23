// SPDX-License-Identifier: MIT

package csqtt

// The bounded relay write (build 438, 2026-09-23).
//
// THE ORDER. The TUN pump — the ONE caller of WritePacket — writes to the
// relays synchronously and therefore IN ORDER across the workers: chunk k's
// last packet has entered worker A's socket before chunk k+1's first packet
// is handed to worker B. That order is not an accident of the old path, it is
// what the csqtt server's CQF1 reassembly lives on: a flow's frames are held
// for a 12-ms gap and whatever arrives later than a released successor is
// dropped as backward — so a chunk that OVERTAKES the one before it costs the
// whole of the earlier chunk. Build 437 put a queue and a writer goroutine
// behind every worker to spare the pump a stuck relay, and with it worker B's
// chunk left while worker A's writer still held the chunk before it: a writer
// delayed 30 ms lost 64 of 65 packets after reassembly, 3 of 3 (the user's
// review, 2026-09-23). Nothing in this package lets a later chunk run ahead
// of an earlier one: the write is synchronous, and the only thing bounded is
// how long the pump may WAIT for it.
//
// THE BOUND. A relay that stops taking bytes — a dead TCP relay, its socket
// buffer full — held the pump's write, and with it the whole uplink, until
// the liveness rule restarted that worker, 35–60 s later (noted 2026-09-06
// and left). Now every relay write runs under a deadline, Config.WriteStall:
// a write the relay has not taken within it is a STALL — the packet is
// dropped and counted (errWriteStalled to the caller), the worker is marked
// not ready at once (the striper hands the rest of its chunk to the next live
// worker, as after any dead one, and begins no chunk on it) and restarted —
// a TCP stream cut inside a frame is no stream: the allocation is given back
// and a fresh one dialled. The uplink stood for the bound, once.
//
// THE NUMBER. DefaultWriteStall sits above every wait a HEALTHY relay makes
// a write take: at the policer's knee a full socket buffer frees room for the
// next packet every few milliseconds, and a retransmission timeout on the
// relay's TCP connection (Darwin's rtt_min of 100 ms plus its 200-ms slop,
// doubling) holds it for hundreds of milliseconds — a second of no progress
// is a relay that has stopped, not one that is slow; and it is far below the
// liveness rule's thirty seconds. Several relays stuck at once cost one bound
// each, in turn. With Config.WriteStall = 0 no deadline is set: the write
// waits as long as the relay makes it, as every build before 438 did.

import (
	"errors"
	"time"
)

// DefaultWriteStall is the bound the app puts on a relay write (see above).
const DefaultWriteStall = time.Second

// errWriteStalled is what a caller hears of a write the relay did not take
// within the bound: the packet was dropped and the worker is being restarted.
var errWriteStalled = errors.New("csqtt: the relay took no bytes within the write's bound — the packet is dropped, the worker restarted")

// stalled is the verdict on a write the relay did not take within the bound,
// under w.mu from writeLocked: counted — the client's total and this worker's
// own, which relay stalls is what a log has to say — the worker not ready at
// once, and restarted. The restart's teardown closes the relay, which frees
// whatever else waits on it (a probe's write; the deallocate goes out under
// its own budget).
func (w *worker) stalled(bound time.Duration) {
	w.stalls.Add(1)
	w.c.writeStalls.Add(1)
	w.markNotReady()
	w.c.cfg.Logf("csqtt: worker %d: the relay took no bytes for %s — a stalled write; the packet is dropped and the worker restarted", w.id, bound)
	w.restart("write stalled: the relay took no bytes for " + bound.String())
}

// markNotReady is the ONE place a worker stops being ready — the session's
// teardown, and a stall's verdict before it: the flag, the moment it became
// ready and the probe that is out go together. A worker read as ready is one
// the striper may begin a chunk on; a stalled one must not be, from the very
// next packet.
func (w *worker) markNotReady() {
	w.ready.Store(false)
	w.readyAt.Store(0)
	w.clearProbe()
}
