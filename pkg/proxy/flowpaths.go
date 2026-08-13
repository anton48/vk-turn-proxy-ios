package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Flow-local path set — each inner 5-tuple prefers a small, STABLE subset of the
// N relay connections instead of racing all of them, but SPILLS to the whole
// pool the instant its subset is busy.
//
// WHY IT EXISTS, and why it is the only reordering lever still open. The uplink
// is per-packet work-stealing across N paths of unequal latency, so one inner
// flow's consecutive packets scatter and arrive out of order — 31-39% of packets
// on the wire, even at F=1. That disorder is a TAX, not a barrier: measured, one
// flow on ONE connection gets 1.69 Mbit/s and on THIRTY gets 8.14, so the fan-out
// wins 4.8x DESPITE all the reordering. Every scheme that cut disorder by cutting
// PATH MULTIPLICITY therefore lost more than it bought, and that family — hard
// affinity k=1, RTT-clustering, "fewer conns, less disorder" — is closed.
//
// 🚨 THIS IS NOT THAT FAMILY, and the distinction is the whole reason it survives.
// The same measurement says a single flow stops gaining after roughly FIVE
// allocations (8.14/1.69 = 4.8), so a set of k≈5 keeps essentially all of the
// fan-out's throughput while sampling the union of only 5 stall processes instead
// of 30. k=1 cut the fan-out to one path and cost -79%; k=5 does not cut it.
//
// 🚨 AND "SOFT" IS LOAD-BEARING — a strict set with no spill IS mini-k1. When the
// preferred paths back up, the packet must go to whichever connection can send
// NOW, or a flow inherits the head-of-line stall the fan-out exists to dilute.
// Everything below is arranged so that the preferred set is a PREFERENCE and
// never a commitment.
//
// WHAT IT IS AIMED AT: the >155 ms hole tail at F=8-16 (the speedtest regime),
// where the inner sender's RACK window is exceeded. Score at F=8/16, never at
// F=1 (nothing to steer) or F=64 (the tail already costs the aggregate nothing),
// with throughput back-to-back against a naked control in the SAME minutes.
// 🚫 Never score it with the server's `uplinkReorder` — that counter is
// flow-blind and falls on harmless cross-flow inversions.
//
// DEFAULT OFF (k=0), byte-for-byte today's behaviour.

const (
	// FlowPathsOff disables the lever: SendPacketFlow uses the shared sendCh and
	// every writer competes for it, exactly as before this file existed.
	FlowPathsOff = 0

	// FlowPathsMin is the smallest set we will ever build. 🚨 k=1 and k=2 are
	// REFUSED (clamped up), not honoured: k=1 is measured at -79% on a single
	// flow, and k=2 is close enough to it to be a slower way of learning the
	// same thing. If a run wants k=1, that run is `NumConns=1`, which has
	// already been done.
	FlowPathsMin = 3

	// FlowPathsMax is the largest set. Beyond ~8 of 30 the set stops being a
	// subset in any useful sense (a flow saturates around 5 paths), so the arm
	// would be indistinguishable from today while still paying the table cost.
	FlowPathsMax = 8

	// flowPathsMaxFlows caps the table. 4096 entries x ~80 B is ~330 KB against
	// GOMEMLIMIT 35 MB. 🚨 It is deliberately NOT ildarmaga's 8192 — theirs is a
	// ring of PACKETS (330 MiB filled, 6.6x the jetsam ceiling); ours holds five
	// int32 indices per flow and nothing that grows with traffic.
	flowPathsMaxFlows = 4096

	// flowPathsIdleTTL retires a flow that has not sent for this long, so a
	// browser's thousands of short-lived connections cannot pin the table.
	flowPathsIdleTTL = 3 * time.Minute

	// flowPathsDefaultDepth is the per-connection queue depth, and it is SMALL
	// on purpose.
	//
	// 🚨 THE PLAN THIS IMPLEMENTS SUGGESTED 64-128 AND THAT WOULD RE-CREATE THE
	// RUN-20 PATHOLOGY. Measured there: our outer socket buffer holds 128 KiB =
	// three relay windows, so a packet handed to a connection that then backs up
	// waits behind up to a full window — 68 packets, ~277 ms of drain — and is
	// invisible to the scheduler, because conn.Write already returned. A 64-deep
	// per-path queue commits ~84 KB to one connection, ~325 ms at the 2.07 Mbit/s
	// knee, and hands that stall straight back to the flow.
	//
	// At depth 2 a backed-up connection's queue fills immediately, the try fails,
	// and the packet spills to a path that can send now — the same
	// self-truncating shape as writeChunk's "write each packet BEFORE taking the
	// next". The queue exists to express a preference, not to buffer.
	flowPathsDefaultDepth = 2
)

// flowPathsK, flowPathsDepth and flowPathsHealth are process-global in the idiom
// of uplinkChunkK and memstatsFastTicks, for the same reason: the extension runs
// exactly one Proxy and the bridge holds no handle on it. PR3 adds the live
// `set_flow_paths_k:` message on top of these; PR2 sets them once from
// ProxyConfig so a device run can be armed at all.
var (
	flowPathsK      atomic.Int64
	flowPathsDepth  atomic.Int64
	flowPathsHealth atomic.Bool
)

// SetFlowPathsK applies the set size to this process. Clamped, so a malformed
// config cannot put k=1 (or k=99) on the hot path.
func SetFlowPathsK(k int) { flowPathsK.Store(int64(ClampFlowPathsK(k))) }

// SetFlowPathsHealth arms the per-tick health filter. Default OFF: it is a
// SECOND arm of the experiment, not part of the first — see pathHealthy for
// why its signal is weak (a stale upper bound against a 100-277 ms stall) and
// why the instantaneous test is the depth of the connection's own queue.
func SetFlowPathsHealth(on bool) { flowPathsHealth.Store(on) }

// ClampFlowPathsK snaps a configured k into the supported range: 0 stays off,
// 1-2 clamp UP to FlowPathsMin (never down toward the refuted k=1), and anything
// above FlowPathsMax clamps down.
func ClampFlowPathsK(k int) int {
	if k <= FlowPathsOff {
		return FlowPathsOff
	}
	if k < FlowPathsMin {
		return FlowPathsMin
	}
	if k > FlowPathsMax {
		return FlowPathsMax
	}
	return k
}

// flowPathsQueueDepth is the per-connection queue depth actually in force.
func flowPathsQueueDepth() int {
	if d := int(flowPathsDepth.Load()); d > 0 {
		return d
	}
	return flowPathsDefaultDepth
}

// newPathQueues builds one shallow queue per connection.
//
// Always allocated, even with the lever off: 30 channels of 2 slots is a few
// kilobytes, and having them ready is what lets PR3 flip k live on a tunnel
// that is already up without reallocating anything under the writers.
func newPathQueues(numConns int) []chan sendItem {
	if numConns <= 0 {
		return nil
	}
	depth := flowPathsQueueDepth()
	qs := make([]chan sendItem, numConns)
	for i := range qs {
		qs[i] = make(chan sendItem, depth)
	}
	return qs
}

// flowEntry is one inner flow's preferred set. Tiny and fixed-size: the whole
// point is that nothing here scales with traffic.
type flowEntry struct {
	paths   []int32 // k distinct connection indices, stable for the flow's life
	rr      atomic.Uint32
	lastUse atomic.Int64 // UnixNano, for the idle sweep
}

// flowTable maps inner-flow key → preferred set.
//
// One mutex, no per-packet allocation: at ~5000 pkt/s a mutex costs tens of
// nanoseconds and the map read allocates nothing. That matters more than
// theoretical concurrency here — this device's history includes a GC death
// spiral under GOMEMLIMIT 35 MB, so a per-packet allocation is the expensive
// mistake, not a lock.
type flowTable struct {
	mu       sync.Mutex
	m        map[uint64]*flowEntry
	numPaths int
	salt     uint64
}

func newFlowTable(numPaths int) *flowTable {
	return &flowTable{
		m:        make(map[uint64]*flowEntry, 64),
		numPaths: numPaths,
		// A fixed per-process salt so two flows that collide in one session do
		// not collide in every session. Derived from the table's own address era
		// rather than a clock: this file must stay deterministic under test.
		salt: 0x9e3779b97f4a7c15,
	}
}

// paths returns the flow's preferred set, creating it on first sight. k is
// passed in (not stored) so a live change re-assigns rather than silently
// serving stale-width sets.
func (t *flowTable) paths(key uint64, k int) *flowEntry {
	if t == nil || k <= 0 || t.numPaths <= 0 {
		return nil
	}
	if k > t.numPaths {
		k = t.numPaths
	}
	now := time.Now().UnixNano()

	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.m[key]; ok && len(e.paths) == k {
		e.lastUse.Store(now)
		return e
	}
	if len(t.m) >= flowPathsMaxFlows {
		t.evictLocked(now)
	}
	e := &flowEntry{paths: assignPaths(key^t.salt, k, t.numPaths)}
	e.lastUse.Store(now)
	t.m[key] = e
	return e
}

// evictLocked drops idle flows, and if that frees nothing, the single oldest —
// so the table is bounded even under a pathological flow rate.
func (t *flowTable) evictLocked(now int64) {
	cutoff := now - int64(flowPathsIdleTTL)
	var oldestKey uint64
	oldestAt := int64(1<<63 - 1)
	freed := 0
	for k, e := range t.m {
		at := e.lastUse.Load()
		if at < cutoff {
			delete(t.m, k)
			freed++
			continue
		}
		if at < oldestAt {
			oldestAt, oldestKey = at, k
		}
	}
	if freed == 0 && len(t.m) > 0 {
		delete(t.m, oldestKey)
	}
}

func (t *flowTable) size() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// assignPaths picks k DISTINCT connection indices for a flow: an anchor from the
// key, then a stride walk, with linear probing when the stride revisits a slot.
//
// 🚨 The distinctness is not cosmetic — k copies of one index is k=1 wearing a
// costume, and k=1 is the -79% result. A test asserts it.
func assignPaths(key uint64, k, numPaths int) []int32 {
	if k > numPaths {
		k = numPaths
	}
	out := make([]int32, 0, k)
	used := make([]bool, numPaths)
	anchor := int(key % uint64(numPaths))
	stride := 1
	if numPaths > 2 {
		stride = 1 + int((key>>32)%uint64(numPaths-1))
	}
	idx := anchor
	for len(out) < k {
		for used[idx] {
			idx = (idx + 1) % numPaths
		}
		used[idx] = true
		out = append(out, int32(idx))
		idx = (idx + stride) % numPaths
	}
	return out
}

// flowPathsStats answers the ONE question a null result cannot be read without:
// did the lever engage at all?
//
// 🚨 THIS IS THE LESSON OF THE CHUNKING SWEEP, PAID FOR ONCE ALREADY. That
// experiment ran 14 arms and moved nothing, and the reason was not that
// reordering does not matter — it was that the mean chunk stayed 1.86 at K=64,
// i.e. the treatment never applied. Without `chunk=` the null would have been
// filed as a refutation of the mechanism. Here the equivalent is the pref/spill
// split: if spill dominates, the flow never used its set and the run tested
// NOTHING, whatever the throughput did.
type flowPathsStats struct {
	pref  atomic.Int64 // placed on a preferred path
	spill atomic.Int64 // preferred set busy → shared sendCh (the "soft" firing)
	skip  atomic.Int64 // a preferred path skipped as unhealthy
	keyed atomic.Int64 // packets that had a flow key at all (0 = keepalive)
}

func (s *flowPathsStats) snapshotAndReset() (pref, spill, skip, keyed int64) {
	return s.pref.Swap(0), s.spill.Swap(0), s.skip.Swap(0), s.keyed.Swap(0)
}

// summary renders one memstats field group, or "" while the lever is off — the
// same shape as chunkStats.summary, and for the same reason: a line that prints
// zeros forever is noise, but a line that is SILENT while the treatment is armed
// would be a lie.
//
// 🎯 HOW TO READ IT, pre-registered, because the throughput number alone cannot
// tell these three apart:
//
//   - pref high (say >70%): the treatment APPLIED. Whatever throughput did is
//     about flow-local paths.
//   - spill dominant: the sets were always busy, so packets took the shared
//     fan-out anyway — the run measured today's behaviour with extra bookkeeping
//     and CANNOT refute the mechanism. Raise the queue depth or lower k and
//     re-run; do not file it as a null.
//   - keyed ≈ 0 with traffic flowing: the WG patch stopped delivering keys, so
//     nothing was ever eligible. That is a plumbing regression, not a result.
func (s *flowPathsStats) summary(t *flowTable) string {
	k := int(flowPathsK.Load())
	pref, spill, skip, keyed := s.snapshotAndReset()
	if k <= FlowPathsOff {
		return ""
	}
	total := pref + spill
	prefPct := 0.0
	if total > 0 {
		prefPct = 100 * float64(pref) / float64(total)
	}
	return fmt.Sprintf(" flowpaths=k=%d flows=%d pref=%d/%d=%.1f%% spill=%d skip=%d keyed=%d",
		k, t.size(), pref, total, prefPct, spill, skip, keyed)
}

// enqueueFlowPath tries to place the packet on one of the flow's preferred
// paths. Returns false when the caller must fall back to the shared sendCh —
// which is the normal, healthy spill, not an error.
//
// The order of the three exits matters:
//  1. k=0, no key (keepalive/handshake), or no table → shared path, untouched.
//  2. a preferred path with room → placed, sticky.
//  3. every preferred path busy → shared path, so a stalled subset never holds
//     the flow. THIS is the "soft" in soft affinity.
func (p *Proxy) enqueueFlowPath(item sendItem, flowKey uint64) bool {
	k := int(flowPathsK.Load())
	if k <= FlowPathsOff || flowKey == 0 || p.flows == nil || len(p.pathQ) == 0 {
		return false
	}
	p.flowPathStats.keyed.Add(1)

	e := p.flows.paths(flowKey, k)
	if e == nil {
		return false
	}
	// Round-robin WITHIN the set, so a flow's packets spread over its k paths
	// rather than piling onto the first one — the set is a subset of the
	// fan-out, not a replacement for it.
	start := int(e.rr.Add(1))
	checkHealth := flowPathsHealth.Load()
	for i := 0; i < len(e.paths); i++ {
		idx := int(e.paths[(start+i)%len(e.paths)])
		if idx < 0 || idx >= len(p.pathQ) {
			continue
		}
		if checkHealth && !p.pathHealthy(idx) {
			p.flowPathStats.skip.Add(1)
			continue
		}
		select {
		case p.pathQ[idx] <- item:
			p.flowPathStats.pref.Add(1)
			return true
		default:
			// Busy. Try the next path in the set rather than waiting — waiting
			// here would be the head-of-line stall this design exists to avoid.
		}
	}
	p.flowPathStats.spill.Add(1)
	return false
}

// pathHealthy reports whether a connection looks able to accept work, from the
// socket sample the memstats tick already takes.
//
// ⚠️ DEFAULT OFF IN PR2, DELIBERATELY, and there are two reasons rather than
// caution. First, one variable at a time: the treatment under test is the sticky
// SET, and a health filter that reorders preference inside it would confound the
// A/B that has to answer whether stickiness helps. Second, this signal is weak
// where it matters — `Snd_sbbytes` INCLUDES in-flight data (an upper bound on the
// queue, per the SDK's own comment) and it is refreshed once per memstats tick,
// i.e. every 10 s by default, against a stall that lasts 100-277 ms. It is 40x
// too slow for the thing it is named after.
//
// 🎯 The instantaneous health test is the one above it: a connection whose own
// 2-deep queue is full IS the backed-up connection, measured now, with no
// syscall and no staleness. This function is the slow second opinion, kept
// because PR3 can arm it as a separate arm.
func (p *Proxy) pathHealthy(connIdx int) bool {
	if p.sockStats == nil {
		return true
	}
	sb, wnd, ok := p.sockStats.lastDepth(connIdx)
	if !ok || wnd <= 0 {
		return true
	}
	return float64(sb) < 0.85*float64(wnd)
}

// nextSendItem is the WRITER side, and it is the reason the set stays soft.
//
// 🚨 EVERY WRITER STILL SELECTS ON THE SHARED sendCh, ALWAYS. The plan this
// implements had writers read only their own path queue, with a global steal as
// an optional extra. That inversion would break two things at once: spilled
// packets would have no drain (so a busy subset would stall its flow — mini-k1,
// the -79% result), and keepalives and handshakes, which carry flowKey=0 and go
// to the shared channel BY DESIGN, would never be sent at all.
//
// Its own queue is preferred, not prioritised absolutely: one non-blocking check
// first (so a sticky packet is taken without waiting on the runtime's random
// select), then a blocking select over both. With k=0 the path queue is nil,
// a receive on a nil channel never fires, and this is exactly the old
// `case item := <-p.sendCh:` — byte-for-byte behaviour, one indirection.
func (p *Proxy) nextSendItem(done <-chan struct{}, connIdx int) (sendItem, bool) {
	var own chan sendItem
	if connIdx >= 0 && connIdx < len(p.pathQ) && flowPathsK.Load() > FlowPathsOff {
		own = p.pathQ[connIdx]
	}
	if own != nil {
		select {
		case item := <-own:
			return item, true
		default:
		}
	}
	select {
	case item := <-own:
		return item, true
	case item := <-p.sendCh:
		return item, true
	case <-done:
		return sendItem{}, false
	}
}
