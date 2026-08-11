package proxy

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// WHAT THE 30 OUTER TCP SOCKETS ARE HOLDING — the last unmeasured place on our
// side of the uplink.
//
// 🎯 WHY THIS EXISTS. By 2026-08-11 everything above the socket is accounted for:
// the server receives 1.01-1.02× of every byte the phone's WireGuard reads from
// the TUN, `sendch-wait` says a packet waits 1-2 ms for a writer and 19.5 ms at
// the very worst, and `sendch-block` says the producer is made to wait 0.2% of
// the time. All of that stops at `conn.Write`.
//
// 🚨 AND `conn.Write` RETURNING IS NOT THE PACKET LEAVING. It means the kernel
// copied the bytes into that connection's send buffer. They can then sit there,
// behind whatever that connection has already queued, for as long as its TCP
// takes to drain — and every counter we own still reads "delivered, on time".
// A packet can be late by tens of milliseconds without a single byte being lost,
// which is precisely the shape that would let US perturb the inner TCP while
// looking innocent.
//
// 🎯 IT ALSO SETTLES SOMETHING ALREADY IN THE RECORD. The uplink's reordering is
// currently attributed to "a fixed ~11 ms of RTT SPREAD between connections,
// i.e. path jitter, not something the fan-out creates" (N-sweep, 2026-08-10).
// That was concluded without ever looking at the sockets. If the spread is in
// `srtt` across the 30 connections, it is the paths and the record stands; if it
// is in `Snd_sbbytes`, it is ours. ⚠️ Note what follows if it is ours: the client
// pacer, refuted three times, would have a measured reason to come back. That is
// an argument for measuring carefully, not for expecting either answer.
//
// ⚠️⚠️ READ THE FIELD DEFINITION BEFORE QUOTING `sb`. The iOS SDK's own comment
// on `tcpi_snd_sbbytes` is *"bytes in send socket buffer, INCLUDING IN-FLIGHT
// DATA"* — so it counts both what is waiting to be sent and what has been sent
// and not yet acknowledged. Only the first part is queueing delay we add. **It
// is an UPPER BOUND on the queue, not the queue.** In-flight is bounded by
// `Snd_cwnd`, which is printed beside it for exactly that reason.
//
// Sampling costs one `getsockopt` per connection per memstats tick — 30 calls,
// read-only, on sockets we opened ourselves. Nothing on the packet path.

// tcpInfo is the platform-independent subset of what a sampler returns.
type tcpInfo struct {
	sbBytes        uint32 // send socket buffer occupancy, INCLUDING in-flight
	cwnd           uint32 // congestion window in bytes — bounds the in-flight part
	srttMs         uint32 // smoothed RTT of the OUTER connection, ms
	rttvarMs       uint32
	rtxPkts        uint64 // cumulative retransmitted packets on this socket
	inLossRecovery bool
	reorderingSeen bool
}

// TCPCI flag bits, from netinet/tcp.h. Kept here rather than pulled from a
// header so the non-Darwin build has them too.
const (
	tcpciFlagLossRecovery       = 0x1
	tcpciFlagReorderingDetected = 0x2
)

// sockStats holds the live TCP connections to the relays, by conn index. A
// connection registers when it is dialled and unregisters before it closes, so a
// reconnect can never leave the sampler holding a dead socket.
type sockStats struct {
	mu    sync.Mutex
	conns map[int]*net.TCPConn

	// Last cumulative retransmit count per conn index, for per-interval deltas.
	// Kept per conn rather than as one total because a reconnect restarts the
	// socket's counter at zero: a global total would go BACKWARDS and print a
	// negative delta, which reads as "retransmits were undone".
	lastRtx map[int]uint64
}

func newSockStats() *sockStats {
	return &sockStats{conns: map[int]*net.TCPConn{}, lastRtx: map[int]uint64{}}
}

// register starts sampling a connection. Safe with a nil receiver or a nil conn
// so the UDP transport path needs no special case.
func (s *sockStats) register(connIdx int, c net.Conn) {
	if s == nil || connIdx < 0 {
		return
	}
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return
	}
	s.mu.Lock()
	s.conns[connIdx] = tc
	s.mu.Unlock()
}

// unregister must run BEFORE the connection is closed. Sampling a closed socket
// is harmless (the getsockopt fails and the conn is skipped), but holding the
// reference would keep it reachable.
func (s *sockStats) unregister(connIdx int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.conns, connIdx)
	delete(s.lastRtx, connIdx)
	s.mu.Unlock()
}

// summary samples every live connection and renders one field group, or "" if
// nothing could be sampled.
func (s *sockStats) summary() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	idx := make([]int, 0, len(s.conns))
	for i := range s.conns {
		idx = append(idx, i)
	}
	sort.Ints(idx)

	var sb, cwnd, srtt []int
	var rtxDelta uint64
	var lossRec, reord int
	for _, i := range idx {
		info, ok := sampleTCPInfo(s.conns[i])
		if !ok {
			continue
		}
		sb = append(sb, int(info.sbBytes))
		cwnd = append(cwnd, int(info.cwnd))
		srtt = append(srtt, int(info.srttMs))
		// max(0, …): a reconnect restarts the socket counter, so a smaller
		// value than last time means "new socket", not "negative retransmits".
		if prev, seen := s.lastRtx[i]; seen && info.rtxPkts >= prev {
			rtxDelta += info.rtxPkts - prev
		}
		s.lastRtx[i] = info.rtxPkts
		if info.inLossRecovery {
			lossRec++
		}
		if info.reorderingSeen {
			reord++
		}
	}
	s.mu.Unlock()

	if len(sb) == 0 {
		return ""
	}
	sort.Ints(sb)
	sort.Ints(cwnd)
	sort.Ints(srtt)
	pct := func(v []int, f float64) int { return v[int(f*float64(len(v)-1))] }
	// ⚠️ `sb` includes in-flight (SDK's own words) — cwnd is printed next to it
	// so a reader can see how much of it could be in flight rather than waiting.
	// srtt's SPREAD is the number that speaks to "the disorder is RTT spread
	// between connections": min-max across the pool, in one glance.
	return fmt.Sprintf(" sock=%d sb=%d/%dKiB cwnd=%dKiB srtt=%d/%d-%dms rtx=+%d lossrec=%d reord=%d",
		len(sb),
		pct(sb, 0.5)/1024, sb[len(sb)-1]/1024,
		pct(cwnd, 0.5)/1024,
		pct(srtt, 0.5), srtt[0], srtt[len(srtt)-1],
		rtxDelta, lossRec, reord)
}
