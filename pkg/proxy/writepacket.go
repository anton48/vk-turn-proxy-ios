package proxy

import "time"

// writePacket writes ONE packet from the shared queue to one connection, and
// prices it into the two residence histograms on the way.
//
// 🚫 THIS IS WHAT IS LEFT OF UPLINK CHUNKING, AND THE REMOVAL IS THE POINT.
// `writeChunk` used to take up to K−1 further packets straight off `sendCh`
// after the first, on the theory that consecutive packets on ONE path reorder
// less. That lever was swept over 14 arms and closed on 2026-08-12: it cannot
// engage (mean chunk 1.86 even at K=64, against a queue whose mean depth is 2.8
// packets shared by ~30 writers), and on the wire it never arrives at all —
// server1 saw no run longer than 17 on either transport while the client was
// building chunks of 37-64.
//
// 🚨 AND IT IS INCOMPATIBLE WITH THE UPLINK PACER, WHICH IS WHY IT IS GONE
// RATHER THAN MERELY DEFAULTED OFF. The pacer reserves ONCE per dequeue
// (uplinkpace.go), so packets 2..K of a chunk were written with no reservation
// and never appeared in `bytes=` — a bucket that reports ENGAGED while up to
// K−1 of every K packets pass it unmetered. The two features cannot both be
// correct on the same queue, and one of them is measured to do nothing.
// *(User-caught, 2026-08-17, reading the port.)*
//
// 🚨 THE ORDER INSIDE IS STILL THE DESIGN, and it survives from the chunk loop:
// the packet is written before this goroutine takes another. A writer holding a
// packet it has not written keeps it where work-stealing cannot see it — the
// run-20 pathology — and the uplink pacer's reserve-before-dequeue rests on the
// same argument.
//
// txConnIdx is the connection whose TX counters this call site maintains, or −1
// for the sites that never accounted for them (DTLS / direct / WRAP-A). Passing
// −1 there keeps those sites byte-for-byte what they were: this helper must not
// quietly add accounting a call site did not have.
func (p *Proxy) writePacket(item sendItem, txConnIdx int, write func(pkt []byte, now time.Time) error) error {
	// 🚨 THE POOL HAND-BACK, and its position is the contract. Dequeuing is what
	// transfers ownership, so this function returns the buffer EXACTLY ONCE on
	// every outcome — success, write error, and any exit added later. A `defer`
	// is what makes "every outcome" true without a reader having to check; see
	// the ownership note on sendPktPool for why a third Put site anywhere else
	// would be a double free of a live buffer rather than a leak.
	defer sendPktPoolPut(item.buf)

	// Read the length BEFORE the write, not after. The deferred Put above runs
	// after the body, so reading len(item.buf) below would in fact still be
	// safe today — but only by that reasoning, and the next edit that moves a
	// read of the CONTENTS down here would be a use-after-Put that nothing
	// catches. Taking it now removes the question.
	n := len(item.buf)

	// One clock read serves both the residence stamp and the write deadline.
	now := time.Now()
	p.sendWait.observe(item.at, now.UnixNano())

	w0 := time.Now()
	err := write(item.buf, now)
	p.writeWait.observe(w0.UnixNano(), time.Now().UnixNano())
	if err != nil {
		return err
	}

	if txConnIdx >= 0 && txConnIdx < len(p.connTxBytes) {
		p.connTxBytes[txConnIdx].Add(int64(n))
		p.lastTxAt[txConnIdx].Store(time.Now().UnixNano())
	}
	return nil
}
