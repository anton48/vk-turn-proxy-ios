// SPDX-License-Identifier: GPL-3.0-only

package proxy

import "log"

// A RELAY MARKED UNREACHABLE ENDS THE SESSIONS STILL ON IT (2026-11-07, the
// failover run on 476 — Nov 7 §591).
//
// The relay health marks a relay UNREACHABLE on evidence (relayhealth.go: an
// attempt on it got no answer while another address or VK answered after the
// attempt began). Until now the mark moved the CURSORS — each connection's
// NEXT hand-out took another address — and nothing else: a session already
// seated on the dead relay lived on until its own kernel gave up on the dead
// TCP connection and its write failed (pingWriteFailed, build 469). On the
// phone that is a spread of 60–140 s, in waves: the own relay black-holed at
// +0, ONE mark at +66 s on VK's answer, the forty sessions back +66 … +138 s
// (Nov 2 §517 saw the same on 469: +94 / +121 s) — while the pool KNEW the
// relay was dead from +66 s on.
//
// Now the pool tells the proxy of every relay it has just marked, and the
// proxy ends every live session still seated on it, at once; each connection
// re-dials through its cursor, which the mark has already moved past the dead
// relay. The restart is a REQUEST, the path restart's own kind (a cancel of
// the session's context): no short-failure count, no dormancy, no retry floor.
// Which relay a connection sits on is recorded at the ONE hand-out site every
// transport's session goes through (resolveTURNAddr) and forgotten with the
// session (endConnSession).
//
// 🚫 The hook runs OUTSIDE the pool's lock: the sessions it ends re-dial, and
// a re-dial asks the pool. 🚫 A false mark costs one restart wave (≈ 3 s on
// VK's relays from the phone), bounded by the mark's own rule — someone other
// than the accused answered after the failure (Nov 4 §555). ⚖️ Not the
// automatic return to the own relay that Nov 2 §526 declined: this is the way
// OFF a dead relay, never back onto one.
//
// THE NOTICE CARRIES A STAMP (the user's review of 589dfb2). Between the mark
// and the hook's run the pool's lock is released; a notice naming only the
// address could arrive late — a path change clears the marks meanwhile, a
// NEW session is handed the same relay and allocates — and end that new
// session. So every hand-out stamps the connection (relayHandSeq, read at
// setConnRelay), the pool reads the counter UNDER its lock at the mark
// (markStamp) and hands it over with the address, and the ending spares every
// session handed its relay after the stamp. The same stamp also spares the
// one re-try of a marked relay (hasCandidate's probe), handed out after the
// mark by construction. And a relay gets marked by THREE paths — the failing
// attempt's own verdict, a neighbour's answer, VK's API answering a mint —
// and all three fire the hook (the third from a goroutine: its callers hold
// the lock across several returns).

// setConnRelay records the relay connIdx was handed (resolveTURNAddr).
func (p *Proxy) setConnRelay(connIdx int, addr string) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if connIdx < 0 || connIdx >= len(p.connRelay) {
		return
	}
	p.connRelay[connIdx] = addr
	if connIdx < len(p.connRelaySeq) {
		p.connRelaySeq[connIdx] = p.relayHandSeq.Add(1) // this hand-out's stamp: a mark's notice reaches only hand-outs before it
	}
}

// connRelayOf: the relay recorded for connIdx, ok false when none (between
// sessions, or an index outside the table).
func (p *Proxy) connRelayOf(connIdx int) (string, bool) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if connIdx < 0 || connIdx >= len(p.connRelay) || p.connRelay[connIdx] == "" {
		return "", false
	}
	return p.connRelay[connIdx], true
}

// endSessionsOnRelay cancels every running session recorded on addr whose
// hand-out is not newer than stamp — the proxy's hand-out counter as the pool
// read it at the mark — and returns how many; the pool calls it, outside its
// lock, for a relay it has just marked UNREACHABLE.
func (p *Proxy) endSessionsOnRelay(addr string, stamp uint64) int {
	if addr == "" || (p.ctx != nil && p.ctx.Err() != nil) {
		return 0
	}
	p.connMu.Lock()
	n := 0
	for i := range p.connRelay {
		if p.connRelay[i] != addr || i >= len(p.connCancel) || p.connCancel[i] == nil {
			continue
		}
		if i < len(p.connRelaySeq) && p.connRelaySeq[i] > stamp {
			continue // handed this relay after the mark: the notice is not about it
		}
		p.connCancel[i]()
		n++
	}
	p.connMu.Unlock()
	if n > 0 {
		log.Printf("proxy: relay %s marked UNREACHABLE — %d session(s) still on it ended; each re-dials the next address", addr, n)
	}
	return n
}
