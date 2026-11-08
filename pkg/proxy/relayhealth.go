// SPDX-License-Identifier: GPL-3.0-only

package proxy

// The standing of every TURN relay the pool dials, by host:port (issues #98
// and #102, 2026-10-19). VK returns two or more relays with a credential and
// any VK relay accepts any VK credential (measured 2026-10-19); until now only
// the first address was ever dialled, and a relay that stopped answering kept
// every connection on it until the credential expired — and the TURN override
// never reached a cached credential.
//
// The rule, decided with the user:
//
//   - An Allocate that gets NO answer (a dial timeout, pion's retransmissions
//     run out, a refused connection) is a verdict on the relay ONLY WITH
//     EVIDENCE that the network works — another relay allocated, or VK's API
//     answered, inside the window (the attempt's start − relayEvidenceWindow)
//     … (its end), on the same path. Without evidence it is the network's
//     failure for all we know: the connection's own CURSOR moves to the next
//     candidate, nothing is marked. When an answer comes later, every address
//     left unanswered on this path since the previous answer is marked then.
//     An attempt begun before the relay's OWN last answer is no verdict on it.
//     🚨 The evidence is SOMEONE ELSE's answer — another relay's or VK's —
//     never the accused relay's own (the overnight run of 2026-11-03: at the
//     tunnel's start one connection's dial failed at once with ENETUNREACH,
//     the routes still settling, and the own relay's answer to a neighbour 94
//     ms earlier served as the evidence that marked it); and a failure that
//     arrives while the relay is answering its neighbours — its own answer
//     inside relayAnswerGrace before the attempt began, or after it — is no
//     verdict either: no packet of that attempt can have reached a relay that
//     answers. A route errno stays «no answer» (a null route for one relay
//     reads so on the stand, 2026-10-19) — what tells the local transient
//     from the network's verdict is the relay's own answers around it.
//   - 🆕 2026-11-08 (the user's run, Nov 8 §620): a failure has a KIND. A
//     SILENT one (a timeout — nobody answered during the attempt's window)
//     is judged only by an answer to an attempt IN FLIGHT BESIDE IT: begun
//     before the silent attempt gave up, answered at or after it began. At
//     a Wi-Fi → LTE switch the new path passed nothing for ≈18 s: every
//     attempt on the own relay timed out, VK's first answer went to an
//     attempt begun after those had given up — and marked the own relay,
//     which never failed; the two attempts had not shared a moment of the
//     network. The path's OWN answer (an errno — no route to host, refused,
//     reset: §618's failover) keeps the rule above: the path spoke, a later
//     answer inside the window is evidence. pathSpoke tells the two apart;
//     the record keeps whether its streak was silent and when its latest
//     attempt gave up. The cost: a black hole that DROPS marks one dial
//     timeout later, when the first answer overlaps the other connections'
//     silent attempts; one connection alone never marks a silent relay —
//     its cursor still moves it on.
//   - A mark does not expire. A marked address is tried again only when a
//     credential has no unmarked candidate left — the oldest mark first, one
//     connection at a time, at growing intervals — at a path change (every
//     mark is cleared: the old verdicts say nothing about the new network) or
//     in a new process (marks live in memory, never on disk).
//   - Nothing here races two relays inside one connection: one attempt at a
//     time, the next candidate after a failure.
//
// Guarded by the pool's mutex (the pool is the only caller).

import (
	"context"
	"errors"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// relayEvidenceWindow: how far before an unanswered attempt's start an
	// answer still counts as evidence that the network works — longer than
	// one UDP Allocate's retransmissions (≈ 25–40 s), shorter than a conn's
	// dormancy (30–60 s).
	relayEvidenceWindow = 60 * time.Second
	// relayAnswerGrace: a relay's own answer this close BEFORE an attempt began
	// voids the attempt's failure as a verdict on it (an answer AFTER the
	// attempt began always does) — the relay was answering its neighbours
	// while this attempt failed, so the failure was not the relay's silence
	// (a tunnel start's route transient, 2026-11-03: the dial failed in 0 s,
	// the relay's answers 94 ms before and 11 ms after). Short, so that a
	// relay that dies seconds after its last answer is still marked by the
	// next failed attempt without a wait (the blackhole of Nov 3 §529).
	relayAnswerGrace = 2 * time.Second
	// relayProbeBackoffMin / Max: the growing interval between re-tries of a
	// marked address once a credential has no other candidate.
	relayProbeBackoffMin = time.Minute
	relayProbeBackoffMax = 30 * time.Minute
	// relayProbeClaim: how long a re-try of a marked address is reserved for
	// the one connection that drew it — one attempt's worth, retransmissions
	// included — so the others do not pile onto the same dead relay.
	relayProbeClaim = 45 * time.Second
	// deadMintPause: how long the pool mints nothing more after a fresh
	// credential named only relays already marked unreachable (VK keeps
	// returning the dead pair — measured 2026-10-19: three mints in a row
	// from one host, the same pair). Doubles up to deadMintPauseMax while
	// the mints keep landing dead.
	deadMintPause    = 2 * time.Minute
	deadMintPauseMax = 16 * time.Minute
)

type relayRecord struct {
	unansweredSince time.Time // the first unanswered attempt of the running streak; zero = none
	unanswered      int       // attempts in the streak
	dead            bool      // marked: unreachable, with evidence
	deadSince       time.Time
	retried         time.Time // the last re-try of a marked address
	retries         int       // re-tries since the mark
	claimedUntil    time.Time // a re-try is out on this address until then
	claimedAt       time.Time // when that re-try was handed out: a result belongs to it only if its attempt began after
	answeredAt      time.Time // the relay's own last answer: an attempt begun before it says nothing about the relay
	markSeq         uint64    // the pool's hand-out counter at the mark (credpool_relay.go): a hand-out stamped at or below it was made before the mark
	lastFailureAt   time.Time // the latest failure of the running streak — when its attempt gave up
	silent          bool      // every failure of the streak was SILENCE (a timeout: nobody answered during the attempt's window), none an errno from the path
}

type relayHealth struct {
	rec          map[string]*relayRecord
	lastAnswer   time.Time // the latest answer on this path — a relay's or VK's API
	lastVKAnswer time.Time // the latest answer of VK's API on this path (the evidence a relay's own answer cannot be)
	// pathChangedAt: when the path last changed. An attempt that BEGAN before
	// it belongs to the old network — its late failure is no verdict on the
	// new one and its late success no evidence for it (the user's review,
	// 2026-10-19: a TCP dial of the old path timing out after a new-path
	// allocation would have marked the relay on the new path).
	pathChangedAt time.Time
	now           func() time.Time
}

func newRelayHealth() *relayHealth {
	return &relayHealth{rec: map[string]*relayRecord{}, now: time.Now}
}

func (h *relayHealth) record(addr string) *relayRecord {
	r := h.rec[addr]
	if r == nil {
		r = &relayRecord{}
		h.rec[addr] = r
	}
	return r
}

// unanswered records an attempt on addr that got no answer, begun at start.
// It reports whether the address is marked now (evidence inside the window).
// An attempt begun before the last path change, or before the address's own
// last answer, says nothing: it set out while the relay was out of reach, and
// its failure arrives a moment after the relay answered, with the evidence
// fresh and the record clear (a stand's whole-network outage, 2026-11-02: four
// such failures marked a relay 0.3–0.8 s after its answer). On a marked
// address only a RE-TRY that was handed out (probe) moves the backoff — not
// the late failures of attempts begun before the mark, which arrive by the
// dozen from parallel connections (the user's review: thirty of them had put
// the first re-try thirty minutes away).
func (h *relayHealth) unanswered(addr string, start time.Time) bool {
	return h.failed(addr, start, false)
}

// failed is unanswered with the failure's KIND: silent (a timeout — nobody
// answered during the attempt's window) or the path's own answer (an errno:
// no route, refused, reset). The kind decides what counts as evidence
// (the user's run of 2026-11-08, Nov 8 §620).
func (h *relayHealth) failed(addr string, start time.Time, silent bool) bool {
	now := h.now()
	if start.Before(h.pathChangedAt) {
		return false
	}
	r := h.record(addr)
	if r.dead {
		// Only the re-try's OWN result — an attempt begun after the claim was
		// handed out — releases the claim and moves the backoff. A late
		// failure of an earlier attempt, or of a re-try whose claim has run
		// out and been handed out again, touches neither (the user's review,
		// 2026-10-19: it had freed the claim, and a second re-try went out
		// beside the first).
		if !r.claimedUntil.IsZero() && !start.Before(r.claimedAt) {
			r.claimedUntil, r.claimedAt = time.Time{}, time.Time{}
			r.retried, r.retries = now, r.retries+1
		}
		return true
	}
	if h.answeredAround(addr, start) {
		return false
	}
	if r.unanswered == 0 {
		r.unansweredSince = start
		r.silent = silent
	} else {
		r.silent = r.silent && silent
	}
	r.unanswered++
	r.lastFailureAt = now
	// The evidence: the latest answer of ANOTHER address or of VK's API —
	// never addr's own (see the header). For SILENCE the answer must have
	// come while this attempt was waiting — at or after its start (the user's
	// run of 2026-11-08: an answer from before the attempt says nothing about
	// the network during it); for the path's own answer the window reaches
	// relayEvidenceWindow back, as before.
	if ev := h.evidenceExcept(addr); !ev.IsZero() {
		since := start.Add(-relayEvidenceWindow)
		if r.silent {
			since = start
		}
		if !ev.Before(since) {
			h.markLocked(r, now)
			return true
		}
	}
	return false
}

// answeredAround: addr answered after the attempt begun at start set out, or
// inside relayAnswerGrace before it — the failure is no verdict on addr: a
// relay that answers its neighbours around the attempt was not silent to it.
// The line is the answer's MOMENT, not the start of the attempt that was
// answered (a slow Allocate answered after three seconds covers a failure
// begun meanwhile).
func (h *relayHealth) answeredAround(addr string, start time.Time) bool {
	r := h.rec[addr]
	return r != nil && !r.answeredAt.IsZero() && start.Before(r.answeredAt.Add(relayAnswerGrace))
}

// evidenceExcept: the latest answer on this path from anyone but addr — another
// relay's or VK's API — zero when nobody else has answered.
func (h *relayHealth) evidenceExcept(addr string) time.Time {
	ev := h.lastVKAnswer
	for a, r := range h.rec {
		if a != addr && r.answeredAt.After(ev) {
			ev = r.answeredAt
		}
	}
	return ev
}

func (h *relayHealth) markLocked(r *relayRecord, now time.Time) {
	r.dead, r.deadSince, r.retries, r.retried = true, now, 0, time.Time{}
}

// answered records an answer from addr ("" for VK's API) to an attempt begun
// at start (zero: now): the network works — the address is alive again, and
// every other address unanswered since the previous answer is marked now. An
// answer to an attempt begun before the last path change is the OLD network's
// and no evidence for this one.
func (h *relayHealth) answered(addr string, start time.Time) {
	now := h.now()
	if !start.IsZero() && start.Before(h.pathChangedAt) {
		return
	}
	prev := h.lastAnswer
	h.lastAnswer = now
	if addr == "" {
		h.lastVKAnswer = now
	}
	if addr != "" {
		// A record is made if there was none: the late failure may still be
		// on its way.
		*h.record(addr) = relayRecord{answeredAt: now}
	}
	for a, r := range h.rec {
		if a == addr || r.dead || r.unanswered == 0 {
			continue
		}
		// A SILENT streak is marked only by an answer to an attempt that was
		// in flight beside it: begun before the streak's latest attempt gave
		// up (an answer without a start — zero — can show no overlap). The
		// user's run of 2026-11-08, Nov 8 §620: at a Wi-Fi → LTE switch the
		// new path passed nothing for ≈18 s; every attempt on the own relay
		// timed out, and the first VK answer — to an attempt begun after
		// those had given up — marked the own relay, which never failed.
		if r.silent && (start.IsZero() || start.After(r.lastFailureAt)) {
			continue
		}
		if prev.IsZero() || !r.unansweredSince.Before(prev) {
			h.markLocked(r, now)
		}
	}
}

// pathChanged forgets everything: the verdicts were about the old network.
func (h *relayHealth) pathChanged() {
	h.rec = map[string]*relayRecord{}
	h.lastAnswer, h.lastVKAnswer = time.Time{}, time.Time{}
	h.pathChangedAt = h.now()
}

func (h *relayHealth) isDead(addr string) bool {
	r := h.rec[addr]
	return r != nil && r.dead
}

// alive is the unmarked candidates, in the list's order.
func (h *relayHealth) alive(cands []string) []string {
	out := make([]string, 0, len(cands))
	for _, a := range cands {
		if !h.isDead(a) {
			out = append(out, a)
		}
	}
	return out
}

func probeBackoff(retries int) time.Duration {
	d := relayProbeBackoffMin
	for i := 0; i < retries && d < relayProbeBackoffMax; i++ {
		d *= 2
	}
	if d > relayProbeBackoffMax {
		d = relayProbeBackoffMax
	}
	return d
}

// dueAt is when a marked address may be tried again.
func (r *relayRecord) dueAt() time.Time {
	from := r.deadSince
	if r.retried.After(from) {
		from = r.retried
	}
	return from.Add(probeBackoff(r.retries))
}

// probe picks, among marked candidates, the one longest due for a re-try
// and reserves it for the caller; ok=false when none is due. nextDue is the
// earliest moment one will be (zero when nothing is marked).
func (h *relayHealth) probe(cands []string) (addr string, ok bool, nextDue time.Time) {
	addr, ok, nextDue = h.dueCandidate(cands)
	if ok {
		now := h.now()
		h.rec[addr].claimedUntil, h.rec[addr].claimedAt = now.Add(relayProbeClaim), now
	}
	return addr, ok, nextDue
}

// probePeek is probe's choice without the claim: the relay a re-try WOULD
// dial — what a hand-out judges the slot on before the claim is taken
// (the user's review of 461: the room was checked on the list's first
// candidate while the probe handed out the one longest due — a third seat on
// a relay with a quota of two).
func (h *relayHealth) probePeek(cands []string) (addr string, ok bool) {
	addr, ok, _ = h.dueCandidate(cands)
	return addr, ok
}

// dueCandidate: among marked candidates, the one longest due for a re-try —
// the ONE selection behind probe and probePeek (a run-out claim is settled
// here, as a fact, whichever asks). Not ok with a re-try already out on one of
// them (nextDue: when its claim runs out) or none due yet (nextDue: the first).
func (h *relayHealth) dueCandidate(cands []string) (addr string, ok bool, nextDue time.Time) {
	now := h.now()
	type due struct {
		addr string
		at   time.Time
	}
	var dues []due
	for _, a := range cands {
		r := h.rec[a]
		if r == nil || !r.dead {
			continue
		}
		if r.claimedUntil.After(now) {
			// A re-try is out on this credential's relays: one connection
			// at a time — the others wait for its answer.
			return "", false, r.claimedUntil
		}
		h.settleRunOutClaim(r)
		dues = append(dues, due{a, r.dueAt()})
	}
	if len(dues) == 0 {
		return "", false, time.Time{}
	}
	sort.SliceStable(dues, func(i, j int) bool { return dues[i].at.Before(dues[j].at) })
	if dues[0].at.After(now) {
		return "", false, dues[0].at
	}
	return dues[0].addr, true, time.Time{}
}

// untried is the unmarked candidates no attempt has gone unanswered on since
// the last answer — the ones worth a connection's next try.
func (h *relayHealth) untried(cands []string) []string {
	out := make([]string, 0, len(cands))
	for _, a := range cands {
		if r := h.rec[a]; r == nil || (!r.dead && r.unanswered == 0) {
			out = append(out, a)
		}
	}
	return out
}

// settleRunOutClaim: a re-try whose claim ran out with no result is counted
// as a failed re-try at the claim's end — the next one after the backoff, not
// at once — and its late result, if any, touches nothing. Called wherever a
// marked address is judged (probe AND hasCandidate — the two agree, so a
// credential never reads as ready on a stale due time and then yields no
// address: the user's review of 5283092).
func (h *relayHealth) settleRunOutClaim(r *relayRecord) {
	if !r.claimedUntil.IsZero() && !r.claimedUntil.After(h.now()) {
		r.retried, r.retries = r.claimedUntil, r.retries+1
		r.claimedUntil, r.claimedAt = time.Time{}, time.Time{}
	}
}

// hasCandidate: an untried candidate, or a marked one due for a re-try. A
// credential whose EVERY candidate went unanswered since the last answer has
// none — it is not ready, and the pool mints (VK's answer is the evidence
// that marks the silent relays; the fresh credential may name others). 🚫
// Not «alive»: a dead cached relay with no alternative and no evidence would
// otherwise be dialled until the credential expired (ams-int, 2026-10-19 —
// the cache held one address).
func (h *relayHealth) hasCandidate(cands []string) bool {
	if len(h.untried(cands)) > 0 {
		return true
	}
	now := h.now()
	due := false
	for _, a := range cands {
		r := h.rec[a]
		if r == nil || !r.dead {
			continue
		}
		if r.claimedUntil.After(now) {
			return false // a re-try is out: one at a time
		}
		h.settleRunOutClaim(r)
		if !r.dueAt().After(now) {
			due = true
		}
	}
	return due
}

// deadList names the marked candidates, for a log line.
func (h *relayHealth) deadList(cands []string) string {
	var out []string
	for _, a := range cands {
		if h.isDead(a) {
			out = append(out, a)
		}
	}
	return strings.Join(out, ", ")
}

// isRelayUnanswered: the relay gave NO answer — the dial timed out, pion's
// retransmissions ran out, the host refused the connection, or the kernel
// could not even send (no route, network unreachable: an ISP's null route for
// ONE relay looks exactly like that — issue #98's «unavailable to this
// client»; a network that is down fails every candidate alike, and the
// cursor's turn costs nothing there, while a MARK needs evidence that the
// network works — relayHealth). Two things are not «no answer»: a STUN error
// response (486, 401, 400, 437 — the relay spoke), and our own closing of the
// socket or cancelling of the attempt.
// pathSpoke: the failure was the PATH's own answer — an errno the network
// returned for the attempt (no route to host, network unreachable, connection
// refused, reset, broken pipe) — as opposed to SILENCE: a timeout, pion's
// retransmissions run out, a deadline. The relay leg wraps its errors with %v,
// so the text is read beside the errno in the chain.
func pathSpoke(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return true
	}
	s := err.Error()
	for _, w := range []string{"no route to host", "network is unreachable", "network is down", "host is down", "connection refused", "connection reset", "broken pipe"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func isRelayUnanswered(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "error response"), strings.Contains(s, "error 4"):
		return false // the relay answered
	case strings.Contains(s, "use of closed network connection"),
		strings.Contains(s, "operation was canceled"),
		strings.Contains(s, "context canceled"):
		return false // our own doing
	}
	return true
}

// turnOverride is the user's TURN relay setting: a LIST of host:port that
// replaces VK's addresses for every credential (cached ones included — the
// address is chosen when the credential is handed out), or the older pair
// (a host, a port, either may be empty) rewritten into each VK address.
type turnOverride struct {
	servers    []string       // the list as the pool dials it: IPs (ResolveTURNServers), the quota fields split off (setServers)
	quotas     map[string]int // address → its configured quota (parseTURNEntry); absent = VK's ten
	paces      map[string]int // address → its configured pace in KiB/s (parseTURNEntry); 0 = no pacer; absent = the default of each direction
	raw        []string       // the list as configured — names and the quota and pace fields included — for a later resolution (reresolveOverride)
	host, port string
}

// hasName: an entry of the list whose host is not an IP literal.
func (o turnOverride) hasName() bool {
	for _, e := range o.raw {
		t, ok := parseTURNEntry(e)
		if !ok {
			continue
		}
		if h, _, err := net.SplitHostPort(t.addr); err == nil && net.ParseIP(h) == nil {
			return true
		}
	}
	return false
}

// allIPs: every entry's host is an IP (a resolution that left a name behind
// is a failed one); the word for VK's relays is no name.
func allIPs(servers []string) bool {
	for _, e := range servers {
		if e == TURNServersVK {
			continue
		}
		t, ok := parseTURNEntry(e)
		if !ok {
			return false
		}
		if h, _, err := net.SplitHostPort(t.addr); err != nil || net.ParseIP(h) == nil {
			return false
		}
	}
	return true
}

// hasVK: the list names VK's own relays somewhere (TURNServersVK) — then it
// is not a FIXED list: a fresh credential may come with other VK relays, and
// a mint is a way out of an exhausted list, as without an override.
func (o turnOverride) hasVK() bool {
	for _, e := range o.servers {
		if e == TURNServersVK {
			return true
		}
	}
	return false
}

// cookieShape is the list as cookie mode reads it, where a slot IS a relay:
// the FIXED entries before the first `$vkurls` take the slots 0..m-1; with
// the word present, every slot from m on is a VK slot — VK's distinct relays,
// as without a list (the minter's discovery); entries after the word are not
// used (a VK slot's count is open). Without the word a slot beyond the fixed
// entries is off.
func (o turnOverride) cookieShape() (fixed []string, vkTail bool) {
	for _, e := range o.servers {
		if e == TURNServersVK {
			return fixed, true
		}
		fixed = append(fixed, e)
	}
	return fixed, false
}

func (o turnOverride) set() bool { return len(o.servers) > 0 || o.host != "" || o.port != "" }

// candidatesFor is the list a credential may be dialled on: the override
// list when set, else the pair applied to VK's addresses, else VK's own —
// deduplicated, never empty when creds has an address.
func (o turnOverride) candidatesFor(creds *TURNCreds) []string {
	var vk []string
	if creds != nil {
		vk = creds.Addresses
		if len(vk) == 0 && creds.Address != "" {
			vk = []string{creds.Address}
		}
	}
	if len(o.servers) > 0 {
		// `$vkurls` stands for VK's own relays — the credential's — in its
		// place (issue #105 (2)).
		out := make([]string, 0, len(o.servers)+len(vk))
		for _, e := range o.servers {
			if e == TURNServersVK {
				out = append(out, vk...)
				continue
			}
			out = append(out, e)
		}
		return dedupeAddrs(out)
	}
	if o.host == "" && o.port == "" {
		return dedupeAddrs(vk)
	}
	out := make([]string, 0, len(vk))
	for _, a := range vk {
		h, p, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		if o.host != "" {
			h = o.host
		}
		if o.port != "" {
			p = o.port
		}
		out = append(out, net.JoinHostPort(h, p))
	}
	return dedupeAddrs(out)
}

// turnEntry is one entry of the TURN override list, read: host:port, or
// host:port:quota — the relay's limit of allocations per identity (2026-10-30,
// the user's design): 0 = the relay has no quota (the slot on it takes every
// connection, has no quota clock and no smart-pause, and takes everyone first
// while it answers); N > 0 = that limit, 10 being VK's — or
// host:port:quota:pace — the pace of this relay's connections in KiB/s of
// counted bytes (2026-11-07, the user's design), the same number in BOTH
// directions: the client's uplink bucket on that relay takes it in place of
// the app's toggle (uplinkpace.go), and the client declares it to the server
// for the downlink behind the hello (groupPaceMagic) in place of the server's
// -downlink-pace. 0 = no pacer: the user's own relay has no per-allocation
// policer, and the pacers are its cost alone (Nov 4 §562: 72 → 224 on the
// uplink). Absent = each direction's default. The pace rides on the quota
// field, never without it: both are the relay's own properties, and the
// relay without a quota is the one with no policer.
// paceFieldMax is the pace field's ceiling: the declaration's uint16, 65535
// KiB/s (≈537 Mbit/s per connection — no relay of ours is near it).
const paceFieldMax = 0xffff

type turnEntry struct {
	addr        string
	quota, pace int
	hasQuota    bool
	hasPace     bool
}

// parseTURNEntry reads one entry; ok false: none of the three forms.
func parseTURNEntry(e string) (t turnEntry, ok bool) {
	if _, _, err := net.SplitHostPort(e); err == nil {
		return turnEntry{addr: e}, true
	}
	field := func(s string) (base string, n int, ok bool) {
		i := strings.LastIndex(s, ":")
		if i <= 0 {
			return "", 0, false
		}
		base, f := s[:i], s[i+1:]
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || f != strconv.Itoa(n) {
			return "", 0, false
		}
		return base, n, true
	}
	base, q, ok := field(e)
	if !ok {
		return turnEntry{}, false
	}
	if _, _, err := net.SplitHostPort(base); err == nil {
		return turnEntry{addr: base, quota: q, hasQuota: true}, true
	}
	// Two fields: the one just read was the pace, the one before it the
	// quota. The pace is bounded by its wire form — the declaration carries
	// a uint16 (groupPaceBytes) — so that the uplink and the downlink never
	// read two rates off one field (the user's review of 9d58dda).
	if q > paceFieldMax {
		return turnEntry{}, false
	}
	base2, q2, ok := field(base)
	if !ok {
		return turnEntry{}, false
	}
	if _, _, err := net.SplitHostPort(base2); err != nil {
		return turnEntry{}, false
	}
	return turnEntry{addr: base2, quota: q2, hasQuota: true, pace: q, hasPace: true}, true
}

// String is the spelling of an entry with its fields, when it has them — the
// list as configured and as resolved keep the fields.
func (t turnEntry) String() string {
	s := t.addr
	if t.hasQuota {
		s += ":" + strconv.Itoa(t.quota)
	}
	if t.hasPace {
		s += ":" + strconv.Itoa(t.pace)
	}
	return s
}

// setServers takes the list as resolved — entries with their quota and pace
// fields — and keeps the ADDRESSES (what the pool dials) apart from them.
func (o *turnOverride) setServers(list []string) {
	o.servers, o.quotas, o.paces = nil, nil, nil
	for _, e := range list {
		if e == TURNServersVK {
			o.servers = append(o.servers, e)
			continue
		}
		t, ok := parseTURNEntry(e)
		if !ok {
			// Not one of the three forms: dropped, never an address to dial
			// (the user's review of 7271aef — the app's validator had let a
			// `host:port:10:65536` through, and this kept it «as a name»). A
			// NAME that did not resolve is host:port and stays.
			log.Printf("credpool: TURN relay override: %q is not host:port[:quota[:pace]] — ignored", e)
			continue
		}
		o.servers = append(o.servers, t.addr)
		if t.hasQuota {
			if o.quotas == nil {
				o.quotas = map[string]int{}
			}
			o.quotas[t.addr] = t.quota
		}
		if t.hasPace {
			if o.paces == nil {
				o.paces = map[string]int{}
			}
			o.paces[t.addr] = t.pace
		}
	}
	o.servers = dedupeAddrs(o.servers)
}

// quota: the relay's configured limit, when the list gives one (0 = none).
func (o turnOverride) quota(addr string) (int, bool) {
	q, ok := o.quotas[addr]
	return q, ok
}

// unlimited: the list says this relay has no quota.
func (o turnOverride) unlimited(addr string) bool {
	q, ok := o.quotas[addr]
	return ok && q == 0
}

// pace: the relay's configured pace in KiB/s, when the list gives one (0 =
// no pacer); ok false = the direction's default applies.
func (o turnOverride) pace(addr string) (int, bool) {
	p, ok := o.paces[addr]
	return p, ok
}

func dedupeAddrs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// TURNServersVK is the word in the TURN override list that stands for VK's own
// relays — the addresses the credential came with — in its place (issue #105
// (2)): `myrelay.example:19302,$vkurls` dials the user's relay while it
// answers and VK's when it does not. Alone it is no override. A `$` so that
// it can be no DNS name; folded to lower case by ParseTURNServers.
const TURNServersVK = "$vkurls"

// ParseTURNServers reads the TURN override list as the app's setting and the
// console's flag spell it: host:port entries separated by commas, spaces or
// newlines; each port numeric. An empty string is no override.
func ParseTURNServers(raw string) ([]string, error) {
	f := func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }
	var out []string
	seen := map[string]bool{} // by ADDRESS: one spelling of a relay, the first
	for _, e := range strings.FieldsFunc(raw, f) {
		if strings.EqualFold(e, TURNServersVK) {
			if !seen[TURNServersVK] {
				out = append(out, TURNServersVK) // VK's own relays, in this place
				seen[TURNServersVK] = true
			}
			continue
		}
		t, ok := parseTURNEntry(e)
		if !ok {
			return nil, &TURNServerListError{Entry: e}
		}
		h, p, err := net.SplitHostPort(t.addr)
		if err != nil || h == "" {
			return nil, &TURNServerListError{Entry: e}
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, &TURNServerListError{Entry: e}
		}
		t.addr = net.JoinHostPort(h, p)
		if seen[t.addr] {
			continue
		}
		seen[t.addr] = true
		out = append(out, t.String())
	}
	return out, nil
}

// TURNServerListError names the entry of a TURN override list that is not
// host:port with a numeric port.
type TURNServerListError struct{ Entry string }

func (e *TURNServerListError) Error() string {
	return "TURN server " + strconv.Quote(e.Entry) + " is not host:port[:quota[:pace]] (nor " + TURNServersVK + ")"
}

// lookupTURNHost is the bounded lookup behind ResolveTURNServers for a name
// the app did not pre-resolve (a test swaps it).
var lookupTURNHost = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// ResolveTURNServers turns the override list's DNS names into IP entries
// before the pool sees them (issue #105): an entry whose host is an IP stays;
// a name becomes one entry per IPv4 address it resolves to, in its place —
// from `pre` (the app's pre-resolved map, which the main app fills on the
// physical path before the extension starts) or, failing that, a bounded
// lookup; a name that resolves to nothing stays as it is (the dial resolves
// it later, and no name is ever published as the tunnel's remote address —
// relayHostToPublish). Why not leave names to the dial: the relay health,
// the cookie slots and the console's route pins all key on host:port, the
// extension's resolver lost 5 s to a timeout on the first dial in the field,
// and iOS refuses a name for the tunnel's remote address.
func ResolveTURNServers(ctx context.Context, servers []string, pre func(host string) []string) []string {
	var out []string
	for _, e := range servers {
		if e == TURNServersVK {
			out = append(out, e) // the word for VK's relays stays in its place
			continue
		}
		t, ok := parseTURNEntry(e)
		if !ok {
			log.Printf("credpool: TURN relay override: %q is not host:port[:quota[:pace]] — ignored", e)
			continue // never an address to dial (the user's review of 7271aef)
		}
		host, port, err := net.SplitHostPort(t.addr)
		if err != nil || net.ParseIP(host) != nil {
			out = append(out, e)
			continue
		}
		var ips []string
		if pre != nil {
			for _, ip := range pre(host) {
				if p := net.ParseIP(ip); p != nil && p.To4() != nil {
					ips = append(ips, p.String())
				}
			}
		}
		if len(ips) == 0 {
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			resolved, lerr := lookupTURNHost(lctx, host)
			cancel()
			for _, ip := range resolved {
				if ip.To4() != nil {
					ips = append(ips, ip.String())
				}
			}
			if lerr != nil || len(ips) == 0 {
				log.Printf("credpool: TURN relay %s: the name did not resolve (%v) — kept as a name; the dial resolves it, and it is never published as the tunnel's address", e, lerr)
				out = append(out, e)
				continue
			}
		}
		for _, ip := range ips {
			t.addr = net.JoinHostPort(ip, port)
			out = append(out, t.String()) // the name's quota and pace fields on each IP
		}
		log.Printf("credpool: TURN relay %s resolved to %s", e, strings.Join(ips, ", "))
	}
	return dedupeAddrs(out)
}

// relayHostToPublish is the host of a relay address as the app may use it for
// the tunnel's remote address: an IP, or nothing — iOS refuses a name there
// (issue #105: "Invalid NETunnelNetworkSettings tunnelRemoteAddress"), and a
// name reaching this point means its resolution failed upstream.
func relayHostToPublish(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return "", false
	}
	return host, true
}
