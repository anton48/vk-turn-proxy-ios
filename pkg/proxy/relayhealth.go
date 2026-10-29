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
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// relayEvidenceWindow: how far before an unanswered attempt's start an
	// answer still counts as evidence that the network works — longer than
	// one UDP Allocate's retransmissions (≈ 25–40 s), shorter than a conn's
	// dormancy (30–60 s).
	relayEvidenceWindow = 60 * time.Second
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
}

type relayHealth struct {
	rec        map[string]*relayRecord
	lastAnswer time.Time // the latest answer on this path — a relay's or VK's API
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
// An attempt begun before the last path change says nothing. On a marked
// address only a RE-TRY that was handed out (probe) moves the backoff — not
// the late failures of attempts begun before the mark, which arrive by the
// dozen from parallel connections (the user's review: thirty of them had put
// the first re-try thirty minutes away).
func (h *relayHealth) unanswered(addr string, start time.Time) bool {
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
	if r.unanswered == 0 {
		r.unansweredSince = start
	}
	r.unanswered++
	if !h.lastAnswer.IsZero() && !h.lastAnswer.Before(start.Add(-relayEvidenceWindow)) {
		h.markLocked(r, now)
		return true
	}
	return false
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
	if addr != "" {
		if r := h.rec[addr]; r != nil {
			*r = relayRecord{}
		}
	}
	for a, r := range h.rec {
		if a == addr || r.dead || r.unanswered == 0 {
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
	h.lastAnswer = time.Time{}
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
	h.rec[dues[0].addr].claimedUntil, h.rec[dues[0].addr].claimedAt = now.Add(relayProbeClaim), now
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
	servers    []string
	host, port string
}

func (o turnOverride) set() bool { return len(o.servers) > 0 || o.host != "" || o.port != "" }

// candidatesFor is the list a credential may be dialled on: the override
// list when set, else the pair applied to VK's addresses, else VK's own —
// deduplicated, never empty when creds has an address.
func (o turnOverride) candidatesFor(creds *TURNCreds) []string {
	if len(o.servers) > 0 {
		return dedupeAddrs(o.servers)
	}
	var vk []string
	if creds != nil {
		vk = creds.Addresses
		if len(vk) == 0 && creds.Address != "" {
			vk = []string{creds.Address}
		}
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

// ParseTURNServers reads the TURN override list as the app's setting and the
// console's flag spell it: host:port entries separated by commas, spaces or
// newlines; each port numeric. An empty string is no override.
func ParseTURNServers(raw string) ([]string, error) {
	f := func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }
	var out []string
	for _, e := range strings.FieldsFunc(raw, f) {
		h, p, err := net.SplitHostPort(e)
		if err != nil || h == "" {
			return nil, &TURNServerListError{Entry: e}
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, &TURNServerListError{Entry: e}
		}
		out = append(out, net.JoinHostPort(h, p))
	}
	return dedupeAddrs(out), nil
}

// TURNServerListError names the entry of a TURN override list that is not
// host:port with a numeric port.
type TURNServerListError struct{ Entry string }

func (e *TURNServerListError) Error() string {
	return "TURN server " + strconv.Quote(e.Entry) + " is not host:port"
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
		host, port, err := net.SplitHostPort(e)
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
			out = append(out, net.JoinHostPort(ip, port))
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
