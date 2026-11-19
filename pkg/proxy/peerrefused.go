package proxy

import (
	"log"
	"strings"
	"time"
)

// A relay that REFUSES the permission for our peer.
//
// A phone, 2026-11-19: the user's own relay first in the override list, started
// with an allow-list of peers that did not name the server. The relay accepts
// the allocation and answers CreatePermission with an error — in milliseconds.
// That is an ANSWER, so the relay health (which marks silence) heard nothing;
// it is no quota and no auth error; and the session never reaches the peer
// handshake the peer mark watches. Nobody read it: conn 0 was handed the same
// slot and the same relay five times, the bootstrap's pauses between them, and
// the tunnel was stopped at its two minutes.
//
// The refusal is the relay's own word that it will not relay to this peer —
// another kind of fact than silence, and it needs no witness from another
// relay: the relay is given the PEER mark at once (relayhandshake.go). New
// attempts go elsewhere; the mark's recovery checks try it again on their
// schedule and a session that comes up through it clears the mark, so a relay
// whose list is mended returns by itself. A path change clears it with the
// other marks.
//
// 🚫 NARROW: an error response to CreatePermission with NO error code (pion's
// server answers so when its permission handler refuses the peer) or with 403
// Forbidden (RFC 5766: the server's policy). Never 400 or 437 — on a VK relay
// those mean "no allocation for this 5-tuple", a changed mapping, the path's
// event (outofreach.go) — and never 401 / 438, the credential's.
// 🚫 A 403 on the PERMISSION is not an auth error: the credential made the
// allocation a moment earlier (isAuthError asks here first — invalidating the
// slot would mint a new credential for the same refusal, every attempt).

// permissionErrorResponse is pion's word for the relay's error-class answer to
// CreatePermission: alone when the answer carries no ERROR-CODE, followed by
// " (error <code>: <reason>)" when it does (pinned against pion's source).
const permissionErrorResponse = "CreatePermission error response"

// isPeerRefused: err is the relay's refusal of a permission for our peer.
func isPeerRefused(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	i := strings.Index(s, permissionErrorResponse)
	if i < 0 {
		return false
	}
	rest := s[i+len(permissionErrorResponse):]
	if !strings.HasPrefix(rest, " (error ") {
		return true // no code: the server's handler refused the peer
	}
	return strings.HasPrefix(rest, " (error 403:")
}

// IsPeerRefused — for the pool's second owner (csqtt), as IsQuotaError is.
func IsPeerRefused(err error) bool { return isPeerRefused(err) }

// notePeerRefused: the relay answered connIdx's CreatePermission for our peer
// with a refusal, on an attempt begun at start. The relay is peer-marked at
// once; a refusal of a relay already marked (a recovery check) leaves the mark
// and its schedule as they are. An attempt begun before the last path change
// says nothing about the network we are on now.
func (cp *credPool) notePeerRefused(connIdx int, relay string, start time.Time) {
	if cp == nil || relay == "" {
		return
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if start.Before(cp.health.pathChangedAt) {
		return
	}
	if !cp.peerMarkLocked(relay) {
		log.Printf("credpool: conn %d: relay %s refused the permission for our peer again — its mark stands", connIdx, relay)
		return
	}
	log.Printf("credpool: conn %d: relay %s REFUSED the permission for our peer — marked at once (its own answer needs no witness): new attempts go elsewhere, recovery checks apart", connIdx, relay)
}

// NotePeerRefused tells the pool that the relay at addr refused a permission
// for our peer on an attempt begun at start (csqtt's dial — the bridge's
// lease). See notePeerRefused.
func (p *CredPool) NotePeerRefused(connIdx int, addr string, start time.Time) {
	p.cp.notePeerRefused(connIdx, addr, start)
}

// relayRefusedPeer is the relay leg's way out on a failed CreatePermission:
// a REFUSAL is told to the pool, the error goes back as it is. Any other
// error passes through untouched.
func (p *Proxy) relayRefusedPeer(connIdx int, turnAddr string, attempt time.Time, err error) error {
	if isPeerRefused(err) {
		p.credPool.notePeerRefused(connIdx, turnAddr, attempt)
	}
	return err
}
