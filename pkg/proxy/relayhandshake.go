package proxy

import (
	"context"
	"log"
	"time"
)

type peerHandshake struct {
	generation uint64
	relay      string
	window     handshakeObservation
}

// One alternate is explored on a path, with the existing relay probe backoff.
// If both routes fail, normal retries stay on the primary instead of using
// every cookie slot while the VPN server may be unavailable.
type relayHandshakeProbe struct {
	primary, alternate string
	slot, conn         int
	pending            bool
	claimedUntil       time.Time
	next               time.Time
	retries            int
}

func (cp *credPool) notePeerHandshakeResult(ctx context.Context, connIdx int, generation uint64, relay string, window handshakeObservation, err error, received []int64) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if ctx.Err() != nil || window.suspended || window.started.Before(cp.health.pathChangedAt) || cp.handStamp[connIdx] != generation {
		return
	}
	if err == nil {
		delete(cp.health.peerFailed, relay)
		cp.peerHandshakes[connIdx] = peerHandshake{generation: generation, relay: relay, window: window}
		delete(cp.peerFailures, relay)
		if cp.peerProbe.primary == relay {
			cp.peerProbe = relayHandshakeProbe{}
		}
		for failed, failure := range cp.peerFailures {
			if failed != relay && handshakeWindowsOverlap(failure, window) {
				cp.markPeerFailedLocked(failed)
			}
		}
		return
	}
	if !window.timedOut {
		return
	}
	cp.peerTimeouts++
	cp.peerFailures[relay] = window
	for conn, success := range cp.peerHandshakes {
		if success.relay == relay || cp.health.peerFailed[success.relay] || cp.handStamp[conn] != success.generation {
			continue
		}
		overlap := handshakeWindowsOverlap(window, success.window)
		if conn >= 0 && conn < len(received) && received[conn] != 0 {
			at := time.Unix(0, received[conn])
			overlap = overlap || !at.Before(window.started) && !at.After(window.ended) && !at.Before(success.window.ended)
		}
		if overlap {
			cp.markPeerFailedLocked(relay)
			return
		}
	}
	cp.planPeerProbeLocked(connIdx, relay)
}

func handshakeWindowsOverlap(a, b handshakeObservation) bool {
	return !a.started.After(b.ended) && !b.started.After(a.ended)
}

func (cp *credPool) markPeerFailedLocked(relay string) {
	if cp.health.peerFailed[relay] {
		return
	}
	cp.health.peerFailed[relay] = true
	cp.peerMarks++
	delete(cp.peerFailures, relay)
	if cp.peerProbe.primary == relay {
		cp.peerProbe = relayHandshakeProbe{}
	}
	log.Printf("credpool: relay %s peer handshake failed while another relay carried the peer connection — avoiding new attempts until peer recovery or a network-path change", relay)
}

func (cp *credPool) peerRelayReadyLocked(slot int, relay string) bool {
	if slot < 0 || slot >= len(cp.pool) || cp.configuredOffLocked(slot) || len(cp.health.untried([]string{relay})) == 0 {
		return false
	}
	return cp.freshOnLocked(slot, relay) && !cp.health.now().Before(cp.markLocked(slot, relay)) && cp.roomOnLocked(slot, relay)
}

func (cp *credPool) planPeerProbeLocked(connIdx int, relay string) {
	now := cp.health.now()
	probe := &cp.peerProbe
	if probe.primary != "" && !cp.hasPeerRelayLocked(probe.primary) {
		*probe = relayHandshakeProbe{}
	}
	if probe.alternate != "" && !cp.hasPeerRelayLocked(probe.alternate) {
		*probe = relayHandshakeProbe{primary: probe.primary}
	}
	if probe.primary == "" {
		probe.primary = relay
	}
	if probe.primary != relay || now.Before(probe.next) || probe.pending && now.Before(probe.claimedUntil) {
		return
	}
	for slot := 0; slot < cp.size && slot < len(cp.pool); slot++ {
		for _, candidate := range cp.candidatesLocked(slot) {
			if candidate == relay || probe.alternate != "" && candidate != probe.alternate || !cp.peerRelayReadyLocked(slot, candidate) {
				continue
			}
			probe.alternate, probe.slot, probe.conn = candidate, slot, connIdx
			probe.pending, probe.claimedUntil = true, now.Add(relayProbeClaim)
			return
		}
	}
}

func (cp *credPool) hasPeerRelayLocked(relay string) bool {
	for slot := 0; slot < cp.size && slot < len(cp.pool); slot++ {
		for _, candidate := range cp.candidatesLocked(slot) {
			if candidate == relay {
				return true
			}
		}
	}
	return false
}

// Peek and allocation use the same reservation, consumed by handOutLocked.
func (cp *credPool) peerProbeChoiceLocked(connIdx int) (int, string, bool) {
	probe := cp.peerProbe
	if !probe.pending || probe.conn != connIdx || !cp.health.now().Before(probe.claimedUntil) || !cp.peerRelayReadyLocked(probe.slot, probe.alternate) {
		return 0, "", false
	}
	for _, relay := range cp.candidatesLocked(probe.slot) {
		if relay == probe.alternate {
			return probe.slot, relay, true
		}
	}
	return 0, "", false
}

func (cp *credPool) claimPeerProbeLocked(connIdx, slot int, relay string) {
	probe := &cp.peerProbe
	if probe.pending && probe.conn == connIdx && probe.slot == slot && probe.alternate == relay {
		probe.pending = false
		probe.next = cp.health.now().Add(probeBackoff(probe.retries))
		probe.retries++
		log.Printf("credpool: conn %d: probing relay %s after a peer handshake timeout via %s", connIdx, relay, probe.primary)
	}
}

func (cp *credPool) peerHandshakeStats() (timeouts, marked uint64) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.peerTimeouts, cp.peerMarks
}
