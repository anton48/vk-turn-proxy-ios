package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"time"
)

// Distinguish a peer handshake failure from TURN setup failures.
type transportHandshakeError struct{ error }

func (e *transportHandshakeError) Unwrap() error { return e.error }

// A handshake timeout changes only this connection's relay preference.
// TURN control replies remain valid health evidence for other connections.
func (cp *credPool) noteHandshakeResult(ctx context.Context, connIdx int, generation uint64, addr string, start time.Time, err error) {
	var networkError net.Error
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &networkError) && networkError.Timeout()) {
		return
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if ctx.Err() != nil || start.Before(cp.health.pathChangedAt) || cp.handStamp[connIdx] != generation {
		return
	}
	if err == nil {
		delete(cp.handshakeFailures, connIdx)
		return
	}
	if cp.handshakeFailures[connIdx] == nil {
		cp.handshakeFailures[connIdx] = map[string]bool{}
	}
	cp.handshakeFailures[connIdx][addr] = true
	cp.cursor[connIdx]++
	log.Printf("credpool: conn %d: peer handshake timed out via relay %s — preferring another available relay on the next attempt", connIdx, addr)
}

// Keep the existing cursor order while passing over handshake failures.
// With no alternatives, retain the usual selection and retry backoff.
func (cp *credPool) pickAliveRelayLocked(slot int, addrs []string, connIdx int) string {
	failed := cp.handshakeFailures[connIdx]
	if len(failed) > 0 {
		index := cp.cursor[connIdx] % len(addrs)
		if index < 0 {
			index = -index
		}
		now := time.Now()
		fallback := ""
		for offset := range addrs {
			addr := addrs[(index+offset)%len(addrs)]
			if !cp.freshOnLocked(slot, addr) || now.Before(cp.markLocked(slot, addr)) || !cp.roomOnLocked(slot, addr) {
				continue
			}
			if fallback == "" {
				fallback = addr
			}
			if !failed[addr] {
				return addr
			}
		}
		if fallback != "" {
			return fallback
		}
		return addrs[index]
	}
	if addr, ok := cp.unlimitedFirstLocked(addrs); ok {
		return addr
	}
	return cp.cursorPickLocked(addrs, connIdx)
}
