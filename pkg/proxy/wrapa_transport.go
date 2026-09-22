// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	wrapATransportCooldown  = 30 * time.Second
	wrapATransportSampleAge = 2 * time.Minute
	wrapABootstrapBudget    = 30 * time.Second
)

type wrapATransportSample struct {
	latency      time.Duration
	at           time.Time
	blockedUntil time.Time
}

// wrapATransportPolicy compares the whole usable-session bootstrap
// (TURN + DTLS + GETCONF), not merely a successful socket dial. It only
// selects transports for new sessions; a healthy session is never interrupted
// for benchmarking.
type wrapATransportPolicy struct {
	mu        sync.Mutex
	epoch     uint64
	initial   int
	preferred int
	samples   [2]wrapATransportSample
}

func newWrapATransportPolicy(useUDP bool) *wrapATransportPolicy {
	i := 1
	if useUDP {
		i = 0
	}
	return &wrapATransportPolicy{initial: i, preferred: i}
}

func wrapATransportIndex(name string) int {
	if name == "tcp" {
		return 1
	}
	return 0
}
func wrapATransportName(i int) string {
	if i == 1 {
		return "tcp"
	}
	return "udp"
}

func (p *wrapATransportPolicy) pick(connIdx, total int, now time.Time) (string, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.preferred
	other := 1 - i
	if now.Before(p.samples[i].blockedUntil) {
		if !now.Before(p.samples[other].blockedUntil) || p.samples[other].blockedUntil.Before(p.samples[i].blockedUntil) {
			i = other
		}
	} else if !now.Before(p.samples[other].blockedUntil) {
		if p.samples[i].at.IsZero() && p.samples[other].at.IsZero() && total > 1 {
			// Split the first pool across both transports. This learns without
			// tearing down the first usable session or extending cold start.
			i = (p.initial + connIdx) % 2
		} else if p.samples[other].at.IsZero() && !p.samples[i].at.IsZero() {
			i = other
		} else if !p.samples[other].at.IsZero() && now.Sub(p.samples[other].at) >= wrapATransportSampleAge {
			i = other
		}
	}
	return wrapATransportName(i), p.epoch
}

func (p *wrapATransportPolicy) success(epoch uint64, name string, latency time.Duration, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != p.epoch {
		return
	}
	i := wrapATransportIndex(name)
	s := &p.samples[i]
	if latency <= 0 {
		latency = time.Microsecond
	}
	if s.latency == 0 {
		s.latency = latency
	} else {
		s.latency = (s.latency*3 + latency) / 4
	}
	s.at, s.blockedUntil = now, time.Time{}
	old := p.samples[p.preferred]
	// Require a 25% improvement so normal relay jitter does not flap the pool.
	if old.latency == 0 || now.Before(old.blockedUntil) || s.latency < old.latency*3/4 {
		p.preferred = i
	}
}

func (p *wrapATransportPolicy) failure(epoch uint64, name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != p.epoch {
		return
	}
	i := wrapATransportIndex(name)
	p.samples[i].at = now
	p.samples[i].blockedUntil = now.Add(wrapATransportCooldown)
	p.preferred = 1 - i
}

func (p *wrapATransportPolicy) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	p.preferred = p.initial
	p.samples = [2]wrapATransportSample{}
}

func isWrapATransportFailure(err error) bool {
	if err == nil || isQuotaError(err) || isAuthError(err) {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "denied:") || strings.Contains(msg, "noconf") || strings.Contains(msg, "missing privatekey") {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	for _, marker := range []string{"timeout", "all retransmissions", "connection refused", "network is unreachable", "broken pipe", "reset by peer", "no route to host"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
