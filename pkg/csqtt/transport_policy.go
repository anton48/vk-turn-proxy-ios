// SPDX-License-Identifier: MIT

package csqtt

import (
	"sync"
	"time"
)

const autoHandshakeBudget = 8 * time.Second
const transportCooldown = 30 * time.Second
const transportSampleAge = 2 * time.Minute

// transportPolicy is shared by workers, not credentials or networks. Samples
// measure GETCONF completion latency (including retries), not Allocate time
// or inferred throughput. Only
// new sessions explore: a healthy session is never torn down for a benchmark.
type transportPolicy struct {
	mu        sync.Mutex
	epoch     uint64
	preferred int
	samples   [2]transportSample
}

type transportSample struct {
	rtt          time.Duration
	at           time.Time
	blockedUntil time.Time
}

func transportIndex(name string) int {
	if name == "tcp" {
		return 1
	}
	return 0
}

func (p *transportPolicy) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	p.preferred = 0
	p.samples = [2]transportSample{}
}

func (p *transportPolicy) pick(now time.Time) (string, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.preferred
	other := 1 - i
	if now.Before(p.samples[i].blockedUntil) {
		if !now.Before(p.samples[other].blockedUntil) || p.samples[other].blockedUntil.Before(p.samples[i].blockedUntil) {
			i = other
		}
	} else if !now.Before(p.samples[other].blockedUntil) &&
		(p.samples[other].at.IsZero() && !p.samples[i].at.IsZero() ||
			!p.samples[other].at.IsZero() && now.Sub(p.samples[other].at) >= transportSampleAge) {
		i = other
	}
	return [2]string{"udp", "tcp"}[i], p.epoch
}

func (p *transportPolicy) success(epoch uint64, name string, rtt time.Duration, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != p.epoch {
		return
	}
	i := transportIndex(name)
	s := &p.samples[i]
	if rtt <= 0 {
		rtt = time.Microsecond
	}
	if s.rtt == 0 {
		s.rtt = rtt
	} else {
		s.rtt = (s.rtt*3 + rtt) / 4
	}
	s.at, s.blockedUntil = now, time.Time{}
	old := p.samples[p.preferred]
	// A 25% margin avoids bouncing between nearly equal paths.
	if old.rtt == 0 || now.Before(old.blockedUntil) || s.rtt < old.rtt*3/4 {
		p.preferred = i
	}
}

func (p *transportPolicy) failure(epoch uint64, name string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if epoch != p.epoch {
		return
	}
	i := transportIndex(name)
	p.samples[i].blockedUntil = now.Add(transportCooldown)
	p.samples[i].at = now
	p.preferred = 1 - i
}
