package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type handshakeObservation struct {
	started, ended time.Time
	lastRetry      time.Time
	received       []int64
	timedOut       bool
	suspended      bool
}

// Apply the existing wake-probe freeze threshold to the handshake window.
// The final sample covers a suspension immediately before the deadline fires.
type handshakeClock struct {
	last      time.Time
	suspended bool
}

func (c *handshakeClock) sample(now time.Time) {
	if now.Sub(c.last) > defaultWakeProbeFreezeStep {
		c.suspended = true
	}
	if now.After(c.last) {
		c.last = now
	}
}

func watchHandshakeClock(started time.Time, ticks, finished <-chan time.Time) bool {
	clock := handshakeClock{last: started}
	for {
		select {
		case <-ticks:
			clock.sample(time.Now())
		case ended := <-finished:
			clock.sample(ended)
			return clock.suspended
		}
	}
}

// Pion's default first retransmission interval is one second. Ignore
// multiple datagrams from the initial flight when looking for a later send.
const peerHandshakeFirstRetry = time.Second

type handshakeSends struct {
	mu        sync.Mutex
	first     time.Time
	lastRetry time.Time
	received  []int64
	finished  bool
}

func (s *handshakeSends) note(now time.Time, snapshotTraffic func([]int64) []int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}
	if s.first.IsZero() {
		s.first = now
	}
	if now.Sub(s.first) < peerHandshakeFirstRetry || now.Before(s.lastRetry) {
		return
	}
	if snapshotTraffic != nil {
		s.received = snapshotTraffic(s.received)
	}
	s.lastRetry = now
}

func observePeerHandshake(ctx context.Context, timeout time.Duration, snapshotTraffic func([]int64) []int64, dial func(context.Context, func()) (net.Conn, error)) (net.Conn, error, handshakeObservation) {
	observation := handshakeObservation{started: time.Now()}
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	finished := make(chan time.Time, 1)
	suspended := make(chan bool, 1)
	go func(started time.Time) {
		tick := time.NewTicker(defaultWakeProbePoll)
		defer tick.Stop()
		suspended <- watchHandshakeClock(started, tick.C, finished)
	}(observation.started)
	var sends handshakeSends
	conn, err := dial(hsCtx, func() { sends.note(time.Now(), snapshotTraffic) })
	sends.mu.Lock()
	sends.finished = true
	observation.ended = time.Now()
	observation.lastRetry = sends.lastRetry
	observation.received = sends.received
	sends.mu.Unlock()
	observation.timedOut = errors.Is(err, context.DeadlineExceeded) && hsCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
	finished <- observation.ended
	observation.suspended = <-suspended
	return conn, err, observation
}

func (p *Proxy) notePeerHandshake(ctx context.Context, connIdx int, generation uint64, relay string, observation handshakeObservation, err error) {
	// Generation zero denotes a setup without a leased session.
	if generation == 0 {
		return
	}
	if observation.suspended {
		p.handshakeSuspended.Add(1)
	}
	received := observation.received
	observation.received = nil
	p.credPool.notePeerHandshakeResult(ctx, connIdx, generation, relay, observation, err, received)
}

func (p *Proxy) snapshotPeerTraffic(received []int64) []int64 {
	if received == nil {
		received = make([]int64, len(p.lastRxAt))
	}
	for i := range received {
		received[i] = p.lastRxAt[i].Load()
	}
	return received
}
