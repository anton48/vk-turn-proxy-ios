package proxy

import (
	"context"
	"errors"
	"net"
	"time"
)

type handshakeObservation struct {
	started, ended time.Time
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
	if now.Sub(c.last) > wakeProbeFreezeStep {
		c.suspended = true
	}
	if now.After(c.last) {
		c.last = now
	}
}

func observePeerHandshake(ctx context.Context, timeout time.Duration, dial func(context.Context) (net.Conn, error)) (net.Conn, error, handshakeObservation) {
	observation := handshakeObservation{started: time.Now()}
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	finished := make(chan time.Time, 1)
	suspended := make(chan bool, 1)
	go func() {
		clock := handshakeClock{last: observation.started}
		tick := time.NewTicker(wakeProbePoll)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				clock.sample(time.Now())
			case ended := <-finished:
				clock.sample(ended)
				suspended <- clock.suspended
				return
			}
		}
	}()
	conn, err := dial(hsCtx)
	observation.ended = time.Now()
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
	var received []int64
	if observation.timedOut && !observation.suspended {
		received = make([]int64, len(p.lastRxAt))
		for i := range received {
			received[i] = p.lastRxAt[i].Load()
		}
	}
	p.credPool.notePeerHandshakeResult(ctx, connIdx, generation, relay, observation, err, received)
}
