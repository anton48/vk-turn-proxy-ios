package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestHandshakeObservationRequiresItsOwnDeadline(t *testing.T) {
	for _, failure := range []error{syscall.ETIMEDOUT, syscall.EAGAIN, context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			conn, err, observation := observePeerHandshake(context.Background(), time.Second, func(context.Context) (net.Conn, error) {
				return nil, failure
			})
			if conn != nil || !errors.Is(err, failure) || observation.timedOut || observation.suspended {
				t.Fatalf("immediate error became a handshake deadline: %+v, %v", observation, err)
			}
		})
	}
	for _, parent := range []string{"active", "deadline", "canceled"} {
		t.Run(parent, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			timeout := 40 * time.Millisecond
			switch parent {
			case "deadline":
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
			case "canceled":
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			_, err, observation := observePeerHandshake(ctx, timeout, func(handshake context.Context) (net.Conn, error) {
				<-handshake.Done()
				return nil, handshake.Err()
			})
			if err == nil || observation.timedOut != (parent == "active") || observation.suspended {
				t.Fatalf("parent %s: wrong deadline attribution: %+v, %v", parent, observation, err)
			}
			if observation.ended.Before(observation.started) {
				t.Fatal("handshake observation ended before it started")
			}
		})
	}
}

func TestHandshakeClockDetectsSuspensionIncludingTheFinalSample(t *testing.T) {
	start := time.Now()
	clock := handshakeClock{last: start}
	clock.sample(start.Add(100 * time.Millisecond))
	if clock.suspended {
		t.Fatal("a normal poll was classified as suspension")
	}
	ended := clock.last.Add(wakeProbeFreezeStep + time.Millisecond)
	clock.sample(ended)
	if !clock.suspended || !clock.last.Equal(ended) {
		t.Fatal("the final sample missed suspension before completion")
	}
	clock.sample(ended.Add(100 * time.Millisecond))
	if !clock.suspended {
		t.Fatal("a later normal sample cleared suspension")
	}
	last := clock.last
	clock.sample(start)
	if !clock.last.Equal(last) {
		t.Fatal("a delayed sample moved the observation clock backwards")
	}
}

func TestKernelTimeoutAtTheHandshakeDeadlineIsNotPeerSilence(t *testing.T) {
	for _, failure := range []error{syscall.ETIMEDOUT, syscall.EAGAIN, nil} {
		_, err, observation := observePeerHandshake(context.Background(), 10*time.Millisecond, func(ctx context.Context) (net.Conn, error) {
			<-ctx.Done()
			return nil, failure
		})
		if !errors.Is(err, failure) || observation.timedOut {
			t.Fatalf("kernel or successful return at the deadline became peer silence: %+v, %v", observation, err)
		}
	}
}
