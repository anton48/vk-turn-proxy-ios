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
			conn, err, observation := observePeerHandshake(context.Background(), time.Second, nil, func(context.Context, func()) (net.Conn, error) {
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
			_, err, observation := observePeerHandshake(ctx, timeout, nil, func(handshake context.Context, _ func()) (net.Conn, error) {
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
		_, err, observation := observePeerHandshake(context.Background(), 10*time.Millisecond, nil, func(ctx context.Context, _ func()) (net.Conn, error) {
			<-ctx.Done()
			return nil, failure
		})
		if !errors.Is(err, failure) || observation.timedOut {
			t.Fatalf("kernel or successful return at the deadline became peer silence: %+v, %v", observation, err)
		}
	}
}

func TestHandshakeClockChecksTheFinalGap(t *testing.T) {
	started := time.Now()
	finished := make(chan time.Time, 1)
	finished <- started.Add(defaultWakeProbeFreezeStep + time.Millisecond)
	if !watchHandshakeClock(started, nil, finished) {
		t.Fatal("the handshake clock ignored the suspension before completion")
	}
}

func TestHandshakeSnapshotsTrafficBeforeTheLastRetry(t *testing.T) {
	started := time.Now()
	var sends handshakeSends
	var lastRx int64
	snapshot := func(received []int64) []int64 {
		if received == nil {
			received = make([]int64, 1)
		}
		received[0] = lastRx
		return received
	}
	sends.note(started, snapshot)
	sends.note(started.Add(time.Millisecond), snapshot)
	if !sends.lastRetry.IsZero() {
		t.Fatal("a second datagram from the first flight counted as a retry")
	}

	earlyPacket := started.Add(5 * time.Second)
	lastRx = earlyPacket.UnixNano()
	retry := started.Add(7 * time.Second)
	sends.note(retry, snapshot)
	lastRx = started.Add(9 * time.Second).UnixNano()
	if !sends.lastRetry.Equal(retry) || sends.received[0] != earlyPacket.UnixNano() {
		t.Fatal("the late packet replaced traffic observed before the retry")
	}
}

func TestPeerHandshakeWithoutALeaseIsIgnored(t *testing.T) {
	cp, clock := peerHandshakePool(t, false, relayA)
	p := Proxy{credPool: cp}
	p.notePeerHandshake(context.Background(), 0, 0, relayA,
		handshakeObservation{started: *clock, ended: clock.Add(time.Second), timedOut: true}, context.DeadlineExceeded)
	if timeouts, _ := cp.peerHandshakeStats(); timeouts != 0 {
		t.Fatal("a handshake without a lease affected relay health")
	}
}
