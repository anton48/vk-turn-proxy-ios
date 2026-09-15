package proxy

// The mark is the ALLOCATION, not the session. The user's control stand on
// build 391 (a real local TURN accepting nine allocations per credential and
// refusing the tenth, the SRTP handshake delayed, production runSRTPSession)
// found 391's mark — at "session established" — measuring session readiness:
// the relay held 18 allocations, the pool saw allocated 0,0, the breaker
// paused minting for a plain quota. Here the two native allocation sites are
// driven on the real stack against the loopback pion TURN with NOTHING above
// the allocation ever completing — runTURN forwards into a pipe nobody
// answers, setupSRTPSession's handshake goes to a silent peer — and the mark
// must be there anyway, the moment the relay's Allocate succeeds. Sabotage
// seen red: the marks moved back to "session established" (391's placement);
// either allocation site's mark dropped.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

func TestTheSlotIsMarkedAtTheTURNAllocationNotAtSessionReadiness(t *testing.T) {
	addr := loopbackTURN(t)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9} // nobody answers a handshake there
	creds := &TURNCreds{Username: "u", Password: "pw", Address: addr, Addresses: []string{addr}}
	newProxy := func() (*Proxy, *credPool) {
		var mints atomic.Int32
		cp := breakerPool(t, &mints)
		cp.mu.Lock()
		cp.pool[0] = credPoolEntry{addr: addr, ts: time.Now(), active: 1, creds: creds}
		cp.mu.Unlock()
		return &Proxy{peer: peer, credPool: cp, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}, cp
	}
	allocated := func(cp *credPool) int {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return cp.pool[0].allocated
	}

	t.Run("runTURN — where DTLS, direct and WRAP-A allocate", func(t *testing.T) {
		p, cp := newProxy()
		conn1, conn2 := connutil.AsyncPacketPipe()
		defer conn1.Close()
		defer conn2.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.runTURN(ctx, addr, creds, conn2, 0, 0) }()
		waitUntil(t, "the slot to be marked allocated", 5*time.Second, func() bool { return allocated(cp) == 1 })
		select {
		case err := <-done:
			t.Fatalf("runTURN returned before the cancel: %v", err)
		default: // still forwarding — no session exists above it, and the mark is already there
		}
		cancel()
		<-done
		if got := allocated(cp); got != 1 {
			t.Fatalf("allocated = %d after the cancel, want 1 — one allocation, one mark", got)
		}
	})

	t.Run("setupSRTPSession — where SRTP allocates, the handshake pending", func(t *testing.T) {
		p, cp := newProxy()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			c, err := p.setupSRTPSession(ctx, addr, creds, 0, 0)
			if c != nil {
				_ = c.Close()
			}
			done <- err
		}()
		waitUntil(t, "the slot to be marked allocated", 5*time.Second, func() bool { return allocated(cp) == 1 })
		select {
		case err := <-done:
			t.Fatalf("setupSRTPSession returned (%v) — the handshake toward a silent peer should still be pending", err)
		default:
		}
		cancel() // the handshake never completes: no session is ever established, the mark stays
		if err := <-done; err == nil {
			t.Fatal("setupSRTPSession succeeded against a silent peer")
		}
		if got := allocated(cp); got != 1 {
			t.Fatalf("allocated = %d, want 1 — the allocation counted whatever became of the handshake", got)
		}
	})
}
