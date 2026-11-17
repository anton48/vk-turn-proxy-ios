package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionHandshakeTimeoutRotatesRelayAfterCleanup(t *testing.T) {
	for _, transport := range []string{"SRTP UDP", "SRTP TCP", "DTLS UDP", "DTLS TCP"} {
		t.Run(transport, func(t *testing.T) {
			udp := transport == "SRTP UDP" || transport == "DTLS UDP"
			srtp := transport == "SRTP UDP" || transport == "SRTP TCP"
			user := futureUser("handshake-timeout")
			known := func(username string) bool { return username == user }
			first := newLaggingRelay(t, 1, 0, known, udp)
			second := newLaggingRelay(t, 1, 0, known, udp)
			peer := silentPeer(t)
			p := NewProxy(Config{UseUDP: udp, UseSrtp: srtp, UseDTLS: true, NumConns: 1, PeerAddr: peer.String()})
			p.peer = peer
			t.Cleanup(p.cancel)
			p.credPool = newCredPool(p.ctx, 1, 0, "", func(bool, int) (string, *TURNCreds, error) {
				t.Error("a handshake timeout must retain the credential")
				return "", nil, errors.New("unexpected credential fetch")
			})
			p.credPool.seedSlot(0, first.addr, &TURNCreds{
				Username: user, Password: "pw", Address: first.addr,
				Addresses: []string{first.addr, second.addr},
			})
			for attempt, relay := range []*laggingRelay{first, second} {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				signaled := false
				var err error
				if srtp {
					err = p.runSRTPSession(ctx, "", nil, &signaled, 0)
				} else {
					err = p.runDTLSSession(ctx, "", nil, &signaled, 0)
				}
				cancel()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("attempt %d: expected handshake deadline, got %v", attempt, err)
				}
				if !p.credPool.handshakeFailures[0][relay.addr] {
					t.Fatalf("attempt %d did not record handshake failure on %s", attempt, relay.addr)
				}
				waitUntil(t, "released TURN allocation", 2*time.Second, func() bool {
					return relay.srv.AllocationCount() == 0
				})
				if udp && (relay.givenBack() != 1 || p.dealloc.confirmed.Load() != int64(attempt+1)) {
					t.Fatalf("attempt %d missed UDP deallocation confirmation", attempt)
				}
			}
			waitUntil(t, "released leases after the relay seat cooldown", 3*time.Second, func() bool {
				p.credPool.mu.Lock()
				defer p.credPool.mu.Unlock()
				return p.credPool.liveLeasesLocked() == 0
			})
		})
	}
}
