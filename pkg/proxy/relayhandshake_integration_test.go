package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
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
			runSession := p.runDTLSSession
			if srtp {
				runSession = p.runSRTPSession
			}
			for attempt, relay := range []*laggingRelay{first, second} {
				wantRetry := udp && attempt == 0
				timeout := 150 * time.Millisecond
				if wantRetry {
					// Exercise one actual DTLS retransmission in each transport family.
					timeout = peerHandshakeFirstRetry + 500*time.Millisecond
				}
				p.dtlsHandshakeTimeout, p.srtpHandshakeTimeout = timeout, timeout
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				signaled := false
				err := runSession(ctx, "", nil, &signaled, 0)
				cancel()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("attempt %d: expected handshake deadline, got %v", attempt, err)
				}
				if addr, ok := p.connRelayOf(0); !ok || addr != relay.addr {
					t.Fatalf("attempt %d used relay %q, want %q", attempt, addr, relay.addr)
				}
				timeouts, marked := p.credPool.peerHandshakeStats()
				if timeouts != uint64(attempt+1) || marked != 0 || p.credPool.health.isDead(relay.addr) {
					t.Fatalf("attempt %d lost deadline telemetry or marked a relay without peer evidence", attempt)
				}
				p.credPool.mu.Lock()
				retry := p.credPool.peerFailures[relay.addr].lastRetry
				p.credPool.mu.Unlock()
				if gotRetry := !retry.IsZero(); gotRetry != wantRetry {
					t.Fatalf("attempt %d recorded a handshake retransmission: %t, want %t", attempt, gotRetry, wantRetry)
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

func TestLegacyHandshakeWaitsForTURNReadiness(t *testing.T) {
	var delayed sync.Once
	user := futureUser("readiness")
	relay := newLaggingRelay(t, 1, 0, func(username string) bool {
		delayed.Do(func() { time.Sleep(200 * time.Millisecond) })
		return username == user
	}, true)
	peer := dtlsPeer(t)
	p := NewProxy(Config{UseUDP: true, UseDTLS: true, NumConns: 1, PeerAddr: peer.String()})
	p.dtlsHandshakeTimeout = 80 * time.Millisecond
	p.peer = peer
	t.Cleanup(p.cancel)
	p.credPool = newCredPool(p.ctx, 1, 0, "", func(bool, int) (string, *TURNCreds, error) {
		return "", nil, errors.New("unexpected credential fetch")
	})
	p.credPool.seedSlot(0, relay.addr, &TURNCreds{Username: user, Password: "pw", Address: relay.addr, Addresses: []string{relay.addr}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		signaled := false
		done <- p.runDTLSSession(ctx, "", ready, &signaled, 0)
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("legacy handshake consumed its deadline before TURN readiness: %v", err)
	case <-ctx.Done():
		t.Fatal("legacy handshake never became ready")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("legacy session did not finish cleanup after cancellation")
	}
	timeouts, marked := p.credPool.peerHandshakeStats()
	if timeouts != 0 || marked != 0 || relay.srv.AllocationCount() != 0 || p.dealloc.confirmed.Load() != 1 {
		t.Fatal("allocation delay became a peer timeout or session cleanup was incomplete")
	}
}

func TestLegacyCancellationBeforeAllocationDoesNotObservePeerHandshake(t *testing.T) {
	entered := make(chan struct{})
	proceed := make(chan struct{})
	defer close(proceed)
	var requested sync.Once
	relay := newLaggingRelay(t, 1, 0, func(string) bool {
		requested.Do(func() { close(entered) })
		<-proceed
		return false
	}, true)
	p := NewProxy(Config{UseUDP: true, UseDTLS: true, NumConns: 1})
	p.peer = silentPeer(t)
	t.Cleanup(p.cancel)
	p.credPool = newCredPool(p.ctx, 1, 0, "", func(bool, int) (string, *TURNCreds, error) {
		return "", nil, errors.New("unexpected credential fetch")
	})
	p.credPool.seedSlot(0, relay.addr, &TURNCreds{Username: futureUser("cancel-before-allocation"), Password: "pw", Address: relay.addr, Addresses: []string{relay.addr}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		signaled := false
		done <- p.runDTLSSession(ctx, "", nil, &signaled, 0)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("TURN allocation was never requested")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the pending TURN allocation")
	}
	timeouts, marked := p.credPool.peerHandshakeStats()
	if p.handshakeSuspended.Load() != 0 || timeouts != 0 || marked != 0 {
		t.Fatal("cancellation before allocation changed peer handshake telemetry or health")
	}
}

func TestWakeDuringHandshakeIsExcludedFromPeerEvidence(t *testing.T) {
	t.Run("DTLS", func(t *testing.T) { testWakeDuringHandshake(t, false) })
	t.Run("SRTP", func(t *testing.T) { testWakeDuringHandshake(t, true) })
}

func testWakeDuringHandshake(t *testing.T, srtp bool) {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	user := futureUser("wake-inside-handshake")
	relay := newLaggingRelay(t, 1, 0, func(username string) bool { return username == user }, true)
	p := NewProxy(Config{UseUDP: true, UseSrtp: srtp, UseDTLS: true, NumConns: 1})
	p.dtlsHandshakeTimeout = 300 * time.Millisecond
	p.srtpHandshakeTimeout = 300 * time.Millisecond
	p.peer = peer.LocalAddr().(*net.UDPAddr)
	t.Cleanup(p.cancel)
	p.credPool = newCredPool(p.ctx, 1, 0, "", func(bool, int) (string, *TURNCreds, error) {
		return "", nil, errors.New("unexpected credential fetch")
	})
	p.credPool.seedSlot(0, relay.addr, &TURNCreds{Username: user, Password: "pw", Address: relay.addr, Addresses: []string{relay.addr}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	runSession := p.runDTLSSession
	if srtp {
		runSession = p.runSRTPSession
	}
	go func() {
		signaled := false
		done <- runSession(ctx, "", nil, &signaled, 0)
	}()
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatalf("peer never received the first handshake packet: %v", err)
	}
	p.broadcastWake()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("silent peer returned an unexpected handshake result: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("handshake did not respect its deadline")
	}
	timeouts, marked := p.credPool.peerHandshakeStats()
	if p.handshakeSuspended.Load() != 1 || timeouts != 0 || marked != 0 || p.credPool.peerProbe.primary != "" {
		t.Fatal("a wake during the actual peer handshake became relay failure evidence")
	}
}
