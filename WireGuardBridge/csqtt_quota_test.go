//go:build ios

package main

// The relay's refusal must reach the POOL — the user's review, 2026-09-06:
// a local TURN answered 486 twice and the real client + adapter showed
// "486 rejections=2, VK mints=1, saturated slots=0, pool available=1": the
// worker retried the allocation with the SAME credential, because the
// pool's slot selection (skip a saturated slot, mint into another) can only
// act on what it is told, and the lease only ever said "released".

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/pion/stun/v3"
)

// quotaTURN is a TURN server that refuses every authenticated Allocate
// with 486 "Allocation Quota Reached" — what VK's relay says when a
// credential's allocations are used up. It answers the anonymous first
// request with the long-term-credential challenge (401 + NONCE + REALM),
// as the real relay does, so pion authenticates and the 486 arrives on
// the request that carries the USERNAME — which is how the server tells
// credentials apart.
type quotaTURN struct {
	conn     *net.UDPConn
	addr     string
	mu       sync.Mutex
	users    map[string]int
	refusals atomic.Int32
}

func newQuotaTURN(t *testing.T) *quotaTURN {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	q := &quotaTURN{conn: uc, addr: uc.LocalAddr().String(), users: map[string]int{}}
	t.Cleanup(func() { uc.Close() })
	go q.serve()
	return q
}

func (q *quotaTURN) serve() {
	buf := make([]byte, 2048)
	allocate := stun.NewType(stun.MethodAllocate, stun.ClassRequest)
	refused := stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse)
	for {
		n, from, err := q.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		m := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if m.Decode() != nil || m.Type != allocate {
			continue
		}
		var resp *stun.Message
		var u stun.Username
		if u.GetFrom(m) != nil {
			resp, err = stun.Build(stun.NewTransactionIDSetter(m.TransactionID), refused,
				stun.ErrorCodeAttribute{Code: stun.CodeUnauthorized, Reason: []byte("Unauthorized")},
				stun.NewNonce("quota-test"), stun.NewRealm("okcdn.ru"), stun.Fingerprint)
		} else {
			q.mu.Lock()
			q.users[u.String()]++
			q.mu.Unlock()
			q.refusals.Add(1)
			resp, err = stun.Build(stun.NewTransactionIDSetter(m.TransactionID), refused,
				stun.ErrorCodeAttribute{Code: 486, Reason: []byte("Allocation Quota Reached")}, stun.Fingerprint)
		}
		if err != nil {
			continue
		}
		_, _ = q.conn.WriteToUDP(resp.Raw, from)
	}
}

// distinctUsers is how many different credentials the relay has refused.
func (q *quotaTURN) distinctUsers() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.users)
}

// The adapter turns the relay's refusal into the pool's own bookkeeping,
// exactly as Proxy's SRTP session does: a 486 marks the slot saturated, so
// the same worker's next Creds is another credential; a 401/403 empties
// the slot (the credential is dead); anything else is the worker's to
// retry and changes nothing in the pool. Sabotages seen red: the quota
// branch dropped from refused (saturated stays 0, the same credential
// comes back); IsQuotaError matching "error 487:" (same).
func TestCsqttPoolAdapterReportsARefusalAsTheProxyDoes(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := csqttNewPool(ctx, proxy.CredPoolConfig{VKLink: "https://vk.ru/call/join/abc", NumConns: 30, Cooldown: 150 * time.Second})
	defer pool.Close()
	a := &csqttPoolAdapter{pool: pool, fatal: func(err error) { t.Errorf("fatal: %v", err) }}

	first, err := a.creds(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	first.Failed(errors.New("turn allocate: Allocate error response (error 486: Allocation Quota Reached)"))
	first.Release()
	if s := pool.Stats(); s.Saturated != 1 {
		t.Fatalf("saturated %d after a 486, want 1 — the pool never heard of the refusal", s.Saturated)
	}
	second, err := a.creds(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Username == first.Username {
		t.Fatalf("the exhausted credential %q came back to the same worker", first.Username)
	}

	before := pool.Stats().WithCreds
	second.Failed(errors.New("turn allocate: Allocate error response (error 401: Unauthorized)"))
	second.Release()
	if after := pool.Stats().WithCreds; after != before-1 {
		t.Fatalf("with-creds %d → %d after a 401, want the slot emptied", before, after)
	}

	third, err := a.creds(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	s0 := pool.Stats()
	third.Failed(errors.New("turn allocate: all retransmissions failed for 8f2c"))
	third.Release()
	if s1 := pool.Stats(); s1.Saturated != s0.Saturated || s1.WithCreds != s0.WithCreds {
		t.Fatalf("a timeout changed the pool (%+v → %+v) — only a refusal is the pool's business", s0, s1)
	}
}

// The user's measurement, end to end: a REAL csqtt.Client over the real
// adapter and a real pool, against a local TURN that refuses every
// credential with 486. The worker's second attempt must reach the relay
// under a DIFFERENT credential — a fresh mint into another slot — and the
// pool must show the refused slot as saturated. On the code the review
// found: one username at the relay for ever, one mint, zero saturated.
// Sabotage seen red: the Failed call dropped from the worker's session().
func TestCsqttQuotaRefusalMovesTheWorkerToAnotherCredential(t *testing.T) {
	relay := newQuotaTURN(t)
	var mints atomic.Int32
	fp := installFakePool(t, func(_ bool, slot int) (string, *proxy.TURNCreds, error) {
		n := mints.Add(1)
		return relay.addr, &proxy.TURNCreds{Username: freshUsername(fmt.Sprintf("mint-%d-slot-%d", n, slot)), Password: "p", Address: relay.addr, Addresses: []string{relay.addr}}, nil
	})
	csqttSeededSettle = 0
	// The real dial (no fake client installed): one worker, UDP to the relay.
	h := csqttStartImpl(`{"peer_addr":"127.0.0.1:46000","csqtt_password":"pw","csqtt_device_id":"dev","vk_link":"https://vk.ru/call/join/abc","num_conns":1,"use_udp":true}`)
	if h < 0 {
		t.Fatalf("csqttStart: %d", h)
	}
	t.Cleanup(func() { csqttTurnOffImpl(h) })

	deadline := time.Now().Add(8 * time.Second)
	for relay.distinctUsers() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	fp.mu.Lock()
	pool := fp.pool
	fp.mu.Unlock()
	stats := pool.Stats()
	t.Logf("486 refusals=%d distinct credentials at the relay=%d VK mints=%d saturated slots=%d",
		relay.refusals.Load(), relay.distinctUsers(), mints.Load(), stats.Saturated)
	if relay.distinctUsers() < 2 {
		t.Fatalf("the relay refused %d allocation(s) and saw only %d credential — the worker keeps retrying the exhausted one (mints %d, saturated %d)",
			relay.refusals.Load(), relay.distinctUsers(), mints.Load(), stats.Saturated)
	}
	if stats.Saturated < 1 {
		t.Fatalf("saturated slots %d — the pool was not told about the 486", stats.Saturated)
	}
	if mints.Load() < 2 {
		t.Fatalf("VK mints %d — the second credential did not come from a fresh mint", mints.Load())
	}
}
