package proxy

// The mark names the CREDENTIAL, not the slot. The user's stand on build 392
// held a TURN answer, cancelled the old session, refilled the slot and let
// the answer through: 3/3 the NEW credential read allocated 1 on the OLD
// one's success, and its own 486s would then have passed as its quota with
// the breaker silent. A slot number does not identify a credential once the
// relay's answer is late — invalidate() on a Resume, invalidateEntry on
// another holder's 401/403 and a Phase-2 replacement all refill a slot under
// a lease — so the mark carries the leased credential and counts only while
// the slot still holds that identity. Sabotage seen red: the identity check
// dropped (a slot-keyed mark); a call site passing nil; the check keyed on
// the pointer instead of the username (a re-fetched copy read as a stranger).

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

func allocatedOn(cp *credPool, slot int) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.pool[slot].allocated
}

func allocatedTotal(cp *credPool) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	n := 0
	for _, e := range cp.pool {
		n += e.allocated
	}
	return n
}

// The stand's shape on the pool alone, through both production paths that
// refill a slot under a lease, and the consequence the stand named: the
// refilled credential has no success of its own, so two fresh 486s on it
// are the relay refusing and the breaker must trip.
func TestALateSuccessOfTheOldCredentialDoesNotCertifyTheNew(t *testing.T) {
	paths := []struct {
		name  string
		clear func(cp *credPool, slot int)
	}{
		{"invalidateEntry — another holder's 401/403 cleared the slot", func(cp *credPool, slot int) { cp.invalidateEntry(slot) }},
		{"invalidate — a Resume rebuilt the pool", func(cp *credPool, _ int) { cp.invalidate() }},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var mints atomic.Int32
			cp := breakerPool(t, &mints)
			_, old, slot, err := cp.get(0, false) // the old session's lease: credential A, its Allocate on the wire
			if err != nil {
				t.Fatal(err)
			}
			path.clear(cp, slot)
			_, fresh, got, err := cp.get(0, false) // the next session mints B — the same conn prefers the same slot
			if err != nil {
				t.Fatal(err)
			}
			if got != slot || fresh.Username == old.Username {
				t.Fatalf("the refill landed on slot %d as %q (A was slot %d, %q) — the stand's shape needs B in A's slot", got, fresh.Username, slot, old.Username)
			}
			cp.noteAllocated(slot, old) // the relay's late answer: it accepted A
			if a := allocatedOn(cp, slot); a != 0 {
				t.Fatalf("allocated on the refilled slot = %d after the OLD credential's late success, want 0 — a slot number is not a credential", a)
			}
			cp.markSaturated(slot) // B's own 486s: fresh, and nothing ever succeeded on B
			cp.markSaturated(slot)
			if refusals, paused := cp.quotaSnapshot(); refusals != 2 || paused <= 0 {
				t.Fatalf("after two fresh 486s on the refilled credential: (%d, paused %s), want (2, > 0) — the breaker took the new credential for an accepted one", refusals, paused)
			}
			cp.noteAllocated(slot, fresh) // B's own success is B's
			if a := allocatedOn(cp, slot); a != 1 {
				t.Fatalf("allocated = %d after the new credential's own success, want 1", a)
			}
		})
	}

	// The identity is the username, not our copy of it: cookie mode fetches
	// the same credential per slot, and the relay's acceptance of that
	// identity holds for the copy that is in the slot now.
	t.Run("the same identity fetched into the slot again IS the credential the relay accepted", func(t *testing.T) {
		const relay = "95.163.34.180:19302"
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		cp := newCredPool(ctx, 12, 2*time.Minute, "", func(_ bool, _ int) (string, *TURNCreds, error) {
			return relay, &TURNCreds{Username: "1:the-same-identity", Password: "p", Address: relay, Addresses: []string{relay}}, nil
		})
		cp.mu.Lock()
		for len(cp.pool) < cp.size {
			cp.pool = append(cp.pool, credPoolEntry{})
		}
		cp.mu.Unlock()
		_, old, slot, err := cp.get(0, false)
		if err != nil {
			t.Fatal(err)
		}
		cp.invalidateEntry(slot)
		_, again, got, err := cp.get(0, false)
		if err != nil {
			t.Fatal(err)
		}
		if got != slot || again == old || again.Username != old.Username {
			t.Fatalf("expected the same identity as a NEW copy in slot %d: got slot %d, same pointer %v, %q vs %q", slot, got, again == old, again.Username, old.Username)
		}
		cp.noteAllocated(slot, old) // the late success of the old COPY
		if a := allocatedOn(cp, slot); a != 1 {
			t.Fatalf("allocated = %d, want 1 — the relay accepted the identity, and a copy is not another identity", a)
		}
	})
}

// holdingTap forwards a TCP connection to the TURN server at once in the
// client → server direction and HOLDS everything the server answers until
// the test releases it — a relay whose answer to Allocate is late.
type holdingTap struct {
	ln        net.Listener
	to        string
	requested chan struct{} // closed once the first client bytes — the Allocate request — went through
	gate      chan struct{} // the server's answers are forwarded only after it is closed
	reqOnce   sync.Once
	gateOnce  sync.Once
	mu        sync.Mutex
	conns     []net.Conn
}

func newHoldingTap(t *testing.T, to string) *holdingTap {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tap := &holdingTap{ln: ln, to: to, requested: make(chan struct{}), gate: make(chan struct{})}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *holdingTap) addr() string { return tap.ln.Addr().String() }

func (tap *holdingTap) release() { tap.gateOnce.Do(func() { close(tap.gate) }) }

func (tap *holdingTap) serve() {
	for {
		c, err := tap.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp4", tap.to)
		if err != nil {
			_ = c.Close()
			return
		}
		tap.mu.Lock()
		tap.conns = append(tap.conns, c, up)
		tap.mu.Unlock()
		go func() { // client → server, at once
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					if _, werr := up.Write(buf[:n]); werr != nil {
						return
					}
					tap.reqOnce.Do(func() { close(tap.requested) })
				}
				if err != nil {
					return
				}
			}
		}()
		go func() { // server → client, held
			<-tap.gate
			_, _ = io.Copy(c, up)
		}()
	}
}

func (tap *holdingTap) close() {
	tap.release() // never leave a copier parked on the gate
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.conns {
		_ = c.Close()
	}
}

// The stand on the real stack, at both native allocation sites: the old
// session's Allocate is on the wire and its answer held; the pool is rebuilt
// and slot 0 refilled with B; the answer arrives — the relay accepted A — and
// the mark must land nowhere.
func TestALateAllocateAnswerMarksTheCredentialItWasIssuedTo(t *testing.T) {
	turnAddr := loopbackTURN(t)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	old := &TURNCreds{Username: "u", Password: "pw", Address: turnAddr, Addresses: []string{turnAddr}}
	arms := []struct {
		name string
		run  func(ctx context.Context, p *Proxy, relay string) error
	}{
		{"runTURN — where DTLS, direct and WRAP-A allocate", func(ctx context.Context, p *Proxy, relay string) error {
			conn1, conn2 := connutil.AsyncPacketPipe()
			defer conn1.Close()
			defer conn2.Close()
			return p.runTURN(ctx, relay, old, conn2, 0, 0)
		}},
		{"setupSRTPSession — where SRTP allocates", func(ctx context.Context, p *Proxy, relay string) error {
			c, err := p.setupSRTPSession(ctx, relay, old, 0, 0)
			if c != nil {
				_ = c.Close()
			}
			return err
		}},
	}
	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			tap := newHoldingTap(t, turnAddr)
			var mints atomic.Int32
			cp := breakerPool(t, &mints)
			cp.mu.Lock()
			cp.pool[0] = credPoolEntry{addr: tap.addr(), ts: time.Now(), active: 1, creds: old}
			cp.mu.Unlock()
			p := &Proxy{peer: peer, credPool: cp, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- arm.run(ctx, p, tap.addr()) }()
			<-tap.requested // A's Allocate is on the wire, its answer held

			// Meanwhile the slot moves on: a Resume rebuilds the pool and the
			// next session refills slot 0 with B.
			cp.invalidate()
			newer := &TURNCreds{Username: "u2", Password: "pw", Address: tap.addr(), Addresses: []string{tap.addr()}}
			cp.mu.Lock()
			cp.pool[0] = credPoolEntry{addr: tap.addr(), ts: time.Now(), active: 1, creds: newer}
			cp.mu.Unlock()

			tap.release() // the relay's answer: it accepted A
			waitUntil(t, "A's Allocate to return", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })
			select {
			case err := <-done:
				t.Fatalf("%s returned before the cancel: %v", arm.name, err)
			default:
			}
			if a := allocatedOn(cp, 0); a != 0 {
				t.Fatalf("allocated on slot 0 = %d after A's late success with B in the slot, want 0 — the slot number is not the credential", a)
			}
			if total := allocatedTotal(cp); total != 0 {
				t.Fatalf("allocated somewhere in the pool = %d, want 0 — A's late success has no slot left to land on", total)
			}
			cancel()
			<-done
		})
	}
}
