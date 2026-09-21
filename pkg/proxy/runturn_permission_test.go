package proxy

// A relay that takes the allocation and then answers NOTHING. The forwarder
// toward the relay sits in CreatePermission's transaction — pion asks for
// the permission on the first packet to the peer and waits for the answer —
// and until build 394 a cancel freed it only when pion's next retransmit
// WRITE failed the deadline the cancel had set: the rtx ladder 200 → 400 →
// 800 → 1600 ms, 1.1–2.1 s after the cancel (Sep 6 §63's "narrower window").
// The SRTP path had it wider: setupSRTPSession's explicit CreatePermission
// had no cancel wiring at all, so a cancel there waited out pion's whole
// ladder, 7.8 s. pion's Client.Close closes the transaction map and nothing
// else (the socket stays ours, the deallocate still goes out), and a closed
// transaction returns errTransactionClosed at once — so the cancel closes
// the client. The tap below goes silent exactly when the permission is
// asked. Sabotage seen red: client.Close dropped from runTURN's cancel
// AfterFunc (the return 1.1 s after the cancel); setupSRTPSession's
// AfterFunc dropped (the 3-s guard).
//
// The user's review of 394: a cancel that lands BEFORE the permission is
// asked. AfterFunc on a ctx already done runs the hook in its own goroutine
// at once, racing CreatePermission's registration, and a Close alone
// releases only what is already registered — the transaction registered
// after it waited out pion's whole ladder (3/3 on their stand). So the hook
// first puts a write deadline in the PAST on the control socket (the first
// write of any later transaction fails at once) and only then closes the
// client: whichever of the two a transaction meets, it ends. The race
// itself is probabilistic, so the ORDER is pinned by a source scan; the
// held-answer stand below shows the behaviour.

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

// permissionMutingTap forwards a TCP connection to the TURN server both ways
// until it sees a CreatePermission request go out (STUN type 0x0008 at the
// head of a client → server chunk); from then on everything the server
// answers is dropped — a relay that stays silent from the permission on.
type permissionMutingTap struct {
	ln        net.Listener
	to        string
	mute      bool // a CreatePermission request silences the relay
	muted     atomic.Bool
	requests  atomic.Int32  // CreatePermission requests seen
	refreshes atomic.Int32  // Refresh requests seen — in these short runs only the deallocate (lifetime 0)
	requested chan struct{} // closed on the first client → server bytes (the Allocate request)
	gate      chan struct{} // with hold: the server's answers are forwarded only once it is closed
	reqOnce   sync.Once
	gateOnce  sync.Once
	mu        sync.Mutex
	conns     []net.Conn
}

// hold: the relay's answers are held back until release() — an Allocate
// whose answer is late, so a cancel can land before anything is armed.
// mute: the relay goes silent at the CreatePermission request; without it
// the relay is healthy throughout and the tap only counts.
func newPermissionMutingTap(t *testing.T, to string, hold, mute bool) *permissionMutingTap {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tap := &permissionMutingTap{ln: ln, to: to, mute: mute, requested: make(chan struct{}), gate: make(chan struct{})}
	if !hold {
		tap.release()
	}
	go tap.serve()
	t.Cleanup(tap.close)
	return tap
}

func (tap *permissionMutingTap) addr() string { return tap.ln.Addr().String() }

func (tap *permissionMutingTap) release() { tap.gateOnce.Do(func() { close(tap.gate) }) }

func (tap *permissionMutingTap) serve() {
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
		go func() { // client → server, always; a CreatePermission request mutes the relay
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if n >= 20 && buf[0] == 0x00 {
					switch buf[1] {
					case 0x08: // CreatePermission request
						tap.requests.Add(1)
						if tap.mute {
							tap.muted.Store(true)
						}
					case 0x04: // Refresh request
						tap.refreshes.Add(1)
					}
				}
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
		go func() { // server → client: held until released, then forwarded until muted
			<-tap.gate
			buf := make([]byte, 64<<10)
			for {
				n, err := up.Read(buf)
				if n > 0 && !tap.muted.Load() {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func (tap *permissionMutingTap) close() {
	tap.release() // never leave a copier parked on the gate
	_ = tap.ln.Close()
	tap.mu.Lock()
	defer tap.mu.Unlock()
	for _, c := range tap.conns {
		_ = c.Close()
	}
}

// runTURN: the first packet's permission is asked, the relay says nothing,
// the cancel lands while pion's ladder runs — runTURN returns at once.
func TestRunTURNReturnsWhenTheRelayGoesSilentAtCreatePermission(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), false, true)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0, nil)
	}()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })

	_, _ = conn1.WriteTo(make([]byte, 100), peer) // the first packet: its permission is asked
	waitUntil(t, "the CreatePermission request to reach the relay", 5*time.Second, func() bool { return tap.requests.Load() >= 1 })
	time.Sleep(300 * time.Millisecond) // past pion's first retransmit: the ladder is running
	if sent := p.connTxBytes[0].Load(); sent != 0 {
		t.Fatalf("fixture: %d bytes went through — the forwarder is not waiting in CreatePermission", sent)
	}
	select {
	case err := <-done:
		t.Fatalf("runTURN returned before the cancel: %v", err)
	default:
	}

	t0 := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runTURN did not return after the cancel: the forwarder waits out pion's retransmit ladder in CreatePermission's transaction")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget {
		t.Fatalf("runTURN took %s after the cancel, want under the %s budget — the transaction wait is not bounded by the cancel", took, relayCloseWriteBudget)
	}
}

// setupSRTPSession: its explicit CreatePermission right after the
// allocation, the relay silent from there — the cancel ends it at once.
func TestSetupSRTPSessionReturnsWhenTheRelayGoesSilentAtCreatePermission(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), false, true)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.setupSRTPSession(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, 0, 0, nil)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	waitUntil(t, "the CreatePermission request to reach the relay", 5*time.Second, func() bool { return tap.requests.Load() >= 1 })
	time.Sleep(300 * time.Millisecond) // past pion's first retransmit: the ladder is running
	select {
	case err := <-done:
		t.Fatalf("setupSRTPSession returned before the cancel: %v", err)
	default:
	}

	t0 := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setupSRTPSession succeeded against a relay that never answered the permission")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setupSRTPSession did not return after the cancel: CreatePermission waits out pion's retransmit ladder")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget {
		t.Fatalf("setupSRTPSession took %s after the cancel, want under the %s budget", took, relayCloseWriteBudget)
	}
}

// The user's review of 394 on the real stack: the Allocate answer held, the
// cancel lands with nothing armed yet, the answer released — the allocation
// completes, the hook fires the moment it is armed (AfterFunc on a done ctx)
// and races CreatePermission's registration, and the relay is silent from
// the permission on. setupSRTPSession must return within the budget
// whichever of the two runs first. The race is real and probabilistic: with
// a Close alone (394) the user's stand saw the ladder 3/3; the ORDER that
// closes every interleaving is pinned by the scan below.
func TestSetupSRTPSessionReturnsWhenTheCancelPrecedesThePermission(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), true, true)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.setupSRTPSession(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, 0, 0, nil)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	<-tap.requested // the Allocate request is on the wire, its answer held
	cancel()        // the early cancel: nothing is armed yet
	t0 := time.Now()
	tap.release() // the allocation completes; the hook and CreatePermission race; the relay is silent from the permission on
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setupSRTPSession succeeded on a cancelled context")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setupSRTPSession did not return: a transaction registered after the hook's Close waited out pion's ladder")
	}
	if took := time.Since(t0); took > relayCloseWriteBudget {
		t.Fatalf("setupSRTPSession took %s after the answer was released, want under the %s budget", took, relayCloseWriteBudget)
	}
}

// The order inside both cancel hooks, and the teardown's re-armed budget,
// pinned by spelling: the race above cannot be made deterministic, and a
// hook that closes first and sets the deadline second leaves a transaction
// registered in between waiting for its next retransmit.
func TestTheCancelHooksSetThePastDeadlineBeforeTheClose(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	hook := func(start string) string {
		i := strings.Index(code, start)
		if i < 0 {
			t.Fatalf("proxy.go lacks %q", start)
		}
		end := strings.Index(code[i:], "\n\t})")
		if end < 0 {
			t.Fatalf("no end for the hook at %q", start)
		}
		return code[i : i+end]
	}
	for _, h := range []struct{ start, deadline, closeCall string }{
		{"context.AfterFunc(turnCtx, func() {", "turnConn.SetWriteDeadline(time.Now())", "client.Close()"},
		{"disarm := context.AfterFunc(ctx, func() {", "ctlConn.SetWriteDeadline(time.Now())", "tc.Close()"},
	} {
		body := hook(h.start)
		d, c := strings.Index(body, h.deadline), strings.Index(body, h.closeCall)
		if d < 0 {
			t.Errorf("the hook at %q sets no PAST write deadline (%q) — a transaction registered after its Close waits out pion's ladder", h.start, h.deadline)
		}
		if c < 0 {
			t.Errorf("the hook at %q does not close the client (%q)", h.start, h.closeCall)
		}
		if d >= 0 && c >= 0 && d > c {
			t.Errorf("the hook at %q closes the client BEFORE the past deadline — a transaction registered between the two waits for its next retransmit", h.start)
		}
		if strings.Contains(body, h.deadline+".Add(") {
			t.Errorf("the hook at %q sets a FUTURE write deadline — a transaction registered after its Close writes once and waits", h.start)
		}
	}
	abort := hook("abortSetup := func() {")
	b, r := strings.Index(abort, "SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))"), strings.Index(abort, "returnAllocation(relayConn, release, gave)") // the ONE body that gives the allocation back — seatcool.go
	if b < 0 || r < 0 || b > r {
		t.Error("setupSRTPSession's abortSetup does not re-arm a live write budget before the deallocate — after a cancel the hook's past deadline would fail it")
	}
	if n := strings.Count(code[strings.Index(code, "abortSetup := func() {"):], "abortSetup()"); n != 2 {
		t.Errorf("abortSetup() is called %d times after its definition, want 2 (the permission's and the handshake's error paths)", n)
	}
}

// The user's review of 395: the cancel hook may still be RUNNING when the
// teardown re-arms its budget — setupSRTPSession's abortSetup after a
// handshake aborted by the same cancel, runTURN's deferred budget after
// forwarders that exited on the hook's first deadline — and its past write
// deadline landing after the budget fails the deallocate on a HEALTHY relay:
// the allocation stays on the quota for its lifetime. Both teardowns now
// stop the hook or wait for it before the budget; the deallocate (a Refresh
// request, lifetime 0) must reach the relay after every cancel. The race is
// probabilistic, so the order is pinned by the scan below as well.
func TestRunTURNDeallocatesAfterACancelOnAHealthyRelay(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), false, false) // healthy: nothing held, nothing muted
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- p.runTURN(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, conn2, 0, 0, nil)
	}()
	waitUntil(t, "the allocation", 5*time.Second, func() bool { return p.turnRTTns.Load() != 0 })
	_, _ = conn1.WriteTo(make([]byte, 100), peer)
	waitUntil(t, "the first packet to go through", 5*time.Second, func() bool { return p.connTxBytes[0].Load() >= 100 })
	if tap.refreshes.Load() != 0 {
		t.Fatalf("fixture: %d Refresh requests before the cancel — the deallocate would not be distinguishable", tap.refreshes.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runTURN did not return after the cancel")
	}
	waitUntil(t, "the deallocate to reach the relay", 2*time.Second, func() bool { return tap.refreshes.Load() >= 1 })
}

func TestSetupSRTPSessionDeallocatesAfterACancelOnAHealthyRelay(t *testing.T) {
	tap := newPermissionMutingTap(t, loopbackTURN(t), false, false)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	p := &Proxy{peer: peer, connTxBytes: make([]atomic.Int64, 1), lastTxAt: make([]atomic.Int64, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.setupSRTPSession(ctx, tap.addr(), &TURNCreds{Username: "u", Password: "pw"}, 0, 0, nil)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	waitUntil(t, "the permission to be asked", 5*time.Second, func() bool { return tap.requests.Load() >= 1 })
	time.Sleep(50 * time.Millisecond) // the permission answered, the handshake toward the silent peer pending
	if tap.refreshes.Load() != 0 {
		t.Fatalf("fixture: %d Refresh requests before the cancel", tap.refreshes.Load())
	}
	cancel() // aborts the handshake through hsCtx AND fires the hook — two goroutines, one deadline
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setupSRTPSession succeeded on a cancelled context")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setupSRTPSession did not return after the cancel")
	}
	waitUntil(t, "the deallocate to reach the relay", 2*time.Second, func() bool { return tap.refreshes.Load() >= 1 })
}

// The order, pinned by spelling: both teardowns stop the hook or wait for
// it before they touch a deadline.
func TestTheTeardownsQuiesceTheCancelHookBeforeReArmingTheBudget(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	// runTURN: the hook closes hookDone at its end; after wg.Wait the hook is
	// stopped or waited for before the deadlines are reset and the deferred
	// budget runs.
	if !strings.Contains(code, "stopHook := context.AfterFunc(turnCtx, func() {\n\t\tdefer close(hookDone)") {
		t.Error("runTURN's cancel hook does not signal its end (stopHook / defer close(hookDone))")
	}
	i := strings.Index(code, "context.AfterFunc(turnCtx, func() {")
	tail := code[i:]
	w := strings.Index(tail, "\twg.Wait()\n")
	if w < 0 {
		t.Fatal("runTURN: no wg.Wait after the hook")
	}
	end := strings.Index(tail[w:], "return nil")
	if end < 0 {
		t.Fatal("runTURN: no return after wg.Wait")
	}
	after := tail[w : w+end]
	wait := strings.Index(after, "if !stopHook() {\n\t\t<-hookDone")
	reset := strings.Index(after, "relayConn.SetDeadline(time.Time{})")
	if wait < 0 {
		t.Error("runTURN does not wait for its cancel hook after wg.Wait — the hook's past deadline can land after the deferred budget and fail the deallocate")
	}
	if wait >= 0 && reset >= 0 && wait > reset {
		t.Error("runTURN resets the deadlines before waiting for the hook")
	}
	if c := strings.Index(after, "turnCancel()"); c < 0 || (wait >= 0 && c > wait) {
		t.Error("runTURN must cancel turnCtx before stopping/waiting for the hook, so a hook that has not started yet is stopped rather than left to run later")
	}
	// setupSRTPSession: the hook closes hookDone; quiesce stops or waits, once;
	// abortSetup quiesces before the budget; the return quiesces too.
	if !strings.Contains(code, "disarm := context.AfterFunc(ctx, func() {\n\t\tdefer close(hookDone)") {
		t.Error("setupSRTPSession's cancel hook does not signal its end (defer close(hookDone))")
	}
	q := strings.Index(code, "quiesce := func() {")
	if q < 0 {
		t.Fatal("setupSRTPSession has no quiesce")
	}
	qbody := code[q : q+strings.Index(code[q:], "\n\t}\n")]
	for _, need := range []string{"quiesceOnce.Do(", "if !disarm() {", "<-hookDone"} {
		if !strings.Contains(qbody, need) {
			t.Errorf("setupSRTPSession's quiesce lacks %q", need)
		}
	}
	if !strings.Contains(code, "\tdefer quiesce()\n") || strings.Contains(code, "\tdefer disarm()\n") {
		t.Error("setupSRTPSession must defer quiesce(), not disarm() — a stop alone does not wait for a hook that has started")
	}
	a := strings.Index(code, "abortSetup := func() {")
	abody := code[a : a+strings.Index(code[a:], "\n\t}\n")]
	qa, ba := strings.Index(abody, "quiesce()"), strings.Index(abody, "SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))")
	if qa < 0 || ba < 0 || qa > ba {
		t.Error("setupSRTPSession's abortSetup does not quiesce the hook BEFORE re-arming the budget — the hook's past deadline can land after it and fail the deallocate")
	}
}
