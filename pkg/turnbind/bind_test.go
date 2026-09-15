package turnbind

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// A proxy that was never started: NewProxy alone starts no goroutine, writes
// no file and touches no socket (CredCachePath empty), so Stop is the cancel
// and an empty wait, and Pause is a real session cancel. Start is what
// reaches the network (it resolves the peer and launches the conns), which
// is why every test here parks its receiver on a proxy that never started.
func testProxy(t *testing.T) *proxy.Proxy {
	t.Helper()
	p := proxy.NewProxy(proxy.Config{VKLink: "https://vk.ru/call/join/abc123", PeerAddr: "127.0.0.1:1"})
	t.Cleanup(func() { p.StopWithTimeout(time.Second) })
	return p
}

type recvResult struct {
	n   int
	err error
}

// receiveFn opens the bind (its own part only — no proxy start) and returns
// the ReceiveFunc of THAT open, the closure bound to that open's done channel,
// exactly what wireguard-go gets from Open.
func receiveFn(t *testing.T, b *TURNBind) conn.ReceiveFunc {
	t.Helper()
	fns, _, err := b.open(0)
	if err != nil || len(fns) != 1 {
		t.Fatalf("open: %v (%d fns)", err, len(fns))
	}
	return fns[0]
}

// park calls fn on a goroutine and returns the channel its result lands on;
// the caller decides whether it is allowed to have returned.
func park(fn conn.ReceiveFunc) <-chan recvResult {
	done := make(chan recvResult, 1)
	go func() {
		n, err := fn([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- recvResult{n, err}
	}()
	return done
}

func mustStayParked(t *testing.T, done <-chan recvResult, after string) {
	t.Helper()
	select {
	case r := <-done:
		t.Fatalf("receive returned (%d, %v) %s — it must stay parked", r.n, r.err, after)
	case <-time.After(150 * time.Millisecond):
	}
}

func mustReturnClosed(t *testing.T, done <-chan recvResult, after string) {
	t.Helper()
	select {
	case r := <-done:
		if r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("receive %s = (%d, %v), want (0, net.ErrClosed): wireguard-go sleeps 333 ms on any other error", after, r.n, r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("receive did not return within 2 s %s", after)
	}
}

// A stopped proxy must read as a CLOSED bind — net.ErrClosed, the one error
// wireguard-go's receive routine exits on at once. Anything else (the
// proxy's context.Canceled passed through, as before) is answered by that
// routine with a third-of-a-second sleep before it asks again, and the
// bind's own Close — the only thing that used to produce net.ErrClosed — is
// set by device.Close, which wgTurnOff runs AFTER the proxy stop; that sleep
// was the ~330 ms of device.Close on every native stop up to build 367.
//
// Sabotage seen red: the context.Canceled clause dropped from receive — the
// call returns context.Canceled and the check after Stop fails on the error.
func TestStoppedProxyReadsAsClosedBind(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)
	fn := receiveFn(t, b)

	done := park(fn)
	mustStayParked(t, done, "on a live proxy with no packet")

	// The proxy's stop — and nothing else: the bind itself is never closed
	// here — releases the receiver, and releases it as a closed bind.
	p.Stop()
	mustReturnClosed(t, done, "after proxy.Stop")
	if b.isClosed() {
		t.Fatal("the bind reports closed although Close was never called — the mapping must come from the proxy's stop")
	}

	// And it stays that way: every later call is an immediate net.ErrClosed,
	// which is what the receive routine's retry would see.
	started := time.Now()
	n, err := fn([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second receive = (%d, %v), want (0, net.ErrClosed)", n, err)
	}
	if took := time.Since(started); took > 100*time.Millisecond {
		t.Fatalf("second receive took %s — a stopped proxy must answer at once", took)
	}
}

// Close ALONE releases a parked receiver, as a closed bind — the conn.Bind
// contract ("every ReceiveFunc returns net.ErrClosed after Close") holds
// with the proxy still running. Until build 386 Close only marked the bind
// and the receiver waited for the proxy's stop, so the contract held only
// under wgTurnOff's proxy-first order: the device's Down (darwin's
// EventDown), a UAPI listen_port through BindUpdate, or a bind closed beside
// a live proxy (the bridge's two-attaches race) parked net.stopping.Wait
// until the proxy stopped. Each open has its own done channel: a second
// Close is a no-op (closeBindLocked runs Close from BindClose and again at
// the top of BindUpdate), and a re-open's receiver parks on a fresh channel
// that the earlier Close did not touch.
//
// Sabotage seen red: the `case <-done` dropped from ReceivePacketUntil (the
// receiver stays parked after Close); the closure passing nil for done
// (same); Close not closing the channel (same); Close closing without the
// `closed` guard (the second Close panics on a closed channel).
func TestCloseAloneReleasesTheReceiver(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)
	fn := receiveFn(t, b)

	done := park(fn)
	mustStayParked(t, done, "on a live proxy with no packet")
	started := time.Now()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !b.isClosed() {
		t.Fatal("Close did not mark the bind")
	}
	mustReturnClosed(t, done, "after Close alone (the proxy still runs)")
	if took := time.Since(started); took > 100*time.Millisecond {
		t.Fatalf("the receiver took %s to wake on Close — the third-of-a-second sleep is back", took)
	}
	// The receiver of this open stays closed on every later call.
	if n, err := fn([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive after Close = (%d, %v), want (0, net.ErrClosed)", n, err)
	}
	// Idempotent: closeBindLocked closes an already-closed bind at the top of
	// BindUpdate.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// A re-open (BindUpdate's second half) parks on its own channel: the
	// earlier Close does not release it, this open's Close does.
	fn2 := receiveFn(t, b)
	if b.isClosed() {
		t.Fatal("open did not reset the closed mark")
	}
	done2 := park(fn2)
	mustStayParked(t, done2, "on the re-opened bind (a fresh done channel)")
	if err := b.Close(); err != nil {
		t.Fatalf("Close of the re-open: %v", err)
	}
	mustReturnClosed(t, done2, "after the re-open's Close")

	// And the proxy was never part of it.
	if p.Stopped() {
		t.Fatal("the proxy was stopped — the wake must come from the bind's Close alone")
	}
}

// A session cancel is NOT a stop. Pause cancels sessCtx — a child whose
// Err() is the same context.Canceled value the mapping keys on — but
// ReceivePacket selects on the ROOT context only, so a paused proxy keeps
// the receiver parked and the device keeps its one receive routine. This
// pins the invariant the mapping stands on; if ReceivePacket ever surfaced
// a session error, this would go red and receive would need a narrower key.
//
// Sabotage seen red: Pause made to cancel the root context (p.cancel()) —
// the receiver comes back with net.ErrClosed right after Pause.
func TestPauseDoesNotReadAsAClosedBind(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)

	done := park(receiveFn(t, b))
	mustStayParked(t, done, "on a live proxy with no packet")
	p.Pause()
	mustStayParked(t, done, "after Pause (a session cancel, not a stop)")

	p.Stop()
	mustReturnClosed(t, done, "after Pause and then proxy.Stop")
}

// openWithoutStart is the real bind with Open not calling proxy.Start: Start
// resolves the peer and launches the credential and connection goroutines
// (the network), and returns an error unless conn 0 comes up — a device can
// only be brought Up over a started proxy in production. Everything else is
// the bind's own open (🚨 including its `closed` reset: BindUpdate closes the
// bind before opening it, and a stub that skipped the reset let the isClosed
// clause answer for the stopped proxy — the test was green under sabotage
// until the stub shared open with production) and the real receive.
type openWithoutStart struct{ *TURNBind }

func (o openWithoutStart) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return o.open(port)
}

// THE SYMPTOM, on a real wireguard-go Device: after the proxy stops,
// device.Close must not wait. Before the fix the receive routine, parked in
// ReceivePacket, got context.Canceled, slept time.Second/3 (device/receive.go,
// the death-spiral guard) and only then saw the bind closed; device.Close →
// downLocked → BindClose → closeBindLocked waited that sleep out in
// net.stopping.Wait — "wgTurnOff: device.Close took 326–338 ms" on every
// native stop from 355 to 367. The order below is wgTurnOff's: proxy first,
// device second. The bridge's own attach tests substitute conn.NewDefaultBind
// and so could never see this; this test runs the real bind.
//
// Sabotage seen red: the context.Canceled clause dropped from receive —
// device.Close takes ~335 ms here, exactly the phone's figure. 🚨 Since the
// bind's Close wakes the receiver too (build 386), that sabotage is red only
// if the routine has ALREADY taken the raw context error and entered its
// sleep when Close runs: a Close that lands first puts a second ready case
// (done) into the receiver's select and the wake is a coin toss. The pause
// after the stop is what makes the check deterministic — and it is the
// phone's own shape, proxy.Stop returning ~10 ms before device.Close.
func TestDeviceCloseDoesNotWaitOnAStoppedProxy(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), openWithoutStart{b}, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.Up(); err != nil {
		t.Fatalf("device.Up: %v", err)
	}
	// Let the receive routine reach ReceivePacket and park there.
	time.Sleep(100 * time.Millisecond)

	p.StopWithTimeout(2 * time.Second)
	// The receiver has seen the stop before the device closes the bind.
	time.Sleep(50 * time.Millisecond)
	started := time.Now()
	dev.Close()
	took := time.Since(started)
	if took > 100*time.Millisecond {
		t.Fatalf("device.Close took %s after the proxy stop — the receive routine slept wireguard-go's third of a second, i.e. the bind reported the stopped proxy as something other than net.ErrClosed", took)
	}
	t.Logf("device.Close after the proxy stop: %s", took.Round(time.Microsecond))
}

// THE OTHER SYMPTOM, on a real wireguard-go Device: the bind closed with the
// proxy STILL RUNNING. device.Down → downLocked → BindClose → closeBindLocked
// → bind.Close, then net.stopping.Wait for the receive routine — which, until
// build 386, sat in ReceivePacket until the proxy stopped: Down parked under
// device.state.Lock for as long as the proxy lived (darwin's EventDown, a
// UAPI listen_port through BindUpdate, the bridge's two-attaches race). Now
// Close wakes the routine, Down returns at once, a second Up opens a fresh
// channel and device.Close on the live proxy returns at once too. The proxy
// is stopped only by the cleanup, after every assertion.
//
// Sabotage seen red: the `case <-done` dropped from ReceivePacketUntil —
// Down does not return within the 2-second guard.
func TestDeviceDownReturnsWithoutAProxyStop(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), openWithoutStart{b}, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.Up(); err != nil {
		t.Fatalf("device.Up: %v", err)
	}
	// Let the receive routine reach ReceivePacketUntil and park there.
	time.Sleep(100 * time.Millisecond)

	// Down on a goroutine: under the sabotage it would park until the proxy
	// stops, and the proxy stops only in the cleanup — so the guard stops it
	// here rather than hanging the test.
	returned := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		_ = dev.Down()
		returned <- time.Since(started)
	}()
	select {
	case took := <-returned:
		if took > 100*time.Millisecond {
			t.Fatalf("device.Down took %s on a live proxy — the receive routine did not wake on the bind's Close", took)
		}
		t.Logf("device.Down on a live proxy: %s", took.Round(time.Microsecond))
	case <-time.After(2 * time.Second):
		p.StopWithTimeout(time.Second) // unpark Down so the deferred device state can be torn down
		t.Fatal("device.Down did not return within 2 s on a live proxy — Close does not wake the parked receiver")
	}
	if p.Stopped() {
		t.Fatal("the proxy was stopped by the device's Down — it must not be")
	}

	// Up again: BindUpdate closes the (closed) bind and opens it anew — a
	// fresh done channel, a new receive routine that parks — and device.Close
	// on the STILL live proxy must return at once as well.
	if err := dev.Up(); err != nil {
		t.Fatalf("second device.Up: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	closed := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		dev.Close()
		closed <- time.Since(started)
	}()
	select {
	case took := <-closed:
		if took > 100*time.Millisecond {
			t.Fatalf("device.Close took %s on a live proxy after a re-Up — the re-open's receiver did not wake", took)
		}
		t.Logf("device.Close on a live proxy after a re-Up: %s", took.Round(time.Microsecond))
	case <-time.After(2 * time.Second):
		p.StopWithTimeout(time.Second)
		t.Fatal("device.Close did not return within 2 s on a live proxy after a re-Up")
	}
	if p.Stopped() {
		t.Fatal("the proxy was stopped by the device's Close — it must not be")
	}
}
