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

// park calls receive on a goroutine and returns the channel its result
// lands on; the caller decides whether it is allowed to have returned.
func park(b *TURNBind) <-chan recvResult {
	done := make(chan recvResult, 1)
	go func() {
		n, err := b.receive([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
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

	done := park(b)
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
	n, err := b.receive([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second receive = (%d, %v), want (0, net.ErrClosed)", n, err)
	}
	if took := time.Since(started); took > 100*time.Millisecond {
		t.Fatalf("second receive took %s — a stopped proxy must answer at once", took)
	}
}

// Close marks the bind and nothing more: a receiver parked in ReceivePacket
// is released by the proxy's stop alone, which is why wgTurnOff stops the
// proxy FIRST (build 56's device-first order parked device.Close here). The
// conn.Bind contract ("every ReceiveFunc returns net.ErrClosed after Close")
// therefore holds only under that order — pinned as it is; the follow-up
// that lets Close wake the receiver (a per-bind done channel) will rewrite
// this test on purpose.
//
// Seen red with the whole error mapping dropped (receive hands the raw error
// back): after Close and Stop the receive comes back with context.Canceled.
// Dropping only the context clause leaves it green — Close was called, so the
// isClosed clause answers; through the real Proxy that clause is never the
// only one that can (ReceivePacket's one error is the root context's).
func TestCloseAloneDoesNotReleaseTheReceiver(t *testing.T) {
	p := testProxy(t)
	b := NewTURNBind(p)

	done := park(b)
	mustStayParked(t, done, "on a live proxy with no packet")
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !b.isClosed() {
		t.Fatal("Close did not mark the bind")
	}
	mustStayParked(t, done, "after Close alone (the proxy still runs)")

	p.Stop()
	mustReturnClosed(t, done, "after Close and then proxy.Stop")
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

	done := park(b)
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
// device.Close takes ~335 ms here, exactly the phone's figure.
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
	started := time.Now()
	dev.Close()
	took := time.Since(started)
	if took > 100*time.Millisecond {
		t.Fatalf("device.Close took %s after the proxy stop — the receive routine slept wireguard-go's third of a second, i.e. the bind reported the stopped proxy as something other than net.ErrClosed", took)
	}
	t.Logf("device.Close after the proxy stop: %s", took.Round(time.Microsecond))
}
