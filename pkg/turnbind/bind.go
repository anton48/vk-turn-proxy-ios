package turnbind

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"golang.zx2c4.com/wireguard/conn"
)

// TURNBind implements conn.Bind by routing WireGuard packets through
// a DTLS/TURN proxy instead of direct UDP sockets.
type TURNBind struct {
	proxy  *proxy.Proxy
	mu     sync.Mutex
	closed bool
}

// NewTURNBind creates a new TURNBind backed by the given proxy.
func NewTURNBind(p *proxy.Proxy) *TURNBind {
	return &TURNBind{proxy: p}
}

// Open starts the proxy and returns a receive function.
func (b *TURNBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Start the proxy (connects to VK TURN, establishes DTLS, etc.)
	if err := b.proxy.Start(); err != nil {
		log.Printf("TURNBind.Open: proxy.Start failed: %v", err)
		return nil, 0, err
	}
	return b.open(port)
}

// open is Open minus the proxy start: the bind's own part. The `closed` reset
// matters — wireguard-go's BindUpdate CLOSES the bind before it opens it
// (device.go: closeBindLocked, then bind.Open), so a stale flag would make
// the first receive error read as a closed bind whatever caused it. The
// device-level test opens the bind through this without a proxy start (a
// started proxy reaches the network).
func (b *TURNBind) open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.closed = false
	b.mu.Unlock()
	return []conn.ReceiveFunc{b.receive}, port, nil
}

// receive is this bind's one conn.ReceiveFunc: the next packet from the
// proxy, or the error wireguard-go's RoutineReceiveIncoming acts on.
//
// 🚨 A STOPPED PROXY IS A CLOSED BIND. ReceivePacket fails only when the
// proxy's context is done, and that context is cancelled by Stop /
// StopWithTimeout alone (Pause and Resume live on sessCtx) — nothing will
// ever arrive through it again. Handed back as is, context.Canceled is
// neither net.ErrClosed nor a non-temporary net.Error, so the receive
// routine (wireguard-go device/receive.go, its death-spiral guard) logs it,
// SLEEPS A THIRD OF A SECOND and asks again; `closed` is set only by the
// device's own Close, which wgTurnOff runs AFTER the proxy stop (the order
// build 56 proved necessary) — hence "device.Close took ~330 ms" on every
// native stop up to build 367, on DTLS, WRAP, WRAP-A and WRAP-S alike.
// net.ErrClosed is the contract's word for "this bind is done" (conn.Bind:
// every ReceiveFunc returns it after Close) and the routine exits on it at
// once. The device-first order is NOT the alternative: Close does not wake
// a receiver parked in ReceivePacket.
//
// ⚠️ The mapping keys on context.Canceled because that is the ONE error
// ReceivePacket has: its root context is a plain WithCancel, never a
// deadline, and a session cancel (Pause, Resume, ForceReconnect — sessCtx)
// never reaches it. Should ReceivePacket ever grow a per-read deadline or a
// per-session error, that error must NOT be mapped here: this bind has one
// receive routine, started once by the device's BindUpdate, and it exits for
// good on net.ErrClosed while the device stays Up. The tests pin both sides
// (stop ⇒ closed; Pause ⇒ still parked).
func (b *TURNBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	n, err := b.proxy.ReceivePacket(packets[0])
	if err != nil {
		if b.isClosed() || errors.Is(err, context.Canceled) {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	sizes[0] = n
	eps[0] = &TURNEndpoint{}
	return 1, nil
}

func (b *TURNBind) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Close stops receiving packets. It marks the bind only: a receiver parked
// in ReceivePacket is released by the proxy's stop, not by this — which is
// why wgTurnOff stops the proxy first.
func (b *TURNBind) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

// SetMark is a no-op on iOS.
func (b *TURNBind) SetMark(mark uint32) error {
	return nil
}

// Send sends WireGuard packets through the DTLS/TURN proxy.
func (b *TURNBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if err := b.proxy.SendPacket(buf); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint creates a TURNEndpoint from a string.
func (b *TURNBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &TURNEndpoint{addr: s}, nil
}

// BatchSize returns 1 (no batching through TURN).
func (b *TURNBind) BatchSize() int {
	return 1
}

// TURNEndpoint is a dummy endpoint since all traffic goes through
// the single TURN relay. WireGuard needs an Endpoint to track peers
// but we only have one path.
type TURNEndpoint struct {
	addr string
}

func (e *TURNEndpoint) ClearSrc() {}

func (e *TURNEndpoint) SrcToString() string {
	return ""
}

func (e *TURNEndpoint) DstToString() string {
	if e.addr != "" {
		return e.addr
	}
	return "turn:0"
}

func (e *TURNEndpoint) DstToBytes() []byte {
	return []byte(fmt.Sprintf("%s", e.DstToString()))
}

func (e *TURNEndpoint) DstIP() netip.Addr {
	if e.addr != "" {
		if ap, err := netip.ParseAddrPort(e.addr); err == nil {
			return ap.Addr()
		}
	}
	return netip.Addr{}
}

func (e *TURNEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
