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
	// done belongs to the CURRENT open: made by open, closed by Close (once,
	// under `closed`), and captured by the ReceiveFunc open returns, so the
	// receiver of an earlier open — BindUpdate closes the bind and opens it
	// again — wakes on its own channel and never on a later one.
	done chan struct{}
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
// the first receive error read as a closed bind whatever caused it. Each
// open gets its own done channel, and the ReceiveFunc it returns is bound
// to THAT channel (a closure, not a method value): Close wakes the receiver
// of this open, and a receiver of an earlier open that is still returning
// keeps its own. The device-level tests open the bind through this without
// a proxy start (a started proxy reaches the network).
func (b *TURNBind) open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	done := make(chan struct{})
	b.mu.Lock()
	b.closed = false
	b.done = done
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return b.receive(done, packets, sizes, eps)
	}
	return []conn.ReceiveFunc{recv}, port, nil
}

// receive is this bind's one conn.ReceiveFunc: the next packet from the
// proxy, or the error wireguard-go's RoutineReceiveIncoming acts on. It
// returns net.ErrClosed — the contract's word for "this bind is done"
// (conn.Bind: every ReceiveFunc returns it after Close), the one error the
// routine exits on at once — in two cases:
//
// 🚨 A STOPPED PROXY IS A CLOSED BIND. ReceivePacket's root context is
// cancelled by Stop / StopWithTimeout alone (Pause and Resume live on
// sessCtx) — nothing will ever arrive through it again. Handed back as is,
// context.Canceled is neither net.ErrClosed nor a non-temporary net.Error,
// so the receive routine (wireguard-go device/receive.go, its death-spiral
// guard) logs it, SLEEPS A THIRD OF A SECOND and asks again — "device.Close
// took ~330 ms" on every native stop up to build 367, on DTLS, WRAP, WRAP-A
// and WRAP-S alike, because wgTurnOff stops the proxy BEFORE the device
// (the order build 56 proved necessary on the TUN side).
//
// 🚨 A CLOSED BIND IS A CLOSED BIND, proxy or no proxy. Until build 386 Close
// only marked the bind, so a receiver parked here was released by the
// proxy's stop alone and the contract held only under wgTurnOff's order:
// the device's Down (darwin's EventDown), a UAPI listen_port through
// BindUpdate, or a bind closed beside a live proxy (the bridge's
// two-attaches race) would have parked wireguard-go's net.stopping.Wait
// under device.state.Lock until the proxy stopped. Close now closes this
// open's done channel and ReceivePacketUntil returns on it; the order in
// wgTurnOff stays proxy-first for the TUN-side reason, not for this one.
//
// ⚠️ The context mapping keys on context.Canceled because that is the ONE
// error the root context yields: a plain WithCancel, never a deadline, and
// a session cancel (Pause, Resume, ForceReconnect — sessCtx) never reaches
// it. Should ReceivePacket ever grow a per-read deadline or a per-session
// error, that error must NOT be mapped here: this bind has one receive
// routine per open, and it exits for good on net.ErrClosed while the device
// stays Up. The tests pin every side (stop ⇒ closed; Close alone ⇒ closed;
// Pause ⇒ still parked).
func (b *TURNBind) receive(done <-chan struct{}, packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	n, err := b.proxy.ReceivePacketUntil(done, packets[0])
	if err != nil {
		if b.isClosed() || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
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

// Close stops receiving packets: it marks the bind and closes the current
// open's done channel, which wakes a receiver parked in ReceivePacketUntil
// with net.ErrClosed. Idempotent — closeBindLocked runs it once from
// BindClose and once more at the top of BindUpdate — and safe before any
// open (nothing to wake).
func (b *TURNBind) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		if b.done != nil {
			close(b.done)
		}
	}
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
