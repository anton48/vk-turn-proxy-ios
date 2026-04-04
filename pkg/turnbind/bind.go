package turnbind

import (
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
	b.mu.Lock()
	b.closed = false
	b.mu.Unlock()

	// Start the proxy (connects to VK TURN, establishes DTLS, etc.)
	if err := b.proxy.Start(); err != nil {
		log.Printf("TURNBind.Open: proxy.Start failed: %v", err)
		return nil, 0, err
	}

	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, nil
		}
		n, err := b.proxy.ReceivePacket(packets[0])
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		sizes[0] = n
		eps[0] = &TURNEndpoint{}
		return 1, nil
	}
	return []conn.ReceiveFunc{recvFunc}, port, nil
}

// Close stops receiving packets.
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
