package proxy

import (
	"net"
	"sync/atomic"

	"github.com/pion/dtls/v3/pkg/protocol"
)

// handshakePacketConn samples outgoing DTLS handshake datagrams before sending.
// Clear observer after negotiation so application traffic never samples evidence.
type handshakePacketConn struct {
	net.PacketConn
	observer atomic.Pointer[func()]
}

func (c *handshakePacketConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	if len(packet) != 0 {
		switch protocol.ContentType(packet[0]) {
		case protocol.ContentTypeHandshake, protocol.ContentTypeChangeCipherSpec:
			if observer := c.observer.Load(); observer != nil {
				(*observer)()
			}
		}
	}
	return c.PacketConn.WriteTo(packet, addr)
}
