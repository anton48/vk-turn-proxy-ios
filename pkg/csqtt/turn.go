// SPDX-License-Identifier: MIT

package csqtt

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// TURNCredentials is one VK relay credential: username, password and the
// relay's host:port. How they are minted is the caller's business (the app
// and the console tool both use pkg/proxy for it).
type TURNCredentials struct {
	Username string
	Password string
	Address  string
}

// Relay is one allocation: the packet conn to write to the csqtt server
// through, plus what has to be closed with it.
type Relay struct {
	Conn  net.PacketConn
	Local net.Addr
	close func()
}

// Close tears down the relayed conn, the TURN client and the control socket.
func (r *Relay) Close() { r.close() }

// DialRelay allocates a VK TURN relay and creates a permission for the csqtt
// server. transport is "udp" (the reference client's default) or "tcp"
// (what the iOS app ships on). pion binds a channel lazily on the first
// write.
//
// 🚨 The local socket is udp4/tcp4 and the address family is STATED. On
// FreeBSD a plain "udp" listener is a dual-stack [::] socket; pion then
// infers IPv6 from it and asks the relay for an IPv6 allocation, which VK's
// relay answers with silence — "all retransmissions failed", nothing else.
// (2026-09-04, the first run of tools/csqtt_client.)
func DialRelay(creds TURNCredentials, peer *net.UDPAddr, transport string, logLevel logging.LogLevel) (*Relay, error) {
	var ctl net.PacketConn
	switch transport {
	case "udp":
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("local udp: %w", err)
		}
		ctl = uc
	case "tcp":
		tcp, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp4", creds.Address)
		if err != nil {
			return nil, fmt.Errorf("dial tcp to relay: %w", err)
		}
		ctl = turn.NewSTUNConn(tcp)
	default:
		return nil, fmt.Errorf("unknown TURN transport %q", transport)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logLevel
	tc, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr:         creds.Address,
		Conn:                   ctl,
		Username:               creds.Username,
		Password:               creds.Password,
		Realm:                  "okcdn.ru",
		Software:               "vk-turn-srtp",
		LoggerFactory:          lf,
		RequestedAddressFamily: addrFamilyFor(peer),
	})
	if err != nil {
		_ = ctl.Close()
		return nil, fmt.Errorf("turn.NewClient: %w", err)
	}
	if err := tc.Listen(); err != nil {
		tc.Close()
		_ = ctl.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}
	relay, err := tc.Allocate()
	if err != nil {
		tc.Close()
		_ = ctl.Close()
		return nil, fmt.Errorf("turn allocate: %w", err)
	}
	if err := tc.CreatePermission(peer); err != nil {
		_ = relay.Close()
		tc.Close()
		_ = ctl.Close()
		return nil, fmt.Errorf("turn create permission: %w", err)
	}
	return &Relay{
		Conn:  relay,
		Local: ctl.LocalAddr(),
		close: func() {
			_ = relay.Close()
			tc.Close()
			_ = ctl.Close()
		},
	}, nil
}

func addrFamilyFor(peer *net.UDPAddr) turn.RequestedAddressFamily {
	if peer != nil && peer.IP.To4() == nil {
		return turn.RequestedAddressFamilyIPv6
	}
	return turn.RequestedAddressFamilyIPv4
}
