//go:build darwin

package proxy

import (
	"net"

	"golang.org/x/sys/unix"
)

// tcpConnectionInfoOpt is TCP_CONNECTION_INFO from netinet/tcp.h. Darwin-only,
// and the reason this file is split out — GOOS=ios satisfies the darwin build
// tag, so the phone and the Mac take this path and nothing else has to.
const tcpConnectionInfoOpt = 0x106

// sampleTCPInfo reads the kernel's view of one connection. Read-only: it does
// not touch the socket's state or its deadlines, so it is safe on a socket the
// netpoller is actively writing to.
//
// ⚠️ Field semantics are the SDK's, not ours, and one of them is a trap:
// `Snd_sbbytes` is documented as "bytes in send socket buffer, including
// in-flight data". Treat it as an upper bound on what is WAITING.
func sampleTCPInfo(c *net.TCPConn) (tcpInfo, bool) {
	if c == nil {
		return tcpInfo{}, false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return tcpInfo{}, false
	}
	var info tcpInfo
	var ok bool
	// Control blocks the runtime from closing the fd for the duration, which is
	// what makes this safe against a concurrent reconnect.
	cerr := raw.Control(func(fd uintptr) {
		ci, gerr := unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, tcpConnectionInfoOpt)
		if gerr != nil || ci == nil {
			return
		}
		info = tcpInfo{
			sbBytes:        ci.Snd_sbbytes,
			cwnd:           ci.Snd_cwnd,
			sndWnd:         ci.Snd_wnd,
			sndWscale:      ci.Snd_wscale,
			srttMs:         ci.Srtt,
			rttvarMs:       ci.Rttvar,
			rtxPkts:        ci.Txretransmitpackets,
			inLossRecovery: ci.Flags&tcpciFlagLossRecovery != 0,
			reorderingSeen: ci.Flags&tcpciFlagReorderingDetected != 0,
		}
		ok = true
	})
	if cerr != nil {
		return tcpInfo{}, false
	}
	return info, ok
}
