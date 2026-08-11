//go:build !darwin

package proxy

import "net"

// TCP_CONNECTION_INFO is a Darwin interface. Everywhere else the sampler
// reports "no data", which makes `sockStats.summary()` return "" rather than a
// line of zeroes — the same rule the rest of these instruments follow: an
// instrument that cannot see must say nothing, not say zero.
func sampleTCPInfo(*net.TCPConn) (tcpInfo, bool) { return tcpInfo{}, false }
