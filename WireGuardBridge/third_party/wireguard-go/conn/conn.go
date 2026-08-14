/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package conn implements WireGuard's network connections.
package conn

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
)

const (
	IdealBatchSize = 128 // maximum number of packets handled per read and write
)

// A ReceiveFunc receives at least one packet from the network and writes them
// into packets. On a successful read it returns the number of elements of
// sizes, packets, and endpoints that should be evaluated. Some elements of
// sizes may be zero, and callers should ignore them. Callers must pass a sizes
// and eps slice with a length greater than or equal to the length of packets.
// These lengths must not exceed the length of the associated Bind.BatchSize().
type ReceiveFunc func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error)

// A Bind listens on a port for both IPv6 and IPv4 UDP traffic.
//
// A Bind interface may also be a PeekLookAtSocketFd or BindSocketToInterface,
// depending on the platform-specific implementation.
type Bind interface {
	// Open puts the Bind into a listening state on a given port and reports the actual
	// port that it bound to. Passing zero results in a random selection.
	// fns is the set of functions that will be called to receive packets.
	Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error)

	// Close closes the Bind listener.
	// All fns returned by Open must return net.ErrClosed after a call to Close.
	Close() error

	// SetMark sets the mark for each packet sent through this Bind.
	// This mark is passed to the kernel as the socket option SO_MARK.
	SetMark(mark uint32) error

	// Send writes one or more packets in bufs to address ep. The length of
	// bufs must not exceed BatchSize().
	Send(bufs [][]byte, ep Endpoint) error

	// ParseEndpoint creates a new endpoint from a string.
	ParseEndpoint(s string) (Endpoint, error)

	// BatchSize is the number of buffers expected to be passed to
	// the ReceiveFuncs, and the maximum expected to be passed to SendBatch.
	BatchSize() int
}

// BindSocketToInterface is implemented by Bind objects that support being
// tied to a single network interface. Used by wireguard-windows.
type BindSocketToInterface interface {
	BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error
	BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error
}

// PeekLookAtSocketFd is implemented by Bind objects that support having their
// file descriptor peeked at. Used by wireguard-android.
type PeekLookAtSocketFd interface {
	PeekLookAtSocketFd4() (fd int, err error)
	PeekLookAtSocketFd6() (fd int, err error)
}

// FlowSender is an OPTIONAL Bind capability, patched in for vk-turn-proxy's
// flow-local path set. When a Bind implements it, Peer.SendBuffers passes a
// per-buffer flow key alongside the packets — a hash of the inner 5-tuple
// (0 = unknown / keepalive / handshake) — so the Bind can keep a flow on a
// stable subset of its outer paths. Binds that do not implement it are sent to
// via the plain Send, so upstream binds are unaffected.
type FlowSender interface {
	SendWithFlows(bufs [][]byte, ep Endpoint, flowKeys []uint64) error
}

// FlowReceiver is the DOWNLINK twin of FlowSender, and it exists for one
// measurement: the upload was traced to a SPURIOUS RTO — half the retransmits
// arrive at a receiver that already had the data, at an original→duplicate
// median of 1203 ms against a 120 ms srtt — and a timer that fires over a
// healthy data path means the sender stopped getting FEEDBACK.
//
// An AGGREGATE version of that measurement was built first and refuted the
// POOL-WIDE form: 81 collapsed-cwnd seconds against 13 ticks with any feedback
// gap. What it could not see is a gap in ONE flow's ACKs while the other flows
// keep the aggregate busy — and with an RTO of ~371 ms against an srtt of
// ~120 ms, barely 3x, that is exactly the size of event that matters.
//
// Seeing it requires the inner 5-tuple, which is ciphertext everywhere except
// here: the plaintext side of WireGuard. Binds that do not implement this are
// simply not called, so upstream binds are unaffected.
type FlowReceiver interface {
	// ObserveInboundAck is called once per inbound PURE TCP ACK (no payload)
	// with its inner-flow key, just before the packet is written to the TUN.
	ObserveInboundAck(flowKey uint64)
}

// An Endpoint maintains the source/destination caching for a peer.
//
//	dst: the remote address of a peer ("endpoint" in uapi terminology)
//	src: the local address from which datagrams originate going to the peer
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() netip.Addr
	SrcIP() netip.Addr
}

var (
	ErrBindAlreadyOpen   = errors.New("bind is already open")
	ErrWrongEndpointType = errors.New("endpoint type does not correspond with bind type")
)

func (fn ReceiveFunc) PrettyName() string {
	name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	// 0. cheese/taco.beansIPv6.func12.func21218-fm
	name = strings.TrimSuffix(name, "-fm")
	// 1. cheese/taco.beansIPv6.func12.func21218
	if idx := strings.LastIndexByte(name, '/'); idx != -1 {
		name = name[idx+1:]
		// 2. taco.beansIPv6.func12.func21218
	}
	for {
		var idx int
		for idx = len(name) - 1; idx >= 0; idx-- {
			if name[idx] < '0' || name[idx] > '9' {
				break
			}
		}
		if idx == len(name)-1 {
			break
		}
		const dotFunc = ".func"
		if !strings.HasSuffix(name[:idx+1], dotFunc) {
			break
		}
		name = name[:idx+1-len(dotFunc)]
		// 3. taco.beansIPv6.func12
		// 4. taco.beansIPv6
	}
	if idx := strings.LastIndexByte(name, '.'); idx != -1 {
		name = name[idx+1:]
		// 5. beansIPv6
	}
	if name == "" {
		return fmt.Sprintf("%p", fn)
	}
	if strings.HasSuffix(name, "IPv4") {
		return "v4"
	}
	if strings.HasSuffix(name, "IPv6") {
		return "v6"
	}
	return name
}
