package proxy

import (
	"fmt"
	"sync/atomic"
)

// Uplink duplication — the FALSIFICATION TEST for systematic FEC over WireGuard
// packets, and nothing more. It is not a production mode and cannot become one:
// at 100% redundancy the useful ceiling is half the allocation budget,
// N x 2.07 / 2 ~ 31 Mbit/s at N=30.
//
// WHY IT EXISTS. ~98% of the inner receiver's holes are closed by the DELAYED
// ORIGINAL rather than by a retransmission, and the inner sender is RACK+SACK,
// so a packet later than about one RTT (~155 ms here) costs throughput through
// the ACK CLOCK: the cumulative ACK cannot advance past the hole, and per-flow
// throughput is set by the rate the fan-out delivers a flow IN ORDER. The server
// resequencer proved the size of that effect — one flow went 4.2 -> 10.7 Mbit/s,
// +155% — and then proved it could not be collected THAT way, because a hold
// timer plus burst release overflows the policer (F=8 -36%, F=32 -42%, loss to
// 23%). FEC would fill the hole WITHOUT holding anything back. Before writing an
// XOR block scheme and a server-side recovery path, this mode answers the one
// question the whole idea rests on:
//
//	if each WireGuard packet travels twice over two DISJOINT groups of
//	connections, and the receiver therefore gets the EARLIEST of two
//	independent draws, does the hole tail shrink and does throughput rise?
//
//	rises          -> earliest-of-two works; FEC can buy most of it back at
//	                  1/8 the cost instead of 1/1.
//	nothing moves  -> FEC will not work either; the tail is not made of
//	                  independent per-connection stalls.
//	tail falls,
//	throughput not -> the ACK-clock account is INCOMPLETE, which is a finding
//	                  about our own model and worth more than the mode.
//
// 🚨 WHY THREE MODES AND NOT TWO. Duplicating over two groups of 15 changes TWO
// things at once: it adds redundancy AND it halves the number of paths each copy
// races. A null with two modes could not tell "earliest-of-two does not help"
// from "each copy lost half its fan-out", and this project has already spent a
// session on an arm that changed two things. UplinkDupSingleGroup is the WIDTH
// CONTROL: bulk traffic on the same 15 connections, one copy. The duplication
// effect is then (dup - single), measured at matched width, and (single - off)
// prices the width change on its own.
//
// 🚨 THE GROUPS ARE BY PARITY, NOT BY HALVES. connIdx % 2 rather than
// connIdx < N/2, because the pool RAMPS: with the low half, a partially
// connected pool would put every live writer in group 0 and leave group 1's
// channel with no consumer at all — the producer would then block forever on a
// copy nobody can take. Parity keeps both groups populated for every prefix of
// the ramp, which also means an arm can start before all 30 are up without
// deadlocking (it should not, but a measurement harness must not be able to
// wedge the tunnel).
//
// 🚨 CONTROL PACKETS NEVER ENTER A GROUP. Keepalives and handshakes keep going
// to the shared channel where all N writers compete for them, so every
// connection keeps getting traffic in every mode. Otherwise the 15 connections
// excluded from single-group mode would idle for a whole arm, the relay or our
// own zombie detection could tear them down, and the NEXT arm would run on a
// degraded pool — an arm silently damaging the arm after it is the worst failure
// mode a paired design has.
const (
	// UplinkDupOff is the shipped behaviour: one shared channel, all N writers
	// competing per packet. Byte-for-byte what the tunnel does today, because
	// nothing is ever put into a group channel.
	UplinkDupOff = 0

	// UplinkDupSingleGroup sends bulk traffic to group 0 only — the same 15
	// connections a duplicated copy would use, without the duplication. The
	// width control.
	UplinkDupSingleGroup = 1

	// UplinkDupBoth sends every bulk packet to BOTH groups: two byte-identical
	// copies, guaranteed to leave on two different connections, and the server's
	// WireGuard drops whichever arrives second by anti-replay.
	UplinkDupBoth = 2
)

// uplinkDupMode is process-global, in the idiom of uplinkChunkK and
// memstatsFastTicks and for the same reasons: the extension runs exactly one
// Proxy, the bridge holds no handle on it, and the value must be settable on a
// tunnel that is ALREADY UP. Applying it through a reconnect would put a ~107 s
// thirty-connection ramp between every pair of arms, on a line measured moving
// 75 -> 363 Mbit/s in ~70 minutes.
var uplinkDupMode atomic.Int64

// SetUplinkDupMode applies the mode immediately, without a reconnect.
func SetUplinkDupMode(m int) { uplinkDupMode.Store(int64(ClampUplinkDupMode(m))) }

// ClampUplinkDupMode snaps a configured value into the supported range. The
// Swift side clamps the same value at the picker and again on backup import, and
// the two must agree, so the range lives in one place per language.
func ClampUplinkDupMode(m int) int {
	if m < UplinkDupOff || m > UplinkDupBoth {
		return UplinkDupOff
	}
	return m
}

// UplinkDupModeName is the name that goes in the log. It exists because a run
// scored under the wrong treatment is the failure this branch inherited from the
// last one: build 257 renamed a field, its own scorer went blind, and a session
// with 154 engaged ticks was filed as "a blind run". The mode is printed on every
// memstats tick and again in the A/B plan line, so no arm can be read as another.
func UplinkDupModeName(m int) string {
	switch ClampUplinkDupMode(m) {
	case UplinkDupSingleGroup:
		return "g15"
	case UplinkDupBoth:
		return "dup"
	default:
		return "off"
	}
}

// uplinkDupGroup maps a connection to its group. Parity, for the ramp reason in
// the file comment. connIdx < 0 (a site with no connection identity) has no
// group and serves only the shared channel.
func uplinkDupGroup(connIdx int) int {
	if connIdx < 0 {
		return -1
	}
	return connIdx % 2
}

// isUplinkBulk reports whether a WireGuard message is DATA carrying a payload,
// as opposed to a keepalive, a handshake or a cookie reply.
//
// A transport message is type 4 with a 16-byte header (type, 3 reserved,
// 4-byte receiver index, 8-byte counter) and a 16-byte Poly1305 tag, so an empty
// keepalive is EXACTLY 32 bytes; handshake initiation / response / cookie are
// types 1 / 2 / 3. Everything that is not bulk data goes to the shared channel —
// see the control-packet note above, this is not an optimisation.
func isUplinkBulk(data []byte) bool {
	return len(data) > 32 && data[0] == 4
}

// nextUplinkItem blocks until this connection has a packet to write, or until
// done fires. It is the ONLY place a writer takes work from, and it is
// deliberately mode-blind: every writer always watches the shared channel AND
// its own group's, so a mode flip needs no wake-up, no re-read and no hint.
//
// 🚨 That is not a stylistic choice. The closed flow-paths lever shipped a
// writer that read its mode once above a blocking select (build 254): after a
// flip, every parked writer still held the channel set it had parked under, so a
// queued packet was reachable only when some OTHER packet on the shared channel
// happened to wake that exact writer — in practice a keepalive, which is how a
// dispatcher defect turned into a 5-second connect stall and cost a day of
// wrong hypotheses. Here the channel set is a function of connIdx alone.
func (p *Proxy) nextUplinkItem(done <-chan struct{}, connIdx int) (sendItem, bool) {
	g := uplinkDupGroup(connIdx)
	if g < 0 {
		select {
		case <-done:
			return sendItem{}, false
		case item := <-p.sendCh:
			return item, true
		}
	}
	select {
	case <-done:
		return sendItem{}, false
	case item := <-p.sendCh:
		return item, true
	case item := <-p.groupCh[g]:
		return item, true
	}
}

// dupStats is the per-interval account of what the mode actually did, in the
// read-and-reset idiom of the other memstats fields.
//
// `copies` and `dropped` are the pair that decides whether an arm tested
// anything: a dup arm whose second copies were mostly dropped is a single-group
// arm wearing the wrong label, exactly the trap `chunk=` was added for after a
// configured K=16 turned out to be writing chunks of 1.
type dupStats struct {
	bulk    atomic.Int64 // bulk packets routed to a group
	copies  atomic.Int64 // second copies actually enqueued
	dropped atomic.Int64 // second copies dropped because the group was full
	ctl     atomic.Int64 // control packets that took the shared channel
}

// summary renders the field group and CLEARS the interval. Unlike the other
// summaries it prints even when everything is zero, because the MODE itself is
// the thing a reader needs on every tick to cut the arms out of the log.
func (d *dupStats) summary() string {
	mode := UplinkDupModeName(int(uplinkDupMode.Load()))
	bulk := d.bulk.Swap(0)
	copies := d.copies.Swap(0)
	dropped := d.dropped.Swap(0)
	ctl := d.ctl.Swap(0)
	return fmt.Sprintf(" updup=%s bulk=%d copies=%d drop=%d ctl=%d",
		mode, bulk, copies, dropped, ctl)
}
