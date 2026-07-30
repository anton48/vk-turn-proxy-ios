// TunnelMTU.swift
//
// The tunnel's inner MTU — bounds, step, default — in ONE place, because four
// call sites have to agree on them: the Advanced screen's Stepper, the config
// builder, the backup importer, and the packet-tunnel extension (which must
// clamp again at the sink, since providerConfiguration can carry whatever an
// imported backup put in UserDefaults).
//
// Compiled into BOTH targets; see the extension's `sources:` in project.yml,
// same pattern as SharedLogger.swift.
//
// WHY THESE NUMBERS — measured on device, then checked against simultaneous
// packet captures taken at BOTH ends (phone + server) on 2026-07-30 at MTU 1000
// and 1400. What those captures actually showed is in
// reference_mtu_and_relay_downstream_loss; the short version:
//
// Ceiling — NOT about fragmentation. There was none in ANY of the four runs, at
// either MTU, on either transport. What 1400 does buy is a very thin margin: with
// the client on UDP its frames reach 1508 bytes, i.e. **6 bytes** short of the
// 1514 an Ethernet path allows, so it works here and would start fragmenting one
// small hop away. That margin, not an observed failure, is why the ceiling stays
// where it is; 1400 also stays under our OWN limit, the 1600-byte relay read
// buffers in pkg/proxy/proxy.go, which cap the inner MTU near 1530 whatever the
// network does.
//
// (With the client on TCP there is a second, transport-specific cost above 1376:
// the ChannelData record stops fitting one segment and every full-size packet
// goes out as a 1514-byte frame plus a 78-byte runt carrying 12 bytes. It does
// not happen on UDP, which is why it is not a bound here.)
//
// Do not reach for this expecting speed. Across TCP runs the MTU differences sat
// inside run-to-run variation; the single best download measured came from UDP at
// 1400, but the transport — `useUDP`, per-server — is what actually moved the
// numbers, not this. The loss that sets the ceiling is congestion in whichever
// direction is saturated (10-22%, while the idle direction stays packet-exact),
// and it is not something an MTU can fix.
//
// Floor — nothing protocol-level forces 1280 here (the tunnel interface is
// IPv4-only; the 1280 that everyone quotes is the IPv6 minimum and does not
// apply). What does bite is that packet RATE scales as 1/MTU, and per-packet
// cost in a 50 MB NetworkExtension is what has historically got this process
// jetsammed. 1000 keeps that in hand while still allowing the one genuinely
// useful direction: lowering it to escape a carrier whose path MTU is smaller
// than we assume, which otherwise shows up as an MTU black hole — handshakes fine,
// bulk transfers dead.
//
// Step — 8, not 1. WireGuard pads the encapsulated packet to a multiple of 16
// before encrypting, so MTUs inside the same 16-byte bucket produce an identical
// worst-case datagram; finer steps would offer choices that cannot change
// whether the packet fits. 8 keeps 1000/1280/1400 all on the grid (16 would have
// forced the bounds to 1008-1392) and IP fragment offsets are 8-byte units too.

import Foundation

enum TunnelMTU {
    /// Stored value meaning "don't override anything" — the tunnel keeps the
    /// built-in default, and on WRAP-A the server's GETCONF value wins as it
    /// always has. This is what a fresh install and every pre-209 backup mean.
    static let automatic = 0

    /// Used when nothing overrides it. Unchanged since the first build; it is
    /// the value every existing deployment is running.
    static let standard = 1280

    static let minimum = 1000
    static let maximum = 1400
    static let step = 8

    static var range: ClosedRange<Int> { minimum...maximum }

    /// Snap an arbitrary integer into the allowed range. `automatic` passes
    /// through untouched — it is a sentinel, not a size.
    static func clamp(_ value: Int) -> Int {
        guard value != automatic else { return automatic }
        return Swift.min(Swift.max(value, minimum), maximum)
    }

    /// The number to actually configure the interface with.
    static func resolve(_ stored: Int) -> Int {
        stored == automatic ? standard : clamp(stored)
    }

    /// What the user has chosen, already clamped. Read from UserDefaults rather
    /// than @AppStorage everywhere but AdvancedView itself — see that file's
    /// header for why nothing near ContentView may observe these keys.
    static func stored(in defaults: UserDefaults = .standard) -> Int {
        clamp(defaults.integer(forKey: "tunnelMTU"))
    }
}
