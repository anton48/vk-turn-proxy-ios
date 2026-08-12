// UplinkChunk.swift
//
// The uplink-chunking EXPERIMENT: bounds, sweep points and default in ONE
// place, because three call sites have to agree on them — the Advanced screen's
// picker, the backup importer, and the config builder that hands the number to
// Go. The Go side clamps again at the sink (pkg/proxy/uplinkchunk.go), since an
// imported backup is an untrusted source.
//
// WHAT IT DOES. The tunnel's uplink is per-packet work-stealing: every relay
// connection's writer competes for one queue, so consecutive WireGuard packets
// scatter across ~30 paths of unequal latency. WireGuard hands packets to the
// TUN in arrival order, so that scatter reaches the inner TCP as reordering,
// and its sender treats reordering as loss. K is how many consecutive packets
// one writer keeps on ONE path before competing again. K = 1 is what this
// tunnel has always done.
//
// 🚨 THIS SCREEN ENTRY IS EXPECTED TO BE REMOVED once the sweep has answered.
// It is a measurement, not a feature — it is here because the sweep has to be
// run by hand on a device, and a hidden backup field is a switch nobody can
// find and therefore nobody tests.
//
// 🚨 WHAT IT CANNOT DO, so a null is read correctly. Only SAME-flow reordering
// costs throughput; one inner flow's packet overtaking another's produces no
// duplicate ACK. With F inner flows active, a flow's own consecutive packets sit
// roughly F apart in the queue, so K only keeps them together when K >= F. This
// is aimed at the speedtest regime (8-16 flows) and is expected to do very
// little at `iperf3 -P 64`. And it must NOT be scored with the server's
// `uplinkReorder` counter, which is flow-blind and will fall whether or not
// throughput moves — score with throughput, back-to-back against a control in
// the same minutes.

import Foundation

enum UplinkChunk {
    /// K = 1: one packet per grab. The behaviour the tunnel has always had, the
    /// default, the off switch, and the control arm of every A/B run.
    static let off = 1

    static let minimum = 1

    /// A chunk cannot outrun the connection it is written to — the relay's
    /// per-allocation policer is ~2.07 Mbit/s and its advertised window ~42 KB,
    /// so beyond roughly one window's worth the write blocks and the chunk
    /// truncates itself. This bound exists to keep a mistyped value from being
    /// interesting, not because 128 is tuned.
    static let maximum = 128

    /// The values worth comparing. A picker rather than a free stepper because
    /// this is a SWEEP, not a dial: these are the points a run steps through,
    /// and doubling is the right spacing when the effect is expected to appear
    /// only once K reaches the inner flow count.
    static let choices = [1, 2, 4, 8, 16, 32, 64, 128]

    /// Snap an arbitrary integer to the nearest supported sweep point. Imports
    /// go through here, so a hand-edited backup cannot introduce a K that the
    /// picker could never show — which would leave the screen displaying
    /// something the tunnel is not doing.
    static func clamp(_ value: Int) -> Int {
        let bounded = Swift.min(Swift.max(value, minimum), maximum)
        return choices.min(by: { abs($0 - bounded) < abs($1 - bounded) }) ?? off
    }

    /// What the user has chosen, already snapped. A key that was never written
    /// reads 0 from UserDefaults, which means "never set" and resolves to `off`
    /// — the same sentinel contract TunnelMTU uses.
    ///
    /// Read through UserDefaults rather than @AppStorage everywhere but
    /// AdvancedView itself: nothing near ContentView may observe these keys, or
    /// a write pops whatever is pushed. See the SwiftUI pop rule.
    static func stored(in defaults: UserDefaults = .standard) -> Int {
        let raw = defaults.integer(forKey: "uplinkChunkK")
        return raw == 0 ? off : clamp(raw)
    }
}
