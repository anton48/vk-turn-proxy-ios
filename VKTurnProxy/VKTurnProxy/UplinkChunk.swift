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
// 🚫🚫 SWEPT AND CLOSED, 2026-08-12 — THE SETTING IS GONE AND MUST NOT COME BACK.
// 14 arms (F = 8/16/32 inner flows x K = 1..64), live-switched inside ~14 minutes
// so drift is excluded, moved throughput nothing and the reordering tail nothing.
// The lever cannot ENGAGE: the mean chunk was 1.86 even at K=64 (1.66 at K=8),
// because ~30 writer goroutines compete for a queue whose mean depth is only
// ~2.8 packets, and filling a chunk of K needs roughly N*K queued at once. At the
// inner receiver the hole RATE stayed flat at 18.1-19.2% even in the arms that
// predicted 75-87.5% fewer holes. That is a "the treatment never applied" result,
// not "reordering does not matter".
//
// What survives here is only the clamp and the sweep points, because the value is
// still reachable as an undocumented `uplinkChunkK` backup field — the idiom this
// project already uses for no-UI diagnostics (see UplinkSynthMbit) — so the
// machinery can be re-driven cheaply IF the fan-out architecture ever changes.
// Default is off, and off is byte-for-byte the behaviour the tunnel has always
// had. Full finding: pkg/proxy/uplinkchunk.go.

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

    /// The values the closed sweep stepped through. Kept so a future re-drive
    /// (backup field only — there is no UI any more) reuses the same grid rather
    /// than inventing one, and so `clamp` has something to snap to.
    static let choices = [1, 2, 4, 8, 16, 32, 64, 128]

    /// Snap an arbitrary integer to the nearest supported sweep point. Imports
    /// go through here, so a hand-edited backup cannot put an arbitrary K on the
    /// hot path; Go clamps again at the sink.
    static func clamp(_ value: Int) -> Int {
        let bounded = Swift.min(Swift.max(value, minimum), maximum)
        return choices.min(by: { abs($0 - bounded) < abs($1 - bounded) }) ?? off
    }

    /// What the user has chosen, already snapped. A key that was never written
    /// reads 0 from UserDefaults, which means "never set" and resolves to `off`
    /// — the same sentinel contract TunnelMTU uses.
    ///
    /// Read through UserDefaults only — there is no longer any view that
    /// declares this key, and nothing near ContentView may ever observe it (a
    /// write there pops whatever is pushed). See the SwiftUI pop rule.
    static func stored(in defaults: UserDefaults = .standard) -> Int {
        let raw = defaults.integer(forKey: "uplinkChunkK")
        return raw == 0 ? off : clamp(raw)
    }
}
