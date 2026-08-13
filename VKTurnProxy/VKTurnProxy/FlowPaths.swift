import Foundation

/// Flow-local path set — how many of the N relay connections one inner flow
/// (one 5-tuple) prefers before it spills to the whole pool.
///
/// The Swift side of `pkg/proxy/flowpaths.go`. The two clamps must agree: this
/// one snaps the picker and every backup import, Go clamps again at the sink so
/// a hand-edited backup or a malformed provider message cannot put an
/// unsupported k on the hot path.
///
/// 🚨 k = 1 AND 2 CLAMP **UP** TO 3, THEY ARE NEVER HONOURED. Hard affinity
/// (k=1) is a measured −79% on a single flow — 1.69 Mbit/s on one connection
/// against 8.14 on thirty. The only reason this lever survives that result is
/// that a flow stops gaining after roughly five paths, so k ≈ 5 keeps the
/// fan-out's throughput while exposing the flow to five stall processes instead
/// of thirty. A setting that could quietly become k=1 would reproduce the
/// failure while the log still said the treatment was on.
enum FlowPaths {
    /// Off: every packet races all N connections. Today's behaviour, the
    /// default, and the control arm of the A/B.
    static let off = 0

    /// Smallest honoured set. Below this the design degenerates toward k=1.
    static let minimum = 3

    /// Largest. Beyond ~8 of 30 the "subset" stops being one, so the arm would
    /// be indistinguishable from off while still paying the table cost.
    static let maximum = 8

    /// The sweep points the device A/B steps through. 0 is in the list because
    /// the control arm has to be reachable from the same picker — switching
    /// between arms must not require a reconnect (see `applyFlowPathsK`).
    static let choices = [0, 3, 4, 5, 6, 8]

    /// Snap an arbitrary integer to a supported value. Anything positive but
    /// below `minimum` goes UP, never down to off: a user who asks for a small
    /// set gets the smallest SAFE one, and never silently gets the control arm
    /// when they thought the treatment was running.
    static func clamp(_ value: Int) -> Int {
        if value <= off { return off }
        if value < minimum { return minimum }
        if value > maximum { return maximum }
        return choices.min(by: { abs($0 - value) < abs($1 - value) }) ?? off
    }

    /// What the user has chosen, already snapped. An unwritten key reads 0,
    /// which is off — the same value the picker shows for "Off", so the
    /// sentinel and the real setting coincide here and no separate
    /// "never set" state is needed.
    static func stored(in defaults: UserDefaults = .standard) -> Int {
        clamp(defaults.integer(forKey: "flowPathsK"))
    }

    /// Label for the picker and for the settings summary.
    static func label(_ k: Int) -> String {
        k == off ? "Off (all paths)" : "\(k) paths"
    }
}
