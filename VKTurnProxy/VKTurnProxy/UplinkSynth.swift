// UplinkSynth.swift
//
// The paced synthetic uplink's rate, as a set of SWEEP POINTS rather than a
// dial — the same shape as FlowPaths and the retired uplinkChunkK picker, and
// for the same reason: these are arms of an experiment, not a preference.
//
// 🎯 THE EXPERIMENT. The server measures uplink loss exactly, from WireGuard's
// own sender-assigned counter (`lost` / `cum-lost` in the reorder line). On
// 2026-08-14 that read 1.16% at home with the ACCESS LINK excluded (the naked
// control lost 0.02%) and server1's socket excluded (`netstat-watch`), leaving
// the phone → VK relay → server1 leg. What is NOT settled is whether VK's
// per-allocation meter is doing it: loss per packet came back FLAT across load
// buckets, which refutes a simple rate clip but not a token bucket, because a
// bucket clips on burst structure that a 2-second average cannot resolve.
//
// The way to settle it is a DOSE-RESPONSE: hold the pool at ~30%, ~60% and
// ~95% of the per-allocation knee and ask whether the loss moves. If it is flat
// at 30% of the knee, a meter that is never emptied cannot be the cause and the
// policer dies as the location in every form.
//
// 🚨 AND WHY THIS EXISTS AT ALL, WHEN WE ALREADY HAVE A LOAD GENERATOR: the
// cwnd probe is TCP, and TCP cannot HOLD a level — congestion control ramps
// until it meets something. In `udptest6` the per-connection load wandered
// 28-101% of the knee inside one run. Only a paced generator can ask what
// happens at 30% of the knee and get an answer about 30% of the knee.
import Foundation

enum UplinkSynth {
    /// Off, and the control arm: the tunnel carries only real traffic.
    static let off = 0.0

    /// VK's measured per-allocation knee, in Mbit/s of payload. Bracketed by
    /// direct measurement at 247-260 KiB/s of counted wire bytes; 2.07 is the
    /// payload figure at a 1200-byte packet.
    static let perAllocationMbit = 2.07

    /// The sweep points, in Mbit/s, against the 30 × 2.07 ≈ 62 Mbit/s allocation
    /// budget: a coarse low end (12/19/37) kept from the first dose-response,
    /// then **40 / 55 / 58 / 59 / 60 packed against the knee** for the ramp that
    /// probes hysteresis, and 80 above it to show the meter engaging.
    ///
    /// 🚨 **EVERY LEVEL `UplinkSynthRunner` USES MUST BE IN THIS LIST.** `clamp`
    /// snaps to the NEAREST point, so a level missing here is not rejected — it
    /// is silently replaced by its neighbour, and the run measures a plan nobody
    /// wrote. Adding 40/55/58/60 to the runner without adding them here would
    /// have run 37/59/59/59 instead, and the log would have looked correct
    /// because the generator honestly reports the rate it was given. The runner
    /// now REFUSES to start if any of its levels does not survive `clamp`
    /// unchanged; this comment is the other half of that guard.
    ///
    /// ⚠️ They are ABSOLUTE, so at a different connection count they mean a
    /// different fraction — recompute rather than assuming. The Go side logs
    /// the rate it actually ran, and the SERVER's 2-second per-conn dump is
    /// what says which fraction was really reached.
    /// 🚨 **30 is here for `UplinkPairedRunner`**, which holds the synthetic at
    /// ~half the budget while real TCP takes the rest. Its guard refuses to
    /// start if its rate is not a sweep point, so this entry and that runner
    /// are one change: removing it does not break a build, it stops a run.
    static let choices: [Double] = [0, 12, 15, 19, 30, 37, 40, 55, 58, 59, 60, 80]
    // 🚨 15 exists for the SPLIT run and for nothing else: with the pool cut in
    // half the synthetic rides 15 allocations, and 15 Mbit/s there is the same
    // ~1 Mbit/s per allocation as 30 Mbit/s over 30. Holding the PER-ALLOCATION
    // rate constant is what keeps that arm comparable with the shared one.

    /// The fraction of the allocation budget a rate represents at `conns`
    /// connections, for the picker's own label. Display only.
    static func fractionOfBudget(_ mbit: Double, conns: Int) -> Double {
        let budget = Double(max(conns, 1)) * perAllocationMbit
        return budget > 0 ? mbit / budget : 0
    }

    /// The picker's label. The fraction is quoted at the SHIPPED default of 30
    /// connections and says so, rather than reaching into the active server
    /// profile for a number that would silently change the meaning of a stored
    /// arm. ⚠️ At a different connection count, recompute — and either way the
    /// SERVER's 2-second per-conn dump is what says which fraction was really
    /// reached, not this label.
    static let referenceConns = 30

    static func label(_ mbit: Double) -> String {
        if mbit <= off { return "Off" }
        return String(format: "%.0f Mbit/s (~%.0f%% at N=30)", mbit,
                      100 * fractionOfBudget(mbit, conns: referenceConns))
    }

    /// Snap an arbitrary value to a supported sweep point. Anything above the
    /// top choice clamps down; Go clamps again at the sink.
    static func clamp(_ value: Double) -> Double {
        if value <= off { return off }
        return choices.min(by: { abs($0 - value) < abs($1 - value) }) ?? off
    }

    static let key = "uplinkSynthMbit"

    static func stored(in defaults: UserDefaults) -> Double {
        clamp(defaults.object(forKey: key) as? Double ?? off)
    }
}
