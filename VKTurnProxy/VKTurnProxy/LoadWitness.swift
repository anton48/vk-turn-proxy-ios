// LoadWitness.swift
//
// Did the real load actually run for the whole of this arm?
//
// 🚨 WHY THE VERDICT IS A FUNCTION AND NOT THREE LINES INSIDE THE RUN LOOP: the
// property it guards fails SILENTLY. A wrong verdict passes an arm that carried
// no neighbour, the arm scores as loaded, and the run reads as "the treatment
// did not engage" — a null produced by the instrument. The runner itself cannot
// be compiled standalone (it needs the probe, the tunnel manager and the app's
// logger), so the judgement lives here, in a Foundation-only file that
// `tools/swiftcheck` compiles against the real source.
//
// The three ways an arm can be unloaded, and each was a separate defect:
//
//  • the load never moved at all — the first version caught only this;
//  • it moved and then DIED, leaving a positive byte delta across the arm while
//    the arm was 99% idle. "Some bytes moved" is not "the load was running";
//  • it ran with FEWER FLOWS than the arm asked for — `connectAll` rejected only
//    ZERO, and a sender dying on a socket error just broke out of its loop, so
//    7 of 8 could be gone while every aggregate stayed healthy on the strength
//    of the last one. This project has measured the neighbour's INTENSITY as a
//    dose (0/8/16 flows → 0.001/1.08/2.4-2.7% collateral loss), so a short pool
//    is A DIFFERENT ARM, not a noisier version of the same one;
//  • it moved, STOPPED FOR MOST OF THE ARM, and resumed just before the end —
//    which has a positive delta, a live probe AND a fresh last byte. 🎯 The only
//    quantity that means "throughout" is the WORST GAP inside the arm, so that
//    is what this judges on; freshness at the end passed a 98%-solo arm;
//  • the probe ended by its own lifecycle — which used to be checked at the next
//    arm's boundary, so a death inside the LAST arm was never seen and the run
//    printed DONE.
//
// *(All three user-caught, 2026-08-16, before the run.)*

import Foundation

enum LoadWitness {
    enum Verdict: Equatable {
        /// The load was moving, and was still moving at the arm's end.
        case ok
        /// Nothing moved for the whole arm — a solo arm wearing a loaded label.
        case noBytes
        /// It moved, then stopped: `ms` is how stale the last byte was.
        case stalled(ms: Int)
        /// The probe was no longer running when the arm closed.
        case ended
        /// Fewer flows were carrying the load than the arm asked for.
        case shortPool(live: Int, want: Int)
    }

    /// 🚨 ORDER MATTERS, and it is by how much each says. `noBytes` outranks
    /// `ended`, because a probe that ended having sent nothing is better
    /// described by what it failed to do than by when it stopped; and `stalled`
    /// is last because it is the only one that needs a threshold, so it must
    /// never be the label on a case the other two already explain exactly.
    static func judge(movedBytes: UInt64,
                      worstGapMs: Int,
                      probeStillRunning: Bool,
                      liveFlows: Int,
                      wantFlows: Int,
                      staleMs: Int) -> Verdict {
        // 🚨 THE POPULATION COMES FIRST BECAUSE IT EXPLAINS THE REST. If flows
        // are missing, every other symptom is downstream of that, and reporting
        // the downstream one sends the reader to the wrong place. It is also the
        // only failure the aggregates CANNOT see: bytes, gaps and lifecycle are
        // all satisfied by one surviving flow.
        if liveFlows != wantFlows { return .shortPool(live: liveFlows, want: wantFlows) }
        if movedBytes == 0 { return .noBytes }
        if !probeStillRunning { return .ended }
        if worstGapMs > staleMs { return .stalled(ms: worstGapMs) }
        return .ok
    }

    /// What the arm ACTUALLY was, as against the label it was running under.
    ///
    /// 🚨 IT LIVES HERE FOR THE SAME REASON `reason` DOES: it was a fixed suffix
    /// on the runner's abort line — *"it is a SOLO arm in disguise"* — which is
    /// true of an arm that carried nothing and FALSE of one that carried 7 of 8
    /// flows. That arm is not solo; it is a different INTENSITY, which is a
    /// different arm in an experiment where intensity is the dose. A phrase that
    /// cannot see the verdict will eventually contradict it.
    /// *(User-caught, 2026-08-16.)*
    static func mislabel(_ v: Verdict) -> String {
        switch v {
        case .ok:
            return "the arm it was labelled"
        case .noBytes, .ended:
            return "a SOLO arm in disguise"
        case .shortPool(let live, _):
            return live == 0 ? "a SOLO arm in disguise"
                             : "an arm at an INTENSITY nobody asked for"
        case .stalled:
            return "an arm that spent part of itself unloaded"
        }
    }

    /// What the log says when an arm is void. Kept beside the verdict so the two
    /// cannot drift apart.
    static func reason(_ v: Verdict) -> String {
        switch v {
        case .ok:            return "the load was up throughout"
        case .noBytes:       return "NO BYTES MOVED at all"
        case .ended:         return "the probe had already ended"
        case .stalled(let m): return "the load stood still for \(m)ms inside this arm"
        case .shortPool(let live, let want):
            return "only \(live) of \(want) flows were carrying the load — the neighbour's "
                 + "INTENSITY is the treatment, so this is a different arm and not a noisy one"
        }
    }
}
