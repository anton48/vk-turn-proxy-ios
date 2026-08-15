// ExperimentKnobs.swift
//
// EVERY EXPERIMENTAL KNOB IN EFFECT, ON ONE LINE, AT THE TOP OF EVERY RUN.
//
// 🚨 WHY THIS EXISTS, and it is the most expensive lesson of 2026-08-15. Nine
// device runs over four days were taken with `uplinkChunkK = 64` — a RETIRED
// lever whose Advanced picker had been deleted, leaving the value it wrote alive
// in UserDefaults with no screen showing it. The number was in every log the
// whole time, inside the config JSON the tunnel dumps at connect. Nobody read it,
// because nothing pointed at it.
//
// 🎯 What makes that failure mode specific rather than mere carelessness: the
// lever is INERT while the send queue is shallow. Mean chunk was 1.000 in every
// synthetic-only run and 1.02-1.17 (max 64) in every run with real inner traffic
// — so it slept through exactly the runs used as CONTROLS and woke in exactly
// the runs used as MEASUREMENTS. A knob like that cannot be caught by noticing
// that a run looks odd; it has to be printed where the run's plan is printed.
//
// ⚠️ SO THE RULE THIS ENCODES: a run's own PLAN line states every knob that could
// change what it measures, and SHOUTS the ones away from production defaults.
// Not the config dump at connect — the plan line of the run being scored. The
// same shape as `flowab PLAN cover=on|off`, which was added after a field rename
// silently voided a session.
//
// This is a REPORTER, not a controller: it changes nothing, and the values it
// reads are the same ones `TunnelManager.buildProxyConfig` hands to Go.

import Foundation

enum ExperimentKnobs {
    /// The knobs whose non-production value would change what a run measures.
    /// Configuration that is not an experiment (connection count, MTU, outer
    /// transport) is printed for the record but never flagged.
    static func summary(defaults: UserDefaults = .standard,
                        server: ServerProfile) -> String {
        let chunk = UplinkChunk.stored(in: defaults)
        let flowK = FlowPaths.stored(in: defaults)
        let cover = FlowPaths.coverStored(in: defaults)
        let synth = UplinkSynth.stored(in: defaults)
        let mtu = TunnelMTU.stored(in: defaults)

        var offenders: [String] = []
        if chunk != UplinkChunk.off { offenders.append("uplinkChunkK=\(chunk)") }
        if flowK != FlowPaths.off { offenders.append("flowPathsK=\(flowK)") }
        if cover { offenders.append("flowPathsCover=on") }
        if synth > 0 { offenders.append("uplinkSynthMbit=\(synth)") }

        let base = "knobs chunkK=\(chunk) flowK=\(flowK) cover=\(cover ? "on" : "off") "
            + "synth=\(synth)Mbit mtu=\(mtu) conns=\(server.numConnections) "
            + "transport=\(server.useUDP ? "UDP" : "TCP")"

        if offenders.isEmpty {
            return base + " — all experiment knobs at production defaults"
        }
        return base + " — 🚨 NOT AT PRODUCTION DEFAULTS: " + offenders.joined(separator: ", ")
            + ". Anything measured here is measured WITH these on; say so when the run is scored."
    }

    /// True when every experimental knob sits at its production value. Runners
    /// that set a knob themselves use this to describe the baseline they started
    /// from, so a run can never silently inherit someone else's arm.
    static func atProductionDefaults(defaults: UserDefaults = .standard) -> Bool {
        UplinkChunk.stored(in: defaults) == UplinkChunk.off
            && FlowPaths.stored(in: defaults) == FlowPaths.off
            && !FlowPaths.coverStored(in: defaults)
            && UplinkSynth.stored(in: defaults) == 0
    }
}
