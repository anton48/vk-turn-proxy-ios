// ProbeDuration.swift
//
// The cwnd probe's runaway stop, in ONE place — because it is the one number
// that can silently shorten a measurement, and it did.
//
// 🚨 WHY IT HAS ITS OWN FILE AND ITS OWN TEST. The bound used to be written
// inline as `min(durationSec, 120)` inside `UplinkCwndProbe.start`, and 120 s
// was the right number when the probe was a hand-driven diagnostic with a
// 5-60 s picker. Once RUNNERS began driving it, that constant became a
// MEASUREMENT defect, because a runner asks for a whole session at once:
//
//   • The SPLIT runner asks for ~1229 s and keeps ONE probe alive across arms
//     3-6. Clamped to 120 s the real load would have died 108 s into arm 3 and
//     left arms 4, 5 and 6 — two SPLIT arms and a COLOCATED one, i.e. THE
//     MEASUREMENT ITSELF — carrying no neighbour at all, while the runner's own
//     `probeRunning` flag still said it was running. The reading would have come
//     back "colocated ≈ split ≈ solo": a perfect null that looks like a finding.
//
//   • The PAIRED runner escaped by a hair, and only by luck of shape: it
//     restarts the probe for every arm and its arm is exactly 120 s, so
//     `tcptest4` shows the probe expiring ~30 ms before the runner stopped it.
//     Had the flows taken their recorded 25.8 s to connect, every paired arm
//     would have lost 25.8 s of its neighbour with nothing in the log to say so.
//
// *(User-caught by reading, 2026-08-16, before the split run.)*
//
// ⇒ The bound STAYS — a probe that outlives the app that started it is worse
// than a short one — but it now sits far above anything a runner asks for, it
// lives in one place, and CLAMPING IS LOUD. A silently shortened run is
// indistinguishable from a completed one, which is the whole reason this cost a
// dedicated file.
//
// Foundation only, deliberately: `tools/swiftcheck` compiles THIS source
// standalone, the same arrangement `UplinkChunk` uses.

import Foundation

enum ProbeDuration {
    /// One hour. The longest plan on a button is the split runner's ~20 minutes,
    /// so this is well clear of every caller while still stopping a value typed
    /// by hand or arriving from a decoded backup.
    static let maxSec = 3600

    /// A probe that runs for zero seconds is not a shorter measurement, it is a
    /// missing one.
    static let minSec = 1

    /// The longest run any in-app runner asks for, kept here so the ceiling can be
    /// checked against it rather than eyeballed. The split runner is the longest:
    /// warm-up 25 + 8 arms × (120 + 8) + 5 settles × 12 + the 120 s of slack it
    /// adds = 1229 s.
    static let longestRunnerRequestSec = 1229

    /// True when `clamp` would actually change the request. The caller LOGS this,
    /// because the failure mode is silence.
    static func clamps(_ sec: Int) -> Bool { sec > maxSec || sec < minSec }

    static func clamp(_ sec: Int) -> Int { max(minSec, min(sec, maxSec)) }
}
