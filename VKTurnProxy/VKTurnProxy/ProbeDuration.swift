// ProbeDuration.swift
//
// The cwnd probe's runaway stop, in ONE place — because it is the one number
// that can silently shorten a measurement, and it did.
//
// 🚨 WHY IT HAS ITS OWN FILE AND ITS OWN TEST. The bound used to be written
// inline as `min(durationSec, 120)` inside `UplinkCwndProbe.start`, and 120 s
// was the right number when the probe was a hand-driven diagnostic with a
// 5-60 s picker. Once RUNNERS began driving it, that constant became a
// MEASUREMENT defect, because a runner asks for a whole session at once: the
// SPLIT runner asks for ~1229 s and keeps ONE probe alive across arms 3-6.
// Clamped to 120 s the real load would have died 108 s into arm 3 and left arms
// 4, 5 and 6 — two SPLIT arms and a COLOCATED one, i.e. THE MEASUREMENT ITSELF
// — carrying no neighbour at all, while the runner's own flag still said it was
// running. The reading would have come back "colocated ≈ split ≈ solo": a
// perfect null that looks like a finding.
// *(User-caught by reading, 2026-08-16, before the split run.)*
//
// ⚠️ A CORRECTION TO MY OWN FIRST ACCOUNT OF THIS, kept because the wrong story
// is the more plausible one. I wrote that the PAIRED runner was also exposed,
// losing its connect time out of each arm — reasoning that the probe's clock
// started at `start()` while the arm's started at `sending`. It does not: the
// probe creates its deadline AFTER `connectAll` returns and after it sets
// `sending`, so connect time is charged to neither. What the paired runner
// really had was TWO TIMERS OF THE SAME LENGTH racing — its 120 s arm against
// the clamped 120 s probe — which is exactly what the ~30 ms between TEARDOWN
// and ARMEND in `tcptest4` shows. Same conclusion, different mechanism, and the
// difference matters: the paired runner was never losing 25.8 s of neighbour.
// *(User-corrected, 2026-08-16.)*
//
// ⇒ The bound STAYS — a probe that outlives the app that started it is worse
// than a short one — but it now sits far above anything a runner asks for, it
// lives in one place, and CLAMPING IS LOUD. A silently shortened run is
// indistinguishable from a completed one, which is the whole reason this cost a
// dedicated file.
//
// 🎯 AND THE CEILING IS NOT CHECKED AGAINST A COPY OF ANY PLAN'S LENGTH. An
// earlier version of this file carried a `longestRunnerRequestSec = 1229`
// constant so a test could compare the two — which is the very defect this
// project keeps paying for: a second copy of something that already has an
// owner. The runner knows how long it runs; it asks `clamps(_:)` about its OWN
// computed request at STEP 0 and REFUSES to start if the answer is yes.
// *(User-caught, 2026-08-16.)*
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

    /// True when `clamp` would actually change the request.
    ///
    /// 🚨 TWO CALLERS, AND THE SECOND IS THE IMPORTANT ONE: the probe LOGS it,
    /// because the failure mode is silence; and a runner asks it BEFORE the run
    /// and refuses to start, because by the time the log says so the session is
    /// already spent.
    static func clamps(_ sec: Int) -> Bool { sec > maxSec || sec < minSec }

    static func clamp(_ sec: Int) -> Int { max(minSec, min(sec, maxSec)) }
}
