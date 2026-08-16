import Foundation

/// The per-allocation uplink token bucket, as a Settings knob — now a RATE, not a
/// switch, because the rate is the axis the evidence points at.
///
/// 🎯 WHY A SWEEP OF RATES AND NOT A TOGGLE. `16.08/udptest2` ran the bucket on all
/// 30 connections under real bidirectional traffic and the registered gate came back
/// **three of four**: upload 30.3 → 46.6 Mbit/s (+54%), loss 2.04% → 0.059% (four of
/// five pairs under the ≲0.05% criterion), download and idle ping untouched — and
/// loaded-UPLOAD ping 228 → 289 ms, which is the one that fails.
///
/// The same run named the axis. Matching each speedtest to its own `PACE-ARMEND`,
/// **Spearman(engagement, loaded-up ping) = +1.00** and (engagement, upload) = +0.90:
/// the run whose bucket engaged 5.5% sat almost exactly on the unpaced arm, the
/// 45.9-48.8% runs took the full gain AND the full price. **Benefit and cost are one
/// dial.** Depth is closed at 16 KiB (`16.08/tcptest3`), so the dial is the RATE.
///
/// 🚫 I REGISTERED THIS RANGE AS A SHORT LEVER AND THAT IS RETRACTED — `udptest3`
/// ran it and the contrast is 123×. I had sized the lever as the shift in the 100 ms
/// admission window (161% → 170% of the knee, 6%). **The swept range crosses the
/// policer**: 247 KiB/s is 97.6% of the ~253 KiB/s knee, 260 is 102.8%, 270 is
/// 106.7%. That is a change of SIGN, not of magnitude — a bucket below the knee
/// cannot sustain an overload because its burst is repaid out of headroom, while one
/// above it sustains an overload indefinitely.
/// 🎯 **The error to avoid next time: I sized a lever by the LENGTH of its span when
/// the decisive quantity changed sign inside it. Ask where the zero is.**
///
/// ✅ MEASURED (`16.08/udptest3`, 13 arms, `off` between every rate, rates a
/// palindrome): loss OFF 1.906% · **247 0.0046%** · 260 0.486% · 270 0.898%, the six
/// paced arms separating with no overlap and forming a symmetric hump in time that
/// mirrors the palindrome. ⇒ **247 is the only swept rate BELOW the knee and the only
/// one that holds the loss gate.** 260 and 270 do buy latency back (+34 / +27 ms of
/// drift-free loaded-up ping against 247's +90) — by letting the overload through to
/// the policer, at 100-200× the loss.
/// ⚠️ The 260↔270 leg is inside its own replicate noise (270's pair differs 1.89×,
/// the boundary 1.09×), so the defensible statement is *"the two lowest-loss arms are
/// both 247"*, not a three-way ordering.
///
/// 🚨 AND KEEP AN `off` ARM IN THE ROTATION. `16.08/tcptest3` dropped its control and
/// produced an unresolvable null: its within-condition replicate spread (3.65× and
/// 6.17×) exceeded the between-condition contrast (3.75×). `udptest2` was clean
/// BECAUSE it alternated with off — that is what removed the line's drift and gave
/// the direction-specific control (download must not move).
enum UplinkPace {
    /// 🚨 A NEW KEY, because the value changed TYPE. The old `uplinkPaceOn` was a
    /// Bool; `UserDefaults.integer(forKey:)` on a Bool-typed value returns 1/0, which
    /// would silently mean "1 KiB/s" — a bucket 247× too strict, and one that would
    /// look like a plausible run rather than an error.
    static let key = "uplinkPaceKiB"

    /// The retired key, kept ONLY so the migration can find and clear it. This
    /// project ran a RETIRED lever for three days because a deleted picker left its
    /// value in UserDefaults; the reverse — a stale key silently outvoting the new
    /// one — is the same defect wearing the other hat.
    static let legacyBoolKey = "uplinkPaceOn"

    static let off = 0

    /// 🚨 SWEEP POINTS, NOT A DIAL. Same reasoning as `UplinkChunk`: these are
    /// comparison points chosen against a measured knee, and a free-form stepper
    /// would invite arms that cannot be compared with anything already run.
    ///  • 247 — the server pacer's shipped rate, 95% of the 260 KiB/s the packet-size
    ///    sweep put the policer at, and the rate every pacer run so far used;
    ///  • 260 — the TOP of the measured 247-260 KiB/s knee bracket;
    ///  • 270 — deliberately ABOVE it: accept a little policer loss in exchange for
    ///    less time spent waiting in our own queue.
    /// ⚠️ At 260 and 270 the pool-wide allowance (30 × rate) passes the ~62 Mbit/s
    /// budget, so the bucket stops being an aggregate limiter altogether and is
    /// purely a burst limiter. That is the intent, and it is worth knowing when
    /// reading the result.
    static let choices = [off, 247, 260, 270]

    /// The default, and it is a TEST default. 247 is what every measurement so far
    /// used, so leaving it here keeps a device that nobody has touched comparable
    /// with `udptest2`.
    static let defaultKiB = 247

    /// Depth is SETTLED and deliberately not offered: `16.08/tcptest3` swept it and
    /// 2 KiB bought nothing while costing 10.5% goodput on TCP and 15.4% on UDP, and
    /// the same run showed why depth cannot be the lever on TCP at all.
    static let burstKiB = 16

    static func clamp(_ v: Int) -> Int {
        choices.contains(v) ? v : (choices.min(by: { abs($0 - v) < abs($1 - v) }) ?? defaultKiB)
    }

    /// 🚨 THE MIGRATION, AND IT RUNS BEFORE ANY READ. A device that has already used
    /// the Bool switch carries `uplinkPaceOn`; on/off becomes 247/0 exactly once, the
    /// old key is REMOVED so it cannot outlive its own meaning, and the step is
    /// announced — the failure mode of a silent migration is that it looks like a
    /// setting the user chose.
    static func migrateOnce(in d: UserDefaults) {
        let marker = "uplinkPaceKiBMigrated"
        guard !d.bool(forKey: marker) else { return }
        d.set(true, forKey: marker)
        // 🚨 NEVER OVERWRITE A VALUE THAT IS ALREADY UNDER THE NEW KEY. The marker
        // alone is not enough: on an upgraded device the old key is still present
        // and this runs at the FIRST read — so a user who opens Advanced before the
        // tunnel starts writes 260 through @AppStorage, `onChange` triggers the
        // first read, and an unconditional migration puts 247 straight back over it.
        // A restore from backup before the first read does the same. The result is
        // not a crash but a first arm at a rate nobody chose — the worst kind of
        // defect for this run, because it scores. *(User-caught, 2026-08-16.)*
        if d.object(forKey: key) != nil {
            d.removeObject(forKey: legacyBoolKey)   // retire it anyway
            return
        }
        guard d.object(forKey: legacyBoolKey) != nil else { return }
        let was = d.bool(forKey: legacyBoolKey)
        let now = was ? defaultKiB : off
        d.set(now, forKey: key)
        d.removeObject(forKey: legacyBoolKey)
        SharedLogger.shared.log("[UplinkPace] migrated \(legacyBoolKey)=\(was) → \(key)=\(now) "
            + "and removed the old key; the pacer is a RATE now, not a switch")
    }

    /// 🚨 NO `register(defaults:)`, DELIBERATELY. A registration-domain value is
    /// visible to `object(forKey:)`, which makes the only question the migration
    /// needs to ask — *"has a value been WRITTEN under the new key?"* —
    /// unanswerable the moment registration has happened. The migration would then
    /// skip itself and leave the device on the registered default instead of its
    /// own choice. Reading the default explicitly costs one line and keeps
    /// `object(forKey:) != nil` meaning exactly "someone wrote this".
    /// *(Found by section 11 when the registration domain leaked between suites —
    /// it is process-wide, not per-instance.)*
    static func migrate(in d: UserDefaults) { migrateOnce(in: d) }

    /// The configured rate in KiB/s of counted bytes per allocation; 0 = off.
    /// 🎯 Off is a rate of ZERO rather than a separate flag, because that is exactly
    /// what the Go side's `PaceOff` means — one representation, no pair of values
    /// that can disagree.
    static func stored(in d: UserDefaults) -> Int {
        migrateOnce(in: d)
        guard let v = d.object(forKey: key) as? Int else { return defaultKiB }
        return clamp(v)
    }

    static func label(_ v: Int) -> String { v == off ? "Off" : "\(v) KiB/s" }
}
