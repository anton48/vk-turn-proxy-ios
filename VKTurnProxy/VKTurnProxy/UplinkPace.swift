// UplinkPace.swift
//
// The uplink pacer's setting: one switch, one rate, one burst — Settings ›
// Advanced, DEFAULT OFF.
//
// WHAT IT DOES. Every relay connection gets a token bucket over the WIRE bytes
// VK's per-allocation policer counts, and a writer reserves from it BEFORE it
// takes a packet off the shared queue. That turns the tunnel's uplink from
// bursts into a stream, which matters because the loss we spent a week locating
// is per-allocation and block-shaped: it arrives as 14-21 consecutive packets
// (20-28 KB) cut out of one allocation at a time, on every allocation the
// burster touches and only those. That is a bucket running dry, and a bucket is
// what answers it. Full mechanism: pkg/proxy/uplinkpace.go.
//
// ✅ WHAT IT BUYS, AND WHAT IT COSTS — both measured on this phone, on 30
// connections, under real bidirectional traffic (`16.08.2026/udptest2`, ten
// alternating speedtests with the pacer toggled live seven times):
//
//   - upload 30.3 → 46.6 Mbit/s (+54%, the two ranges do not overlap);
//   - uplink loss 2.04% → 0.059%, and 0.0046% in the rate sweep the next run;
//   - download, idle ping and loaded-DOWNLOAD ping ALL unchanged — the effect is
//     direction-specific, which is an internal control in every run;
//   - loaded-UPLOAD ping 228 → 289 ms. That is the whole price.
//
// 🎯 WHY 247 AND NOT A DIAL. The sweep (`16.08.2026/udptest3`, 13 arms with
// `off` between every rate) separated loss perfectly and with no overlap: OFF
// 1.906% · **247 0.0046%** · 260 0.486% · 270 0.898%. The reason is not a
// gradient but a THRESHOLD — 247 KiB/s is 97.6% of the ~253 KiB/s knee, 260 is
// 102.8% and 270 is 106.7%. A bucket below the knee cannot sustain an overload
// because its burst is repaid out of headroom; one above it sustains an overload
// indefinitely. So the two higher rates are not "less aggressive settings", they
// are settings that give the effect back, and exposing them here would be
// offering the user two measured losers.
//
// 🚫 AND THE BURST IS NOT A DIAL EITHER. 2 KiB against 16 KiB bought nothing on
// loss and cost 10.5% of goodput on TCP; on UDP it cut loss 36× and cost 15.4%.
// We ship TCP. 16 KiB is settled — pkg/proxy/uplinkpace.go carries the argument.
//
// ⚠️ WHY IT SHIPS DEFAULT OFF. The registered gate had four criteria and this
// passes three: loss, goodput and no cross-talk. Loaded-upload latency fails it
// on an absolute threshold — though the calibration says the failure is not one
// a user would feel (the induced uplink delay is ~135-152 ms against the ~469 ms
// this phone's own 5G adds under the same load). Default OFF is the honest
// reading of a gate that did not pass in full; the switch is how it gets used.

import Foundation

enum UplinkPace {
    /// 0 = off. The value is a RATE in KiB/s and not a boolean, because that is
    /// exactly what the Go side stores: `PaceOff` is a rate of zero, so there is
    /// one representation and no pair of values that can disagree.
    static let off = 0

    /// The one shipped rate. See the header for why it is not a picker.
    static let onKiB = 247

    /// The bucket's capacity. Settled, and deliberately not a setting.
    static let burstKiB = 16

    /// 🚨 AN Int KEY, AND THE TYPE IS LOAD-BEARING. `UserDefaults.integer(forKey:)`
    /// on a value that was written as a Bool returns 1, which as a rate means
    /// **1 KiB/s** — a bucket 247× too strict, which throttles the uplink to a
    /// crawl while looking like a setting the user chose. That is why the retired
    /// test switch below has a DIFFERENT name and is removed rather than reused.
    static let key = "uplinkPaceKiB"

    /// The test-only switch that the diagnostic builds (296-298) wrote as a Bool,
    /// kept ONLY so it can be deleted. It defaulted to ON for measurement; leaving
    /// it in place would let a retired key outvote the shipped default, which is
    /// the same defect that once ran a removed chunking picker for three days.
    static let retiredBoolKey = "uplinkPaceOn"

    /// 🚨 THE MARKER FOR THE PRODUCTION RESET, AND IT IS DELIBERATELY A NEW NAME.
    /// A marker set by a diagnostic build cannot guard a production reset: the
    /// device that most needs resetting is exactly the one that ran those builds
    /// and already has their marker. Reusing one is how a guard passes for the
    /// worst-case device. *(User-caught, 2026-08-17 — the first port shipped that
    /// mistake in the chunking retirement.)*
    static let productionResetKey = "uplinkPaceResetToProductionDefault"

    /// What the tunnel should run: 0, or the one shipped rate. Anything else in
    /// the store — a hand-edited backup, or one of the sweep rates written by a
    /// diagnostic build — reads as "on" and snaps to 247, because the sweep
    /// measured 260 and 270 as strictly worse and they are not offered here.
    static func stored(in d: UserDefaults = .standard) -> Int {
        d.integer(forKey: key) == off ? off : onKiB
    }

    static func isOn(in d: UserDefaults = .standard) -> Bool { stored(in: d) != off }

    /// 🚨 REMOVING A UI DOES NOT REMOVE THE STATE IT WROTE — the lesson this
    /// project paid three days of measurements for. The 296-298 builds shipped a
    /// Bool switch that defaulted to ON *for testing*, and a device that ran them
    /// still carries `uplinkPaceOn = true`. Production must come up OFF, so the
    /// retired key is deleted rather than migrated: carrying its value over would
    /// silently make the shipped default a lie on exactly the devices that
    /// measured it.
    ///
    /// 🚨 AND THERE ARE **TWO** DIAGNOSTIC REPRESENTATIONS TO UNDO, NOT ONE.
    /// Builds 299-302 wrote **this very key** as a rate — the sweep's picker stored
    /// 247 / 260 / 270 under `uplinkPaceKiB`. Clearing only the Bool leaves that
    /// value in place, and `stored()` turns any non-zero into 247, so the one
    /// device that ran the rate sweep would enter production with the pacer ON
    /// while the setting claims to ship off. *(User-caught, 2026-08-17.)*
    ///
    /// ⇒ Both representations are zeroed exactly ONCE, behind a marker no
    /// diagnostic build has ever set. After it, the user's choice is theirs and
    /// survives every launch — this must never become a switch that resets itself.
    ///
    /// ⚠️ It deliberately does not READ the old values to decide anything: carrying
    /// `true` or `247` across would make "default OFF" a lie on precisely the
    /// devices that measured the feature.
    @discardableResult
    static func resetToProductionDefaultOnce(in d: UserDefaults = .standard,
                                             log: ((String) -> Void)? = nil) -> Bool {
        guard !d.bool(forKey: productionResetKey) else { return false }
        d.set(true, forKey: productionResetKey)

        let hadBool = d.object(forKey: retiredBoolKey) != nil
        let hadRate = (d.object(forKey: key) as? Int) ?? 0
        d.removeObject(forKey: retiredBoolKey)
        d.removeObject(forKey: key)
        guard hadBool || hadRate != 0 else { return false }

        log?("uplink-pace: reset to the production default (OFF). This device carried "
            + (hadBool ? "the retired test switch \(retiredBoolKey) " : "")
            + (hadBool && hadRate != 0 ? "and " : "")
            + (hadRate != 0 ? "a diagnostic rate \(key)=\(hadRate) " : "")
            + "from builds 296-302, where the pacer was ON for measurement. Neither value is "
            + "carried over — turn it on in Settings › Advanced if you want it.")
        return true
    }
}
