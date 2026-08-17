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
    /// Runs once, says so when it fires, and never touches the new key.
    @discardableResult
    static func clearRetiredTestKeyOnce(in d: UserDefaults = .standard,
                                        log: ((String) -> Void)? = nil) -> Bool {
        let marker = "uplinkPaceOnCleared"
        guard !d.bool(forKey: marker) else { return false }
        d.set(true, forKey: marker)
        guard d.object(forKey: retiredBoolKey) != nil else { return false }

        let was = d.bool(forKey: retiredBoolKey)
        d.removeObject(forKey: retiredBoolKey)
        log?("uplink-pace: cleared the retired test switch \(retiredBoolKey)=\(was) left by "
            + "builds 296-298, which defaulted it ON for measurement. The shipped setting is "
            + "\(key) and its default is OFF; turn the pacer on in Settings › Advanced if you "
            + "want it.")
        return true
    }
}
