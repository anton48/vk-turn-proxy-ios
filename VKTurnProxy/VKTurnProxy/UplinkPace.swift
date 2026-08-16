import Foundation

/// The per-allocation uplink token bucket, as a Settings knob.
///
/// 🚨 THIS IS A TEST KNOB, NOT A SHIPPED DEFAULT, AND THE DIFFERENCE IS RECORDED
/// HERE BECAUSE THE DEFAULT IS `on`. The bucket's effect is measured and large —
/// `16.08/tcptest2` cut group-B loss sevenfold (0.85% → 0.12%) and raised delivered
/// goodput 43% (17.1 → 24.4 Mbit/s) — but that run **failed its own registered KEEP
/// gate**, and the reason it is on by default is that the person running these
/// builds wants it armed while testing, not that it is ready to ship.
///
/// What is NOT yet measured, and each one is load-bearing:
///  • it has only ever run on **15 of 30** connections (the diagnostic split);
///  • the load has only ever been **bulk TCP** — 8 probe flows to `cwndsink`, with
///    **no downlink workload at all** (rx was ACK-only in every arm);
///  • **no tested point passes goodput and latency together.** 16 KiB wins
///    throughput at the price of bufferbloat in OUR OWN queue (`sendch-peak`
///    82 → 256/256, the producer blocked in 67-71 of 120 ticks, ≈91 ms of FIFO
///    residence that the OUTER sockets' srtt never sees — it stayed flat at
///    119-120 ms while the inner flows went 155 → 222-371 ms); 2 KiB removes the
///    loss at the price of throughput (−10.5% on TCP, −15.4% on UDP).
///
/// ⇒ The open question is not *"does it work"* but *"is there a point on the
/// rate × depth plane that passes both"*, and that needs a run on the full pool
/// under real bidirectional traffic.
enum UplinkPace {
    /// 🚨 The key is read by non-view code too, so it lives here rather than in a
    /// `@AppStorage` literal — the same reason `UplinkChunk` exists. A second copy
    /// of a key is a second thing to go stale.
    static let key = "uplinkPaceOn"

    /// Rate and depth are NOT exposed. The depth was swept and settled at 16 KiB
    /// (`16.08/tcptest3`) and the rate is the server pacer's shipped 247; a picker
    /// for either would invite a sweep that has already been run.
    static let rateKiB = 247
    static let burstKiB = 16

    /// 🚨 DEFAULT ON — and `register` is what makes that true on a device that has
    /// never opened Settings. `UserDefaults.bool(forKey:)` returns **false** for an
    /// absent key, so a bare `@AppStorage("…") var on = true` reads `true` in the
    /// view and `false` everywhere else, and the tunnel would run unpaced while the
    /// switch showed on. That split-brain is the shape of the App Group defect this
    /// project has already paid for twice.
    static func register(in d: UserDefaults) {
        d.register(defaults: [key: true])
    }

    /// Whether the bucket should be armed. Non-view callers use this.
    static func stored(in d: UserDefaults) -> Bool {
        register(in: d)
        return d.bool(forKey: key)
    }

    /// The rate to hand the extension: the configured one when on, 0 when off.
    /// 🎯 Off is expressed as a RATE OF ZERO rather than a separate flag, because
    /// that is exactly what the Go side's `PaceOff` means — one representation, no
    /// pair of values that can disagree.
    static func rate(in d: UserDefaults) -> Int {
        stored(in: d) ? rateKiB : 0
    }

    /// 🚨 The bucket is wired into ALL FOUR writer loops as of build 296, so every
    /// transport mode is paced. It was SRTP-only before that, and three of the four
    /// modes whose names contain "SRTP" (`.srtpWrap`, `.srtpWrapS`, `.srtpWrapA`)
    /// leave `useSrtp = false` — so a mode-based reading of "is it on" was wrong in
    /// a way the log could not show, because an unwired writer renders exactly like
    /// a bucket that never had to wait (`waited=0` → "NEVER WAITED").
    /// Kept as a note rather than a check: there is nothing left to refuse.
    static let wiredIntoEveryWriter = true
}
