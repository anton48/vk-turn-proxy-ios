// InternetRTTReading.swift
//
// The ONE rule for the "Internet" box on the main screen: what it holds after
// a measurement.
//
// The box is the app's own TCP connect to a public address, made every ten
// seconds or so; the app's sockets go through the tunnel, so it is the one
// number on the screen that says whether the tunnel CARRIES anything. It used
// to be written only when a connect succeeded — a failed or timed-out connect
// left the previous value standing — and so, over a tunnel that had been dead
// for three hours, the screen still read "28 ms" (the user's screenshot,
// 2026-09-19): the last good answer, shown as the current one.
//
// 🚨 A measurement that did not complete is NOT "no news". It is the news: the
// box goes to 0, which the screen renders as "—", until a connect succeeds
// again. Never the previous value. The rule is Foundation-only so the harness
// can drive it; TunnelManager publishes every outcome through it.

import Foundation

enum InternetRTTReading {
    enum Outcome: Equatable {
        case connected(milliseconds: Double)
        case failed
        case timedOut
    }

    /// What the box holds after `outcome`: the measured time, or 0 ("—") when
    /// the measurement did not complete.
    static func value(after outcome: Outcome) -> Double {
        if case .connected(let ms) = outcome, ms > 0 { return ms }
        return 0
    }
}
