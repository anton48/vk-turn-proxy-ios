// LoadProgress.swift
//
// How much the real load has moved, and — the part that matters — THE LONGEST IT
// EVER STOOD STILL inside the window being scored.
//
// 🚨 THIS TYPE HAS BEEN WRONG THREE TIMES, EACH TIME IN A WAY THAT PASSED AN
// UNLOADED ARM, so the whole history is here rather than in a commit nobody
// reads. All three were caught by the user before the run.
//
//  1. A LIFECYCLE FLAG. `probe.sending` is set once when the flows come up and
//     cleared once when the run ends, so a pool whose every sender had broken on
//     a socket error read as a healthy one for the rest of the deadline.
//
//  2. A CUMULATIVE TOTAL. "Bytes moved during this arm" is satisfied by a probe
//     that sends for one second and dies for the other 119. A cumulative
//     quantity can say that something HAPPENED and never that it was still
//     happening.
//
//  3. FRESHNESS AT THE END. Requiring the last byte to be recent catches the
//     arm that dies and stays dead — and passes `1 s of load · 117 s of nothing
//     · 2 s of load`, which is 98% solo and ends looking perfect. ⇒ 🎯 THE ONLY
//     QUANTITY THAT MEANS "THROUGHOUT" IS THE WORST GAP INSIDE THE WINDOW, and
//     it has to be watermarked from the arm's own start, not from the run's.
//
// 🚨 AND THE CLOCK IS MONOTONIC, NOT `Date()`. Wall time can step — NTP on a
// phone that has just joined a network is exactly the situation these runs are
// taken in — and a backward step yields a NEGATIVE idle that compares as fresh,
// turning a dead arm into a passing one; a forward step invents a stall in a
// healthy one. `DispatchTime.uptimeNanoseconds` cannot do either.
// *(User-caught, 2026-08-16.)*
//
// The clock is injectable so the gap arithmetic can be tested without sleeping:
// `tools/swiftcheck` drives it with a fake one.

import Foundation
import Dispatch

final class LoadProgress {
    /// Nanoseconds on a monotonic clock.
    typealias Clock = () -> UInt64

    static let monotonic: Clock = { DispatchTime.now().uptimeNanoseconds }

    private let lock = NSLock()
    private let now: Clock

    private var total: UInt64 = 0
    /// When the last non-zero delta landed. Zero means "not since the window
    /// opened", which is why the window's own start is the fallback reference.
    private var lastAdvanceNs: UInt64 = 0
    private var windowStartNs: UInt64 = 0
    private var worstGapNs: UInt64 = 0

    init(clock: @escaping Clock = LoadProgress.monotonic) {
        self.now = clock
    }

    /// A fresh run: everything, including the total, starts over.
    func reset() {
        lock.lock(); defer { lock.unlock() }
        total = 0
        lastAdvanceNs = 0
        windowStartNs = now()
        worstGapNs = 0
    }

    /// Open a new scoring window — an arm. The TOTAL is deliberately left alone
    /// (the caller takes differences of it), but the gap watermark restarts, or
    /// one arm's stall would condemn every arm after it.
    func openWindow() {
        lock.lock(); defer { lock.unlock() }
        windowStartNs = now()
        worstGapNs = 0
    }

    func advance(by delta: UInt64) {
        guard delta > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        let t = now()
        // A gap that began BEFORE this window is charged only from the window's
        // start: the part of it inside the arm is what this arm suffered.
        let since = max(lastAdvanceNs, windowStartNs)
        if t > since { worstGapNs = max(worstGapNs, t - since) }
        total &+= delta
        lastAdvanceNs = t
    }

    /// `worstGapMs` INCLUDES a gap that is still open at this instant, so it is
    /// never smaller than the current idle time — which is what lets one number
    /// carry the whole verdict.
    func snapshot() -> (bytes: UInt64, idleMs: Int, worstGapMs: Int) {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        let since = max(lastAdvanceNs, windowStartNs)
        let openGap = t > since ? t - since : 0
        let idle = lastAdvanceNs > 0 && t > lastAdvanceNs ? t - lastAdvanceNs : openGap
        return (total, ms(idle), ms(max(worstGapNs, openGap)))
    }

    private func ms(_ ns: UInt64) -> Int { Int(ns / 1_000_000) }
}
