// DiagnosticRunLock.swift
//
// ONE DIAGNOSTIC RUN AT A TIME, PROCESS-WIDE.
//
// 🚨 WHY THIS EXISTS, and it cost a device run. On 2026-08-15 the eight-arm
// paired A/B was started TWICE: the user tapped, the screen looked as if nothing
// had happened, and the second tap started a second runner **38 seconds behind
// the first**. Both drove the same tunnel — each with its own cwnd probe, so the
// paired arms carried **16 real flows instead of 8** — and the solo/paired
// windows of the two schedules overlapped, which is contamination no re-analysis
// can undo. (The chunk size survived only by luck: both instances follow the
// same schedule, so they always set the SAME K.)
//
// 🚨 WHY THE EXISTING GUARD COULD NOT STOP IT. Every runner has
// `guard !running else { return }` — but `running` is a property of the RUNNER
// OBJECT, and the second tap arrived on a DIFFERENT object. A view can be
// re-created for many reasons (a re-render, a pop and re-push, an @AppStorage
// write higher up); its `@StateObject` is then a fresh, idle runner, while the
// old one's background thread runs on. **A guard whose scope is one object
// cannot protect a resource that is process-wide** — and the tunnel is
// process-wide.
//
// So the lock lives here, outside every object and every view, and it names its
// holder so the refusal can say what is already running rather than just "no".
//
// ⚠️ Deliberately NOT re-entrant and deliberately NOT covering `UplinkCwndProbe`:
// the runners START the probe as part of their own run, so locking the probe
// would make every runner refuse itself. What must not overlap is one DIAGNOSTIC
// RUN with another, and that is exactly what this covers.

import Foundation

enum DiagnosticRunLock {
    private static let mutex = NSLock()
    private static var holder: String?

    /// Takes the lock for `who`, or returns nil if a run is already in progress —
    /// in which case the returned value is the name of the run that holds it, so
    /// the caller can say so.
    ///
    /// 🚨 Call this from `start()`, on the caller's thread, BEFORE dispatching
    /// any work: the race this closes is two taps a second apart, and a check
    /// made inside the background closure is already too late.
    static func acquire(_ who: String) -> Bool {
        mutex.lock()
        defer { mutex.unlock() }
        if holder != nil { return false }
        holder = who
        return true
    }

    /// Releases the lock if `who` holds it. Releasing from a run that does not
    /// hold it is a no-op rather than an error, so a `defer` on an early return
    /// path is always safe to write.
    static func release(_ who: String) {
        mutex.lock()
        defer { mutex.unlock() }
        if holder == who { holder = nil }
    }

    /// The run currently in progress, or nil. For the refusal message.
    static var current: String? {
        mutex.lock()
        defer { mutex.unlock() }
        return holder
    }
}
