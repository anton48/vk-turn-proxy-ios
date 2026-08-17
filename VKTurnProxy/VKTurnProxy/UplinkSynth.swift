// UplinkSynth.swift
//
// The PACED SYNTHETIC UPLINK — a diagnostic load generator that lives in the Go
// core (pkg/proxy/synth.go) and is armed by two undocumented backup-JSON fields,
// `uplinkSynthMbit` and `uplinkSynthSec`. It has no Settings entry and never
// had one: it exists so a run can hold a known offered load while the server
// counts what arrives.
//
// 🚨 WHAT THIS FILE IS FOR, AND IT IS NOT THE GENERATOR. It retires a stored
// value that no screen can show, for the same reason the pacer's own retirement
// exists:
// a key written during a measurement session outlives the session, and this one
// arms a generator that PUSHES TRAFFIC. A device left with `uplinkSynthMbit`
// set would send tens of Mbit/s of synthetic packets on every connect, on the
// user's own uplink and their own metered link, with nothing in the UI saying
// so — the chunking defect, but expensive rather than merely invisible.
//
// The value is cleared ONCE, so the documented way back in (import a backup
// carrying the field) still works for the next measurement. What is removed is
// the *inheritance* of a diagnostic setting into ordinary use.

import Foundation

enum UplinkSynth {
    static let mbitKey = "uplinkSynthMbit"
    static let secKey = "uplinkSynthSec"

    /// Runs the retirement exactly once, so a deliberate re-arm survives the next
    /// launch — the documented way back in is importing a backup that carries the
    /// field, and a retirement that ran every launch would undo it.
    static let clearedKey = "uplinkSynthStaleCleared"

    @discardableResult
    static func clearStaleValueOnce(in defaults: UserDefaults = .standard,
                                    log: ((String) -> Void)? = nil) -> Bool {
        guard !defaults.bool(forKey: clearedKey) else { return false }
        defaults.set(true, forKey: clearedKey)

        let mbit = defaults.double(forKey: mbitKey)
        let sec = defaults.integer(forKey: secKey)
        guard mbit > 0 || sec > 0 else { return false }

        defaults.removeObject(forKey: mbitKey)
        defaults.removeObject(forKey: secKey)
        log?("uplink-synth: 🚨 CLEARED a stale load generator left in UserDefaults "
            + "(\(mbitKey)=\(mbit) Mbit/s, \(secKey)=\(sec)s). It has no Settings entry, so it "
            + "would have kept generating synthetic uplink traffic on every connect with "
            + "nothing on screen saying so. Re-arm deliberately by importing a backup that "
            + "carries the field.")
        return true
    }
}
