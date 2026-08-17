// A standalone check for the app's dependency-free Swift invariants, compiled
// against the REAL source files rather than copies:
//
//   ./tools/swiftcheck/run.sh          (from the repository root)
//
// 🚨 THE COMMAND LIVES IN run.sh, NOT HERE. A compile line written into a comment
// goes stale the first time a section adds a source, and then the *documented* way
// to run the harness is broken while the harness itself is fine. One copy, and it
// is executable so it cannot drift silently.
//
// (the file is named main.swift because Swift allows top-level code in that one
// file only, and a multi-file compile rejects it anywhere else)
//
// 🚨 WHY IT IS NOT AN XCTest. The app has no test target, and adding one touches
// the scheme that `install.sh` and `release.sh` drive — not something to change in
// the middle of a measurement series. The types it asserts about depend on
// Foundation alone, so they compile standalone, and this file is the whole
// harness.
//
// WHAT IT GUARDS, and every one of these fails SILENTLY on a device:
//
//   • the two retirements of state that removed UIs left behind — each must fire,
//     must fire exactly ONCE (so the user's own later choice survives), must not
//     fire on a clean install, and must cover EVERY representation the diagnostic
//     builds wrote (the pacer had two: a Bool and a rate);
//   • the pacer's setting reads back as the one shipped rate, and OFF stays off;
//   • the two ENDS of the live-toggle message agree — a mismatch there is the
//     worst failure mode in the feature, because the toggle then does nothing on
//     a running tunnel and works perfectly after the next reconnect;
//   • the pacer's @AppStorage key is not observed by the navigation HOST, which
//     is how build 177 and issue #65 popped a pushed screen;
//   • EACH retirement is actually CALLED at launch, and ordered before the first
//     reader of its keys. Guarding the function and not its call site is the shape
//     that once bought a green suite and an empty log;
//   • the chunking machinery stays removed — it cannot coexist with a pacer that
//     reserves once per dequeue.

import Foundation

var failures = 0

func check(_ ok: Bool, _ what: String) {
    if ok {
        print("  ok   \(what)")
    } else {
        print("  FAIL \(what)")
        failures += 1
    }
}

func freshDefaults(_ name: String) -> UserDefaults {
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    return d
}

/// Reads a source file for the scanning sections. A missing file FAILS rather
/// than returning "" quietly: a guard that scans text passes vacuously the moment
/// the file it scans is renamed, and that is the failure mode these sections are
/// most exposed to.
func source(_ path: String) -> String {
    guard let s = try? String(contentsOfFile: path, encoding: .utf8) else {
        check(false, "reading \(path) — a scan over a missing file would pass vacuously")
        return ""
    }
    return s
}

print("UplinkPace — the production reset, and the shipped rate")

// 5. 🚨 TWO DIAGNOSTIC REPRESENTATIONS, NOT ONE. Builds 296-298 wrote the Bool
//    `uplinkPaceOn` (defaulting to ON for measurement) and 299-302 wrote RATES
//    into `uplinkPaceKiB` itself. Both must be zeroed, and neither may be carried
//    over: migrating either would make the shipped default a lie on exactly the
//    devices that took the measurements. *(The first port cleared only the Bool.)*
do {
    let d = freshDefaults("pacecheck.retired-on")
    d.set(true, forKey: UplinkPace.retiredBoolKey)

    var logged: [String] = []
    let fired = UplinkPace.resetToProductionDefaultOnce(in: d, log: { logged.append($0) })

    check(fired, "the retired test switch is cleared")
    check(d.object(forKey: UplinkPace.retiredBoolKey) == nil,
          "and it is REMOVED, so it cannot outlive its own meaning")
    check(UplinkPace.stored(in: d) == UplinkPace.off,
          "🚨 the pacer comes up OFF — the retired ON must NOT be carried into the new key")
    check(logged.count == 1, "the retirement is announced")
}

// 5b. 🚨 AND THE REPRESENTATION THE FIRST PORT MISSED: a device that ran the RATE
//     SWEEP (builds 299-302) has no Bool at all — it has 247/260/270 sitting in
//     the production key itself. Clearing only the Bool returns early there, and
//     `stored()` turns whatever is left into 247, so the one device that measured
//     the feature would enter production with the pacer ON.
do {
    let d = freshDefaults("pacecheck.sweep-rate")
    d.set(270, forKey: UplinkPace.key)          // left by the sweep; no Bool anywhere

    var logged: [String] = []
    let fired = UplinkPace.resetToProductionDefaultOnce(in: d, log: { logged.append($0) })

    check(fired, "a diagnostic RATE is reset even with no retired Bool present")
    check(UplinkPace.stored(in: d) == UplinkPace.off,
          "🚨 the sweep device comes up OFF — this is the case the first port shipped wrong")
    check(logged.count == 1 && logged[0].contains("270"),
          "and the reset names the rate it removed")
}

// 6. Once only, for the same reason as the chunk key: whatever the user chooses
//    afterwards has to survive the next launch.
do {
    let d = freshDefaults("pacecheck.once")
    d.set(true, forKey: UplinkPace.retiredBoolKey)
    _ = UplinkPace.resetToProductionDefaultOnce(in: d)

    d.set(UplinkPace.onKiB, forKey: UplinkPace.key) // the user turns it on
    check(!UplinkPace.resetToProductionDefaultOnce(in: d), "the retirement does not fire twice")
    check(UplinkPace.stored(in: d) == UplinkPace.onKiB, "and the user's own choice survives")
}

// 7. A clean install: nothing to clear, and OFF is the default that reaches the
//    tunnel.
do {
    let d = freshDefaults("pacecheck.clean")
    check(!UplinkPace.resetToProductionDefaultOnce(in: d), "nothing to clear on a clean install")
    check(UplinkPace.stored(in: d) == UplinkPace.off, "the pacer is OFF by default")
    check(!UplinkPace.isOn(in: d), "and isOn agrees with stored")
}

// 8. Any non-zero value means ON AT THE ONE SHIPPED RATE. The sweep measured 260
//    and 270 as strictly worse (0.486% and 0.898% loss against 247's 0.0046%), so
//    a backup carrying one of them — or a hand-edited number — must not put the
//    tunnel on a rate the app does not offer. And 1 must never survive as a rate:
//    1 KiB/s is what a Bool read through `integer(forKey:)` looks like, and it
//    would throttle the uplink to nothing while looking deliberate.
do {
    let d = freshDefaults("pacecheck.clamp")
    for raw in [1, 100, 247, 260, 270, 9999] {
        d.set(raw, forKey: UplinkPace.key)
        check(UplinkPace.stored(in: d) == UplinkPace.onKiB,
              "a stored \(raw) reads as the shipped \(UplinkPace.onKiB) KiB/s")
    }
    d.set(0, forKey: UplinkPace.key)
    check(UplinkPace.stored(in: d) == UplinkPace.off, "and 0 stays off")
}

print("UplinkSynth — the load generator with no screen")

// 9. The synthetic generator is armed only by two undocumented backup fields, so
//    a value left over from a measurement session would keep PUSHING traffic on
//    the user's own uplink with nothing on screen saying so.
do {
    let d = freshDefaults("synthcheck.stale")
    d.set(30.0, forKey: UplinkSynth.mbitKey)
    d.set(600, forKey: UplinkSynth.secKey)

    var logged: [String] = []
    let fired = UplinkSynth.clearStaleValueOnce(in: d, log: { logged.append($0) })

    check(fired, "a stale load generator is cleared")
    check(d.object(forKey: UplinkSynth.mbitKey) == nil && d.object(forKey: UplinkSynth.secKey) == nil,
          "BOTH keys go — a rate without a duration still arms it")
    check(logged.count == 1 && logged[0].contains("30"),
          "the retirement is announced and names what it removed")

    let d2 = freshDefaults("synthcheck.clean")
    check(!UplinkSynth.clearStaleValueOnce(in: d2), "nothing to clear on a clean install")
}

print("The live-toggle message — both ends of it")

// 10. 🚨 THE WORST FAILURE MODE IN THE FEATURE, and the one no unit test can
//     reach: `TunnelManager` and `PacketTunnelProvider` are different PROCESSES
//     and do not compile together. If the sender's format and the receiver's
//     parser disagree, the toggle silently does nothing on a running tunnel —
//     and then works perfectly at the next reconnect, because the same value also
//     rides ProxyConfig. That reads as "it works, sometimes", which is the
//     hardest kind of report to act on.
//
//     So this is a source scan, deliberately, and it is scoped as tightly as the
//     property allows: the prefix must appear on both sides, and the number of
//     comma-separated fields the sender writes must equal the number the receiver
//     requires.
do {
    let tm = source("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    let pt = source("VKTurnProxy/PacketTunnel/PacketTunnelProvider.swift")
    let marker = "\"set_uplink_pace:"

    // The sender's literal, from the opening quote to the closing one.
    func literalAfter(_ m: String, in s: String) -> String? {
        guard let r = s.range(of: m) else { return nil }
        var out = ""
        var i = r.upperBound
        while i < s.endIndex {
            if s[i] == "\"" { return out }
            out.append(s[i])
            i = s.index(after: i)
        }
        return nil
    }

    // Commas OUTSIDE `\( … )` are the field separators; commas inside an
    // interpolation belong to Swift, not to the wire format.
    func fieldCount(_ lit: String) -> Int {
        var plain = ""
        var depth = 0
        var i = lit.startIndex
        while i < lit.endIndex {
            let next = lit.index(after: i)
            if lit[i] == "\\", next < lit.endIndex, lit[next] == "(" {
                depth += 1
                i = lit.index(i, offsetBy: 2)
                continue
            }
            if depth > 0 {
                if lit[i] == "(" { depth += 1 }
                if lit[i] == ")" { depth -= 1 }
                i = next
                continue
            }
            plain.append(lit[i])
            i = next
        }
        return plain.filter { $0 == "," }.count + 1
    }

    guard let sent = literalAfter(marker, in: tm) else {
        check(false, "TunnelManager no longer sends a set_uplink_pace: message")
        exit(1)
    }
    guard let recvRange = pt.range(of: "set_uplink_pace:") else {
        check(false, "PacketTunnelProvider no longer handles set_uplink_pace:")
        exit(1)
    }
    let window = String(pt[recvRange.upperBound...].prefix(1200))
    guard let cr = window.range(of: "parts.count == "),
          let expected = Int(window[cr.upperBound...].prefix(while: { $0.isNumber })) else {
        check(false, "the receiver no longer states how many fields it requires")
        exit(1)
    }

    check(fieldCount(sent) == expected,
          "both ends agree on \(expected) fields (the sender writes \(fieldCount(sent)))")
    check(window.contains("guard") && window.contains("return"),
          "a malformed message is refused rather than half-applied")
}

print("The SwiftUI pop rule, and the launch-time calls")

// 11. 🚨 THE KEY MUST NOT BE OBSERVED BY THE NAVIGATION HOST. ContentView hosts
//     the NavigationView, so any @AppStorage it declares re-renders it on write —
//     and re-rendering the host tears down whatever is pushed. That is the exact
//     cause of build 177 and GitHub #65, and an unused declaration still counts,
//     because @AppStorage subscribes whether or not the value is read.
do {
    let advanced = source("VKTurnProxy/VKTurnProxy/AdvancedView.swift")
    let content = source("VKTurnProxy/VKTurnProxy/ContentView.swift")

    check(advanced.contains("@AppStorage(UplinkPace.key)"),
          "the pacer's key is declared on the pushed screen that owns the switch")
    check(!content.contains("UplinkPace.key") && !content.contains("uplinkPaceKiB"),
          "🚨 and NOT in ContentView, which hosts the NavigationView")
}

// 12. 🚨 THE RETIREMENTS MUST BE CALLED, AT LAUNCH, AND **EACH** OF THEM MUST BE
//     ORDERED — the first version of this section compared only the FIRST call
//     against the reader, so moving either of the others below it left the suite
//     green while the commit message claimed otherwise. A loop over the calls that
//     checks only existence is not a check on order. *(User-caught, 2026-08-17.)*
do {
    let app = source("VKTurnProxy/VKTurnProxy/VKTurnProxyApp.swift")
    guard let store = app.range(of: "_ = ServerStore.shared") else {
        check(false, "could not locate the launch sequence to order the retirements against")
        exit(1)
    }
    for call in ["UplinkPace.resetToProductionDefaultOnce",
                 "UplinkSynth.clearStaleValueOnce"] {
        guard let r = app.range(of: call) else {
            check(false, "\(call) is called at launch")
            continue
        }
        check(r.lowerBound < store.lowerBound,
              "\(call) runs BEFORE anything that reads its keys")
    }
}

// 13. 🚫 THE CHUNKING MACHINERY MUST STAY REMOVED ON THE SWIFT SIDE TOO. It was
//     deleted because packets 2..K of a chunk were written after a SINGLE pace
//     reservation, so the bucket metered one packet in K while reporting ENGAGED.
//     The Go guard covers the core; this one covers the config the app builds.
do {
    let tm = source("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    check(!tm.contains("uplink_chunk_k") && !tm.contains("UplinkChunk"),
          "the app no longer sends a chunk size to the tunnel")
    check(!FileManager.default.fileExists(atPath: "VKTurnProxy/VKTurnProxy/UplinkChunk.swift"),
          "and UplinkChunk.swift is gone rather than dormant")
}

print("")
if failures == 0 {
    print("swiftcheck: all checks passed")
    exit(0)
}
print("swiftcheck: \(failures) FAILED")
exit(1)
