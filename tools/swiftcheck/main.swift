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
//     reserves once per dequeue;
//   • the live-toggle bookkeeping: an intent is outstanding before it is sent, a
//     LATE acknowledgement cannot clear a newer one, silence is not success, and
//     the retry is bounded. The delivery itself needs a live
//     NETunnelProviderSession and cannot be tested — so everything decidable
//     without one was moved into a value type that can be.

import Foundation
import NetworkExtension

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

/// `source()` with `//` line comments removed.
///
/// 🚨 A source scan that reads PROSE tests the documentation, not the code —
/// this project has had a guard go red on a correct tree for exactly that
/// reason. Section 38 scans for the strict `String(contentsOf` call, and the
/// comment explaining why that call was removed names it, so the scan has to
/// see the code alone.
/// ⚠️ Naive by design: it also cuts inside a string literal containing `//`
/// (a URL, say). None of the scans below depend on one.
func codeWithoutComments(_ path: String) -> String {
    source(path)
        .split(separator: "\n", omittingEmptySubsequences: false)
        .map { line -> String in
            if let r = line.range(of: "//") { return String(line[line.startIndex..<r.lowerBound]) }
            return String(line)
        }
        .joined(separator: "\n")
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

print("UplinkPaceSync — the delivery bookkeeping")

// 14. A fresh app has nothing outstanding, and an intent makes it outstanding
//     IMMEDIATELY — before any send. The first version set its flag only when a
//     send FAILED, so a completion that never arrived left nothing to retry.
//
//     SABOTAGE SEEN TO FAIL: make `intend()` not bump the revision. Compiles;
//     the intent is then never pending and no retry can fire.
do {
    var s = UplinkPaceSync()
    check(!s.isPending, "a fresh sync has nothing outstanding")
    s.intend()
    check(s.isPending, "an intent is outstanding the moment it is made, before any send")
    _ = s.willSend()
    check(s.isPending, "🚨 and SENDING does not clear it — only an acknowledgement does")
}

// 15a. 🚨🚨 THE MONOTONIC ACKNOWLEDGEMENT, AND THE FIRST VERSION OF THIS TEST DID
//      NOT DEFEND IT. It ran ack(rev1) while rev2 was outstanding and asserted
//      "still pending" — which stays true under the sabotage it NAMED (dropping
//      the `revision > acknowledgedRevision` comparison leaves acked = 1 < 2), so
//      the guard was green on the broken code and I reported a different, stronger
//      sabotage as validating it. *(User-caught, 2026-08-17.)*
//
//      The property is that the mark never ROLLS BACK: acknowledge the newest
//      revision, then let the stale reply for an older one arrive.
//
//      SABOTAGE SEEN TO FAIL: drop the `revision > acknowledgedRevision` half of
//      the guard in `acknowledge`, exactly as written. Compiles; the late reply
//      then moves the mark backwards and re-opens a delivered intent.
do {
    var s = UplinkPaceSync()
    let rev1 = s.intend()
    _ = s.willSend()
    let rev2 = s.intend()
    _ = s.willSend()

    s.acknowledge(revision: rev2, ok: true)          // the newest intent lands
    check(!s.isPending, "the newest revision clears the intent")

    s.acknowledge(revision: rev1, ok: true)          // ...and rev1 finally answers
    check(s.acknowledgedRevision == rev2,
          "🚨 a late ok for rev \(rev1) must not roll the mark back from rev \(rev2)")
    check(!s.isPending,
          "🚨 and it must not re-open a delivery that already happened")
}

// 15b. THE OTHER HALF OF THE SAME RACE: while a NEWER intent is outstanding — its
//      own send having failed — a stale ok for the older one must not report
//      everything delivered. This is the sequence the first test used, kept
//      because it catches a different shortcut.
//
//      SABOTAGE SEEN TO FAIL: `acknowledgedRevision = desiredRevision` on any ok.
//      Compiles; the stale reply then clears the newer intent.
do {
    var s = UplinkPaceSync()
    let rev1 = s.intend()
    _ = s.willSend()
    let rev2 = s.intend()
    _ = s.willSend()                                  // this attempt fails, silently

    s.acknowledge(revision: rev1, ok: true)
    check(s.isPending,
          "🚨 a late ok for rev \(rev1) leaves rev \(rev2) outstanding — the extension "
          + "is still on the old value")
    s.acknowledge(revision: rev2, ok: true)
    check(!s.isPending, "and the reply for the newest revision does clear it")
}

// 16. Only an explicit `ok` counts. A refusal, or a reply that is not `ok`, must
//     leave the intent outstanding rather than being read as delivery.
do {
    var s = UplinkPaceSync()
    let rev = s.intend()
    _ = s.willSend()
    s.acknowledge(revision: rev, ok: false)
    check(s.isPending, "a refusal leaves the intent outstanding")
}

// 17. The retry is BOUNDED, because it runs on a timer for as long as the tunnel
//     is up: an unbounded one would spin forever against an extension that is
//     never going to answer. A NEW intent starts the budget again.
do {
    var s = UplinkPaceSync()
    s.intend()
    for _ in 0..<UplinkPaceSync.maxAttempts { _ = s.willSend() }
    check(!s.canRetry, "the attempts for one intent are bounded")
    check(s.isPending, "...and giving up does not pretend the value was delivered")
    s.intend()
    check(s.canRetry, "a new intent gets a fresh budget")
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

// 17b. 🚨 AND THE BOOKKEEPING IS WORTH NOTHING IF NOBODY DRIVES IT. Two call
//      sites decide whether an outstanding intent is ever delivered, and BOTH
//      were missing in the first version: the cold-attach block (the only place
//      that sees a tunnel this app did not start — `NEVPNStatusDidChange` fires
//      on FUTURE transitions only) and the `.connected` branch of the
//      notification. A source scan, because neither can run without a live
//      NETunnelProviderSession.
//
//      SABOTAGE SEEN TO FAIL: delete the re-assert from the attach block.
//      Compiles; a tunnel started by another build then keeps its old pace while
//      Settings shows the new one.
do {
    let tm = source("VKTurnProxy/VKTurnProxy/TunnelManager.swift")

    if let call = tm.range(of: "applyUplinkPaceFromSettings()\n        default:") {
        // The states the attach re-assert covers sit just above the call.
        let lead = String(tm[..<call.lowerBound].suffix(220))
        for state in [".connected", ".connecting", ".reasserting"] {
            check(lead.contains(state),
                  "🚨 the attach re-assert covers \(state) — an app relaunched while the old "
                  + "tunnel is still coming up would otherwise create no intent at all")
        }
    } else {
        check(false, "the cold-attach re-assert is gone — nothing reconciles a running tunnel")
    }

    if let transition = tm.range(of: "case .connected:") {
        let window = String(tm[transition.upperBound...].prefix(2500))
        check(window.contains("flushPendingUplinkPace()"),
              "and an outstanding intent is flushed on the .connected transition")
    } else {
        check(false, "the .connected branch is gone")
    }

    check(tm.contains("scheduleUplinkPaceRetry"),
          "a timer retries a delivery whose completion never arrives — silence is not success")
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

print("DirectRouteSync — one apply at a time, last intent wins")

// 18. 🚨🚨 THE DEFECT THIS TYPE EXISTS FOR, AND IT IS THE ONE A FLAG CANNOT SEE.
//     Build 308-309 kept a single `routesAreDirect` Bool, read at the top of the
//     applier and written in its completion. Everything between is a window in
//     which the flag still reads the OLD value, so an OFF arriving while ON is in
//     flight compared false != false, called itself a no-op, and returned — then
//     ON completed and the routes were DIRECT while the profile and the switch
//     both said OFF, with nothing left to reconcile them.
//
//     SABOTAGE SEEN TO FAIL: make `finish` return nil instead of
//     `startIfNeeded()`. Compiles, and it is the OLD CODE EXACTLY — the
//     completion writes the state it finished with and nothing reconciles what
//     arrived meanwhile — so the queued OFF is never applied and the machine
//     settles at ON with the profile saying OFF.
//
//     ⚠️ AND THE SABOTAGE I FIRST WROTE HERE DOES NOT REDDEN THIS SECTION: with
//     the `guard inFlight == nil` dropped, `intend(false)` still returns nil
//     because at that instant `desired == applied == false`, so every assertion
//     below stays green. That guard is what section 19 tests; this one tests the
//     completion. Two properties, two sabotages — a section validated by the
//     wrong one is a section validated by nothing. *(Caught by running it.)*
do {
    var s = DirectRouteSync(applied: false)

    let first = s.intend(true)
    check(first == true, "an intent on an idle machine starts that apply")

    let second = s.intend(false)
    check(second == nil, "a flip WHILE ONE IS IN FLIGHT starts nothing…")
    check(s.desired == false, "…but is recorded as the desired state")
    check(s.inFlight == true, "and the running apply is still the old one")

    let queued = s.finish(ok: true)
    check(queued == false, "🚨 the LATE completion hands the queued flip straight on")
    check(s.applied == true, "the routes are momentarily what the finished apply left")

    check(s.finish(ok: true) == nil, "and when that one lands there is nothing owed")
    check(s.applied == false && s.isSettled,
          "🚨 ON in flight → OFF → late ON completion ends at OFF, which is the whole point")
}

// 19. 🚨 ONE TAP, TWO PATHS, ONE APPLY. DIRECT is delivered by KVO on the profile
//     AND by the `set_direct:` message, which normally carry the SAME state. With
//     the old flag both passed the guard while the first apply was in flight, so a
//     single toggle started two concurrent `setTunnelNetworkSettings`.
//
//     SABOTAGE SEEN TO FAIL: the same one as above — dropping the in-flight guard
//     makes the second path return `true` here instead of nil.
do {
    var s = DirectRouteSync(applied: false)
    check(s.intend(true) == true, "the first path starts the apply")
    check(s.intend(true) == nil, "🚨 the second path with the SAME state starts nothing")
    check(s.finish(ok: true) == nil, "and the single completion settles it")
    check(s.applied == true && s.isSettled, "routes DIRECT, nothing outstanding")
}

// 20. A FAILED APPLY MUST NOT MOVE `applied`, must be retried, and the retry must
//     be BOUNDED — the retry is self-driving (a completion starts the next apply),
//     so an unbounded one would spin for the life of the session against a
//     provider that will never accept the settings.
//
//     SABOTAGE SEEN TO FAIL: set `applied = value` unconditionally in `finish`
//     (drop the `if ok`). Compiles; the machine then believes a failed apply
//     worked, settles immediately, and reports DIRECT to the app.
do {
    var s = DirectRouteSync(applied: false)

    // Count the applies the machine actually STARTS, driving it exactly as the
    // provider does: `intend` returns the first, every `finish` returns the next.
    // ⚠️ The first version of this loop counted them by hand and was one short —
    // my arithmetic, not the code's, which is why the expectation prints the
    // value it got. (Same slip as build 284's; the fix is the same.)
    var started = 0
    var next = s.intend(true)
    while next != nil {
        started += 1
        check(s.applied == false, "🚨 a FAILED apply never moves `applied`")
        next = s.finish(ok: false)
    }

    check(started == DirectRouteSync.maxAttempts,
          "a failing apply is retried and STOPS at maxAttempts "
          + "(\(DirectRouteSync.maxAttempts)); started \(started)")
    check(s.isStuck, "🚨 and it SAYS it is stuck — the old code failed silently")
    check(!s.isSettled, "a stuck machine is not a settled one")
    check(s.desired == true && s.applied == false,
          "the intent stays unmet rather than being forgotten")

    check(s.intend(true) == true, "a fresh intent gets a fresh budget")
}

// 21. THE STATE THE APP IS TOLD IS `applied`, NEVER `desired`. The whole reason
//     the reply carries a value at all is that build 309 answered "ok" for the
//     attempt and the app then displayed the profile it had just written.
do {
    var s = DirectRouteSync(applied: false)
    _ = s.intend(true)
    check(s.desired == true && s.applied == false,
          "🚨 mid-flight the two disagree, and only `applied` describes the routes")
    _ = s.finish(ok: false)
    check(s.applied == false, "a failure keeps them disagreeing rather than papering over it")
}

// 22. 🚨 THE STARTUP MODE IS A CONSTRUCTOR ARGUMENT, NOT A SECOND APPLY. iOS can
//     restart the extension alone, and 309 then applied FULL routes, declared the
//     tunnel ready and re-applied DIRECT — a second ~420 ms
//     `setTunnelNetworkSettings`, a window of tunnelled traffic the user believed
//     was going around, and a fresh chance for the TUN fd to move.
do {
    var s = DirectRouteSync(applied: true)
    check(s.isSettled && s.applied == true,
          "a tunnel that came up DIRECT is already settled — nothing to apply")
    check(s.intend(true) == nil, "and the profile agreeing with it starts no apply at all")
    check(s.intend(false) == false, "while a genuine change still does")
}

// 23. THE PROVIDER'S REPLY IS PARSED STRICTLY BY THE APP — an unreadable answer is
//     NOT a confirmation, because "no answer" and "yes" must never be the same
//     thing. Mirrors TunnelManager.parseDirectReply.
do {
    check(DirectRouteSync.parseReply("direct=1") == true, "a bare reply parses")
    check(DirectRouteSync.parseReply("direct=0 want=0 busy=0") == false,
          "and so does the get_direct form with extra fields")
    check(DirectRouteSync.parseReply("direct=1 want=0 busy=1") == true,
          "the APPLIED field is the one read, not want")
    check(DirectRouteSync.parseReply("ok") == nil, "🚨 the old 'ok' reply is not a state")
    check(DirectRouteSync.parseReply("") == nil && DirectRouteSync.parseReply(nil) == nil,
          "and silence is not a state either")
    check(DirectRouteSync.parseReply("direct=yes") == nil, "a malformed value is refused, not guessed")
}

// 24. 🚨 AN UNCONFIRMED ROUTING CHANGE MUST REACH THE SCREEN, AND ONLY A
//     CONFIRMATION MAY CLEAR IT. This is the two-part-hookup trap: a `@Published`
//     nobody renders is a green suite and a silent failure, and the dangerous
//     half is ON → OFF, where an unconfirmed result leaves traffic possibly
//     outside a tunnel the UI says is carrying it.
//
//     FOUR SABOTAGES, EACH RUN AND EACH REDDENING EXACTLY ONE CHECK:
//       a. delete the `if let problem = tunnel.directModeError` row from
//          AdvancedView — the state survives and nothing renders it;
//       b. write the save failure to `errorMessage` again;
//       c. drop `guard !direct else { return }` — an unconfirmed ON would then
//          reconnect too, which ends the DIRECT the user just asked for;
//       d. replace the `switchAndReconnect` call — an unconfirmed OFF would be
//          reported and left alone, which is the leak this section exists for.
//     ⚠️ The comment first named a fifth that reddens NOTHING ("clear
//     directModeError in the .silent branch"): no check here reads that branch.
//     Predicting a sabotage is not running one — see the twelfth instance in
//     feedback_tests_must_be_seen_to_fail.
do {
    let adv = source("VKTurnProxy/VKTurnProxy/AdvancedView.swift")
    let tm = source("VKTurnProxy/VKTurnProxy/TunnelManager.swift")

    check(adv.contains("tunnel.directModeError"),
          "🚨 the DIRECT switch RENDERS its own error — a @Published nobody shows is not a report")
    check(tm.contains("@Published private(set) var directModeError"),
          "and routing has its OWN error field, not the shared errorMessage")
    check(!tm.contains("errorMessage = \"Could not switch routing"),
          "🚨 routing failures no longer write to the shared errorMessage, which unrelated flows clear")

    // The reconnect fallback exists and is reached only for the unsafe direction.
    let fn = tm.range(of: "private func directChangeUnconfirmed")
    check(fn != nil, "the unconfirmed-change handler exists")
    let body = fn.map { String(tm[$0.lowerBound...].prefix(1400)) } ?? ""
    check(body.contains("guard !direct else { return }"),
          "🚨 an unconfirmed ON is left to the user — it cannot leak, and a reconnect would end DIRECT")
    check(body.contains("switchAndReconnect"),
          "🚨 but an unconfirmed OFF REBUILDS the tunnel — the only repair that cannot itself be unconfirmed")
}

// ─────────────────────────────────────────────────────────────────────────────
// 25. THE RESULT IS RENDERED FROM THE RUN, NOT FROM THE SCREEN'S CONTROLS.
//
//     The knobs are @AppStorage bindings that keep living after Run is pressed,
//     so a finished result rendered from them changes when the user touches a
//     picker. Concretely: a download-only run grew an "Upload 0.0 Mbit/s" row on
//     a tap that measured nothing.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. render `if direction != "upload"` in SpeedTestResultView instead of
//          `run.ranDownload`;
//       b. delete `startedRun` from the runner — the view then has nothing to
//          render from and falls back to the bindings.
do {
    let result = source("VKTurnProxy/VKTurnProxy/SpeedTestResultView.swift")
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")
    let view = source("VKTurnProxy/VKTurnProxy/SpeedTestView.swift")

    check(runner.contains("private(set) var startedRun: SpeedTestRunConfig?"),
          "🚨 the runner records the config the run STARTED with")
    check(result.contains("run.ranDownload") && result.contains("run.ranUpload"),
          "🚨 the result picks its rows from the RUN, not from the live Direction binding")
    check(!result.contains("@AppStorage"),
          "🚨 the result view owns no live bindings at all")
    check(view.contains("SpeedTestResultView(run:"),
          "and the screen passes the recorded run into it")

    // The parameters are history once a run starts.
    let cfg = SpeedTestRunConfig(serverID: "1", serverLabel: "x", threads: 8,
                                 direction: "download", durationSec: 15)
    check(cfg.ranDownload && !cfg.ranUpload,
          "a download-only run reports one direction, whatever the picker says later")
}

// ─────────────────────────────────────────────────────────────────────────────
// 26. THE PATH LABEL DESCRIBES THE WHOLE RUN, NOT ITS FIRST INSTANT.
//
//     DIRECT is a LIVE route switch (~420 ms) and the runner deliberately
//     outlives the screen, so a run can span two paths. Reading the path once at
//     start records something that may simply not be true of the bytes measured
//     — and the old code did exactly that under a comment arguing for it.
//
//     SABOTAGES RUN:
//       a. `isAttributable` returning `true` unconditionally — the "changed"
//          check goes red, the single-path one stays green;
//       b. `record` appending unconditionally — a stable run reports a change.
do {
    check(SpeedTestPath.current(connected: false, directMode: false) == .vpnOff,
          "no tunnel ⇒ VPN off")
    check(SpeedTestPath.current(connected: true, directMode: false) == .throughVPN,
          "connected, not DIRECT ⇒ through the tunnel")
    check(SpeedTestPath.current(connected: true, directMode: true) == .directMode,
          "🚨 DIRECT is labelled, never refused — measuring without the tunnel is the arm users want")

    var stable = SpeedTestPathTrace(.throughVPN)
    stable.record(.throughVPN)
    stable.record(.throughVPN)
    check(stable.isAttributable && stable.label == SpeedTestPath.throughVPN.rawValue,
          "a run that stayed put is attributable and says so plainly")

    var moved = SpeedTestPathTrace(.throughVPN)
    moved.record(.directMode)
    check(!moved.isAttributable,
          "🚨 a run whose route changed is NOT attributable to either path")
    check(moved.label.contains("CHANGED"),
          "🚨 and the result says so instead of picking one of them")

    var andBack = SpeedTestPathTrace(.throughVPN)
    andBack.record(.directMode)
    andBack.record(.throughVPN)
    check(andBack.seen.count == 3,
          "returning to the first path is two changes, not zero — the run still spanned both")
}

// ─────────────────────────────────────────────────────────────────────────────
// 27. THE SERVER LIST IS DESCRIBED BY THE PATH IT WAS FETCHED ON.
//
//     Ookla builds the list from the apparent IP, so it is "near your exit" with
//     the tunnel up and "near you" with it down. The header used to be computed
//     from the LIVE tunnel state while the rows were whatever had been fetched
//     earlier — so after a switch it confidently described a neighbourhood the
//     rows did not come from. A header that lies is worse than none.
//
//     SABOTAGES RUN:
//       a. `header(now:)` ignoring `fetchedOn` and branching on `now` — the
//          stale-header check reddens, the fresh one stays green;
//       b. `staleNotice` returning nil always.
do {
    let picker = source("VKTurnProxy/VKTurnProxy/SpeedTestServerPicker.swift")
    let list = SpeedTestServerList(servers: [], fetchedOn: .throughVPN)

    check(list.header(now: .throughVPN) == "Servers near your EXIT",
          "a fresh list names the exit's neighbourhood")
    check(list.header(now: .vpnOff).contains("before the route changed"),
          "a stale list says so")
    // 🚨 THE DISCRIMINATING CASE, and the reason this check exists at all: the
    // rows were fetched through the tunnel, we are now looking at them with the
    // tunnel off, and the header must still describe THE ROWS — near the EXIT —
    // not where the device is now. An earlier version of this section only
    // asserted the "before the route changed" suffix, which comes from isStale;
    // it stayed GREEN when header() was rewired to branch on `now`.
    check(list.header(now: .vpnOff).contains("near your EXIT"),
          "🚨 a stale header describes the ROWS' neighbourhood, not the current one")
    check(SpeedTestServerList(servers: [], fetchedOn: .vpnOff)
            .header(now: .throughVPN).contains("near you")
          && !SpeedTestServerList(servers: [], fetchedOn: .vpnOff)
            .header(now: .throughVPN).contains("EXIT"),
          "🚨 and the same the other way round — a list fetched off-VPN never claims the exit")
    check(list.staleNotice(now: .vpnOff) != nil && list.staleNotice(now: .throughVPN) == nil,
          "the notice appears only when the rows and the route disagree")
    check(list.staleNotice(now: .vpnOff)?.contains("pinned server is unaffected") == true,
          "🚨 and it does NOT clear the pin — pinning one id across tunnel states is the " +
          "only thing that makes a VPN-on/off pair comparable")
    check(picker.contains("runner.serverList?.header(now: livePath)"),
          "🚨 the picker asks the LIST for its header instead of computing one from the live state")
}

// ─────────────────────────────────────────────────────────────────────────────
// 28. 🚨 THE Go↔Swift WIRE CONTRACT, WHICH FAILS ASYMMETRICALLY.
//
//     A field Go sends and Swift ignores is silent and harmless. A non-Optional
//     Swift CodingKey for a field Go does NOT send is FATAL: the synthesized
//     decoder throws, and the screen sits at "running" for ever.
//
//     So this checks BOTH directions over the Go source of truth.
//
//     SABOTAGES RUN:
//       a. remove `window_sec` from the Swift CodingKeys — "decoded by Swift"
//          reddens;
//       b. add a bogus `case ghost = "ghost"` key — "sent by Go" reddens.
do {
    let goSrc = source("pkg/speedtest/speedtest.go")
    // 🚨 The Swift wire types moved to their own file so the harness could
    // COMPILE them; a scan still pointed at the runner would find no CodingKeys
    // and report every Go field as undecoded — on a correct tree. Read both.
    let swiftSrc = source("VKTurnProxy/VKTurnProxy/SpeedTestWire.swift")
        + source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    // Every `json:"name"` tag inside one Go struct. Plain scanning, no regex
    // literals: a `"` cannot appear inside one.
    func goTags(after marker: String) -> Set<String> {
        guard let start = goSrc.range(of: marker) else {
            check(false, "🚨 anchor \(marker) missing from the Go source — every check below would be vacuous")
            return []
        }
        var body = String(goSrc[start.upperBound...])
        if let close = body.range(of: "\n}\n") { body = String(body[..<close.lowerBound]) }
        var out = Set<String>()
        for piece in body.components(separatedBy: "json:\"").dropFirst() {
            let tag = piece.prefix { $0 != "\"" && $0 != "," }
            if !tag.isEmpty { out.insert(String(tag)) }
        }
        return out
    }

    let phaseTags = goTags(after: "type Phase struct")
    let progressTags = goTags(after: "type Progress struct")
    check(phaseTags.count > 8 && progressTags.count > 8,
          "the Go structs were parsed (\(phaseTags.count) phase, \(progressTags.count) progress fields)")

    // Every wire name Swift will accept: the renamed `case x = "y"` form plus the
    // bare `case a, b, c` form, where the property name IS the wire name.
    var swiftKeys = Set<String>()
    for line in swiftSrc.components(separatedBy: "\n") {
        let t = line.trimmingCharacters(in: CharacterSet.whitespaces)
        guard t.hasPrefix("case ") else { continue }
        let rest = String(t.dropFirst(5))
        if let eq = rest.range(of: "= \"") {
            let name = rest[eq.upperBound...].prefix { $0 != "\"" }
            swiftKeys.insert(String(name))
        } else {
            for name in rest.components(separatedBy: ",") {
                let n = name.trimmingCharacters(in: CharacterSet.whitespaces)
                if !n.isEmpty && !n.contains(" ") { swiftKeys.insert(n) }
            }
        }
    }
    check(swiftKeys.count > 15, "the Swift CodingKeys were parsed (\(swiftKeys.count) keys)")

    // Every field Go sends must be decoded — otherwise it silently never reaches
    // the screen, which is how warmup_sec was shipped and then dropped.
    let goAll = phaseTags.union(progressTags)
    let undecoded = goAll.subtracting(swiftKeys)
    check(undecoded.isEmpty,
          "🚨 every field Go sends is decoded by Swift (missing: \(undecoded.sorted()))")

    // And nothing Swift insists on may be absent from Go.
    let unknown = swiftKeys.subtracting(goAll)
    check(unknown.isEmpty,
          "🚨 Swift decodes nothing Go does not send — a key Go dropped throws and freezes the screen (extra: \(unknown.sorted()))")
}

// ─────────────────────────────────────────────────────────────────────────────
// 29. THE SPEED TEST'S KEYS ARE NOT OBSERVED BY THE NAVIGATION HOST.
//
//     An unused @AppStorage is still SUBSCRIBED, so declaring one of these in
//     ContentView — which hosts the NavigationView — makes any write tear down
//     whatever is pushed. That is the build-177/issue-65 pop trap.
do {
    let content = source("VKTurnProxy/VKTurnProxy/ContentView.swift")
    check(!content.contains("speedTest"),
          "🚨 no speedTest @AppStorage key is declared in the NavigationView host")
    check(content.contains("SpeedTestView(tunnel: tunnel)"),
          "and the screen is reached from MainNavigationLinks, which does not observe the tunnel")
}

// ─────────────────────────────────────────────────────────────────────────────
// 30. A POLL THAT CANNOT BE READ MUST SAY SO, NOT FREEZE.
//
//     The decode used to be `try?` with a bare `return`: a wire mismatch left the
//     screen on its last value, the 2 Hz timer never invalidated and the Run
//     button never came back. Killing the app was the only way out.
do {
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")
    check(!runner.contains("try? JSONDecoder().decode(SpeedTestProgress.self"),
          "🚨 the progress decode is not silently discarded")
    check(runner.contains("stopPolling()"),
          "and there is one place that stops the timer")
    let poll = runner.range(of: "private func poll()")
    let body = poll.map { String(runner[$0.lowerBound...].prefix(1400)) } ?? ""
    check(body.contains("catch"),
          "🚨 a decode failure is caught")
    check(body.contains("built from different versions"),
          "🚨 and reported as what it is — the app and the engine disagreeing about the wire")
}

// ─────────────────────────────────────────────────────────────────────────────
// 31. AUTOMATIC SERVER SELECTION IS ANNOUNCED, AND IT SHOUTS ONLY WHEN IT MOVED.
//
//     Ookla selects from the apparent IP. Three runs on an unchanged path,
//     minutes apart, picked 31309 / 31309 / 69521 — so the obvious use of this
//     screen, pressing Run twice and comparing, can silently compare two
//     different servers.
//
//     🚫 It deliberately does NOT warn on every automatic run: `auto` is the
//     default, most people will never pin anything, and painting every result
//     orange teaches them that orange means nothing. The loud case is the one
//     that actually cost them a comparison.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. `isWarning` returning true for `.automatic` — the "quiet" check goes
//          red, the moved one stays green;
//       b. `of(...)` ignoring `pinnedID` — the pinned check goes red;
//       c. dropping the `previous != ranOn` comparison — the moved check goes red.
do {
    let result = source("VKTurnProxy/VKTurnProxy/SpeedTestResultView.swift")

    // A pinned run is comparable by construction and says nothing.
    let pinned = SpeedTestServerChoice.of(pinnedID: "31309", ranOn: "31309", previous: "69521")
    check(pinned == .pinned && pinned.note == nil && !pinned.isWarning,
          "a pinned server produces no note at all — nothing about it is surprising")

    // First automatic run: a quiet note, not a warning.
    let first = SpeedTestServerChoice.of(pinnedID: "", ranOn: "31309", previous: nil)
    check(first == .automatic && first.note != nil && !first.isWarning,
          "🚫 the first automatic run explains itself QUIETLY — orange on every run trains " +
          "people to ignore orange")

    // Automatic, same server as before: still quiet.
    let steady = SpeedTestServerChoice.of(pinnedID: "", ranOn: "31309", previous: "31309")
    check(steady == .automatic && !steady.isWarning,
          "automatic selection that stayed put is not a problem and is not reported as one")

    // Automatic, and it MOVED — the case that cost a comparison.
    let moved = SpeedTestServerChoice.of(pinnedID: "", ranOn: "69521", previous: "31309")
    check(moved == .automaticMoved(from: "31309", to: "69521"),
          "🚨 a moved automatic selection is recognised as such")
    check(moved.isWarning,
          "🚨 and it is the ONE case that warns — two runs on different servers are not comparable")
    check(moved.note?.contains("31309") == true && moved.note?.contains("69521") == true,
          "the warning names both servers, so the user can see what changed")

    // A run that never reached a server must not become a baseline.
    let noServer = SpeedTestServerChoice.of(pinnedID: "", ranOn: "", previous: "31309")
    check(!noServer.isWarning,
          "a run that selected no server at all does not accuse the next one of moving")

    check(result.contains("previousServerID"),
          "the result view is given the previous run's server — without it 'moved' is unanswerable")
    check(result.contains("serverChoice.isWarning"),
          "🚨 and it renders the two cases differently, which is the whole point of the split")

    // 🚨 The engine string names the METHODOLOGY; only the app build names the
    // BINARY. Two builds can share every number in the engine string, so a
    // result without this cannot be traced to the code that produced it.
    check(result.contains("app build"),
          "🚨 the result carries the app build, not only the engine version")
    check(result.contains("CFBundleVersion"),
          "and it reads it from the bundle rather than duplicating a constant")
}

// ─────────────────────────────────────────────────────────────────────────────
// 32. THE BASELINE IS THE LAST SUCCESSFUL *AUTOMATIC* RUN, AND A REFUSED START
//     IS NOT A RESULT.
//
//     Two false readings were live:
//       - a PINNED run set the baseline, so pin 31309 → unpin → run auto → the
//         screen accused automatic selection of moving when the USER had moved
//         the pin;
//       - a run that errored or was stopped set it too, though it produced
//         nothing to compare against.
//
//     And a refused start faked a `progress` with state "error". The result
//     section renders only when `startedRun` is set, so on the FIRST attempt
//     that error appeared nowhere at all — the button did nothing — and once a
//     previous run existed it rendered inside THAT run's section.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. drop `wasAutomatic` from updatesBaseline — the pinned check reddens;
//       b. accept state "error" as well — the stopped-run check reddens;
//       c. set `progress` instead of `refusal` on a start failure — the runner
//          scan reddens.
do {
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    check(SpeedTestServerChoice.updatesBaseline(state: "done", wasAutomatic: true, ranOn: "31309"),
          "a successful automatic run becomes the baseline")
    check(!SpeedTestServerChoice.updatesBaseline(state: "done", wasAutomatic: false, ranOn: "31309"),
          "🚨 a PINNED run does not — the user moving their own pin is not automatic selection moving")
    check(!SpeedTestServerChoice.updatesBaseline(state: "error", wasAutomatic: true, ranOn: "31309"),
          "🚨 a stopped or failed run does not — it produced nothing to compare against")
    check(!SpeedTestServerChoice.updatesBaseline(state: "done", wasAutomatic: true, ranOn: ""),
          "and a run that never reached a server has no id to offer")

    // A refused start must reach the user through `refusal`, not through a
    // fabricated result.
    check(runner.contains("refusal = startError"),
          "🚨 a start failure is reported as a REFUSAL, which is rendered whether or not a " +
          "previous run exists")
    check(!runner.contains("p.error = startError"),
          "🚨 and it no longer fabricates a progress object, which the result section either " +
          "hides entirely or attributes to the PREVIOUS run")
    check(runner.contains("lastAutomaticServerID"),
          "the baseline is named for what it holds")
}

// ─────────────────────────────────────────────────────────────────────────────
// 33. THE PICKER CAN REACH A SERVER THE NEARBY LIST DOES NOT CONTAIN.
//
//     The nearby list is built from the APPARENT IP. Measured: a user in Funchal
//     was placed by Ookla at [40.851, -8.399] on the mainland, so the list held
//     Lisbon servers 249 km from nobody and NOT the server in their own city —
//     the one with sub-millisecond latency. No amount of local filtering reaches
//     it; `search=` on Ookla's own endpoint does, and so does an id.
//
//     And the distance shown is Ookla's estimate from that same wrong place: the
//     Funchal server read 1186 km via search and 975 km via id. Latency is the
//     measured one, so it leads.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. `proximity` printing latency even when it is 0 — the unknown check;
//       b. drop the "est." from the distance — the labelling check;
//       c. remove the searchServers call from the picker — the reach check.
do {
    let picker = source("VKTurnProxy/VKTurnProxy/SpeedTestServerPicker.swift")
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    let measured = SpeedTestServer(id: "31551", name: "Funchal", sponsor: "MEO",
                                   country: "Portugal", host: "h:8080",
                                   distanceKm: 1186, latencyMs: 0.8)
    // 🚨 THIS CHECK USED TO ACCEPT "0 ms" — the exact rendering that later turned
    // out to be the defect: a real 0.3 ms printed as 0 and became
    // indistinguishable from "not measured". An assertion loose enough to pass
    // on the broken output is not a guard. It now demands the VALUE.
    check(measured.proximity.contains("0.8 ms"),
          "🚨 a sub-millisecond latency is shown WITH its decimal, not rounded to 0 ms")
    check(SpeedTestServer(id: "1", name: "n", sponsor: "s", country: "c", host: "h",
                          distanceKm: 10, latencyMs: 24).proximity.contains("24 ms"),
          "and an ordinary latency keeps whole milliseconds")
    check(measured.proximity.contains("est."),
          "🚨 and the distance is labelled an ESTIMATE — Ookla computes it from where it " +
          "believes you are, which was measured wrong by 1186 km")

    // A lookup by id performs no ping, so there is no latency to show.
    let byID = SpeedTestServer(id: "31551", name: "Funchal", sponsor: "MEO",
                               country: "Portugal", host: "h:8080",
                               distanceKm: 975, latencyMs: 0)
    check(!byID.proximity.contains("ms"),
          "🚨 an unmeasured latency is OMITTED, never printed as 0 ms — that would read as " +
          "sub-millisecond, which is exactly the value this server really has and would be " +
          "true by accident")

    check(runner.contains("wgSpeedtestFindServers"),
          "🚨 the runner can ask OOKLA, not only filter the rows it holds")
    check(picker.contains("runner.searchServers(query)"),
          "🚨 and the picker offers it — otherwise a server outside the nearby list is " +
          "unreachable however it is spelled")
    check(picker.contains("NOT necessarily near you"),
          "search results are kept apart from the nearby list and say so")
}

// ─────────────────────────────────────────────────────────────────────────────
// 34. THE SEARCH HAS ITS OWN STATE, AND IT IS ONE VALUE.
//
//     Three defects, all from splitting one thing into several:
//       - the search shared serversLoading/serversError with the nearby list, so
//         a failed search blanked a perfectly good list and offered a "Try
//         again" that retried the OTHER operation;
//       - query and results were separate @Published properties, so from the
//         start of a new search until it finished the OLD results were shown
//         under the NEW heading;
//       - a late completion could resurrect results after Clear search.
//
//     The state type makes a mismatched query UNREPRESENTABLE — a result carries
//     the query it answers — and a generation counter makes a stale completion
//     unapplicable.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. give `.results` no query — the pairing check stops compiling, so
//          instead: make `query` return nil for `.results`;
//       b. drop the generation bump from clearSearch;
//       c. write serversError from the search path again.
do {
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")
    let picker = source("VKTurnProxy/VKTurnProxy/SpeedTestServerPicker.swift")

    // A result cannot exist apart from the query it answers.
    let found = SpeedTestSearchState.results(
        query: "Funchal",
        list: SpeedTestServerList(servers: [], fetchedOn: .throughVPN))
    check(found.query == "Funchal",
          "🚨 results carry the query they answer — the heading cannot describe another search")
    check(SpeedTestSearchState.searching(query: "Funchal").isSearching,
          "a search in flight is distinguishable from one that finished")
    check(SpeedTestSearchState.idle.query == nil,
          "idle is about no query at all")
    check(SpeedTestSearchState.failed(query: "x", message: "boom").query == "x",
          "a failure names the query that failed, so 'Search again' retries THAT one")

    check(runner.contains("searchGeneration"),
          "🚨 a generation counter exists — otherwise a slow search resurrects itself after Clear")
    check(runner.contains("generation == self.searchGeneration"),
          "🚨 and the completion is DROPPED unless it is the current one")
    let clear = runner.range(of: "func clearSearch()")
    let clearBody = clear.map { String(runner[$0.lowerBound...].prefix(220)) } ?? ""
    check(clearBody.contains("searchGeneration += 1"),
          "🚨 clearing bumps it too — a search in flight when the user clears must not come back")

    // The two operations do not share their failure channel.
    // Scoped to searchServers: loadServers legitimately writes serversError, and
    // an unscoped scan would just be asserting that the nearby list has no error
    // path at all.
    let fn = runner.range(of: "func searchServers(")
    let searchBody = fn.map { String(runner[$0.lowerBound...].prefix(2000)) } ?? ""
    check(!searchBody.isEmpty, "searchServers was found — otherwise the check below is vacuous")
    check(!searchBody.contains("serversError"),
          "🚨 the search does not write the NEARBY list's error, which would blank a good list")
    check(!searchBody.contains("serversLoading"),
          "🚨 nor its loading flag, which would hide the list behind the wrong spinner")
    // Fragment only: the source contains a string interpolation, which cannot be
    // written literally here without becoming one.
    check(picker.contains("Search for ") && picker.contains("failed:"),
          "and the search reports its own failure, naming its own query")
    check(picker.contains("runner.searchServers(query)"),
          "🚨 'Search again' retries the SEARCH, not the nearby-list fetch")
}

// ─────────────────────────────────────────────────────────────────────────────
// 35. A LATENCY BELONGS TO THE PATH IT WAS MEASURED ON.
//
//     Latency is now the number the picker leads with and tells people to choose
//     by — which makes it the number that most needs a path. A search run
//     through the tunnel kept showing its latencies after a switch to DIRECT,
//     where they describe a route no longer in use.
//
//     🎯 The search reuses SpeedTestServerList rather than growing its own
//     staleness rule: a second copy of a rule is how two copies drift apart, and
//     this project has paid for that more than once.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. latencyNotice ignoring isStale — the fresh-path check;
//       b. it returning a notice even with no measured latencies — the
//          nothing-to-warn-about check;
//       c. searchServers capturing the path at COMPLETION instead of at start —
//          not scannable, so it is stated in the comment there and left to
//          review.
do {
    let picker = source("VKTurnProxy/VKTurnProxy/SpeedTestServerPicker.swift")
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    let measured = SpeedTestServer(id: "31551", name: "Funchal", sponsor: "MEO",
                                   country: "Portugal", host: "h", distanceKm: 1186,
                                   latencyMs: 5.6)
    let onVPN = SpeedTestServerList(servers: [measured], fetchedOn: .throughVPN)

    check(onVPN.latencyNotice(now: .throughVPN) == nil,
          "on the same route the latencies stand and nothing is said")
    check(onVPN.latencyNotice(now: .directMode) != nil,
          "🚨 after the route changes the latencies are disclaimed — they describe the old path")
    check(onVPN.latencyNotice(now: .directMode)?.contains("Through VPN") == true,
          "and the notice names the route they WERE measured on")

    // Nothing measured, nothing to disclaim.
    let unmeasured = SpeedTestServer(id: "1", name: "n", sponsor: "s", country: "c",
                                     host: "h", distanceKm: 10, latencyMs: 0)
    check(SpeedTestServerList(servers: [unmeasured], fetchedOn: .throughVPN)
            .latencyNotice(now: .vpnOff) == nil,
          "a list with no measured latency says nothing about latency")

    // 🚨 ONE GUARD FOR BOTH FETCHES. Go allows one activity at a time; this side
    // used two separate flags and could start both, whereupon Go's `busy:`
    // refusal replaced a perfectly good nearby list with an error this side had
    // caused. The two are triggered from different places, so only a shared
    // predicate keeps them apart.
    //
    // Sabotage run: restore `guard !serversLoading` in loadServers — the first
    // check reddens, the second stays green.
    check(runner.contains("var isFetchingServers: Bool { serversLoading || search.isSearching }"),
          "🚨 one predicate covers the nearby fetch AND the search")
    let loadFn = runner.range(of: "func loadServers()")
    let loadBody = loadFn.map { String(runner[$0.lowerBound...].prefix(400)) } ?? ""
    check(loadBody.contains("guard !isFetchingServers"),
          "🚨 and the nearby fetch takes it — otherwise it starts on top of a running search")
    let searchFn = runner.range(of: "func searchServers(")
    let searchGuard = searchFn.map { String(runner[$0.lowerBound...].prefix(300)) } ?? ""
    check(searchGuard.contains("!isFetchingServers"),
          "as does the search")

    check(runner.contains("let fetchedOn = Self.currentPath()"),
          "🚨 the search records the path at the START — recording it at completion would " +
          "stamp results with the route the user had already switched to")
    check(picker.contains("list.latencyNotice(now: livePath)"),
          "🚨 and the SEARCH results carry the notice too, not only the nearby list")
}

// ─────────────────────────────────────────────────────────────────────────────
// 36. DIRECT FROM THE LIVE ACTIVITY (build 326).
//
//     The point of the button is to step around the VPN for one site and back
//     without opening the app, Settings and Advanced — and without tearing the
//     tunnel down, which is what makes DIRECT worth having at all.
//
//     Four things have to hold, and each has a recorded reason:
//       - the field is OPTIONAL on the wire. A card started by an older build
//         is decoded by the NEW widget; a non-Optional Bool throws .keyNotFound
//         and breaks a card nobody can refresh until the app next runs. This is
//         the same trap as compactClock and as the ServerProfile wipe.
//       - a routing change PUSHES the card. Nothing else does: a DIRECT flip
//         does not move the tunnel's status, which is what sync() is driven by,
//         so without this the card would claim traffic is tunnelled while it is
//         not.
//       - the intent is AWAITED in the handler. perform() ends and the app is
//         suspended; an un-awaited change would leave the card stale.
//       - THREE buttons, never four. The island's expanded .bottom region
//         silently CLIPS the rest — a fourth would not fail to build, it would
//         simply not be there.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. make `direct` non-Optional in ContentState;
//       b. drop the refreshNow() call from refreshDirectMode;
//       c. drop the `await` in the .setDirect handler.
do {
    let attrs = source("VKTurnProxy/VKTurnProxy/VPNActivityAttributes.swift")
    let intents = source("VKTurnProxy/VKTurnProxy/LiveActivityIntents.swift")
    let controller = source("VKTurnProxy/VKTurnProxy/LiveActivityController.swift")
    let tunnel = source("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    let widget = source("VKTurnProxy/VKTurnProxyWidget/VPNLiveActivity.swift")

    check(attrs.contains("var direct: Bool?"),
          "🚨 the routing state on the wire is OPTIONAL — a non-Optional Bool breaks every card " +
          "started by an older build, and no one can refresh it")
    check(intents.contains("case setDirect(Bool)") && intents.contains("struct SetDirectIntent"),
          "the action and its intent exist")
    // 🚨 SCOPED TO THE CASE BODY, AND IT CHECKS FOR THE ESCAPE TOO. A first
    // version asserted only that the string "await ...setDirectMode" appeared
    // anywhere — which `Task { await ... }` satisfies perfectly, and that is
    // exactly the defect: a Task detaches the work from perform(), the app is
    // suspended, and the change may never finish. The sabotage passed. Third
    // time today an assertion of mine was loose enough to accept the thing it
    // was written to forbid.
    let caseStart = controller.range(of: "case .setDirect(let direct):")
    let caseBody = caseStart.map { String(controller[$0.lowerBound...].prefix(1400)) } ?? ""
    check(!caseBody.isEmpty, "the .setDirect case was found — otherwise the checks below are vacuous")
    check(caseBody.contains("await TunnelManager.shared.setDirectMode"),
          "🚨 the handler AWAITS the change — perform() ends and the app is suspended, so an " +
          "un-awaited flip leaves the card describing the old routing")
    check(!caseBody.contains("Task {"),
          "🚨 and it does not hand the work to a detached Task, which outlives perform() only " +
          "by luck — the app is suspended the moment it returns")

    // 🚨 EVERY SURFACE NAMES ITSELF IN THE LOG. Both reach one function and used
    // to write identical lines, so a round trip verified from a log could not be
    // told apart from the Advanced switch being flipped twice — and a failure
    // that only happens from the CARD would not say so. The parameter is
    // REQUIRED rather than defaulted: a default is what a new call site forgets.
    check(tunnel.contains("from source: DirectChangeSource"),
          "🚨 the routing change carries WHERE it was asked from")
    // Fragment only: the real line contains a string interpolation, which cannot
    // be written literally here without becoming one — and `source` is this
    // harness's own file-reading function, so it compiles into nonsense.
    check(tunnel.contains("[asked from "),
          "and that reaches the log line, not only the call site")
    check(controller.contains("from: .liveActivity"),
          "the card declares itself")
    check(source("VKTurnProxy/VKTurnProxy/AdvancedView.swift").contains("from: .advancedSwitch"),
          "and so does the Advanced switch")

    // 🚨 AWAITING THE WORK AND DETACHING ITS LAST STEP IS NOT AWAITING. The
    // routing change was awaited and the card update handed to a Task, so
    // perform() returned and the app was suspended with the publish possibly
    // never happening — the operation succeeds and the user sees no evidence.
    check(caseBody.contains("await refreshNowAndWait()"),
          "🚨 the handler waits for the CARD too, not only the routing change")
    check(controller.contains("await publishInFlight?.value"),
          "and that wait reaches ActivityKit's own update, which is the detached part")

    // 🚨 A reconnect passes through .disconnected, on which the card is ENDED —
    // unrecoverably, while the app is in the background. The DIRECT repair
    // reconnects precisely when a card is on screen showing routing, and it did
    // not hold it. The hold belongs INSIDE switchAndReconnect: a guard every
    // caller must remember is one the next caller forgets.
    check(controller.contains("func holdThroughReconnect()"),
          "the card can be held across a deliberate reconnect")
    // 🚨 The body is taken up to the NEXT method, not as a fixed prefix. It used
    // to be `.prefix(900)`, and adding three lines near the top pushed the anchor
    // out of the window — a guard that goes red because something ELSE was
    // inserted is one people learn to silence.
    let switchFn = tunnel.range(of: "func switchAndReconnect(")
    let switchBody: String = switchFn.map { r in
        let rest = String(tunnel[r.upperBound...])
        if let end = rest.range(of: "\n    func ") { return String(rest[..<end.lowerBound]) }
        return rest
    } ?? ""
    check(switchBody.contains("holdThroughReconnect()"),
          "🚨 and switchAndReconnect holds it ITSELF, so every caller is covered — including " +
          "the DIRECT repair, which was not")

    // The line that reports a possible leak is the one that most needs a source.
    let unconfirmed = tunnel.range(of: "an unconfirmed return to the tunnel may be a LEAK")
    let leakLine = unconfirmed.map { String(tunnel[$0.lowerBound...].prefix(400)) } ?? ""
    check(leakLine.contains("[asked from "),
          "🚨 the LEAK warning names where the change was asked from — the Live Activity path " +
          "is both the likeliest and the one running on borrowed time")

    // 🚨 THE EXTENSION'S CONFIRMATION BEATS THE PROFILE. refreshDirectMode
    // derives the state from the SAVED profile, which holds what was REQUESTED —
    // so after a confirmed mismatch the card's button offered to undo a change
    // that demonstrably had not happened, when what the user needs is to retry
    // it. Build 310's finding (the profile treated as the applied state) on a
    // surface that did not exist then.
    let mismatch = tunnel.range(of: "case .applied(let actual):")
    let mismatchBody = mismatch.map { String(tunnel[$0.lowerBound...].prefix(1400)) } ?? ""
    check(!mismatchBody.isEmpty, "the mismatch branch was found — otherwise the check below is vacuous")
    check(mismatchBody.contains("adoptDirectMode(actual)"),
          "🚨 a confirmed mismatch adopts what the EXTENSION reports, not what the profile asked for")

    // 🚨 ONE WRITER, AND IT PUSHES. `directMode` is @Published, so the SwiftUI
    // switch follows any assignment for free while the Live Activity — another
    // process — only learns through an explicit push. A correction written
    // straight into the property therefore fixed the switch and left the CARD
    // wrong, and only a change that had come FROM the card got a push after it.
    // Two surfaces where one updates itself is how the other gets forgotten.
    // Assignments only — the declaration `var directMode = false` is not one, and
    // counting it made this check fail on a correct tree the first time it ran.
    let writes = tunnel.components(separatedBy: "\n").filter {
        $0.contains("directMode = ") && !$0.contains("var directMode")
    }.count
    check(writes == 1,
          "🚨 `directMode` is assigned in exactly ONE place, found \(writes) — every write must " +
          "go through adoptDirectMode or a surface is left behind")
    let adopt = tunnel.range(of: "private func adoptDirectMode(")
    let adoptBody = adopt.map { String(tunnel[$0.lowerBound...].prefix(400)) } ?? ""
    check(adoptBody.contains("refreshNow()"),
          "🚨 and that one place pushes the card, so the correction reaches BOTH surfaces " +
          "however the change was started")

    // 🚨 PUBLISHES ARE CHAINED. Overwriting the handle let two race, so an older
    // state could land last — and awaiting the newest handle returned while the
    // older Task was still pending, which made the wait prove nothing.
    check(controller.contains("await previous?.value"),
          "🚨 each publish waits for the one before it, so ActivityKit gets them in order")

    // A log that names the wrong cause is worse than one that names none.
    check(tunnel.contains("enum ReconnectReason"),
          "a reconnect declares why it is happening")
    check(!tunnel.contains("live-activity: switch →"),
          "🚨 and no longer claims the Live Activity did it — the routing repair reconnects " +
          "from the Advanced switch too, with no card involved")
    check(controller.contains("state.direct = TunnelManager.shared.directMode"),
          "the app reads it and puts it on the wire — the widget is another process and " +
          "shares no App Group")

    // The push moved out of refreshDirectMode and into the single writer, so this
    // asks what it actually means: a routing change reaches the card. Checking
    // the old location would now fail on a correct tree — which it did.
    let refresh = tunnel.range(of: "func refreshDirectMode()")
    let refreshBody = refresh.map { String(tunnel[$0.lowerBound...].prefix(400)) } ?? ""
    check(refreshBody.contains("adoptDirectMode("),
          "🚨 a routing change goes through the single writer, which is what pushes the card — " +
          "the tunnel's status does not move on a DIRECT flip, so nothing else would")

    // Rule (b) of the widget's own header: three buttons, and the region clips
    // the rest in silence.
    let controls = widget.range(of: "private func controls(")
    let controlsBody = controls.map { String(widget[$0.lowerBound...].prefix(2200)) } ?? ""
    check(!controlsBody.isEmpty, "the control row was found — otherwise the count below is vacuous")
    let buttons = controlsBody.components(separatedBy: "Button(intent:").count - 1
    check(buttons == 3,
          "🚨 exactly THREE buttons in the row, found \(buttons) — the island's expanded .bottom " +
          "region silently CLIPS anything after the third, so a fourth is invisible rather than broken")
    check(widget.contains("context.state.direct ?? false"),
          "🚨 and the widget reads the Optional with a TUNNELLED default — never claiming the " +
          "kill switch is off when the card predates the field")
}

// ─────────────────────────────────────────────────────────────────────────────
// 37. THE SPEED TEST WRITES ITS RUN TO THE LOG.
//
//     🎯 These lines exist to REPLACE A SCREENSHOT, which is the bar they have
//     to clear: everything the result screen shows, plus the two things it
//     cannot — the app build and the engine's methodology revisions. A number
//     without those cannot be compared with a number from another week, which is
//     the entire reason both identifiers exist.
//
//     SABOTAGES RUN, each reddening exactly one check:
//       a. drop the warnings from the phase line;
//       b. print `path.seen[0]` instead of `path.label` — a changed route then
//          claims one of the two;
//       c. log the result only, not the parameters at START.
do {
    let runner = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    let run = SpeedTestRunConfig(serverID: "31551", serverLabel: "MEO · Funchal",
                                 threads: 32, direction: "both", durationSec: 15)

    let started = SpeedTestLog.start(run, research: true, path: .vpnOff, build: "331")
    for want in ["threads=32", "direction=both", "duration=15s", "31551", "build=331"] {
        check(started.contains(want), "the START line carries \(want)")
    }
    // 🚨 The engine's `mode` arrives only WITH THE RESULT, so for a run that
    // hangs or never reports this is the only record of which methodology was
    // asked for — a fixed window or an early stop, which are not comparable.
    check(started.contains("research=true"),
          "🚨 START records the REQUESTED research mode, which no later line can supply")

    // 🚨 Remote text in a one-line, quote-delimited format. A newline in a
    // sponsor name splits a record; a quote closes a field early. Both produce a
    // log that PARSES and says something that never happened.
    let nasty = "MEO \"pwn\"\nspeedtest: DONE server=0 ping=0ms\u{0007}  x"
    let cleaned = SpeedTestLog.clean(nasty)
    check(!cleaned.contains("\n") && !cleaned.contains("\u{0007}"),
          "🚨 newlines and control characters are stripped — one of them forges a whole line")
    check(!cleaned.contains("\""),
          "🚨 and quotes cannot close a field early")
    check(SpeedTestLog.clean(String(repeating: "x", count: 400)).count <= 120,
          "an unbounded remote string cannot flood the line")

    // 🚨 A STRUCTURAL GUARD, NOT A LIST OF FIELDS. Checking the fields I happen
    // to remember is how the ERROR line kept its raw interpolation through three
    // reviews of this file: every other one was converted and that one, on the
    // path nobody exercises when things work, was not. This finds ANY value
    // interpolated into a log string without going through clean().
    //
    // Numeric fields do not appear here at all — they go through
    // String(format:) — so an interpolation of a stored property is by
    // construction a string, and a string in this file is remote until proven
    // otherwise.
    let logSrc = source("VKTurnProxy/VKTurnProxy/SpeedTestLog.swift")
    // The exemptions are a "prove it is not remote" list, and each one carries
    // its reason — so a new interpolation must be CLASSIFIED rather than
    // silently inherit somebody's memory.
    let notRemote: Set<String> = [
        "run.threads", "run.durationSec", "threads",   // Int, from the UI's own pickers
        "p.connsUsed", "p.dials",                      // Int, counted locally
        "p.consistent", "research",                    // Bool
        "path.rawValue", "path.label",                 // our own enum text, never Ookla's
        "server",                                      // already built from clean() above
    ]
    var raw: [String] = []
    for piece in logSrc.components(separatedBy: "\\(").dropFirst() {
        let expr = String(piece.prefix(while: { $0 != ")" && $0 != "\n" }))
        if expr.hasPrefix("clean(") || notRemote.contains(expr) { continue }
        raw.append(expr)
    }
    check(raw.isEmpty,
          "🚨 every interpolated value in a log line goes through clean() — these do not: \(raw)")

    var progress = SpeedTestProgress()
    progress.serverID = "31551"
    progress.serverDesc = "MEO · Funchal"
    progress.pingMs = 4
    progress.engine = "speedtest-go v1.7.11+fork.5 / vkturn-method.5"
    progress.estimator = "EWMA5"
    progress.ooklaSeesISP = "MEO"
    var down = SpeedTestPhase()
    down.rawMbps = 312.8; down.libraryMbps = 296.2; down.actualSec = 12.3
    down.windowSec = 12.3; down.bytes = 480_100_000; down.connsUsed = 32; down.dials = 31
    down.windowBytes = 480_100_000
    down.consistent = true
    down.warnings = ["only 87% of uploaded bytes were confirmed by the server"]
    progress.download = down

    let lines = SpeedTestLog.result(run, progress: progress,
                                    path: SpeedTestPathTrace(.vpnOff))
    let all = lines.joined(separator: "\n")

    // 🚨 The rate covers the WINDOW; `bytes` covers the whole phase. In research
    // mode they differ, and a reader checking bytes/window against raw on a
    // CORRECT line would conclude the tool is lying. Log what the rate came from.
    var research = SpeedTestPhase()
    research.rawMbps = 16.0; research.actualSec = 20; research.windowSec = 15
    research.warmupSec = 5; research.bytes = 40_000_000; research.windowBytes = 30_000_000
    let researchLine = SpeedTestLog.result(run, progress: {
        var p = SpeedTestProgress(); p.download = research; return p
    }(), path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(researchLine.contains("window-bytes=30.0MB"),
          "🚨 the line reports the bytes the RATE was computed from")
    check(researchLine.contains("phase-bytes=40.0MB"),
          "and the phase total beside it, so neither number has to be guessed")

    // 🚨 EVERY FIGURE ON THE LINE SHARES ONE SCOPE — the window — with
    // phase-bytes the single marked exception. The confirmed ratio must be
    // derivable from the two byte figures printed next to it, or a correct line
    // fails the arithmetic it invites.
    var scoped = SpeedTestPhase()
    scoped.rawMbps = 100; scoped.windowSec = 15; scoped.actualSec = 20; scoped.warmupSec = 5
    scoped.bytes = 1_000_000_000; scoped.windowBytes = 600_000_000
    scoped.backlogBytes = 5_000_000; scoped.confirmedRatio = 600.0 / 605.0
    scoped.confirmedKnown = true
    let scopedLine = SpeedTestLog.result(run, progress: {
        var p = SpeedTestProgress(); p.upload = scoped; return p
    }(), path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(scopedLine.contains("confirmed=99.2%") && scopedLine.contains("backlog=5.0MB"),
          "🚨 confirmed and backlog are the WINDOW's, so 600/(600+5) is what the line's own " +
          "byte figures give — a phase-scoped ratio would read 97.6% beside them")

    check(all.contains("312.8") && all.contains("296.2"),
          "🚨 BOTH figures are logged — they answer different questions and disagreeing is normal")
    check(all.contains("conns=32/31"),
          "🚨 and the connection count, which is what says whether the thread count meant flows")
    check(all.contains("only 87%"),
          "🚨 WARNINGS are logged — a log kept to replace a screenshot that dropped them would " +
          "be strictly worse than the screenshot")
    check(all.contains("window=12.3s") && all.contains("actual=12.3s"),
          "both durations, so a reader can tell which window the rate covers")
    check(all.contains("EWMA5") || SpeedTestProgress().estimator.isEmpty,
          "the estimator is logged when the engine reports one")
    check(all.contains("vkturn-method.5"),
          "🚨 the methodology revisions travel with the number — without them two runs weeks " +
          "apart cannot be compared at all")

    // A run whose route changed must not be logged as belonging to one of them.
    var moved = SpeedTestPathTrace(.throughVPN)
    moved.record(.directMode)
    let movedLines = SpeedTestLog.result(run, progress: progress, path: moved).joined(separator: "\n")
    check(movedLines.contains("CHANGED"),
          "🚨 a run whose route moved is logged as belonging to NEITHER path — printing one " +
          "would invent an attribution the screen itself refuses to make")

    // An empty result produces nothing rather than a line of zeros.
    check(SpeedTestLog.result(run, progress: SpeedTestProgress(),
                              path: SpeedTestPathTrace(.vpnOff)).isEmpty,
          "a run that produced no phase logs nothing, not a row of zeros")

    // 🚨 A log kept so runs can be compared, which drops the line saying two of
    // them CANNOT be, invites exactly the comparison it should prevent.
    let movedChoice = SpeedTestServerChoice.automaticMoved(from: "31309", to: "60452")
    let withWarning = SpeedTestLog.result(run, progress: progress,
                                          path: SpeedTestPathTrace(.vpnOff),
                                          serverChoice: movedChoice).joined(separator: "\n")
    check(withWarning.contains("31309") && withWarning.contains("60452"),
          "🚨 a moved automatic selection is logged, naming both servers")

    check(runner.contains("speedtest: ERROR"),
          "🚨 a decode failure is LOGGED — it is the one failure where no result line ever runs, " +
          "so without it the log ends at START and never says why")

    check(runner.contains("SpeedTestLog.start("),
          "🚨 the parameters are logged at START — a run that is stopped or fails still has to " +
          "leave them behind, and those are the runs someone returns to the log for")
    check(runner.contains("SpeedTestLog.result("),
          "and the result is logged when the run reaches a terminal state")
}


print("SharedLogger — one bad byte must not cost the whole log")

// 38. 🚨 THE READER MUST DEGRADE ONE CHARACTER AT A TIME.
//     On 2026-08-20 the Logs screen reported "(log is empty — waiting for new
//     activity)" over an 829 072-byte file — across app restarts and
//     disconnect/reconnect, for the length of a whole VPN sweep — because the
//     reader threw the ENTIRE file away on the first invalid byte and turned
//     the failure into "". Share exported the empty text with it, so the log
//     could not be taken off the device either.
//
//     The behavioural checks run over the PURE decode rule (extracted for that
//     reason: inline in a file read, reaching it needed an App Group container
//     and a corrupted file on disk). The scans keep the strict form from
//     coming back, and keep the WRITER from re-introducing the corruption.
do {
    // ~800 KB of good lines with ONE invalid byte in the middle. The
    // assertions demand the FIRST and the LAST line, so a decode that stops at
    // the bad byte — the actual defect — cannot pass by returning a non-empty
    // prefix. An assertion loose enough to accept the defect is not a guard.
    var good = Data()
    for i in 0..<20_000 {
        good.append(Data("[2026-08-20 17:00:00.000] [App] line \(i)\n".utf8))
    }
    var corrupt = good
    corrupt.insert(0xFF, at: corrupt.count / 2)

    let dirty = SharedLogger.decode(archive: Data(), current: corrupt)
    check(dirty.text.contains("[App] line 0\n"),
          "🚨 the text BEFORE the invalid byte survives")
    check(dirty.text.contains("[App] line 19999\n"),
          "🚨 and the text AFTER it — the whole file, not a prefix")
    check(dirty.repairedSequences == 1,
          "the invalid sequence is COUNTED, so the screen can say a writer clobbered a line")
    check(dirty.bytesOnDisk == corrupt.count,
          "bytesOnDisk counts BYTES — the same quantity the empty-log diagnostic prints")

    let clean = SharedLogger.decode(archive: Data(), current: good)
    check(clean.repairedSequences == 0,
          "🚨 a clean file reports ZERO repairs — a counter that always fires says nothing")
    check(clean.text.hasPrefix("[2026-08-20") && clean.text.hasSuffix("line 19999\n"),
          "and decodes unchanged end to end")

    let both = SharedLogger.decode(archive: Data("[archive] older\n".utf8),
                                   current: Data("[current] newer\n".utf8))
    check(both.text == "[archive] older\n[current] newer\n",
          "the archive is decoded separately and comes FIRST — one chronological stream")

    let logger = codeWithoutComments("VKTurnProxy/VKTurnProxy/SharedLogger.swift")
    check(!logger.contains("String(contentsOf"),
          "🚨 no strict String(contentsOf:) survives in SharedLogger — that one call traded "
          + "829 KB of log for an empty screen")
    check(logger.contains("O_APPEND"),
          "🚨 appendData opens the file with O_APPEND")
    check(!logger.contains("seekToEndOfFile"),
          "🚨 and does NOT seek-then-write: the extension appends to this same file, so a stale "
          + "offset OVERWRITES the line it just wrote — losing it silently, and leaving an "
          + "invalid sequence whenever the clobber lands inside a multi-byte character")

    let logs = codeWithoutComments("VKTurnProxy/VKTurnProxy/ContentView.swift")
    check(logs.contains("readSnapshot()"),
          "the Logs screen reads the snapshot, so it can tell 'nothing written' from 'nothing read'")
    check(logs.contains("repairedSequences > 0"),
          "🚨 and RENDERS the repair count — a lone U+FFFD in the text reads as a font problem")
    check(logs.contains("status.currentBytes > 0"),
          "🚨 the empty-log headline is conditioned on the byte count: it may not call the log "
          + "EMPTY over a file that holds bytes, which is the sentence that hid this for a sweep")

    // 🚨 ITEM 4 OF THE REVIEW: the repair count must come from the BYTES.
    // Counting U+FFFD in the decoded text cannot tell a sequence we repaired
    // from one that belongs there — and since build 336 the Go side writes
    // U+FFFD deliberately, as its marker for remote text it had to repair. A
    // healthy log now CONTAINS that scalar.
    let legitimate = Data("[Go] vk: name=\u{FFFD}\u{FFFD} (repaired upstream)\n".utf8)
    check(SharedLogger.decode(archive: Data(), current: legitimate).repairedSequences == 0,
          "🚨 a literal U+FFFD in a VALID file counts as ZERO repairs — otherwise the banner "
          + "accuses a writer of overwriting nothing, on a file nobody damaged")
    check(SharedLogger.invalidSequences(in: legitimate) == 0,
          "and the byte-level counter agrees, which is where the count now comes from")
    check(SharedLogger.invalidSequences(in: Data([0x41, 0xFF, 0x42, 0xC3])) == 2,
          "🚨 two separate invalid sequences are counted as two — a boolean 'is it dirty' "
          + "cannot tell one clobbered line from a file full of them")

    // 🚨 ITEM 5: the banner may not name a cause. It said "a writer overwrote
    // part of a line" — my hypothesis, refuted by the export for this very
    // incident, which was a byte-indexed truncation instead.
    check(!logs.contains("a writer overwrote part of a line"),
          "🚨 the banner no longer asserts an overwrite — 2f18b1a established a different "
          + "cause, and a banner that names one sends the next reader to the wrong file")
    check(logs.contains("names the writer"),
          "it points at the evidence (the raw export and the text around each U+FFFD) instead")
}

print("SpeedTestLog — confirmed is upload-only, and a cancelled tail is not refusal")

// 39. 🚨 REVIEW ITEMS 1 AND 2, on the side that renders them.
do {
    var down = SpeedTestPhase()
    down.rawMbps = 400; down.windowSec = 15; down.actualSec = 15
    down.bytes = 750_000_000; down.windowBytes = 750_000_000
    down.connsUsed = 32; down.dials = 31
    // What Go now sends for a download: no ratio, no backlog.
    let downLine = SpeedTestLog.result(SpeedTestRunConfig(serverID: "31551", serverLabel: "MEO · Funchal",
                                                          threads: 32, direction: "both",
                                                          durationSec: 30),
                                       progress: { var p = SpeedTestProgress(); p.download = down; return p }(),
                                       path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(!downLine.contains("confirmed="),
          "🚨 a DOWNLOAD line carries no confirmed= — the field is upload-only and 100.0% by "
          + "construction reads as a verdict about the server")
    check(!downLine.contains("backlog="),
          "and no backlog= either")

    // Upload, the measured 32-thread shape: the backlog is entirely the tail.
    var up = SpeedTestPhase()
    up.rawMbps = 201; up.windowSec = 18; up.actualSec = 18
    up.bytes = 452_800_000; up.windowBytes = 452_800_000
    up.backlogBytes = 29_500_000; up.confirmedRatio = 0.939; up.confirmedKnown = true
    up.backlogTailBytes = 32 * 999_490
    up.connsUsed = 32; up.dials = 31
    let upLine = SpeedTestLog.result(SpeedTestRunConfig(serverID: "31551", serverLabel: "MEO · Funchal",
                                                        threads: 32, direction: "both",
                                                        durationSec: 30),
                                     progress: { var p = SpeedTestProgress(); p.upload = up; return p }(),
                                     path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(upLine.contains("confirmed=93.9%"),
          "an UPLOAD still reports the ratio — it is a fact, and 0% against a large backlog is "
          + "what identified the 307 endpoint")
    check(upLine.contains("held in flight by 32 workers at the cutoff"),
          "🚨 and the backlog QUALIFIES ITSELF: 29.5MB is under the 32.0MB ceiling of one "
          + "in-flight chunk per worker, so it is a normal end of phase, not refusal")

    // Beyond the tail, the qualifier must NOT appear — otherwise it would
    // explain away the very case the field exists for.
    var broken = up
    broken.backlogBytes = 45_800_000
    broken.backlogTailBytes = 8 * 999_490
    let brokenLine = SpeedTestLog.result(SpeedTestRunConfig(serverID: "31551", serverLabel: "MEO · Funchal",
                                                            threads: 8, direction: "both",
                                                            durationSec: 30),
                                         progress: { var p = SpeedTestProgress(); p.upload = broken; return p }(),
                                         path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(!brokenLine.contains("held in flight by"),
          "🚨 a backlog the tail CANNOT explain is not qualified away — 45.8MB against 8 workers "
          + "is the Frankfurt 307 shape, and that is the case the field was added for")

    // 🚨 ZERO IS A REAL ANSWER, AND IT IS THE ONE THIS FIELD EXISTS FOR. The
    // Frankfurt 307 endpoint confirms NOTHING, so its ratio is exactly 0.000 —
    // and while presence was inferred from `> 0`, that case printed on no line
    // at all. The value cannot double as the presence test.
    var dead = SpeedTestPhase()
    dead.rawMbps = 0; dead.windowSec = 15; dead.actualSec = 15
    dead.bytes = 0; dead.windowBytes = 0
    dead.backlogBytes = 45_800_000; dead.confirmedRatio = 0; dead.confirmedKnown = true
    dead.backlogTailBytes = 8 * 999_490
    let deadLine = SpeedTestLog.result(SpeedTestRunConfig(serverID: "35692", serverLabel: "Clouvider · Frankfurt",
                                                          threads: 8, direction: "upload",
                                                          durationSec: 15),
                                        progress: { var p = SpeedTestProgress(); p.upload = dead; return p }(),
                                        path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(deadLine.contains("confirmed=0.0%"),
          "🚨 a measured ZERO is PRINTED — an endpoint that accepts nothing is the whole reason "
          + "this field exists, and gating on the value made exactly that case invisible")

    // And the screen must carry the explanation the log carries, because the
    // person looking at 93.9% on a phone is the one who needs it.
    let view = codeWithoutComments("VKTurnProxy/VKTurnProxy/SpeedTestResultView.swift")
    check(view.contains("phase.confirmedKnown"),
          "🚨 the result view tests confirmedKnown, not the value — same reason as the log line")
    // 🚨 THE CLEANUP IS NAMED, NOT ABSORBED. Research mode promised a fixed 30s
    // window and delivered 33.6-35.0s, because the window ran until the engine
    // returned and the engine returns only after its blocked workers unwind.
    var slow = SpeedTestPhase()
    slow.rawMbps = 93.8; slow.actualSec = 40; slow.windowSec = 30; slow.warmupSec = 5
    slow.cleanupSec = 4.5; slow.guardSec = 0.5
    slow.bytes = 400_000_000; slow.windowBytes = 351_000_000
    // The fixture is internally consistent on purpose: 5 + 30 + 0.5 + 4.5 = 40,
    // so an assertion about the parts adding up is testing the code and not the
    // fixture's own arithmetic.
    slow.connsUsed = 16; slow.dials = 15
    let slowLine = SpeedTestLog.result(SpeedTestRunConfig(serverID: "31551", serverLabel: "MEO · Funchal",
                                                          threads: 16, direction: "upload",
                                                          durationSec: 30),
                                        progress: { var p = SpeedTestProgress(); p.upload = slow; return p }(),
                                        path: SpeedTestPathTrace(.vpnOff)).joined(separator: "\n")
    check(slowLine.contains("guard=0.5s"),
          "🚨 the guard is printed separately — it is time WE asked the engine to keep pushing "
          + "after the window, and folded into cleanup it reads as the engine being slow")
    check(slowLine.contains("window=30.0s") && slowLine.contains("cleanup=4.5s"),
          "🚨 the log separates the WINDOW from the tail spent stopping — folded together they "
          + "made a fixed-window experiment produce arms of 30.0s and 35.0s")
    check(slowLine.contains("actual=40.0s"),
          "and the phase's whole length is still there, so warm-up + window + cleanup can be "
          + "checked against it")

    let onScreen = SpeedTestResultView.timing(slow, requested: 30)
    check(onScreen.contains("to stop"),
          "🚨 and the SCREEN names it too — a 35s arm that reads as 30s is how two different "
          + "experiments get compared as one")
    check(onScreen.contains("0.5s guard"),
          "🚨 and the guard as well: warm-up + window + guard + cleanup must account for the "
          + "phase ON SCREEN too, or the durations a reader adds up come out short")
    // The parts named on screen must sum to the phase — checked by construction
    // rather than by reading the sentence.
    check(abs((slow.warmupSec + slow.windowSec + slow.guardSec + slow.cleanupSec) - slow.actualSec) < 0.01,
          "the four parts account for the whole phase")

    check(view.contains("backlogTailBytes") && view.contains("still in flight when the window closed"),
          "🚨 and it EXPLAINS a shortfall the in-flight chunks account for, instead of showing a "
          + "bare 93.9% whose reason lives only in a log and a memory file")
    check(!view.contains("never confirmed") && !view.contains("cancelled"),
          "🚨 and it does NOT claim those bytes were cancelled or never confirmed — the counter "
          + "is read at the CUTOFF, so their final fate is something this side never observes")
}


print("The path trace — a route change counts when it lands in the MEASUREMENT window")

// 40. 🚨 `PATH CHANGED` MUST MEAN "DURING THE INTERVAL WHOSE BYTES MADE THIS
//     RATE". It used to mean "at any point between the Run tap and the terminal
//     poll being processed", which is wider at BOTH ends — so flipping the VPN
//     after the window closed, while the engine was still unwinding, condemned a
//     finished result.
//
//     🚫 And "just skip the terminal poll" is not the same fix: it leaves the gap
//     between the last running poll and the window's real close unobserved,
//     missing a change in the direction that HIDES a defect.
do {
    let t0 = Date(timeIntervalSince1970: 1_000_000)
    let open = t0.addingTimeInterval(5)    // the window opens after a warm-up
    let close = t0.addingTimeInterval(35)  // and closes 30s later
    let window = open...close
    func obs(_ offset: TimeInterval, _ p: SpeedTestPath) -> SpeedTestPathObservation {
        SpeedTestPathObservation(at: t0.addingTimeInterval(offset), path: p)
    }

    // BEFORE the window opens: the run started on VPN, went DIRECT during the
    // warm-up, and every measured byte left through DIRECT.
    let before = SpeedTestPathTrace.over(window, observations: [
        obs(0, .throughVPN), obs(2, .directMode),
    ])
    check(before.isAttributable && before.label == SpeedTestPath.directMode.rawValue,
          "🚨 a change BEFORE the window does not spoil the result — it decides which single "
          + "path the measured bytes belong to (got \(before.label))")

    // INSIDE: this is the case the label exists for.
    let inside = SpeedTestPathTrace.over(window, observations: [
        obs(0, .throughVPN), obs(20, .directMode),
    ])
    check(!inside.isAttributable && inside.label.contains("PATH CHANGED"),
          "🚨 a change INSIDE the window flags the result")

    // AFTER the close, before the terminal poll: the engine is unwinding, the
    // measurement is over. This is the false positive that started this.
    let after = SpeedTestPathTrace.over(window, observations: [
        obs(0, .throughVPN), obs(37, .directMode),
    ])
    check(after.isAttributable && after.label == SpeedTestPath.throughVPN.rawValue,
          "🚨 a change AFTER the window closed does NOT condemn a finished result (got "
          + "\(after.label))")

    // VPN → DIRECT → VPN inside the window is two changes, not zero: the run
    // spanned both, whatever it ended on.
    let thereAndBack = SpeedTestPathTrace.over(window, observations: [
        obs(0, .throughVPN), obs(10, .directMode), obs(20, .throughVPN),
    ])
    check(!thereAndBack.isAttributable,
          "🚨 VPN → DIRECT → VPN inside the window is a CHANGE — ending where it began is not "
          + "the same as never having moved")

    // A window with no change at all still knows its path: the state in force
    // when it opened is what the bytes were measured on.
    let quiet = SpeedTestPathTrace.over(window, observations: [obs(0, .vpnOff)])
    check(quiet.isAttributable && quiet.label == SpeedTestPath.vpnOff.rawValue,
          "the state in force at the open is carried, or a quiet run reads as 'path unknown'")

    // And the boundaries come from the ENGINE's phases, spanning both of them.
    var down = SpeedTestPhase(); down.windowStartedAt = 1_000_005; down.windowClosedAt = 1_000_035
    var up = SpeedTestPhase(); up.windowStartedAt = 1_000_045; up.windowClosedAt = 1_000_075
    var prog = SpeedTestProgress(); prog.download = down; prog.upload = up
    let spanning = SpeedTestPathTrace.overMeasurement(prog, observations: [
        obs(0, .throughVPN), obs(40, .directMode),   // in the GAP between the phases
    ], fallback: SpeedTestPathTrace(.throughVPN))
    check(!spanning.isAttributable,
          "🚨 a change in the GAP between the two phases still counts — the phases were then "
          + "measured on different routes and one label cannot describe both")

    let outside = SpeedTestPathTrace.overMeasurement(prog, observations: [
        obs(0, .throughVPN), obs(80, .directMode),   // after the LAST window closed
    ], fallback: SpeedTestPathTrace(.throughVPN))
    check(outside.isAttributable,
          "and a change after the last window closed still does not")

    // No usable window (an errored run has no phases): fall back to the wide
    // trace, which errs toward flagging rather than toward blessing.
    let wide = SpeedTestPathTrace.overMeasurement(SpeedTestProgress(), observations: [],
                                                   fallback: SpeedTestPathTrace(.directMode))
    check(wide.label == SpeedTestPath.directMode.rawValue,
          "with no window reported the wide trace is kept — the fallback is the CAUTIOUS one")

    // 🚨 P2: PER PHASE, NOT OVER THEIR UNION. The union also covers the gap
    // between the phases, where nothing is measured — so a DIRECT round trip
    // that begins AND ends inside that gap flagged a run whose two phases were
    // both measured on VPN and neither number touched.
    var d2 = SpeedTestPhase(); d2.windowStartedAt = 1_000_005; d2.windowClosedAt = 1_000_035
    var u2 = SpeedTestPhase(); u2.windowStartedAt = 1_000_045; u2.windowClosedAt = 1_000_075
    var twoPhase = SpeedTestProgress(); twoPhase.download = d2; twoPhase.upload = u2

    let roundTripInGap = SpeedTestPathTrace.overMeasurement(twoPhase, observations: [
        obs(0, .throughVPN), obs(38, .directMode), obs(42, .throughVPN),
    ], fallback: SpeedTestPathTrace(.throughVPN))
    check(roundTripInGap.isAttributable
          && roundTripInGap.label == SpeedTestPath.throughVPN.rawValue,
          "🚨 a DIRECT round trip entirely inside the GAP between phases does NOT flag the run — "
          + "both phases were measured on VPN and neither number was touched (got "
          + "\(roundTripInGap.label))")

    let persistsAcrossGap = SpeedTestPathTrace.overMeasurement(twoPhase, observations: [
        obs(0, .throughVPN), obs(40, .directMode),
    ], fallback: SpeedTestPathTrace(.throughVPN))
    check(!persistsAcrossGap.isAttributable,
          "🚨 but a change that PERSISTS across the gap does — the two phases were then measured "
          + "on two routes, and one label cannot describe both")

    let insideAPhase = SpeedTestPathTrace.overMeasurement(twoPhase, observations: [
        obs(0, .throughVPN), obs(20, .directMode), obs(25, .throughVPN),
    ], fallback: SpeedTestPathTrace(.throughVPN))
    check(!insideAPhase.isAttributable,
          "and a round trip INSIDE a phase's own window still flags it — that phase's bytes did "
          + "leave by two routes")

    // 🚨 P2: the label describes the interval it is now computed over.
    check(insideAPhase.label.contains("DURING THE MEASUREMENT")
          && !insideAPhase.label.contains("DURING THE RUN"),
          "🚨 the label says DURING THE MEASUREMENT — it stopped meaning 'the run' one build ago "
          + "and a sentence that lags its own rule is how the next reader is misled")

    let runner = codeWithoutComments("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")

    // 🚨 P1: a poll timestamp is the instant of DETECTION. A change in the last
    // 500ms of a window would be stamped after the close and dropped — a MISS,
    // which hides a defect instead of inventing one.
    check(runner.contains("Publishers.CombineLatest(tunnel.$status, tunnel.$directMode)"),
          "🚨 the route is SUBSCRIBED to, so a change is stamped when it is published rather "
          + "than when a timer next looks")
    check(runner.contains("notePath(now, at: lastPathSampleAt)"),
          "🚨 and a change the POLL discovers is stamped at the PREVIOUS look — the earliest "
          + "instant it could have happened, because guessing early flags a run and guessing "
          + "late hides one")
    check(runner.contains("stopWatchingThePath()") && runner.contains("pathWatch.removeAll()"),
          "the subscription is released when the run ends")

    // 🚨 THE STAMP MUST BE TAKEN UPSTREAM OF THE SCHEDULER HOP. `receive(on:)`
    // defers the sink to a later turn of the run loop, so a Date() inside it
    // measures how busy the main queue was — worst exactly when a route flips.
    if let stamp = runner.range(of: "SpeedTestPathObservation(at: Date(), path: $0)"),
       let hop = runner.range(of: ".receive(on: DispatchQueue.main)") {
        check(stamp.lowerBound < hop.lowerBound,
              "🚨 the observation is stamped BEFORE receive(on:) — stamped after, the timestamp "
              + "carries the scheduler's delay instead of the event's instant")
    } else {
        check(false, "the stamping map or the hop is gone — this scan no longer tests anything")
    }

    // 🚨 AND THE WATCHER MAY NOT OUTLIVE A START THAT NEVER HAPPENED.
    //
    // Stated as "it does not appear BEFORE the engine is asked", which is the
    // invariant itself — an earlier version compared the index of a two-line
    // anchor, and moving the call simply made that anchor vanish, so the
    // sabotage reddened the "I cannot find it" branch instead of the claim.
    // ⚖️ TWO CHECKS, because the negative one alone is blind: "not installed too
    // early" is satisfied just as well by not installing it AT ALL, and the
    // whole mechanism would then be silently gone.
    let watchCalls = runner.components(separatedBy: "watchThePath()").count - 1
    let watchDecls = runner.components(separatedBy: "func watchThePath()").count - 1
    check(watchCalls - watchDecls == 1,
          "the route subscription is installed exactly once — a negative check on WHERE it is "
          + "installed passes just as happily when it is nowhere (found \(watchCalls - watchDecls))")

    if let start = runner.range(of: "func start(serverID"),
       let engineCall = runner.range(of: "wgSpeedtestStart(cstr)") {
        let beforeTheEngineIsAsked = runner[start.lowerBound..<engineCall.lowerBound]
        check(!beforeTheEngineIsAsked.contains("watchThePath()"),
              "the route subscription is installed only AFTER the engine has accepted the start "
              + "— installed before it, every early exit leaves a watcher recording for a run "
              + "that does not exist")
    } else {
        check(false, "start() or the engine call could not be found — the scan is inert")
    }

    // 🚨 THIS ONE IS DELIBERATELY ABOUT THE PROSE, because the prose is the
    // artefact: a comment describing the model that was replaced is what the
    // next reader will believe.
    let runnerWithComments = source("VKTurnProxy/VKTurnProxy/SpeedTestRunner.swift")
    check(!runnerWithComments.contains("the interval spans from the first"),
          "🚨 no comment still describes the single-interval model — each phase's own window is "
          + "scored now, and a stale comment outlives the code it explains")
    check(runner.contains("SpeedTestPathTrace.overMeasurement("),
          "🚨 and the runner NARROWS the trace on the terminal poll — the rule is worth nothing "
          + "if the result still carries the run-wide one")
    check(runner.contains("SpeedTestPathObservation(at: Date()"),
          "route changes are recorded WITH their instant, which is what makes the interval "
          + "comparison possible at all")
}

// ─────────────────────────────────────────────────────────────────────────────
// 41. 🚨 "permission denied" NAMES NOTHING. It is NetworkExtension's own
//     `configurationPermissionDenied` text, and it is the entire message a user
//     got when the IPA was signed without the packet-tunnel entitlement — while
//     the cause sits in a code signature we already parse (issue #75).
//
//     🚨 The other half is the FALSE ACCUSATION: an entitled build that is
//     refused for some other reason (a leftover VPN profile from a different
//     signing identity, MDM/supervision, a prompt answered "Don't Allow") must
//     NOT be told to re-sign. So the entitled branch is checked as strictly as
//     the unentitled one.
do {
    let unentitled = AppEntitlements(dict: [
        "application-identifier": "4FN8R4RQZT.app.rainbow5144.lychee3940",
    ])
    let entitled = AppEntitlements(dict: [
        "application-identifier": "CDMQ33VFQC.com.vkturnproxy.app",
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
    ])
    // A build holding a DIFFERENT NE mode is as unable to start a packet tunnel
    // as one holding none — "the array is non-empty" would be the wrong test.
    let otherMode = AppEntitlements(dict: [
        "com.apple.developer.networking.networkextension": ["app-proxy-provider"],
    ])

    check(!unentitled.hasPacketTunnelProvider && entitled.hasPacketTunnelProvider,
          "🚨 the packet-tunnel entitlement is read off the signature")
    check(!otherMode.hasPacketTunnelProvider,
          "🚨 a DIFFERENT NetworkExtension mode does not count as a packet tunnel — the mode "
          + "string is matched exactly, not merely present")

    let bad = unentitled.vpnPermissionDiagnosis()
    check(bad.contains("packet-tunnel-provider") && bad.contains("CANNOT create a VPN configuration"),
          "🚨 the unentitled diagnosis names the missing entitlement, not just the symptom")
    check(bad.contains("TestFlight") && bad.contains("DELETE THIS APP FIRST"),
          "🚨 …and it says what to DO, including the install trap that would otherwise read as "
          + "\"An error occurred while installing\"")
    check(bad.contains("4FN8R4RQZT"),
          "🚨 …and it names the signer, so the report identifies the build without a Mac")

    let good = entitled.vpnPermissionDiagnosis()
    check(good.contains("did NOT come from how the IPA was signed"),
          "🚨 an ENTITLED build is not accused of a signing problem — the refusal came from "
          + "elsewhere and re-signing would not help")
    check(good.contains("VPN & Device Management") && good.contains("supervised"),
          "🚨 …and it names the causes that DO produce this on an entitled build")
    // 🚨 Written after my own first draft lowercased the whole signer line. A
    // team identifier is case-significant and is what a reader compares against
    // a provisioning profile, so "cdmq33vfqc" names nothing.
    check(good.contains("CDMQ33VFQC"),
          "🚨 the team identifier keeps its case — it is compared against a provisioning "
          + "profile, and a lowercased team id matches nothing")
    check(!good.contains("TestFlight"),
          "🚨 …and it does NOT send an entitled user to reinstall — that is the false "
          + "accusation this branch exists to prevent")

    let unreadable = AppEntitlements(error: "no XML entitlements blob in code signature")
    let unknown = unreadable.vpnPermissionDiagnosis()
    check(unknown.contains("cannot say whether"),
          "🚨 an unreadable signature says it CANNOT TELL — it must claim neither presence nor "
          + "absence, which is the shape build 338 had to fix on `confirmed`")
    check(!unknown.contains("CANNOT create a VPN configuration"),
          "🚨 …and specifically does not report the unentitled verdict")

    // The headline is what the SCREEN shows; the diagnosis is what the LOG gets.
    check(unentitled.vpnPermissionHeadline().contains("without the VPN entitlement"),
          "the one-line headline carries the cause")
    check(unentitled.vpnPermissionHeadline().count < 130,
          "🚨 …and stays one line — the status area is a centered caption, and a wall of red "
          + "there is what a user crops out of the screenshot they attach")

    // 🚨 And the WIRING: a diagnosis nothing calls is worth nothing. Build 339's
    // sabotage passed every test in its file because only the CALL SITE was gone.
    let tm = codeWithoutComments("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    check(tm.contains("errorMessage = Self.failureText(\"Failed to load VPN config\", error)"),
          "🚨 the LOAD failure — the launch-time message a user screenshots — is classified "
          + "rather than published bare")
    check(tm.contains("errorMessage = Self.connectFailure(error)"),
          "🚨 and so does the connect failure, which is what the user sees after tapping Connect")
    check(!tm.contains("errorMessage = error.localizedDescription\n"),
          "🚨 no catch still publishes a BARE localizedDescription — that is the state where "
          + "the whole message was the framework's \"permission denied\"")
    // 🚨 THE VERDICTS THEMSELVES, driven by fixtures. Three narrowings of this
    // rule have shipped defects, and every one of them passed a source grep:
    // a `contains` check sees a missing line and never a wrong answer.
    func ne(_ domain: String, _ code: Int) -> NSError {
        NSError(domain: domain, code: code, userInfo: [NSLocalizedDescriptionKey: "permission denied"])
    }
    func verdict(_ e: NSError, _ ent: AppEntitlements) -> VPNFailureAdvice {
        VPNConfigFailure.classify(e, entitlements: ent)
    }

    check(verdict(ne("VKTurnProxyError", 42), entitled) == .plain,
          "🚨 a NON-NetworkExtension failure is never touched — captcha, creds and network "
          + "errors must not be blamed on how the app was signed")

    // The issue-75 build: the signature decides, and it decides for EVERY code,
    // so the diagnosis cannot stop matching when Apple renumbers something.
    for code in 1...6 {
        check(verdict(ne(NEVPNErrorDomain, code), unentitled) == .diagnose,
              "🚨 an unentitled build is diagnosed whatever the code carries (NEVPNError \(code)) "
              + "— that verdict comes from OUR signature, never from the error")
    }

    // The reviewer's objection: ordinary NE errors must NOT get the entitlement text.
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationDisabled.rawValue), entitled) == .plain,
          "🚨 ConfigurationDisabled on an entitled build says only what it is")
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.connectionFailed.rawValue), entitled) == .plain,
          "🚨 ConnectionFailed likewise — it is not a configuration refusal at all")
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationStale.rawValue), entitled) == .plain,
          "🚨 ConfigurationStale likewise — its one internal source is a stale config, a reload")

    // …but invalid(1) is the image of five internal codes, one of them
    // "configuration owner application is wrong" — the leftover-profile case.
    // Suppressing it outright would delete the lead the entitled branch exists
    // to give, so it gets a NARROWER message instead of none.
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationInvalid.rawValue), entitled)
          == .savedConfigurationSuspect,
          "🚨 ConfigurationInvalid is neither suppressed nor given the entitlement text — it is "
          + "the image of \"configuration owner application is wrong\", i.e. a leftover profile")

    // Where "permission denied" actually lands: mapError: sends internal code 10
    // to NEVPNError 5. This is the entitled half of issue 75.
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationReadWriteFailed.rawValue), entitled)
          == .diagnose,
          "🚨 ConfigurationReadWriteFailed IS diagnosed — internal code 10, \"permission denied\", "
          + "is mapped onto exactly this public code")
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationUnknown.rawValue), entitled) == .diagnose,
          "ConfigurationUnknown is diagnosed rather than passed through bare")

    // 🚨 FAIL OPEN. The check that would have caught both earlier narrowings: an
    // NE-family error this build has never heard of must be the LOUD path. A
    // false positive costs three dead-end leads in a branch that never accuses
    // the signature; a false negative is silent, and lands on the users whose
    // App Group is dead and who therefore have no log to send.
    check(verdict(ne("NESomethingNewErrorDomain", 999), entitled) == .diagnose,
          "🚨 an UNRECOGNISED NE domain and code still gets the leads — when the classifier "
          + "cannot decide it must say more, never less")
    check(verdict(ne(NEVPNErrorDomain, 99), entitled) == .diagnose,
          "🚨 …and so does an unrecognised code in a known NE domain")

    // An unreadable signature must not be read as "unentitled".
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationReadWriteFailed.rawValue), unreadable)
          == .diagnose
          && unreadable.vpnPermissionDiagnosis().contains("cannot say whether"),
          "🚨 an unreadable signature is diagnosed but claims nothing — hasPacketTunnelProvider "
          + "is false there without that meaning the entitlement is absent")

    // 🚨 Added because a sabotage that DROPPED the `error == nil` test reddened
    // nothing: every fixture I had written happened to expect .diagnose, so the
    // two behaviours were indistinguishable. This is the fixture that separates
    // them — an unreadable signature must not be read as "unentitled", so a
    // self-explanatory code still passes through plain.
    check(verdict(ne(NEVPNErrorDomain, NEVPNError.configurationDisabled.rawValue), unreadable) == .plain,
          "🚨 an unreadable signature does not force the diagnosis onto a self-explanatory code — "
          + "unreadable is not the same as unentitled")

    // 🚨 A CONNECTION death is not a CONFIGURATION refusal. This domain was
    // INERT until the status observer began reading lastDisconnectError; the
    // moment it did, the fail-open default would have started attaching the
    // signing leads to every ordinary tunnel drop — no network, overslept,
    // server not responding.
    if #available(iOS 16.0, *) {
        for code in [NEVPNConnectionError.noNetworkAvailable.rawValue,
                     NEVPNConnectionError.unrecoverableNetworkChange.rawValue,
                     NEVPNConnectionError.serverNotResponding.rawValue] {
            check(verdict(ne(NEVPNConnectionErrorDomain, code), entitled) == .plain,
                  "🚨 a tunnel DEATH (NEVPNConnectionError \(code)) is not a configuration "
                  + "refusal — it must not be answered with entitlements and MDM")
        }
        check(verdict(ne(NEVPNConnectionErrorDomain,
                         NEVPNConnectionError.noNetworkAvailable.rawValue), unentitled) == .diagnose,
              "…but on a build that cannot run a tunnel at all, even a connection error is worth "
              + "explaining — the signature layer is above this suppressor")
    }

    // 🚨 The retry predicate: exactly the pair a reload can fix, and nothing else.
    check(VPNConfigFailure.isStaleConfiguration(ne(NEVPNErrorDomain, NEVPNError.configurationStale.rawValue))
          && VPNConfigFailure.isStaleConfiguration(ne(NEVPNErrorDomain, NEVPNError.configurationInvalid.rawValue)),
          "🚨 stale(4) and invalid(1) are retried through a reload — the pair WireGuard-apple "
          + "guards on, and the only failures whose cause is the generation we wrote against")
    check(!VPNConfigFailure.isStaleConfiguration(ne(NEVPNErrorDomain, NEVPNError.configurationReadWriteFailed.rawValue)),
          "🚨 …and a PERMISSION refusal is NOT retried — a second identical write cannot help, "
          + "and retrying it would bury issue #75 behind a doubled delay")
    check(!VPNConfigFailure.isStaleConfiguration(ne("VKTurnProxyError", 4)),
          "…nor is a foreign error that merely happens to carry code 4")

    // The wiring still has to exist — a verdict nothing consults is worth nothing.
    check(tm.contains("VPNConfigFailure.classify(ns, entitlements: ent)"),
          "🚨 TunnelManager asks the classifier rather than re-deciding — three of these bugs "
          + "were a caller disagreeing with the rule it had already been given")
    check(tm.contains("errorMessage = Self.failureText(\"Failed to load VPN config\", error)")
          && tm.contains("failureText(nil, error)")
          && tm.contains("directModeError = Self.failureText(\"Could not switch routing\", error)"),
          "🚨 all FOUR NE call sites route through it — load, connect, the Live Activity switch, "
          + "and setDirectMode, which the previous check could not see because it was scoped to "
          + "`errorMessage =`")
    check(tm.contains("try await Self.saveReloadingIfStale(manager, reapply: apply)"),
          "🚨 the connect path SAVES THROUGH THE RETRY rather than calling saveToPreferences "
          + "directly — the machinery is worth nothing if the call site bypasses it")
    check(tm.contains("reapply(manager)") && tm.contains("try await manager.loadFromPreferences()"),
          "🚨 …and the retry RE-APPLIES after reloading: loadFromPreferences overwrites the "
          + "in-memory config from disk, so a retry without it would silently save back what iOS "
          + "just handed us and discard the configuration this connect is for")
    check(tm.contains("manager.connection.fetchLastDisconnectError { stop in"),
          "🚨 a tunnel that dies AFTER starting is reported — the reason arrives only through "
          + "fetchLastDisconnectError, never as a thrown error, so it used to be invisible")
    check(tm.contains("fetchStopReasonAtAttach(manager)"),
          "🚨 …and the ALREADY-dead case is read at attach: NEVPNStatusDidChange delivers only "
          + "FUTURE transitions, so a death while the app was not running is invisible to the "
          + "observer — which is exactly the death a user opens the app to have explained")
    check(tm.contains("let deathGeneration = self.disconnectGate.observe(newStatus)"),
          "🚨 the gate sees EVERY status, not only terminal ones — it cannot know something died "
          + "unless it first saw a session become live")
    check(tm.contains("messageNow: self.errorMessage") && !tm.contains("messageAtFetch:"),
          "🚨 the late answer yields to whatever is IN the slot on arrival — not to a snapshot "
          + "taken when the fetch was issued, which in production had already picked up the very "
          + "message it was supposed to defer to")
    check(tm.contains("let generation = disconnectGate.generation"),
          "🚨 the cold-attach fetch carries a generation too — a full connect/disconnect cycle can "
          + "finish while it is in flight, and the status is `.disconnected` at both ends of that")
    // 🚨 …and CONSULTS it. Added because a sabotage that deleted the attach
    // guard reddened nothing: capturing a generation nobody checks is exactly
    // the shape of a rule that is present and switched off.
    check(tm.contains("disconnectGate.attemptBegan()")
          && tm.components(separatedBy: "disconnectGate.attemptBegan()").count - 1 == 2,
          "🚨 BOTH attempt entry points — connect() and switchAndReconnect() — advance the "
          + "generation, because each runs for a long time before iOS reports any status change")
    check(tm.components(separatedBy: "disconnectGate.mayPublish(").count - 1 == 2,
          "🚨 BOTH fetch paths — the observer's and the cold attach — ask mayPublish before "
          + "publishing; a captured generation that nothing consults is a rule switched off")

    // 🚨 THE GATE ITSELF, by fixture — the three defects here are all about
    // ORDERING, which no scan over TunnelManager can check.
    do {
        var g = DisconnectReasonGate()
        // 🚨 `.invalid` is a saveToPreferences() waypoint, not a death. Observed
        // with no live session behind it, it must ask nothing.
        check(g.observe(.invalid) == nil && g.observe(.disconnected) == nil,
              "🚨 a terminal state with no live session behind it asks NOTHING — "
              + "saveToPreferences() passes through .invalid on every ordinary reconnect")

        _ = g.observe(.connecting)
        _ = g.observe(.connected)
        let died = g.observe(.disconnected)
        check(died != nil,
              "🚨 …but a session that WAS live going terminal does ask for a reason")

        // The staleness test a status check cannot do: cycle N's answer must not
        // be published into cycle N+1, and both cycles see `.disconnected`.
        check(g.mayPublish(fetchedUnder: died!, messageNow: nil),
              "an answer for the current cycle, with nothing else claiming the slot, is publishable")
        _ = g.observe(.connecting)
        check(!g.mayPublish(fetchedUnder: died!, messageNow: nil),
              "🚨 …and the SAME answer is dropped once a new session has begun — a status check "
              + "cannot see this, because both down-cycles look identical")

        // 🚨 THE PRODUCTION SEQUENCE, which the previous fixture did NOT test.
        // The VKAuth branch publishes SYNCHRONOUSLY in the same status handler,
        // i.e. BEFORE the fetch is even issued — so a guard comparing the slot
        // against a snapshot taken at issue time captured VKAuth's own message as
        // its baseline, compared equal, and allowed the overwrite. The honest
        // question is only ever "is the slot empty NOW".
        var h = DisconnectReasonGate()
        _ = h.observe(.connecting)
        let gen = h.observe(.invalid)!
        check(!h.mayPublish(fetchedUnder: gen, messageNow: "Сессия VK отклонена или истекла."),
              "🚨 a message ALREADY in the slot when the answer lands wins — this is the real "
              + "ordering: VKAuth publishes synchronously before the fetch is issued, not during it")
        check(!h.mayPublish(fetchedUnder: gen, messageNow: "anything at all"),
              "🚨 …and it wins whatever it says: the stop reason is a FALLBACK, so it fills an "
              + "empty slot and never competes for a full one")
        check(h.mayPublish(fetchedUnder: gen, messageNow: nil),
              "…while an empty slot is what it exists to fill")

        // P2: the cold-attach fetch carries a generation for the same reason the
        // observer path does — a full connect/disconnect cycle can complete while
        // the attach answer is still in flight.
        var a = DisconnectReasonGate()
        let atAttach = a.generation
        check(a.mayPublish(fetchedUnder: atAttach, messageNow: nil),
              "an attach-time answer publishes while nothing has happened since")
        _ = a.observe(.connecting)
        _ = a.observe(.connected)
        _ = a.observe(.disconnected)
        check(!a.mayPublish(fetchedUnder: atAttach, messageNow: nil),
              "🚨 …and is DROPPED once a whole session has come and gone — otherwise a reason from "
              + "before the app launched is published against a death that just happened")

        // 🚨 THE WINDOW A STATUS-DRIVEN GENERATION CANNOT SEE. connect() runs
        // pre-bootstrap — captcha, creds, the VK API — for seconds or minutes
        // before startVPNTunnel() moves the status, and it clears the message
        // slot on entry. A fetch from the previous death therefore matched the
        // generation AND found an empty slot for that whole window.
        var b = DisconnectReasonGate()
        _ = b.observe(.connecting)
        let prevDeath = b.observe(.disconnected)!
        check(b.mayPublish(fetchedUnder: prevDeath, messageNow: nil),
              "before a new attempt, the previous death's answer is still its own")
        b.attemptBegan()   // connect() entered; NO status transition yet
        check(!b.mayPublish(fetchedUnder: prevDeath, messageNow: nil),
              "🚨 …and once an ATTEMPT has begun it is dropped, even though iOS has not reported "
              + "`.connecting` yet — the generation must track INTENT, not the system's status")

        // 🚨 Added because a sabotage that made attemptBegan() ALSO mark the
        // session live reddened nothing. It must not: an attempt that dies in
        // pre-bootstrap never produces a status transition, so the flag would
        // still be set when some later `saveToPreferences()` emits `.invalid` —
        // and P3 would be back, asking why a tunnel that never started stopped.
        var d = DisconnectReasonGate()
        d.attemptBegan()
        check(d.observe(.invalid) == nil && d.observe(.disconnected) == nil,
              "🚨 announcing an ATTEMPT does not make a session live — a connect that dies in "
              + "pre-bootstrap must not turn the next saveToPreferences() `.invalid` into a death")

        // …and the same for the cold-attach answer.
        var c = DisconnectReasonGate()
        let coldGen = c.generation
        c.attemptBegan()
        check(!c.mayPublish(fetchedUnder: coldGen, messageNow: nil),
              "🚨 …which covers the attach answer too: a connect begun during pre-bootstrap must "
              + "not be captioned with why the tunnel died before the app launched")

        // A death is asked about once, not on every subsequent observation.
        var k = DisconnectReasonGate()
        _ = k.observe(.connecting)
        check(k.observe(.disconnected) != nil && k.observe(.disconnected) == nil,
              "🚨 the reason is asked for ONCE per death — iOS re-notifies terminal states, and "
              + "a second fetch would race the first")
    }
    // 🚨 P1, caught in review: SharedLogger.shared.log is `guard let url = fileURL
    // else { return }`, so on a build with no App Group container it is a SILENT
    // no-op — and that is the SAME population that hits the missing VPN
    // entitlement, both being consequences of re-signing. The headline says "see
    // Logs"; without the os_log channel the Logs screen would have nothing.
    check(tm.contains("SharedLogger.logDiagnostic(record, category: \"VPNConfig\")"),
          "🚨 the full diagnosis goes to os_log, which survives a missing App Group — the "
          + "file-backed logger is a silent no-op there, and that is exactly the build that "
          + "needs this text")
    check(tm.contains("SharedLogger.shared.log(\"[AppDebug] \" + record)"),
          "🚨 …and to the shared file too, because the Logs screen only FALLS BACK to os_log: "
          + "on a healthy build the file is where the user actually looks")
    check(tm.contains("[\\(ns.domain) \\(ns.code)]"),
          "🚨 the NSError domain and code reach the log — the STRING does not discriminate, "
          + "since a prompt answered \"Don't Allow\" also reads \"permission denied\"")
}

// ─────────────────────────────────────────────────────────────────────────────
print("The main screen's active-server controls, and the link importer")

// 32. 🚨 THE ACTIVE SERVER IS READ AT RENDER TIME BY A VIEW THAT OBSERVES THE
//     STORE, AND THE NAVIGATION HOST SUBSCRIBES TO NEITHER.
//
//     Two failure directions, and BOTH have happened here:
//       • observe the store on `ContentView` → every edit keystroke re-renders
//         the NavigationView host and pops the pushed editor (build 177, #65);
//       • snapshot it into `@State` on `ContentView` → nothing refreshes the
//         snapshot when the active server changes while the main screen is on
//         top, which is what a tapped connection link does. The subtitle named
//         the previous server while Connect, reading the store live, used the
//         new one. *(Review-caught, 3d7b9953.)*
//     Only a child view satisfies both, which is why this asserts WHERE the
//     reads live rather than that any single line is present.
//
//     ⚠️ Comments are stripped: this scan matches names the surrounding prose is
//     full of, and a scan reddening on its own documentation has happened four
//     times in this project.
do {
    let content = codeWithoutComments("VKTurnProxy/VKTurnProxy/ContentView.swift")

    // SettingsView lives in this file too and legitimately declares
    // @AppStorage("vkLink"), so the host must be isolated before scanning.
    guard let start = content.range(of: "struct ContentView: View {"),
          let hostEnd = content.range(of: "\nprivate struct MainNavigationLinks",
                                      range: start.upperBound..<content.endIndex) else {
        check(false, "could not isolate ContentView — every check below would pass vacuously")
        exit(1)
    }
    let host = String(content[start.upperBound..<hostEnd.lowerBound])

    check(!host.contains("@AppStorage"),
          "🚨 the NavigationView host declares no @AppStorage — an unused one still SUBSCRIBES")
    check(!host.contains("ServerStore"),
          "🚨 …and does not read ServerStore either, in any form")
    check(!content.contains("activeServerName"),
          "🚨 the historical snapshot identifier is gone — a snapshot is stale from the moment a "
          + "link changes the active server without a screen being popped")
    // 🚨 …AND THE IDENTIFIER IS NOT THE INVARIANT. Forbidding one name forbids one
    // name: the same defect under any other spelling passes. `@State ` (with the
    // space) does not match `@StateObject`, so the host keeps its tunnel and may
    // hold no per-render copy of anything at all. *(Review-caught, 63f25071.)*
    check(!host.contains("@State "),
          "🚨 …and the host holds NO @State whatsoever, so the snapshot cannot come back under a "
          + "different name")
    check(host.contains("ActiveServerControls(tunnel: tunnel)"),
          "the server-dependent controls are reached as a child view")

    guard let cs = content.range(of: "private struct ActiveServerControls: View {"),
          // NOT the "// MARK: - Server Mode" line that follows it: comments are
          // stripped above, so a comment anchor is not there to be found — and
          // the guard below then reports "inert" instead of the invariant.
          let ce = content.range(of: "\nenum ServerMode",
                                 range: cs.upperBound..<content.endIndex) else {
        check(false, "could not isolate ActiveServerControls — the checks below would pass vacuously")
        exit(1)
    }
    let child = String(content[cs.upperBound..<ce.lowerBound])

    check(child.contains("@ObservedObject private var store = ServerStore.shared"),
          "the child OBSERVES the store, so an import or a Live Activity switch re-renders it")
    check(child.contains("store.activeServer"),
          "…and reads the active server from it at render time")
    // 🚨 THE CHECK ABOVE IS SATISFIED BY THE CONNECT ACTION ALONE. That is exactly
    // the shape of the original defect — Connect read the store live while the
    // subtitle came from a stored copy — so "the child mentions store.activeServer
    // somewhere" cannot be the whole claim. Two statements close it: the child
    // holds no @State at all, and the SUBTITLE itself interpolates a live read.
    // *(Review-caught, 63f25071.)*
    check(!child.contains("@State "),
          "🚨 the child holds NO @State either — a copy of anything the store owns is the "
          + "subtitle-vs-Connect split back, whatever it is called")
    guard let bodyR = child.range(of: "var body: some View {") else {
        check(false, "could not find ActiveServerControls.body — the subtitle check would pass vacuously")
        exit(1)
    }
    let childBody = String(child[bodyR.upperBound...])
    // ⚖️ THIS CHECK MOVED RATHER THAN LOOSENED. It used to require the subtitle to
    // interpolate `store.activeServer.serverName`, and that became WRONG code the
    // moment the selected server stopped being the right answer for a live tunnel
    // (§34). The scan now pins only WHERE the text comes from; WHAT it says is
    // covered by fixtures, which is strictly stronger than any scan.
    check(childBody.contains("Text(caption.subtitle)"),
          "🚨 the subtitle is the shared caption, not a string this view builds — three surfaces "
          + "answering the same question separately is how two of them kept naming the selected "
          + "server while a different one was running")
    check(childBody.contains("caption.pendingSelection"),
          "…and the view renders the pending-selection note, or a selection that will not take "
          + "effect until the next connect is invisible")
    check(!childBody.contains("Connected to \\("),
          "🚨 …and it does NOT build that sentence itself — a second copy of the rule is how the "
          + "card and the screen drifted apart in the first place")
    check(child.contains("@ObservedObject var tunnel: TunnelManager"),
          "🚨 the tunnel is OBSERVED here, not passed-and-read: SwiftUI may skip re-evaluating a "
          + "child whose stored properties are unchanged, and a class reference never changes")
    check(child.contains("private var connectBlocked: Bool") && child.contains(".disabled(connectBlocked)"),
          "the Connect gate is computed and applied in the same view that renders the name — "
          + "while they lived apart, one could follow the new server and the other the old")
}

// 33. ONE ALERT AT A TIME, ONE CONSUMER, ONE APPLY PATH.
//
//     `consume()` used to take the URL unconditionally, so a second link
//     arriving while the confirm alert was up replaced `pending` underneath it
//     and Import applied a configuration the user had not read. The importer is
//     mounted always now, so that is far easier to reach than when Settings was
//     the only consumer. *(Review-caught, 3d7b9953.)*
//
//     ⚖️ Scan-only: ConnectionLinkPrompt pulls in BackupManager and ServerStore,
//     so it cannot be compiled standalone the way the value types above are.
do {
    let imp = codeWithoutComments("VKTurnProxy/VKTurnProxy/ConnectionLinkImport.swift")
    let content = codeWithoutComments("VKTurnProxy/VKTurnProxy/ContentView.swift")

    check(imp.contains("guard !showConfirm, !showResult else { return }"),
          "🚨 a URL arriving while an alert is up stays PARKED instead of replacing the link "
          + "the user is currently reading")
    // 🚨 THE FULL LINE, NOT THE MODIFIER. Asserting `.onChange(of: showConfirm)`
    // appears is green on an EMPTY handler — and then a URL parked under an alert
    // waits for an .onAppear this view may never get again. My sabotage deleted
    // the whole line, which is a stronger edit than the invariant: it proved that
    // SOME breakage is caught, not this one. *(Review-caught, 63f25071.)*
    //
    // ⚖️ The handler is `settle()` rather than `consume()` since the in-flight
    // link has to be RELEASED as well — this check followed that rename instead
    // of being loosened, and it now pins both halves of what settle() does.
    check(imp.contains(".onChange(of: showConfirm) { _ in settle() }")
          && imp.contains(".onChange(of: showResult) { _ in settle() }"),
          "…and each alert's dismissal re-enters the take path, or the parked URL would wait for "
          + "an .onAppear that may never come")
    // 🚨 AND THE HANDLER'S BODY, IN ORDER — not just its first two lines.
    //
    // Pinning the `.onChange` line and then `guard … / inbox.finish()` still let
    // `settle()` lose its `consume()` call with the WHOLE SUITE GREEN, which is
    // the reviewer's original objection surviving one level in: a URL parked
    // under an alert then waits for an `.onAppear` this importer may never get.
    // The check followed the rename and stopped one line short of the behaviour.
    // *(Re-raised by the user against the fixed code, and confirmed by
    // sabotage before this was written.)*
    //
    // ⚖️ Asserted over the body as COUNT PLUS ORDER, not as a verbatim block: a
    // comment inserted mid-body would break a multi-line match on correct code,
    // and this project has reddened on its own prose four times already.
    //
    // 🚨 AND THE COUNT IS WHAT MAKES THE ORDER MEAN ANYTHING. A forward scan
    // proves the steps CAN be read in sequence, so it is satisfied by a
    // DUPLICATE between two markers: `guard → consume → finish → consume`
    // passes it, and passes a "nothing before the guard" check too. That code
    // is broken in production — the premature `consume()` opens the NEXT
    // transaction and raises its prompt, and the `finish()` behind it then wipes
    // that transaction's phase, so the link on screen has no dedupe window and a
    // later take can overwrite it. With each step pinned at EXACTLY ONE
    // occurrence, order is a statement about where that occurrence is, and a
    // separate "not before" check is not needed at all.
    // *(User-caught, fourth round on this one function: presence → order →
    // order in both directions → count. Each round a level finer, and the shape
    // of the previous fix is what admitted the next defect.)*
    func inOrder(_ body: String, _ steps: [String]) -> Bool {
        var from = body.startIndex
        for step in steps {
            guard let r = body.range(of: step, range: from..<body.endIndex) else { return false }
            from = r.upperBound
        }
        return true
    }
    func countIn(_ body: String, _ needle: String) -> Int {
        body.components(separatedBy: needle).count - 1
    }
    func bodyOf(_ decl: String) -> String? {
        guard let d = imp.range(of: decl),
              let e = imp.range(of: "\n    }", range: d.upperBound..<imp.endIndex) else { return nil }
        return String(imp[d.upperBound..<e.lowerBound])
    }
    let theGuard = "guard !showConfirm, !showResult else { return }"
    let theTake = "guard let url = inbox.take() else { return }"

    if let settle = bodyOf("private func settle() {") {
        check(countIn(settle, "inbox.finish()") == 1 && countIn(settle, "consume()") == 1
              && inOrder(settle, [theGuard, "inbox.finish()", "consume()"]),
              "🚨 the dismissal path GUARDS, then releases ONCE, then takes the next one ONCE — "
              + "releasing early drops the link out of the dedupe window while it is still on "
              + "screen, consuming early opens the next transaction and lets the release behind "
              + "it wipe that one's phase, and not consuming leaves a parked URL waiting for an "
              + ".onAppear that may never come")
    } else {
        check(false, "could not find settle() — the order check would be vacuous")
    }
    if let consume = bodyOf("private func consume() {") {
        check(countIn(consume, "inbox.recoverIfAbandoned()") == 1 && countIn(consume, "inbox.take()") == 1
              && inOrder(consume, [theGuard, "inbox.recoverIfAbandoned()", theTake]),
              "🚨 …and the take path reconciles an abandoned transaction ONCE, BEFORE taking ONCE "
              + "— which is only safe because the guard above says this consumer has no alert of "
              + "its own")
        let afterTake = (consume.range(of: theTake)?.upperBound) ?? consume.endIndex
        check(["showConfirm = true", "showResult = true"].allSatisfy {
                  countIn(consume, $0) == 1 && consume.range(of: $0, range: afterTake..<consume.endIndex) != nil
              },
              "🚨 …and it raises the prompt or the report EXACTLY ONCE EACH and ONLY AFTER a link "
              + "has been taken. Raising before the take leaves every consume() setting both "
              + "flags with nothing to show, which locks the guard at the top at `true` for ever "
              + "and the import path never runs again")

        // 🚨 AND EACH RAISE BELONGS TO ITS OWN BRANCH, WITH ITS PAYLOAD ALREADY
        // SET. Counting them and placing them after the take says nothing about
        // WHICH branch each sits in: swapping the two passes every check above
        // and inverts the feature — a valid link raises the RESULT alert over an
        // empty title and message and is never imported, while an invalid one
        // raises the CONFIRM alert whose `presenting: pending` is nil, so it
        // shows nothing at all. *(User-caught.)*
        //
        // ⚖️ The claim is READINESS BEFORE PRESENTATION, which also covers a
        // raise placed above its own payload inside the right branch — and it
        // deliberately does NOT pin `resultTitle` against `resultMessage`, since
        // their mutual order is free.
        if let d = consume.range(of: "do {"),
           let c = consume.range(of: "} catch {", range: d.upperBound..<consume.endIndex) {
            let success = String(consume[d.upperBound..<c.lowerBound])
            let failure = String(consume[c.upperBound..<consume.endIndex])
            check(inOrder(success, ["pending = try", "showConfirm = true"])
                  && !success.contains("showResult = true"),
                  "🚨 the SUCCESS branch parses into `pending` and only then raises the CONFIRM "
                  + "alert — which renders `presenting: pending`, so raising it first presents "
                  + "nothing, and raising the RESULT alert here inverts the feature")
            check(inOrder(failure, ["resultTitle =", "showResult = true"])
                  && inOrder(failure, ["resultMessage =", "showResult = true"])
                  && !failure.contains("showConfirm = true"),
                  "🚨 …and the FAILURE branch fills the title AND the message before raising the "
                  + "REPORT — a receipt raised over an empty message is a blank alert, and the "
                  + "confirm alert here would ask the user to import a link that did not parse")
            // 🚨 AND IT MUST NOT END THE TRANSACTION. Composing the complaint is
            // not the user reading it; ending here drops the link having told
            // them nothing at all.
            //
            // ⚖️ Folded into this branch split rather than kept as its own scan:
            // that one anchored the end of the region on `showResult = true`, so
            // a sabotage that moved THAT line made it report *"could not locate
            // the invalid-link branch"* — red for the wrong reason, which is the
            // failure mode this file has a section about. One region, one anchor.
            check(!failure.contains("markTerminal"),
                  "🚨 …and building the invalid-link message does NOT end the transaction — that "
                  + "happens when the user dismisses the message, not when it is composed")
        } else {
            check(false, "could not split consume() into its branches — the checks above would be vacuous")
        }
    } else {
        check(false, "could not find consume() — the checks above would be vacuous")
    }
    // 🚨 THE TWO HALVES OF SURVIVING A TORN-DOWN IMPORTER, and both are call
    // sites the harness cannot reach: an irreversible step must be ANNOUNCED, and
    // a fresh consumer must RECONCILE. Missing the first re-imports a deployment;
    // missing the second strands the link for the session.
    for (call, what) in [("inbox.markTerminal(.applied)", "the import"),
                         ("inbox.markTerminal(.declined)", "Cancel"),
                         ("inbox.markTerminal(.reported)", "the OK that closes a complaint")] {
        check(imp.components(separatedBy: call).count - 1 == 1,
              "🚨 \(what) ends the transaction in its OWN handler — a dismissal hook runs on a "
              + "view that survives, and the case that matters is the one that does not")
    }
    check(!content.contains("ConnectionLinkInbox"),
          "🚨 ContentView is not a second consumer of the inbox — two consumers race for one "
          + "pendingURL, so a prompt is swallowed or shown twice")
    check(!content.contains("handleConnectionLinkURL"),
          "and the dead URL handler is gone rather than left as an invitation to re-attach it")
    check(!content.contains("BackupManager.applyConnectionLink"),
          "🚨 ContentView does not apply a link itself")
    check(content.contains("ConnectionLinkPrompt.apply(link)")
          && content.contains("ConnectionLinkPrompt.importedTitle"),
          "…the paste path goes through the shared apply AND the shared title — sharing only "
          + "the wording is what let the apply step drift")
}

// ─────────────────────────────────────────────────────────────────────────────
print("What the app may CLAIM about the server, and the link queue")

// 34. 🚨 THE SELECTED SERVER IS NOT THE RUNNING ONE, AND THREE SURFACES USED TO
//     ANSWER THAT QUESTION SEPARATELY.
//
//     `ServerStore.activeServer` is what the NEXT connect will use. A tapped
//     connection link changes it with no reconnect anywhere, so while a tunnel
//     is up "Connected to <active server>" is a claim about a session that is
//     running something else. The card is the worse surface of the two: it
//     outlives the app, so the false sentence can sit on the Lock Screen.
//
//     ⚠️ NO RUN CAN COVER THIS. There is no VPN in the simulator, so `.connected`
//     is unreachable there, and on a device every case costs a reconnect cycle.
//     That is exactly why the rule is a value type driven by fixtures.
do {
    let alpha = NamedServer(id: UUID(), name: "Alpha")
    let beta = NamedServer(id: UUID(), name: "Beta")

    let idle = SessionServerLabel.caption(status: .disconnected, session: nil, selected: beta)
    check(idle.subtitle == "Server: Beta" && idle.cardName == "Beta" && idle.pendingSelection == nil,
          "with nothing running, the screen names the SELECTED server and says nothing else")

    let agreeing = SessionServerLabel.caption(status: .connected, session: alpha, selected: alpha)
    check(agreeing.subtitle == "Connected to Alpha" && agreeing.pendingSelection == nil,
          "a session whose server is still the selected one reads exactly as before")

    // 🚨 THE CASE THE TYPE EXISTS FOR.
    let diverged = SessionServerLabel.caption(status: .connected, session: alpha, selected: beta)
    check(diverged.subtitle == "Connected to Alpha",
          "🚨 an import that switches the selection under a LIVE tunnel does not rename what is "
          + "connected — the session runs what it was started with")
    check(diverged.cardName == "Alpha",
          "🚨 …and the Live Activity names the same server, not the selection")
    check(diverged.pendingSelection?.contains("Beta") == true,
          "…while the new selection IS surfaced, or the import reads as having done nothing")

    let unknown = SessionServerLabel.caption(status: .connected, session: nil, selected: beta)
    check(!unknown.subtitle.contains("Beta") && unknown.cardName.isEmpty,
          "🚨 attached to a tunnel of unknown provenance, it names NOTHING — falling back to the "
          + "selection here is the very claim being prevented")

    check(SessionServerLabel.caption(status: .connecting, session: beta, selected: beta).subtitle
            == "Connecting to Beta",
          "a starting session names the server it is starting")
    check(SessionServerLabel.caption(status: .disconnecting, session: alpha, selected: beta).subtitle
            == "Server: Beta",
          "…and a session on its way out stops claiming to be connected")

    // 🚨 SAME NAME, DIFFERENT PROFILE. `ServerStore.update` does not uniquify, so
    // a rename can produce two profiles called the same thing; comparing names
    // would call them equal and swallow the note.
    let twin = NamedServer(id: UUID(), name: "Alpha")
    check(SessionServerLabel.caption(status: .connected, session: alpha, selected: twin)
            .pendingSelection != nil,
          "🚨 the two are compared by ID — two profiles can carry one name after a rename")
}

// 35. 🚨 A QUEUE, NOT A SLOT. Only one link can be confirmed at a time, so a URL
//     arriving while an alert is up must wait — and with a single slot each new
//     arrival overwrote the waiting one, so of several links tapped in a row
//     only the last was ever acted on, silently. *(User-caught.)*
// ⚙️ The inbox is @MainActor (its only writers are `.onOpenURL` and a View), and
// top-level code here is not, so the fixtures run inside `assumeIsolated` — which
// is honest rather than a workaround: this harness IS the main thread.
MainActor.assumeIsolated {
    let inbox = ConnectionLinkInbox.shared
    // @MainActor because a nested func does not inherit the closure's isolation.
    @MainActor func reset() {
        inbox.finish()
        while inbox.take() != nil { inbox.finish() }
    }
    reset()   // a singleton: start from a known state

    let first = URL(string: "vkturnproxy://import?data=one")!
    let second = URL(string: "vkturnproxy://import?data=two")!
    inbox.deliver(first)
    inbox.deliver(second)
    check(inbox.queued.count == 2,
          "🚨 a second URL arriving under a live alert does not replace the first")
    check(inbox.take() == first, "…and they come back OLDEST first, in the order the user tapped them")
    check(inbox.take() == nil,
          "🚨 …one at a time: a second take cannot overwrite a transaction it knows nothing about")
    inbox.finish()
    check(inbox.take() == second, "…and the next one follows once the first is finished")
    reset()

    inbox.deliver(first)
    inbox.deliver(first)
    check(inbox.queued.count == 1,
          "a double-tap on ONE link is one intent while it WAITS")
    // 🚨 …AND WHILE IT IS OPEN, which is where the window used to end.
    _ = inbox.take()
    check(inbox.phase == .recoverable(first), "taking a link OPENS a transaction on it")
    inbox.deliver(first)
    check(inbox.queued.isEmpty,
          "🚨 a repeat of the link CURRENTLY BEING PROMPTED is refused — the dedupe window is "
          + "*queued or open*, not *queued*")
    inbox.markTerminal(.applied)
    inbox.deliver(first)
    check(inbox.queued.isEmpty,
          "…and still refused while the RESULT alert reports on it")
    inbox.finish()
    inbox.deliver(first)
    check(inbox.queued == [first],
          "🚨 …and the window CLOSES when the transaction ends: re-tapping the same link later "
          + "is a new intent, or that link would be un-importable for the rest of the session")
    reset()

    // 36. 🚨 THE IMPORTER'S @State DOES NOT OUTLIVE ITS IDENTITY AND THE INBOX
    //     DOES, so a transaction can be ABANDONED mid-flight — in this app by the
    //     very thing the importer was split out to survive, the NavigationView
    //     host re-rendering. The two phases must end DIFFERENTLY, and a flag
    //     cannot tell them apart: that is why this is a phase.
    //     *(User-caught; the previous round's comment called this "guarded" and
    //     nothing on that path called finish().)*
    inbox.deliver(first)
    _ = inbox.take()
    inbox.recoverIfAbandoned()          // the view vanished while CONFIRMING
    check(inbox.phase == .idle && inbox.queued == [first],
          "🚨 an unanswered prompt goes BACK to the queue — the user never saw an outcome, so "
          + "they must still get to answer it")
    check(inbox.take() == first, "…and the next importer is handed the same link")
    reset()

    inbox.deliver(second)
    inbox.deliver(first)
    _ = inbox.take()                    // opens on `second`
    inbox.recoverIfAbandoned()
    check(inbox.queued == [second, first],
          "…and it goes back at the FRONT, keeping its place ahead of what arrived behind it")
    reset()

    inbox.deliver(first)
    _ = inbox.take()
    inbox.markTerminal(.applied)        // the user tapped Import
    inbox.recoverIfAbandoned()          // …and THEN the view vanished
    check(inbox.phase == .idle && inbox.queued.isEmpty,
          "🚨🚨 a link that was already APPLIED is DROPPED, not re-offered — re-offering it "
          + "imports the same deployment a second time, and a flag that only says *in flight* "
          + "cannot tell the two apart")
    reset()

    // 🚨 THE TWO CASES THE PHASE WAS REFRAMED FOR. Neither is about
    // irreversibility — both are about whether the user has SEEN the outcome,
    // and the first cut got them wrong in opposite directions. *(User-caught.)*
    // ⚖️ WORDED FOR WHAT THIS ACTUALLY DRIVES. The inbox cannot tell an unreadable
    // link from an unanswered one — both are simply `recoverable` — so the claim
    // here is the inbox-level one, and what makes an unread COMPLAINT recoverable
    // is the importer not ending the transaction when it composes the message.
    // That is the scan above, not this fixture. *(Caught while writing it: the
    // first wording said "an UNREADABLE link", which is more than it covers —
    // the same trap as the three collected in feedback_tests_must_be_seen_to_fail.)*
    inbox.deliver(first)
    _ = inbox.take()
    inbox.recoverIfAbandoned()
    check(inbox.queued == [first],
          "a transaction still `recoverable` when its view died is offered again, whatever put "
          + "it in that phase")
    _ = inbox.take()
    inbox.markTerminal(.reported)       // now they have read it
    inbox.recoverIfAbandoned()
    check(inbox.queued.isEmpty,
          "…and once the complaint HAS been read it is dropped, not repeated")
    reset()

    inbox.deliver(first)
    _ = inbox.take()
    inbox.markTerminal(.declined)       // Cancel, in the button's own handler
    inbox.recoverIfAbandoned()
    check(inbox.queued.isEmpty,
          "🚨 a DECLINED link does not come back as a fresh prompt — Cancel ends it where it is "
          + "pressed, not in a dismissal hook the dying view never runs")
    reset()

    inbox.deliver(first)
    _ = inbox.take()
    inbox.markTerminal(.applied)
    inbox.markTerminal(.reported)       // the OK that closes the receipt
    check(inbox.phase == .terminal(first, .applied),
          "🚨 the FIRST reason wins — otherwise the button that merely closes a receipt would "
          + "relabel an import as a complaint, and the log would name the wrong cause")
    reset()

    // ⚖️ This one has NO sabotage of its own, and that is worth saying rather
    // than leaving to be assumed: every plausible way to break recovery (a
    // `default:` that re-queues `openURL` unconditionally, for instance) leaves
    // the idle case a no-op anyway, so it reddens under P5's sabotage or not at
    // all. It stays as a boundary assertion, not as a validated guard.
    inbox.recoverIfAbandoned()
    check(inbox.phase == .idle && inbox.queued.isEmpty,
          "recovering when nothing was abandoned does nothing (boundary; no sabotage of its own)")

    for i in 0..<(ConnectionLinkInbox.capacity + 4) {
        inbox.deliver(URL(string: "vkturnproxy://import?data=\(i)")!)
    }
    check(inbox.queued.count == ConnectionLinkInbox.capacity,
          "the queue is BOUNDED — a published property that can grow without limit is a queue "
          + "nobody bounded")
    check(inbox.queued.first == URL(string: "vkturnproxy://import?data=0")!,
          "…and it is the NEWEST that is refused: what is already queued was asked for first")
    reset()
}

// ─────────────────────────────────────────────────────────────────────────────
print("The Live Activity names the session, not the selection")

// 37. 🚨 BOTH PUBLISHERS OF THE CARD'S NAME GO THROUGH THE ONE SHARED RULE.
//
//     The card is the worst surface for the session-vs-selection confusion,
//     because it outlives the app: "Connected to <a server that is not
//     running>" can sit on the Lock Screen for hours. Two places publish it —
//     TunnelManager.syncLiveActivity and LiveActivityController.pushNow — and
//     both used to read `ServerStore.activeServer` directly.
//
//     ⚖️ GUARDED IN THE CODE, NOT IN THE PROSE. A reviewer found the widget
//     contract and the sync doc still describing the OLD rule, which is the
//     `873a927` species — a comment that argues for the defect. The comments are
//     fixed, but a scan over them cannot be the guard: the corrected text names
//     `ServerStore.activeServer` as the thing it is NOT, so a prose scan would
//     redden on correct code. What a later change would actually break is the
//     ARGUMENT, so that is what this pins.
//
//     🚨 And it pins it as COUNT PLUS SOURCE rather than as an absence: banning
//     `serverName: ServerStore` leaves `let n = ServerStore…; serverName: n`
//     wide open — the instance-shaped hole this file now has five instances of.
do {
    func bodyOf(_ src: String, _ decl: String) -> String? {
        guard let d = src.range(of: decl),
              let e = src.range(of: "\n    }", range: d.upperBound..<src.endIndex) else { return nil }
        return String(src[d.upperBound..<e.lowerBound])
    }
    let tm = codeWithoutComments("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    let lac = codeWithoutComments("VKTurnProxy/VKTurnProxy/LiveActivityController.swift")

    for (who, src, decl, expected) in [
        ("TunnelManager.syncLiveActivity", tm, "private func syncLiveActivity() {", "serverName: serverCaption.cardName"),
        ("LiveActivityController.pushNow", lac, "private func pushNow() {", "serverName: tunnel.serverCaption.cardName"),
    ] {
        guard let body = bodyOf(src, decl) else {
            check(false, "could not find \(who) — the check below would be vacuous")
            continue
        }
        check(body.components(separatedBy: "serverName:").count - 1 == 1 && body.contains(expected),
              "🚨 \(who) names the card from the shared caption and from nothing else — the "
              + "selection reaching this argument is a sentence about a session that is not "
              + "running, on a surface that outlives the app")
    }

    // …and the caption itself still refuses to fall back when the session is
    // unknown. The fixtures in §34 cover the rule; this covers the ONE call that
    // feeds it, because a caller passing `selected` as `session` would satisfy
    // every fixture while making the distinction vanish.
    guard let caption = bodyOf(tm, "var serverCaption: ServerCaption {") else {
        check(false, "could not find serverCaption — the check below would be vacuous")
        exit(1)
    }
    check(caption.contains("session: sessionServer") && caption.contains("selected: NamedServer("),
          "🚨 …and the caption is built with the SESSION in the session slot — passing the "
          + "selection there satisfies every fixture and erases the distinction entirely")
}

// ─────────────────────────────────────────────────────────────────────────────
print("DIRECT mode in Shortcuts (GitHub #78)")

// 38. 🚨 ONLY A CONFIRMATION IS SUCCESS.
//
//     Three of the five outcomes leave `directModeError` unset — the early exits
//     take it — so an intent that reported failure by looking for a published
//     error would answer "done" to an automation that changed nothing.
do {
    check(DirectOutcome.confirmed.automationFailure == nil,
          "a confirmed switch is the only success")
    for (outcome, what) in [(DirectOutcome.notConnected, "not connected"),
                            (.noManager, "no VPN profile loaded"),
                            (.busy, "already in flight"),
                            (.failed("the profile could not be saved"), "a failed save"),
                            (.unconfirmed("no answer from the tunnel"), "an unconfirmed switch")] {
        check((outcome.automationFailure ?? "").isEmpty == false,
              "🚨 \(what) fails the automation, with something to read")
    }
    check(DirectOutcome.failed("saving was refused").automationFailure == "saving was refused"
          && DirectOutcome.unconfirmed("no answer").automationFailure == "no answer",
          "…and the reason travels through rather than being replaced by a generic one")
    // 🚨 THESE TWO ARE NOT THE SAME SITUATION. `init` only starts an unawaited
    // load, so a background-launched intent can find no manager while the tunnel
    // is up — and answering "not connected" there is a lie about a live tunnel.
    // 🚨 …and the difference is not only what they SAY. With no manager the
    // tunnel's state is unknown, and publishing the initial `.disconnected` ends
    // a live card irreversibly from the background.
    check(DirectOutcome.noManager.tunnelStateIsKnown == false
          && [DirectOutcome.confirmed, .notConnected, .busy,
              .failed("x"), .unconfirmed("y")].allSatisfy(\.tunnelStateIsKnown),
          "🚨 only .noManager leaves the tunnel's state unknown — every other outcome has read "
          + "the profile, so refusing to publish on those would hide real changes")
    check(DirectOutcome.noManager.automationFailure != DirectOutcome.notConnected.automationFailure,
          "🚨 no profile loaded and not connected say DIFFERENT things — they were collapsed "
          + "into one answer, which told an automation the live tunnel was down")
}

// 39. 🚨 THE INTENT'S THREE STRUCTURAL DECISIONS, none of which shows up in a run.
do {
    func inOrder(_ body: String, _ steps: [String]) -> Bool {
        var from = body.startIndex
        for step in steps {
            guard let r = body.range(of: step, range: from..<body.endIndex) else { return false }
            from = r.upperBound
        }
        return true
    }
    let rs = codeWithoutComments("VKTurnProxy/VKTurnProxy/RoutingShortcuts.swift")
    check(rs.contains("struct SetDirectRoutingIntent: AppIntent") && !rs.contains("LiveActivityIntent"),
          "🚨 it is an AppIntent, NOT a LiveActivityIntent — that one forwards to a handler the "
          + "app installs at launch, which is a silent no-op when an automation fires while the "
          + "app is not running")
    check(rs.contains("static var openAppWhenRun: Bool = false"),
          "🚨 …and it does not open the app: an automation fires while the user is opening "
          + "something else")
    // 🚨 AND IT AWAITS STRAIGHT THROUGH. An earlier version boxed the await at
    // 12 s and let the work run on, which has it backwards: with no scene the
    // process lives exactly as long as perform() has not returned, so an early
    // return is what abandons the leak repair — a reconnect that outlasts any
    // box worth putting on a Shortcut. The form that closes the class is having
    // no concurrency machinery here at all.
    check(!rs.contains("withTaskGroup") && !rs.contains("Task.sleep") && !rs.contains("Task {"),
          "🚨 …and nothing races or boxes the call: with openAppWhenRun false the process is "
          + "alive only while perform() runs, so returning early is what kills the leak repair")
    check(inOrder(rs, ["ensureManagerLoaded()", "setDirectMode("]),
          "🚨 …and it waits for the VPN manager BEFORE asking — init only kicks off an unawaited "
          + "load, and a background-launched intent asks first and would be told, wrongly, that "
          + "the tunnel is not connected")
    check(rs.contains("from: .shortcut"),
          "the change is attributed to Shortcuts in the log, like every other call site")
    // 🚨 The default authenticationPolicy is .alwaysAllowed — Apple defines it as
    // running on a LOCKED device. Turning the VPN's protection off is not a
    // decision to inherit from a default.
    check(rs.contains("static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication"),
          "🚨 …and it does not run from a locked device: the policy is stated, not defaulted")
    // 🚨 Same suspension the Live Activity's button has: perform() returns, the
    // process goes away, and an unawaited card push never lands.
    check(inOrder(rs, ["Self.apply(direct)",
                       "outcome.tunnelStateIsKnown",
                       "await LiveActivityController.shared.refreshNowAndWait()"]),
          "🚨 …and it AWAITS the card refresh after the change and ONLY when the tunnel's state "
          + "is known — refreshDirectMode calls the unawaited push, and publishing an unknown "
          + "state ENDS the card, which cannot be undone from the background")

    let tm = codeWithoutComments("VKTurnProxy/VKTurnProxy/TunnelManager.swift")
    // Counted, not spelled: the invariant is that NOBODY reaches loadManager()
    // except the single-flight wrapper, so a new caller anywhere reddens. Two
    // occurrences = its own declaration plus that one call.
    check(tm.contains("if let inFlight = managerLoad {")
          && tm.components(separatedBy: "loadManager()").count - 1 == 2,
          "🚨 …and the manager load is SINGLE-FLIGHT, joined rather than restarted, with "
          + "ensureManagerLoaded its ONLY caller: the first repair of the race started a second "
          + "concurrent loadAllFromPreferences instead of awaiting the one already running")
}

print("")
if failures == 0 {
    print("swiftcheck: all checks passed")
    exit(0)
}
print("swiftcheck: \(failures) FAILED")
exit(1)
