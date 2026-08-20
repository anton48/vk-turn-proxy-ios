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
    let switchFn = tunnel.range(of: "func switchAndReconnect(")
    let switchBody = switchFn.map { String(tunnel[$0.lowerBound...].prefix(900)) } ?? ""
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

print("")
if failures == 0 {
    print("swiftcheck: all checks passed")
    exit(0)
}
print("swiftcheck: \(failures) FAILED")
exit(1)
