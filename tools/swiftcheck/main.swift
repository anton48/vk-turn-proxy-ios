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

print("")
if failures == 0 {
    print("swiftcheck: all checks passed")
    exit(0)
}
print("swiftcheck: \(failures) FAILED")
exit(1)
