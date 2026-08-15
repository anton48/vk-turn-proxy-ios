// A standalone check for the app's dependency-free invariants, compiled against
// the REAL source files rather than copies:
//
//   swiftc VKTurnProxy/VKTurnProxy/UplinkChunk.swift \
//          VKTurnProxy/VKTurnProxy/ProbeDuration.swift \
//          VKTurnProxy/VKTurnProxy/LoadWitness.swift \
//          VKTurnProxy/VKTurnProxy/DiagnosticRunLock.swift \
//          tools/swiftcheck/main.swift -o /tmp/chunkcheck && /tmp/chunkcheck
//
// (the compile line lists every source it asserts about; leaving one out is a
// link error, not a silent skip, which is the property that keeps it honest)
//
// (the file is named main.swift because Swift allows top-level code in that one
// file only, and a multi-file compile rejects it anywhere else)
//
// 🚨 WHY IT IS NOT AN XCTest. The app has no test target, and adding one touches
// the scheme that `install.sh` and `release.sh` drive — not something to change
// in the middle of a measurement series. `UplinkChunk` depends on Foundation
// only, so it compiles standalone, and this file is the whole harness.
//
// WHAT IT GUARDS, and why each half matters:
//  • the stale value IS cleared — the defect that ran K=64 for three days;
//  • it is cleared exactly ONCE — otherwise a deliberate re-arm through the
//    `uplinkChunkK` backup field would be undone at the next launch, and that
//    field is the only way back in now that the picker is gone.
// Getting either half wrong is silent on the device: one leaves the tunnel
// chunking, the other makes the documented re-arm path quietly dead.

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

// 1. A device that had touched the deleted picker: the value is cleared, once,
//    and the clearing is announced rather than silent.
do {
    let d = freshDefaults("chunkcheck.stale")
    d.set(64, forKey: UplinkChunk.key)

    var logged: [String] = []
    let fired = UplinkChunk.clearStaleValueOnce(in: d, log: { logged.append($0) })

    check(fired, "a stale K is cleared")
    check(UplinkChunk.stored(in: d) == UplinkChunk.off, "K reads as off after the reset")
    check(logged.count == 1 && logged[0].contains("64"),
          "the reset is announced and names the value it removed")
}

// 2. It must not fire twice. A deliberate re-arm through the backup field is the
//    only remaining way to drive this machinery, and a migration that ran every
//    launch would silently undo it.
do {
    let d = freshDefaults("chunkcheck.rearm")
    d.set(64, forKey: UplinkChunk.key)
    _ = UplinkChunk.clearStaleValueOnce(in: d)

    d.set(32, forKey: UplinkChunk.key) // a deliberate re-arm, after the migration
    let firedAgain = UplinkChunk.clearStaleValueOnce(in: d)

    check(!firedAgain, "the migration does not fire a second time")
    check(UplinkChunk.stored(in: d) == 32, "a deliberate re-arm survives")
}

// 3. A device that never touched the picker is left alone — and still gets the
//    marker, so the migration cannot fire later against a deliberate value.
do {
    let d = freshDefaults("chunkcheck.clean")
    let fired = UplinkChunk.clearStaleValueOnce(in: d)

    check(!fired, "nothing to clear on a clean install")
    check(UplinkChunk.stored(in: d) == UplinkChunk.off, "K is off on a clean install")

    d.set(64, forKey: UplinkChunk.key)
    check(!UplinkChunk.clearStaleValueOnce(in: d), "the marker was set even with nothing to clear")
    check(UplinkChunk.stored(in: d) == 64, "so a value set afterwards is left alone")
}

// 4. K = 1 stored explicitly is not "stale" — it is production, and clearing it
//    would be a no-op that still burns the one-shot marker.
do {
    let d = freshDefaults("chunkcheck.explicit-off")
    d.set(UplinkChunk.off, forKey: UplinkChunk.key)
    check(!UplinkChunk.clearStaleValueOnce(in: d), "an explicit K=1 is not treated as stale")
}

// ---------------------------------------------------------------------------
// DiagnosticRunLock — the guard added after a device run was taken TWICE.
// ---------------------------------------------------------------------------

// 5. A second run cannot start while one holds the lock, and the refusal can
//    name what is running — which is the whole point of holding a name rather
//    than a bool.
do {
    check(DiagnosticRunLock.acquire("pairedab"), "the first run takes the lock")
    check(!DiagnosticRunLock.acquire("synthab"), "a second run is refused")
    check(DiagnosticRunLock.current == "pairedab", "the refusal can name the holder")

    // A non-holder must not be able to free it — otherwise the second runner's
    // own `defer` would release the FIRST one's lock on its way out, and the
    // guard would be undone by the very attempt it just refused.
    DiagnosticRunLock.release("synthab")
    check(DiagnosticRunLock.current == "pairedab", "a non-holder cannot release it")

    DiagnosticRunLock.release("pairedab")
    check(DiagnosticRunLock.current == nil, "the holder releases it")
    check(DiagnosticRunLock.acquire("synthab"), "and the next run can then start")
    DiagnosticRunLock.release("synthab")
}

// 6. 🚨 THE RACE THIS EXISTS FOR: two taps arriving at once. Exactly one may win,
//    however many threads ask.
do {
    let winners = NSMutableArray()
    let guardLock = NSLock()
    DispatchQueue.concurrentPerform(iterations: 64) { i in
        if DiagnosticRunLock.acquire("run\(i)") {
            guardLock.lock(); winners.add(i); guardLock.unlock()
        }
    }
    check(winners.count == 1, "exactly one of 64 concurrent starts wins (got \(winners.count))")
    if let w = winners.firstObject as? Int { DiagnosticRunLock.release("run\(w)") }
    check(DiagnosticRunLock.current == nil, "and the winner can release it")
}

// 7. 🚨 THE PROBE'S DURATION BOUND. It was an inline `min(durationSec, 120)`
//    written when the probe was hand-driven from a 5-60 s picker; the split
//    runner asks for ~1229 s and keeps ONE probe alive across arms 3-6, so the
//    clamp would have killed the real load 108 s into arm 3 and left two SPLIT
//    arms and a COLOCATED one — the measurement itself — carrying no neighbour.
//
//    ⚠️ WHAT IS *NOT* ASSERTED HERE, deliberately: "the ceiling clears the
//    longest runner request". An earlier version kept a copy of that length in
//    ProbeDuration so this file could compare the two — a second copy of
//    something that already has an owner, which is the defect class that put
//    three of today's bugs in the log. The runner asks `clamps(_:)` about its
//    OWN computed request at STEP 0 and refuses to start; only the clamp's own
//    semantics live here.
//
//    SABOTAGE SEEN TO FAIL: make `clamps` return `sec > maxSec` only. Compiles,
//    and the floor half goes red — a zero-second run would then be started
//    without a word.
do {
    // The bound has to BE a bound; the point was never to remove it.
    check(ProbeDuration.clamp(ProbeDuration.maxSec + 1) == ProbeDuration.maxSec,
          "a value past the ceiling is clamped")
    check(ProbeDuration.clamp(ProbeDuration.maxSec) == ProbeDuration.maxSec,
          "the ceiling itself survives")
    check(ProbeDuration.clamp(0) == ProbeDuration.minSec, "zero is not a shorter run")
    check(ProbeDuration.clamp(-5) == ProbeDuration.minSec, "nor is a negative one")

    // 🚨 AND THE CLAMP MUST BE ANNOUNCEABLE. The failure mode is SILENCE — a
    // shortened run reads exactly like a completed one — so `clamps(_:)` has to
    // agree with `clamp(_:)` in BOTH directions: never missing, never noise.
    check(ProbeDuration.clamps(ProbeDuration.maxSec + 1), "past the ceiling is reported")
    check(ProbeDuration.clamps(0), "below the floor is reported")
    check(!ProbeDuration.clamps(ProbeDuration.maxSec), "the ceiling itself is not a clamp")
    check(!ProbeDuration.clamps(ProbeDuration.minSec), "nor is the floor")
    for sec in [ProbeDuration.minSec, 60, 1229, ProbeDuration.maxSec] {
        check(ProbeDuration.clamps(sec) == (ProbeDuration.clamp(sec) != sec),
              "clamps(\(sec)) agrees with clamp(\(sec))")
    }
}

// 8. 🚨 THE LOAD WITNESS. The arm's neighbour IS the treatment, so an arm that
//    ran without one is a solo arm wearing a loaded label — and it scores as a
//    loaded one, quietly. Three ways to be unloaded, each a separate shipped
//    defect.
//
//    SABOTAGE SEEN TO FAIL: delete the `idleMs > staleMs` case. Compiles, and
//    the "moved then died" checks go red — which is exactly the arm that sends
//    for one second and idles for the other 119.
do {
    let stale = 2000
    func judge(_ moved: UInt64, _ idle: Int, _ up: Bool) -> LoadWitness.Verdict {
        LoadWitness.judge(movedBytes: moved, idleMs: idle, probeStillRunning: up, staleMs: stale)
    }

    check(judge(1 << 20, 100, true) == .ok, "moving, fresh, alive => ok")

    // 🚨 THE CASE "SOME BYTES MOVED" LET THROUGH: a probe that sent for a second
    // and then died leaves a big positive delta across the whole arm.
    check(judge(64 << 20, 118_000, true) == .stalled(ms: 118_000),
          "a big delta does NOT excuse a load that stopped 118 s ago")
    check(judge(1, stale + 1, true) == .stalled(ms: stale + 1), "one ms past the bound is stale")
    check(judge(1 << 20, stale, true) == .ok, "the bound itself is not stale")

    check(judge(0, 0, true) == .noBytes, "nothing moved => noBytes, whatever the clock says")
    check(judge(0, 100, false) == .noBytes,
          "noBytes outranks ended - what it failed to do beats when it stopped")
    check(judge(1 << 20, 100, false) == .ended, "fresh bytes but the probe is gone => ended")

    // Every verdict must be able to SAY itself, or a void arm reaches the log
    // with no reason attached.
    for v: LoadWitness.Verdict in [.noBytes, .ended, .stalled(ms: 5), .ok] {
        check(!LoadWitness.reason(v).isEmpty, "the verdict has a reason string")
    }
}

print(failures == 0 ? "PASS" : "FAIL (\(failures))")
exit(failures == 0 ? 0 : 1)
