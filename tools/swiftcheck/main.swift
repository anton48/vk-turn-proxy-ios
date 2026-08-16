// A standalone check for the app's dependency-free invariants, compiled against
// the REAL source files rather than copies:
//
//   swiftc VKTurnProxy/VKTurnProxy/UplinkChunk.swift \
//          VKTurnProxy/VKTurnProxy/ProbeDuration.swift \
//          VKTurnProxy/VKTurnProxy/LoadWitness.swift \
//          VKTurnProxy/VKTurnProxy/LoadProgress.swift \
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
    func judge(_ moved: UInt64, _ worstGap: Int, _ up: Bool,
               _ live: Int = 8, _ want: Int = 8) -> LoadWitness.Verdict {
        LoadWitness.judge(movedBytes: moved, worstGapMs: worstGap, probeStillRunning: up,
                          liveFlows: live, wantFlows: want, staleMs: stale)
    }

    check(judge(1 << 20, 100, true) == .ok, "moving, fresh, alive => ok")

    // 🚨 THE CASE "SOME BYTES MOVED" LET THROUGH: a probe that sent for a second
    // and then died leaves a big positive delta across the whole arm.
    check(judge(64 << 20, 118_000, true) == .stalled(ms: 118_000),
          "a big delta does NOT excuse a 118 s hole inside the arm")
    check(judge(1, stale + 1, true) == .stalled(ms: stale + 1), "one ms past the bound is stale")
    check(judge(1 << 20, stale, true) == .ok, "the bound itself is not stale")

    check(judge(0, 0, true) == .noBytes, "nothing moved => noBytes, whatever the clock says")
    check(judge(0, 100, false) == .noBytes,
          "noBytes outranks ended - what it failed to do beats when it stopped")
    check(judge(1 << 20, 100, false) == .ended, "fresh bytes but the probe is gone => ended")

    // 🚨 THE POPULATION, WHICH EVERY AGGREGATE ABOVE IS BLIND TO. `connectAll`
    // rejected only a pool of ZERO and a sender dying on a socket error just
    // broke out of its loop, so 7 of 8 flows could be gone while bytes, gaps and
    // lifecycle all read perfectly on the strength of the last one — and the
    // neighbour's INTENSITY is the treatment (0/8/16 flows gave 0.001/1.08/2.4%
    // collateral loss), so that is a DIFFERENT ARM.
    check(judge(64 << 20, 100, true, 7, 8) == .shortPool(live: 7, want: 8),
          "one flow short is a different arm, however healthy the bytes look")
    check(judge(64 << 20, 100, true, 8, 8) == .ok, "a full pool with healthy bytes is ok")

    // It outranks the others BECAUSE IT EXPLAINS THEM — reporting a downstream
    // symptom sends the reader to the wrong place.
    check(judge(0, 999_999, false, 0, 8) == .shortPool(live: 0, want: 8),
          "an empty pool is reported as such, not as noBytes/ended/stalled")

    // 🚨 AND WHAT THE ARM ACTUALLY WAS MUST TRACK THE VERDICT, not be a fixed
    // suffix. "A SOLO arm in disguise" is true of an arm that carried nothing
    // and FALSE of one that carried 7 of 8 flows — that one is a different
    // INTENSITY, which in this experiment is a different arm.
    //
    // SABOTAGE SEEN TO FAIL: return "a SOLO arm in disguise" for every case.
    // Compiles, and the 7-of-8 check goes red.
    check(!LoadWitness.mislabel(.shortPool(live: 7, want: 8)).contains("SOLO"),
          "7 of 8 flows is a different INTENSITY, not a solo arm")
    check(LoadWitness.mislabel(.shortPool(live: 0, want: 8)).contains("SOLO"),
          "…but a pool of zero really is solo")
    check(LoadWitness.mislabel(.noBytes).contains("SOLO"), "nothing moved is solo")

    // Every verdict must be able to SAY itself, or a void arm reaches the log
    // with no reason attached.
    for v: LoadWitness.Verdict in [.noBytes, .ended, .stalled(ms: 5), .shortPool(live: 3, want: 8), .ok] {
        check(!LoadWitness.reason(v).isEmpty, "the verdict has a reason string")
    }
}

// 9. 🚨 THE GAP WATERMARK — the quantity that actually means "throughout".
//    Freshness at the arm's END passed `1 s of load / 117 s of nothing / 2 s of
//    load`: positive delta, live probe, fresh last byte, 98% solo. Driven here
//    with a FAKE MONOTONIC CLOCK so the arithmetic is exact and nothing sleeps.
//
//    SABOTAGE SEEN TO FAIL: in `advance`, use `lastAdvanceNs` alone as the
//    reference instead of `max(lastAdvanceNs, windowStartNs)`. Compiles, and the
//    charge-from-window-start check goes red — a gap that began in the previous
//    arm would then be billed to this one in full.
do {
    var clockNs: UInt64 = 1_000_000_000          // never starts at 0
    let sec: (Double) -> UInt64 = { UInt64($0 * 1_000_000_000) }
    let p = LoadProgress(clock: { clockNs })

    p.reset()
    p.openWindow()

    // The arm that used to pass: one second of load, then a long hole, then a
    // late burst that leaves the END looking perfect.
    p.advance(by: 1 << 20)
    clockNs += sec(1)
    p.advance(by: 1 << 20)
    clockNs += sec(117)                           // the hole
    p.advance(by: 1 << 20)
    clockNs += sec(2)
    p.advance(by: 1 << 20)

    let a = p.snapshot()
    check(a.idleMs == 0, "the last byte is fresh — which is exactly why idle cannot decide")
    check(a.worstGapMs == 117_000, "the 117 s hole is what the arm actually suffered (got \(a.worstGapMs))")
    check(LoadWitness.judge(movedBytes: a.bytes, worstGapMs: a.worstGapMs,
                            probeStillRunning: true, liveFlows: 8, wantFlows: 8,
                            staleMs: 2000) == .stalled(ms: 117_000),
          "…and the verdict is stalled, where freshness said ok")

    // A NEW ARM MUST NOT INHERIT IT, or one bad arm condemns the rest of the run.
    p.openWindow()
    clockNs += sec(0.1)
    p.advance(by: 1 << 20)
    check(p.snapshot().worstGapMs == 100, "openWindow restarts the watermark (got \(p.snapshot().worstGapMs))")

    // A gap STILL OPEN at the end counts — it is the case the end-of-arm check
    // did catch, and it must survive the change.
    clockNs += sec(30)
    check(p.snapshot().worstGapMs == 30_000, "an open gap is charged without waiting for it to close")
    check(p.snapshot().idleMs == 30_000, "and it is the idle time too")

    // A gap that began BEFORE the window is charged only from the window's start.
    p.openWindow()
    clockNs += sec(5)
    p.advance(by: 1 << 20)
    check(p.snapshot().worstGapMs == 5_000,
          "the pre-window part of a gap belongs to the previous arm (got \(p.snapshot().worstGapMs))")

    // Totals accumulate across windows; only the watermark restarts.
    check(p.snapshot().bytes == 6 << 20,
          "openWindow leaves the byte total alone (got \(p.snapshot().bytes >> 20) MiB of 6)")

    // 🚨 A CLOCK THAT NEVER MOVES MUST NOT INVENT A STALL. On a monotonic clock
    // that is the only degenerate case; on `Date()` a backward NTP step would
    // have produced a NEGATIVE idle that compares as fresh.
    p.openWindow()
    check(p.snapshot().worstGapMs == 0, "no elapsed time, no gap")
}


// ─── section 10: the run's two EXITS must restore the same way ──────────────
//
// 🚨 WHY A SOURCE SCAN AND NOT A BEHAVIOUR TEST. The runner cannot be built
// standalone (it needs TunnelManager, the probe, the log), and the property is
// SILENT: an aborted run that forgets to restore looks exactly like one that did,
// until someone notices the tunnel is unpaced while Settings shows the switch on.
// That is precisely what shipped in build 296 — the normal exit restored the
// setting and `abortRun` still called `setPace(0)`, and the closing line claimed
// "restored to 0" on both paths. *(User-caught.)*
func checkPaceRunnerRestore() {
    let path = "VKTurnProxy/VKTurnProxy/UplinkPaceRunner.swift"
    guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else {
        check(false, "section 10: cannot read \(path)"); return
    }
    // 🚨 SCAN THE CODE, NOT THE PROSE ABOUT IT. Both of these assertions failed on
    // CORRECT code the first time they ran, because the comments explaining why the
    // old refusal was removed quote its old reason verbatim, and the comment
    // explaining the two-reads defect names `applyUplinkPaceFromSettings`. A
    // source scan that reads comments tests the documentation. Same family as the
    // guard that once matched a function's own declaration.
    let src = raw.split(separator: "\n", omittingEmptySubsequences: false)
        .map { line -> String in
            guard let r = line.range(of: "//") else { return String(line) }
            return String(line[line.startIndex..<r.lowerBound])
        }
        .joined(separator: "\n")
    // 1. Exactly one restore helper, and both exits go through it.
    let restores = src.components(separatedBy: "restoreAfterRun()").count - 1
    check(restores >= 3,
          "section 10: expected the restore helper plus a call from EACH exit "
          + "(abort and done); found \(restores) mentions of restoreAfterRun()")
    // 2. No exit may force the pacer off behind the setting's back.
    let afterHelper = src.range(of: "func restoreAfterRun()").map { String(src[$0.upperBound...]) } ?? src
    check(!afterHelper.contains("setPace(0); setLevel(0); setSplit(0)"),
          "section 10: an exit path still calls setPace(0) directly — an aborted run "
          + "would leave the tunnel unpaced while the Settings switch still shows ON")
    // 3. The closing line must be DERIVED, not a hand-written claim.
    check(!src.contains("restored to 0."),
          "section 10: the log still hard-codes \"restored to 0\", which is false "
          + "whenever the setting is ON — the summary must come from the restore")
    // 4. The obsolete SRTP refusal must be gone: its stated reason is false since 296.
    check(!src.contains("pacer is wired into the SRTP writer only"),
          "section 10: the SRTP refusal is back, and its reason is false — all four "
          + "writer loops reserve since build 296")
    // 5. ...but LEGACY must still be refused, and for the SCORER's reason. `.legacy`
    //    is raw DTLS+WG with no RTP wrapper, and B-loss is counted purely from outer
    //    RTP sequence gaps — so such a run burns nine minutes and cannot be scored.
    //    The predicate must be the RTP one, not `useSrtp` alone.
    check(src.contains("server.useSrtp || server.useWrap || server.useWrapA || server.useWrapS"),
          "section 10: the outer-RTP predicate is missing — either Legacy is admitted "
          + "(unscorable: no RTP to count gaps in) or the WRAP modes are refused for "
          + "no reason")
    check(src.contains("guard hasOuterRTP else"),
          "section 10: nothing refuses a mode without an outer RTP header")
    // 6. The restore must take ONE snapshot: reading the setting and sending the
    //    command in the same block, not a read here and a second read on main.
    let restoreBody: String = {
        guard let a = src.range(of: "func restoreAfterRun()"),
              let b = src.range(of: "func abortRun(", range: a.upperBound..<src.endIndex)
        else { return "" }
        return String(src[a.upperBound..<b.lowerBound])
    }()
    check(!restoreBody.isEmpty, "section 10: cannot isolate restoreAfterRun()")
    check(!restoreBody.contains("applyUplinkPaceFromSettings"),
          "section 10: the restore delegates to the re-reading form, so the value it "
          + "REPORTS and the value it SENDS come from two different reads of a switch "
          + "the user can flip in between")
    check(restoreBody.contains("DispatchQueue.main.sync"),
          "section 10: the restore does not read and send in one synchronous block, so "
          + "its return value need not describe the command it issued")
    // 7. The sentence may only claim what was SENT: the provider message is
    //    fire-and-forget, so "restored" is a promise the code cannot keep.
    check(restoreBody.lowercased().contains("requested"),
          "section 10: the restore line claims a completed restore, but the provider "
          + "message is fire-and-forget — it can only report what was requested")
}

print("section 10: the pace runner's two exits")
checkPaceRunnerRestore()

print(failures == 0 ? "PASS" : "FAIL (\(failures))")
exit(failures == 0 ? 0 : 1)
