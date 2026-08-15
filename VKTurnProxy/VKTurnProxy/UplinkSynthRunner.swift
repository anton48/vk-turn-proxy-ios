import Foundation

/// Drives the uplink-loss DOSE-RESPONSE end to end: it holds the connection pool
/// at a series of fixed loads and lets the server measure, from WireGuard's own
/// counter space, whether the loss moves with the level.
///
/// 🎯 THE QUESTION IT ANSWERS. On 2026-08-14 the loss the server measures
/// (`lost` / `cum-lost`) came back at 1.16% with the access link excluded (the
/// naked control lost 0.02% while the tunnel lost 2.15%), server1's UDP socket
/// excluded (`netstat-watch`: Recv-Q max 112 B), wireguard-go excluded (its
/// inbound send is blocking, so the kernel would drop and be counted) and our
/// transport excluded (`sendch-block` ~0) — leaving the phone → VK relay →
/// server1 leg. What is NOT settled is whether VK's per-allocation meter does
/// it. Loss per packet was FLAT across load buckets, which refutes a simple rate
/// clip, but a token bucket clips on burst structure that a 2-second average
/// cannot resolve. Holding a level and watching the loss is what separates them:
///
///  • loss flat across ~30 / ~60 / ~95% of the knee ⇒ **a meter that is never
///    emptied cannot be the cause**, and the policer dies as the location in
///    every form — the pacer question dies with it;
///  • loss near zero at 30% and rising toward 95% ⇒ consistent with the bucket,
///    and pacing the uplink becomes the direct answer;
///  • bursty and level-independent but present even at 30% ⇒ the same verdict as
///    the first branch, pointing at the relay's buffers or the leg itself.
///
/// ⚠️ ONE-SIDED BY CONSTRUCTION: it can KILL the meter, not confirm it. Loss
/// rising with load is consistent with any load-dependent mechanism.
///
/// 🚨 WHY A SYNTHETIC AND NOT THE cwnd PROBE, which is the whole reason this
/// runner is separate from `UplinkFlowABRunner`: **TCP cannot hold a level.** Its
/// congestion control ramps until it meets something, which is why per-connection
/// load wandered 28-101% of the knee inside one `udptest6` run. A dose-response
/// needs the dose to be a constant, and only a paced generator gives one.
///
/// 🚨 AND WHY THE ARMS ARE SCORED ON `cum-lost`, NOT ON `lost`. The interval
/// counter is DEFERRED: a counter is only called lost once the dup window has
/// slid past it, which is 8128 packets — at 19 Mbit/s about 4.5 seconds. So the
/// tail of every arm's loss lands in the NEXT arm's ticks, and summing `lost`
/// per arm would smear each level into its successor. `cum-lost` is span minus
/// arrivals, so the DIFFERENCE across an arm's boundaries carries no deferral at
/// all. The gap between arms exists for the other half of the same problem: it
/// lets the packets in flight at the boundary land before the next reading.
final class UplinkSynthRunner: ObservableObject {
    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// 🚨 THE PLAN IS PRE-REGISTERED AND IS NOT A KNOB.
    ///
    /// With `passes = 2` and the order reversed on the second pass, this list
    /// produces **40 · 55 · 58 · 59 · 60 · 60 · 59 · 58 · 55 · 40** — a RAMP UP
    /// AND BACK DOWN, which is a different experiment from the first sweep and a
    /// better one for the question that survived it.
    ///
    /// 🎯 **WHY A RAMP: IT IS A HYSTERESIS PROBE.** The 08-15 runs left exactly
    /// one form of VK's meter alive — a token bucket — and the signature that
    /// separates a bucket from a plain rate limit is **memory**: a bucket
    /// emptied at 60 is still empty when the load comes back down to 59 and 58,
    /// so the DOWN arm at a level must lose more than the UP arm at the same
    /// level. A rate limit has no memory and the two arms must match. **The
    /// paired comparison is arm 4 vs arm 7 (59), arm 3 vs arm 8 (58), arm 2 vs
    /// arm 9 (55), arm 1 vs arm 10 (40)** — score those pairs, not the levels
    /// in isolation.
    ///
    /// 🚨 **WHAT THE RAMP GIVES UP, stated because it is a real cost.** The
    /// reversal used to be drift control: each level appeared once early and
    /// once late, so a session that got worse over time loaded on no level in
    /// particular. In a palindrome the SEPARATION IS UNEQUAL — 40 is measured
    /// first and last, while the two 60 arms are ADJACENT. So the top level, the
    /// one we care most about, has the worst protection against drift, and the
    /// naked controls at both ends are the only guard on it. Take them.
    ///
    /// ⚠️ **And the levels are packed where the resolution is worst.** 58/59/60
    /// are 3% apart in offered rate while the per-arm loss at that level varied
    /// **10× between two arms of the same level** on 08-15 (961 against 87). So
    /// this plan can show a MONOTONE TREND across 40 → 60 and a hysteresis gap
    /// between up and down; it cannot resolve 58 from 59 from 60 on one session.
    /// Do not read a difference between adjacent top levels as a finding.
    ///
    /// ⚠️ The percentages assume the shipped NumConns = 30: 40/55/58/59/60
    /// Mbit/s are roughly **66 / 90 / 95 / 97 / 98%** of the knee in WIRE bytes.
    /// The SERVER's per-conn dump is what says which fraction was really
    /// reached — never this list.
    private let levels: [Double] = [40, 55, 58, 59, 60]

    /// 120 s per arm. Long enough that a ~1% loss made of bursts (67% of it
    /// arrived in 4 of 36 ticks on the run that motivated this) has many bursts
    /// to average over: at 19 Mbit/s that is ~216 000 packets per arm.
    private let armSec = 120

    /// Two passes with the level order REVERSED. With the ramp above this is
    /// what makes the sequence a palindrome — the second pass IS the way back
    /// down, and each level's up-arm and down-arm are the pair to compare.
    private let passes = 2

    /// Between arms: long enough for the packets in flight at the boundary to
    /// land, so the `cum-lost` read that closes one arm is not still counting
    /// them. At ~120 ms RTT a second is ample; 8 gives margin and keeps each
    /// boundary unambiguous in the log.
    private let gapSec = 8

    /// A first arm nobody scores, which absorbs the generator's one-off wait for
    /// the connection pool.
    ///
    /// 🚨 THIS IS THE "WAIT FOR BYTES, NOT FOR THE CALL" LESSON, and it cost two
    /// runs on 2026-08-13 in the other runner: the Go side waits for ≥90% of the
    /// pool before its first packet, and that wait is invisible from here. Put
    /// it in an arm whose number nobody uses.
    private let warmupSec = 25

    var estimatedSeconds: Int {
        warmupSec + passes * levels.count * (armSec + gapSec)
    }

    func start() {
        guard !running else { return }
        running = true
        cancelledFlag.set(false)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run()
        }
    }

    /// Stops the LOAD as well as the schedule — the defect the flow runner had
    /// on its first outing, where Stop set a flag and left the traffic running
    /// for up to a whole arm.
    func cancel() {
        cancelledFlag.set(true)
        setLevel(0)
    }

    /// 🚨 STEP 0 — REFUSE RATHER THAN SPEND THIRTEEN MINUTES ON NOTHING. The
    /// generator needs the pool up: the Go side waits for ≥90% of it and gives
    /// up if it never arrives, and a plan started before the ramp finishes would
    /// score its first arms against an idle link. This is the same discipline as
    /// the flow runner's `pref < 50%` gate — a run that could not have measured
    /// anything must not be filed as a null.
    ///
    /// ⚠️ `statsReceivedOnce` is checked FIRST and separately, because until a
    /// reply has arrived `activeConns` is the all-zero initial value: that zero
    /// is the ABSENCE OF AN ANSWER, not an answer of zero, and treating it as
    /// one is a trap this codebase has already documented on the stats object
    /// itself.
    private func poolReady() -> (ok: Bool, why: String) {
        var received = false
        var active: Int32 = 0
        var total: Int32 = 0
        DispatchQueue.main.sync {
            let live = TunnelManager.shared.live
            received = live.statsReceivedOnce
            active = live.stats.activeConns
            total = live.stats.totalConns
        }
        if !received {
            return (false, "the extension has not answered a stats poll yet — "
                + "is the tunnel connected?")
        }
        if total <= 0 || active <= 0 {
            return (false, "no connections are up (\(active)/\(total))")
        }
        if Double(active) < 0.9 * Double(total) {
            return (false, "only \(active) of \(total) connections are up; the ramp takes "
                + "~107 s for 30, and the generator refuses below 90% anyway")
        }
        return (true, "\(active)/\(total) connections")
    }

    /// 🚨 STEP 0b — REFUSE RATHER THAN RUN A PLAN NOBODY WROTE.
    ///
    /// `UplinkSynth.clamp` snaps to the NEAREST sweep point, so a level this
    /// runner asks for that is missing from `UplinkSynth.choices` is not
    /// rejected — it is silently replaced by its neighbour. Adding 40/55/58/60
    /// here without adding them there would have run 37/59/59/59, and nothing
    /// in the log would have looked wrong, because the generator faithfully
    /// reports the rate it was handed. This is the same defect class as the
    /// cover toggle the A/B runner never touched, and the same fix: make the
    /// silent substitution loud.
    private func levelsAreSupported() -> (ok: Bool, why: String) {
        let bad = levels.filter { UplinkSynth.clamp($0) != $0 }
        guard bad.isEmpty else {
            let list = bad.map { String(format: "%.0f→%.0f", $0, UplinkSynth.clamp($0)) }
            return (false, "these levels are not sweep points and would be SILENTLY "
                + "SNAPPED to their neighbours: \(list.joined(separator: ", ")). "
                + "Add them to UplinkSynth.choices.")
        }
        return (true, "")
    }

    private func run() {
        let log = SharedLogger.shared

        let planOK = levelsAreSupported()
        guard planOK.ok else {
            log.log("synthab REFUSED — \(planOK.why) Nothing was sent.")
            publish("not started — the plan's levels are not sweep points", running: false)
            return
        }

        let gate = poolReady()
        guard gate.ok else {
            log.log("synthab REFUSED — \(gate.why). Nothing was sent; connect the tunnel, "
                + "wait for the pool, and start again.")
            publish("not started — \(gate.why)", running: false)
            return
        }
        let plan = (0..<passes).map { p -> [Double] in
            p % 2 == 0 ? levels : levels.reversed()
        }
        let totalArms = passes * levels.count

        log.log("synthab PLAN pool=\(gate.why) levels=\(levels.map { String(format: "%.0f", $0) }.joined(separator: ",")) Mbit/s "
            + "armSec=\(armSec) passes=\(passes) gapSec=\(gapSec) warmupSec=\(warmupSec) "
            + "arms=\(totalArms) estimated=\(estimatedSeconds)s — RAMP UP AND BACK DOWN, "
            + "so this is a HYSTERESIS probe: pair each level's dir=up arm with its dir=down arm "
            + "(a token bucket emptied at the top is still empty on the way down and must lose MORE "
            + "there; a plain rate limit has no memory and the two must match). "
            + "Score each arm as the DELTA of cum-lost across its boundaries, per receiver index "
            + "(the synthetic is 5d170000) — cum-lost is a DEFICIT SNAPSHOT, not an accumulator, so "
            + "it falls when late packets land and only the level it settles at is loss; the "
            + "per-interval `lost` is deferred by one 8128-counter window and would smear each level "
            + "into the next. Verify the LEVEL from the server's 2s per-conn dump and its 100ms "
            + "conn-rate line, never from these numbers.")

        // Warm-up: the generator waits for the pool on its first arm, and that
        // wait must not land inside a scored one.
        publish("warm-up \(warmupSec)s (the generator is waiting for the pool)")
        log.log("synthab WARMUP mbit=\(levels[0]) sec=\(warmupSec) — NOT SCORED")
        setLevel(levels[0])
        sleep(seconds: warmupSec)

        var armIdx = 0
        for (p, order) in plan.enumerated() {
            for level in order {
                if cancelled { break }
                armIdx += 1

                // Drop to zero first, so the boundary is unambiguous in the log
                // and the in-flight packets of the previous arm land before the
                // next one starts numbering.
                setLevel(0)
                log.log("synthab GAP a=\(armIdx)/\(totalArms) sec=\(gapSec) — letting the previous "
                    + "arm's packets land before the next boundary")
                publish("gap \(gapSec)s before arm \(armIdx)/\(totalArms)")
                sleep(seconds: gapSec)
                if cancelled { break }

                setLevel(level)
                let started = Date()
                // `dir` is what makes the hysteresis pairing greppable: the UP
                // arm and the DOWN arm at the same `mbit` are the comparison,
                // and an arm boundary that lives only in the operator's head is
                // an arm boundary that cannot be recovered from the log.
                let dir = p % 2 == 0 ? "up" : "down"
                log.log(String(format: "synthab ARM a=%d/%d pass=%d dir=%@ mbit=%.0f sec=%d",
                               armIdx, totalArms, p + 1, dir, level, armSec))
                publish(String(format: "arm %d/%d · pass %d · %.0f Mbit/s · %ds",
                               armIdx, totalArms, p + 1, level, armSec))
                sleep(seconds: armSec)
                log.log(String(format: "synthab ARMEND a=%d/%d mbit=%.0f elapsed=%ds",
                               armIdx, totalArms, level, Int(Date().timeIntervalSince(started))))
            }
            if cancelled { break }
        }

        // 🚨 Always leave the tunnel in the shipped state, on EVERY exit path.
        // A cancelled run must not leave a load generator armed — the Go side
        // stops an arm after ten minutes by itself, but "it would have stopped
        // eventually" is not a state to hand back.
        setLevel(0)
        let done = cancelled ? "cancelled" : "done"
        log.log("synthab DONE state=\(done) arms=\(armIdx)/\(totalArms) — load restored to 0. "
            + "Export the log now, and take the naked control in these same minutes.")
        publish(done == "done"
            ? "done — \(armIdx) arms. Export the log and take the naked control."
            : "cancelled after \(armIdx) arm(s). Load restored to 0.", running: false)
    }

    /// Applies the level the same way the picker does — through UserDefaults so
    /// the UI follows along, then the live provider message so it lands without
    /// a reconnect.
    private func setLevel(_ mbit: Double) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(UplinkSynth.clamp(mbit), forKey: UplinkSynth.key)
            TunnelManager.shared.applyUplinkSynthMbit()
        }
    }

    /// Sleeps in short slices so Stop is felt immediately rather than at the end
    /// of a two-minute arm.
    private func sleep(seconds: Int) {
        guard seconds > 0 else { return }
        let deadline = Date().addingTimeInterval(TimeInterval(seconds))
        while Date() < deadline && !cancelled {
            Thread.sleep(forTimeInterval: 0.05)
        }
    }

    private func publish(_ s: String, running r: Bool? = nil) {
        DispatchQueue.main.async {
            self.status = s
            if let r = r { self.running = r }
        }
    }
}
