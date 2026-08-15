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

    /// 🚨 THE PLAN IS PRE-REGISTERED AND IS NOT A KNOB. Three levels, chosen as
    /// roughly 30 / 60 / 95% of the 30 × 2.07 ≈ 62 Mbit/s allocation budget, so
    /// the sweep straddles the knee rather than surrounding it — the bucket
    /// lesson of the ACK-gap counter, where 250 and 500 ms differed 39× in
    /// frequency and the deciding value sat between them.
    ///
    /// ⚠️ The percentages assume the shipped NumConns = 30. At another count the
    /// same rates mean another fraction, and the SERVER's 2-second per-conn dump
    /// is what says which fraction was really reached — never this list.
    private let levels: [Double] = [19, 37, 59]

    /// 120 s per arm. Long enough that a ~1% loss made of bursts (67% of it
    /// arrived in 4 of 36 ticks on the run that motivated this) has many bursts
    /// to average over: at 19 Mbit/s that is ~216 000 packets per arm.
    private let armSec = 120

    /// Two passes with the level order REVERSED, so a drift across the session
    /// loads onto neither end of the sweep.
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

    private func run() {
        let log = SharedLogger.shared

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
            + "arms=\(totalArms) estimated=\(estimatedSeconds)s — "
            + "score each arm as the DELTA of cum-lost across its boundaries, per receiver index "
            + "(the synthetic is 5d170000); the per-interval `lost` is deferred by one 8128-counter "
            + "window and would smear each level into the next. Verify the LEVEL from the server's "
            + "2s per-conn dump, not from these numbers.")

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
                log.log(String(format: "synthab ARM a=%d/%d pass=%d mbit=%.0f sec=%d",
                               armIdx, totalArms, p + 1, level, armSec))
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
