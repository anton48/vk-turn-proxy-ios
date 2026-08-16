import Foundation

/// Does a per-allocation token bucket on the UPLINK remove the allocation-local
/// drops that `16.08.2026/tcptest1` measured?
///
/// 🚨 THE CLIENT PACER WAS REFUTED FOUR TIMES, AND THIS IS NOT A FIFTH ATTEMPT
/// AT THE SAME THING. Every one of those refutations aimed at reordering or at
/// the outer TCP window, and every one rested on the premise *"the client
/// policer never fires — 21-30% of the allowance, 99.98% delivered"*. That
/// premise was measured FALSE on 08-14, and on 08-16 the pool-split run named
/// what pacing would actually treat:
///
///  • the loss is PER-ALLOCATION — the same synthetic loses 0.0000% alone,
///    0.0003% with the neighbour on the other fifteen allocations of the same
///    relay, and 1.9981% with it on its own;
///  • the burster loses on its OWN allocations with nothing beside it —
///    0.82-0.91% at a mean of 60% of the knee;
///  • the loss arrives as CONSECUTIVE BLOCKS of 14-21 packets, 20-28 KB cut in
///    one go, on every allocation it touches and only those.
///
/// That is a bucket running dry, and a bucket is what answers it.
///
/// 🎯 THE DESIGN IS THE SPLIT RUN'S, REUSED: the synthetic stays on group A
/// unpaced, real TCP stays on group B, and only B's writers get the bucket. So
/// group A is an untouched in-run control for cross-talk, and the treatment
/// moves exactly one thing.
///
/// ARMS: `off · on · on · off` on B — a palindrome, so a drift across the
/// session loads on neither condition, and the two `off` arms reproduce the
/// 0.82-0.91% the same machine measured hours earlier.
///
/// 🚨🚨 WHERE THE SCORE COMES FROM, AND IT IS NOT THE COUNTER YOU WOULD REACH
/// FOR FIRST. Group B carries the REAL stream, whose WireGuard keypair ROTATES
/// (~2 min) — so its `by-idx` entries appear and vanish between dumps and a
/// difference across an arm boundary yields NEGATIVE spans. `cum-lost` CANNOT
/// score this run. The primary metric is the CAPTURE: gaps in the outer RTP
/// sequence on group B's relay ports, joined through the client's own
/// `[conn N] TURN relay allocated:` lines. Only the synthetic's index is fixed
/// by construction, and it is on group A — which is why A can still be scored
/// from the counter as the cross-talk control.
/// *(Established 2026-08-16 from the split run's own data.)*
final class UplinkPaceRunner: ObservableObject {
    /// 🚨 SHARED — see DiagnosticRunLock. A runner must outlive the view that
    /// started it, or a re-created screen hands the next tap a fresh idle object
    /// and a second concurrent run begins.
    static let shared = UplinkPaceRunner()

    private let runName = "paceab"

    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// The synthetic's rate on group A. Held at the split run's own level so the
    /// two sessions are comparable arm for arm.
    private let synthMbit: Double = 15
    private let probeFlows = 8
    private let armSec = 120
    private let gapSec = 8
    private let warmupSec = 25
    private let settleSec = 12

    /// The bucket. 🚨 BOTH NUMBERS ARE HYPOTHESES AND THE SECOND IS THE ONE THE
    /// EVIDENCE POINTS AT. 247 KiB/s is the server pacer's shipped rate (95% of
    /// the 260 KiB/s the packet-size sweep put the policer at) and the return
    /// leg was measured to be policed identically — but "identically" was
    /// established on the RATE, never on the bucket DEPTH, which is what a
    /// block-shaped loss is about.
    ///
    /// ⚠️ AND THE RATE SITS WELL ABOVE THE TRAFFIC: group B's measured mean is
    /// ~152 KiB/s of counted bytes, 62% of 247. The bucket can therefore only
    /// ever act on BURSTS — which is the intent, and which is exactly why
    /// `waited=` must be read before any conclusion. If it reads 0 the arm
    /// tested nothing, and the number to move is the BURST, not the rate.
    private let paceKiB = 247
    private let paceBurstKiB = 16

    private enum Arm { case off, on }
    private let arms: [Arm] = [.off, .on, .on, .off]

    /// Every transition of the REAL load costs a settle. Here the load runs
    /// CONTINUOUSLY through all four arms — only the bucket is toggled — so
    /// there is exactly one: the start.
    ///
    /// 🚨 Derived rather than written down, for the reason the split runner's
    /// twin exists: a constant that duplicates knowledge living in `arms` goes
    /// stale the moment `arms` changes, and it did.
    private var loadTransitions: Int {
        var count = 0, running = false
        for _ in arms where !running { count += 1; running = true }
        return count
    }

    var estimatedSeconds: Int {
        warmupSec + arms.count * (armSec + gapSec) + loadTransitions * settleSec
    }

    /// How long the load may stand still anywhere inside an arm before the arm
    /// is called unloaded. ⚠️ A PACED arm is EXPECTED to stall more than an
    /// unpaced one — that is the pacer working — so this bound is deliberately
    /// generous and `gapmax=` is printed on every arm so the first run can say
    /// what the honest value is.
    private let staleLoadMs = 3000

    func stop() { cancelledFlag.set(true) }

    func start(host: String, port: UInt16, probe: UplinkCwndProbe) {
        guard !running else { return }
        guard DiagnosticRunLock.acquire(runName) else {
            SharedLogger.shared.log("\(runName) REFUSED — `\(DiagnosticRunLock.current ?? "?")` is "
                + "already running on this tunnel. One diagnostic run per process.")
            return
        }
        cancelledFlag.set(false)
        running = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            defer { DiagnosticRunLock.release(self?.runName ?? "") }
            self?.run(host: host, port: port, probe: probe)
        }
    }

    private func publish(_ s: String, running r: Bool? = nil) {
        DispatchQueue.main.async {
            self.status = s
            if let r = r { self.running = r }
        }
    }

    private func sleep(seconds: Int) {
        for _ in 0..<(seconds * 10) {
            if cancelled { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        let log = SharedLogger.shared
        var received = false
        var active: Int32 = 0
        var total: Int32 = 0
        var knobs = ""
        var flowK = 0
        var conns = 0
        var isTCP = false
        DispatchQueue.main.sync {
            let live = TunnelManager.shared.live
            received = live.statsReceivedOnce
            active = live.stats.activeConns
            total = live.stats.totalConns
            let server = ServerStore.shared.activeServer
            knobs = ExperimentKnobs.summary(server: server)
            flowK = FlowPaths.stored(in: UserDefaults.standard)
            conns = server.numConnections
            isTCP = !server.useUDP
        }
        let n = conns / 2

        // The same refusals as the split run, for the same reasons. Each one is
        // a way the arms would have been silently incomparable.
        //
        // 🚨 `statsReceivedOnce` is checked FIRST: until a reply arrives
        // `activeConns` is the all-zero initial value, and that zero is the
        // ABSENCE of an answer rather than an answer of zero.
        guard received, total > 0, Double(active) >= 0.9 * Double(total) else {
            log.log("\(runName) REFUSED — the pool is not up (\(active)/\(total), stats "
                + "received: \(received)). Nothing was sent.")
            publish("not started — the pool is not up", running: false); return
        }
        guard conns >= 4, conns % 2 == 0 else {
            log.log("\(runName) REFUSED — NumConns=\(conns); this run splits the pool by index "
                + "and half of an odd pool is not a half.")
            publish("not started — NumConns must be even", running: false); return
        }
        guard isTCP else {
            log.log("\(runName) REFUSED — the active server is on UDP transport. TURN over TCP is "
                + "terminated at the relay, so every counted gap is made at or after it — the "
                + "region this run acts on. Switch the server to TCP.")
            publish("not started — switch to TCP transport", running: false); return
        }
        guard flowK == FlowPaths.off else {
            log.log("\(runName) REFUSED — flowPathsK is armed and would route WireGuard onto the "
                + "synthetic's own connections, undoing the split this run stands on.")
            publish("not started — flow-path k is armed", running: false); return
        }
        let probeRequestSec = estimatedSeconds + 120
        guard !ProbeDuration.clamps(probeRequestSec) else {
            log.log("\(runName) REFUSED — this plan needs the load for \(probeRequestSec)s and the "
                + "probe would clamp that to \(ProbeDuration.clamp(probeRequestSec))s. Every arm "
                + "after the load ended would be unpaced AND unloaded.")
            publish("not started — the probe cannot cover the plan", running: false); return
        }

        log.log("\(runName) TARGET \(host):\(port) — 🚨 server1's INNER address with `cwndsink` "
            + "listening, or the real load never reaches server1 and every arm is a control.")
        log.log("\(runName) \(knobs)")
        log.log("\(runName) PLAN pool=\(conns) split=\(n)+\(n) synth=\(Int(synthMbit))Mbit/s on A "
            + "(NEVER paced) · real TCP flows=\(probeFlows) on B · pace=\(paceKiB)KiB/s "
            + "burst=\(paceBurstKiB)KiB on B ONLY · arms=off·on·on·off · armSec=\(armSec) "
            + "transport=TCP k=1 estimated=\(estimatedSeconds)s. "
            + "🎯 THE QUESTION: does a per-allocation bucket remove the allocation-local drops "
            + "measured at 0.82-0.91% on this same group at a mean of 60% of the knee? "
            + "🚨🚨 SCORE B FROM THE CAPTURE, NOT FROM `cum-lost`: the real stream's WireGuard "
            + "keypair ROTATES, so its by-idx spans go NEGATIVE across an arm boundary and the "
            + "counter cannot difference it. The metric is RTP-sequence gaps on group B's relay "
            + "ports (conns \(n)-\(conns - 1)), joined via the client's `[conn N] TURN relay "
            + "allocated:` lines. Group A's synthetic IS scoreable from the counter (index "
            + "5d170000, fixed by construction) and is the CROSS-TALK CONTROL: it must stay ~0. "
            + "🚨 READ `pace=` FIRST: `waited=0` means the bucket never emptied and THE ARM "
            + "TESTED NOTHING — group B's mean is ~152 KiB/s against a \(paceKiB) KiB/s rate, so "
            + "this bucket can only act on BURSTS by construction. If loss does not fall, move "
            + "the BURST before the rate: the losses are block-shaped (14-21 packets, 20-28 KB), "
            + "i.e. a DEPTH. "
            + "⚠️ EXPECT `sendch-block` AND `gapmax` TO RISE IN THE PACED ARMS — a writer without "
            + "budget sleeps and the queue backs up into the inner TCP. That is the pacer "
            + "working, not a regression; do not void an arm for it. "
            + "KEEP needs all four: B-loss → ≲0.05% palindrome-consistently · B goodput > 17.3 "
            + "Mbit/s DELIVERED at the sink (not offered) · A stays ~0 · loaded srtt not visibly "
            + "up. KILL/refine: loss flat ⇒ not policer-shape or the cost unit is wrong; loss↓ "
            + "goodput flat ⇒ throttling costs more than the drops did; goodput↑ latency↑ ⇒ "
            + "burst, not rate; A rises ⇒ a pacer or split bug.")

        // 🚨 K IS PINNED, not assumed: a retired lever's stored value drove this
        // tunnel for three days once.
        DispatchQueue.main.async { TunnelManager.shared.applyUplinkChunkK(UplinkChunk.off) }

        func abortRun(_ why: String) {
            log.log("\(runName) ABORTED — \(why). The palindrome is broken; score nothing from "
                + "this session. Pace and load restored to 0 and the pool un-split.")
            setPace(0); setLevel(0); setSplit(0)
            DispatchQueue.main.async { probe.stop() }
            publish("aborted — the real load failed mid-run", running: false)
        }

        publish("warm-up \(warmupSec)s")
        log.log("\(runName) WARMUP sec=\(warmupSec) — NOT SCORED")
        setPace(0)
        setSplit(n)
        setLevel(synthMbit)
        sleep(seconds: warmupSec)

        var probeRunning = false
        for (i, arm) in arms.enumerated() {
            if cancelled { break }
            let no = i + 1
            // 🚨 The PACE changes inside the GAP, never inside an arm, so no arm
            // straddles the switch — the same discipline the split's mode has.
            setPace(0)
            log.log("\(runName) GAP a=\(no)/\(arms.count) sec=\(gapSec)")
            publish("gap \(gapSec)s before arm \(no)/\(arms.count)")
            sleep(seconds: gapSec)
            if cancelled { break }

            var lifecycleAlive = false
            DispatchQueue.main.sync { lifecycleAlive = probe.running }
            if probeRunning && !lifecycleAlive {
                abortRun("the real load ended before arm \(no) without this runner stopping it, "
                    + "so arm \(no - 1) ran wholly or partly SOLO while labelled loaded")
                return
            }
            if !probeRunning {
                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: self.probeFlows,
                                durationSec: self.estimatedSeconds + 120)
                }
                guard waitForRealLoad(probe, upTo: 45) else {
                    abortRun("the cwnd probe never started sending — `cwndsink` must be LISTENING "
                        + "on \(host):\(port), or every arm is unloaded")
                    return
                }
                let c = probe.flowCensus()
                guard c.connected == probeFlows else {
                    abortRun("only \(c.connected) of \(probeFlows) flows connected — the load's "
                        + "INTENSITY is the treatment's own baseline, so a short pool is a "
                        + "different arm and not a noisy one")
                    return
                }
                probeRunning = true
                log.log("\(runName) SETTLE sec=\(settleSec) — the probe just started; letting TCP "
                    + "leave slow start before the arm is declared")
                sleep(seconds: settleSec)
                if cancelled { break }
            }

            let paced = (arm == .on)
            setPace(paced ? paceKiB : 0)
            let mode = paced ? "paced" : "unpaced"
            log.log("\(runName) ARM a=\(no)/\(arms.count) mode=\(mode) "
                + "pace=\(paced ? "\(paceKiB)KiB/s burst \(paceBurstKiB)KiB on B" : "off") "
                + "synth=\(Int(synthMbit))Mbit/s(A) flows=\(probe.flowCensus().live)/\(probeFlows)(B) "
                + "sec=\(armSec)")
            publish("arm \(no)/\(arms.count) · \(mode) · \(armSec)s")

            let before = probe.loadProgress()
            sleep(seconds: armSec)
            let after = probe.loadProgress()
            var stillUp = false
            DispatchQueue.main.sync { stillUp = probe.running }
            let census = probe.flowCensus()
            let moved = after.bytes &- before.bytes
            let verdict = LoadWitness.judge(movedBytes: moved, worstGapMs: after.worstGapMs,
                                            probeStillRunning: stillUp,
                                            liveFlows: census.live, wantFlows: probeFlows,
                                            staleMs: staleLoadMs)
            let note = " load=+\(moved / (1 << 20))MiB idle=\(after.idleMs)ms "
                + "gapmax=\(after.worstGapMs)ms flows=\(census.live)/\(probeFlows)"
            if verdict != .ok {
                let why = LoadWitness.reason(verdict)
                log.log("\(runName) ARMEND a=\(no)/\(arms.count) mode=\(mode)\(note) 🚨 \(why)")
                abortRun("arm \(no) was labelled '\(mode)' but \(why) — it is "
                    + "\(LoadWitness.mislabel(verdict))")
                return
            }
            log.log("\(runName) ARMEND a=\(no)/\(arms.count) mode=\(mode)\(note)")
        }

        setPace(0); setLevel(0); setSplit(0)
        DispatchQueue.main.async { probe.stop() }
        let done = cancelled ? "cancelled" : "done"
        log.log("\(runName) DONE state=\(done) — pace, load and split all restored to 0. "
            + "🚨 THE COMPARISON IS THE TWO PACED ARMS AGAINST THE TWO UNPACED ONES, on group B's "
            + "RTP-sequence gaps from the capture — NOT on `cum-lost`, which cannot difference a "
            + "rotating keypair. Group A's synthetic is the cross-talk control and must still "
            + "read ~0. Read `pace=` before either: an arm whose bucket never emptied tested "
            + "nothing.")
        publish(done == "done" ? "done — export the log" : "cancelled", running: false)
    }

    private func waitForRealLoad(_ probe: UplinkCwndProbe, upTo seconds: Int) -> Bool {
        let deadline = Date().addingTimeInterval(TimeInterval(seconds))
        while Date() < deadline && !cancelled {
            var moving = false
            DispatchQueue.main.sync { moving = probe.sending }
            if moving { return true }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return false
    }

    private func setPace(_ kib: Int) {
        DispatchQueue.main.async {
            TunnelManager.shared.applyUplinkPace(kib: kib, burstKiB: self.paceBurstKiB,
                                                 groupBOnly: true)
        }
    }

    private func setSplit(_ n: Int) {
        DispatchQueue.main.async { TunnelManager.shared.applyUplinkSplitN(n, colocated: false) }
    }

    private func setLevel(_ mbit: Double) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(UplinkSynth.clamp(mbit), forKey: UplinkSynth.key)
            TunnelManager.shared.applyUplinkSynthMbit()
        }
    }
}
