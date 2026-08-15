import Foundation

/// Runs the paced synthetic ALONE and ALONGSIDE real inner-TCP traffic, at the
/// same synthetic rate in both, and now at BOTH uplink chunk sizes — so the
/// synthetic's own loss can be compared with WireGuard idle and with WireGuard
/// working, without the comparison carrying a second, uncontrolled change.
///
/// 🎯 THE QUESTION IT ANSWERS, and it is the user's, not mine. Every loss result
/// so far came from the paced synthetic — whose packets server1's WireGuard
/// **discards at the index lookup**: no decryption, no TUN write, nothing
/// forwarded to server2. Real traffic makes WireGuard do all of that. So the
/// synthetic has only ever tested the path **up to our proxy**, and any
/// mechanism that needs a BUSY WireGuard is untested by construction.
///
/// 🚨🚨 AND THE FIRST RUN OF THIS DESIGN CARRIED A CONFOUNDER THAT THE DESIGN
/// ITSELF ACTIVATED — which is why K is now an arm. `uplinkChunkK` had been left
/// at **64** by a picker that was later deleted, and chunking is INERT while the
/// send queue is shallow: the solo arms measured mean chunk **1.000** (asleep)
/// and the paired arms **1.04-1.06 with max 64** (awake), because the real TCP
/// is what fills the queue. So "paired" changed two things at once, and the
/// second was CAUSED by the first: no re-analysis can separate them.
/// A 64-packet chunk is ~84 KB committed to ONE allocation in a couple of
/// milliseconds — about 340 ms of that allocation's 2.07 Mbit/s budget — which
/// is a burst nothing else in the design produces. *(Found 2026-08-15.)*
///
/// THE DESIGN: the synthetic runs at ONE rate throughout. Two things alternate —
/// whether the cwnd probe runs beside it, and the uplink chunk size — and the
/// eight arms are a PALINDROME in both, so a drift across the session cannot
/// load onto either variable:
///
///     solo/64 · solo/1 · paired/64 · paired/1 · paired/1 · paired/64 · solo/1 · solo/64
///
///  • paired loses more than solo at BOTH chunk sizes ⇒ the effect is the
///    neighbour, and K=64 was not what produced it;
///  • paired/64 loses and paired/1 does not ⇒ the effect was OUR dispatcher
///    committing 64-packet bursts to single allocations, and the 08-15 paired
///    result does not transfer to production, where K=1;
///  • the two solo pairs MUST agree with each other — they are the same load by
///    construction, and they audit the scoring window before any of it is
///    believed.
///
/// ⚠️ THE TWO STREAMS SHARE THE ALLOCATION BUDGET. The synthetic holds its rate
/// while TCP takes what is left, so the paired arms carry MORE total load than
/// the solo ones — that is inherent and must not be read as a level effect.
/// It is why the synthetic's rate is set well below the knee: at 30 Mbit/s it is
/// about half the 30 × 2.07 ≈ 62 budget, leaving room for the probe without
/// pushing the pool into the region where loss appears at all.
final class UplinkPairedRunner: ObservableObject {
    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// One rate, held in every arm. Deliberately ~half the budget: the question
    /// is whether the SERVER changes the path's loss, and putting the pool near
    /// its knee would add the very load-dependent loss the comparison is trying
    /// to see past.
    private let synthMbit: Double = 30

    /// Inner TCP flows in the paired arms. 8 is the count at which the probe has
    /// always been run, so its behaviour here is comparable with the record.
    private let probeFlows = 8

    private let armSec = 120
    private let gapSec = 8
    private let warmupSec = 25

    /// The chunk size that was accidentally in effect for every run of 08-12→15,
    /// carried here as the TREATMENT so its effect is measured rather than
    /// argued about.
    private let treatmentK = 64

    private struct Arm {
        let paired: Bool
        let k: Int
    }

    /// A palindrome in both variables — see the type comment.
    private var arms: [Arm] {
        [Arm(paired: false, k: treatmentK), Arm(paired: false, k: UplinkChunk.off),
         Arm(paired: true, k: treatmentK), Arm(paired: true, k: UplinkChunk.off),
         Arm(paired: true, k: UplinkChunk.off), Arm(paired: true, k: treatmentK),
         Arm(paired: false, k: UplinkChunk.off), Arm(paired: false, k: treatmentK)]
    }

    var estimatedSeconds: Int { warmupSec + arms.count * (armSec + gapSec) }

    func start(host: String, port: UInt16, probe: UplinkCwndProbe) {
        guard !running else { return }
        running = true
        cancelledFlag.set(false)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run(host: host, port: port, probe: probe)
        }
    }

    func cancel() {
        cancelledFlag.set(true)
        setLevel(0)
        restoreChunkK()
    }

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        let log = SharedLogger.shared
        let plan = arms

        guard UplinkSynth.clamp(synthMbit) == synthMbit else {
            // The same trap the sweep runner refuses on: `clamp` snaps to the
            // nearest sweep point, so a rate that is not one of them is
            // silently replaced and the run measures a plan nobody wrote.
            log.log("pairedab REFUSED — \(synthMbit) Mbit/s is not a sweep point and "
                + "would be snapped to \(UplinkSynth.clamp(synthMbit)). Add it to UplinkSynth.choices.")
            publish("not started — the synthetic rate is not a sweep point", running: false)
            return
        }
        guard UplinkChunk.clamp(treatmentK) == treatmentK else {
            log.log("pairedab REFUSED — K=\(treatmentK) is not a supported chunk size and "
                + "would be snapped to \(UplinkChunk.clamp(treatmentK)).")
            publish("not started — the chunk treatment is not a sweep point", running: false)
            return
        }

        var received = false
        var active: Int32 = 0
        var total: Int32 = 0
        var knobs = ""
        var flowK = 0
        DispatchQueue.main.sync {
            let live = TunnelManager.shared.live
            received = live.statsReceivedOnce
            active = live.stats.activeConns
            total = live.stats.totalConns
            knobs = ExperimentKnobs.summary(server: ServerStore.shared.activeServer)
            flowK = FlowPaths.stored(in: UserDefaults.standard)
        }
        // `statsReceivedOnce` first, because until a reply arrives `activeConns`
        // is the all-zero initial value and that zero is the ABSENCE of an
        // answer, not an answer of zero.
        guard received, total > 0, Double(active) >= 0.9 * Double(total) else {
            log.log("pairedab REFUSED — the pool is not up (\(active)/\(total), "
                + "stats received: \(received)). Nothing was sent.")
            publish("not started — the pool is not up", running: false)
            return
        }
        // 🚨 THE GUARD THAT KEEPS THE K ARMS FROM BEING A SILENT NULL.
        // `writeChunk` force-disables chunking whenever a flow-local path set is
        // armed — deliberately, because a chunk would pull other flows' packets
        // onto one connection and undo the stickiness. With flowPathsK > 0 the
        // K=64 arms would therefore run at K=1, the treatment would equal the
        // control, and the run would return a flat result that reads as an
        // answer. Refuse instead.
        guard flowK == FlowPaths.off else {
            log.log("pairedab REFUSED — flowPathsK=\(flowK) is armed, and `writeChunk` "
                + "force-disables chunking whenever it is. Every K=\(treatmentK) arm would "
                + "silently run at K=\(UplinkChunk.off), the treatment would equal the control, "
                + "and the flat result would look like a finding. Set the flow-path k to 0 first.")
            publish("not started — flow-path k is armed; chunking cannot engage", running: false)
            return
        }

        log.log("pairedab TARGET \(host):\(port) — 🚨 this must be server1's INNER "
            + "(tunnel) address and `cwndsink` must be listening there. A public address "
            + "can be routed AROUND the tunnel (serverAddress is exempt under "
            + "includeAllNetworks), and then the real load never reaches server1's "
            + "WireGuard — which is the entire point of the paired arms.")
        // 🚨 EVERY KNOB, ON THE PLAN LINE. Nine runs were scored without anyone
        // noticing uplinkChunkK=64 in the config dump; a knob that changes what a
        // run measures belongs where the run's plan is stated.
        log.log("pairedab \(knobs)")
        log.log("pairedab PLAN pool=\(active)/\(total) synth=\(Int(synthMbit))Mbit/s "
            + "flows=\(probeFlows) armSec=\(armSec) arms=\(plan.count) "
            + "chunkK=\(treatmentK)-vs-\(UplinkChunk.off) estimated=\(estimatedSeconds)s — arms are "
            + "solo·solo·paired·paired·paired·paired·solo·solo, a PALINDROME in both the real "
            + "load and the chunk size. The synthetic rate is the SAME in all eight. Score the "
            + "SYNTHETIC's own cum-lost (index 5d170000) by (mode × K); the real stream's loss "
            + "rides the other indices in the same dump. 🚨 Read `chunk=mean/max` on the memstats "
            + "line to confirm the treatment ENGAGED — solo arms read 1.000 at either K because "
            + "chunking cannot engage on a shallow queue, and that is the control, not a failure. "
            + "🚨 The two solo/K pairs must AGREE with each other; if they do not, the scoring "
            + "window is wrong before the world is.")

        publish("warm-up \(warmupSec)s")
        log.log("pairedab WARMUP sec=\(warmupSec) — NOT SCORED")
        setChunkK(UplinkChunk.off)
        setLevel(synthMbit)
        sleep(seconds: warmupSec)

        for (i, arm) in plan.enumerated() {
            if cancelled { break }
            let n = i + 1
            setLevel(0)
            log.log("pairedab GAP a=\(n)/\(plan.count) sec=\(gapSec)")
            publish("gap \(gapSec)s before arm \(n)/\(plan.count)")
            sleep(seconds: gapSec)
            if cancelled { break }

            // K is applied in the GAP, so no arm ever straddles the switch.
            setChunkK(arm.k)
            setLevel(synthMbit)
            if arm.paired {
                // 🚨 THE REAL LOAD IS THE cwnd PROBE, AND IT NEEDS `cwndsink`
                // LISTENING ON THE OTHER END. If it is not, every flow fails to
                // connect, the arm carries the synthetic only, and the run
                // becomes all-solo — a null that looks like a finding. The
                // probe's own duration outlives the arm and it is stopped
                // explicitly below, so a slow connect cannot end the real load
                // early either.
                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: self.probeFlows,
                                durationSec: self.armSec + 60)
                }
                // ⚠️ WAIT FOR BYTES, NOT FOR THE CALL — connecting the flows
                // through the tunnel took 25.8 s in one recorded run, and an arm
                // that starts on `running` would spend that time measuring an
                // idle link. `sending` is the probe's own "bytes are moving".
                guard waitForRealLoad(probe, upTo: 45) else {
                    log.log("pairedab ABORTED at arm \(n) — the cwnd probe never started "
                        + "sending. 🚨 `cwndsink` must be LISTENING on \(host):\(port); without "
                        + "it every paired arm is a solo arm in disguise and the whole "
                        + "comparison is void. Nothing further was run.")
                    publish("aborted — no real load; is cwndsink running?", running: false)
                    setLevel(0)
                    restoreChunkK()
                    DispatchQueue.main.async { probe.stop() }
                    return
                }
            }
            let mode = arm.paired ? "paired" : "solo"
            log.log("pairedab ARM a=\(n)/\(plan.count) mode=\(mode) k=\(arm.k) "
                + "synth=\(Int(synthMbit))Mbit/s flows=\(arm.paired ? probeFlows : 0) sec=\(armSec)")
            publish("arm \(n)/\(plan.count) · \(mode) · k=\(arm.k) · \(armSec)s")
            sleep(seconds: armSec)
            if arm.paired { DispatchQueue.main.async { probe.stop() } }
            log.log("pairedab ARMEND a=\(n)/\(plan.count) mode=\(mode) k=\(arm.k)")
        }

        setLevel(0)
        restoreChunkK()
        DispatchQueue.main.async { probe.stop() }
        let done = cancelled ? "cancelled" : "done"
        log.log("pairedab DONE state=\(done) — load restored to 0 and the chunk size restored "
            + "to the stored value. Export the log; the comparison is the synthetic's loss by "
            + "(solo|paired) × (k=\(treatmentK)|k=\(UplinkChunk.off)).")
        publish(done == "done" ? "done — export the log" : "cancelled", running: false)
    }

    /// Blocks until the probe reports that bytes are actually moving, or gives
    /// up. 🚨 `running` is set the moment `start()` is called and says nothing
    /// about whether a single flow connected; `sending` is the probe's own
    /// statement that the CSV's clock has started. Scheduling an arm against
    /// the wrong one is the defect that cost two runs of six on 2026-08-13.
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

    private func setLevel(_ mbit: Double) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(UplinkSynth.clamp(mbit), forKey: UplinkSynth.key)
            TunnelManager.shared.applyUplinkSynthMbit()
        }
    }

    /// ⚠️ K is sent to the RUNNING tunnel and deliberately NOT written to
    /// UserDefaults. An arm is a transient state of one measurement; persisting
    /// it is how a retired lever survived three days of runs in the first place.
    private func setChunkK(_ k: Int) {
        DispatchQueue.main.async { TunnelManager.shared.applyUplinkChunkK(k) }
    }

    /// Every exit path goes through here, so a cancelled or aborted run cannot
    /// leave the treatment armed on the tunnel the user then keeps using.
    private func restoreChunkK() {
        DispatchQueue.main.async {
            TunnelManager.shared.applyUplinkChunkK(UplinkChunk.stored(in: UserDefaults.standard))
        }
    }

    private func sleep(seconds: Int) {
        guard seconds > 0 else { return }
        let deadline = Date().addingTimeInterval(TimeInterval(seconds))
        while Date() < deadline && !cancelled { Thread.sleep(forTimeInterval: 0.05) }
    }

    private func publish(_ s: String, running r: Bool? = nil) {
        DispatchQueue.main.async {
            self.status = s
            if let r = r { self.running = r }
        }
    }
}
