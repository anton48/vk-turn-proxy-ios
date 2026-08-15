import Foundation

/// Runs the paced synthetic ALONE and ALONGSIDE real inner-TCP traffic, at the
/// same synthetic rate in both, so the synthetic's own loss can be compared
/// with WireGuard idle and with WireGuard working.
///
/// 🎯 THE QUESTION IT ANSWERS, and it is the user's, not mine. Every loss result
/// so far came from the paced synthetic — whose packets server1's WireGuard
/// **discards at the index lookup**: no decryption, no TUN write, nothing
/// forwarded to server2. Real traffic makes WireGuard do all of that. So the
/// synthetic has only ever tested the path **up to our proxy**, and any
/// mechanism that needs a BUSY WireGuard is untested by construction. The
/// runs that refuted VK's meter cannot exclude it.
///
/// 🚨 WHAT THE SERVER'S ARCHITECTURE ALREADY SAYS, because it narrows what this
/// can find. One UDP socket carries all thirty relay connections and ONE demux
/// goroutine reads it; its hand-off into a per-session queue is **non-blocking**.
/// So a slow consumer cannot stall that reader and cannot make the kernel drop
/// on that socket. It can only fill the queue until the demux drops — and that
/// drop lands UPSTREAM of the loss counter, where it is indistinguishable from
/// network loss. That drop is logged and counted (`srtpwrap`, and the server's
/// `wg-write` line carries the queue's peak depth), and it has been silent in
/// every log to date. ⇒ **This run is looking for a mechanism that is already
/// argued against; its most likely outcome is a null, and the null is worth
/// having because it closes the last thing the synthetic could not see.**
///
/// THE DESIGN: the synthetic runs at ONE rate throughout, and what alternates is
/// whether the cwnd probe is also running. Four arms, palindromic —
/// **solo · paired · paired · solo** — so a drift across the session cannot load
/// onto either condition.
///
///  • the synthetic's loss identical in both ⇒ a working WireGuard costs the
///    path nothing, and the server side is closed;
///  • the synthetic's loss HIGHER while paired ⇒ the loss depends on what the
///    server is doing, not only on the network, and the demux queue / `wg-write`
///    line in the same ticks says which part;
///  • and the real stream's own loss comes free in the same dump, under its own
///    receiver indices, which is a controlled comparison **inside one session**
///    rather than across two.
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

    /// solo · paired · paired · solo.
    private let paired = [false, true, true, false]

    var estimatedSeconds: Int { warmupSec + paired.count * (armSec + gapSec) }

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
    }

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        let log = SharedLogger.shared

        guard UplinkSynth.clamp(synthMbit) == synthMbit else {
            // The same trap the sweep runner refuses on: `clamp` snaps to the
            // nearest sweep point, so a rate that is not one of them is
            // silently replaced and the run measures a plan nobody wrote.
            log.log("pairedab REFUSED — \(synthMbit) Mbit/s is not a sweep point and "
                + "would be snapped to \(UplinkSynth.clamp(synthMbit)). Add it to UplinkSynth.choices.")
            publish("not started — the synthetic rate is not a sweep point", running: false)
            return
        }

        var received = false
        var active: Int32 = 0
        var total: Int32 = 0
        DispatchQueue.main.sync {
            let live = TunnelManager.shared.live
            received = live.statsReceivedOnce
            active = live.stats.activeConns
            total = live.stats.totalConns
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

        log.log("pairedab TARGET \(host):\(port) — 🚨 this must be server1's INNER "
            + "(tunnel) address and `cwndsink` must be listening there. A public address "
            + "can be routed AROUND the tunnel (serverAddress is exempt under "
            + "includeAllNetworks), and then the real load never reaches server1's "
            + "WireGuard — which is the entire point of the paired arms.")
        log.log("pairedab PLAN pool=\(active)/\(total) synth=\(Int(synthMbit))Mbit/s "
            + "flows=\(probeFlows) armSec=\(armSec) arms=\(paired.count) "
            + "estimated=\(estimatedSeconds)s — arms are solo·paired·paired·solo, the synthetic "
            + "rate is the SAME in all four and only the real load changes. Score the "
            + "SYNTHETIC's own cum-lost (index 5d170000) solo vs paired; the real stream's "
            + "loss rides the other indices in the same dump. 🚨 Read the server's `wg-write` "
            + "line in those ticks — its demux queue peak is what would rise first if a busy "
            + "WireGuard were pushing loss upstream, and a drop there is counted as network loss.")

        publish("warm-up \(warmupSec)s")
        log.log("pairedab WARMUP sec=\(warmupSec) — NOT SCORED")
        setLevel(synthMbit)
        sleep(seconds: warmupSec)

        for (i, withProbe) in paired.enumerated() {
            if cancelled { break }
            let arm = i + 1
            setLevel(0)
            log.log("pairedab GAP a=\(arm)/\(paired.count) sec=\(gapSec)")
            publish("gap \(gapSec)s before arm \(arm)/\(paired.count)")
            sleep(seconds: gapSec)
            if cancelled { break }

            setLevel(synthMbit)
            if withProbe {
                // 🚨 THE REAL LOAD IS THE cwnd PROBE, AND IT NEEDS `cwndsink`
                // LISTENING ON THE OTHER END. If it is not, every flow fails to
                // connect, the arm carries the synthetic only, and the run
                // becomes solo·solo·solo·solo — a null that looks like a
                // finding. The probe's own duration outlives the arm and it is
                // stopped explicitly below, so a slow connect cannot end the
                // real load early either.
                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: self.probeFlows,
                                durationSec: self.armSec + 60)
                }
                // ⚠️ WAIT FOR BYTES, NOT FOR THE CALL — connecting the flows
                // through the tunnel took 25.8 s in one recorded run, and an arm
                // that starts on `running` would spend that time measuring an
                // idle link. `sending` is the probe's own "bytes are moving".
                guard waitForRealLoad(probe, upTo: 45) else {
                    log.log("pairedab ABORTED at arm \(arm) — the cwnd probe never started "
                        + "sending. 🚨 `cwndsink` must be LISTENING on \(host):\(port); without "
                        + "it every paired arm is a solo arm in disguise and the whole "
                        + "comparison is void. Nothing further was run.")
                    publish("aborted — no real load; is cwndsink running?", running: false)
                    setLevel(0)
                    DispatchQueue.main.async { probe.stop() }
                    return
                }
            }
            let mode = withProbe ? "paired" : "solo"
            log.log("pairedab ARM a=\(arm)/\(paired.count) mode=\(mode) "
                + "synth=\(Int(synthMbit))Mbit/s flows=\(withProbe ? probeFlows : 0) sec=\(armSec)")
            publish("arm \(arm)/\(paired.count) · \(mode) · \(armSec)s")
            sleep(seconds: armSec)
            if withProbe { DispatchQueue.main.async { probe.stop() } }
            log.log("pairedab ARMEND a=\(arm)/\(paired.count) mode=\(mode)")
        }

        setLevel(0)
        DispatchQueue.main.async { probe.stop() }
        let done = cancelled ? "cancelled" : "done"
        log.log("pairedab DONE state=\(done) — load restored to 0. Export the log; the "
            + "comparison is the synthetic's loss in the two solo arms against the two paired ones.")
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
