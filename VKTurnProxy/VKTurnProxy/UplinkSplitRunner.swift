import Foundation

/// Runs the synthetic beside real inner TCP twice over: once with both streams
/// SHARING all 30 allocations, and once with the pool split so they share the
/// relay and the phone but **not an allocation**.
///
/// 🎯 THE QUESTION, and it is the last fork in the uplink-loss investigation. A
/// paced synthetic that loses ~0 alone loses 0.5-2.7% the moment real TCP runs
/// beside it, and the loss is synchronised across allocations (83-99% of gap
/// events coincide within 10 ms against a permutation null of 5-21%). Two
/// mechanisms fit equally:
///
///  • **per-allocation** — each allocation has its own meter or buffer, and the
///    client's burst empties many of them at once;
///  • **above it** — one resource shared by all 30: the relay's egress or CPU,
///    or the relay → server1 leg.
///
/// A capture at server1 cannot separate them: three ways of asking *"was the
/// losing allocation the one bursting"* bracket the proportional null, because
/// the deciding quantity is only observable through a channel the drop corrupts.
/// So the separation is built into the experiment instead.
///
/// 🚨 WHY NOT TWO RELAYS FIRST — this is the user's correction and it is right.
/// Splitting 15+15 across two relays changes whether the streams share an
/// ALLOCATION *and* whether they share a HOST, and a clean result would not say
/// which mattered. This run changes one thing. If the synthetic goes clean here
/// the answer is per-allocation and the two-relay run is unnecessary; if it
/// still loses, the resource is above the allocation and two relays is the NEXT
/// question.
///
/// ⚡ AND A CLEAN RESULT ALSO EXCLUDES THE PHONE. The radio, the socket, this
/// dispatcher and the air stay shared however the allocations are cut, so if the
/// loss disappears when only the allocations become disjoint, nothing on our
/// side can be the cause.
///
/// ⚠️ THE CONFOUND, AND HOW THE PLAN CONTROLS IT. Splitting halves each stream's
/// fan-out, so per-allocation load and the reordering each stream sees both
/// change. The synthetic's rate is therefore HALVED in the split arms — 30
/// Mbit/s over 30 allocations and 15 over 15 are both ~1 Mbit/s per allocation —
/// so what changes for the synthetic is only whether a neighbour is on its
/// allocations. ⚠️ The real stream's per-allocation load RISES in those arms
/// (it keeps its offered rate on half the pool); that is inherent to the design
/// and is why the synthetic, not the real stream, is the thing being scored.
///
/// 🎯 HOW TO READ IT — the reference already exists and does not need measuring
/// again: the ramp measured a smooth stream ALONE at this per-allocation level
/// at **0.02-0.03%**. So the split arm reading ~0.03% means *"needs a shared
/// allocation"*, and reading ~0.5% means *"does not"*.
final class UplinkSplitRunner: ObservableObject {
    /// 🚨 SHARED — see DiagnosticRunLock. A runner must outlive the view that
    /// started it, or a re-created view hands the next tap a fresh idle object
    /// and a second concurrent run begins.
    static let shared = UplinkSplitRunner()

    private let runName = "splitab"

    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// The synthetic's rate when it has the whole pool, and when it has half.
    /// Both are ~1 Mbit/s per allocation at NumConns = 30 — the point of the
    /// pair. Both must be sweep points or `UplinkSynth.clamp` would silently
    /// substitute a neighbour.
    private let sharedMbit: Double = 30
    private let splitMbit: Double = 15

    private let probeFlows = 8
    private let armSec = 120
    private let gapSec = 8
    private let warmupSec = 25

    /// shared · split · split · shared — a palindrome, so a drift across the
    /// session cannot load onto either condition.
    private let arms = [false, true, true, false]

    var estimatedSeconds: Int { warmupSec + arms.count * (armSec + gapSec) }

    func start(host: String, port: UInt16, probe: UplinkCwndProbe) {
        guard !running else { return }
        guard DiagnosticRunLock.acquire(runName) else {
            let who = DiagnosticRunLock.current ?? "another run"
            SharedLogger.shared.log("\(runName) REFUSED — `\(who)` is already running on this "
                + "tunnel. Stop the other one first.")
            status = "not started — \(who) is already running"
            return
        }
        running = true
        cancelledFlag.set(false)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run(host: host, port: port, probe: probe)
        }
    }

    func cancel() {
        cancelledFlag.set(true)
        setLevel(0)
        setSplit(0)
    }

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        defer { DiagnosticRunLock.release(runName) }
        let log = SharedLogger.shared

        for r in [sharedMbit, splitMbit] where UplinkSynth.clamp(r) != r {
            log.log("\(runName) REFUSED — \(r) Mbit/s is not a sweep point and would be snapped "
                + "to \(UplinkSynth.clamp(r)). Add it to UplinkSynth.choices.")
            publish("not started — a rate is not a sweep point", running: false)
            return
        }

        var received = false
        var active: Int32 = 0
        var total: Int32 = 0
        var knobs = ""
        var flowK = 0
        var conns = 0
        DispatchQueue.main.sync {
            let live = TunnelManager.shared.live
            received = live.statsReceivedOnce
            active = live.stats.activeConns
            total = live.stats.totalConns
            let server = ServerStore.shared.activeServer
            knobs = ExperimentKnobs.summary(server: server)
            flowK = FlowPaths.stored(in: UserDefaults.standard)
            conns = server.numConnections
        }
        guard received, total > 0, Double(active) >= 0.9 * Double(total) else {
            log.log("\(runName) REFUSED — the pool is not up (\(active)/\(total), "
                + "stats received: \(received)). Nothing was sent.")
            publish("not started — the pool is not up", running: false)
            return
        }
        // 🚨 The split is by connection INDEX, so half of an odd or tiny pool is
        // not a half. Refuse rather than measure an uneven cut nobody planned.
        guard conns >= 4, conns % 2 == 0 else {
            log.log("\(runName) REFUSED — NumConns=\(conns); this run splits the pool by index "
                + "and needs an even count of at least 4.")
            publish("not started — NumConns must be even and ≥4", running: false)
            return
        }
        // Same guard as the paired runner's, for the same reason: a flow-local
        // path set would put WireGuard packets on the synthetic's writers and
        // undo the disjointness this run exists to create.
        guard flowK == FlowPaths.off else {
            log.log("\(runName) REFUSED — flowPathsK=\(flowK) is armed and would route WireGuard "
                + "packets onto the synthetic's own connections, undoing the split. Set it to 0.")
            publish("not started — flow-path k is armed", running: false)
            return
        }

        let n = conns / 2
        log.log("\(runName) TARGET \(host):\(port) — 🚨 this must be server1's INNER (tunnel) "
            + "address with `cwndsink` listening, or the real load never reaches server1.")
        log.log("\(runName) \(knobs)")
        log.log("\(runName) PLAN pool=\(active)/\(total) split=\(n)+\(conns - n) "
            + "synth=\(Int(sharedMbit))Mbit/s(shared) vs \(Int(splitMbit))Mbit/s(split) "
            + "flows=\(probeFlows) armSec=\(armSec) arms=\(arms.count) "
            + "estimated=\(estimatedSeconds)s — arms are shared·split·split·shared, a PALINDROME. "
            + "The synthetic's rate is HALVED in the split arms so its PER-ALLOCATION load is the "
            + "same in all four (~1 Mbit/s); what changes is only whether real TCP is on its "
            + "allocations. Score the SYNTHETIC's own cum-lost (index 5d170000). "
            + "🚨 Read `split=N synth-pkts=… wg-pkts=…` on the memstats line FIRST — a split arm "
            + "with either count at 0 tested nothing. "
            + "🎯 The reference is the ramp's 0.02-0.03% for a smooth stream ALONE at this "
            + "per-allocation level: a split arm near it means the loss needs a SHARED "
            + "ALLOCATION; a split arm near 0.5% means it does not, and the resource is above "
            + "the allocation — the relay or the leg after it.")

        // 🚨 THE REAL LOAD RUNS FOR THE WHOLE SESSION, not per arm. It is on in
        // all four arms by design, and restarting it at every boundary would
        // make each arm begin with TCP in slow start — a difference between arms
        // that has nothing to do with the split.
        DispatchQueue.main.async {
            probe.start(host: host, port: port, flows: self.probeFlows,
                        durationSec: self.estimatedSeconds + 120)
        }
        guard waitForRealLoad(probe, upTo: 45) else {
            log.log("\(runName) ABORTED — the cwnd probe never started sending. 🚨 `cwndsink` "
                + "must be LISTENING on \(host):\(port); without it every arm is solo and the "
                + "whole comparison is void.")
            publish("aborted — no real load; is cwndsink running?", running: false)
            setLevel(0); setSplit(0)
            DispatchQueue.main.async { probe.stop() }
            return
        }

        publish("warm-up \(warmupSec)s")
        log.log("\(runName) WARMUP sec=\(warmupSec) — NOT SCORED")
        setSplit(0)
        setLevel(sharedMbit)
        sleep(seconds: warmupSec)

        for (i, split) in arms.enumerated() {
            if cancelled { break }
            let arm = i + 1
            setLevel(0)
            log.log("\(runName) GAP a=\(arm)/\(arms.count) sec=\(gapSec)")
            publish("gap \(gapSec)s before arm \(arm)/\(arms.count)")
            sleep(seconds: gapSec)
            if cancelled { break }

            // Both applied in the GAP, so no arm straddles a switch.
            setSplit(split ? n : 0)
            setLevel(split ? splitMbit : sharedMbit)
            let mode = split ? "split" : "shared"
            log.log("\(runName) ARM a=\(arm)/\(arms.count) mode=\(mode) splitN=\(split ? n : 0) "
                + "synth=\(Int(split ? splitMbit : sharedMbit))Mbit/s flows=\(probeFlows) sec=\(armSec)")
            publish("arm \(arm)/\(arms.count) · \(mode) · \(armSec)s")
            sleep(seconds: armSec)
            log.log("\(runName) ARMEND a=\(arm)/\(arms.count) mode=\(mode)")
        }

        setLevel(0)
        setSplit(0)
        DispatchQueue.main.async { probe.stop() }
        let done = cancelled ? "cancelled" : "done"
        log.log("\(runName) DONE state=\(done) — load restored to 0 and the pool un-split. "
            + "The comparison is the synthetic's loss in the two shared arms against the two "
            + "split ones, read against the ramp's 0.02-0.03% for a smooth stream alone.")
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

    private func setLevel(_ mbit: Double) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(UplinkSynth.clamp(mbit), forKey: UplinkSynth.key)
            TunnelManager.shared.applyUplinkSynthMbit()
        }
    }

    /// ⚠️ Sent to the running tunnel and deliberately NOT persisted: an arm is a
    /// transient state of one measurement, and a diagnostic that survives a
    /// reconnect is how a retired lever once drove the tunnel for three days.
    private func setSplit(_ n: Int) {
        DispatchQueue.main.async { TunnelManager.shared.applyUplinkSplitN(n) }
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
