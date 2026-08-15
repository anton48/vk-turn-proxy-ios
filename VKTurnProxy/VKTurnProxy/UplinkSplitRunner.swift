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

    /// After the real load is switched on or off, before the arm is declared:
    /// long enough for 8 TCP flows to leave slow start, and for the pool to
    /// drain when it goes the other way.
    private let settleSec = 12

    /// 🎯 THE SEQUENCE, and it is the user's (2026-08-16). Six arms, a palindrome
    /// in every condition, so a drift across the session cannot load onto any of
    /// them:
    ///
    ///     solo · shared · split · split · shared · solo
    ///
    /// The two SOLO arms are what make the reading unambiguous, and they are the
    /// part my first plan got wrong: it leaned on the ramp's 0.02-0.03% from
    /// ANOTHER SESSION as the "alone" reference, on a line that moves 75 → 363
    /// Mbit/s inside 70 minutes. The control belongs in the same minutes.
    ///
    ///	  shared loses, split ≈ solo   ⇒ the competition is ALLOCATION-LOCAL:
    ///	                                 a shared meter or buffer per allocation.
    ///	  shared > split > solo        ⇒ allocation-local AND something wider —
    ///	                                 the relay, or the leg before it.
    ///	  shared ≈ split > solo        ⇒ the mechanism is NOT the shared
    ///	                                 allocation; it is the relay or beyond.
    ///	  all three equal              ⇒ either the effect needs a different load,
    ///	                                 or the treatment did not engage — read
    ///	                                 `split=` before concluding anything.
    ///
    /// 🚨 SOLO AND SPLIT ARE GEOMETRY-MATCHED, which is the other half of making
    /// the table unambiguous: in BOTH the synthetic rides the same 15
    /// allocations at the same 15 Mbit/s, and the ONLY difference is whether real
    /// TCP is running on the other 15. Without that, "split ≈ solo" could be a
    /// coincidence of fan-out (15 paths against 30) rather than a statement about
    /// the neighbour.
    ///
    /// ⚠️ SHARED IS DELIBERATELY *NOT* GEOMETRY-MATCHED — it is the historical
    /// condition (synthetic over all 30 at 30 Mbit/s, real TCP over all 30), kept
    /// exactly as the runs that produced 0.5-2.7% so this session can show the
    /// effect is present at all. Read shared↔split as a positive control, and
    /// solo↔split as the measurement.
    private enum Arm { case solo, shared, split }
    private let arms: [Arm] = [.solo, .shared, .split, .split, .shared, .solo]

    /// Two transitions of the real load (on before arm 2, off before arm 6)
    /// each cost a settle.
    var estimatedSeconds: Int { warmupSec + arms.count * (armSec + gapSec) + 2 * settleSec }

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
        // 🚨 OUTER TRANSPORT IS FIXED TO TCP, and this is a refusal rather than a
        // note. TURN over TCP is terminated at the relay, so the phone → relay
        // hop is protected by retransmission and every gap the server counts is
        // made AT OR AFTER the relay — which is precisely the region this run is
        // trying to divide. On UDP both hops are exposed and the arms would carry
        // an extra term that has nothing to do with the split.
        guard isTCP else {
            log.log("\(runName) REFUSED — the active server is on UDP transport. This run fixes "
                + "the outer transport to TCP so the first hop is retransmission-protected and "
                + "every counted gap is at or after the relay. Switch the server to TCP.")
            publish("not started — switch the server to TCP transport", running: false)
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
        var probeRunning = false
        log.log("\(runName) TARGET \(host):\(port) — 🚨 this must be server1's INNER (tunnel) "
            + "address with `cwndsink` listening, or the real load never reaches server1.")
        log.log("\(runName) \(knobs)")
        log.log("\(runName) PLAN pool=\(active)/\(total) split=\(n)+\(conns - n) "
            + "synth=\(Int(splitMbit))Mbit/s(solo,split) vs \(Int(sharedMbit))Mbit/s(shared) "
            + "flows=\(probeFlows) armSec=\(armSec) arms=\(arms.count) transport=TCP k=1 "
            + "estimated=\(estimatedSeconds)s — arms are solo·shared·split·split·shared·solo, a "
            + "PALINDROME in every condition. "
            + "🚨 SOLO AND SPLIT ARE GEOMETRY-MATCHED: in both, the synthetic rides the SAME 15 "
            + "allocations at the SAME 15 Mbit/s, and the only difference is whether real TCP is "
            + "on the other 15 — so solo↔split is the MEASUREMENT. SHARED is the historical "
            + "condition (synthetic over all 30 at 30, real over all 30) and is the POSITIVE "
            + "CONTROL that the effect is present in this session at all; it is not "
            + "geometry-matched, so read shared↔split with that in mind. "
            + "READING: shared loses while split ≈ solo ⇒ allocation-local; shared > split > solo "
            + "⇒ allocation-local AND something wider; shared ≈ split > solo ⇒ not the shared "
            + "allocation at all; all three equal ⇒ the effect needs another load, or the "
            + "treatment did not engage. "
            + "🚨 Read `split=N synth→A=… synth→B=… wg→A=… wg→B=… wrong=…` on the memstats line "
            + "FIRST: wrong>0 VOIDS the arm, and either group at 0 means nothing was tested. "
            + "🎯 SCORE THE SYNTHETIC ALONE — its own cum-lost (index 5d170000), and in the pcap "
            + "only the SSRCs of group A, never the aggregate of both groups. Group A is conns "
            + "0-\(n - 1): map them to relay ports with the client's own `[conn N] TURN relay "
            + "allocated:` lines and select those source ports.")

        // 🚨 K IS PINNED, not assumed. Chunking is retired and its stored value
        // was found driving the tunnel for three days after its UI was deleted;
        // an experiment that cares about burst structure states its own K.
        DispatchQueue.main.async { TunnelManager.shared.applyUplinkChunkK(UplinkChunk.off) }

        publish("warm-up \(warmupSec)s")
        log.log("\(runName) WARMUP sec=\(warmupSec) — NOT SCORED")
        setSplit(0)
        setLevel(sharedMbit)
        sleep(seconds: warmupSec)

        for (i, arm) in arms.enumerated() {
            if cancelled { break }
            let no = i + 1
            setLevel(0)
            log.log("\(runName) GAP a=\(no)/\(arms.count) sec=\(gapSec)")
            publish("gap \(no == 1 ? 1 : gapSec)s before arm \(no)/\(arms.count)")
            sleep(seconds: gapSec)
            if cancelled { break }

            // The real load is only ON where the arm calls for it, and every
            // transition happens inside the GAP so no arm straddles one.
            //
            // ⚠️ TCP RESTARTS IN SLOW START. An arm that begins the instant the
            // probe does would spend its first seconds measuring a ramp, so a
            // arm that turns the load ON waits for bytes AND then settles before
            // it is declared. The arms that inherit an already-running probe pay
            // nothing, which is why the plan keeps arms 2-5 continuous.
            let wantsLoad = arm != .solo
            if wantsLoad && !probeRunning {
                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: self.probeFlows,
                                durationSec: self.estimatedSeconds + 120)
                }
                guard waitForRealLoad(probe, upTo: 45) else {
                    log.log("\(runName) ABORTED at arm \(no) — the cwnd probe never started "
                        + "sending. 🚨 `cwndsink` must be LISTENING on \(host):\(port); without "
                        + "it every arm is solo and the comparison is void.")
                    publish("aborted — no real load; is cwndsink running?", running: false)
                    setLevel(0); setSplit(0)
                    DispatchQueue.main.async { probe.stop() }
                    return
                }
                probeRunning = true
                log.log("\(runName) SETTLE sec=\(settleSec) — the probe just started; letting "
                    + "TCP leave slow start before the arm is declared")
                sleep(seconds: settleSec)
                if cancelled { break }
            } else if !wantsLoad && probeRunning {
                DispatchQueue.main.async { probe.stop() }
                probeRunning = false
                log.log("\(runName) SETTLE sec=\(settleSec) — the probe was stopped; letting the "
                    + "pool drain before the solo arm is declared")
                sleep(seconds: settleSec)
                if cancelled { break }
            }

            // Geometry: solo and split are IDENTICAL for the synthetic (same 15
            // allocations, same 15 Mbit/s); only shared puts it back on all 30.
            let splitN = (arm == .shared) ? 0 : n
            let mbit = (arm == .shared) ? sharedMbit : splitMbit
            setSplit(splitN)
            setLevel(mbit)
            let mode = "\(arm)"
            log.log("\(runName) ARM a=\(no)/\(arms.count) mode=\(mode) splitN=\(splitN) "
                + "synth=\(Int(mbit))Mbit/s flows=\(wantsLoad ? probeFlows : 0) sec=\(armSec)")
            publish("arm \(no)/\(arms.count) · \(mode) · \(armSec)s")
            sleep(seconds: armSec)
            log.log("\(runName) ARMEND a=\(no)/\(arms.count) mode=\(mode)")
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
