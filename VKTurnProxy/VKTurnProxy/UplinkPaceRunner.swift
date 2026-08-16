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

    /// 🎯 THE ARMS ARE BURST DEPTHS NOW, AND THE RATE NEVER MOVES. `16.08/tcptest2`
    /// answered the first question — a per-allocation bucket cuts the loss 7× and
    /// raises goodput 43% — and left a residual **floor** of 0.10-0.14%. This run
    /// asks what that floor is made of, by moving the ONE parameter the evidence
    /// points at.
    ///
    /// **Why depth and not rate.** At 247 KiB/s a 100 ms window admits
    /// 24.7 KiB of drain plus the whole bucket: **40.7 KiB against the 26 KiB
    /// that 260 KiB/s allows in the same window.** The bucket is still the
    /// generous term. And the server's own 100 ms sampler agrees: the top
    /// windows fell from an almost constant 166% unpaced to a median ~130%
    /// paced, while still reaching 161-166%.
    ///
    /// **2 KiB is a one-packet credit** at `paceMaxCost` = 1530 counted bytes, so
    /// it is the diagnostic end of the axis rather than a candidate setting: it
    /// separates *"16 KiB is still too much"* from *"the spacing is destroyed
    /// BELOW us, after the pacer"*. ⚠️ Expect it to cost MORE latency, not less
    /// — nearly every packet will wait ~6 ms — which is the price of an answer,
    /// not a regression.
    ///
    /// ⚠️ **AND THE ONE THING THIS DESIGN GIVES UP, SAID OUT LOUD: there is no
    /// UNPACED arm**, so the 0.85% baseline is a PRIOR from another session and
    /// NOT a control in these minutes. The line moves 75 → 363 Mbit/s in 70
    /// minutes. That is the right trade for *"does depth move the floor"*, which
    /// is answered entirely within `burst16 ↔ burst2`; it is the wrong trade for
    /// any sentence of the form *"burst 2 recovers X% of the unpaced loss"*.
    /// If that sentence is wanted, add `off` arms at both ends and pay 4 minutes.
    /// ✅ **THE SWEEP RAN AND THE DEPTH IS SETTLED AT 16 KiB** (`16.08/tcptest3`).
    /// burst2 bought nothing on loss — within-condition replicate ratios 3.65× and
    /// 6.17× against a 3.75× between-condition contrast, exact permutation p = 2/3 —
    /// and cost **−10.5% goodput** and **+9.7% added delay per paced packet**. The
    /// only branch it excludes is "burst2 loses LESS".
    ///
    /// 🚨 And it named why depth cannot be the lever: at 247 KiB/s a 2 KiB bucket
    /// admits ≤26.7 KiB per 100 ms ≈ **106% of the knee**, yet the server's 100 ms
    /// sampler read **166-167% in all four arms**. The spacing is destroyed below
    /// the pacer, by the relay's TCP reassembly releasing a clump when a retransmit
    /// closes a hole.
    ///
    /// ⇒ **These arms are kept ONLY for the one open follow-up: the same sweep over
    /// TURN/UDP**, where there is no reassembly to compress anything. If 2 KiB then
    /// reads ~106-110% at the server, the outer TCP is confirmed as the compressor;
    /// if it stays 160%+, the destroyer is the network or the relay's scheduler.
    /// 🚫 Do NOT re-run this on TCP transport — that question is answered.
    private let arms: [Int] = [16, 2, 2, 16]   // KiB of burst; 0 would be off

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
    /// 🚨 RAISED FOR THE BURST SWEEP, DELIBERATELY. At a 2 KiB burst nearly every
    /// packet waits, and `16.08/tcptest2` already produced a 2041 ms worst gap at
    /// 16 KiB. A bound of 3 s would abort the very arm the run exists to take —
    /// throwing away ten minutes over the treatment WORKING. The bound is here to
    /// catch a load that DIED, and death shows up as `moved == 0` or a probe that
    /// is no longer running, both of which the witness checks separately.
    private let staleLoadMs = 8000

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
        var isSRTP = false
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
            isSRTP = server.useSrtp
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
        // 🚨 SRTP, NOT MERELY TCP. The pacer is wired into the SRTP writer alone —
        // the other three writer sites keep no per-connection identity and cannot
        // own a per-allocation bucket. A TCP-but-not-SRTP profile would spend the
        // whole run with the treatment silently absent.
        guard isSRTP else {
            log.log("\(runName) REFUSED — the active server is not in SRTP mode. The uplink "
                + "pacer is wired into the SRTP writer only, so every paced arm would run "
                + "unpaced with nothing saying so.")
            publish("not started — server must be in SRTP mode", running: false); return
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
        // The two depths this sweep contrasts, DERIVED from `arms` so the reading
        // printed below cannot name a burst the run does not carry.
        let depthsPlanned = Set(arms.filter { $0 > 0 }).sorted()
        let hi = depthsPlanned.last ?? 0
        let lo = depthsPlanned.first ?? 0
        log.log("\(runName) PLAN pool=\(conns) split=\(n)+\(n) synth=\(Int(synthMbit))Mbit/s on A "
            + "(NEVER paced) · real TCP flows=\(probeFlows) on B · pace=\(paceKiB)KiB/s on B ONLY, "
            + "THE RATE NEVER MOVES · arms=burst" + arms.map(String.init).joined(separator: "·burst")
            + "KiB · armSec=\(armSec) transport=TCP k=1 estimated=\(estimatedSeconds)s. "
            + "🎯 THE QUESTION: the bucket already cut the loss 7× and raised DELIVERED goodput 43% (17.1→24.6 Mbit/s at the sink; the sender-side load= agrees at +43%), leaving a "
            + "FLOOR of 0.10-0.14%. Is that floor made of bucket DEPTH, or of spacing destroyed "
            + "BELOW us after the pacer? At 247 KiB/s a 100 ms window admits 24.7KiB of drain PLUS "
            + "the whole bucket — 40.7KiB against the 26KiB that 260 KiB/s allows — so the burst is "
            + "still the generous term, and the server's 100 ms sampler agrees (top windows 166% "
            + "unpaced → median ~130% paced, still touching 161-166%). 2KiB is a ONE-PACKET credit "
            + "at paceMaxCost=1530: the diagnostic end of the axis, not a candidate setting. "
            + "⚠️ EXPECT 2KiB TO COST MORE LATENCY, not less — nearly every packet waits ~6ms. "
            + "⚠️ AND THERE IS NO UNPACED ARM: the 0.85% baseline is a PRIOR from another session, "
            + "NOT a control in these minutes. `burst16↔burst2` is the whole measurement; any "
            + "sentence of the form \"burst2 recovers X% of the unpaced loss\" is cross-session "
            + "and not supported by this run. "
            + "🎯 NEW INSTRUMENT: `rtx-by-conn=[conn:+N sb=…]` on the memstats line names WHICH "
            + "outer socket retransmitted, so a capture gap keyed to one relay port can be joined "
            + "to a stall on the SAME allocation instead of to the pool. The prior correlation "
            + "(57-66% of paced loss within ±2s of any retransmit against 19-20% unpaced) is "
            + "AGGREGATE and cannot carry a mechanism on its own. "
            + "🚨🚨 THE SINGLE SOURCE OF B-LOSS, FIXED BEFORE THE RUN: `cum-lost`/`by-idx` is "
            + "UNUSABLE for B — the real stream's WireGuard keypairs ROTATE, so a difference "
            + "between arm boundaries is undefined and its spans go NEGATIVE. The recipe is "
            + "exactly: conns \(n)-\(conns - 1) → relay ports from this log's own `[conn N] TURN "
            + "relay allocated:` lines · the pcap filtered to THOSE ports only · the outer RTP "
            + "sequence per SSRC SEPARATELY, with 16-bit unwrap · reported as "
            + "expected(span)/received(distinct)/missing plus reordered and dup · arm boundaries "
            + "taken from these ARM/ARMEND markers. 🚨 Counting FORWARD JUMPS instead would "
            + "double-charge a reordered packet and overstate missing — span-minus-distinct is "
            + "immune to reordering and is the same semantics as `by-idx`'s N. The scorer is "
            + "`tools/logscore/paceab_score.py`, written BEFORE this run and commissioned against "
            + "`16.08.2026/tcptest1`, where it reproduced 0.88%/0.79% on B and 0.0000% on A. "
            + "Group A's synthetic REMAINS scoreable from the counter (index 5d170000, fixed by "
            + "construction) and is the CROSS-TALK CONTROL: it must stay ~0. "
            + "🚨 THE ENGAGEMENT VERDICT IS THE `PACE-ARMEND` LINE, ONE PER PACED ARM, NOT the "
            + "per-tick `pace=` field — that one covers ten seconds and a zero in it is a quiet "
            + "interval, not a verdict. `PACE-ARMEND … waited=N(x%) total=… planned=… max=…` is "
            + "the arm's own accumulator, printed once when the pacer is turned off. "
            + "`waited=0` there means the bucket never emptied and THE ARM TESTED NOTHING — "
            + "group B's mean is ~152 KiB/s against a \(paceKiB) KiB/s rate, so this bucket can "
            + "only act on BURSTS by construction and an inert arm is the likely failure, not a "
            + "null. ⚠️ `total` is MEASURED writer-time and `planned` is what the bucket asked "
            + "for; only `total` may be divided by the interval to get a dose. If loss does not "
            + "fall, move the BURST before the rate: the losses are block-shaped (14-21 packets, "
            + "20-28 KB), i.e. a DEPTH. "
            + "⚠️ EXPECT `sendch-block` AND `gapmax` TO RISE IN THE PACED ARMS — a writer without "
            + "budget sleeps and the queue backs up into the inner TCP. That is the pacer "
            + "working, not a regression; do not void an arm for it. "
            // 🚨 THE READING IS THIS SWEEP'S, NOT THE FIRST A/B's. What stood here was
            // the pacer A/B's KEEP gate — four criteria including an ABSOLUTE
            // "goodput > 17.3 Mbit/s DELIVERED", which is a threshold taken from
            // another session's unpaced arms. This run has no unpaced arm and its own
            // text forbids differencing against that baseline, so the gate contradicted
            // the plan it was printed on. This asks a DIFFERENT question — what the
            // residual floor is made of — and its outcomes are read burst-to-burst.
            + "🎯 THE READING, and every branch is \(hi)↔\(lo) WITHIN this run: "
            + "burst\(lo) loses LESS ⇒ \(hi)KiB was still too generous and the floor is OURS to "
            + "lower, the depth axis is live · burst\(lo) ≈ burst\(hi) ⇒ the floor is NOT set by "
            + "our bucket's depth, so the spacing is destroyed BELOW us AFTER the pacer, and "
            + "`rtx-by-conn` is then the lead that matters · burst\(lo) loses MORE ⇒ we are "
            + "throttling past the point where our own queue costs more than the drops did. "
            + "⚠️ burst\(lo) SHOULD COST MORE LATENCY, NOT LESS — a one-packet credit makes nearly "
            + "every packet wait; if `sendch-wait` and `gapmax` do NOT rise on it, suspect that "
            + "the setting never reached the extension rather than a mild treatment. "
            + "🚫 NO ABSOLUTE THRESHOLD ON LOSS OR GOODPUT — no arm here is unpaced, so a "
            + "criterion of the form \"below X%\" or \"above Y Mbit/s\" is borrowed from another "
            + "session and means nothing in these minutes. A rises ⇒ a pacer or split bug.")

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

            // 🚨 RE-ARM THE SYNTHETIC EVERY ARM. Its generator carries a TEN-MINUTE
            // safety stop, and this plan is 549 s nominal plus up to 45 s waiting
            // for the real load to come up — 594 s, leaving six seconds for
            // oversleep, IPC and scheduling. If that deadline fires, the real
            // load keeps running, nothing tells the runner, and GROUP A SILENTLY
            // STOPS BEING A CONTROL. Re-sending the SAME rate does not restart
            // the generator; it only refreshes the deadline.
            // *(User-caught, 2026-08-16.)*
            setLevel(synthMbit)
            let paced = arm > 0
            setPace(paced ? paceKiB : 0, burstKiB: arm)
            let mode = paced ? "burst\(arm)" : "unpaced"
            log.log("\(runName) ARM a=\(no)/\(arms.count) mode=\(mode) "
                + "pace=\(paced ? "\(paceKiB)KiB/s burst \(arm)KiB on B" : "off") "
                + "synth=\(Int(synthMbit))Mbit/s(A) flows=\(probe.flowCensus().live)/\(probeFlows)(B) "
                + "sec=\(armSec)")
            publish("arm \(no)/\(arms.count) · \(mode) · \(armSec)s")

            // 🚨 openLoadWindow, not loadProgress: it RESETS the gap watermark so
            // `gapmax` measures THIS arm. Reading the snapshot without opening the
            // window is what made three arms report the same 2041 ms.
            let before = probe.openLoadWindow()
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
            // ⚠️ `synthA=` is the re-armed level, not a measurement of what flowed —
            // the measurement is `synth→A` on the memstats lines inside the arm,
            // which must sit at ~1430 packets/s for 15 Mbit/s. Printing the level
            // here is what makes a silent generator deadline visible as a
            // disagreement between the two.
            let note = " load=+\(moved / (1 << 20))MiB idle=\(after.idleMs)ms "
                + "gapmax=\(after.worstGapMs)ms flows=\(census.live)/\(probeFlows) "
                + "synthA=\(Int(synthMbit))Mbit/s(re-armed)"
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
        // 🚨 THE CLOSING LINE IS WHERE THE READER TAKES THE COMPARISON FROM, so it
        // is DERIVED from `arms` rather than written out. Its first version said
        // "the two paced arms against the two unpaced ones" and "the two
        // PACE-ARMEND lines" — true of the first A/B and false of this sweep,
        // where every arm is paced, all four carry a verdict and no unpaced arm
        // exists at all. A constant that duplicates knowledge living in `arms`
        // goes stale the moment `arms` changes, and this is the third time here.
        let pacedArms = arms.filter { $0 > 0 }.count
        let depths = Set(arms.filter { $0 > 0 }).sorted()
        let comparison = depths.count > 1
            ? "THE COMPARISON IS burst\(depths.last ?? 0) AGAINST burst\(depths.first ?? 0) "
                + "— EVERY ARM IS PACED and there is NO unpaced control in these minutes, so the "
                + "0.85% unpaced baseline is a PRIOR from another session and must not be "
                + "differenced against these arms"
            : "THE COMPARISON IS THE PACED ARMS AGAINST THE UNPACED ONES"
        log.log("\(runName) DONE state=\(done) — pace, load and split all restored to 0. "
            + "🚨 \(comparison), on group B's "
            + "RTP-sequence gaps from the capture — NOT on `cum-lost`, which cannot difference a "
            + "rotating keypair. Group A's synthetic is the cross-talk control and must still "
            + "read ~0. 🚨 READ THE \(pacedArms) `PACE-ARMEND` LINES FIRST — one per paced arm, "
            + "printed when its pacer was turned off, carrying that ARM's own waited/total AND "
            + "the rate/burst it actually ran at. The per-tick "
            + "`pace=` field covers ten seconds and cannot speak for an arm. "
            + "`tools/logscore/paceab_score.py` refuses to print a table unless every paced arm "
            + "has its own verdict, in its own gap, engaged, and REPORTING THE RATE AND BURST "
            + "ITS LABEL CLAIMS — the setting is sent to the extension fire-and-forget, so "
            + "\"asked\" and \"applied\" are two different facts.")
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

    private func setPace(_ kib: Int, burstKiB: Int = 16) {
        DispatchQueue.main.async {
            TunnelManager.shared.applyUplinkPace(kib: kib, burstKiB: burstKiB, groupBOnly: true)
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
