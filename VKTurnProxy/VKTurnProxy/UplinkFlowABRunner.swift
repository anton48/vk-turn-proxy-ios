import Foundation

/// Drives the flow-local-path A/B end to end: it runs the cwnd probe repeatedly
/// and flips `flow_paths_k` on a schedule, so the arms are separated by seconds
/// of wall clock rather than by however long a human takes to tap a picker.
///
/// WHY THIS EXISTS RATHER THAN A CHECKLIST. The comparison is only readable if
/// the arms sit inside one state of the line: it has been measured moving
/// 75 → 363 Mbit/s in ~70 minutes, and the session spread is ±40%, so anything
/// scored across a gap is drift. Hand-driving it means the flip instants, the
/// arm lengths and the run order all vary per arm — the three quantities the
/// pairing depends on. Here they are constants.
///
/// 🚨 THE PLAN BELOW IS THE PRE-REGISTERED ONE. It is not a starting point to
/// tune while looking at results: primary F=16/k=5, F=8 with k=8 (the coverage
/// correction — at F=8/k=5 about seven of thirty connections get no sticky
/// traffic and the aggregate would fall for a structural reason that reads as a
/// KILL of the mechanism), four 15 s arms per run, three runs per phase with the
/// starting arm alternated so order effects cancel. Changing it after seeing a
/// number turns the experiment into a search.
///
/// The runner writes `flowab` markers to the same log as the probe, so the
/// parser aligns arms on the log's own timestamps instead of a stopwatch.
final class UplinkFlowABRunner: ObservableObject {
    @Published var running = false
    @Published var status = "idle"

    private var cancelled = false

    /// One phase of the plan: a flow count and the treatment k to compare
    /// against 0 at that flow count.
    private struct Phase {
        let name: String
        let flows: Int
        let treatment: Int
    }

    /// 🚨 Coverage decides these pairings, not preference. A connection is in no
    /// flow's set with probability ((N−k)/N)^F, so at F=8 a k of 5 leaves ~23% of
    /// the pool unused; k=8 brings that to ~8%. At F=16, k=5 already leaves only
    /// ~5%, which is why F=16 is the primary arm.
    private let phases = [
        Phase(name: "A", flows: 16, treatment: 5),
        Phase(name: "B", flows: 8, treatment: 8),
    ]

    private let runsPerPhase = 3
    private let armSec = 15
    private let armsPerRun = 4
    /// Between runs: the pipeline holds MiB that keep draining after the sender
    /// stops (tens of MiB at F=32, seconds' worth), and that drain must not be
    /// attributed to whichever arm happens to start next. Held at k=0.
    private let cooldownSec = 10

    var estimatedSeconds: Int {
        phases.count * runsPerPhase * (armSec * armsPerRun + cooldownSec)
    }

    func start(host: String, port: UInt16, probe: UplinkCwndProbe) {
        guard !running else { return }
        running = true
        cancelled = false
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run(host: host, port: port, probe: probe)
        }
    }

    func cancel() { cancelled = true }

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        let log = SharedLogger.shared
        let runSec = armSec * armsPerRun
        var runIdx = 0
        var aborted = 0
        let total = phases.count * runsPerPhase

        log.log("flowab PLAN host=\(host):\(port) phases=\(phases.count) runsPerPhase=\(runsPerPhase) "
            + "armSec=\(armSec) armsPerRun=\(armsPerRun) cooldownSec=\(cooldownSec) "
            + "estimated=\(estimatedSeconds)s — pairs are scored per arm AFTER discarding 4s past each flip")

        for phase in phases {
            for r in 0..<runsPerPhase {
                if cancelled { break }
                runIdx += 1

                // Alternate the starting arm so an order effect cancels across
                // the three runs instead of loading onto the treatment.
                let arms: [Int] = (r % 2 == 0)
                    ? [0, phase.treatment, 0, phase.treatment]
                    : [phase.treatment, 0, phase.treatment, 0]

                publish("phase \(phase.name) · run \(runIdx)/\(total) · F=\(phase.flows) · arming k=\(arms[0])")
                setK(arms[0])
                // Let the provider message land before the first byte moves, so
                // arm 1 is not half of the previous state.
                sleep(seconds: 1)
                if cancelled { break }

                log.log("flowab RUN r=\(runIdx)/\(total) phase=\(phase.name) F=\(phase.flows) "
                    + "treat=\(phase.treatment) arms=\(arms.map(String.init).joined(separator: ","))")

                let startedAt = Date()
                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: phase.flows, durationSec: runSec)
                }
                log.log("flowab ARM r=\(runIdx) i=1/\(armsPerRun) k=\(arms[0]) t=0")

                var armAborted = false
                for i in 1..<armsPerRun {
                    sleep(seconds: armSec)
                    if cancelled { armAborted = true; break }
                    // The probe ending early means it never connected (the sink
                    // is down, or the tunnel is). Stop the whole plan rather
                    // than spending the remaining minutes on nothing.
                    if !probe.running {
                        log.log("flowab ABORT r=\(runIdx) — the probe stopped after "
                            + "\(Int(Date().timeIntervalSince(startedAt)))s of \(runSec)s; "
                            + "check the sink and that the tunnel is up")
                        armAborted = true
                        break
                    }
                    setK(arms[i])
                    log.log("flowab ARM r=\(runIdx) i=\(i + 1)/\(armsPerRun) k=\(arms[i]) t=\(i * armSec)")
                    publish("phase \(phase.name) · run \(runIdx)/\(total) · F=\(phase.flows) · "
                        + "arm \(i + 1)/\(armsPerRun) · k=\(arms[i])")
                }
                if armAborted {
                    aborted += 1
                    if !cancelled { cancelled = true } // an abort ends the plan
                    break
                }

                // Ride out the last arm, then drop to the control arm for the
                // drain so the cooldown belongs to no treatment.
                let elapsed = Date().timeIntervalSince(startedAt)
                if elapsed < Double(runSec) { sleep(seconds: Int(Double(runSec) - elapsed) + 1) }
                setK(0)
                log.log("flowab RUNEND r=\(runIdx) elapsed=\(Int(Date().timeIntervalSince(startedAt)))s")

                if runIdx < total && !cancelled {
                    publish("cooling down \(cooldownSec)s (k=0, letting the pipeline drain)")
                    log.log("flowab COOLDOWN r=\(runIdx) sec=\(cooldownSec) k=0")
                    sleep(seconds: cooldownSec)
                }
            }
            if cancelled { break }
        }

        // 🚨 Always leave the tunnel in the shipped state, on every exit path —
        // a cancelled run must not leave an experimental arm armed for the rest
        // of the day.
        setK(0)
        let done = cancelled ? (aborted > 0 ? "aborted" : "cancelled") : "done"
        log.log("flowab DONE state=\(done) runs=\(runIdx)/\(total) aborted=\(aborted) — "
            + "k restored to 0. Export the log now: at 1s ticks it rotates in about half a day.")
        publish(done == "done"
            ? "done — \(runIdx) runs. Export the log."
            : "\(done) after \(runIdx) run(s). k restored to 0.", running: false)
    }

    /// Applies k the same way the picker does — through UserDefaults so the UI
    /// follows along and a reconnect keeps it, then the live provider message so
    /// it lands without a reconnect (which would insert a ~107 s ramp between
    /// arms and defeat the whole design).
    private func setK(_ k: Int) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(FlowPaths.clamp(k), forKey: "flowPathsK")
            TunnelManager.shared.applyFlowPathsK()
        }
    }

    private func sleep(seconds: Int) {
        guard seconds > 0 else { return }
        Thread.sleep(forTimeInterval: TimeInterval(seconds))
    }

    private func publish(_ s: String, running r: Bool? = nil) {
        DispatchQueue.main.async {
            self.status = s
            if let r = r { self.running = r }
        }
    }
}
