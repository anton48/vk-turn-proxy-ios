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
/// 🚨 THE PLAN IS PRE-REGISTERED AND IS NOT A KNOB TO TUNE WHILE WATCHING
/// RESULTS. It changed once, on 2026-08-13, and the reason it is not a search:
/// the first plan measured F=16/k=5 (+27.7% then +16.6%, 12/12 pairs) and
/// F=8/k=8 (+42.9% on two pairs, then −5.9% on six — withdrawn), while the
/// SPEEDTEST, the workload a user feels, got 30% WORSE at k=5. The first plan
/// had deliberately paired F=8 with k=8 to AVOID the coverage corner — and that
/// is exactly the corner a speedtest runs in, so it was never measured. This
/// plan measures it, with a prediction registered before the run rather than an
/// explanation fitted after: a connection is in no flow's set with probability
/// ((N−k)/N)^F, so at F=4/k=5 about 48% of the pool (≈14 of 30) should be
/// NEAR-IDLE in the treatment arms. Idle conns AND a throughput drop confirm the
/// coverage explanation and close the lever on its merits; all conns busy WITH a
/// drop refutes it and the −30% needs another cause. Phase C repeats the one arm
/// that worked, as a positive control on the session itself.
///
/// The runner writes `flowab` markers to the same log as the probe, so the
/// parser aligns arms on the log's own timestamps instead of a stopwatch.
final class UplinkFlowABRunner: ObservableObject {
    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// One phase of the plan: a flow count and the treatment k to compare
    /// against 0 at that flow count.
    private struct Phase {
        let name: String
        let flows: Int
        let treatment: Int
        let runs: Int
    }

    /// 🚨 k IS ONE NUMBER BUT COVERAGE DEPENDS ON F — that is the thing under
    /// test now. Predicted share of the pool receiving no sticky traffic,
    /// ((30−k)/30)^F: **F=4/k=5 → 48%**, F=8/k=5 → 23%, F=16/k=5 → 5%. The first
    /// two are the corner a speedtest lives in and the corner the previous plan
    /// stepped around; the third is the arm already measured twice and is here
    /// only to prove the session is comparable.
    private let phases = [
        Phase(name: "A", flows: 4, treatment: 5, runs: 2),
        Phase(name: "B", flows: 8, treatment: 5, runs: 2),
        Phase(name: "C", flows: 16, treatment: 5, runs: 1),
    ]
    private let armSec = 15
    private let armsPerRun = 4
    /// Between runs: the pipeline holds MiB that keep draining after the sender
    /// stops (tens of MiB at F=32, seconds' worth), and that drain must not be
    /// attributed to whichever arm happens to start next. Held at k=0.
    private let cooldownSec = 10

    var estimatedSeconds: Int {
        phases.reduce(0) { $0 + $1.runs * (armSec * armsPerRun + cooldownSec) }
    }

    func start(host: String, port: UInt16, probe: UplinkCwndProbe) {
        guard !running else { return }
        running = true
        cancelledFlag.set(false)
        self.probe = probe
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run(host: host, port: port, probe: probe)
        }
    }

    /// 🚨 Stops the TRAFFIC as well as the schedule. The first version only set a
    /// flag the runner checked between 15-second arms and left the probe sending,
    /// so Stop appeared to do nothing for up to a minute — reported from device.
    func cancel() {
        cancelledFlag.set(true)
        probe?.stop()
    }

    private weak var probe: UplinkCwndProbe?

    private func run(host: String, port: UInt16, probe: UplinkCwndProbe) {
        let log = SharedLogger.shared
        let runSec = armSec * armsPerRun
        var runIdx = 0
        var aborted = 0
        let total = phases.reduce(0) { $0 + $1.runs }

        log.log("flowab PLAN host=\(host):\(port) phases=\(phases.count) runs=\(total) "
            + "armSec=\(armSec) armsPerRun=\(armsPerRun) cooldownSec=\(cooldownSec) "
            + "estimated=\(estimatedSeconds)s — pairs are scored per arm AFTER discarding 4s past each flip")

        for phase in phases {
            for r in 0..<phase.runs {
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

                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: phase.flows, durationSec: runSec)
                }
                // 🚨 WAIT FOR BYTES, NOT FOR THE CALL. The first version started
                // the arm clock here, and in run 5 of 2026-08-13 the probe spent
                // 25.8 s connecting its flows through the tunnel — so two arms
                // were flipped over an idle link and that run had to be thrown
                // away. `running` is true the instant start() is called;
                // `sending` is true when the CSV's t_ms starts counting.
                let connectDeadline = Date().addingTimeInterval(60)
                while !probe.sending && Date() < connectDeadline && !cancelled {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                if !probe.sending {
                    log.log("flowab ABORT r=\(runIdx) — the flows never came up within 60s; "
                        + "check the sink and that the tunnel is up")
                    aborted += 1
                    cancelledFlag.set(true)
                    break
                }
                let startedAt = Date()
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
                    cancelledFlag.set(true) // an abort ends the plan
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

    /// Sleeps in short slices so Stop is felt immediately. A single
    /// Thread.sleep(15) is why the first version took up to an arm to react.
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
