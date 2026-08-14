import Foundation

/// Drives the uplink-duplication A/B end to end: it runs the cwnd probe
/// repeatedly and switches the duplication arm on a schedule, so the arms are
/// separated by seconds of wall clock rather than by however long a human takes
/// to tap a picker.
///
/// WHY A RUNNER RATHER THAN A CHECKLIST. The comparison is only readable if the
/// arms sit inside ONE state of the line: it has been measured moving
/// 75 → 363 Mbit/s in ~70 minutes, and the session spread is ±40%, so anything
/// scored across a gap is drift, not treatment. Hand-driving it varies the flip
/// instants, the arm lengths and the run order — the three quantities the
/// pairing depends on. Here they are constants.
///
/// 🚨 THE PLAN IS PRE-REGISTERED AND IS NOT A KNOB TO TUNE WHILE WATCHING
/// RESULTS. The predictions live below, written before the first run:
///
///  • **dup rises and the >155 ms hole tail falls** ⇒ earliest-of-two works,
///    and systematic FEC can buy most of it back at 1/8 the redundancy instead
///    of 1/1. That is the result that justifies building the XOR scheme and the
///    server-side recovery path.
///  • **nothing moves** ⇒ FEC will not work either: the tail is not made of
///    independent per-connection stalls, and a second draw of the same
///    distribution cannot help.
///  • **the tail falls but throughput does not** ⇒ our ACK-clock account of the
///    upload limit is INCOMPLETE. That is a finding about the model, and it is
///    worth more than the mode itself.
///
/// 🚨 AND WHY THREE ARMS RATHER THAN TWO. Duplicating over two groups of 15
/// changes redundancy AND halves the paths each copy races. With only off/dup a
/// null could not tell "earliest-of-two does not help" from "each copy lost half
/// its fan-out" — and this project has already spent a session on an arm that
/// moved two things at once. Phase A prices the width change alone (15 paths,
/// one copy); phase B is the same width WITH duplication; the mechanism is the
/// difference between the two deltas, not either one against off.
///
/// Phase C repeats the duplication arm at F=8 because the closest prior
/// experiment — the server resequencer, which also traded wire for order —
/// was strongly negative-sum as the flow count rose (+155% at one flow but
/// −36% at eight, −42% at thirty-two). If duplication inverts the same way, the
/// coding rate of any real FEC has to be a function of the flow count, and it is
/// much cheaper to learn that here than after building it.
///
/// The runner writes `dupab` markers to the same log as the probe, so the parser
/// cuts arms on the log's own timestamps instead of a stopwatch.
final class UplinkDupABRunner: ObservableObject {
    @Published var running = false
    @Published var status = "idle"

    private let cancelledFlag = AtomicFlag()
    private var cancelled: Bool { cancelledFlag.get() }

    /// One phase of the plan: a flow count and the arm to compare against `off`
    /// at that flow count.
    private struct Phase {
        let name: String
        let flows: Int
        let treatment: Int
        let runs: Int
    }

    /// 🚨 F=4 IS NOT AN ARBITRARY CHOICE. A phone-side capture measured Ookla
    /// uploading with EXACTLY four flows, and the per-flow answer says a single
    /// sequenced flow at low F pulls only ~2-4 allocations because it is
    /// ACK-clocked at the fan-out's IN-ORDER delivery rate. Low F is where the
    /// head-of-line tax is paid and where the prize is.
    private let phases = [
        Phase(name: "A", flows: 4, treatment: UplinkDup.singleGroup, runs: 2),
        Phase(name: "B", flows: 4, treatment: UplinkDup.both, runs: 2),
        Phase(name: "C", flows: 8, treatment: UplinkDup.both, runs: 1),
    ]
    private let armSec = 15
    private let armsPerRun = 4
    /// Between runs: the pipeline holds MiB that keep draining after the sender
    /// stops (tens of MiB at F=32, seconds' worth), and that drain must not be
    /// attributed to whichever arm starts next. Held at `off`.
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

    /// 🚨 Stops the TRAFFIC as well as the schedule. A flag checked only between
    /// 15-second arms leaves the probe sending, so Stop appears to do nothing
    /// for up to a minute — reported from device on the previous runner.
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

        log.log("dupab PLAN host=\(host):\(port) phases=\(phases.count) runs=\(total) "
            + "armSec=\(armSec) armsPerRun=\(armsPerRun) cooldownSec=\(cooldownSec) "
            + "arms=\(phases.map { "\($0.name):F=\($0.flows)/\(UplinkDup.logName($0.treatment))" }.joined(separator: " ")) "
            + "estimated=\(estimatedSeconds)s — pairs are scored per arm AFTER discarding 4s past each flip")

        for phase in phases {
            for r in 0..<phase.runs {
                if cancelled { break }
                runIdx += 1

                // Alternate the starting arm so an order effect cancels across
                // the runs of a phase instead of loading onto the treatment.
                let arms: [Int] = (r % 2 == 0)
                    ? [UplinkDup.off, phase.treatment, UplinkDup.off, phase.treatment]
                    : [phase.treatment, UplinkDup.off, phase.treatment, UplinkDup.off]

                publish("phase \(phase.name) · run \(runIdx)/\(total) · F=\(phase.flows) · "
                    + "arming \(UplinkDup.logName(arms[0]))")
                setMode(arms[0])
                // Let the provider message land before the first byte moves, so
                // arm 1 is not half of the previous state.
                sleep(seconds: 1)
                if cancelled { break }

                log.log("dupab RUN r=\(runIdx)/\(total) phase=\(phase.name) F=\(phase.flows) "
                    + "treat=\(UplinkDup.logName(phase.treatment)) "
                    + "arms=\(arms.map { UplinkDup.logName($0) }.joined(separator: ","))")

                DispatchQueue.main.async {
                    probe.start(host: host, port: port, flows: phase.flows, durationSec: runSec)
                }
                // 🚨 WAIT FOR BYTES, NOT FOR THE CALL. `running` is true the
                // instant start() is called; `sending` is true when the CSV's
                // t_ms starts counting. Starting the arm clock at the call once
                // cost a whole run to a 25.8 s connect, with two arms flipped
                // over an idle link.
                let connectDeadline = Date().addingTimeInterval(60)
                while !probe.sending && Date() < connectDeadline && !cancelled {
                    Thread.sleep(forTimeInterval: 0.1)
                }
                if !probe.sending {
                    log.log("dupab ABORT r=\(runIdx) — the flows never came up within 60s; "
                        + "check the sink and that the tunnel is up")
                    aborted += 1
                    cancelledFlag.set(true)
                    break
                }
                let startedAt = Date()
                log.log("dupab ARM r=\(runIdx) i=1/\(armsPerRun) mode=\(UplinkDup.logName(arms[0])) t=0")

                var armAborted = false
                for i in 1..<armsPerRun {
                    sleep(seconds: armSec)
                    if cancelled { armAborted = true; break }
                    // The probe ending early means the sink is down, or the
                    // tunnel is. Stop the plan rather than spending the
                    // remaining minutes on nothing.
                    if !probe.running {
                        log.log("dupab ABORT r=\(runIdx) — the probe stopped after "
                            + "\(Int(Date().timeIntervalSince(startedAt)))s of \(runSec)s; "
                            + "check the sink and that the tunnel is up")
                        armAborted = true
                        break
                    }
                    setMode(arms[i])
                    log.log("dupab ARM r=\(runIdx) i=\(i + 1)/\(armsPerRun) "
                        + "mode=\(UplinkDup.logName(arms[i])) t=\(i * armSec)")
                    publish("phase \(phase.name) · run \(runIdx)/\(total) · F=\(phase.flows) · "
                        + "arm \(i + 1)/\(armsPerRun) · \(UplinkDup.logName(arms[i]))")
                }
                if armAborted {
                    aborted += 1
                    cancelledFlag.set(true) // an abort ends the plan
                    break
                }

                // Ride out the last arm, then drop to the control for the drain
                // so the cooldown belongs to no treatment.
                let elapsed = Date().timeIntervalSince(startedAt)
                if elapsed < Double(runSec) { sleep(seconds: Int(Double(runSec) - elapsed) + 1) }
                setMode(UplinkDup.off)
                log.log("dupab RUNEND r=\(runIdx) elapsed=\(Int(Date().timeIntervalSince(startedAt)))s")

                if runIdx < total && !cancelled {
                    publish("cooling down \(cooldownSec)s (off, letting the pipeline drain)")
                    log.log("dupab COOLDOWN r=\(runIdx) sec=\(cooldownSec) mode=off")
                    sleep(seconds: cooldownSec)
                }
            }
            if cancelled { break }
        }

        // 🚨 Always leave the tunnel in the shipped state, on every exit path.
        // A cancelled run must not leave the uplink duplicating for the rest of
        // the day — at 100% redundancy that halves the usable ceiling.
        setMode(UplinkDup.off)
        let done = cancelled ? (aborted > 0 ? "aborted" : "cancelled") : "done"
        log.log("dupab DONE state=\(done) runs=\(runIdx)/\(total) aborted=\(aborted) — "
            + "mode restored to off. Export the log now: at 1s ticks it rotates in about half a day.")
        publish(done == "done"
            ? "done — \(runIdx) runs. Export the log."
            : "\(done) after \(runIdx) run(s). Mode restored to off.", running: false)
    }

    /// Applies the arm the same way the picker does — through UserDefaults so
    /// the UI follows along and a reconnect keeps it, then the live provider
    /// message so it lands without a reconnect (which would insert a ~107 s ramp
    /// between arms and defeat the whole design).
    private func setMode(_ mode: Int) {
        DispatchQueue.main.async {
            UserDefaults.standard.set(UplinkDup.clamp(mode), forKey: "uplinkDupMode")
            TunnelManager.shared.applyUplinkDupMode()
        }
    }

    /// Sleeps in short slices so Stop is felt immediately. A single
    /// Thread.sleep(15) is why the first runner took up to an arm to react.
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
