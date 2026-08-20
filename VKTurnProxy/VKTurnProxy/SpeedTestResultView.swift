import SwiftUI

/// The finished (or in-flight) result.
///
/// 🚨 IT RENDERS FROM THE RUN, NOT FROM THE SCREEN. Everything here comes from
/// `run` — the parameters the measurement was started with — and from `progress`
/// — what the engine reported. Nothing reads the pickers, because they are live
/// bindings: changing Direction after a run used to change which rows a finished
/// result displayed.
struct SpeedTestResultView: View {
    let run: SpeedTestRunConfig
    let progress: SpeedTestProgress
    let path: SpeedTestPathTrace

    var body: some View {
        // 🚨 The error and the rows are NOT exclusive. They used to be, so
        // pressing Stop during the upload phase of a "both" run replaced a
        // completed, valid download figure with a red triangle — discarding a
        // measurement the user had already paid 15 seconds for.
        if let err = progress.error {
            Label(err, systemImage: "exclamationmark.triangle")
                .foregroundColor(.red)
                .font(.callout)
        }
        // A direction that did not run is ABSENT, not zero — Go omits it.
        if run.ranDownload, let down = progress.download {
            phaseRow("Download", down)
        }
        if run.ranUpload, let up = progress.upload {
            phaseRow("Upload", up)
        }
        metadata
    }

    @ViewBuilder
    private func phaseRow(_ title: String, _ phase: SpeedTestPhase) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.headline)
                Spacer()
                Text(String(format: "%.1f Mbit/s", phase.rawMbps))
                    .font(.headline.monospacedDigit())
            }
            // Both figures, always. They answer different questions and it is
            // normal for them to disagree: the engine's own number is weighted
            // to the last seconds of the run, the raw one is the average.
            Text(String(format: "engine %.1f · raw %.1f", phase.libraryMbps, phase.rawMbps))
                .font(.caption.monospacedDigit())
                .foregroundColor(.secondary)

            Text(Self.timing(phase, requested: progress.requestedSec))
                .font(.caption.monospacedDigit())
                .foregroundColor(.secondary)

            Text(Self.connections(phase, threads: run.threads))
                .font(.caption.monospacedDigit())
                .foregroundColor(.secondary)

            if phase.confirmedRatio > 0 && phase.confirmedRatio < 0.999 {
                Text(String(format: "confirmed %.1f%%", phase.confirmedRatio * 100))
                    .font(.caption.monospacedDigit())
                    .foregroundColor(.secondary)
            }
            ForEach(phase.warnings ?? [], id: \.self) { w in
                Label(w, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
        }
        .padding(.vertical, 2)
    }

    /// 🚨 NOTHING IS SUBTRACTED HERE. The warm-up and the window arrive already
    /// split, and they sum to the actual duration by construction. The old line
    /// printed the whole phase duration beside a rate measured over a shorter
    /// window, so a research run read "20.0s" next to a figure covering 15 —
    /// two numbers on one line that could not both be true.
    static func timing(_ phase: SpeedTestPhase, requested: Int) -> String {
        if phase.warmupSec > 0 {
            return String(format: "%.1fs warm-up discarded + %.1fs measured (asked for %ds)",
                          phase.warmupSec, phase.windowSec, requested)
        }
        return String(format: "%.1fs measured of %ds asked", phase.windowSec, requested)
    }

    /// The figure that says whether "Threads" meant anything.
    static func connections(_ phase: SpeedTestPhase, threads: Int) -> String {
        String(format: "%d threads · %d TCP connections at once · %d opened",
               threads, phase.peakConns, phase.dials)
    }

    @ViewBuilder
    private var metadata: some View {
        VStack(alignment: .leading, spacing: 2) {
            // 🚨 Mandatory, not decoration: the "label it, do not refuse it"
            // decision made visible. Without it a DIRECT-mode run reads as VPN
            // speed — and if the route moved mid-run this says THAT instead of
            // picking one of the two.
            Text(path.label)
                .font(.caption.bold())
                .foregroundColor(path.isAttributable ? .secondary : .orange)

            if !progress.serverDesc.isEmpty {
                Text("\(progress.serverDesc) · id \(progress.serverID)").font(.caption)
            }
            if progress.pingMs > 0 {
                Text(String(format: "ping %.0f ms · %@", progress.pingMs, progress.estimator))
                    .font(.caption)
            }
            if !progress.mode.isEmpty {
                Text(progress.mode).font(.caption)
            }
            if !progress.ooklaSeesIP.isEmpty {
                // Named for whose view it is: measured 2026-08-20 to differ from
                // this device's actual address by a whole address.
                Text("seen by Ookla as \(progress.ooklaSeesIP) (\(progress.ooklaSeesISP))").font(.caption)
            }
            Text(progress.engine).font(.caption)
        }
        .foregroundColor(.secondary)
    }
}
