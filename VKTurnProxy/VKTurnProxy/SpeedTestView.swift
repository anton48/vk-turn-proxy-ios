import SwiftUI

/// The in-app speed test.
///
/// 🚨 Every `@AppStorage` key below is declared HERE and nowhere else. An unused
/// `@AppStorage` is still SUBSCRIBED, so declaring one in ContentView — which
/// hosts the NavigationView — makes any write to it tear down whatever is
/// pushed. That is the build-177/195 pop trap; the check is
/// `grep -c speedTest ContentView.swift` = 0.
struct SpeedTestView: View {
    let tunnel: TunnelManager

    /// 🚨 ObservedObject, not StateObject: the runner outlives this screen on
    /// purpose. See SpeedTestRunner.
    @ObservedObject private var runner = SpeedTestRunner.shared

    @AppStorage("speedTestServerID") private var serverID = ""
    @AppStorage("speedTestServerLabel") private var serverLabel = ""
    @AppStorage("speedTestThreads") private var threads = 4
    @AppStorage("speedTestDirection") private var direction = "both"
    @AppStorage("speedTestDuration") private var durationSec = 15
    @AppStorage("speedTestResearch") private var research = false

    @State private var showParameters = false

    private let threadChoices = [1, 2, 4, 8, 16, 32]

    var body: some View {
        Form {
            serverSection
            testSection
            runSection
            if runner.progress.state != "idle" { resultSection }
        }
        .navigationTitle("Speed test")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: Server

    private var serverSection: some View {
        Section {
            NavigationLink {
                SpeedTestServerPicker(serverID: $serverID, serverLabel: $serverLabel)
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(serverLabel.isEmpty ? "Auto (nearest)" : serverLabel)
                    if !serverID.isEmpty {
                        Text("id \(serverID)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        } header: {
            Text("Server")
        }
    }

    // MARK: Parameters

    private var testSection: some View {
        Section {
            Picker("Direction", selection: $direction) {
                Text("Download").tag("download")
                Text("Upload").tag("upload")
                Text("Both").tag("both")
            }
            .pickerStyle(.segmented)

            DisclosureGroup("Parameters", isExpanded: $showParameters) {
                Picker("Threads", selection: $threads) {
                    ForEach(threadChoices, id: \.self) { Text("\($0)").tag($0) }
                }
                Stepper("Duration: \(durationSec) s", value: $durationSec, in: 5...60, step: 5)
                Toggle("Research mode", isOn: $research)
                Text("Research mode discards a warm-up and reports the raw figure — "
                     + "confirmed bytes over the time they actually took — so runs at "
                     + "different thread counts can be compared.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        } header: {
            Text("Test")
        } footer: {
            Text("Duration is a ceiling: the engine stops early once the rate steadies, "
                 + "so the result reports how long each direction really ran. "
                 + "Keep the app open — the test stops if you leave it.")
        }
    }

    // MARK: Run

    private var runSection: some View {
        Section {
            if runner.isRunning {
                HStack {
                    ProgressView()
                    Text(runner.progress.stage.isEmpty ? "Running…" : "Running: \(runner.progress.stage)")
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("Stop") { runner.cancel() }
                        .foregroundColor(.red)
                }
            } else {
                if let refusal = runner.refusal {
                    Label(refusal, systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundColor(.orange)
                }
                Button {
                    runner.start(serverID: serverID, threads: threads,
                                 direction: direction, durationSec: durationSec,
                                 research: research)
                } label: {
                    Text("Run").frame(maxWidth: .infinity)
                }
            }
        }
    }

    // MARK: Result

    @ViewBuilder
    private var resultSection: some View {
        let p = runner.progress
        Section {
            if p.state == "error" {
                Label(p.error ?? "unknown error", systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            } else {
                if direction != "upload" { phaseRow("Download", p.download) }
                if direction != "download" { phaseRow("Upload", p.upload) }
                metadata(p)
            }
        } header: {
            Text("Result")
        }
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
            Text(String(format: "engine %.1f · raw %.1f · %.1fs of %ds",
                        phase.libraryMbps, phase.rawMbps, phase.actualSec, p_requested))
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

    private var p_requested: Int { runner.progress.requestedSec }

    @ViewBuilder
    private func metadata(_ p: SpeedTestProgress) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            // 🚨 Mandatory, not decoration: this is the "label it, do not refuse
            // it" decision made visible. Without it a DIRECT-mode run reads as
            // VPN speed.
            Text(runner.path.rawValue).font(.caption.bold())
            if !p.serverDesc.isEmpty {
                Text("\(p.serverDesc) · id \(p.serverID)").font(.caption)
            }
            if p.pingMs > 0 {
                Text(String(format: "ping %.0f ms · threads %d · %@",
                            p.pingMs, p.threads, p.estimator)).font(.caption)
            }
            if !p.ooklaSeesIP.isEmpty {
                // Named for whose view it is: measured 2026-08-20 to differ from
                // this device's actual address by a whole address.
                Text("seen by Ookla as \(p.ooklaSeesIP) (\(p.ooklaSeesISP))").font(.caption)
            }
            Text(p.engine).font(.caption)
        }
        .foregroundColor(.secondary)
    }
}
