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
            if let run = runner.startedRun, runner.progress.state != "idle" {
                Section {
                    SpeedTestResultView(run: run,
                                        progress: runner.progress,
                                        path: runner.pathTrace)
                } header: {
                    Text("Result")
                }
            }
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
            // 🚨 BOTH HALVES OF THIS USED TO BE FALSE.
            //   - "the engine stops early" is not true in Research mode, whose
            //     toggle is eleven lines above: two adjacent controls contradicting
            //     each other on screen. The sentence is now conditional.
            //   - "the test stops if you leave it" was implemented NOWHERE. iOS
            //     suspends the process; the phase's timer then fires on resume,
            //     the duration spans the suspended interval, and the result is a
            //     collapsed rate explained by a warning about the estimator —
            //     precisely the "true statement offered as the wrong reason" this
            //     screen's own warnings are split to avoid. Say what actually
            //     happens instead of promising a stop nothing performs.
            Text(research
                 ? "Research mode holds the full duration: a warm-up is discarded and the "
                   + "rest is measured as a fixed window, so runs at different thread counts "
                   + "can be compared. Keep the app open and on this screen — iOS suspends "
                   + "the app in the background, which corrupts the timing rather than "
                   + "stopping the run."
                 : "Duration is a ceiling: the engine stops early once the rate steadies, so "
                   + "the result reports how long each direction really ran. Keep the app open "
                   + "and on this screen — iOS suspends the app in the background, which "
                   + "corrupts the timing rather than stopping the run.")
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
                // Surfaced WHILE running, not only afterwards: if the route
                // moves now, the user can stop and re-run instead of finding out
                // at the end that the number belongs to neither path.
                if !runner.pathTrace.isAttributable {
                    Label(runner.pathTrace.label, systemImage: "arrow.triangle.branch")
                        .font(.caption)
                        .foregroundColor(.orange)
                }
            } else {
                if let refusal = runner.refusal {
                    Label(refusal, systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundColor(.orange)
                }
                Button {
                    runner.start(serverID: serverID, serverLabel: serverLabel,
                                 threads: threads, direction: direction,
                                 durationSec: durationSec, research: research)
                } label: {
                    Text("Run").frame(maxWidth: .infinity)
                }
            }
        }
    }

}
