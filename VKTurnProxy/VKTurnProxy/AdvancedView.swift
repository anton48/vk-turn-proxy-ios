// AdvancedView.swift
//
// The "Advanced" screen, pushed from SettingsView. Home for settings that are
// opt-in, experimental, or otherwise not part of the everyday flow. Only the
// Live Activity switch lives here for now; more are expected.
//
// 🚨 Read reference: "SwiftUI pop rule" before adding anything here.
//
// This screen is PUSHED (Content → Settings → Advanced), and writing an
// @AppStorage key from a pushed screen is harmless — re-rendering a pushed view
// does not disturb the navigation stack. What is NOT harmless is letting
// ContentView observe the same key: ContentView hosts the NavigationView, and
// any re-render of it tears down whatever is pushed. That is exactly how build
// 177 and GitHub #65 happened.
//
// So the rule for every key added here: declare it on THIS screen (and wherever
// it is consumed below the navigation links), never in ContentView. Consumers
// that are not views read it through UserDefaults.standard instead.

import SwiftUI

struct AdvancedView: View {
    /// Live Activity master switch (GitHub issue #64). Default OFF — the feature
    /// is opt-in: it puts a persistent card on the Lock Screen and, on iOS 17+,
    /// controls that can disconnect the tunnel or switch servers from there.
    /// Deliberately NOT declared in ContentView (see the file header).
    @AppStorage("liveActivityEnabled") private var liveActivityEnabled = false

    /// Session clock in the COLLAPSED Dynamic Island. Default OFF because it is
    /// not free: the collapsed island is sized by its content and shares the top
    /// of the screen with the status bar, so a clock there costs one status-bar
    /// item. Same rule as above — declared HERE, never in ContentView.
    @AppStorage("liveActivityCompactClock") private var liveActivityCompactClock = false

    /// Tunnel MTU. `TunnelMTU.automatic` (0) means "don't override", which is
    /// both the default and what every pre-209 install has — see TunnelMTU.swift
    /// for where the bounds come from. One key, not two: a separate "override?"
    /// boolean would be a second thing to keep in sync, in the backup as well.
    @AppStorage("tunnelMTU") private var tunnelMTU = TunnelMTU.automatic

    /// The switch is a view onto the sentinel: on = start from the standard
    /// 1280, off = back to automatic.
    private var mtuIsManual: Binding<Bool> {
        Binding(get: { tunnelMTU != TunnelMTU.automatic },
                set: { tunnelMTU = $0 ? TunnelMTU.standard : TunnelMTU.automatic })
    }

    /// Diagnostic: skip the captcha-free VK Calls path so credential fetching
    /// falls through to the legacy solver. Existed since build 149 but only
    /// reachable by hand-editing a backup; surfaced here in build 212 because a
    /// switch nobody can find is a switch nobody tests.
    @AppStorage("forceLegacyCaptcha") private var forceLegacyCaptcha = false

    /// Force the 1 s memstats cadence (build 229). Until now 1 s was reachable
    /// only by tripping an ALLOC-SPIKE — i.e. at moments the garbage collector
    /// picked, not the person measuring — which is why of three A/B logs taken
    /// on 2026-08-11 one had 1 s ticks over the burst, one over the dead gap
    /// between runs, and one had none. Same rule as the keys above: declared
    /// HERE, never in ContentView.
    @AppStorage("memstatsFastTicks") private var memstatsFastTicks = false

    /// Diagnostic uplink cwnd probe (build 241). Ephemeral @State, not backed
    /// up: it is a one-sitting measurement, not a preference. The runner is a
    /// @StateObject so it survives this pushed view's re-renders while running.
    @StateObject private var cwndProbe = UplinkCwndProbe()
    /// The scripted uplink-duplication A/B. Same lifetime reasoning as the
    /// probe: a @StateObject so it survives this pushed view's re-renders while
    /// a six-minute plan is running.
    @StateObject private var dupAB = UplinkDupABRunner()
    /// 🚨 @AppStorage, not @State: the runner writes the same key, and the
    /// picker must follow the arm it arms. It is an experiment switch, so it is
    /// deliberately NOT in any backup — a restore must never bring back an
    /// armed arm whose ceiling is half the budget.
    @AppStorage("uplinkDupMode") private var uplinkDupMode = UplinkDup.off
    @State private var probeHost = "192.168.102.1:5202"
    @State private var probeFlows = 8
    @State private var probeDuration = 20

    var body: some View {
        Form {
            Section {
                Toggle("Enable", isOn: $liveActivityEnabled)
                    // Apply immediately rather than at the next status change:
                    // turning it OFF must remove a card that is on screen right
                    // now, and turning it ON should show one while the tunnel is
                    // already up. Requesting an activity needs the foreground,
                    // which is exactly where we are when the user taps this.
                    .onChange(of: liveActivityEnabled) { _ in
                        TunnelManager.shared.refreshLiveActivity()
                    }

                Toggle("Session time in collapsed island", isOn: $liveActivityCompactClock)
                    // Nothing to configure while the feature itself is off, and a
                    // live switch that changes nothing invites a bug report.
                    .disabled(!liveActivityEnabled)
                    // The widget cannot read this key (separate process, no App
                    // Group), so it travels in ContentState — which means the
                    // card only changes on the next push. Force one now.
                    .onChange(of: liveActivityCompactClock) { _ in
                        TunnelManager.shared.refreshLiveActivity()
                    }
            } header: {
                // Per-feature section, so the header names the feature and the
                // row says what the switch does. More sections are expected here.
                Text("Live Activity")
            } footer: {
                Text("Shows the connection state and the active server on the Lock Screen, and in the Dynamic Island on iPhone 14 Pro and later. On iOS 17+ it also gets buttons to disconnect and to switch server without opening the app. Requires iOS 16.2 or later. Off by default.\n\nSession time in the collapsed island widens it, so iOS hides part of the status bar — on cellular the network-type label, on Wi-Fi the signal indicator. The clock is always shown on the Lock Screen card and in the expanded island, where there is room for it.")
            }

            Section {
                Toggle("Set MTU manually", isOn: mtuIsManual)

                // Shown only while manual: a disabled stepper displaying the
                // sentinel would have to render "0", which is not a size.
                if tunnelMTU != TunnelMTU.automatic {
                    Stepper(value: $tunnelMTU, in: TunnelMTU.range, step: TunnelMTU.step) {
                        HStack {
                            Text("MTU")
                            Spacer()
                            Text("\(tunnelMTU)")
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Tunnel")
            } footer: {
                // The numbers are deliberately in the UI: someone reaches for
                // this setting while diagnosing, and "what should I try?" is the
                // next question. Range and reasoning live in TunnelMTU.swift.
                Text("Size of the largest packet the tunnel carries. Automatic uses \(TunnelMTU.standard); on SRTP-WRAP-A servers automatic means the server's own value, and setting it here overrides that.\n\nLower it (try \(TunnelMTU.standard - 64)) if the tunnel connects but large transfers stall — that is the usual sign that packets are too big for the network's path.\n\nThis setting is for making a difficult network work, not for going faster.\n\nAllowed range \(TunnelMTU.minimum)–\(TunnelMTU.maximum). Applied on the next connect.")
            }

            Section {
                Toggle("Force legacy captcha path", isOn: $forceLegacyCaptcha)
            } header: {
                Text("Diagnostics")
            } footer: {
                // Deliberately blunt about the cost. This is the one switch here
                // that makes the app slower and more fragile on purpose, and the
                // person who finds it should be able to tell whether they want it
                // without reading the source.
                Text("Skips the captcha-free path VK Calls uses, so getting credentials falls through to the older flow that has to solve a captcha. That solver never runs otherwise, which is exactly why it is hard to test.\n\nLeave this off. On, connecting is slower, can fail where it would have succeeded, and repeated attempts may get the captcha refused for a while. Applied on the next connect.")
            }

            // 🚨 ITS OWN SECTION, not another row under Diagnostics. A Form
            // footer belongs to the whole section, so a second unrelated switch
            // there pushes the first one's explanation below it and the text
            // reads as if it describes the wrong toggle — which is exactly what
            // happened when this shipped as one section in build 230.
            // One footer, one switch, unless the switches are one feature (the
            // two Live Activity rows above share theirs deliberately).
            Section {
                Toggle("Detailed log every second", isOn: $memstatsFastTicks)
                    // Pushed to a running tunnel instead of waiting for the next
                    // connect: the reason to reach for this is usually "the next
                    // few minutes are worth recording", and reconnecting to
                    // apply it would re-ramp 30 connections over ~107 s and
                    // record the ramp instead. proxyConfig carries the same
                    // value, so a later reconnect keeps the setting.
                    .onChange(of: memstatsFastTicks) { _ in
                        TunnelManager.shared.applyMemstatsFastTicks()
                    }
            } header: {
                Text("Logging")
            } footer: {
                Text("Writes the memory and queue lines once a second instead of once every ten — the resolution needed to see what happens inside a single second of a transfer. Takes effect immediately, on a tunnel that is already connected.\n\nLeave it off for everyday use: the log fills about ten times faster, so it starts discarding its oldest entries after roughly half a day instead of several. Turn it on for a measurement, then off.")
            }

            // 🚨 Its own section (see the note above the Logging one). Diagnostic
            // only: opens real TCP flows from the app through the tunnel and
            // reads the kernel's cwnd/flags — the direct answer to "flat window
            // (growth-starved) vs sawtooth (loss-limited)". Nothing here is a
            // preference, so it is @State, not @AppStorage — no ContentView key,
            // no backup entry.
            Section {
                TextField("Sink host:port", text: $probeHost)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.numbersAndPunctuation)
                Stepper("Flows: \(probeFlows)", value: $probeFlows, in: 1...64)
                Stepper("Duration: \(probeDuration) s", value: $probeDuration, in: 5...60, step: 5)
                Button(cwndProbe.running ? "Running…" : "Run uplink cwnd probe") {
                    let parts = probeHost.split(separator: ":", maxSplits: 1)
                    let h = parts.first.map(String.init) ?? "192.168.102.1"
                    let p: UInt16 = parts.count > 1 ? (UInt16(parts[1]) ?? 5202) : 5202
                    cwndProbe.start(host: h, port: p, flows: probeFlows, durationSec: probeDuration)
                }
                .disabled(cwndProbe.running)
                Text(cwndProbe.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                // The scripted comparison. Same section as the probe on
                // purpose: the probe is its load generator AND its instrument,
                // and switching an arm must not mean leaving this screen.
                Picker("Uplink duplication", selection: $uplinkDupMode) {
                    ForEach(UplinkDup.choices, id: \.self) { m in
                        Text(UplinkDup.label(m)).tag(m)
                    }
                }
                .onChange(of: uplinkDupMode) { _ in
                    TunnelManager.shared.applyUplinkDupMode()
                }
                Button(dupAB.running
                       ? "Running the A/B…"
                       : "Run duplication A/B (~\(dupAB.estimatedSeconds / 60) min)") {
                    let parts = probeHost.split(separator: ":", maxSplits: 1)
                    let h = parts.first.map(String.init) ?? "192.168.102.1"
                    let p: UInt16 = parts.count > 1 ? (UInt16(parts[1]) ?? 5202) : 5202
                    dupAB.start(host: h, port: p, probe: cwndProbe)
                }
                .disabled(dupAB.running || cwndProbe.running)
                if dupAB.running {
                    Button("Stop the A/B", role: .destructive) { dupAB.cancel() }
                }
                Text(dupAB.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Uplink cwnd probe")
            } footer: {
                Text("Diagnostic. Opens the chosen number of plain TCP flows to a discard sink through the tunnel, sends bulk data, and logs the kernel's snd_cwnd, srtt, loss-recovery and reordering-detected flags every 100 ms — the direct read of whether each flow's window is held flat or sawtooths.\n\nConnect the tunnel first and keep this screen in the foreground. Start a sink on the far end first (on 192.168.102.1: nc -lk 5202 >/dev/null). Results go to the log as 'cwndprobe' lines — grep them out of the exported log. For a control, run the same with the VPN off against an internet sink in the same minutes.\n\nUplink duplication is a DIAGNOSTIC and not a usable mode: sending every packet twice halves the ceiling to about 31 Mbit/s. It exists to test whether delivering the earliest of two copies shrinks the late-packet tail — the question a forward-error-correction scheme would answer far more cheaply. The middle setting sends one copy over the same 15 connections, so the two effects can be told apart. The A/B button runs the whole comparison itself and restores Off when it finishes or is stopped; keep this screen in the foreground and take a VPN-off control before and after.")
            }
        }
        .navigationTitle("Advanced")
    }
}
