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
    // 🚨 DECLARED HERE ONLY. An @AppStorage the NavigationView HOST observes
    // re-renders the host and POPS this pushed screen — the cause of build 177
    // and issue #65 — and an UNUSED one is still subscribed.
    // Default lives in UplinkPace.register, not in this literal: a bare
    // `= true` here would read true in the view and FALSE in every
    // non-view caller, since UserDefaults.bool returns false for an
    // absent key. The switch would show on while the tunnel ran unpaced.
    @AppStorage(UplinkPace.key) private var uplinkPaceKiB = UplinkPace.defaultKiB
    // 🚨 Declared HERE and nowhere else — never in ContentView or SettingsView.
    // An @AppStorage is subscribed even when unused, and a write to a key the
    // NavigationView host observes re-renders the host and tears down whatever
    // screen is pushed (build 177, GitHub #65). Verified with
    // `grep -c flowPathsK ContentView.swift` = 0.
    @AppStorage("flowPathsK") private var flowPathsK = FlowPaths.off
    @AppStorage("flowPathsCover") private var flowPathsCover = false
    // Same pop rule: declared HERE only. `grep -c uplinkSynthMbit
    // ContentView.swift` = 0.
    @AppStorage(UplinkSynth.key) private var uplinkSynthMbit = UplinkSynth.off

    /// Diagnostic uplink cwnd probe (build 241). Ephemeral, not backed up: it is
    /// a one-sitting measurement, not a preference.
    ///
    /// 🚨 SHARED INSTANCES, `@ObservedObject`, NOT `@StateObject` — and this is a
    /// correctness fix, not a style choice. `@StateObject` ties the object's life
    /// to the VIEW's: when this pushed screen is re-created for any reason, the
    /// old runner's background thread keeps driving the tunnel while the new view
    /// gets a fresh, idle one. On 2026-08-15 that is exactly what happened — the
    /// screen showed "idle" during a run, the next tap started a SECOND eight-arm
    /// run 38 s behind the first, and the paired arms carried 16 real flows
    /// instead of 8. With one shared instance the screen shows the true state
    /// after any re-render, and `running` means what it says.
    /// See [[DiagnosticRunLock]] for the second line of defence.
    @ObservedObject private var cwndProbe = UplinkCwndProbe.shared
    @ObservedObject private var pairedAB = UplinkPairedRunner.shared
    @ObservedObject private var flowAB = UplinkFlowABRunner.shared
    @ObservedObject private var synthAB = UplinkSynthRunner.shared
    @ObservedObject private var splitAB = UplinkSplitRunner.shared
    @ObservedObject private var paceAB = UplinkPaceRunner.shared
    @State private var probeHost = "192.168.102.1:5202"

    /// The sink address, parsed once. It used to be split inline at every call
    /// site; a fourth copy is how the runners quietly end up pointing at
    /// different hosts.
    private func probeTarget() -> (String, UInt16) {
        let parts = probeHost.split(separator: ":", maxSplits: 1)
        let h = parts.first.map(String.init) ?? "192.168.102.1"
        let p: UInt16 = parts.count > 1 ? (UInt16(parts[1]) ?? 5202) : 5202
        return (h, p)
    }

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

            // 🚨 ITS OWN SECTION, for the reason the comment below repeats: a Form
            // footer belongs to its SECTION, so sharing one would leave the other
            // switch's explanation reading as if it described this one.
            Section {
                Picker("Uplink pacing", selection: $uplinkPaceKiB) {
                    ForEach(UplinkPace.choices, id: \.self) { v in
                        Text(UplinkPace.label(v)).tag(v)
                    }
                }
                    // Live, then carried by proxyConfig — same shape as the
                    // logging switch, and for the same reason: applying it
                    // through a reconnect would re-ramp 30 connections over
                    // ~107 s and measure the ramp.
                    .onChange(of: uplinkPaceKiB) { _ in
                        TunnelManager.shared.applyUplinkPaceFromSettings()
                    }
            } header: {
                Text("Uplink pacing")
            } footer: {
                Text("Spaces this device's uploads so each relay allocation receives an even stream instead of bursts. Measured on 2026-08-16 across 30 connections and ten alternating speed tests: upload rose 30 → 47 Mbit/s and upload packet loss fell from 2.0% to 0.06%.\n\n🚧 A TEST SETTING, and the rates are COMPARISON POINTS, not a dial. 247 is what every measurement so far used. Higher rates hold back less, which should cost less delay — that is the open question this sweep exists to answer.\n\n⚠️ IT COSTS UPLOAD LATENCY: the same run measured loaded upload ping 228 → 289 ms, because packets wait in a queue inside the app. A speed test will not show it; a video call will. When comparing rates, always run Off in between — the line itself moves, and only an alternating comparison controls for that.")
            }

            // 🚨 ITS OWN SECTION, and the note above the Logging one says why:
            // a Form footer belongs to the SECTION, so putting this picker in
            // with the logging switch would leave that switch's explanation
            // reading as if it described this one. Build 230 shipped exactly
            // that bug once.
            //
            // EXPERIMENT, like uplink chunking before it — this row is expected
            // to be removed once the A/B has answered, and it is default Off.
            Section {
                Picker("Flow-local paths", selection: $flowPathsK) {
                    ForEach(FlowPaths.choices, id: \.self) { k in
                        Text(FlowPaths.label(k)).tag(k)
                    }
                }
                // Live, for the reason the logging switch is live and one more:
                // this is an A/B knob. Applying an arm through a reconnect would
                // put a ~107 s 30-connection ramp between every pair of arms on
                // a line that has been seen to move 75 → 363 Mbit/s inside 70
                // minutes, so the arms would differ by drift as much as by k —
                // the very thing the knob exists to measure. Switching live
                // keeps one state of the line, one set of connections, one ramp.
                .onChange(of: flowPathsK) { _ in
                    TunnelManager.shared.applyFlowPathsK()
                }
                // 🚨 NOT disabled while k is Off, and that was a real defect in
                // build 257. This is a SESSION mode that has to be armed BEFORE a
                // measurement, and k is 0 at rest — the A/B runner restores k=0 on
                // every exit path — so gating it on k>0 made it unreachable in
                // exactly the workflow it exists for. It simply has no effect
                // until a set is armed, which the footer says.
                Toggle("Least-used paths first", isOn: $flowPathsCover)
                    .onChange(of: flowPathsCover) { _ in
                        TunnelManager.shared.applyFlowPathsCover()
                    }
                // 🚨 A PACED GENERATOR, NOT A SECOND PROBE, AND THE REASON IS
                // THE WHOLE POINT: TCP cannot HOLD a load level — its
                // congestion control ramps until it meets something, which is
                // why per-connection load wandered 28-101% of the knee inside
                // one recorded run. The question this answers needs a level
                // held: does the loss the server measures from WireGuard's own
                // counter space move between ~30%, ~60% and ~95% of the
                // per-allocation knee? Flat at 30% and VK's meter cannot be the
                // cause, because a bucket that is never emptied cannot clip.
                //
                // ⚠️ It ADDS to real traffic rather than replacing it, and it
                // bypasses the inner TCP entirely — so read the answer at the
                // server (ΣUP, `lost`, `cum-lost`, and the by-idx split that
                // separates this stream from the real one), never here.
                Picker("Synthetic uplink load", selection: $uplinkSynthMbit) {
                    ForEach(UplinkSynth.choices, id: \.self) { m in
                        Text(UplinkSynth.label(m)).tag(m)
                    }
                }
                .onChange(of: uplinkSynthMbit) { _ in
                    TunnelManager.shared.applyUplinkSynthMbit()
                }
                .disabled(synthAB.running)

                // The scripted dose-response. Same section and footer as the
                // picker it drives, for the same reason the flow A/B sits with
                // the probe: it is that setting on a schedule, not a second
                // unrelated switch.
                //
                // 🚨 A RUNNER RATHER THAN A STOPWATCH, and the reason is on
                // record: hand-timed arms are how build 247 lost two runs of
                // six. Here the arm length, the gaps and the level order are
                // constants, and every boundary lands in the log as a marker.
                Button(synthAB.running
                        ? "Running the sweep…"
                        : "Run the load sweep (~\(synthAB.estimatedSeconds / 60) min)") {
                    synthAB.start()
                }
                .disabled(synthAB.running || cwndProbe.running || flowAB.running)
                if synthAB.running {
                    Button("Stop the sweep", role: .destructive) { synthAB.cancel() }
                }
                Text(synthAB.status)

                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Uplink experiment")
            } footer: {
                Text("Sends each connection's traffic over a few of the tunnel's paths instead of all of them, while still using every path when those few are busy. Takes effect immediately, on a tunnel that is already connected.\n\nOff is the normal behaviour. This is a measurement, not a speed setting — leave it Off unless you are running one.\n\nLeast-used paths first changes HOW those few paths are picked: each new connection takes the ones carrying the fewest others, so the small sets still add up to all of them. It does nothing while the setting above is Off, and it changes what that setting measures — so turn it on before a measurement, not during one.\n\nSynthetic uplink load sends paced filler traffic through the tunnel at a fixed rate, to hold the connections at a chosen share of what each one is allowed to carry. It applies to a tunnel that is already connected, it ADDS to whatever else the phone is sending, and it stops itself after ten minutes so a level left on cannot keep the radio busy. Off is the normal setting; the answer is read on the server, not here.\n\nThe sweep button runs the pre-registered comparison by itself: three load levels, two minutes each, twice through with the order reversed, with short gaps so the numbers for one level stay its own. It writes marker lines so the levels can be cut out of the log exactly, it refuses to start unless the connections are up, and it returns the load to Off when it finishes or is stopped. Keep this screen in the foreground, and take a VPN-off control before and after.")
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
                    let (h, p) = probeTarget()
                    cwndProbe.start(host: h, port: p, flows: probeFlows, durationSec: probeDuration)
                }
                .disabled(cwndProbe.running || flowAB.running)
                Text(cwndProbe.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                // The scripted A/B. Same feature, same section, same footer:
                // it drives the probe above rather than being a second unrelated
                // switch (which is what the one-footer-one-switch rule forbids).
                Button(flowAB.running ? "Running the A/B…" : "Run flow-path A/B (~\(flowAB.estimatedSeconds / 60) min)") {
                    let (h, p) = probeTarget()
                    flowAB.start(host: h, port: p, probe: cwndProbe)
                }
                .disabled(cwndProbe.running || flowAB.running)
                if flowAB.running {
                    Button("Stop the A/B", role: .destructive) { flowAB.cancel() }
                }
                Text(flowAB.status)
                // The synthetic alone vs the synthetic next to real inner TCP,
                // at the SAME synthetic rate — the one thing the sweep cannot
                // see, because WireGuard discards the synthetic at the index
                // lookup and so is never loaded by it.
                Button(pairedAB.running
                        ? "Running the paired A/B…"
                        : "Run synth-vs-real A/B (~\(pairedAB.estimatedSeconds / 60) min)") {
                    let (h, p) = probeTarget()
                    pairedAB.start(host: h, port: p, probe: cwndProbe)
                }
                .disabled(pairedAB.running || synthAB.running || splitAB.running || cwndProbe.running || flowAB.running)
                if pairedAB.running {
                    Button("Stop the paired A/B", role: .destructive) { pairedAB.cancel() }
                }
                Text(pairedAB.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                // The same synthetic beside the same real TCP, but with the pool
                // SPLIT so the two streams stop sharing allocations — the one
                // thing a capture at server1 cannot separate on its own.
                Button(splitAB.running
                        ? "Running the split A/B…"
                        : "Run shared-vs-split A/B (~\(splitAB.estimatedSeconds / 60) min)") {
                    let (h, p) = probeTarget()
                    splitAB.start(host: h, port: p, probe: cwndProbe)
                }
                .disabled(splitAB.running || pairedAB.running || synthAB.running
                          || cwndProbe.running || flowAB.running || paceAB.running)
                if splitAB.running {
                    Button("Stop the split A/B", role: .destructive) { splitAB.cancel() }
                }
                Text(splitAB.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                // 🎯 The answer to what the split run FOUND: the loss is
                // per-allocation and block-shaped, so a per-allocation token
                // bucket is the direct treatment. The synthetic stays unpaced on
                // group A as the cross-talk control; only group B gets the
                // bucket. 🚨 Score group B from the CAPTURE — its keypair
                // rotates and `cum-lost` cannot difference it.
                Button(paceAB.running
                        ? "Running the pace A/B…"
                        : "Run uplink-pacer A/B (~\(paceAB.estimatedSeconds / 60) min)") {
                    let (h, p) = probeTarget()
                    paceAB.start(host: h, port: p, probe: cwndProbe)
                }
                .disabled(paceAB.running || splitAB.running || pairedAB.running
                          || synthAB.running || cwndProbe.running || flowAB.running)
                if paceAB.running {
                    Button("Stop the pace A/B", role: .destructive) { paceAB.stop() }
                }
                Text(paceAB.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Uplink cwnd probe")
            } footer: {
                Text("Diagnostic. Opens the chosen number of plain TCP flows to a discard sink through the tunnel, sends bulk data, and logs the kernel's snd_cwnd, srtt, loss-recovery and reordering-detected flags every 100 ms — the direct read of whether each flow's window is held flat or sawtooths.\n\nConnect the tunnel first and keep this screen in the foreground. Start a sink on the far end first (on 192.168.102.1: nc -lk 5202 >/dev/null). Results go to the log as 'cwndprobe' lines — grep them out of the exported log. For a control, run the same with the VPN off against an internet sink in the same minutes.\n\nThe A/B button runs the pre-registered comparison by itself: five 60-second runs, flipping the flow-path setting every 15 seconds and alternating which arm starts, with the number of connections changing between phases. It writes 'flowab' markers so the arms can be cut out of the log exactly, and it restores the setting to Off when it finishes or is stopped. Keep this screen in the foreground for the whole run, and take a VPN-off control before and after it.")
            }
        }
        .navigationTitle("Advanced")
    }
}
