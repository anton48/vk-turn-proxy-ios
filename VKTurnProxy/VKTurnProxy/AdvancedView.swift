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
        }
        .navigationTitle("Advanced")
    }
}
