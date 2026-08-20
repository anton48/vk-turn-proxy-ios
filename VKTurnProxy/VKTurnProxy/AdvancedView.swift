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
    /// The DIRECT switch reads its state from the profile via TunnelManager;
    /// nothing here is @AppStorage, so the pop rule does not apply to it.
    @ObservedObject private var tunnel = TunnelManager.shared

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

    /// The uplink pacer, as a RATE in KiB/s where 0 means off — the same value
    /// the Go side stores, so the switch and the tunnel cannot disagree. Default
    /// OFF; see UplinkPace.swift for what it buys and what it costs. Declared
    /// HERE and nowhere near ContentView, per the file header.
    @AppStorage(UplinkPace.key) private var uplinkPaceKiB = UplinkPace.off

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
                Toggle("Pace the uplink", isOn: Binding(
                    get: { uplinkPaceKiB != UplinkPace.off },
                    set: { uplinkPaceKiB = $0 ? UplinkPace.onKiB : UplinkPace.off }
                ))
                // 🎯 ONE Int KEY, NOT A BOOL, and the binding is what makes a
                // rate look like a switch. The stored value IS the rate handed
                // to Go, where 0 is literally how "off" is spelled — so there is
                // no second value that can disagree with this one. A Bool key
                // read back as an integer would mean 1 KiB/s.
                    .onChange(of: uplinkPaceKiB) { _ in
                        // Applied to a running tunnel: the alternative is a
                        // reconnect, whose ~107 s thirty-connection ramp would be
                        // the price of flipping a switch. proxyConfig carries the
                        // same value, so a later reconnect keeps it.
                        TunnelManager.shared.applyUplinkPaceFromSettings()
                    }
            } header: {
                Text("Uplink")
            } footer: {
                Text("Spaces this device's uploads across the relay connections instead of sending them in bursts, so the relay's own rate limit stops cutting them.\n\nMeasured here on 30 connections under real traffic: upload 30 → 47 Mbit/s and uplink packet loss 2% → 0.06%, with download and idle ping unchanged. The cost is response time while the upload is saturated — about 60 ms more, against roughly 470 ms that this phone's cellular link adds under the same load.\n\nOff by default. Takes effect immediately, on a tunnel that is already connected.")
            }

            // Issue #72. A SWITCH, not the two buttons the experiment used: a
            // button that starts async work and says nothing reads as broken,
            // which is exactly how the first field run went (four taps because
            // nothing acknowledged the first).
            Section {
                Toggle("Send traffic around the tunnel", isOn: Binding(
                    get: { tunnel.directMode },
                    set: { on in Task { await tunnel.setDirectMode(on, from: .advancedSwitch) } }
                ))
                .disabled(tunnel.directModeBusy || tunnel.status != .connected)

                // 🚨 AN UNCONFIRMED CHANGE MUST NOT LOOK LIKE A SUCCESSFUL ONE.
                // The switch is driven by the PROFILE, so it flips as soon as
                // the profile is saved — before anything has confirmed that the
                // routes followed. Without this row a lost acknowledgement is
                // indistinguishable from success, and in the ON → OFF direction
                // that means the UI claims the tunnel is protecting traffic
                // that may still be going around it. Its own field, not the
                // shared `errorMessage`: that one is about connecting and is
                // cleared by unrelated flows. *(User-caught.)*
                if let problem = tunnel.directModeError {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("DIRECT")
            } footer: {
                Text("Sends this device's traffic straight out, while the connections to VK stay up — so switching back is instant instead of rebuilding the whole tunnel. Useful for an app or a site that refuses to work through a proxy.\n\nSwitching takes about half a second, and one packet may be lost.\n\n⚠️ While this is on, the \"all traffic through the tunnel\" protection is off: if the tunnel drops, traffic keeps flowing outside it. Reconnecting always returns to the normal mode.\n\nAvailable only while connected.")
            }

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
        }
        .navigationTitle("Advanced")
    }
}
