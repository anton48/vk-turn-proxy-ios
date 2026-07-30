// VPNLiveActivity.swift
//
// The Lock Screen and Dynamic Island presentations (GitHub issue #64, M2).
//
// Two things here are correctness, not decoration:
//
//  1. `context.isStale`. Only the app may refresh a Live Activity, and the app
//     is suspended for most of a tunnel's life — so a state published 20
//     minutes ago may no longer be true. Past the staleDate the system tells us
//     so, and every presentation then stops ASSERTING the state: the dot goes
//     grey, the label reads "Last known", and the session clock is withdrawn
//     because we can no longer vouch for it either. A control surface that
//     confidently reports a tunnel that dropped is worse than one that admits
//     it doesn't know.
//
//  2. The session clock is `Text(_:style:.timer)` over a Date, never a number
//     we push. The system ticks it with the app dead. See
//     VPNActivityAttributes.swift for why no other counter can be here.
//
// Everything is laid out for a name of arbitrary length: server names are user
// input, so every label truncates rather than pushing the timer off-screen.
//
// Three layout rules, each learned the hard way — (a) on device, (b) and (c) on
// the prototype:
//
//  a. The COMPACT island is sized by its content, and it shares the status bar
//     with the clock, signal and battery. A live text there (`style: .timer`)
//     asks for a width unrelated to the string it shows, so it MUST be given an
//     explicit `.frame` — unbounded it took ~82% of the screen and hid the status
//     bar entirely (build 205; fixed in 207). See compactTrailing for the numbers.
//  b. The island's expanded .bottom region fits THREE buttons and silently CLIPS
//     anything after them — a cancel/paging row stacked under the server list
//     simply vanished, leaving no way out of the picker. Chrome therefore lives
//     in .leading/.trailing, which are separate regions.
//  c. An expired picker renders as the NORMAL layout. staleDate is the picker's
//     deadline (see LiveActivityController): the app is asleep and cannot close
//     the menu itself, so this is the only thing that gets the user out without
//     a tap.

import ActivityKit
import SwiftUI
import WidgetKit

struct VPNLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: VPNActivityAttributes.self) { context in
            Group {
                if picking(context) { lockScreenPicker(context) } else { lockScreen(context) }
            }
                .activityBackgroundTint(Color.black.opacity(0.45))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    if picking(context), #available(iOS 17.0, *) {
                        Button(intent: ExitPickerIntent()) {
                            Image(systemName: "xmark").font(.caption2)
                        }
                        .buttonStyle(.bordered)
                    } else {
                    Label {
                        // SHORT form only: this region is ~1/3 of the island's
                        // width, and "Last known: Connected" truncated to
                        // "Last kno…" — which said less than nothing. The
                        // staleness wording lives in .bottom, which is full
                        // width; here it shows as the grey glyph and colour.
                        //
                        // Even the short form does not always fit: "Connecting…"
                        // came back as "Connecti..." on an iPhone Air (29.07).
                        // Latent since build 192 — the island had only ever been
                        // looked at while Connected, which does fit — and stage 2
                        // surfaced it by making a long stay in Connecting easy.
                        // Shrink the word rather than cut it; a scaled label is
                        // still a word, a truncated one is a puzzle.
                        Text(shortStatus(context.state.status))
                            .font(.subheadline.weight(.medium))
                            .lineLimit(1)
                            .minimumScaleFactor(0.7)
                    } icon: {
                        shield(context)
                    }
                    .foregroundStyle(context.isStale ? .secondary : .primary)
                    }
                }
                DynamicIslandExpandedRegion(.trailing) {
                    if picking(context) {
                        if context.state.pageCount > 1, #available(iOS 17.0, *) {
                            Button(intent: NextPageIntent()) {
                                Text("\(context.state.page + 1)/\(context.state.pageCount) ›")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                        }
                    } else {
                        clock(context)
                            .font(.subheadline.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                DynamicIslandExpandedRegion(.bottom) {
                    if picking(context) {
                        if #available(iOS 17.0, *) {
                            // Nothing else may go in here — see rule (b) above.
                            VStack(spacing: 4) {
                                ForEach(context.state.choices) { c in
                                    serverButton(c, busy: context.state.busyServerId == c.id)
                                }
                            }
                        }
                    } else {
                        VStack(spacing: 6) {
                            HStack(spacing: 4) {
                                Text(context.state.serverName)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                if context.isStale {
                                    Text("· last known")
                                        .lineLimit(1)
                                        .layoutPriority(1)   // drop the NAME first, not this
                                }
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            if #available(iOS 17.0, *) {
                                controls(context)
                            }
                        }
                    }
                }
            } compactLeading: {
                shield(context)
            } compactTrailing: {
                // 🚨 The `.frame` is load-bearing — never drop it. A live text
                // (`style: .timer`, and `Text(timerInterval:)` too) asks for a
                // width that has NOTHING to do with the string on screen, and the
                // compact island sizes itself to its content. Unbounded, the pill
                // grew to ~82% of the screen and swallowed the whole status bar:
                // no clock, no signal, no battery. That is what build 205 shipped.
                //
                // A/B-measured on an iPhone Air simulator, 12 h 35 m session:
                //   unbounded ................ 82% wide, status bar gone
                //   Text(timerInterval:) ..... 92% wide — worse, and no better
                //                              bounded: a 1 h range showing "0:15"
                //                              reserves as much as a 99 h one
                //   frame 44 + scale 0.6 ..... 53% wide, "12:35:18" in full ✅
                //   no clock at all .......... 40% wide
                //
                // 44pt is chosen for the longest string the format really produces
                // ("12:34:56" = 8 glyphs), which is why the prototype's 42pt was
                // wrong twice over: it was picked for "0:12" and truncated a
                // 12-hour session to "12:3…". minimumScaleFactor is the insurance
                // — past 99 h the label shrinks instead of truncating, because a
                // scaled number is still a number (same reasoning as build 203).
                //
                // What it costs is why the clock here is OPT-IN (Settings ›
                // Advanced, default off): iOS sheds status-bar items right-to-left
                // as the island grows, so 53% drops the "LTE"/"5G" label on
                // cellular — this app's normal habitat, where the signal bars,
                // battery and clock all survive — or the cellular dots on Wi-Fi.
                // Off, the pill is 40% wide and the status bar stays intact.
                //
                // `compactClock == true`, not `?? false`: nil means the state was
                // published before the setting existed, which reads as off.
                if context.state.compactClock == true {
                    clock(context)
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .frame(maxWidth: 44)
                } else if context.isStale {
                    // Staleness still has to be sayable with the clock off: the
                    // greyed shield alone reads as a colour choice, not as "we
                    // stopped being able to vouch for this" (stage 1). One
                    // character, and only while stale.
                    Text("?")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } minimal: {
                // Several activities collapse to this single glyph, so it has to
                // identify the app on its own — a bare dot could be anyone's.
                shield(context)
            }
            .keylineTint(tint(context))
        }
    }

    // MARK: - Controls (iOS 17+)

    /// Is the picker open AND still live? See rule (c) in the file header.
    private func picking(_ context: ActivityViewContext<VPNActivityAttributes>) -> Bool {
        context.state.mode == .picking && !context.isStale
    }

    @available(iOS 17.0, *)
    @ViewBuilder
    private func controls(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        HStack(spacing: 8) {
            Button(intent: DisconnectIntent()) {
                Label(context.state.status == .disconnecting ? "Disconnecting…" : "Disconnect",
                      systemImage: "power")
                    .font(.caption)
            }
            .buttonStyle(.bordered)
            .tint(.red)
            // Already on its way down — a second tap has nothing to add.
            .disabled(context.state.status == .disconnecting)

            Button(intent: EnterPickerIntent()) {
                Label("Switch", systemImage: "arrow.triangle.2.circlepath")
                    .font(.caption)
            }
            .buttonStyle(.bordered)
        }
    }

    @available(iOS 17.0, *)
    private func serverButton(_ choice: ServerChoice, busy: Bool) -> some View {
        Button(intent: SelectServerIntent(serverId: choice.id)) {
            HStack(spacing: 4) {
                if busy { Image(systemName: "circle.dotted").font(.caption2) }
                Text(choice.name)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .tint(busy ? .green : nil)
    }

    /// The picker, Lock Screen edition. Roomier than the island, so the chrome
    /// can sit on the title row instead of borrowing other regions.
    @ViewBuilder
    private func lockScreenPicker(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Switch server").font(.subheadline.weight(.semibold))
                Spacer()
                if #available(iOS 17.0, *) {
                    HStack(spacing: 6) {
                        Button(intent: ExitPickerIntent()) {
                            Image(systemName: "xmark").font(.caption2)
                        }
                        .buttonStyle(.bordered)
                        if context.state.pageCount > 1 {
                            Button(intent: NextPageIntent()) {
                                Label("More (\(context.state.page + 1)/\(context.state.pageCount))",
                                      systemImage: "chevron.right")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                }
            }
            if #available(iOS 17.0, *) {
                ForEach(context.state.choices) { c in
                    serverButton(c, busy: context.state.busyServerId == c.id)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - Lock Screen

    @ViewBuilder
    private func lockScreen(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
        HStack(spacing: 12) {
            shield(context)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(statusText(context))
                    .font(.headline)
                    .foregroundStyle(context.isStale ? .secondary : .primary)
                    .lineLimit(1)
                Text(context.state.serverName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 8)
            clock(context)
                .font(.title3.monospacedDigit())
                .foregroundStyle(.secondary)
                // Never let a long uptime squeeze the name below legibility —
                // but bound it, do NOT use .fixedSize().
                //
                // 🚨 `.fixedSize()` here made the whole card fail to render:
                // shield, status and server name appeared, the clock and BOTH
                // buttons did not. Proven by bisection in ~/work/la-widget-harness
                // on 2026-07-30 — removing this one modifier brought them back.
                // Mechanism: a live text asks for a width unrelated to its string
                // (the same property that blew up the compact island), and
                // .fixedSize() promotes that absurd width to a requirement the
                // layout cannot satisfy, so WidgetKit abandons the subtree.
                // Simulator-only so far — the device has always rendered this
                // card — but there is no version of this modifier that is worth
                // that risk.
                // 170pt because the Lock Screen does NOT render this as a clock:
                // `.timer` becomes a PHRASE there ("<1 minute", "12 hours, 35
                // minutes") while the island renders the same view as digits
                // ("2:16"). 20 characters at .title3 is ~175pt, so anything
                // tighter truncates a real session to "12 hours, 35 min…".
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .frame(maxWidth: 170, alignment: .trailing)
        }
        if #available(iOS 17.0, *) {
            controls(context)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - Pieces

    /// Status glyph. Grey whenever the content is stale — at that point the
    /// colour would be a claim we can't back.
    private func shield(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        Image(systemName: symbol(context.state.status))
            .foregroundStyle(tint(context))
            .symbolRenderingMode(.hierarchical)
    }

    /// The session clock, or a dash. Withheld while connecting (there is no
    /// session yet) and while stale (we can't vouch for it still running).
    ///
    /// Anywhere this goes it needs a width the layout controls: in the expanded
    /// island and on the Lock Screen the region itself provides one, but in the
    /// compact island it must be given an explicit `.frame` — see the note at
    /// `compactTrailing` for what an unbounded live text does to the island.
    @ViewBuilder
    private func clock(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        if context.isStale {
            // A question mark, not a dash: a dash reads as "no session", and the
            // point is that we no longer know. The compact island says the same
            // thing with its own "?" for the same reason.
            Text("?")
        } else if let since = context.state.connectedSince {
            Text(since, style: .timer)
        } else {
            Text("—")
        }
    }

    /// Plain state, for places too narrow for a qualifier.
    private func shortStatus(_ s: VPNActivityStatus) -> String {
        switch s {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .disconnected: return "Disconnected"
        }
    }

    /// Full wording — only for the Lock Screen, which has the width for it.
    private func statusText(_ context: ActivityViewContext<VPNActivityAttributes>) -> String {
        let base = shortStatus(context.state.status)
        guard context.isStale else { return base }
        return "Last known: " + base.replacingOccurrences(of: "…", with: "")
    }

    private func tint(_ context: ActivityViewContext<VPNActivityAttributes>) -> Color {
        guard !context.isStale else { return .gray }
        switch context.state.status {
        case .connected: return .green
        case .connecting, .disconnecting: return .orange
        case .disconnected: return .gray
        }
    }

    private func symbol(_ s: VPNActivityStatus) -> String {
        switch s {
        case .connected: return "lock.shield.fill"
        case .connecting, .disconnecting: return "shield.lefthalf.filled"
        case .disconnected: return "shield.slash"
        }
    }
}
