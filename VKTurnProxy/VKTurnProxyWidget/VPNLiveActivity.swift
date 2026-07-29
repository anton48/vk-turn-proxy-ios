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
// STAGE 2 adds the controls. Two rules learned on the prototype:
//
//  a. The island's expanded .bottom region fits THREE buttons and silently CLIPS
//     anything after them — a cancel/paging row stacked under the server list
//     simply vanished, leaving no way out of the picker. Chrome therefore lives
//     in .leading/.trailing, which are separate regions.
//  b. An expired picker renders as the NORMAL layout. staleDate is the picker's
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
                        Text(shortStatus(context.state.status))
                            .font(.subheadline.weight(.medium))
                            .lineLimit(1)
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
                            // Nothing else may go in here — see rule (a) above.
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
                clock(context)
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            } minimal: {
                // Several activities collapse to this single glyph, so it has to
                // identify the app on its own — a bare dot could be anyone's.
                shield(context)
            }
            .keylineTint(tint(context))
        }
    }

    // MARK: - Controls (iOS 17+)

    /// Is the picker open AND still live? See rule (b) in the file header.
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
                // Never let a long uptime squeeze the name below legibility.
                .lineLimit(1)
                .fixedSize()
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
    @ViewBuilder
    private func clock(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
        if context.isStale {
            // A question mark, not a dash: in the compact island this glyph and
            // the greyed shield are the ONLY room there is to say "we are not
            // watching any more", and a dash reads as "no session".
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
