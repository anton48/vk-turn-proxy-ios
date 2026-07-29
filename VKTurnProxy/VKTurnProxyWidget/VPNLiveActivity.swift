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

import ActivityKit
import SwiftUI
import WidgetKit

struct VPNLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: VPNActivityAttributes.self) { context in
            lockScreen(context)
                .activityBackgroundTint(Color.black.opacity(0.45))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
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
                DynamicIslandExpandedRegion(.trailing) {
                    clock(context)
                        .font(.subheadline.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                DynamicIslandExpandedRegion(.bottom) {
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

    // MARK: - Lock Screen

    @ViewBuilder
    private func lockScreen(_ context: ActivityViewContext<VPNActivityAttributes>) -> some View {
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
