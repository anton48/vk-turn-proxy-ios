// VPNLiveActivity.swift
//
// M1 PLACEHOLDER. Deliberately unstyled: the point of this stage is to prove
// the pipeline end to end — a third bundle that provisions, installs and gets
// handed a ContentState by the system — before any effort goes into layout.
// M2 is the design pass over these same regions.
//
// Session time is rendered with Text(timerInterval:) rather than a number we
// push: the system ticks it without any Activity.update, which matters because
// the app is usually suspended while the tunnel runs. See
// VPNActivityAttributes.swift for why no throughput counters live here.

import ActivityKit
import SwiftUI
import WidgetKit

struct VPNLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: VPNActivityAttributes.self) { context in
            // Lock Screen / banner presentation.
            HStack(spacing: 10) {
                statusDot(context.state.status)
                VStack(alignment: .leading, spacing: 2) {
                    Text(statusText(context.state.status))
                        .font(.headline)
                    Text(context.state.serverName)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                sessionClock(context.state.connectedSince)
                    .font(.subheadline)
                    .monospacedDigit()
            }
            .padding()
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    HStack(spacing: 6) {
                        statusDot(context.state.status)
                        Text(statusText(context.state.status)).font(.subheadline)
                    }
                }
                DynamicIslandExpandedRegion(.trailing) {
                    sessionClock(context.state.connectedSince)
                        .font(.subheadline)
                        .monospacedDigit()
                }
                DynamicIslandExpandedRegion(.bottom) {
                    Text(context.state.serverName)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } compactLeading: {
                statusDot(context.state.status)
            } compactTrailing: {
                sessionClock(context.state.connectedSince)
                    .font(.caption2)
                    .monospacedDigit()
            } minimal: {
                statusDot(context.state.status)
            }
            .keylineTint(statusColor(context.state.status))
        }
    }

    // MARK: - Pieces

    private func statusDot(_ s: VPNActivityStatus) -> some View {
        Circle()
            .fill(statusColor(s))
            .frame(width: 10, height: 10)
    }

    /// Live-ticking session time when connected; a dash otherwise. `.timer`
    /// counts up from the given date and is driven by the system, so it stays
    /// correct with the app suspended.
    @ViewBuilder
    private func sessionClock(_ since: Date?) -> some View {
        if let since {
            Text(since, style: .timer)
        } else {
            Text("—")
        }
    }

    private func statusColor(_ s: VPNActivityStatus) -> Color {
        switch s {
        case .connected: return .green
        case .connecting, .disconnecting: return .orange
        case .disconnected: return .gray
        }
    }

    private func statusText(_ s: VPNActivityStatus) -> String {
        switch s {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .disconnected: return "Disconnected"
        }
    }
}
