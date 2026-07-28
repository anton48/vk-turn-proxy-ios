// VPNActivityAttributes.swift
//
// The Live Activity contract, compiled into BOTH the app and the widget
// extension (see the widget target's `sources:` list in project.yml, same
// pattern as SharedLogger.swift). The app produces these values; the widget
// only renders them.
//
// Scope note (GitHub issue #64, stage 1): this stage is DISPLAY ONLY —
// connection state + active server name. No buttons, so it needs iOS 16.1
// rather than the 17.0 that interactive Live Activities require; stage 2 adds
// connect/disconnect and profile switching via App Intents and raises that
// floor for the interactive parts only.
//
// Deliberately NOT carried here: throughput and connection counters. Only the
// app may call Activity.update, never the tunnel extension where those numbers
// live (Apple DevForums 735382), so any counter we put here would freeze the
// moment the app is suspended and then lie. Session time is the exception — it
// is rendered from `connectedSince` with Text(timerInterval:), which the system
// ticks on its own without a single update() call.

import Foundation
import ActivityKit

/// Mirrors the subset of NEVPNStatus the user actually cares about. A closed
/// enum rather than the raw status so the widget can't be handed a state it has
/// no rendering for, and a String raw value so the payload stays readable.
enum VPNActivityStatus: String, Codable, Hashable {
    case connecting
    case connected
    case disconnecting
    case disconnected
}

@available(iOS 16.1, *)
struct VPNActivityAttributes: ActivityAttributes {
    /// The mutable part. Keep it small: ActivityKit caps a ContentState at
    /// roughly 4 KB, and every field here is a field someone has to keep true.
    struct ContentState: Codable, Hashable {
        var status: VPNActivityStatus
        /// Name of the active server (ServerStore.activeServer.serverName).
        var serverName: String
        /// When the tunnel reached .connected, or nil when it isn't up. The
        /// view renders a live timer from this, so the clock keeps running even
        /// while the app is suspended and cannot update anything.
        var connectedSince: Date?
    }

    /// When the activity itself was started. Informational — the session clock
    /// uses `connectedSince` so a reconnect inside one activity restarts it.
    var startedAt: Date
}
