// VPNActivityAttributes.swift
//
// The Live Activity contract, compiled into BOTH the app and the widget
// extension (see the widget target's `sources:` list in project.yml, same
// pattern as SharedLogger.swift). The app produces these values; the widget
// only renders them.
//
// Scope note (GitHub issue #64, stage 1): this stage is DISPLAY ONLY —
// connection state + active server name. No buttons, so its floor is iOS 16.2
// (ActivityContent, and with it staleDate, arrived in 16.2 — 16.1 only has the
// deprecated contentState API) rather than the 17.0 that interactive Live
// Activities require; stage 2 adds
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

/// Which of the two presentations the activity is currently showing.
enum ActivityMode: String, Codable, Hashable {
    case normal, picking
}

/// One selectable server. Deliberately tiny — id + name is all the picker needs.
struct ServerChoice: Codable, Hashable, Identifiable {
    var id: String      // ServerProfile.id.uuidString
    var name: String
}

/// Server buttons per page. The Dynamic Island's expanded region is the tighter
/// of the two surfaces and fits three; a fourth is silently clipped, which is
/// how the cancel/paging row disappeared during prototyping.
let serversPerPage = 3

@available(iOS 16.2, *)
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

        // ── stage 2 (GitHub #64): the two-mode server picker ──────────────
        // A Live Activity has no Menu, Picker, List, scrolling or gestures —
        // Button and Toggle are the entire palette. "Choose one of N servers"
        // is therefore done by re-rendering the SAME activity as a page of
        // buttons and back again.
        var mode: ActivityMode = .normal
        /// Populated ONLY while `mode == .picking`, so the normal-mode payload
        /// stays exactly as small as it was in stage 1 (ContentState is capped
        /// around 4 KB, and this is the only part that grows with the config).
        var choices: [ServerChoice] = []
        var page: Int = 0
        var pageCount: Int = 1
        /// The row whose switch is in flight, so a tap visibly does something
        /// during the seconds before the status catches up.
        var busyServerId: String?

        // ── build 208: the compact island's clock is opt-in ────────────────
        /// Show the session clock in the COLLAPSED Dynamic Island (Settings ›
        /// Advanced). It has to travel here rather than be read by the widget
        /// itself: the widget is a separate process and, by design, shares no
        /// App Group with the app (that is what keeps the Live Activity working
        /// on third-party re-signed builds), so `UserDefaults.standard` in the
        /// widget is NOT the app's.
        ///
        /// **Optional on purpose.** An activity started by build ≤207 was
        /// encoded without this key, and after an app update the NEW widget
        /// decodes that OLD payload; a non-Optional `Bool` would throw
        /// `.keyNotFound` there and break a card nobody can refresh until the
        /// app next runs. `nil` therefore means "published before the setting
        /// existed" and reads as off — same reasoning as the Optional fields in
        /// AppSettings, and the same trap that once wiped ServerProfile.
        var compactClock: Bool?
    }

    /// When the activity itself was started. Informational — the session clock
    /// uses `connectedSince` so a reconnect inside one activity restarts it.
    var startedAt: Date
}
