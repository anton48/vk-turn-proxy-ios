// LiveActivityController.swift
//
// Owns the VPN Live Activity from the MAIN APP — the only process allowed to
// call Activity.request/update/end. The tunnel extension cannot (Apple
// DevForums 735382), which is why nothing here is shared with PacketTunnel and
// why the activity carries no counters: see VPNActivityAttributes.swift.
//
// Everything ActivityKit is gated at iOS 16.2 (ActivityContent/staleDate landed
// there; 16.1 only has the deprecated contentState calls); the app floor is 15.0. Call
// sites use `LiveActivityBridge`, which compiles on 15.0 and does nothing
// there, so TunnelManager stays free of availability noise.

import Foundation
import NetworkExtension
import ActivityKit

/// Availability shim. TunnelManager talks to this; it forwards to the real
/// controller only where ActivityKit exists.
enum LiveActivityBridge {
    /// Reflect the current tunnel state in the Live Activity. Idempotent and
    /// cheap: safe to call on every status transition.
    static func sync(status: NEVPNStatus, connectedAt: Date?, serverName: String) {
        guard #available(iOS 16.2, *) else { return }
        // Hop to the main actor rather than demanding callers already be on it:
        // TunnelManager is not uniformly MainActor-isolated, and this is called
        // from both a @MainActor task and plain setup code.
        Task { @MainActor in
            LiveActivityController.shared.sync(status: status,
                                               connectedAt: connectedAt,
                                               serverName: serverName)
        }
    }
}

@available(iOS 16.2, *)
@MainActor
final class LiveActivityController {
    static let shared = LiveActivityController()

    private var activity: Activity<VPNActivityAttributes>?
    /// Logged once per reason so a permanently-disabled setting can't spam the
    /// log on every status change.
    private var loggedFailure: String?
    /// Last content we published, and when. Lets `sync` be called from the 2s
    /// stats poll without hammering ActivityKit: an unchanged state is only
    /// re-pushed when its staleDate is approaching.
    private var lastPushed: (state: VPNActivityAttributes.ContentState, at: Date)?

    private init() {
        // Adopt an activity that outlived the app (relaunch while the tunnel
        // stayed up). Without this we would orphan the old one and request a
        // second, and the user would see two.
        activity = Activity<VPNActivityAttributes>.activities.first
        if activity != nil {
            SharedLogger.shared.log("[AppDebug] live-activity: adopted an existing activity after relaunch")
        }
    }

    // MARK: - Entry point

    func sync(status: NEVPNStatus, connectedAt: Date?, serverName: String) {
        guard let mapped = Self.map(status) else {
            // .invalid and anything Apple adds later: treat as "no session".
            end()
            return
        }
        if mapped == .disconnected {
            end()
            return
        }
        let state = VPNActivityAttributes.ContentState(
            status: mapped,
            serverName: serverName,
            // Only a real .connected has a session clock; while connecting the
            // view shows a dash rather than a timer counting from nothing.
            connectedSince: mapped == .connected ? connectedAt : nil
        )
        if activity == nil {
            start(state)
            return
        }
        // Re-publishing an identical state is only worth doing to push the
        // staleDate out; do it well before that date so the island never
        // flickers into "last known" while the app is watching.
        if let last = lastPushed, last.state == state,
           Date().timeIntervalSince(last.at) < Self.refreshInterval {
            return
        }
        update(state)
    }

    // MARK: - Lifecycle

    private func start(_ state: VPNActivityAttributes.ContentState) {
        // Fails silently otherwise — the user can switch Live Activities off
        // per app in Settings, and we spent enough of this project chasing
        // features that quietly did nothing.
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            note("Live Activities are disabled for this app in Settings — no island")
            return
        }
        do {
            activity = try Activity.request(
                attributes: VPNActivityAttributes(startedAt: Date()),
                content: ActivityContent(state: state, staleDate: Self.staleDate()),
                pushType: nil   // no push: see the note on push updates below
            )
            loggedFailure = nil
            lastPushed = (state, Date())
            SharedLogger.shared.log("[AppDebug] live-activity: started (\(state.status.rawValue), server=\"\(state.serverName)\")")
        } catch {
            note("Activity.request failed: \(error.localizedDescription)")
        }
    }

    private func update(_ state: VPNActivityAttributes.ContentState) {
        guard let activity else { return }
        lastPushed = (state, Date())
        Task {
            await activity.update(ActivityContent(state: state, staleDate: Self.staleDate()))
        }
    }

    private func end() {
        guard let activity else { return }
        self.activity = nil
        lastPushed = nil
        SharedLogger.shared.log("[AppDebug] live-activity: ended")
        Task {
            await activity.end(nil, dismissalPolicy: .immediate)
        }
    }

    // MARK: - Details

    /// How long the content may be trusted before the system marks it stale.
    ///
    /// This is the honest half of a trade we cannot escape: only the app can
    /// refresh the activity, and the app is suspended for most of a tunnel's
    /// life, so a state we published an hour ago may no longer be true. Too
    /// short and the island is permanently hedged; too long and it can assert
    /// "Connected" over a tunnel that dropped. 15 minutes keeps it accurate for
    /// the common case while bounding how long a wrong state can stand.
    /// `context.isStale` is what the view should render differently (M2).
    private static let staleAfter: TimeInterval = 15 * 60
    private static func staleDate() -> Date { Date().addingTimeInterval(staleAfter) }

    /// How often an UNCHANGED state is re-published while the app is running.
    /// Comfortably inside `staleAfter`, so a foreground session never shows
    /// "last known" — that wording is reserved for when we genuinely are not
    /// watching. Also the reason `sync` is cheap enough for the 2s stats poll.
    private static let refreshInterval: TimeInterval = 5 * 60

    private static func map(_ s: NEVPNStatus) -> VPNActivityStatus? {
        switch s {
        case .connected: return .connected
        // .reasserting is a live tunnel re-establishing itself — from the
        // user's side that reads as "connecting", not as a new session.
        case .connecting, .reasserting: return .connecting
        case .disconnecting: return .disconnecting
        case .disconnected: return .disconnected
        case .invalid: return nil
        @unknown default: return nil
        }
    }

    /// Report a reason the island isn't showing. Uses the diagnostic channel so
    /// it survives an unusable App Group, and fires once per distinct reason.
    private func note(_ reason: String) {
        guard loggedFailure != reason else { return }
        loggedFailure = reason
        SharedLogger.logDiagnostic("live-activity: \(reason)", category: "LiveActivity")
    }
}
