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
import UIKit

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

    /// Picker state lives HERE, not in the tunnel: it is UI state owned by the
    /// activity, so every sync() has to MERGE it back in rather than rebuild
    /// ContentState from tunnel state alone. Without that, the 2s stats poll
    /// would close the menu under the user's finger — verified on the prototype,
    /// where tunnel-driven updates during a reconnect kept arriving with
    /// mode=picking exactly as intended.
    private struct Picker {
        var page: Int
        var busyServerId: String?
    }
    private var picker: Picker?

    /// When the in-flight server switch stops excusing terminal states.
    ///
    /// A boolean cleared "when the switch call returns" is NOT enough, and the
    /// device proved it (29.07 vpn.8): `switchAndReconnect` ends at
    /// `startVPNTunnel()`, which returns immediately, while the status changes it
    /// caused are still queued — LiveActivityBridge hops each one through a
    /// Task. They then drained AFTER the flag was cleared, the first `.invalid`
    /// ended the activity, and the re-`request` died on "Target is not
    /// foreground". So the excuse has to last until the tunnel actually SETTLES,
    /// which is a deadline, not a call boundary. Cleared early the moment
    /// `.connected` arrives.
    private var switchDeadline: Date?
    private var isSwitching: Bool {
        guard let d = switchDeadline else { return false }
        if Date() >= d { switchDeadline = nil; return false }
        return true
    }
    /// Generous on purpose: a cold reconnect can spend up to the extension's
    /// 120s bootstrap before the first conn is up. Overshooting only means the
    /// card says "Connecting" a while longer; undershooting loses the card.
    private static let switchWindow: TimeInterval = 150

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

    /// Master switch, Settings › Advanced. Read from UserDefaults rather than
    /// declared as @AppStorage anywhere near ContentView — see AdvancedView's
    /// header for why that distinction matters in this app.
    private var featureEnabled: Bool {
        UserDefaults.standard.bool(forKey: "liveActivityEnabled")
    }

    /// Session clock in the COLLAPSED island, Settings › Advanced, default off.
    /// Read here and carried in ContentState because the widget process cannot
    /// see these defaults — see VPNActivityAttributes.compactClock.
    private var compactClockEnabled: Bool {
        UserDefaults.standard.bool(forKey: "liveActivityCompactClock")
    }

    func sync(status: NEVPNStatus, connectedAt: Date?, serverName: String, force: Bool = false) {
        // Turned off: make sure nothing of ours is left on the Lock Screen. This
        // runs before every other branch, so flipping the switch while connected
        // takes the card down on the next sync (≤2s, the stats poll) and the
        // explicit refresh from AdvancedView makes it immediate.
        guard featureEnabled else {
            if activity != nil { end() }
            return
        }
        // ── Mid-switch, NOTHING may end the activity. ────────────────────
        //
        // Not a nicety: ending it forces a re-`request`, and iOS REFUSES to
        // start a Live Activity while the app is in the background —
        // "Activity.request failed: Target is not foreground" (device log
        // 29.07, 14:42:26). The card then vanishes for good, because every
        // button that could bring it back lives on the card. `update` from the
        // background is allowed; `request` is not. So the only safe move is to
        // keep the same activity alive across the whole switch.
        //
        // Both terminal-looking states occur during a normal switch:
        //   .disconnected — the stop we asked for;
        //   .invalid      — saveToPreferences() invalidating the session while
        //                   we rewrite the profile. This one was missed first
        //                   time round and cost exactly the failure above.
        // A settled tunnel ends the switch window early — from here the normal
        // rules apply again.
        if isSwitching {
            if Self.map(status) == .connected {
                switchDeadline = nil
            } else {
                let waypoint = pickerApplied(.connecting, connectedAt: nil, serverName: serverName)
                // Same anti-chatter rule as the normal path: the 2s stats poll
                // calls in here too, and re-pushing an identical state would
                // burn ActivityKit updates for nothing.
                if lastPushed?.state != waypoint { update(waypoint) }
                return
            }
        }
        guard let mapped = Self.map(status) else {
            // .invalid and anything Apple adds later: treat as "no session".
            end()
            return
        }
        if mapped == .disconnected {
            end()
            return
        }
        var state = VPNActivityAttributes.ContentState(
            status: mapped,
            serverName: serverName,
            // Only a real .connected has a session clock; while connecting the
            // view shows a dash rather than a timer counting from nothing.
            connectedSince: mapped == .connected ? connectedAt : nil
        )
        state.compactClock = compactClockEnabled
        // Read here, not in the widget: the widget is a separate process and
        // shares no App Group with the app. Same reasoning as compactClock.
        state.direct = TunnelManager.shared.directMode
        applyPicker(to: &state)
        if activity == nil {
            start(state)
            return
        }
        // Re-publishing an identical state is only worth doing to push the
        // staleDate out; do it well before that date so the island never
        // flickers into "last known" while the app is watching.
        if !force, let last = lastPushed, last.state == state,
           Date().timeIntervalSince(last.at) < Self.refreshInterval {
            return
        }
        update(state)
    }

    /// Merge the open picker into a freshly-built state.
    private func applyPicker(to state: inout VPNActivityAttributes.ContentState) {
        guard let p = picker else { return }
        let all = ServerStore.shared.servers
        let pages = max(1, Int(ceil(Double(all.count) / Double(serversPerPage))))
        let page = min(p.page, pages - 1)
        let start = page * serversPerPage
        state.mode = .picking
        state.choices = all[start..<min(start + serversPerPage, all.count)]
            .map { ServerChoice(id: $0.id.uuidString, name: $0.serverName) }
        state.page = page
        state.pageCount = pages
        state.busyServerId = p.busyServerId
    }

    /// Publish immediately — no throttle, no "unchanged" check. A button tap has
    /// to land now; `sync` is for the tunnel's own chatter.
    /// Re-publish the card because something it SHOWS changed, without the
    /// tunnel's status having moved. Public because routing is the one such
    /// thing: TunnelManager.refreshDirectMode calls it.
    func refreshNow() { pushNow() }

    private func pushNow() {
        let tunnel = TunnelManager.shared
        sync(status: tunnel.status,
             connectedAt: tunnel.live.connectedAt,
             serverName: ServerStore.shared.activeServer.serverName,
             force: true)
    }

    /// Build a state with the picker merged in — used where sync()'s normal
    /// mapping doesn't apply (the mid-switch waypoint above).
    private func pickerApplied(_ status: VPNActivityStatus,
                               connectedAt: Date?,
                               serverName: String) -> VPNActivityAttributes.ContentState {
        var state = VPNActivityAttributes.ContentState(status: status,
                                                       serverName: serverName,
                                                       connectedSince: connectedAt)
        state.compactClock = compactClockEnabled
        // Read here, not in the widget: the widget is a separate process and
        // shares no App Group with the app. Same reasoning as compactClock.
        state.direct = TunnelManager.shared.directMode
        applyPicker(to: &state)
        return state
    }

    // MARK: - Button taps

    func handle(_ action: LiveActivityAction) async {
        let tunnel = TunnelManager.shared
        switch action {
        case .disconnect:
            picker = nil
            tunnel.disconnect()
            // AWAITED: after perform() returns the app is suspended and would
            // never see .disconnected, leaving the card stuck on "Disconnecting"
            // instead of disappearing. The end() happens in the sync that the
            // terminal status triggers, so it must land before we return.
            await tunnel.awaitTerminal()

        case .enterPicker:
            picker = Picker(page: 0, busyServerId: nil)
            pushNow()

        case .exitPicker:
            picker = nil
            pushNow()

        case .nextPage:
            guard var p = picker else { return }
            let pages = max(1, Int(ceil(Double(ServerStore.shared.servers.count) / Double(serversPerPage))))
            p.page = (p.page + 1) % pages
            picker = p
            pushNow()

        case .setDirect(let direct):
            // 🚨 AWAITED, like .disconnect and for the same reason: after
            // perform() returns the app is suspended, and this change is not
            // instant — a profile save, then a round-trip to the extension for
            // the confirmation. Returning early would leave the card showing the
            // old routing until something else happened to push a state.
            //
            // ⚠️ WHAT CANNOT BE AWAITED TO COMPLETION is the repair an
            // UNCONFIRMED change triggers: an unconfirmed OFF rebuilds the
            // tunnel, which takes about a hundred seconds, and perform() does
            // not live that long. It starts here and continues only if the app
            // happens to stay alive. So the card must not imply routing is
            // settled — refreshDirectMode(), which every one of those paths
            // calls, pushes the state that is actually true.
            await TunnelManager.shared.setDirectMode(direct, from: .liveActivity)
            pushNow()

        case .selectServer(let idString):
            guard let id = UUID(uuidString: idString) else { return }
            picker?.busyServerId = idString
            pushNow()
            switchDeadline = Date().addingTimeInterval(Self.switchWindow)
            await tunnel.switchAndReconnect(to: id)
            // switchDeadline is deliberately NOT cleared here — see its doc.
            picker = nil
            pushNow()
        }
    }

    // MARK: - Lifecycle

    private func start(_ state: VPNActivityAttributes.ContentState) {
        // Fails silently otherwise — the user can switch Live Activities off
        // per app in Settings, and we spent enough of this project chasing
        // features that quietly did nothing.
        // iOS refuses Activity.request outside the foreground, and a failed
        // request is unrecoverable here: every control that could bring the card
        // back lives ON the card. Say so plainly instead of logging an opaque
        // "Target is not foreground".
        guard UIApplication.shared.applicationState != .background else {
            note("cannot start a Live Activity from the background — iOS only allows request() in the foreground")
            return
        }
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            note("Live Activities are disabled for this app in Settings — no island")
            return
        }
        do {
            activity = try Activity.request(
                attributes: VPNActivityAttributes(startedAt: Date()),
                content: ActivityContent(state: state, staleDate: staleDate(for: state.status)),
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
            await activity.update(ActivityContent(state: state, staleDate: staleDate(for: state.status)))
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

    /// An open picker must not stay open forever — the user taps "switch", gets
    /// distracted, and the island sits on a menu instead of reporting the tunnel.
    ///
    /// ⚠️ This CANNOT be a timer in the app. Measured on the prototype: once the
    /// app is backgrounded its Timers stop, so any app-side deadline never fires
    /// — precisely in the case that needs it. The expiry is therefore handed to
    /// the SYSTEM as the activity's staleDate, and the views render an expired
    /// picker as the normal layout.
    private static let pickerTimeout: TimeInterval = 45

    /// A `.connecting` we cannot confirm must not stand as long as a confirmed
    /// `.connected`. Only the app may refresh the card and it is suspended right
    /// after the switch, so an unconfirmed "Connecting…" would otherwise sit
    /// there for the full 15 minutes looking authoritative.
    ///
    /// Seen on device 29.07 (vpn.10): a fifth rapid switch found every cred slot
    /// in its VK per-relay cooldown (1m45s-9m57s), so the extension's credpool
    /// parked rather than over-fetch and bootstrap kept retrying. The tunnel was
    /// genuinely coming up — just far slower than the intent can wait. Three
    /// minutes is long enough for an ordinary connect and short enough that a
    /// stuck one visibly becomes "last known" instead of a confident claim.
    private static let connectingStaleAfter: TimeInterval = 3 * 60

    private func staleDate(for status: VPNActivityStatus) -> Date {
        if picker != nil { return Date().addingTimeInterval(Self.pickerTimeout) }
        let window = (status == .connected) ? Self.staleAfter : Self.connectingStaleAfter
        return Date().addingTimeInterval(window)
    }

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
