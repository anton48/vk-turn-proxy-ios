// RoutingShortcuts.swift
//
// DIRECT mode in the Shortcuts app (GitHub issue #78), so "when app X opens,
// route around the VPN" can be an automation instead of two taps in Settings.

import Foundation
import AppIntents

/// 🚨 An `AppIntent`, NOT the `SetDirectIntent` that the Live Activity uses.
/// That one is a `LiveActivityIntent` whose `perform()` only forwards to a
/// handler the app installs at launch — from an automation, which can fire while
/// the app is not running, that forwarding is a silent no-op. This one reaches
/// `TunnelManager` directly, so there is no half of a hookup to be missing.
@available(iOS 16.0, *)
struct SetDirectRoutingIntent: AppIntent {
    static var title: LocalizedStringResource = "Set VPN Bypass"
    static var description = IntentDescription("Routes traffic around the tunnel, or puts it back through it. Requires a running connection; this does not connect or disconnect.")
    /// Automations fire while the user is opening something else; do not yank
    /// them into this app to do it.
    static var openAppWhenRun: Bool = false

    /// 🚨 EXPLICIT, because the default is `.alwaysAllowed` — which Apple defines
    /// as running even on a LOCKED device. This intent turns the VPN's protection
    /// off; that is not something a locked phone should do for whoever is holding
    /// it. The automations this exists for fire when an app is opened, which the
    /// device has to be unlocked for anyway. *(User-caught: it was the default,
    /// i.e. a security decision nobody made.)*
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    @Parameter(title: "Bypass VPN")
    var direct: Bool

    init() {}
    init(direct: Bool) { self.direct = direct }

    static var parameterSummary: some ParameterSummary {
        Summary("Set VPN bypass to \(\.$direct)")
    }

    func perform() async throws -> some IntentResult {
        let outcome = await Self.apply(direct)
        // 🚨 AWAITED, for the same reason the Live Activity's button awaits it:
        // the process is suspended the moment perform() returns, so a card
        // update left in flight may never happen — and the card would go on
        // describing routing that has changed. `refreshDirectMode` inside
        // `setDirectMode` only calls the unawaited `refreshNow()`.
        // *(User-caught.)*
        // 🚨 GATED: on `.noManager` the tunnel's state is unknown and `status` is
        // still its initial `.disconnected`, which the controller answers by
        // ENDING the card — irreversibly from the background.
        if outcome.tunnelStateIsKnown, #available(iOS 16.2, *) {
            await LiveActivityController.shared.refreshNowAndWait()
        }
        if let failure = outcome.automationFailure {
            throw RoutingIntentError.message(failure)
        }
        return .result()
    }

    /// 🚨 NOT time-boxed, and the earlier version that was had it backwards.
    ///
    /// The process is alive exactly while `perform()` has not returned — with
    /// `openAppWhenRun` false there is no scene to keep it up — so returning
    /// early is what abandons the work. And the work that must not be abandoned
    /// is the dangerous one: an unconfirmed switch BACK to the tunnel may be a
    /// leak, and its repair is a full reconnect (awaitTerminal up to 15 s, a
    /// cred probe, awaitConnected up to 12 s) started inside `setDirectMode`,
    /// well past any box worth putting on a Shortcut.
    ///
    /// ⚖️ `setDirectMode` already bounds the part that should be bounded: a 5 s
    /// confirmation round trip plus a 2 s re-ask. The confirmed path measures
    /// about 400 ms on device, so Shortcuts waits a moment normally, and in the
    /// rare bad case it may time out on its own while the repair finishes.
    @MainActor
    private static func apply(_ direct: Bool) async -> DirectOutcome {
        // `init` only kicks off an unawaited load, and a background-launched
        // intent asks before it lands.
        await TunnelManager.shared.ensureManagerLoaded()
        return await TunnelManager.shared.setDirectMode(direct, from: .shortcut)
    }
}

@available(iOS 16.0, *)
enum RoutingIntentError: Swift.Error, CustomLocalizedStringResourceConvertible {
    case message(String)

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .message(let m): return "\(m)"
        }
    }
}

/// Report whether traffic is going through the tunnel right now, so a shortcut
/// can branch on it.
@available(iOS 16.0, *)
struct GetConnectionStatusIntent: AppIntent {
    static var title: LocalizedStringResource = "Get Connection Status"
    static var description = IntentDescription("Returns Connected or Disconnected.")
    static var openAppWhenRun: Bool = false

    /// ⚖️ STATED, not inherited. Unlike the bypass action this only READS, and
    /// whether a VPN is up is not worth locking behind an unlock prompt — an
    /// automation that checks the tunnel before doing something else would then
    /// fail on a locked phone for no benefit.
    static var authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed

    init() {}

    func perform() async throws -> some IntentResult & ReturnsValue<String> {
        // 🚨 The same race the bypass action lost: `init` only starts an
        // unawaited load, and a background-launched intent asks first — which
        // would report a live tunnel as Disconnected.
        await TunnelManager.shared.ensureManagerLoaded()
        // 🚨 `liveStatus`, not the published mirror: that one is fed by
        // notifications a suspended process never received, so a warm launch can
        // answer with a status from hours ago. nil means the profile could not be
        // read, and answering "Disconnected" there would be a guess dressed as a
        // fact.
        guard let status = await TunnelManager.shared.liveStatus else {
            throw RoutingIntentError.message("VK Turn Proxy could not read its VPN configuration.")
        }
        return .result(value: ConnectionReport.text(for: status))
    }
}

/// Two phrases for one intent, which is what "two buttons" means here.
@available(iOS 16.0, *)
struct RoutingAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: SetDirectRoutingIntent(direct: true),
            phrases: ["Bypass the VPN in \(.applicationName)"],
            shortTitle: "Bypass VPN",
            systemImageName: "arrow.uturn.forward"
        )
        AppShortcut(
            intent: SetDirectRoutingIntent(direct: false),
            phrases: ["Route through the VPN in \(.applicationName)"],
            shortTitle: "Use VPN",
            systemImageName: "lock.shield"
        )
    }
}
