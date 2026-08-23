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

    @Parameter(title: "Bypass VPN")
    var direct: Bool

    init() {}
    init(direct: Bool) { self.direct = direct }

    static var parameterSummary: some ParameterSummary {
        Summary("Set VPN bypass to \(\.$direct)")
    }

    func perform() async throws -> some IntentResult {
        if let failure = await Self.apply(direct).automationFailure {
            throw RoutingIntentError.message(failure)
        }
        return .result()
    }

    /// Time-boxed, because one path inside `setDirectMode` is not: an
    /// unconfirmed switch BACK to the tunnel may be a leak, and its repair is a
    /// full reconnect of about 107 seconds. Shortcuts will not wait that long.
    ///
    /// 🚨 The work is deliberately NOT cancelled when the box expires — that
    /// repair has to finish. What expires is only our willingness to report on
    /// it, and the honest report then is that it was not confirmed.
    @MainActor
    private static func apply(_ direct: Bool) async -> DirectOutcome {
        let work = Task { await TunnelManager.shared.setDirectMode(direct, from: .shortcut) }
        let settled: DirectOutcome? = await withTaskGroup(
            of: DirectOutcome?.self
        ) { group in
            group.addTask { await work.value }
            group.addTask {
                try? await Task.sleep(nanoseconds: 12 * NSEC_PER_SEC)
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        return settled ?? .unconfirmed("The tunnel did not answer in time. Check the app.")
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
