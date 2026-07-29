// LiveActivityIntents.swift
//
// The buttons on the Live Activity (GitHub issue #64, stage 2). Compiled into
// BOTH the app and the widget extension, like VPNActivityAttributes.swift.
//
// Why the router indirection: a LiveActivityIntent's perform() runs in the APP
// process, but the intent TYPE must also exist in the WIDGET process for
// Button(intent:) to reference it — so this file has to COMPILE in the widget,
// where TunnelManager and ServerStore are unavailable (they would drag in
// NetworkExtension and the Go xcframework). perform() therefore only forwards an
// enum to a handler the app installs at launch; in the widget the handler is nil
// and perform() never runs there anyway.
//
// Everything here is iOS 17+: Live Activities themselves are 16.1/16.2, but
// Button and Toggle *inside* one arrived in 17. The widget's floor stays 16.2 and
// the views fall back to a read-only layout below 17.

import Foundation
import AppIntents

enum LiveActivityAction {
    case disconnect
    case enterPicker
    case exitPicker
    case nextPage
    case selectServer(id: String)
}

/// App-installed sink for Live Activity button taps. See the file header.
@MainActor
final class LiveActivityActionRouter {
    static let shared = LiveActivityActionRouter()
    var handler: ((LiveActivityAction) async -> Void)?
    private init() {}

    func handle(_ action: LiveActivityAction) async {
        await handler?(action)
    }
}

/// Stop the tunnel.
///
/// NOT a Toggle, deliberately. The activity only exists while the tunnel is up,
/// so a switch's "off" position is unreachable — it would always render "on" and
/// then vanish rather than flip when tapped. A button says what the tap does.
/// Connecting from the Lock Screen is given up on purpose: iOS already offers it
/// in Settings › VPN without launching the app, and a card kept alive while
/// disconnected would still be removed at the system's activity-lifetime cap.
@available(iOS 17.0, *)
struct DisconnectIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "Disconnect"
    // A control surface, not an automation — keep it out of Shortcuts/Spotlight.
    static var isDiscoverable: Bool = false
    init() {}

    func perform() async throws -> some IntentResult {
        await LiveActivityActionRouter.shared.handle(.disconnect)
        return .result()
    }
}

@available(iOS 17.0, *)
struct EnterPickerIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "Choose a server"
    static var isDiscoverable: Bool = false
    init() {}
    func perform() async throws -> some IntentResult {
        await LiveActivityActionRouter.shared.handle(.enterPicker)
        return .result()
    }
}

@available(iOS 17.0, *)
struct ExitPickerIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "Cancel"
    static var isDiscoverable: Bool = false
    init() {}
    func perform() async throws -> some IntentResult {
        await LiveActivityActionRouter.shared.handle(.exitPicker)
        return .result()
    }
}

@available(iOS 17.0, *)
struct NextPageIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "More servers"
    static var isDiscoverable: Bool = false
    init() {}
    func perform() async throws -> some IntentResult {
        await LiveActivityActionRouter.shared.handle(.nextPage)
        return .result()
    }
}

@available(iOS 17.0, *)
struct SelectServerIntent: LiveActivityIntent {
    static var title: LocalizedStringResource = "Switch to server"
    static var isDiscoverable: Bool = false

    @Parameter(title: "Server ID")
    var serverId: String

    init() {}
    init(serverId: String) { self.serverId = serverId }

    func perform() async throws -> some IntentResult {
        await LiveActivityActionRouter.shared.handle(.selectServer(id: serverId))
        return .result()
    }
}
