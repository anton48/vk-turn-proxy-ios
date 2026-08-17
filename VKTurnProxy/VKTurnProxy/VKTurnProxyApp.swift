import SwiftUI

/// Tiny inbox that forwards an incoming `vkturnproxy://import?data=…`
/// URL from the App's `.onOpenURL` (which fires reliably on cold and
/// warm launches at the WindowGroup level) into SettingsView, where
/// the parse + confirm + apply flow lives. SettingsView observes
/// `pendingURL` via @StateObject and consumes it on .onAppear AND
/// .onChange, so the URL is acted on whether SettingsView was already
/// mounted at the moment of delivery or only mounted later when the
/// user navigates to it.
@MainActor
final class ConnectionLinkInbox: ObservableObject {
    static let shared = ConnectionLinkInbox()
    @Published var pendingURL: URL?
    private init() {}
}

@main
struct VKTurnProxyApp: App {
    init() {
        // Version comes from Bundle's CFBundleVersion = $(CURRENT_PROJECT_VERSION)
        // (per project.yml info.properties). Both main app and PacketTunnel
        // extension log their own build number on startup so post-mortem log
        // analysis can immediately tell whether the running binary matches
        // the source git state — earlier confusion (2026-05-10) was caused
        // by an extension running stale Go code from a not-rebuilt xcframework
        // while the source had moved on.
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        SharedLogger.shared.log("[App] VKTurnProxy launched (build \(build))")

        // 🚨 RETIRE THE STATE THAT REMOVED UIs LEFT BEHIND, BEFORE ANYTHING READS
        // IT. Both of these ran on this device with no screen showing them:
        //
        //   - `uplinkChunkK` was written by an Advanced picker deleted on
        //     2026-08-12 when the chunking sweep closed. The VALUE stayed, and the
        //     tunnel ran K=64 for three days — invisible, because chunking is
        //     inert while the send queue is shallow and only wakes under real
        //     traffic, i.e. silent in the control runs and alive in the measured
        //     ones.
        //   - `uplinkPaceOn` was the pacer's test switch in builds 296-298, where
        //     it deliberately defaulted to ON. Production ships the pacer OFF, and
        //     a retired key that outvotes the shipped default is the same defect
        //     wearing the other hat.
        //
        // Both run once, shout when they fire, and leave the documented backup
        // field as the deliberate way back in. Removing a UI does not remove the
        // state it wrote.
        UplinkChunk.clearStaleValueOnce { SharedLogger.shared.log("[App] \($0)") }
        UplinkPace.clearRetiredTestKeyOnce { SharedLogger.shared.log("[App] \($0)") }
        UplinkSynth.clearStaleValueOnce { SharedLogger.shared.log("[App] \($0)") }

        // Instantiate the named-server store: first-launch migration captures the
        // user's existing single config as "Server1", and the store projects the
        // active server onto the flat @AppStorage keys that ContentView /
        // TunnelManager read.
        _ = ServerStore.shared

        // Live Activity buttons (issue #64 stage 2). The intents live in a file
        // compiled into the widget too, so they cannot reference TunnelManager
        // directly; the app installs the sink they forward to. Gated because
        // ActivityKit — and the controller — start at iOS 16.2.
        if #available(iOS 16.2, *) {
            Task { @MainActor in
                LiveActivityActionRouter.shared.handler = { action in
                    await LiveActivityController.shared.handle(action)
                }
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                // Capture vkturnproxy://, wdtt:// AND freeturn:// URLs at the
                // WindowGroup level so cold-launch via URL-tap works regardless
                // of which page SettingsView is currently on. wdtt:// is
                // amurcanov's proxy-turn-vk-android scheme (SRTP-WRAP-A interop);
                // freeturn:// is samosvalishe's free-turn-proxy scheme
                // (SRTP-WRAP-S interop). Neither of those apps registers its own
                // scheme, so we're the sole handler. Any other scheme is ignored.
                .onOpenURL { url in
                    let scheme = url.scheme?.lowercased()
                    if scheme == "vkturnproxy" || scheme == "wdtt" || scheme == "freeturn" {
                        ConnectionLinkInbox.shared.pendingURL = url
                    }
                }
                // Tap-anywhere-to-dismiss-keyboard, wired at the window level
                // (see KeyboardDismisser.swift) — a plain SwiftUI tap gesture
                // doesn't reach the empty space inside Form/List, so this is
                // attached once here for every screen instead.
                .background(KeyboardDismisser())
        }
    }
}
