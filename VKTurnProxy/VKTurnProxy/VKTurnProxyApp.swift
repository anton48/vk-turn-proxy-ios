import SwiftUI

/// Tiny inbox that parks an incoming `vkturnproxy://import?data=…` URL from the
/// App's `.onOpenURL` (which fires reliably on cold and warm launches at the
/// WindowGroup level) until a view consumes it.
///
/// 🚨 THE SOLE CONSUMER IS `ConnectionLinkImporter`, mounted at the root — see
/// ConnectionLinkImport.swift. It used to be SettingsView, which meant a link
/// tapped while the app sat on the main screen did NOTHING until the user
/// happened to open Settings. Do not add a second consumer: two of them race
/// for one `pendingURL`, so one prompt is swallowed or shown twice.
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
        //   - the pacer: builds 296-298 wrote the Bool `uplinkPaceOn` and 299-302
        //     wrote RATES into `uplinkPaceKiB` itself, both ON for measurement.
        //     BOTH are zeroed, behind a marker no diagnostic build ever set —
        //     reusing one would skip exactly the device that ran the sweep.
        //   - the synthetic load generator: no UI at all.
        //
        // Both run once, shout when they fire, and leave the documented backup
        // field as the deliberate way back in. Removing a UI does not remove the
        // state it wrote.
        UplinkPace.resetToProductionDefaultOnce { SharedLogger.shared.log("[App] \($0)") }
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
