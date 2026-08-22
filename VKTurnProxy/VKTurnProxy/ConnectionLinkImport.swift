import SwiftUI

/// The root-level consumer for `vkturnproxy://` / `wdtt://` / `freeturn://`
/// links, and the one place the confirmation text is built.
///
/// WHY THIS EXISTS
/// ---------------
/// `.onOpenURL` at the `WindowGroup` fires reliably and parks the URL in
/// `ConnectionLinkInbox`. Until build 350 the ONLY consumer was `SettingsView`,
/// through its `.onAppear` / `.onChange` — so a link tapped while the app was on
/// the main screen sat in the inbox and **nothing happened until the user
/// navigated to Settings**, at which point the prompt finally appeared. That was
/// the reported behaviour, and the code described it as intended: *"acted on
/// whether SettingsView was already mounted … or only mounted later when the
/// user navigates to it"*. Reproduced in the simulator before this was written.
///
/// 🚨 WHY IT IS A SEPARATE VIEW AND NOT AN OBSERVER ON `ContentView`
/// The obvious fix — let `ContentView` watch the inbox — re-arms the trap this
/// project has been bitten by twice (build 177, GitHub #65): `ContentView` hosts
/// the `NavigationView`, so anything that re-renders its body tears down
/// whatever is pushed. A link arriving while the user was inside Settings or
/// ServerEditView would have thrown them out of it. That is also why
/// `ContentView` keeps the active server name as a `@State` snapshot rather than
/// observing `ServerStore`.
///
/// Owning the `@StateObject` HERE means the inbox's publish re-renders only this
/// view. `ContentView`'s body does not read the inbox and therefore does not
/// re-run — the push survives. Same move as `MainNavigationLinks`, which was
/// lifted out of the churning root for the same reason.
/// → reference_swiftui_pop_navigationview_host_rerender
///
/// ⚖️ `SettingsView` keeps its own copy of the confirm alert, because it also
/// serves the PASTE path ("Import from Connection Link…"), which never touches
/// the inbox. Both call `ConnectionLinkPrompt` so the wording and the apply step
/// exist once — two copies of a rule is how two copies drift apart.
struct ConnectionLinkImporter: View {
    @StateObject private var inbox = ConnectionLinkInbox.shared

    @State private var pending: ConnectionLink?
    @State private var showConfirm = false
    @State private var resultTitle = ""
    @State private var resultMessage: String?
    @State private var showResult = false

    var body: some View {
        // An empty, zero-footprint view: it exists to host the alerts and to be
        // the thing that re-renders when a URL arrives.
        Color.clear
            .frame(width: 0, height: 0)
            .alert("Import Connection Link?", isPresented: $showConfirm, presenting: pending) { link in
                Button("Import", role: .destructive) {
                    let msg = ConnectionLinkPrompt.apply(link)
                    pending = nil
                    resultTitle = "Connection Link Imported"
                    resultMessage = msg
                    showResult = true
                }
                Button("Cancel", role: .cancel) { pending = nil }
            } message: { link in
                Text(ConnectionLinkPrompt.message(for: link))
            }
            .alert(resultTitle, isPresented: $showResult) {
                Button("OK", role: .cancel) {}
            } message: {
                if let m = resultMessage { Text(m) }
            }
            .onAppear { consume() }
            .onChange(of: inbox.pendingURL) { _ in consume() }
    }

    /// Take the URL out of the inbox and act on it.
    ///
    /// Consuming (setting `pendingURL = nil`) is what stops the link being
    /// replayed the next time this view appears.
    private func consume() {
        guard let url = inbox.pendingURL else { return }
        inbox.pendingURL = nil
        do {
            pending = try BackupManager.parseConnectionLink(from: url)
            showConfirm = true
        } catch {
            pending = nil
            resultTitle = "Connection Link Invalid"
            resultMessage = error.localizedDescription
            showResult = true
        }
    }
}

/// The confirmation wording and the apply step, in one place so the two
/// presenters — this importer (tapped links) and SettingsView (pasted links) —
/// cannot drift apart.
enum ConnectionLinkPrompt {
    /// What the user is about to get. Names what will be CREATED rather than
    /// what gets overwritten: since build 179 a link ADDS a named server and
    /// makes it active instead of replacing the current configuration.
    static func message(for link: ConnectionLink) -> String {
        let s = link.settings
        let created = ServerProfile(link: s)
        let name = created.serverName.isEmpty ? "a new server" : "\"\(created.serverName)\""
        let extras = [
            s.numConnections.map { "\($0) conns" },
            s.dnsServers.map { "DNS \($0)" }
        ].compactMap { $0 }.joined(separator: ", ")
        let extrasText = extras.isEmpty ? "" : " (\(extras))"
        // A freeturn:// link (SRTP-WRAP-S) carries neither WG keys nor a VK call
        // link, so the new server starts without them — say so, or the user will
        // expect the import to have filled them in. A quick_link.py WRAP-S link
        // DOES include WG keys (privateKey non-nil).
        if s.useWrapS == true, s.privateKey == nil {
            let prof = s.obfProfile ?? "rtpopus"
            return "Add \(name) as SRTP-WRAP-S for \(s.peerAddress)\(extrasText)? "
                 + "Sets the server, WRAP key, obf profile (\(prof)) and Client-ID, and makes it "
                 + "active. WireGuard keys and the VK call link are NOT included — enter them manually."
        }
        return "Add \(name) [\(created.modeLabel)] for \(s.peerAddress)\(extrasText) and make it "
             + "active? Your existing servers are kept; the VK call link is global and will be updated."
    }

    /// Applies the link and returns the message to show afterwards.
    static func apply(_ link: ConnectionLink) -> String {
        BackupManager.applyConnectionLink(link)
        return "Settings applied. Reconnect to use them."
    }
}
