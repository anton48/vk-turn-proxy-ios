import SwiftUI

/// The root-level consumer for `vkturnproxy://` / `wdtt://` / `freeturn://`
/// links, and the one place the confirmation wording and the apply step live.
///
/// 🚨 IT IS A SEPARATE VIEW, NOT AN OBSERVER ON `ContentView`. `ContentView`
/// hosts the `NavigationView`, so anything that re-renders its body tears down
/// whatever is pushed (build 177, GitHub #65) — a link arriving while the user
/// was inside Settings or ServerEditView would have thrown them out of it.
/// Owning the `@StateObject` here means the inbox's publish re-renders only this
/// view. Same move as `MainNavigationLinks` and `ActiveServerControls`.
/// → reference_swiftui_pop_navigationview_host_rerender
///
/// ⚖️ `SettingsView` keeps its own copy of the confirm alert because it also
/// serves the PASTE path ("Import from Connection Link…"), which never touches
/// the inbox. Both go through `ConnectionLinkPrompt`, so the wording, the titles
/// and the apply step exist once — two copies of a rule is how two copies drift.
struct ConnectionLinkImporter: View {
    @StateObject private var inbox = ConnectionLinkInbox.shared

    @State private var pending: ConnectionLink?
    @State private var showConfirm = false
    @State private var resultTitle = ""
    @State private var resultMessage: String?
    @State private var showResult = false

    var body: some View {
        // An invisible, inert layer: it exists to host the alerts and to be the
        // thing that re-renders when a URL arrives.
        //
        // ⚖️ SIZED AND HIT-TEST-DISABLED, not 0×0. A `.background` takes its
        // parent's size and does not affect its layout, so this is invisible
        // either way — but a zero-bounds host is a documented way to lose an
        // alert presentation or an `.onAppear`, and there is no reason to stand
        // on that. `allowsHitTesting(false)` is what keeps a full-size clear
        // layer from swallowing taps on the scroll view's empty space.
        // *(Review-raised twice: 3d7b9953, 63f25071.)*
        //
        // 🚫 NOT moved to the `WindowGroup` beside `KeyboardDismisser`, which was
        // the other half of that suggestion: presenting over a PUSHED screen,
        // over a cold launch, and chained confirm → result are all measured
        // working from here (simulator, 2026-08-22), and moving verified
        // structure on a theory buys nothing. ⚠️ The residual is simulator vs
        // DEVICE, which neither placement addresses.
        Color.clear
            .allowsHitTesting(false)
            .alert("Import Connection Link?", isPresented: $showConfirm, presenting: pending) { link in
                Button("Import", role: .destructive) {
                    let msg = ConnectionLinkPrompt.apply(link)
                    pending = nil
                    resultTitle = ConnectionLinkPrompt.importedTitle
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
            .onChange(of: inbox.queued) { _ in consume() }
            // A URL that arrives while an alert is up stays PARKED; these two
            // fire when that alert goes away and pick it up then.
            .onChange(of: showConfirm) { _ in consume() }
            .onChange(of: showResult) { _ in consume() }
    }

    /// Take the oldest URL out of the inbox and act on it.
    ///
    /// Taking it is what stops the link being replayed the next time this view
    /// appears; anything still queued behind it is picked up when this alert is
    /// dismissed.
    private func consume() {
        // 🚨 ONE ALERT AT A TIME. This used to take the URL unconditionally and
        // overwrite `pending` UNDERNEATH a live confirmation, so a second link
        // arriving while the user read the first was the one Import applied —
        // a different configuration from the one on screen, silently. And
        // raising `showConfirm` while `showResult` is still true puts two
        // alerts on one view, which SwiftUI resolves by dropping one.
        //
        // Leaving it queued costs nothing: the queue is published and the
        // dismissal hooks above re-enter here, with `.onAppear` as the backstop
        // if a present is swallowed for arriving mid-dismissal. The importer is
        // always mounted now, so this is far easier to reach than when Settings
        // was the only consumer. *(Review-caught, 3d7b9953.)*
        //
        // ⚖️ And the inbox is a QUEUE rather than one slot, so several links
        // tapped in a row are all acted on in order instead of all but the last
        // being overwritten in silence. *(User-caught, 63f25071 follow-up.)*
        guard !showConfirm, !showResult else { return }
        guard let url = inbox.take() else { return }
        do {
            pending = try BackupManager.parseConnectionLink(from: url)
            showConfirm = true
        } catch {
            pending = nil
            resultTitle = ConnectionLinkPrompt.invalidTitle
            resultMessage = error.localizedDescription
            showResult = true
        }
    }
}

/// The confirmation wording, the alert titles and the apply step, in one place
/// so the two presenters — this importer (tapped links) and SettingsView (pasted
/// links) — cannot drift apart.
enum ConnectionLinkPrompt {
    static let importedTitle = "Connection Link Imported"
    static let invalidTitle = "Connection Link Invalid"

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
