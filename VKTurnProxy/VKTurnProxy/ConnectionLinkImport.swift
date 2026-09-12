import SwiftUI

/// The root-level consumer for `vkturnproxy://` / `wdtt://` / `freeturn://` /
/// `csqtt://` links, and the one place the confirmation wording and the apply
/// step live.
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
                    // 🚨 The device has changed AND the user has seen it happen.
                    // Terminal here, in the button's own handler: if this view is
                    // torn down before the receipt is dismissed, the inbox must
                    // not offer the link again — that imports it twice.
                    inbox.markTerminal(.applied)
                    pending = nil
                    resultTitle = ConnectionLinkPrompt.importedTitle
                    resultMessage = msg
                    showResult = true
                }
                Button("Cancel", role: .cancel) {
                    // 🚨 HERE, not in the dismissal hook. The hook runs on a view
                    // that survives to see `showConfirm` flip; a view destroyed
                    // in the same update never runs it, and the link would come
                    // back as a fresh prompt for something just declined.
                    // *(User-caught.)*
                    inbox.markTerminal(.declined)
                    pending = nil
                }
            } message: { link in
                Text(ConnectionLinkPrompt.message(for: link))
            }
            .alert(resultTitle, isPresented: $showResult) {
                Button("OK", role: .cancel) {
                    // What makes an INVALID link terminal: until the complaint is
                    // read, a torn-down view must show it again. ⚖️ After an
                    // import this is a no-op — `markTerminal` keeps the first
                    // reason, so the phase stays `applied` rather than being
                    // relabelled by the button that closed the receipt.
                    inbox.markTerminal(.reported)
                }
            } message: {
                if let m = resultMessage { Text(m) }
            }
            .onAppear { consume() }
            .onChange(of: inbox.queued) { _ in consume() }
            // A URL that arrives while an alert is up stays PARKED; these two
            // fire when that alert goes away and pick it up then.
            .onChange(of: showConfirm) { _ in settle() }
            .onChange(of: showResult) { _ in settle() }
    }

    /// An alert closed. Release whatever it was showing — so a later tap of the
    /// SAME link counts as a new intent again — and then take the next one.
    ///
    /// 🚨 The order matters and the guard is what makes it safe: `finish()` must
    /// not run while the other alert is still up (the Import button closes the
    /// confirm and opens the result in one step), or the link on screen would
    /// drop out of the dedupe window a step early — the very hole this closes.
    private func settle() {
        guard !showConfirm, !showResult else { return }
        inbox.finish()
        consume()
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
        // 🚨 THIS VIEW'S @State DOES NOT OUTLIVE ITS IDENTITY, AND THE INBOX
        // DOES. If a previous importer was torn down mid-transaction — the
        // NavigationView host re-rendering does exactly that — the inbox is
        // still holding it, and only the inbox knows whether the link had
        // already been applied. Reconciling it is safe HERE and nowhere else:
        // the guard above is what says this consumer has no alert of its own.
        // *(User-caught: the previous version could neither recover nor safely
        // re-offer, so the link was stuck for the session.)*
        inbox.recoverIfAbandoned()
        guard let url = inbox.take() else { return }
        do {
            pending = try BackupManager.parseConnectionLink(from: url)
            showConfirm = true
        } catch {
            // 🚫 DELIBERATELY NOT TERMINAL HERE. Composing the complaint is not
            // the user reading it: a view torn down between the two would drop
            // the link having told them nothing at all. It becomes terminal on
            // the OK button above. *(User-caught.)*
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
        // SRTP-WRAP-S: a freeturn:// link never carries a VK call link and
        // carries WireGuard keys only through its `wg` field (their commit
        // 9da2c8e; GitHub #86). Say what the new server starts WITH and WITHOUT
        // from the LINK itself — keys present or not, a call link present or
        // not — never from the mode: a vkturnproxy:// WRAP-S link is the same
        // mode with both, and applyConnectionLink writes a non-empty vkLink.
        if s.useWrapS == true {
            let prof = s.obfProfile ?? "rtpopus"
            let keys = s.privateKey != nil
            let vk = !s.vkLink.isEmpty
            var text = "Add \(name) as SRTP-WRAP-S for \(s.peerAddress)\(extrasText)? "
                     + "Sets the server, WRAP key, obf profile (\(prof)), Client-ID"
            if keys {
                // Only what the section actually carried: an IPv6-only or
                // absent Address leaves the profile's default in place.
                var from = ["the WireGuard keys"]
                if s.tunnelAddress != nil { from.append("tunnel address") }
                if s.dnsServers != nil { from.append("DNS") }
                text += " and " + listing(from) + " from the link, and makes it active."
                if !vk { text += " The VK call link is NOT included — enter it manually." }
                if s.tunnelAddress == nil {
                    text += " The link's WireGuard section has no IPv4 address — check the tunnel address in the server's settings."
                }
            } else if !vk {
                text += ", and makes it active. WireGuard keys and the VK call link are NOT included — enter them manually."
            } else {
                text += ", and makes it active. WireGuard keys are NOT included — enter them manually."
            }
            if vk { text += " The VK call link is global and will be updated." }
            if s.wgConfUnreadable == true {
                text += " The link's WireGuard section could not be read (no usable key pair) — enter the keys manually."
            }
            // The link's WireGuard section may be an AmneziaWG conf (free-turn's
            // default backend): the keys are the same protocol, the obfuscation
            // parameters are not ours — name them before the first failed
            // connect rather than after it. The names come through a
            // letters-and-digits filter: the field is Codable, a crafted
            // vkturnproxy:// payload could put anything in it.
            let awgNames = (s.awgWireParametersIgnored ?? []).prefix(16)
                .map { String($0.filter { $0.isLetter || $0.isNumber }.prefix(24)) }.filter { !$0.isEmpty }
            let awg = awgNames.isEmpty ? "" :
                " Note: the WireGuard section is an AmneziaWG config (\(awgNames.joined(separator: ", "))); "
                + "this app speaks plain WireGuard and cannot use those settings — the tunnel will not connect "
                + "to a server that enforces them. Use these keys with an AmneziaWG client, or ask the server's "
                + "admin for a plain-WireGuard peer."
            text += awg
            return text
        }
        // csqtt: say what the user is signing up for — the password is the
        // tunnel's only key, so there is no forward secrecy on this transport.
        if created.useCsqtt {
            let dev = (s.csqttDeviceID ?? "").isEmpty
                ? "A Device ID will be generated; if the server already binds this password to a device, "
                  + "enter that Device ID in the server's settings. "
                : "Device ID \(s.csqttDeviceID ?? "") from the link. "
            return "Add \(name) as csqtt for \(s.peerAddress)\(extrasText) and make it active? "
                 + "The server assigns the tunnel address and DNS. \(dev)Note: csqtt has no key exchange — "
                 + "the password is the tunnel's only key, so recorded traffic can be decrypted by "
                 + "anyone who learns it later (no forward secrecy)."
        }
        return "Add \(name) [\(created.modeLabel)] for \(s.peerAddress)\(extrasText) and make it "
             + "active? Your existing servers are kept; the VK call link is global and will be updated."
    }

    /// Applies the link and returns the message to show afterwards — with the
    /// name the server actually got (a collision with an existing name adds
    /// " 2", which the confirmation could not know).
    static func apply(_ link: ConnectionLink) -> String {
        let created = BackupManager.applyConnectionLink(link)
        return "Added \"\(created.serverName)\" [\(created.modeLabel)] and made it active. Reconnect to use it."
    }

    /// "a", "a and b", "a, b and c".
    private static func listing(_ items: [String]) -> String {
        switch items.count {
        case 0: return ""
        case 1: return items[0]
        default: return items.dropLast().joined(separator: ", ") + " and " + items[items.count - 1]
        }
    }
}
