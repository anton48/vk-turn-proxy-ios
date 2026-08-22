// SessionServer.swift
//
// Which server the app may CLAIM is running — a different question from which
// server is selected, and the two were being answered with one value.
//
// 🚨 WHY THIS EXISTS
// ------------------
// `ServerStore.activeServer` is the server the NEXT connect will use. The
// running session carries the configuration it was STARTED with, and nothing
// re-reads the store until a reconnect. So the moment the active server can
// change while a tunnel is up — a tapped connection link does exactly that,
// with no reconnect anywhere — "Connected to <active server>" becomes a claim
// about a session that is not running that server at all.
//
// The repo already knew this in ONE place: `switchAndReconnect` stops the tunnel
// BEFORE activating the new profile, with the reason written out — *"activating
// the profile first would make syncLiveActivity publish the NEW name while the
// OLD tunnel still carries traffic — the card would assert something untrue."*
// That guard protects the reconnect path only. The main screen and the card
// derived the name from the store directly, so the import path walked past it.
//
// ⚖️ Build 350 made this VISIBLE rather than introducing it: the name used to be
// a `@State` snapshot that happened to lag, so the false claim arrived a moment
// later instead of at once. Reading the store live is right; reading the store
// for a question the store cannot answer is not.
//
// 🎯 The rule is a pure function so the harness can drive it. The state that
// makes it interesting — a LIVE tunnel whose session server differs from the
// selected one — cannot be reached in the simulator at all (no VPN there), and
// on a device each case costs a reconnect cycle.

import Foundation
import NetworkExtension

/// A server profile reduced to what a caption needs: an identity that survives a
/// rename, and a name to print.
struct NamedServer: Equatable {
    let id: UUID
    let name: String

    init(id: UUID, name: String) {
        self.id = id
        self.name = name
    }
}

/// What the main screen and the Live Activity are allowed to say.
struct ServerCaption: Equatable {
    /// The line under the status text.
    let subtitle: String
    /// Shown when the SELECTED server is not the one running, so the user is not
    /// left wondering why the screen still names the old one. nil when the two
    /// agree, or when there is no live session to disagree with.
    let pendingSelection: String?
    /// What the Live Activity card may name. EMPTY means *name nothing* — the
    /// card must not fall back to the selected server, which is the defect.
    let cardName: String
}

enum SessionServerLabel {
    /// - Parameters:
    ///   - session: the server the RUNNING session was started with; nil when
    ///     there is no session, or when there is one this app did not start and
    ///     whose profile carries no identity (a tunnel left running by a build
    ///     older than this one).
    ///   - selected: `ServerStore.activeServer`, i.e. the next connect's server.
    static func caption(status: NEVPNStatus,
                        session: NamedServer?,
                        selected: NamedServer) -> ServerCaption {
        // `.disconnecting` counts as not-live on purpose: the session is going
        // away, and naming it as connected outlives the truth by a second.
        let live = status == .connected || status == .connecting || status == .reasserting
        guard live else {
            return ServerCaption(subtitle: "Server: \(selected.name)",
                                 pendingSelection: nil,
                                 cardName: selected.name)
        }
        let verb = status == .connected ? "Connected to" : "Connecting to"
        guard let session else {
            // 🚨 The honest answer, and deliberately NOT the selected server:
            // this is the one case where a session is known to be up and its
            // server is not known. Naming the selection here would be exactly
            // the claim this type exists to prevent.
            return ServerCaption(subtitle: status == .connected
                                    ? "Connected — server unknown"
                                    : "Connecting — server unknown",
                                 pendingSelection: nil,
                                 cardName: "")
        }
        // ⚖️ Compared by ID, not by name. `ServerStore.update` does not
        // uniquify, so two profiles CAN carry the same name after a rename and
        // a name comparison would then call two different servers equal.
        let pending = session.id == selected.id
            ? nil
            : "\(selected.name) is selected and will be used on the next connect."
        return ServerCaption(subtitle: "\(verb) \(session.name)",
                             pendingSelection: pending,
                             cardName: session.name)
    }
}
