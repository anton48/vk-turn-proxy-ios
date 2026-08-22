// ConnectionLinkInbox.swift
//
// Extracted from VKTurnProxyApp.swift so the harness can COMPILE it and drive
// the queue with fixtures. Its behaviour — ordering, deduplication, the bound —
// is exactly the kind that a source scan can only assert the shape of.

import Foundation
import Combine

/// Tiny inbox that parks incoming `vkturnproxy://import?data=…` URLs from the
/// App's `.onOpenURL` (which fires reliably on cold and warm launches at the
/// WindowGroup level) until a view consumes them.
///
/// 🚨 THE SOLE CONSUMER IS `ConnectionLinkImporter`, mounted at the root — see
/// ConnectionLinkImport.swift. It used to be SettingsView, which meant a link
/// tapped while the app sat on the main screen did NOTHING until the user
/// happened to open Settings. Do not add a second consumer: two of them race
/// over one queue, so a prompt is swallowed or shown twice.
@MainActor
final class ConnectionLinkInbox: ObservableObject {
    static let shared = ConnectionLinkInbox()

    /// 🚨 A QUEUE, NOT A SLOT. Only one link can be confirmed at a time, so a
    /// URL arriving while an alert is up has to wait — and with a single slot
    /// each new arrival OVERWROTE the one waiting, so of several links tapped
    /// in a row only the last survived, silently. Three taps are three intents.
    @Published private(set) var queued: [URL] = []

    /// WHERE the one open transaction has got to.
    ///
    /// 🚨 IT IS A PHASE, NOT A FLAG, AND THE INBOX OWNS IT — because the inbox
    /// OUTLIVES THE VIEW. `ConnectionLinkImporter` is a SwiftUI view whose
    /// `@State` (the pending link, both alert flags) dies when its identity is
    /// lost, and in THIS app that is a live possibility: re-rendering the view
    /// that hosts the `NavigationView` tears its subtree down, which is the
    /// build-177 / #65 trap the importer itself was split out to survive.
    ///
    /// 🎯 AND THE LINE IS *HAS THE USER SEEN THE OUTCOME*, NOT *IS IT
    /// IRREVERSIBLE*. The first cut of this phase used the second question and
    /// got two cases wrong in opposite directions: an UNREADABLE link was
    /// marked done the moment the error was composed, so a view torn down
    /// before the alert was read dropped it and the user was never told; and
    /// CANCEL was left recoverable until a dismissal hook that a dying view
    /// never runs, so a link the user had just declined came back as a fresh
    /// prompt. *(Both user-caught.)*
    enum Phase: Equatable {
        case idle
        /// The user has not been given the outcome yet — an unanswered prompt,
        /// or an error they have not acknowledged. If the view goes away,
        /// showing this again is the CORRECT repair.
        case recoverable(URL)
        /// Over: applied, declined, or the complaint was read. Showing it again
        /// would import twice, re-ask something already answered, or repeat a
        /// complaint the user has already dismissed.
        case terminal(URL, EndReason)
    }

    /// Why a transaction ended. It exists for the LOG and it is REQUIRED, so a
    /// new ending cannot inherit somebody else's reason — the same shape as
    /// `TunnelManager.ReconnectReason`, which is there because a log naming the
    /// wrong cause sends the next reader to the wrong feature. The first cut
    /// logged *"was already applied"* for a link that had merely been found
    /// unreadable. *(User-caught.)*
    enum EndReason: String, Equatable {
        case applied = "applied"
        case declined = "declined by the user"
        case reported = "reported as unreadable"
    }

    private(set) var phase: Phase = .idle

    /// The URL of the open transaction, in either phase. A repeat tap of it is
    /// the same intent whether it is being confirmed or being reported on, so
    /// the dedupe window is *queued OR open*, never just *queued*.
    var openURL: URL? {
        switch phase {
        case .idle: return nil
        case .recoverable(let u): return u
        case .terminal(let u, _): return u
        }
    }

    /// Bounded, so a pathological producer cannot grow it without limit. Far
    /// past any real sequence of taps; beyond it the NEWEST is refused, because
    /// the ones already queued were asked for first.
    static let capacity = 16

    private init() {}

    func deliver(_ url: URL) {
        // A double-tap on one link is ONE intent; two different links are two.
        guard url != openURL, !queued.contains(url) else {
            SharedLogger.shared.log("[AppDebug] connection link already queued or open — ignoring the repeat")
            return
        }
        guard queued.count < Self.capacity else {
            SharedLogger.shared.log("[AppDebug] 🚨 connection-link queue full (\(Self.capacity)) — dropping the newest")
            return
        }
        queued.append(url)
    }

    /// Removes and returns the oldest queued URL and OPENS a transaction on it.
    ///
    /// ⚖️ Refuses while one is already open, so a second caller cannot overwrite
    /// a transaction it knows nothing about — one of the two ways this used to
    /// lose a link. Reconciling an abandoned one is `recoverIfAbandoned()`'s
    /// job, and it is deliberately a separate decision.
    func take() -> URL? {
        guard case .idle = phase, !queued.isEmpty else { return nil }
        let url = queued.removeFirst()
        phase = .recoverable(url)
        return url
    }

    /// The user has now been given the outcome: they imported it, they declined
    /// it, or they dismissed the complaint about it.
    ///
    /// 🚨 CALL THIS FROM THE BUTTON'S OWN HANDLER, never from a dismissal hook.
    /// A hook runs on a view that survives to see the flag change, and the whole
    /// point here is the view that does not.
    ///
    /// ⚖️ The FIRST reason wins: after an import the result alert's OK is a
    /// no-op, so the phase keeps `applied` rather than being relabelled by the
    /// button that merely closed the receipt.
    func markTerminal(_ reason: EndReason) {
        if case .recoverable(let u) = phase { phase = .terminal(u, reason) }
    }

    /// The transaction is over AND its last alert is gone — release the dedupe
    /// window so the same link may be tapped afresh later.
    ///
    /// ⚖️ It must be called, and it must NOT be skipped as "tidier": leaving a
    /// transaction open for ever would make that exact link un-importable for
    /// the rest of the session, which is the same defect pointing the other way.
    func finish() {
        phase = .idle
    }

    /// Reconcile a transaction whose view went away without finishing it.
    ///
    /// 🚨 CALL THIS ONLY FROM A CONSUMER WITH NO ALERT ON SCREEN. A view that is
    /// still showing the link has not abandoned anything, and re-queuing under
    /// it would produce a second prompt for what is already up.
    ///
    /// The two phases end differently, and that difference is the whole point:
    ///   • `recoverable` — the user never saw the outcome, so the link goes back
    ///     to the FRONT of the queue, keeping its place ahead of anything that
    ///     arrived behind it;
    ///   • `terminal` — they did, so it is DROPPED. After an import what is lost
    ///     is the receipt alone; the new server is in Settings and the main
    ///     screen already names it.
    func recoverIfAbandoned() {
        switch phase {
        case .idle:
            return
        case .recoverable(let u):
            phase = .idle
            queued.insert(u, at: 0)
            SharedLogger.shared.log("[AppDebug] a connection link's prompt went away unanswered — offering it again")
        case .terminal(_, let reason):
            phase = .idle
            // ⚖️ The URL itself is NOT logged: a connection link's payload
            // carries WireGuard keys, and vpn.log is the file users send us.
            SharedLogger.shared.log("[AppDebug] a connection link was already \(reason.rawValue) "
                + "before its prompt went away — not offering it again")
        }
    }
}
