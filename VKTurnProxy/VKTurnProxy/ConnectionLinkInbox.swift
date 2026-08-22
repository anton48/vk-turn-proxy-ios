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
    /// With a bare `inFlight` flag the two survivors disagreed and both answers
    /// were wrong:
    ///   • the flag was cleared ONLY from `.onChange(of:)` on the alert flags,
    ///     and a freshly built view produces no such transition — so the URL
    ///     stayed in flight for ever and that link became UN-IMPORTABLE for the
    ///     rest of the session;
    ///   • and "just hand it out again on the next `take()`" is UNSAFE, because
    ///     the flag cannot say whether the user had already tapped Import. If
    ///     the view vanished while the RESULT alert was up, the link is already
    ///     applied, and re-offering it imports the same deployment twice.
    /// *(User-caught, and the previous round's comment claiming this was
    /// "guarded" was wrong: nothing called `finish()` on that path.)*
    ///
    /// So the phase records whether anything has HAPPENED to the device yet,
    /// which is the only thing that decides how an abandoned transaction ends.
    enum Phase: Equatable {
        case idle
        /// Handed to a view and being confirmed. Nothing has been applied, so if
        /// that view goes away this URL may safely be offered again.
        case offering(URL)
        /// Acted on — applied, or rejected as unreadable. Offering it again
        /// would import the same deployment twice, or re-ask about a link the
        /// user has already been told is invalid.
        case acted(URL)
    }

    private(set) var phase: Phase = .idle

    /// The URL of the open transaction, in either phase. A repeat tap of it is
    /// the same intent whether it is being confirmed or being reported on, so
    /// the dedupe window is *queued OR open*, never just *queued*.
    var openURL: URL? {
        switch phase {
        case .idle: return nil
        case .offering(let u), .acted(let u): return u
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
    /// a transaction it knows nothing about — the other way this used to lose a
    /// link. Reconciling an abandoned one is `recoverIfAbandoned()`'s job, and
    /// it is deliberately a separate decision.
    func take() -> URL? {
        guard case .idle = phase, !queued.isEmpty else { return nil }
        let url = queued.removeFirst()
        phase = .offering(url)
        return url
    }

    /// Something irreversible has happened to this link: it was applied, or it
    /// was rejected as unreadable and the user told so. From here it must never
    /// be offered again.
    func markActed() {
        if case .offering(let u) = phase { phase = .acted(u) }
    }

    /// The transaction is over — the last alert about it has been dismissed.
    ///
    /// ⚖️ It must be called, and it must NOT be skipped as "tidier": leaving a
    /// transaction open for ever would make that exact link un-importable for
    /// the rest of the session, which is the same defect pointing the other way.
    /// Re-tapping the same link later is a legitimate new intent.
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
    ///   • `.offering` — nothing was applied, so the link goes back to the FRONT
    ///     of the queue and is offered again, keeping its place ahead of
    ///     anything that arrived behind it;
    ///   • `.acted` — the device already changed, so it is DROPPED. What is lost
    ///     is the confirmation alert, which is cosmetic; the new server is in
    ///     Settings and the main screen already names it.
    func recoverIfAbandoned() {
        switch phase {
        case .idle:
            return
        case .offering(let u):
            phase = .idle
            queued.insert(u, at: 0)
            SharedLogger.shared.log("[AppDebug] connection link was left unconfirmed — offering it again")
        case .acted(let u):
            phase = .idle
            SharedLogger.shared.log("[AppDebug] connection link \(u.scheme ?? "?") was already applied before the "
                + "prompt went away — not offering it again")
        }
    }
}
