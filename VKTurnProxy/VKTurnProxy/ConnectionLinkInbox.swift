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

    /// The URL the importer is currently PROMPTING for. It has left `queued` —
    /// `take()` handed it over — but a repeat of it is still the same intent, so
    /// the window deduplication covers has to include it.
    ///
    /// 🚨 WITHOUT THIS THE DEDUPE WINDOW ENDED AT `take()`: the link on screen
    /// was no longer "already queued", so tapping it again while its own confirm
    /// alert was up re-enqueued it, and answering Import produced a SECOND
    /// prompt for the link just imported — and importing both adds the same
    /// deployment twice ("Alpha" and "Alpha 2"). *(User-caught.)*
    private(set) var inFlight: URL?

    /// Bounded, so a pathological producer cannot grow it without limit. Far
    /// past any real sequence of taps; beyond it the NEWEST is refused, because
    /// the ones already queued were asked for first.
    static let capacity = 16

    private init() {}

    func deliver(_ url: URL) {
        // A double-tap on one link is ONE intent; two different links are two.
        // The window is *queued OR on screen*, not *queued* — see `inFlight`.
        guard url != inFlight, !queued.contains(url) else {
            SharedLogger.shared.log("[AppDebug] connection link already queued or on screen — ignoring the repeat")
            return
        }
        guard queued.count < Self.capacity else {
            SharedLogger.shared.log("[AppDebug] 🚨 connection-link queue full (\(Self.capacity)) — dropping the newest")
            return
        }
        queued.append(url)
    }

    /// Removes and returns the oldest queued URL, and marks it IN FLIGHT until
    /// `finish()`. Taking is what stops a link being replayed the next time the
    /// importer appears.
    func take() -> URL? {
        guard !queued.isEmpty else { return nil }
        let url = queued.removeFirst()
        inFlight = url
        return url
    }

    /// The importer has finished with whatever `take()` handed it — the prompt
    /// was answered, cancelled, or the link was rejected as invalid.
    ///
    /// ⚖️ It must be called, and it must NOT be skipped as "tidier": leaving a
    /// URL in flight for ever would make that exact link un-importable for the
    /// rest of the session, which is the opposite failure and just as silent.
    /// Re-tapping the same link later is a legitimate new intent.
    func finish() {
        inFlight = nil
    }
}
