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

    /// Bounded, so a pathological producer cannot grow it without limit. Far
    /// past any real sequence of taps; beyond it the NEWEST is refused, because
    /// the ones already queued were asked for first.
    static let capacity = 16

    private init() {}

    func deliver(_ url: URL) {
        // A double-tap on one link is ONE intent; two different links are two.
        guard !queued.contains(url) else {
            SharedLogger.shared.log("[AppDebug] connection link already queued — ignoring the repeat")
            return
        }
        guard queued.count < Self.capacity else {
            SharedLogger.shared.log("[AppDebug] 🚨 connection-link queue full (\(Self.capacity)) — dropping the newest")
            return
        }
        queued.append(url)
    }

    /// Removes and returns the oldest queued URL. Taking is what stops a link
    /// being replayed the next time the importer appears.
    func take() -> URL? {
        queued.isEmpty ? nil : queued.removeFirst()
    }
}
