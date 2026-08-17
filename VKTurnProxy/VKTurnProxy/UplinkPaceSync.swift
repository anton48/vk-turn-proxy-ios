// UplinkPaceSync.swift
//
// The bookkeeping behind "the tunnel is running the pace the settings say it is".
// It is a plain value type with no NetworkExtension in sight, DELIBERATELY: the
// delivery path needs a live `NETunnelProviderSession` and cannot be tested at
// all, so everything that can be decided without one is decided here, where the
// harness compiles it. What is left in TunnelManager is a thin shim — send, and
// report the outcome back into this type.
//
// 🚨 WHY A REVISION AND NOT A BOOL. The first version tracked one `pending` flag
// and cleared it on any `ok`. Two ways that loses a change, both user-caught:
//
//   1. **The flag was set only on FAILURE.** If the completion never arrived at
//      all — the extension wedged, the IPC dropped it — nothing was ever marked
//      outstanding, so no retry could fire. Intent must be recorded BEFORE the
//      send, not after it fails.
//   2. **A late acknowledgement clears a newer intent.** Send revision 1, it is
//      slow; the user flips again, revision 2 is sent and FAILS; revision 1's
//      `ok` then arrives and clears the flag. The extension is on the old value,
//      the switch shows the new one, and nothing will ever reconcile them.
//
// ⇒ Every intent gets a monotonically increasing revision, and only an explicit
// `ok` for a revision NEWER than the last acknowledged one may advance the
// acknowledged mark. Pending is then not a flag anyone sets — it is the fact
// that `acked < desired`, which a stale reply cannot fake.
//
// 🚨 AND SILENCE IS NOT SUCCESS. A completion that never comes leaves the two
// marks apart, so `isPending` stays true and the caller's timer retries. That is
// the whole reason the state is a comparison rather than an event.

import Foundation

struct UplinkPaceSync {
    /// How many attempts a single intent gets before the caller gives up and
    /// says so in the log. Bounded because the retry runs on a timer while the
    /// tunnel is up: an unbounded one would spin for the life of the session
    /// against an extension that is never going to answer.
    static let maxAttempts = 5

    private(set) var desiredRevision = 0
    private(set) var acknowledgedRevision = 0
    private(set) var attempts = 0

    /// True whenever the extension has not confirmed the newest intent. Nothing
    /// sets this; it is derived, which is what makes a stale reply harmless.
    var isPending: Bool { acknowledgedRevision < desiredRevision }

    /// Records a NEW intent — the user changed the setting, or the app is
    /// re-asserting it after attaching to a tunnel it did not start. Returns the
    /// revision now outstanding.
    ///
    /// 🚨 This marks the intent pending immediately. The send has not happened
    /// yet and may never happen; that is exactly the state being recorded.
    @discardableResult
    mutating func intend() -> Int {
        desiredRevision += 1
        attempts = 0
        return desiredRevision
    }

    /// Called immediately before a delivery attempt. Returns the revision being
    /// sent, which the completion handler must quote back.
    @discardableResult
    mutating func willSend() -> Int {
        attempts += 1
        return desiredRevision
    }

    /// Whether another delivery attempt is allowed for the outstanding intent.
    var canRetry: Bool { isPending && attempts < Self.maxAttempts }

    /// The extension answered. Only an explicit `ok` counts, and only for a
    /// revision newer than the last one acknowledged — a reply for revision 1
    /// arriving after revision 2 went out must leave revision 2 outstanding.
    mutating func acknowledge(revision: Int, ok: Bool) {
        guard ok, revision > acknowledgedRevision else { return }
        acknowledgedRevision = revision
    }
}
