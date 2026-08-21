// DisconnectReason.swift
//
// Decides WHEN to ask iOS why the tunnel stopped, and whether the answer may
// still be published when it arrives.
//
// Why this is a value type in its own file
// ----------------------------------------
// `fetchLastDisconnectError(completionHandler:)` is an ASYNC fetch, so every
// interesting question about it is about ordering, and ordering is exactly what
// a source scan over `TunnelManager` cannot check. Three defects in the sibling
// classifier shipped behind green greps for that reason. Here the rule is a
// value the harness drives with fixtures.
//
// The three things that went wrong in the first version, all found in review:
//
// 1. 🚨 THE ANSWER LANDED AFTER THE BRANCH IT WAS MEANT TO YIELD TO. The fetch
//    was issued before the VKAuth check "so the more specific message wins" —
//    but being FIRST in source order means arriving LAST in time, so it
//    overwrote precisely the message it was written to defer to. Source order
//    is not precedence once a callback is involved.
//
// 2. 🚨 A STATUS CHECK CANNOT SEPARATE ONE DOWN-CYCLE FROM THE NEXT. Guarding
//    the completion on "are we still disconnected" looks like a staleness test
//    and is not: cycle N's answer and cycle N+1's both see `.disconnected`, so
//    a reason from a previous stop could be published against the current one.
//    That needs a generation counter, which is what `generation` is.
//
// 3. 🚨 `.invalid` IS NOT TUNNEL DEATH. `saveToPreferences()` routinely
//    invalidates the session while rewriting the profile — this repo already
//    documents that in LiveActivityController — so fetching on every observation
//    of `.invalid` asks for a reason during an ordinary reconnect. A reason is
//    only meaningful when something that WAS live or starting has gone terminal.

import Foundation
import NetworkExtension

struct DisconnectReasonGate {
    /// True once a session has been seen running or trying to run, cleared when
    /// it goes terminal. This is what makes `.invalid` during a profile save a
    /// non-event rather than a death.
    private(set) var sawLiveSession = false

    /// Bumped when a NEW session starts. A fetch captures the value current when
    /// it was issued; if a reconnect has begun by the time the answer lands, the
    /// two disagree and the answer belongs to a cycle nobody is looking at.
    private(set) var generation = 0

    init() {}

    /// Feed every status observation. Returns the generation to fetch the stop
    /// reason under, or nil when this transition is not a session death.
    mutating func observe(_ status: NEVPNStatus) -> Int? {
        switch status {
        case .connecting, .connected, .reasserting:
            if !sawLiveSession {
                // A new session is starting: anything still in flight from the
                // previous one is now answering a question nobody is asking.
                generation += 1
            }
            sawLiveSession = true
            return nil
        case .disconnected, .invalid:
            // 🚨 Only a session that was actually live or starting can have died.
            // Without this, every `saveToPreferences()` would ask why the tunnel
            // stopped and get the reason for something the user already forgot.
            guard sawLiveSession else { return nil }
            sawLiveSession = false
            return generation
        default:
            // .disconnecting — not terminal yet.
            return nil
        }
    }

    /// Whether an answer fetched under `fetchedUnder` may still be shown.
    ///
    /// `messageAtFetch` / `messageNow` are the error message as it stood when the
    /// fetch was issued and as it stands now: if anything else has published in
    /// between it is both newer and more specific, and this must not clobber it.
    /// That is defect (1) above, and no ordering of the CALL can fix it — only
    /// comparing the slot can.
    func mayPublish(fetchedUnder: Int, messageAtFetch: String?, messageNow: String?) -> Bool {
        fetchedUnder == generation && messageAtFetch == messageNow
    }
}
