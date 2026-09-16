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

    /// The generation whose stop the USER asked for — `disconnect()` records it
    /// before `stopVPNTunnel()`. A stop asked for during the start still
    /// completes that start with an error: iOS is owed a completion and has no
    /// "cancelled" outcome, so the provider names the stop (domain
    /// "VKTurnProxy", code 3) and iOS records it as the last disconnect error —
    /// the fetch then read the user's own Disconnect back as "The tunnel
    /// stopped: The tunnel was stopped while it was starting." (Sep 14 §116,
    /// the user's screenshot on 2026-09-16). Keyed on the generation like
    /// everything else here, so a Disconnect tapped in one cycle cannot caption
    /// a death in the next.
    private(set) var userStopGeneration: Int?

    /// True once this generation's session reported `.connected`: a stop after
    /// that is an ordinary stop, whoever asked for it. Reset whenever the
    /// generation advances.
    private(set) var connectedThisGeneration = false

    init() {}

    /// Call from `disconnect()`, BEFORE the stop is issued: the user's intent.
    mutating func stopRequestedByUser() {
        userStopGeneration = generation
    }

    /// The user's own Disconnect of a session that never connected — known
    /// from the app's own record alone, no stop reason needed. iOS may record
    /// NO error for it: when the stop's completion beats the start's, the stop
    /// is filed as a clean user stop and `fetchLastDisconnectError` answers nil
    /// (the phone, 2026-09-16 19:26 — status 2 at the tap, nothing fetched,
    /// nothing shown; on build 385 the same tap had shown the start's error
    /// because the completions landed the other way round). So the fetch's
    /// nil answer, and a build without the fetch, consult this instead.
    func userCancelledTheStart(_ generationOfDeath: Int) -> Bool {
        userStopGeneration == generationOfDeath && !connectedThisGeneration
    }

    /// The provider's stop-during-start outcome as it crosses the process
    /// boundary (PacketTunnelProvider.stoppedDuringStartError); the domain and
    /// code are pinned on both sides by swiftcheck.
    static let stoppedDuringStartDomain = "VKTurnProxy"
    static let stoppedDuringStartCode = 3

    static func isStoppedDuringStart(_ error: Error) -> Bool {
        let ns = error as NSError
        return ns.domain == stoppedDuringStartDomain && ns.code == stoppedDuringStartCode
    }

    /// What the main screen says instead of a stop reason when the user
    /// cancelled the start themselves — a notice, not an error.
    static let cancelledByUserText = "Connection cancelled by the user"

    /// Whether a stop reason fetched under `fetchedUnder` is the user's own
    /// Disconnect during the start: BOTH the intent (recorded for this
    /// generation) AND the outcome (the provider's stop-during-start error).
    /// The same error without the intent is iOS stopping a start on its own (a
    /// reason=1 it fires for a network change under includeAllNetworks) and
    /// keeps the honest text; any other error after a Disconnect — the cookie
    /// watchdog's, csqtt's — is the extension's own reason and is shown as
    /// such.
    func wasCancelledByUser(_ stop: Error, fetchedUnder: Int) -> Bool {
        userStopGeneration == fetchedUnder && Self.isStoppedDuringStart(stop)
    }

    /// Call when a new attempt BEGINS — the user's intent, not the system's status.
    ///
    /// 🚨 `observe` can only advance the generation when iOS reports
    /// `.connecting`, and that is far too late. Pre-bootstrap — captcha, creds,
    /// the VK API — runs for seconds or minutes inside `connect()` before
    /// `startVPNTunnel()` moves the status at all. Throughout that window a fetch
    /// left over from the PREVIOUS death still matched the generation and still
    /// found the message slot empty, because `connect()` had just cleared it —
    /// so it published a stale death reason on top of a connect in progress.
    ///
    /// ⚖️ It deliberately does not touch `sawLiveSession`: an attempt that dies
    /// in pre-bootstrap never produces a status transition at all, and marking a
    /// session live here would make the next `.invalid` from an ordinary
    /// `saveToPreferences()` look like a death.
    mutating func attemptBegan() {
        generation += 1
        connectedThisGeneration = false
    }

    /// Feed every status observation. Returns the generation to fetch the stop
    /// reason under, or nil when this transition is not a session death.
    mutating func observe(_ status: NEVPNStatus) -> Int? {
        switch status {
        case .connecting, .connected, .reasserting:
            if !sawLiveSession {
                // A new session is starting: anything still in flight from the
                // previous one is now answering a question nobody is asking.
                generation += 1
                connectedThisGeneration = false
            }
            sawLiveSession = true
            if status == .connected {
                connectedThisGeneration = true
            }
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
    /// 🚨 THE SLOT MUST BE EMPTY, not merely unchanged. The first version compared
    /// the message as it stood when the fetch was ISSUED against the message now —
    /// which is only a defence if the more specific writer publishes DURING the
    /// fetch. In production it publishes BEFORE: the VKAuth branch runs
    /// synchronously in the same status handler, so the snapshot captured VKAuth's
    /// own message as the baseline, the two compared equal, and the guard cheerfully
    /// permitted the overwrite it existed to prevent. Moving the call after that
    /// branch did not help — it is what made the snapshot pick the message up.
    ///
    /// 🎯 The disconnect reason is a FALLBACK, so the honest test is "is anything
    /// else already saying something about this cycle?", and that is a test on the
    /// slot NOW. `messageAtFetch` was a test of my belief about the ordering rather
    /// than of the ordering, and it is gone.
    ///
    /// ⚖️ `.connected` clears the slot, and so does `connect()`, so a cycle that
    /// reaches the tunnel starts empty and a genuine death does get reported.
    func mayPublish(fetchedUnder: Int, messageNow: String?) -> Bool {
        fetchedUnder == generation && messageNow == nil
    }
}
