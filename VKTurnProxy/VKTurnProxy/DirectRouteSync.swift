// DirectRouteSync.swift
//
// The bookkeeping behind "the tunnel's ROUTES are what the profile says they
// are". It is a plain value type with no NetworkExtension in sight, for the same
// reason [[UplinkPaceSync]] is: `setTunnelNetworkSettings` needs a live provider
// and cannot be tested at all, so everything decidable without one is decided
// here, where the harness compiles it. What is left in the provider is a shim —
// apply, and report the outcome back into this type.
//
// 🚨 WHY THIS EXISTS: A "CURRENT VALUE" FLAG CANNOT SERIALISE AN ASYNC APPLY.
// Build 308-309 tracked one `routesAreDirect` Bool, read at the top of the
// applier and written in its completion. Everything between those two points is
// a window in which the flag still says the OLD value, and DIRECT has *two*
// independent sources — KVO on `protocolConfiguration` and the `set_direct:`
// provider message — which normally deliver the SAME desired state by two paths.
// Two defects follow, both user-caught by reading:
//
//   1. **A change can be swallowed.** Routes are tunnelled; ON starts applying;
//      OFF arrives while it is in flight, compares `false != false`, decides it
//      is already there and returns; ON then completes and sets the flag to
//      DIRECT. The profile and the switch say OFF, the routes are DIRECT, and
//      nothing will ever reconcile them.
//   2. **One toggle can start TWO applies.** While the first is in flight the
//      flag is unchanged, so the second path's identical request passes the
//      guard too — two concurrent `setTunnelNetworkSettings` for one tap.
//
// ⇒ The state is not "what the routes are" but the TRIPLE (desired, applied,
// in-flight). A source may only ever move `desired`; only a completion may move
// `applied`; and at most one apply exists at a time. A request that arrives
// mid-flight is not dropped and not run — it is left in `desired`, and the
// completion picks it up. That is what makes the last writer win.
//
// 🎯 THE INVARIANT WORTH REMEMBERING: after every completion the machine either
// is settled (`desired == applied`) or has another apply running. There is no
// third state in which an unmet intent sits with nothing driving it.

import Foundation

struct DirectRouteSync {
    /// How many times a single unmet intent may be re-applied after a FAILING
    /// apply before the machine stops trying. Bounded because the retry is
    /// self-driving — a completion starting the next apply — so an unbounded one
    /// would spin against a provider that is never going to accept the settings.
    /// A fresh `intend` resets the count: the bound exists to stop an automatic
    /// loop, not to stop the user.
    static let maxAttempts = 3

    /// What the profile (or the app's message) last said it wants.
    private(set) var desired: Bool

    /// What a completed `setTunnelNetworkSettings` actually left in force. This
    /// is the only value that may be reported to the app as the truth.
    private(set) var applied: Bool

    /// The value currently being applied, or nil when nothing is running.
    /// Its presence — not a separate Bool — is what makes "one at a time" true.
    private(set) var inFlight: Bool?

    /// Consecutive apply attempts for the current unmet intent.
    private(set) var attempts = 0

    /// The machine has nothing left to do and the routes match the intent.
    var isSettled: Bool { inFlight == nil && desired == applied }

    /// An intent that cannot be pursued any further: nothing is running, the
    /// routes still disagree with the profile, and the attempt budget is spent.
    /// The caller must SAY so — this is the state that used to be silent.
    var isStuck: Bool { inFlight == nil && desired != applied && attempts >= Self.maxAttempts }

    init(applied: Bool) {
        self.desired = applied
        self.applied = applied
        self.inFlight = nil
    }

    /// A source — KVO on the profile, or a `set_direct:` message — reports the
    /// state it wants. Returns the value to start applying NOW, or nil when
    /// nothing should start: either the routes already match, or an apply is in
    /// flight and its completion will pick this up.
    ///
    /// 🚨 Returning nil is NOT "request dropped". The intent is recorded in
    /// `desired` either way; nil only means "do not call the applier yet".
    mutating func intend(_ value: Bool) -> Bool? {
        desired = value
        attempts = 0
        guard inFlight == nil else { return nil }
        return startIfNeeded()
    }

    /// An apply finished. `ok` is whether `setTunnelNetworkSettings` succeeded
    /// AND the TUN descriptor survived it — a moved fd is not a success, because
    /// wireguard-go is then holding a dead one.
    ///
    /// Returns the next value to apply, or nil when the machine has come to
    /// rest. A failure deliberately leaves `applied` alone: the routes are
    /// whatever they were, and the intent stays unmet so it will be retried.
    mutating func finish(ok: Bool) -> Bool? {
        guard let value = inFlight else { return nil }
        inFlight = nil
        if ok {
            applied = value
            attempts = 0
        }
        return startIfNeeded()
    }

    /// Reads `direct=<0|1>` out of the extension's reply, which may carry other
    /// fields (`get_direct` answers `direct=N want=N busy=N`).
    ///
    /// 🚨 STRICT ON PURPOSE: anything unreadable returns nil, and nil is NOT a
    /// confirmation. The handler used to answer a bare `"ok"` meaning "I tried",
    /// and the app treated that as "the routes are what I asked for" — so an
    /// unparseable answer and silence must land in the same place, which is
    /// "ask again".
    ///
    /// It lives on this type rather than in TunnelManager because the harness
    /// compiles this file and cannot compile anything importing
    /// NetworkExtension; a copy over there would be a second parser to keep in
    /// step with the one the tests actually check.
    static func parseReply(_ reply: String?) -> Bool? {
        guard let reply = reply else { return nil }
        for field in reply.split(separator: " ") {
            let parts = field.split(separator: "=")
            guard parts.count == 2, parts[0] == "direct" else { continue }
            if parts[1] == "1" { return true }
            if parts[1] == "0" { return false }
            return nil
        }
        return nil
    }

    /// Starts an apply if one is warranted. Private because only `intend` and
    /// `finish` may decide that — a caller that could start one directly could
    /// start a second.
    private mutating func startIfNeeded() -> Bool? {
        guard desired != applied else {
            attempts = 0
            return nil
        }
        guard attempts < Self.maxAttempts else { return nil }
        attempts += 1
        inFlight = desired
        return desired
    }
}
