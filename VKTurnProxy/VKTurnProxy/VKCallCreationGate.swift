// VKCallCreationGate.swift
//
// The ONE rule for the "Get VK call URL" control: whether it is enabled, and
// what the caption under it says when it is not.
//
// A VK call is created FROM the saved VK login — the remixsid + p pair the
// cookie-auth login harvests — and nothing else can stand in for it: the
// sign-in form inside VK's OAuth flow is broken (issue #69's finding), so the
// flow can only ever say "Continue as <existing user>". Started without the
// login it flashed an empty screen and ended in "VK did not recognise the
// saved login" — about a login that did not exist (the user's report,
// 2026-09-16). So the control is unavailable until a login is on record, and
// the caption says why and how.
//
// 🚨 The cookie-auth TOGGLE is not the condition. It decides what the TUNNEL
// authenticates with; the call needs the LOGIN, which the toggle's section
// harvests and keeps whether the toggle is on or off. The rule takes the saved
// login's expiry and nothing else, so the harness can drive it.

import Foundation

enum VKCallCreationGate {
    enum State: Equatable {
        case available
        case noLogin
        case loginExpired(Date)
    }

    static func state(loginExpiry: Date?, now: Date = Date()) -> State {
        guard let expiry = loginExpiry else { return .noLogin }
        return expiry > now ? .available : .loginExpired(expiry)
    }

    static func isAvailable(_ state: State) -> Bool {
        state == .available
    }

    /// The caption under the control: the reason it is unavailable and what to
    /// do about it, or nil when it is available.
    static func reason(_ state: State) -> String? {
        switch state {
        case .available:
            return nil
        case .noLogin:
            return "Unavailable without a saved VK login. Turn on “Use VK account (cookie) auth” below and log in; the toggle can be turned off again afterwards — the saved login is what the call is created from."
        case .loginExpired:
            return "The saved VK login has expired. Log in again under “Use VK account (cookie) auth” below (turn it on if it is off; it can be turned off again afterwards)."
        }
    }
}
