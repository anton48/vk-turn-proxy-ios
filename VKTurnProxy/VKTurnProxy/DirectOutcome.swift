// DirectOutcome.swift
//
// How a routing change ended, and what to tell an automation about it.
//
// A top-level type rather than one nested in TunnelManager so the harness can
// compile it: the mapping below is the whole contract an App Intent has with
// Shortcuts, and TunnelManager cannot be compiled outside the app.

import Foundation

enum DirectOutcome: Equatable {
    case confirmed
    case notConnected
    case busy
    case failed(String)
    /// Asked for, not confirmed. For OFF this has already started the ~107 s
    /// reconnect that repairs a possible leak.
    case unconfirmed(String)

    /// 🚨 The message to fail an automation with, or nil ONLY when the extension
    /// confirmed the routes. Every other case leaves `directModeError` either
    /// unset (the early exits) or set to something the user needs, so "no error
    /// was published" must never be read as "it worked".
    var automationFailure: String? {
        switch self {
        case .confirmed:
            return nil
        case .notConnected:
            return "VK Turn Proxy is not connected, so there is nothing to route around."
        case .busy:
            return "A routing change is already in progress."
        case .failed(let m), .unconfirmed(let m):
            return m
        }
    }
}
