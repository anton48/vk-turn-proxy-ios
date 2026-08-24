// ConnectionReport.swift
//
// What an automation is told about the tunnel's state.

import Foundation
import NetworkExtension

enum ConnectionReport {
    static let connected = "Connected"
    static let disconnected = "Disconnected"

    /// 🚨 Only `.connected` reads as connected. `.connecting` has no tunnel
    /// carrying traffic yet, and `.disconnecting` no longer has one, so a
    /// shortcut branching on this gets the answer it is actually asking about —
    /// "is my traffic going through the tunnel right now".
    ///
    /// ⚖️ `.reasserting` counts as connected: the session is up and
    /// re-establishing its path, which is a hiccup rather than a gap, and
    /// reporting it as disconnected would make an automation tear down a tunnel
    /// that is about to be fine.
    static func text(for status: NEVPNStatus) -> String {
        switch status {
        case .connected, .reasserting: return connected
        default: return disconnected
        }
    }
}
