// ConnectionReport.swift
//
// What an automation is told about the tunnel's state.

import Foundation
import NetworkExtension

enum ConnectionReport {
    static let connected = "Connected"
    static let disconnected = "Disconnected"

    /// 🚨 `.connected` AND `.reasserting` read as connected; `.connecting`,
    /// `.disconnecting` and `.invalid` do not.
    ///
    /// The question a shortcut is asking is "is my traffic going through the
    /// tunnel right now". `.connecting` has no tunnel carrying it yet and
    /// `.disconnecting` no longer has one. `.reasserting` does: the session is
    /// up and re-establishing its path, a hiccup rather than a gap, and
    /// reporting it as disconnected would make an automation tear down a tunnel
    /// that is about to be fine.
    static func text(for status: NEVPNStatus) -> String {
        switch status {
        case .connected, .reasserting: return connected
        default: return disconnected
        }
    }
}
