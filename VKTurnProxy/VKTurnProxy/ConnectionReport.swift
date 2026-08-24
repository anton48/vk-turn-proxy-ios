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
    /// ⚖️ WHAT "Connected" CLAIMS, precisely: a tunnel SESSION EXISTS. It does
    /// not claim a confirmed datapath — `.reasserting` is a live session
    /// re-establishing its path, and packets may not be crossing it at the
    /// instant this is read. Those are different questions and the two-value
    /// answer can only carry one of them, and the tempting phrasing — asking
    /// whether traffic is crossing the tunnel — is the one it cannot deliver.
    ///
    /// `.reasserting` is reported as connected anyway because the alternative is
    /// worse: a hiccup would read as a gap and have an automation tear down a
    /// tunnel that is about to be fine. `.connecting` has no session yet and
    /// `.disconnecting` is losing one, so neither is a session to report.
    static func text(for status: NEVPNStatus) -> String {
        switch status {
        case .connected, .reasserting: return connected
        default: return disconnected
        }
    }
}
