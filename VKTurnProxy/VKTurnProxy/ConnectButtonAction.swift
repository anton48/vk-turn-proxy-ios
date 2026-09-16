// ConnectButtonAction.swift
//
// What a tap on the main button DOES, and what the button SAYS — one rule for
// both, so they cannot disagree.
//
// 2026-09-16 (build 398, the user's finding on 397): the label read
// "Disconnect" during pre-bootstrap — the app's own work before
// startVPNTunnel(): the cached credential or the captcha probe, the VK API,
// seconds to minutes — while the ACTION branched on the NE status, which is
// still .disconnected for that whole window. A Disconnect tapped there ran the
// Connect branch, logged "user pressed Connect", and was swallowed as a
// duplicate attempt; the tunnel then came up as if nothing had been tapped.

import Foundation
import NetworkExtension

enum ConnectButtonAction: Equatable {
    case connect
    case disconnect

    /// The rule. `preBootstrapInProgress` is TunnelManager's own flag for the
    /// attempt it is running before iOS knows anything; it wins over the NE
    /// status because the status cannot see that work.
    static func forTap(status: NEVPNStatus, preBootstrapInProgress: Bool) -> ConnectButtonAction {
        if preBootstrapInProgress { return .disconnect }
        switch status {
        case .connected, .connecting: return .disconnect
        default: return .connect
        }
    }

    var label: String {
        switch self {
        case .connect: return "Connect"
        case .disconnect: return "Disconnect"
        }
    }
}
