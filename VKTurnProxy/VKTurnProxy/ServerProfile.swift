// ServerProfile.swift
//
// A named set of per-server connection settings (a "server"). Exactly one
// ServerProfile is the ACTIVE server at a time; ServerStore projects the
// active profile's fields into the flat @AppStorage keys that ContentView and
// TunnelManager already consume at connect time (Option A — see ServerStore).
//
// vkLink and vkAuth (UserDefaults key "VKAuth") are GLOBAL and are NOT part of
// a profile. allowedIPs is never stored — it is always the constant
// "0.0.0.0/0" (pinned since the field was removed from the UI in build 160).

import Foundation

struct ServerProfile: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var serverName: String = "Server1"

    // WireGuard identity — used by SRTP / SRTP-WRAP / SRTP-WRAP-S. Unused by
    // SRTP-WRAP-A, whose WG keys are minted by the server via GETCONF.
    var privateKey: String = ""
    var peerPublicKey: String = ""
    var presharedKey: String = ""
    var tunnelAddress: String = "192.168.102.3/24"
    var peerAddress: String = ""

    // Common transport / cred-pool settings.
    var dnsServers: String = "1.1.1.1"
    var numConnections: Int = 30
    var credPoolCooldownSeconds: Int = 150
    var turnServerOverride: String = ""
    var useUDP: Bool = false
    // No UI toggle since build 127; effectively a constant (true).
    var useDTLS: Bool = true

    // Transport mode — exactly one of these is true. Mutual exclusion is
    // enforced by the ServerMode binding (as it already is for @AppStorage).
    var useSrtp: Bool = true
    var useWrap: Bool = false
    var useWrapA: Bool = false
    var useWrapS: Bool = false

    // SRTP-WRAP / SRTP-WRAP-S obfuscation.
    var wrapKeyHex: String = ""
    var obfProfile: String = "rtpopus"
    var clientID: String = ""        // SRTP-WRAP-S per-stream id (auto-UUID)
    // SRTP-WRAP-A.
    var wrapAPassword: String = ""

    /// Human-readable transport mode, matching the ServerMode picker labels.
    /// Used in log lines and import confirmations.
    var modeLabel: String {
        if useWrapS { return "SRTP-WRAP-S" }
        if useWrapA { return "SRTP-WRAP-A" }
        if useSrtp { return "SRTP" }
        if useWrap { return "SRTP+WRAP" }
        return "Legacy (DTLS+WG)"
    }
}
