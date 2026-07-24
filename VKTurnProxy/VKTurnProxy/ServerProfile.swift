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

/// Backup form of a ServerProfile (the elements of `AppSettings.servers`).
///
/// Every field except the name is Optional so a backup written by a different
/// build still decodes — an absent key falls back to the ServerProfile default
/// on import. The profile `id` is deliberately NOT part of the backup: importing
/// mints fresh UUIDs, so restoring onto a device that already has servers can
/// never collide on identity.
struct ServerSettings: Codable {
    var serverName: String
    var privateKey: String? = nil
    var peerPublicKey: String? = nil
    var presharedKey: String? = nil
    var tunnelAddress: String? = nil
    var peerAddress: String? = nil
    var dnsServers: String? = nil
    var numConnections: Int? = nil
    var credPoolCooldownSeconds: Int? = nil
    var turnServerOverride: String? = nil
    var useUDP: Bool? = nil
    var useDTLS: Bool? = nil
    var useSrtp: Bool? = nil
    var useWrap: Bool? = nil
    var useWrapA: Bool? = nil
    var useWrapS: Bool? = nil
    var wrapKeyHex: String? = nil
    var obfProfile: String? = nil
    var clientID: String? = nil
    var wrapAPassword: String? = nil

    init(_ p: ServerProfile) {
        serverName = p.serverName
        privateKey = p.privateKey
        peerPublicKey = p.peerPublicKey
        presharedKey = p.presharedKey
        tunnelAddress = p.tunnelAddress
        peerAddress = p.peerAddress
        dnsServers = p.dnsServers
        numConnections = p.numConnections
        credPoolCooldownSeconds = p.credPoolCooldownSeconds
        turnServerOverride = p.turnServerOverride
        useUDP = p.useUDP
        useDTLS = p.useDTLS
        useSrtp = p.useSrtp
        useWrap = p.useWrap
        useWrapA = p.useWrapA
        useWrapS = p.useWrapS
        wrapKeyHex = p.wrapKeyHex
        obfProfile = p.obfProfile
        clientID = p.clientID
        wrapAPassword = p.wrapAPassword
    }

    /// Rebuild a profile, filling every absent field with the ServerProfile
    /// default. `allowedIPs` is not carried (always the pinned 0.0.0.0/0).
    var profile: ServerProfile {
        var p = ServerProfile()
        p.serverName = serverName
        if let v = privateKey { p.privateKey = v }
        if let v = peerPublicKey { p.peerPublicKey = v }
        if let v = presharedKey { p.presharedKey = v }
        if let v = tunnelAddress { p.tunnelAddress = v }
        if let v = peerAddress { p.peerAddress = v }
        if let v = dnsServers { p.dnsServers = v }
        if let v = numConnections { p.numConnections = v }
        if let v = credPoolCooldownSeconds { p.credPoolCooldownSeconds = v }
        if let v = turnServerOverride { p.turnServerOverride = v }
        if let v = useUDP { p.useUDP = v }
        if let v = useDTLS { p.useDTLS = v }
        if let v = useSrtp { p.useSrtp = v }
        if let v = useWrap { p.useWrap = v }
        if let v = useWrapA { p.useWrapA = v }
        if let v = useWrapS { p.useWrapS = v }
        if let v = wrapKeyHex { p.wrapKeyHex = v }
        if let v = obfProfile { p.obfProfile = v }
        if let v = clientID { p.clientID = v }
        if let v = wrapAPassword { p.wrapAPassword = v }
        return p
    }
}
