// AppConfig.swift
//
// Codable representation of the entire app's persisted state, used by
// BackupManager for the user-facing Export/Import flow in Settings.
//
// Two scopes of "state" the user might want to preserve:
//   1. UserDefaults-backed @AppStorage values (connection params,
//      WireGuard keys, tuning knobs).
//   2. The TURN credential cache the extension writes to the App Group
//      container (creds-pool.json). Including this in the backup means
//      a restore can skip the VK PoW + captcha round on first connect
//      after import — directly relevant when migrating to a fresh install
//      after `xcrun devicectl install` left the previous cache behind.
//
// Schema version is independent of the on-disk creds-pool.json schema —
// they bump for different reasons. This file's `version` increments when
// the AppConfig wrapper itself changes; CredCacheFile's `version` (which
// we embed verbatim) increments when the TURN-cache shape changes. A
// future v2 of AppConfig might wrap a v3 CredCacheFile, etc.
//
// Sensitive content: WireGuard private key, preshared key, and TURN
// credentials are all in plaintext here. The app warns the user before
// share — no encryption in this iteration. Friend-shareable subsets
// (without TURN cache) are a separate "connection link" feature planned
// for a follow-up.

import Foundation

/// Top-level wrapper. `type` is reserved for the future when we add a
/// `connection-only` shareable form alongside `full`.
struct AppConfig: Codable {
    let version: Int
    let type: String
    let exportedAt: Int64
    let settings: AppSettings
    /// Optional because exporters may produce backups before the
    /// extension has ever populated the cache (fresh install with no
    /// prior connect), and importers must tolerate that.
    let turnPool: CredCacheFile?
    /// Captured-from-real-browser PoW solver profile. Optional for the
    /// same reason as turnPool — fresh install + never-solved-captcha
    /// state has nothing to back up. Also Optional so backups exported
    /// before this field shipped still decode (Codable synthesised init
    /// treats absent Optional keys as nil).
    let vkProfile: VKProfileEntry?

    enum CodingKeys: String, CodingKey {
        case version
        case type
        case exportedAt = "exported_at"
        case settings
        case turnPool = "turn_pool"
        case vkProfile = "vk_profile"
    }
}

/// Mirrors every @AppStorage in ContentView.swift / SettingsView. Keep
/// JSON keys identical to the AppStorage keys so a future "edit the
/// backup file in a text editor" workflow has obvious field names.
///
/// Newer fields (added after the v1 schema shipped) are declared
/// Optional so loading an older backup that doesn't contain them
/// still decodes — Codable's synthesised init treats absent Optional
/// keys as nil. The corresponding apply step in BackupManager uses
/// the AppStorage default when nil. Each addition documents which
/// build introduced it for traceability.
struct AppSettings: Codable {
    let privateKey: String
    let peerPublicKey: String
    let presharedKey: String
    let tunnelAddress: String
    let dnsServers: String
    let allowedIPs: String
    let vkLink: String
    let peerAddress: String
    let useDTLS: Bool
    let numConnections: Int
    let credPoolCooldownSeconds: Int
    /// WRAP layer (ChaCha20-XOR ChannelData payload obfuscation, see
    /// vk-turn-proxy-ios commit 1c1edc1 / branch add-client-wrap-layer).
    /// Optional for back-compat with backups exported before WRAP shipped.
    /// NOTE 2026-05-20: WRAP no longer bypasses VK's content classifier
    /// — use useSrtp below instead. WRAP fields retained for backward-
    /// compat with legacy backups.
    let useWrap: Bool?
    /// 64-character hex encoding of the 32-byte WRAP shared key. Must
    /// match the server's -wrap-key. Optional for back-compat.
    let wrapKeyHex: String?
    /// SRTP transport (DTLS+SRTP+RTP framing, see pkg/proxy/srtpwrap
    /// and add-server-srtp-layer server branch, added 2026-05-20 build
    /// 115+). Bypasses VK's per-allocation shape policy. Optional for
    /// back-compat with backups exported before SRTP shipped.
    let useSrtp: Bool?
    /// TURN control-transport: UDP (true) vs TCP (false, default).
    /// Surfaced as a Settings toggle in build 128. TCP-control bypasses
    /// VK's per-cred allocation-rate throttle (introduced 2026-05-18);
    /// UDP-control is the historical default and can be re-enabled if
    /// the user is on a network where TCP-to-relay is blocked or much
    /// slower. Optional for back-compat with backups exported before
    /// this build — nil leaves the AppStorage default (false / TCP).
    let useUDP: Bool?
    /// WRAP-A (amurcanov-compatible 4th transport mode, added 2026-06-03).
    /// Optional for back-compat with backups exported before WRAP-A shipped —
    /// nil leaves the AppStorage default (false). The per-install deviceID is
    /// deliberately NOT backed up (device identity, regenerated on fresh
    /// install so two devices never collide on the server's WG-peer pool).
    let useWrapA: Bool?
    /// WRAP-A shared secret (obfuscation key + GETCONF auth). Optional for
    /// back-compat. Plaintext like the WG private key above.
    let wrapAPassword: String?
    /// turnServerOverride: optional "IP:port" (added 2026-06-08). When set,
    /// fresh VK fetches are forced onto this TURN relay; disk-cached creds keep
    /// their stored address. Optional for back-compat; nil = no override.
    let turnServerOverride: String?
    /// UNDOCUMENTED on-device captcha-test toggle (build 149): when true the
    /// extension skips the captcha-free VK Calls path so the legacy
    /// captchaNotRobot.* solver runs — lets a tester exercise the captcha fix
    /// (the free path is captcha-free, so the solver never runs otherwise).
    /// Optional + default nil so normal backups omit it; a tester adds
    /// `"forceLegacyCaptcha": true` to the backup JSON by hand. No Settings UI.
    /// `var` (not `let`) so the synthesised Decodable actually decodes it — an
    /// immutable property with an initial value is never decoded by Codable.
    var forceLegacyCaptcha: Bool? = nil
    /// VKAuth (non-anonymous cookie cred path) toggle. Round-trips in full
    /// backups so the preference is preserved. The cookies themselves are NEVER
    /// in the backup — they live in the Keychain (VKCookieStore). Optional +
    /// `var` so Codable decodes it (nil-preserve on import). Default nil.
    var vkAuth: Bool? = nil
    // SRTP-WRAP-S (samosvalishe/free-turn-proxy). `var ... = nil` like vkAuth so
    // old backups/links decode and importers don't force the mode when absent.
    var useWrapS: Bool? = nil
    var obfProfile: String? = nil
    var clientID: String? = nil
}

// MARK: - 1-Click Connection Link
//
// Lightweight payload sibling to AppConfig used for the 1-Click import
// feature. Encoded as base64 inside `vkturnproxy://import?data=…` URLs
// (or raw on the clipboard) so a server admin can hand a fresh device
// the entire deployment definition in one tap.
//
// Deliberately a SEPARATE struct from AppConfig/AppSettings — does NOT
// reuse them — so that:
//   • Connection links don't accidentally leak the TURN credential cache
//     or the captured browser profile (those belong to the device, not
//     the deployment).
//   • Field requirements differ from full backups: dnsServers and
//     numConnections are optional in a link (the receiving device keeps
//     its current value if absent), whereas in a full backup they're
//     always present. credPoolCooldownSeconds is excluded entirely from
//     links — it's an internal tuning knob nobody should override at
//     onboarding time.
//
// Schema version is shared with AppConfig (BackupManager.supportedConfigVersion)
// so a new schema version invalidates BOTH backup files and connection
// links uniformly.

struct ConnectionLink: Codable {
    let version: Int
    /// Always "connection" for link payloads. Distinguishes from
    /// AppConfig's "full" so the parser can early-reject mismatched
    /// inputs (e.g. user accidentally pastes a full-backup base64 here).
    let type: String
    let settings: ConnectionSettings
}

/// Subset of AppSettings that defines a deployment. WG keys + server
/// address + vkLink + WRAP key are all required; per-device tunables
/// (dnsServers, numConnections) are optional.
struct ConnectionSettings: Codable {
    /// privateKey / peerPublicKey / tunnelAddress / allowedIPs made Optional
    /// 2026-06-03 so a WRAP-A link can omit them entirely — amurcanov's server
    /// provisions WireGuard via GETCONF, so a WRAP-A deployment has no client-
    /// chosen WG keys. Nil-preserves-default on import (absent → keep the
    /// device's current value, so switching modes later doesn't lose keys).
    /// Non-WRAP-A links still include them; quick_link.py requires them unless
    /// useWrapA is set.
    let privateKey: String?
    let peerPublicKey: String?
    /// presharedKey made Optional in build 134 — WireGuard PSK is
    /// optional in the protocol (RFC 4193 §5.2: "If a PSK is not
    /// configured, then it is assumed to be all zeros"), so deployments
    /// that don't use one shouldn't be forced to provide a value in the
    /// link payload. Nil-preserves-default on import: absent → keep
    /// whatever the receiving device already had. Older quick_link.py-
    /// generated links that still carry the field continue to apply it
    /// through unchanged. AppSettings.presharedKey (full-backup path)
    /// remains required because currentConfig() always populates it from
    /// UserDefaults.
    let presharedKey: String?
    let tunnelAddress: String?
    let allowedIPs: String?
    let vkLink: String
    let peerAddress: String
    /// useDTLS / useWrap / wrapKeyHex made Optional in build 129. UI
    /// toggles for both are gone (useDTLS removed build 127, useWrap
    /// removed build 115), so admins generating links should typically
    /// omit them and let the importer keep whatever the device already
    /// has — useDTLS defaults to true so the legacy DTLS+WG path stays
    /// the safe fallback; useWrap defaults to false so the importer
    /// doesn't unintentionally turn on WRAP against a non-WRAP server.
    /// Older quick_link.py-generated links that still set these fields
    /// continue to apply them on import — nil semantics is purely an
    /// additive relaxation for new link generators.
    let useDTLS: Bool?
    let useWrap: Bool?
    let wrapKeyHex: String?
    /// SRTP transport (added 2026-05-20). Optional for back-compat with
    /// connection links exported before SRTP shipped — receiving device
    /// keeps its current useSrtp value (default false) if absent.
    let useSrtp: Bool?
    /// TURN control-transport UDP vs TCP (added build 128). Optional
    /// for back-compat — receiving device keeps its current useUDP
    /// value (default false / TCP) if absent in the link payload.
    let useUDP: Bool?
    /// WRAP-A (amurcanov interop) mode + password (added 2026-06-03). This is
    /// the 1-click payload the "how do I reach amurcanov's server from iOS"
    /// askers need: a link of {peerAddress, useWrapA:true, wrapAPassword}
    /// auto-provisions WireGuard via GETCONF — NO WG keys in the link.
    /// Optional for back-compat; nil keeps the device's current value.
    let useWrapA: Bool?
    let wrapAPassword: String?
    /// turnServerOverride: optional "IP:port" TURN-relay override (added
    /// 2026-06-08). nil keeps the device's current value.
    let turnServerOverride: String?
    /// Optional: if absent, the importing device keeps its current
    /// dnsServers value (or the AppStorage default of "1.1.1.1" if
    /// never set). Always set on apply when present.
    let dnsServers: String?
    /// Optional: if absent, the importing device keeps its current
    /// numConnections (default 30). Useful for an admin to ship a
    /// "recommended for this deployment" hint while still letting
    /// users tune later.
    let numConnections: Int?
    // VKAuth (cookie auth) toggle. Optional, nil-preserve. Lets a connection link
    // provision a device for the non-anonymous cookie path; cookies are NEVER in
    // links (device Keychain only), so the device still logs in via WKWebView on
    // first connect. A multiline vkLink above carries the call links. `var ... =
    // nil` (like AppSettings.forceLegacyCaptcha) so Codable decodes it AND the
    // synthesised memberwise init defaults it (existing construction sites — e.g.
    // parseWdttLink — stay unchanged).
    var vkAuth: Bool? = nil
    // SRTP-WRAP-S (samosvalishe/free-turn-proxy). `var ... = nil` like vkAuth so
    // old backups/links decode and importers don't force the mode when absent.
    var useWrapS: Bool? = nil
    var obfProfile: String? = nil
    var clientID: String? = nil
}
