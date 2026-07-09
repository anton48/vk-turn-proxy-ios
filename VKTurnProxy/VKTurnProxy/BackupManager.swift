// BackupManager.swift
//
// Export/Import/Reset of app state for the Settings → Backup & Restore
// section.
//
// Export builds an AppConfig snapshot of (1) all @AppStorage values via
// UserDefaults.standard and (2) the current creds-pool.json from the App
// Group container. Output is a temp .json file fed into UIActivityViewController
// (Share Sheet) so the user picks the destination — Files, AirDrop, Mail, etc.
//
// Import is the inverse: read a JSON the user picked from the document
// picker, decode as AppConfig, and atomically replace UserDefaults +
// creds-pool.json. Atomicity here means "all or nothing per-domain":
// UserDefaults writes happen first (they're synchronous and don't fail
// in normal conditions), then creds-pool.json is replaced via
// tmp-file + rename to match how the Go side writes (atomic relative
// to readers). If creds-pool.json write fails after UserDefaults already
// changed, the user has settings restored but no TURN cache — first
// connect will fall through to the regular VK fetch path. We log the
// failure but don't try to roll back UserDefaults; the previous file
// would be lost anyway.
//
// Reset just deletes creds-pool.json. The pool gets rebuilt on next
// connect via the normal VK API + PoW path. No UserDefaults changes.

import Foundation

enum BackupError: Error, LocalizedError {
    case noContainer
    case writeFailed(String)
    case readFailed(String)
    case decodeFailed(String)
    case versionMismatch(Int)

    var errorDescription: String? {
        switch self {
        case .noContainer:
            return "App Group container is unavailable. Check entitlements."
        case .writeFailed(let detail):
            return "Failed to write file: \(detail)"
        case .readFailed(let detail):
            return "Failed to read file: \(detail)"
        case .decodeFailed(let detail):
            return "Backup file is invalid or corrupted: \(detail)"
        case .versionMismatch(let v):
            return "Backup file version \(v) is not supported by this build."
        }
    }
}

enum BackupManager {
    /// Schema version of AppConfig itself. Bump when the wrapper shape
    /// changes (new top-level fields, restructured settings, etc.).
    static let supportedConfigVersion = 1

    /// Path to the App Group's creds-pool.json. Mirrors the Go-side
    /// `filepath.Dir(logFilePath) + "/creds-pool.json"` and the Swift-side
    /// `CredCache.cacheURL`. Kept here as a private duplicate so the
    /// backup logic is self-contained and won't break if CredCache ever
    /// computes the path differently.
    private static var credsPoolURL: URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.vkturnproxy.app"
        )?.appendingPathComponent("creds-pool.json")
    }

    // MARK: - Build current snapshot

    /// Reads all @AppStorage values via UserDefaults.standard (since
    /// @AppStorage is a thin wrapper over UserDefaults) and the current
    /// creds-pool.json. Always returns an AppConfig — turnPool is nil if
    /// the cache file is absent or unreadable, which is normal after a
    /// fresh install or a Reset TURN Cache.
    static func currentConfig() -> AppConfig {
        let d = UserDefaults.standard
        // Every value is pre-computed into a local so the AppSettings(...) init
        // below stays a plain list of identifiers — a large init literal with
        // inline `??`/`as?` expressions makes Swift's type-checker time out.
        // Defaults must match SettingsView's @AppStorage defaults (UserDefaults
        // returns nil for unset keys); `object(forKey:) as? Bool` distinguishes
        // "explicitly false" from "never set".
        let privateKey = d.string(forKey: "privateKey") ?? ""
        let peerPublicKey = d.string(forKey: "peerPublicKey") ?? ""
        let presharedKey = d.string(forKey: "presharedKey") ?? ""
        let tunnelAddress = d.string(forKey: "tunnelAddress") ?? "192.168.102.3/24"
        let dnsServers = d.string(forKey: "dnsServers") ?? "1.1.1.1"
        let allowedIPs = d.string(forKey: "allowedIPs") ?? "0.0.0.0/0"
        let vkLink = d.string(forKey: "vkLink") ?? ""
        let peerAddress = d.string(forKey: "peerAddress") ?? ""
        let useDTLS = (d.object(forKey: "useDTLS") as? Bool) ?? true
        let numConnections = (d.object(forKey: "numConnections") as? Int) ?? 30
        let credPoolCooldownSeconds = (d.object(forKey: "credPoolCooldownSeconds") as? Int) ?? 150
        let useWrap = (d.object(forKey: "useWrap") as? Bool) ?? false
        let wrapKeyHex = d.string(forKey: "wrapKeyHex") ?? ""
        let useSrtp = (d.object(forKey: "useSrtp") as? Bool) ?? false
        let useUDP = (d.object(forKey: "useUDP") as? Bool) ?? false
        let useWrapA = (d.object(forKey: "useWrapA") as? Bool) ?? false
        let wrapAPassword = d.string(forKey: "wrapAPassword") ?? ""
        let wrapSOn = (d.object(forKey: "useWrapS") as? Bool) ?? false
        let wrapSProfile = d.string(forKey: "obfProfile") ?? "rtpopus"
        let wrapSClientID = d.string(forKey: "clientID") ?? ""
        let turnServerOverride = d.string(forKey: "turnServerOverride")
        let vkAuth = (d.object(forKey: "VKAuth") as? Bool) ?? false
        let settings = AppSettings(
            privateKey: privateKey,
            peerPublicKey: peerPublicKey,
            presharedKey: presharedKey,
            tunnelAddress: tunnelAddress,
            dnsServers: dnsServers,
            allowedIPs: allowedIPs,
            vkLink: vkLink,
            peerAddress: peerAddress,
            useDTLS: useDTLS,
            numConnections: numConnections,
            credPoolCooldownSeconds: credPoolCooldownSeconds,
            useWrap: useWrap,
            wrapKeyHex: wrapKeyHex,
            useSrtp: useSrtp,
            useUDP: useUDP,
            useWrapA: useWrapA,
            wrapAPassword: wrapAPassword,
            turnServerOverride: turnServerOverride,
            vkAuth: vkAuth,
            useWrapS: wrapSOn,
            obfProfile: wrapSProfile,
            clientID: wrapSClientID
        )

        var turnPool: CredCacheFile? = nil
        if let url = credsPoolURL,
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode(CredCacheFile.self, from: data) {
            turnPool = decoded
        }

        // Captured browser profile (vk_profile.json). Optional — fresh
        // installs without any solved captcha won't have it. Skipped
        // silently on missing/corrupt file so the rest of the export
        // still produces a usable backup.
        let vkProfile = VKProfileCache.load()

        return AppConfig(
            version: supportedConfigVersion,
            type: "full",
            exportedAt: Int64(Date().timeIntervalSince1970),
            settings: settings,
            turnPool: turnPool,
            vkProfile: vkProfile
        )
    }

    // MARK: - Export

    /// Encodes currentConfig() to a pretty-printed JSON file in the temp
    /// directory and returns its URL. Caller passes the URL to
    /// UIActivityViewController. The temp file persists until the OS
    /// cleans /tmp (boot, low storage) — fine for one-shot Share Sheet
    /// flows since the user either saves it elsewhere immediately or
    /// dismisses the sheet.
    static func exportToTempFile() throws -> URL {
        let config = currentConfig()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(config)
        } catch {
            throw BackupError.writeFailed("encode: \(error.localizedDescription)")
        }

        // Filename includes a timestamp so the user gets distinguishable
        // files when they export multiple times — useful when iterating
        // on settings and AirDropping each iteration to the Mac.
        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let filename = "vkturnproxy-backup-\(timestamp).json"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)

        do {
            try data.write(to: url, options: .atomic)
        } catch {
            throw BackupError.writeFailed(error.localizedDescription)
        }
        SharedLogger.shared.log("[AppDebug] Backup: exported \(data.count) bytes to \(url.lastPathComponent)")
        return url
    }

    // MARK: - Import

    /// Reads JSON at the given file URL. Used by the document picker
    /// callback after the user selects a file. Validates schema version
    /// before applying anything — a too-new backup is rejected before
    /// any state is changed.
    static func importFromFileURL(_ url: URL) throws -> AppConfig {
        // Document picker hands us a security-scoped URL when the file
        // lives outside our sandbox (iCloud Drive, On My iPhone, etc.).
        // Without start/stopAccessing, Data(contentsOf:) returns
        // "Operation not permitted" for those sources.
        let needsScope = url.startAccessingSecurityScopedResource()
        defer {
            if needsScope {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw BackupError.readFailed(error.localizedDescription)
        }

        let config: AppConfig
        do {
            config = try JSONDecoder().decode(AppConfig.self, from: data)
        } catch {
            throw BackupError.decodeFailed(error.localizedDescription)
        }

        if config.version != supportedConfigVersion {
            throw BackupError.versionMismatch(config.version)
        }
        return config
    }

    /// Applies the AppConfig to UserDefaults + creds-pool.json. Called
    /// after the user confirms the import in the alert dialog. Logs both
    /// success and per-step failures so post-mortem analysis from vpn.log
    /// can pinpoint what landed and what didn't.
    static func applyConfig(_ config: AppConfig) throws {
        let d = UserDefaults.standard
        let s = config.settings
        d.set(s.privateKey, forKey: "privateKey")
        d.set(s.peerPublicKey, forKey: "peerPublicKey")
        d.set(s.presharedKey, forKey: "presharedKey")
        d.set(s.tunnelAddress, forKey: "tunnelAddress")
        d.set(s.dnsServers, forKey: "dnsServers")
        d.set(s.allowedIPs, forKey: "allowedIPs")
        d.set(s.vkLink, forKey: "vkLink")
        d.set(s.peerAddress, forKey: "peerAddress")
        d.set(s.useDTLS, forKey: "useDTLS")
        d.set(s.numConnections, forKey: "numConnections")
        d.set(s.credPoolCooldownSeconds, forKey: "credPoolCooldownSeconds")
        // WRAP fields: nil → leave UserDefaults alone so the AppStorage
        // default kicks in, matching the behaviour for an older backup
        // that never had these keys. Non-nil → write through, including
        // false / empty if the user explicitly set them that way.
        if let v = s.useWrap { d.set(v, forKey: "useWrap") }
        if let v = s.wrapKeyHex { d.set(v, forKey: "wrapKeyHex") }
        // useSrtp: same pattern as WRAP fields — nil leaves the
        // AppStorage default in place, non-nil writes through.
        if let v = s.useSrtp { d.set(v, forKey: "useSrtp") }
        // useUDP: same nil-preserves-default pattern.
        if let v = s.useUDP { d.set(v, forKey: "useUDP") }
        // WRAP-A (amurcanov interop): same nil-preserves-default pattern.
        if let v = s.useWrapA { d.set(v, forKey: "useWrapA") }
        if let v = s.wrapAPassword { d.set(v, forKey: "wrapAPassword") }
        if let v = s.useWrapS { d.set(v, forKey: "useWrapS") }
        if let v = s.obfProfile { d.set(v, forKey: "obfProfile") }
        if let v = s.clientID { d.set(v, forKey: "clientID") }
        if let v = s.turnServerOverride { d.set(v, forKey: "turnServerOverride") }
        // forceLegacyCaptcha: undocumented on-device captcha-test toggle
        // (build 149) — same nil-preserves-default pattern.
        if let v = s.forceLegacyCaptcha { d.set(v, forKey: "forceLegacyCaptcha") }
        if let v = s.vkAuth { d.set(v, forKey: "VKAuth") }

        SharedLogger.shared.log("[AppDebug] Backup: applied settings (numConnections=\(s.numConnections), cooldown=\(s.credPoolCooldownSeconds)s, useDTLS=\(s.useDTLS), useWrap=\(s.useWrap ?? false), useSrtp=\(s.useSrtp ?? false), useUDP=\(s.useUDP ?? false))")

        // creds-pool.json: write only if backup contained one. If the
        // backup has nil turnPool (e.g. user exported on a fresh install
        // before any successful connect), leave the existing cache
        // alone — overwriting with empty would defeat the point of
        // restoring on a fresh device that DOES have a cache from a
        // previous install.
        guard let pool = config.turnPool else {
            SharedLogger.shared.log("[AppDebug] Backup: turn_pool absent in backup, leaving creds-pool.json unchanged")
            return
        }
        guard let url = credsPoolURL else {
            throw BackupError.noContainer
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(pool)
        } catch {
            throw BackupError.writeFailed("encode turn_pool: \(error.localizedDescription)")
        }

        // tmp+rename mirrors Go-side saveToDisk's atomicity: a reader
        // (the extension when it next launches) sees either the old file
        // or the new, never a torn write.
        let tmpURL = url.appendingPathExtension("tmp")
        do {
            try? FileManager.default.removeItem(at: tmpURL)
            try data.write(to: tmpURL, options: .atomic)
            // Replace existing file. _ = is fine — replaceItemAt either
            // succeeds, throws, or returns the result URL; we don't need
            // the URL since we know our target.
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
        } catch {
            try? FileManager.default.removeItem(at: tmpURL)
            throw BackupError.writeFailed("write creds-pool.json: \(error.localizedDescription)")
        }
        SharedLogger.shared.log("[AppDebug] Backup: restored creds-pool.json with \(pool.creds.count) slots")

        // Captured browser profile: write only if the backup contained one.
        // Same nil-tolerance reasoning as turn_pool — older backups
        // exported before the field shipped just leave the existing
        // vk_profile.json (if any) alone. Failure here is logged but
        // doesn't abort the import: the worst case is a stale or absent
        // profile, which the auto-solver tolerates by falling back to
        // generated browser_fp.
        if let entry = config.vkProfile {
            do {
                try VKProfileCache.applyFromBackup(entry)
                SharedLogger.shared.log("[AppDebug] Backup: restored vk_profile.json (device=\(entry.device.count)c, browser_fp=\(entry.browser_fp.count)c)")
            } catch {
                SharedLogger.shared.log("[AppDebug] Backup: vk_profile.json write failed (non-fatal): \(error.localizedDescription)")
            }
        } else {
            SharedLogger.shared.log("[AppDebug] Backup: vk_profile absent in backup, leaving vk_profile.json unchanged")
        }
    }

    // MARK: - Reset TURN Cache

    /// Deletes creds-pool.json. The pool will be rebuilt from scratch on
    /// next connect via the normal VK API path. Idempotent — succeeds
    /// silently if the file was already gone (ENOENT is treated as success
    /// since the post-condition "no creds-pool.json exists" holds).
    static func resetTurnCache() throws {
        guard let url = credsPoolURL else {
            throw BackupError.noContainer
        }
        do {
            try FileManager.default.removeItem(at: url)
            SharedLogger.shared.log("[AppDebug] Backup: deleted creds-pool.json (Reset TURN Cache)")
        } catch CocoaError.fileNoSuchFile {
            SharedLogger.shared.log("[AppDebug] Backup: Reset TURN Cache — file already absent")
        } catch let nsErr as NSError where nsErr.code == NSFileNoSuchFileError {
            SharedLogger.shared.log("[AppDebug] Backup: Reset TURN Cache — file already absent")
        } catch {
            throw BackupError.writeFailed("delete creds-pool.json: \(error.localizedDescription)")
        }
    }

    // MARK: - Reset Captured Browser Profile

    /// Deletes vk_profile.json. The auto-PoW solver will fall back to
    /// its generated browser_fp + canned device descriptor, with the
    /// pre-build-55 BOT-detection rate (~6%) — until the next manual
    /// captcha solve in CaptchaWKWebView re-captures fresh values.
    /// Idempotent same way as resetTurnCache.
    static func resetCapturedProfile() throws {
        try VKProfileCache.delete()
    }

    // MARK: - 1-Click Connection Link

    /// Parses a `vkturnproxy://import?data=<base64>` URL. The system
    /// hands one of these to .onOpenURL whenever the user taps a link
    /// with the registered scheme. Throws on any structural error so
    /// the caller can show a single "Connection Link Invalid" alert
    /// with the underlying message.
    static func parseConnectionLink(from url: URL) throws -> ConnectionLink {
        // amurcanov compat: wdtt:// links use a flat colon-delimited format,
        // not our base64 payload — route them to the dedicated parser.
        if url.scheme?.lowercased() == "wdtt" {
            return try parseWdttLink(url.absoluteString)
        }
        // samosvalishe free-turn-proxy compat: freeturn://<base64url(json)>.
        if url.scheme?.lowercased() == "freeturn" {
            return try parseFreeturnLink(url.absoluteString)
        }
        guard url.scheme?.lowercased() == "vkturnproxy" else {
            throw BackupError.decodeFailed("URL scheme is not vkturnproxy://")
        }
        // Accept both vkturnproxy://import?data=… and the looser
        // vkturnproxy:?data=… form. URL.host is "import" for the first
        // and nil for the second; both should work.
        if let host = url.host, host.lowercased() != "import" {
            throw BackupError.decodeFailed("URL host must be 'import' (got '\(host)')")
        }
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let dataItem = comps.queryItems?.first(where: { $0.name == "data" }),
              let b64 = dataItem.value, !b64.isEmpty else {
            throw BackupError.decodeFailed("URL is missing the 'data' query parameter")
        }
        return try parseConnectionLinkBase64(b64)
    }

    /// Same as parseConnectionLink(from:) but takes the raw clipboard
    /// string. Tolerant of either a full URL ("vkturnproxy://…") or a
    /// bare base64 blob — the user might have copied either form.
    static func parseConnectionLinkString(_ raw: String) throws -> ConnectionLink {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // amurcanov compat: a pasted wdtt:// link (his android server's format).
        if trimmed.lowercased().hasPrefix("wdtt://") {
            return try parseWdttLink(trimmed)
        }
        // samosvalishe free-turn-proxy compat: a pasted freeturn:// link.
        if trimmed.lowercased().hasPrefix("freeturn://") {
            return try parseFreeturnLink(trimmed)
        }
        if let url = URL(string: trimmed), url.scheme?.lowercased() == "vkturnproxy" {
            return try parseConnectionLink(from: url)
        }
        // No URL prefix — treat input as raw base64.
        return try parseConnectionLinkBase64(trimmed)
    }

    /// Decodes a base64 string (standard or url-safe, with or without
    /// padding) into the ConnectionLink JSON. Common bottom layer for
    /// both URL- and clipboard-string entry points.
    private static func parseConnectionLinkBase64(_ b64Input: String) throws -> ConnectionLink {
        // Normalise to standard base64 with padding before Foundation's
        // Data(base64Encoded:) — it's strict about both.
        var b64 = b64Input.replacingOccurrences(of: "-", with: "+")
                          .replacingOccurrences(of: "_", with: "/")
        let padNeeded = (4 - b64.count % 4) % 4
        b64 += String(repeating: "=", count: padNeeded)
        guard let data = Data(base64Encoded: b64) else {
            throw BackupError.decodeFailed("Invalid base64 in connection link")
        }
        let link: ConnectionLink
        do {
            link = try JSONDecoder().decode(ConnectionLink.self, from: data)
        } catch {
            throw BackupError.decodeFailed("Connection link JSON: \(error.localizedDescription)")
        }
        if link.version != supportedConfigVersion {
            throw BackupError.versionMismatch(link.version)
        }
        if link.type != "connection" {
            throw BackupError.decodeFailed("Expected type=connection, got '\(link.type)'")
        }
        return link
    }

    // MARK: - amurcanov wdtt:// compat link

    /// Parses an amurcanov `wdtt://` link into our ConnectionLink (SRTP-WRAP-A
    /// mode). Format (verified against proxy-turn-vk-android v1.2.2 —
    /// server.go link generation + SettingsTab.kt parser):
    ///
    ///   wdtt://<IP>:<dtlsPort>:<wgPort>:<localPeerPort>:<password>:<hash[,hash…]>
    ///
    /// We use only IP+dtlsPort (→ peerAddress), password (→ wrapAPassword) and
    /// the FIRST VK hash (→ vkLink = https://vk.com/call/join/<hash>, which our
    /// Go side reduces to the lastPathComponent token). wgPort/localPeerPort are
    /// his server-internal / android-loopback values — irrelevant to us (we
    /// provision WireGuard via GETCONF and route via our own conn.Bind). His
    /// links can carry up to 4 hashes; we take the first — our credpool already
    /// grows a full conn pool from a single VK link. His own Android app doesn't
    /// register the wdtt:// scheme (paste-only), so when WE register it there's
    /// no handler collision.
    static func parseWdttLink(_ raw: String) throws -> ConnectionLink {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("wdtt://") else {
            throw BackupError.decodeFailed("URL scheme is not wdtt://")
        }
        let body = String(trimmed.dropFirst("wdtt://".count))
        // omittingEmptySubsequences:false keeps positional integrity if a field
        // is empty — matches amurcanov's Kotlin split(":") semantics so our
        // field indices line up with his.
        let parts = body.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 6 else {
            throw BackupError.decodeFailed("wdtt:// link needs 6 colon-separated fields, got \(parts.count)")
        }
        let ip = parts[0].trimmingCharacters(in: .whitespaces)
        let dtlsPort = parts[1].trimmingCharacters(in: .whitespaces)
        // parts[2] = wgPort, parts[3] = localPeerPort — intentionally ignored.
        let password = parts[4]
        // parts[5] may be a comma-separated list of VK hashes — take the first.
        let firstHashRaw = parts[5]
            .split(separator: ",", omittingEmptySubsequences: false)
            .first.map(String.init) ?? ""
        let firstHash = stripVkUrl(firstHashRaw)

        guard !ip.isEmpty, !dtlsPort.isEmpty, Int(dtlsPort) != nil else {
            throw BackupError.decodeFailed("wdtt:// link has an invalid IP or DTLS port")
        }
        guard !password.isEmpty else {
            throw BackupError.decodeFailed("wdtt:// link is missing the tunnel password")
        }
        guard !firstHash.isEmpty else {
            throw BackupError.decodeFailed("wdtt:// link is missing the VK hash")
        }

        let settings = ConnectionSettings(
            privateKey: nil, peerPublicKey: nil, presharedKey: nil,
            tunnelAddress: nil, allowedIPs: nil,
            vkLink: "https://vk.com/call/join/" + firstHash,
            peerAddress: "\(ip):\(dtlsPort)",
            useDTLS: nil, useWrap: nil, wrapKeyHex: nil,
            useSrtp: nil, useUDP: nil,
            useWrapA: true, wrapAPassword: password,
            turnServerOverride: nil,
            dnsServers: nil, numConnections: nil
        )
        return ConnectionLink(version: supportedConfigVersion, type: "connection", settings: settings)
    }

    /// Strips a VK call/join URL prefix (+ any query/fragment) from a hash,
    /// canonicalising to the bare token. Mirrors amurcanov's stripVkUrlStatic;
    /// also tolerates our own vk.me/join/ form defensively. amurcanov's server
    /// already emits bare hashes, so this is belt-and-suspenders.
    private static func stripVkUrl(_ input: String) -> String {
        var s = input.trimmingCharacters(in: .whitespaces)
        let prefixes = [
            "https://vk.com/call/join/", "http://vk.com/call/join/",
            "https://m.vk.com/call/join/", "http://m.vk.com/call/join/",
            "m.vk.com/call/join/", "vk.com/call/join/",
            "https://vk.me/join/", "http://vk.me/join/", "vk.me/join/"
        ]
        let lower = s.lowercased()
        for p in prefixes where lower.hasPrefix(p) {
            s = String(s.dropFirst(p.count))
            break
        }
        if let q = s.firstIndex(of: "?") { s = String(s[..<q]) }
        if let h = s.firstIndex(of: "#") { s = String(s[..<h]) }
        return s.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
    }

    // MARK: - samosvalishe free-turn-proxy freeturn:// compat link

    /// Parses a samosvalishe `freeturn://<base64url(json)>` link into our
    /// ConnectionLink (SRTP-WRAP-S mode). Verified against free-turn-proxy
    /// internal/uri/uri.go: the body after `freeturn://` is a base64url
    /// (RawURLEncoding — url-safe, NO padding) JSON object.
    ///
    /// We map ONLY the fields that have an equivalent in our app:
    ///   peer→peerAddress, transport(tcp|udp)→useUDP, obf→obfProfile,
    ///   key→wrapKeyHex, n→numConnections, cid→clientID, dnss→dnsServers.
    /// Every other field (provider, mode, bond, spc, listen, dns, mcap, name)
    /// is intentionally ignored. Importing always switches to SRTP-WRAP-S.
    ///
    /// The link carries NEITHER a VK call link NOR WireGuard keys (free-turn
    /// passes the VK -link + WG config as separate CLI flags, not in the URI),
    /// so those stay untouched: WG keys via nil-preserve, and vkLink by passing
    /// the device's current value straight back through (applyConnectionLink
    /// writes vkLink unconditionally). The user still fills WG keys + the VK
    /// call link in by hand after import.
    static func parseFreeturnLink(_ raw: String) throws -> ConnectionLink {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("freeturn://") else {
            throw BackupError.decodeFailed("URL scheme is not freeturn://")
        }
        var body = String(trimmed.dropFirst("freeturn://".count))
        // .onOpenURL can hand back an authority-only URL with a trailing slash.
        while body.hasSuffix("/") { body = String(body.dropLast()) }
        guard !body.isEmpty else {
            throw BackupError.decodeFailed("freeturn:// link has an empty payload")
        }
        // base64url (RawURLEncoding) → standard base64 with padding, then decode.
        var b64 = body.replacingOccurrences(of: "-", with: "+")
                      .replacingOccurrences(of: "_", with: "/")
        let padNeeded = (4 - b64.count % 4) % 4
        b64 += String(repeating: "=", count: padNeeded)
        guard let data = Data(base64Encoded: b64),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw BackupError.decodeFailed("freeturn:// link payload is not valid base64url JSON")
        }

        // Version gate — free-turn's currentVersion == 1.
        if let v = obj["v"] as? Int, v != 1 {
            throw BackupError.decodeFailed("Unsupported freeturn:// version \(v) (expected 1)")
        }

        // peer (host:port) → peerAddress. free-turn marks -peer mandatory.
        let peer = (obj["peer"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        guard !peer.isEmpty else {
            throw BackupError.decodeFailed("freeturn:// link is missing the peer (server) address")
        }

        // transport (tcp|udp to the TURN relay) → useUDP. Absent = nil-preserve.
        var useUDP: Bool? = nil
        switch (obj["transport"] as? String)?.lowercased() {
        case "udp": useUDP = true
        case "tcp": useUDP = false
        default: break
        }

        // obf → obfProfile. Only our three known profiles map; "none"/absent/
        // anything else leaves the device's current profile in place.
        var obfProfile: String? = nil
        if let o = (obj["obf"] as? String)?.lowercased(),
           o == "rtpopus" || o == "rtpopus2" || o == "rtpopus3" {
            obfProfile = o
        }

        // key (hex obf key) → wrapKeyHex. Absent = nil-preserve.
        var wrapKeyHex: String? = nil
        if let k = (obj["key"] as? String)?.trimmingCharacters(in: .whitespaces), !k.isEmpty {
            wrapKeyHex = k
        }

        // n (parallel TURN streams) → numConnections. Absent/≤0 = nil-preserve.
        var numConnections: Int? = nil
        if let n = obj["n"] as? Int, n > 0 { numConnections = n }

        // cid (client id) → clientID. Absent = nil-preserve.
        var clientID: String? = nil
        if let c = (obj["cid"] as? String)?.trimmingCharacters(in: .whitespaces), !c.isEmpty {
            clientID = c
        }

        // dnss (comma-separated DNS servers) → dnsServers. Absent = nil-preserve.
        var dnsServers: String? = nil
        if let dns = (obj["dnss"] as? String)?.trimmingCharacters(in: .whitespaces), !dns.isEmpty {
            dnsServers = dns
        }

        // vkLink is non-Optional and written unconditionally by
        // applyConnectionLink; the link has none, so pass the device's current
        // value straight back through → the apply is a no-op for it (preserve).
        let currentVkLink = UserDefaults.standard.string(forKey: "vkLink") ?? ""

        let settings = ConnectionSettings(
            privateKey: nil, peerPublicKey: nil, presharedKey: nil,
            tunnelAddress: nil, allowedIPs: nil,
            vkLink: currentVkLink,
            peerAddress: peer,
            useDTLS: nil, useWrap: nil, wrapKeyHex: wrapKeyHex,
            useSrtp: nil, useUDP: useUDP,
            useWrapA: nil, wrapAPassword: nil,
            turnServerOverride: nil,
            dnsServers: dnsServers, numConnections: numConnections,
            useWrapS: true, obfProfile: obfProfile, clientID: clientID
        )
        return ConnectionLink(version: supportedConfigVersion, type: "connection", settings: settings)
    }

    /// Applies the ConnectionLink to UserDefaults. Does NOT touch
    /// creds-pool.json or vk_profile.json — those belong to the
    /// receiving device and rebuild themselves on first connect after
    /// the new settings take effect. Optional fields (dnsServers,
    /// numConnections) only overwrite when present in the link;
    /// absent values preserve whatever the device already had.
    static func applyConnectionLink(_ link: ConnectionLink) {
        let d = UserDefaults.standard
        let s = link.settings
        // privateKey/peerPublicKey/tunnelAddress/allowedIPs Optional since
        // 2026-06-03 (a WRAP-A link omits them; the server provisions WG via
        // GETCONF). Nil-preserves-default keeps the device's existing keys.
        if let v = s.privateKey { d.set(v, forKey: "privateKey") }
        if let v = s.peerPublicKey { d.set(v, forKey: "peerPublicKey") }
        // presharedKey made Optional in build 134 — WG PSK is optional in
        // the protocol; deployments without one omit the field entirely
        // (quick_link.py does that automatically). Nil-preserves-default
        // keeps the device's current PSK alone when absent. Non-nil writes
        // through, including empty string if explicitly set.
        if let v = s.presharedKey { d.set(v, forKey: "presharedKey") }
        if let v = s.tunnelAddress { d.set(v, forKey: "tunnelAddress") }
        if let v = s.allowedIPs { d.set(v, forKey: "allowedIPs") }
        d.set(s.vkLink, forKey: "vkLink")
        d.set(s.peerAddress, forKey: "peerAddress")
        // useDTLS/useWrap/wrapKeyHex made Optional in build 129 — UI
        // toggles for both are gone, so links generated by quick_link.py
        // after the corresponding update will typically omit these.
        // Nil-preserves-default matches the useSrtp/useUDP pattern below.
        // Older quick_link.py-generated links that still carry these
        // fields apply them through unchanged.
        if let v = s.useDTLS { d.set(v, forKey: "useDTLS") }
        if let v = s.wrapKeyHex { d.set(v, forKey: "wrapKeyHex") }
        // Server-mode triple (useWrapA / useSrtp / useWrap) encodes ONE enum
        // with precedence useWrapA > useSrtp > useWrap (see ServerMode +
        // serverModeBinding). It MUST be applied as a COUPLED set, not as three
        // independent nil-preserve writes — otherwise a stale flag survives: a
        // link with useSrtp:true but no useWrapA could NOT switch a device OUT
        // of SRTP-WRAP-A, because the leftover useWrapA=true keeps winning the
        // precedence (bug observed 2026-06-10). So if the link specifies ANY of
        // the three, resolve its intended mode and write all three explicitly
        // (mutual exclusion). A link carrying none of them keeps the current mode.
        if s.useWrapS != nil || s.useWrapA != nil || s.useSrtp != nil || s.useWrap != nil {
            let wrapS = s.useWrapS ?? false
            let wrapA = s.useWrapA ?? false
            let srtp  = s.useSrtp ?? false
            let wrap  = s.useWrap ?? false
            // Precedence matches serverModeBinding: useWrapS > useWrapA > useSrtp > useWrap.
            d.set(wrapS, forKey: "useWrapS")
            d.set(!wrapS && wrapA, forKey: "useWrapA")
            d.set(!wrapS && !wrapA && srtp, forKey: "useSrtp")
            d.set(!wrapS && !wrapA && !srtp && wrap, forKey: "useWrap")
        }
        // useUDP optional in ConnectionSettings (added build 128): nil keeps
        // the device's current value (default false / TCP).
        if let v = s.useUDP { d.set(v, forKey: "useUDP") }
        // wrapAPassword: nil-preserve (only meaningful in WRAP-A mode).
        if let v = s.wrapAPassword { d.set(v, forKey: "wrapAPassword") }
        // SRTP-WRAP-S: obf profile + Client-ID nil-preserve (wrapKeyHex above).
        if let v = s.obfProfile { d.set(v, forKey: "obfProfile") }
        if let v = s.clientID { d.set(v, forKey: "clientID") }
        if let v = s.turnServerOverride { d.set(v, forKey: "turnServerOverride") }
        if let v = s.dnsServers { d.set(v, forKey: "dnsServers") }
        if let v = s.numConnections { d.set(v, forKey: "numConnections") }
        if let v = s.vkAuth { d.set(v, forKey: "VKAuth") }
        // Log the RESOLVED server mode (read back after applying) — that's the
        // field whose stale value caused the 2026-06-10 import bug, so it's the
        // useful thing to see in triage.
        let nc = s.numConnections.map(String.init) ?? "(kept default)"
        let dn = s.dnsServers ?? "(kept default)"
        let mode = d.bool(forKey: "useWrapS") ? "SRTP-WRAP-S"
                 : d.bool(forKey: "useWrapA") ? "SRTP-WRAP-A"
                 : d.bool(forKey: "useSrtp")  ? "SRTP"
                 : d.bool(forKey: "useWrap")  ? "SRTP+WRAP" : "legacy"
        SharedLogger.shared.log("[AppDebug] Backup: applied connection link (peer=\(s.peerAddress), mode=\(mode), numConnections=\(nc), dnsServers=\(dn))")
    }
}
