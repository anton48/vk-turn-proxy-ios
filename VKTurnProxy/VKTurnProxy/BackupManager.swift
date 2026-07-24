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
        // Globals (not per-server). Everything else now lives in `servers`.
        let vkLink = d.string(forKey: "vkLink") ?? ""
        let vkAuth = (d.object(forKey: "VKAuth") as? Bool) ?? false
        // Named servers (build 179+). The legacy flat per-server fields are
        // deliberately NOT written alongside them — a backup from this build is
        // not meant to be readable by 178 and earlier.
        let store = ServerStore.shared
        let servers = store.servers.map { ServerSettings($0) }
        let activeServer = store.activeServer.serverName
        let settings = AppSettings(
            vkLink: vkLink,
            servers: servers,
            activeServer: activeServer,
            useWrap: nil,
            wrapKeyHex: nil,
            useSrtp: nil,
            useUDP: nil,
            useWrapA: nil,
            wrapAPassword: nil,
            turnServerOverride: nil,
            vkAuth: vkAuth
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

        // GLOBAL settings first — they apply to both backup shapes.
        d.set(s.vkLink, forKey: "vkLink")
        // forceLegacyCaptcha: undocumented on-device captcha-test toggle
        // (build 149) — nil-preserves-default pattern.
        if let v = s.forceLegacyCaptcha { d.set(v, forKey: "forceLegacyCaptcha") }
        if let v = s.vkAuth { d.set(v, forKey: "VKAuth") }

        if let backedUpServers = s.servers, !backedUpServers.isEmpty {
            // Build 179+ backup: the named server sets ARE the configuration.
            // replaceAll projects the active one onto the flat keys.
            ServerStore.shared.replaceAll(backedUpServers.map { $0.profile },
                                          activeName: s.activeServer)
        } else {
            // Pre-179 backup: one flat configuration. Write it to the flat keys
            // exactly as before, then capture it as the single "Server1".
            // nil → leave the key alone so the @AppStorage default applies,
            // matching how older builds tolerated absent fields.
            if let v = s.privateKey { d.set(v, forKey: "privateKey") }
            if let v = s.peerPublicKey { d.set(v, forKey: "peerPublicKey") }
            if let v = s.presharedKey { d.set(v, forKey: "presharedKey") }
            if let v = s.tunnelAddress { d.set(stripControlChars(v), forKey: "tunnelAddress") }
            if let v = s.dnsServers { d.set(v, forKey: "dnsServers") }
            if let v = s.allowedIPs { d.set(stripControlChars(v), forKey: "allowedIPs") }
            if let v = s.peerAddress { d.set(stripControlChars(v), forKey: "peerAddress") }
            if let v = s.useDTLS { d.set(v, forKey: "useDTLS") }
            if let v = s.numConnections { d.set(v, forKey: "numConnections") }
            if let v = s.credPoolCooldownSeconds { d.set(v, forKey: "credPoolCooldownSeconds") }
            if let v = s.useWrap { d.set(v, forKey: "useWrap") }
            if let v = s.wrapKeyHex { d.set(v, forKey: "wrapKeyHex") }
            if let v = s.useSrtp { d.set(v, forKey: "useSrtp") }
            if let v = s.useUDP { d.set(v, forKey: "useUDP") }
            if let v = s.useWrapA { d.set(v, forKey: "useWrapA") }
            if let v = s.wrapAPassword { d.set(v, forKey: "wrapAPassword") }
            if let v = s.useWrapS { d.set(v, forKey: "useWrapS") }
            if let v = s.obfProfile { d.set(v, forKey: "obfProfile") }
            if let v = s.clientID { d.set(v, forKey: "clientID") }
            if let v = s.turnServerOverride { d.set(v, forKey: "turnServerOverride") }
            ServerStore.shared.resetFromFlatKeys()
        }

        SharedLogger.shared.log("[AppDebug] Backup: applied settings (servers=\(s.servers?.count ?? 0), vkAuth=\(s.vkAuth ?? false))")

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
            // VK domain migration (vk.com -> vk.ru): accept BOTH so a link the
            // user already has (vk.com) AND a new vk.ru link both strip to the
            // bare hash. Do NOT drop the vk.com forms — VK still emits them today.
            "https://vk.ru/call/join/", "http://vk.ru/call/join/",
            "https://m.vk.ru/call/join/", "http://m.vk.ru/call/join/",
            "m.vk.ru/call/join/", "vk.ru/call/join/",
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

        // name → serverName. free-turn's own links carry a human label; absent
        // → ServerStore assigns the next free "ServerN".
        var serverName: String? = nil
        if let n = (obj["name"] as? String)?.trimmingCharacters(in: .whitespaces), !n.isEmpty {
            serverName = n
        }

        // vkLink is non-Optional and a freeturn:// link carries no call data, so
        // pass the device's current value straight back through → the global
        // vkLink is left untouched on import (preserve).
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
            useWrapS: true, obfProfile: obfProfile, clientID: clientID,
            serverName: serverName
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

        // Build 179+: a link ADDS a named server and makes it active instead of
        // overwriting the single configuration. Only the GLOBAL settings are
        // written here; everything per-server goes into the new profile.
        //
        // vkLink (call data) is global: vkturnproxy:// and wdtt:// carry it,
        // freeturn:// does not (its parser passes the device's current value
        // straight back, so writing it is a no-op). Empty → don't clobber.
        if !s.vkLink.isEmpty { d.set(s.vkLink, forKey: "vkLink") }
        if let v = s.vkAuth { d.set(v, forKey: "VKAuth") }

        let created = ServerStore.shared.addAndActivate(ServerProfile(link: s))
        SharedLogger.shared.log("[AppDebug] Backup: connection link imported as new server \"\(created.serverName)\" [\(created.modeLabel)] (peer=\(stripControlChars(created.peerAddress)), numConnections=\(created.numConnections), dnsServers=\(created.dnsServers))")
    }

    /// Strip ASCII control characters (CR/LF/etc.) from an imported free-form
    /// field before it is persisted or logged. Prevents a malicious connection
    /// link / backup from injecting wireguard-go UAPI directives (via
    /// peerAddress / allowedIPs / tunnelAddress → buildUAPIConfig) or forging
    /// vpn.log lines.
    static func stripControlChars(_ s: String) -> String {
        return s.filter { ch in
            !ch.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7f }
        }
    }
}
