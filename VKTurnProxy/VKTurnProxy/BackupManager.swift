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
        let settings = AppSettings(
            privateKey: d.string(forKey: "privateKey") ?? "",
            peerPublicKey: d.string(forKey: "peerPublicKey") ?? "",
            presharedKey: d.string(forKey: "presharedKey") ?? "",
            // Default values must match SettingsView's AppStorage defaults
            // — UserDefaults.string(forKey:) returns nil for unset keys
            // (unlike @AppStorage which returns the default). Using the
            // same defaults here ensures the export captures the in-app
            // state even if the user never opened Settings.
            tunnelAddress: d.string(forKey: "tunnelAddress") ?? "192.168.102.3/24",
            dnsServers: d.string(forKey: "dnsServers") ?? "1.1.1.1",
            allowedIPs: d.string(forKey: "allowedIPs") ?? "0.0.0.0/0",
            vkLink: d.string(forKey: "vkLink") ?? "",
            peerAddress: d.string(forKey: "peerAddress") ?? "",
            // Bool defaults: UserDefaults.bool(forKey:) returns false for
            // unset, but useDTLS defaults to true in @AppStorage. Use
            // object(forKey:) to distinguish "set to false" from "unset".
            useDTLS: (d.object(forKey: "useDTLS") as? Bool) ?? true,
            numConnections: (d.object(forKey: "numConnections") as? Int) ?? 30,
            credPoolCooldownSeconds: (d.object(forKey: "credPoolCooldownSeconds") as? Int) ?? 150,
            // WRAP defaults match SettingsView's @AppStorage defaults
            // (false / empty). Same object(forKey:) trick as useDTLS to
            // distinguish "explicitly set false" from "never set" — though
            // for a default of false the difference is invisible, the
            // pattern stays consistent with surrounding code.
            useWrap: (d.object(forKey: "useWrap") as? Bool) ?? false,
            wrapKeyHex: d.string(forKey: "wrapKeyHex") ?? "",
            useSrtp: (d.object(forKey: "useSrtp") as? Bool) ?? false,
            // useUDP default false matches SettingsView's @AppStorage
            // default — TCP-control was made default in build 109 to
            // bypass VK's per-cred allocation-rate throttle.
            useUDP: (d.object(forKey: "useUDP") as? Bool) ?? false
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

    /// Applies the ConnectionLink to UserDefaults. Does NOT touch
    /// creds-pool.json or vk_profile.json — those belong to the
    /// receiving device and rebuild themselves on first connect after
    /// the new settings take effect. Optional fields (dnsServers,
    /// numConnections) only overwrite when present in the link;
    /// absent values preserve whatever the device already had.
    static func applyConnectionLink(_ link: ConnectionLink) {
        let d = UserDefaults.standard
        let s = link.settings
        d.set(s.privateKey, forKey: "privateKey")
        d.set(s.peerPublicKey, forKey: "peerPublicKey")
        // presharedKey made Optional in build 134 — WG PSK is optional in
        // the protocol; deployments without one omit the field entirely
        // (quick_link.py does that automatically). Nil-preserves-default
        // keeps the device's current PSK alone when absent. Non-nil writes
        // through, including empty string if explicitly set.
        if let v = s.presharedKey { d.set(v, forKey: "presharedKey") }
        d.set(s.tunnelAddress, forKey: "tunnelAddress")
        d.set(s.allowedIPs, forKey: "allowedIPs")
        d.set(s.vkLink, forKey: "vkLink")
        d.set(s.peerAddress, forKey: "peerAddress")
        // useDTLS/useWrap/wrapKeyHex made Optional in build 129 — UI
        // toggles for both are gone, so links generated by quick_link.py
        // after the corresponding update will typically omit these.
        // Nil-preserves-default matches the useSrtp/useUDP pattern below.
        // Older quick_link.py-generated links that still carry these
        // fields apply them through unchanged.
        if let v = s.useDTLS { d.set(v, forKey: "useDTLS") }
        if let v = s.useWrap { d.set(v, forKey: "useWrap") }
        if let v = s.wrapKeyHex { d.set(v, forKey: "wrapKeyHex") }
        // useSrtp optional in ConnectionSettings (added 2026-05-20): if
        // absent, keep whatever the device currently has (default false).
        if let v = s.useSrtp { d.set(v, forKey: "useSrtp") }
        // useUDP optional in ConnectionSettings (added build 128): same
        // keep-current-on-absent semantics as useSrtp.
        if let v = s.useUDP { d.set(v, forKey: "useUDP") }
        if let v = s.dnsServers { d.set(v, forKey: "dnsServers") }
        if let v = s.numConnections { d.set(v, forKey: "numConnections") }
        // Truncate vkLink and peerAddress in the log so we don't dump
        // long token URLs into a file the user might share for triage.
        let nc = s.numConnections.map(String.init) ?? "(kept default)"
        let dn = s.dnsServers ?? "(kept default)"
        let dtlsStr = s.useDTLS.map(String.init(describing:)) ?? "(kept default)"
        let wrapStr = s.useWrap.map(String.init(describing:)) ?? "(kept default)"
        SharedLogger.shared.log("[AppDebug] Backup: applied connection link (peer=\(s.peerAddress), useDTLS=\(dtlsStr), useWrap=\(wrapStr), numConnections=\(nc), dnsServers=\(dn))")
    }
}
