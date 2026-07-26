import Foundation
import Security

/// VKCookieStore — Keychain-backed storage for the logged-in VK session cookie
/// used by the non-anonymous "VKAuth" cred path (see pkg/proxy/creds_vkcookie.go).
///
/// Stored in a SHARED keychain access group so BOTH the main app (Settings
/// login + pre-bootstrap probe) and the PacketTunnel extension (startTunnel)
/// can read it. A cookie is a credential, so it lives in the Keychain
/// (encrypted) — NEVER in UserDefaults, the backup JSON, or the VPN
/// providerConfiguration.
///
/// What's stored: the raw `Cookie:` header we send to VK ("remixsid=…; p=…")
/// plus the pair's expiry (the min of the harvested cookies' expiresDate). When
/// the cookie is past expiry — or VK rejects it server-side — the app
/// re-harvests via the WKWebView login (VKAuthWebView). The toggle that turns
/// VKAuth on/off is a separate UserDefaults flag ("VKAuth"); disabling it does
/// NOT delete the cookie — only `delete()` (the Settings button / sign-out) does.
enum VKCookieStore {
    /// Shared keychain access group. MUST match the `keychain-access-groups`
    /// entitlement (`$(AppIdentifierPrefix)com.vkturnproxy.shared`) in BOTH
    /// VKTurnProxy.entitlements and PacketTunnel.entitlements. There,
    /// `$(AppIdentifierPrefix)` expands at build time to the team id + "." —
    /// i.e. "CDMQ33VFQC." (DEVELOPMENT_TEAM in project.yml) — so the
    /// fully-qualified group below must stay in sync if the team ever changes.
    private static let canonicalAccessGroup = "CDMQ33VFQC.com.vkturnproxy.shared"

    /// The group to scope the item to, or **nil to use this process's default
    /// group** — resolved once, from the entitlements the build was actually
    /// signed with.
    ///
    /// Naming a group we are not entitled to makes every SecItem call fail with
    /// `errSecMissingEntitlement` (-34018), and that is precisely what happens
    /// on a third-party re-signed IPA: the signer replaces our
    /// `keychain-access-groups` with its own (`4FN8R4RQZT.*`, …), so VKAuth
    /// could never store or read the cookie there. Omitting the attribute puts
    /// the item in the process default instead — and because such a re-signer
    /// stamps BYTE-IDENTICAL entitlements onto the app and the appex (verified
    /// 2026-07-25), both processes resolve the same default and can still share
    /// it, which is all VKAuth needs.
    ///
    /// A correctly signed build is unaffected: it IS entitled, so it keeps
    /// naming the group explicitly, exactly as before. If the entitlements
    /// cannot be read at all we also keep today's behaviour rather than guess.
    private static let accessGroup: String? = {
        let e = AppEntitlements.current
        if e.error != nil { return canonicalAccessGroup }
        if e.keychainAccessGroups.contains(canonicalAccessGroup) { return canonicalAccessGroup }
        SharedLogger.logDiagnostic(
            "keychain group \(canonicalAccessGroup) is not entitled to this build "
          + "(entitled: \(e.keychainAccessGroups.joined(separator: ", "))) — "
          + "storing the VK cookie in the process default group instead.",
            category: "Keychain")
        return nil
    }()

    private static let service = "com.vkturnproxy.vkauth"
    private static let account = "cookie"

    /// The persisted record.
    struct Stored: Codable {
        let cookieHeader: String
        let expiry: Date
        let savedAt: Date
    }

    /// Save (upsert) the cookie header + expiry. Overwrites any existing item.
    /// Returns false if the Keychain write fails.
    @discardableResult
    static func save(cookieHeader: String, expiry: Date) -> Bool {
        let stored = Stored(cookieHeader: cookieHeader, expiry: expiry, savedAt: Date())
        guard let data = try? JSONEncoder().encode(stored) else { return false }

        // Delete-then-add is the simplest correct upsert (avoids attribute-merge
        // surprises across iOS versions).
        SecItemDelete(baseQuery() as CFDictionary)

        var add = baseQuery()
        add[kSecValueData as String] = data
        // AfterFirstUnlock (NOT WhenUnlocked): the extension must read this in
        // the background, possibly while the screen is locked, after the user
        // has unlocked the device at least once since boot.
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(add as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Load the stored cookie, or nil if absent / unreadable.
    static func load() -> Stored? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else { return nil }
        return try? JSONDecoder().decode(Stored.self, from: data)
    }

    /// Delete the stored cookie (the "Delete saved cookies" button / sign-out).
    @discardableResult
    static func delete() -> Bool {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// True when a cookie is stored AND not past its expiry.
    static func isValid(now: Date = Date()) -> Bool {
        guard let s = load() else { return false }
        return s.expiry > now
    }

    /// The Cookie header to send, only when currently (locally) valid; else nil.
    static func validCookieHeader(now: Date = Date()) -> String? {
        guard let s = load(), s.expiry > now else { return nil }
        return s.cookieHeader
    }

    private static func baseQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // Absent (not empty) when we aren't entitled to the group — see
        // `accessGroup`. An empty string here would NOT mean "default", it
        // would name a group nobody has.
        if let group = accessGroup {
            q[kSecAttrAccessGroup as String] = group
        }
        return q
    }
}
