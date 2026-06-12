// ConfigValidation.swift
//
// Field-level validation for the connection config, shared by SettingsView
// (inline hints under each field) and ContentView (the Connect-button gate)
// so the two never disagree on what "valid" means.
//
// Pure functions over the raw @AppStorage string values. Two severities:
//   .error   (red)    — a REQUIRED field for the active server mode is empty
//                       or clearly invalid. ContentView blocks Connect on any
//                       .error for the active mode.
//   .warning (orange) — an optional field set to something malformed, or a
//                       value whose format doesn't look right. Informational
//                       only; never blocks Connect.
//
// Deliberately lenient where a strict check could reject a valid-but-unusual
// input: hosts may be IP or hostname (only the port is checked), IPv6 literals
// are accepted loosely (any token containing ":"), and format-shape issues are
// warnings, not errors. The only hard (.error) checks are emptiness of a
// required field, a numeric in-range port, a base64 32-byte WireGuard key, and
// a 64-hex-char WRAP key.

import Foundation

enum ConfigValidation {
    enum Severity { case error, warning }

    struct Issue {
        let severity: Severity
        let message: String
        init(_ severity: Severity, _ message: String) {
            self.severity = severity
            self.message = message
        }
    }

    // MARK: - Primitive shape checks

    /// host:port with a non-empty host and an all-digit port in 1...65535.
    /// Host left lenient (IP or hostname). Splits on the LAST colon so an
    /// IPv4:port parses; a bare IPv6 without brackets won't pass (acceptable —
    /// the TURN/proxy endpoints here are IPv4/hostname in practice).
    static func isHostPort(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let colon = t.lastIndex(of: ":") else { return false }
        let host = String(t[..<colon])
        let port = String(t[t.index(after: colon)...])
        guard !host.isEmpty, !port.isEmpty, port.allSatisfy(\.isNumber),
              let p = Int(port), (1...65535).contains(p) else { return false }
        return true
    }

    /// base64 (standard or url-safe, padded or not) decoding to exactly 32
    /// bytes — a WireGuard Curve25519 key.
    static func isWgKey(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return false }
        var b64 = t.replacingOccurrences(of: "-", with: "+")
                   .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - b64.count % 4) % 4
        b64 += String(repeating: "=", count: pad)
        guard let d = Data(base64Encoded: b64) else { return false }
        return d.count == 32
    }

    /// Exactly 64 hex chars (32 bytes) — the WRAP key.
    static func isHex64(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.count == 64 && t.allSatisfy(\.isHexDigit)
    }

    /// Strict dotted-quad IPv4.
    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            !p.isEmpty && p.allSatisfy(\.isNumber) && (Int(p).map { (0...255).contains($0) } ?? false)
        }
    }

    /// Loose "looks like an IP": exact IPv4, or any token containing ":"
    /// (assumed IPv6 — we don't nag IPv6 users with a strict parser).
    static func looksLikeIP(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        return isIPv4(t) || t.contains(":")
    }

    /// Loose "looks like ip/prefix": IPv4-or-IPv6-ish host + numeric prefix 0...128.
    static func looksLikeCIDR(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let slash = t.lastIndex(of: "/") else { return false }
        let ip = String(t[..<slash])
        let pfx = String(t[t.index(after: slash)...])
        guard let n = Int(pfx), (0...128).contains(n) else { return false }
        return isIPv4(ip) || ip.contains(":")
    }

    // MARK: - Field validators (return the first issue, or nil if OK)

    static func vkLink(_ s: String) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return Issue(.error, "VK call link is required.") }
        let token = t.split(separator: "/").last.map(String.init) ?? ""
        if token.isEmpty || token == "REPLACE_ME" {
            return Issue(.warning, "Doesn't look like a VK call link / token.")
        }
        return nil
    }

    static func peerAddress(_ s: String) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return Issue(.error, "Proxy server is required (host:port).") }
        if !isHostPort(t) { return Issue(.error, "Must be host:port with a numeric port.") }
        return nil
    }

    /// Optional override. Empty = OK (use VK's relay). A non-empty value must be
    /// host:port, else a warning (the config layer silently ignores it).
    static func turnOverride(_ s: String) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return nil }
        if !isHostPort(t) {
            return Issue(.warning, "Not a valid IP:port — it will be ignored (VK's relay is used).")
        }
        return nil
    }

    /// Only meaningful in SRTP+WRAP mode.
    static func wrapKeyHex(_ s: String) -> Issue? {
        if !isHex64(s) { return Issue(.error, "WRAP key must be 64 hex characters (server -gen-wrap-key).") }
        return nil
    }

    /// Only meaningful in SRTP-WRAP-A mode.
    static func wrapAPassword(_ s: String) -> Issue? {
        if s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return Issue(.error, "Server password is required — derives the obfuscation key and authenticates GETCONF.")
        }
        return nil
    }

    /// WireGuard key field. `required` true → empty/invalid is an error;
    /// false (preshared key) → empty is OK, non-empty-invalid is a warning.
    static func wgKey(_ s: String, label: String, required: Bool) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty {
            return required ? Issue(.error, "\(label) is required (base64 32-byte key).") : nil
        }
        if !isWgKey(t) {
            return Issue(required ? .error : .warning, "\(label) must be a base64 32-byte WireGuard key.")
        }
        return nil
    }

    /// Required in non-WRAP-A modes. Empty is an error; a non-empty value that
    /// doesn't look like ip/prefix is a (non-blocking) warning.
    static func tunnelAddress(_ s: String) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return Issue(.error, "Tunnel address is required (e.g. 192.168.102.3/24).") }
        if !looksLikeCIDR(t) { return Issue(.warning, "Should look like ip/prefix (e.g. 192.168.102.3/24).") }
        return nil
    }

    static func dnsServers(_ s: String) -> Issue? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return nil }
        let parts = t.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
        if parts.contains(where: { !looksLikeIP($0) }) {
            return Issue(.warning, "Should be IP address(es), comma-separated (e.g. 1.1.1.1).")
        }
        return nil
    }

    // allowedIPs validator removed 2026-06-11 with the UI field — allowedIPs is
    // pinned to 0.0.0.0/0 (WireGuard cryptokey routing must be full under
    // includeAllNetworks=true) and is no longer user-editable, so there's
    // nothing to validate. looksLikeCIDR is still used by tunnelAddress above.
}
