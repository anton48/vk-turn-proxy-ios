// ProxyConfigRedaction.swift
//
// The proxy config as it may appear in vpn.log. The extension logs the whole
// proxy_config at startTunnel — that line is what users send us — and the
// config carries SECRETS: csqtt's password (the tunnel's only key; there is no
// key exchange on that transport), WRAP-A's password, the WRAP/SRTP wrap key
// and the seeded VK TURN credential's password.
//
// 🚨 STRUCTURAL, NOT TEXTUAL. The first redaction (build 355) was a regular
// expression over the serialized text — `"csqtt_password":"[^"]*"` — and JSON
// writes a quote inside a string as `\"`, so a password that contained one
// ended the match early and the rest of it went to the log verbatim (found by
// the user 2026-09-07: `"SECRET_AFTER_QUOTE` came out as
// `"…"SECRET_AFTER_QUOTE"`). Every pattern over the text has this class of
// hole; parsing the JSON and masking by KEY does not — the value's bytes are
// never inspected, whatever they contain.
//
// The failure mode is "log nothing", never "log the text": input that does not
// parse as a JSON object is replaced by a placeholder that carries none of it.
//
// Foundation only, no NetworkExtension: the extension has no test target, so
// tools/swiftcheck compiles THIS file and runs the redaction on real encodings
// (a quote, a backslash, ", a nested seeded_turn, truncated input).

import Foundation

enum ProxyConfigRedaction {
    /// Keys whose values are secrets, matched at ANY depth of the config.
    /// `password` covers seeded_turn.password (the VK TURN credential).
    static let secretKeys: Set<String> = ["csqtt_password", "wrap_a_password", "wrap_key_hex", "password"]

    /// What a masked value reads as. An EMPTY string stays empty: it is not a
    /// secret, and "the password was empty" is the diagnostic the line exists
    /// for (csqttStart refuses with -2 on exactly that).
    static let mask = "…"

    /// The config with every secret masked and the keys sorted (one stable
    /// line to grep across logs), or a placeholder when the input is not a
    /// JSON object — never the input itself.
    static func redacted(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data),
              let dict = parsed as? [String: Any],
              let out = try? JSONSerialization.data(withJSONObject: masked(dict), options: [.sortedKeys]),
              let text = String(data: out, encoding: .utf8) else {
            return "<proxy config not logged: not a JSON object, \(json.utf8.count) bytes>"
        }
        return text
    }

    private static func masked(_ dict: [String: Any]) -> [String: Any] {
        var out = dict
        for (key, value) in dict {
            out[key] = masked(key: key, value: value)
        }
        return out
    }

    private static func masked(key: String, value: Any) -> Any {
        if secretKeys.contains(key) {
            if let s = value as? String, s.isEmpty { return s }
            return mask
        }
        if let inner = value as? [String: Any] {
            return masked(inner)
        }
        if let list = value as? [Any] {
            return list.map { element -> Any in
                if let inner = element as? [String: Any] { return masked(inner) }
                return element
            }
        }
        return value
    }
}
