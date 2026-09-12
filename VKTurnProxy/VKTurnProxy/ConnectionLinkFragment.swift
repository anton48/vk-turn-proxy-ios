// ConnectionLinkFragment.swift
//
// The `#fragment` of a wdtt:// or csqtt:// connection link, read as the NAME
// of the server the import creates — the vless-style "remark" (GitHub #81).
// Neither scheme defines a fragment; people append one by hand to a link they
// hand out ("…#🇩🇪 Germany-1") so the recipient's server list reads well.
//
// Foundation only, no app types: tools/swiftcheck compiles and RUNS it against
// fixtures. The per-scheme decision of WHERE the `#` may sit (after the hash
// list of a wdtt:// link, after host:port of a legacy csqtt:// link, at the
// end of the connect form) stays in BackupManager beside each parser; this
// file only cuts and cleans. `clean` is also the rule for a name that arrives
// in a freeturn:// link's JSON `name` field — one rule for every imported name.

import Foundation

enum ConnectionLinkFragment {
    /// A server name longer than this is cut — the main screen and the card
    /// show the name in one line; SharedLogger uses the same bound for an SSID.
    static let maxLength = 64

    /// Splits `s` at the FIRST `#`: (the text before it, the text after it or
    /// nil when there is no `#`). A `#` inside the fragment itself is kept.
    static func split(_ s: String) -> (String, String?) {
        guard let h = s.firstIndex(of: "#") else { return (s, nil) }
        return (String(s[..<h]), String(s[s.index(after: h)...]))
    }

    /// The server name a fragment yields: percent-decoded when that decodes
    /// (a TAPPED link reaches .onOpenURL percent-encoded, a PASTED one is raw;
    /// a `%` that is not an escape — "100% VPN" — is kept as typed; a pasted
    /// name that happens to contain a valid escape is decoded too — accepted,
    /// the two paths cannot be told apart here), then `clean`ed.
    static func serverName(from fragment: String?) -> String? {
        guard var s = fragment else { return nil }
        if s.contains("%"), let decoded = s.removingPercentEncoding { s = decoded }
        return clean(s)
    }

    /// The one cleaning rule for an imported server name: control characters,
    /// Unicode format characters (bidi overrides and isolates — a name must
    /// not read reversed) and line/paragraph separators removed (a name is
    /// persisted, shown on one line and logged; the ASCII half is the same
    /// rule as BackupManager.stripControlChars), the zero-width joiner kept
    /// (it is what holds a composite emoji together), surrounding whitespace
    /// trimmed, cut at maxLength characters. nil when nothing is left, which
    /// keeps the old behaviour: ServerStore assigns the next free "ServerN".
    static func clean(_ raw: String) -> String? {
        var scalars = String.UnicodeScalarView()
        scalars.append(contentsOf: raw.unicodeScalars.filter(keeps))
        var s = String(scalars).trimmingCharacters(in: .whitespacesAndNewlines)
        if s.count > maxLength {
            s = String(s.prefix(maxLength)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return s.isEmpty ? nil : s
    }

    private static func keeps(_ u: Unicode.Scalar) -> Bool {
        if u.value < 0x20 || u.value == 0x7f { return false }
        switch u.properties.generalCategory {
        case .control, .lineSeparator, .paragraphSeparator:
            return false
        case .format:
            return u.value == 0x200D   // ZERO WIDTH JOINER: 🏳️‍🌈, 👨‍👩‍👧
        default:
            return true
        }
    }
}
