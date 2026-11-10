import Foundation
import CryptoKit

/// A csqtt 2.5 connection link: `csqtt://` + base64url( IV(12) ‖ AES-256-GCM )
/// of the SAME query the plain 2.1.9 link carries in the open —
/// `connect?v=2&host=…&peer=…&password=…[&hashes=a+b…|&token=…]`. The key is
/// the SHA-256 of a seed every csqtt app carries: obfuscation, not secrecy.
///
/// So the FORMAT of a csqtt:// link says which protocol its server speaks: a
/// body that decrypts is a 2.5 link, a plain one is 2.1.9's (the importer sets
/// the server's generation from it — a server answers the wrong protocol with
/// silence, and nothing could correct the choice at Connect).
///
/// Foundation and CryptoKit only, so that swiftcheck RUNS it on vectors made
/// by the Go implementation (pkg/csqtt25/link.go, itself pinned to the
/// reference app's published vector): two decoders of one format are compared
/// on the format, not on each other's source.
enum Csqtt25Link {
    struct Fields: Equatable {
        var host: String
        var port: Int
        var password: String
        /// Bare VK call hashes, when the link carries them. A link may carry
        /// a VK access token instead: this app has no use for one, and the
        /// decoder does not read it — such a link brings no call link.
        var hashes: [String]
    }

    private static let scheme = "csqtt://"
    private static let keySeed = "csqtt-chiper-key"

    /// The link's fields, or nil when `raw` is not a 2.5 link — a plain
    /// csqtt:// link, a damaged one, or one that decrypts to something else
    /// than the connect query.
    static func decode(_ raw: String) -> Fields? {
        guard let plain = decrypt(raw) else { return nil }
        return parse(plain)
    }

    /// The decrypted query, or nil. The body may be base64 in either alphabet,
    /// padded or not (the reference writes url-safe, unpadded). What decides
    /// is the tag: a body that authenticates under the link key is the link.
    static func decrypt(_ raw: String) -> String? {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.prefix(scheme.count).lowercased() == scheme else { return nil }
        var b64 = String(t.dropFirst(scheme.count)).filter { !$0.isWhitespace }
        b64 = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        // A blob too short for the IV(12) and the tag(16) is refused by the box.
        guard let blob = Data(base64Encoded: b64) else { return nil }
        let key = SymmetricKey(data: Data(SHA256.hash(data: Data(keySeed.utf8))))
        guard let box = try? AES.GCM.SealedBox(combined: blob),
              let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return String(data: plain, encoding: .utf8)
    }

    /// Parses the decrypted query as the Go side does: everything behind the
    /// first `?`, `&`-separated, each value percent-decoded with `+` LEFT ALONE
    /// (in this query a `+` separates the hashes and is never a space — which
    /// is why this is not URLComponents: a raw `&`, `%` or space in a password
    /// the reference wrote unescaped must not fail the whole link either).
    static func parse(_ plain: String) -> Fields? {
        var q = Substring(plain)
        if let i = q.firstIndex(of: "?") { q = q[q.index(after: i)...] }
        var f: [String: String] = [:]
        for kv in q.split(separator: "&", omittingEmptySubsequences: false) {
            guard let eq = kv.firstIndex(of: "=") else { continue }
            guard let v = String(kv[kv.index(after: eq)...]).removingPercentEncoding else { return nil }
            f[String(kv[..<eq])] = v
        }
        guard f["v"] == "2", let host = f["host"], !host.isEmpty,
              let port = Int(f["peer"] ?? ""), (1...65535).contains(port) else { return nil }
        let hashes = (f["hashes"] ?? "").isEmpty ? [] : (f["hashes"] ?? "").components(separatedBy: "+")
        return Fields(host: host, port: port,
                      password: (f["password"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                      hashes: hashes)
    }
}
