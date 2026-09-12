// WireGuardConfText.swift
//
// A WireGuard / AmneziaWG client configuration in its textual (.conf, INI)
// form, reduced to what THIS app can use: the two keys, the optional preshared
// key, the tunnel address and the DNS list. Foundation only — tools/swiftcheck
// compiles and RUNS it against fixtures, one of them free-turn's relay.conf
// template verbatim.
//
// Where it comes from (GitHub #86): a samosvalishe/free-turn-proxy `freeturn://`
// link's `wg` field (their commit 9da2c8e, 2026-09-06). install.sh embeds the
// client's relay .conf verbatim (newlines JSON-escaped), and the template is an
// AmneziaWG 3.1 client conf: Jc/Jmin/Jmax, S1–S4, H1–H4, HeaderProtectionKey
// and the 3.1 extras under [Interface]. This app speaks PLAIN WireGuard
// (wireguard-go). The keys, the address and the DNS mean the same on both;
// the obfuscation parameters are not ours to honour, so they are REPORTED
// (`awgKeys`, `awgWireChanging`) for the confirmation text, never applied.
//
// Parsing follows wg(8)'s config reader where it matters for a hand-edited
// conf: a `#` starts a comment ANYWHERE on a line (wireguard-tools config.c
// cuts at the first COMMENT_CHAR), keys and section names are case-insensitive,
// a repeated PrivateKey/PublicKey OVERWRITES (last wins, as wg does), while
// Address/DNS lines ACCUMULATE (as wg-quick does — the first IPv4 entry across
// them is the tunnel address). A leading BOM and CR/LF/CRLF line ends are
// tolerated. Only the first [Peer] counts.
//
// What is deliberately NOT read: AllowedIPs (ours is the constant 0.0.0.0/0),
// Endpoint (the WireGuard endpoint is the relay's local socket in their model;
// ours is TURNBind), MTU (ours is automatic), PersistentKeepalive (a constant
// 25 here too), a second [Peer].

import Foundation

struct WireGuardConfText: Equatable {
    /// [Interface] PrivateKey — 32 bytes, base64. Required.
    var privateKey: String
    /// [Peer] PublicKey — 32 bytes, base64. Required.
    var peerPublicKey: String
    /// [Peer] PresharedKey — 32 bytes, base64. Optional; a malformed one is
    /// dropped rather than imported (a wrong PSK is a tunnel that never
    /// handshakes, silently).
    var presharedKey: String?
    /// [Interface] Address — the FIRST entry that is an IPv4 address with an
    /// optional /prefix ("/32" is appended when the conf gives none). nil when
    /// there is none (an IPv6-only conf, a hostname, no Address line) — the
    /// profile then keeps its default and the confirmation says so.
    var tunnelAddress: String?
    /// [Interface] DNS — the entries comma-joined without spaces
    /// ("1.1.1.1,1.0.0.1"), the form `dnsServers` already carries. Optional.
    var dnsServers: String?
    /// AmneziaWG keys present under [Interface] with a non-empty value, in
    /// file order and their own spelling. Empty for a plain WireGuard conf.
    var awgKeys: [String]
    /// The subset of `awgKeys` that changes the WIRE format — junk prefixes on
    /// the handshake/transport packets (S1–S4 ≠ 0), non-standard message types
    /// (H1–H4 ≠ 1…4), header protection (HeaderProtectionKey), random trailers
    /// on the handshake response (RandomTrailers on: plain wireguard-go drops
    /// a response whose length is not exactly MessageResponseSize). A plain
    /// WireGuard client cannot talk to a server that enforces these. Jc/Jmin/
    /// Jmax and I1–I5 are NOT here: junk packets are something the client
    /// SENDS before its handshake, not something a server checks for.
    var awgWireChanging: [String]

    static let awgKeyNames: Set<String> = [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5", "headerprotectionkey",
        "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime",
        "keepalivetimeout", "maxhandshakeattempts", "randomtrailers", "disablecookies",
    ]

    /// Parses the conf text. Returns nil when there is no usable identity —
    /// no PrivateKey, no Peer PublicKey, or either not 32 base64 bytes — so
    /// the caller imports the link WITHOUT WireGuard settings (and says the
    /// section could not be read when there was one).
    static func parse(_ text: String) -> WireGuardConfText? {
        var section = ""
        var privateKey = "", publicKey = ""
        var psk: String? = nil, address: String? = nil
        var dns: [String] = []
        var awgKeys: [String] = [], wireChanging: [String] = []
        var peerSeen = false

        var body = text
        if body.hasPrefix("\u{FEFF}") { body.removeFirst() }
        for rawLine in body.components(separatedBy: .newlines) {
            // wg(8): a comment starts at the first `#` anywhere on the line.
            var line = rawLine
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]) }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix(";") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces).lowercased()
                if section == "peer" {
                    if peerSeen { break }
                    peerSeen = true
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let keyText = line[..<eq].trimmingCharacters(in: .whitespaces)
            let key = keyText.lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            switch section {
            case "interface":
                switch key {
                case "privatekey":
                    privateKey = value
                case "address":
                    if address == nil { address = firstIPv4(value) }
                case "dns":
                    dns.append(contentsOf: dnsEntries(value))
                default:
                    if awgKeyNames.contains(key), !value.isEmpty {
                        awgKeys.append(keyText)
                        if changesTheWire(key: key, value: value) { wireChanging.append(keyText) }
                    }
                }
            case "peer":
                switch key {
                case "publickey":
                    publicKey = value
                case "presharedkey":
                    if isKey32(value) { psk = value }
                default:
                    break
                }
            default:
                break
            }
        }
        guard isKey32(privateKey), isKey32(publicKey) else { return nil }
        return WireGuardConfText(privateKey: privateKey, peerPublicKey: publicKey, presharedKey: psk,
                                 tunnelAddress: address, dnsServers: dns.isEmpty ? nil : dns.joined(separator: ","),
                                 awgKeys: awgKeys, awgWireChanging: wireChanging)
    }

    /// A WireGuard key: exactly 32 bytes of standard base64.
    static func isKey32(_ s: String) -> Bool {
        guard let d = Data(base64Encoded: s) else { return false }
        return d.count == 32
    }

    /// "a.b.c.d" or "a.b.c.d/n": four decimal octets 0…255, an optional prefix 0…32.
    static func isIPv4CIDR(_ s: String) -> Bool {
        let halves = s.split(separator: "/", omittingEmptySubsequences: false)
        guard halves.count == 1 || halves.count == 2 else { return false }
        let octets = halves[0].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4, octets.allSatisfy({ o in
            !o.isEmpty && o.count <= 3 && o.allSatisfy(\.isNumber) && Int(o).map { $0 <= 255 } == true
        }) else { return false }
        if halves.count == 2 {
            guard let p = Int(halves[1]), !halves[1].isEmpty, (0...32).contains(p) else { return false }
        }
        return true
    }

    private static func changesTheWire(key: String, value: String) -> Bool {
        switch key {
        case "s1", "s2", "s3", "s4":
            return value != "0"
        case "h1": return value != "1"
        case "h2": return value != "2"
        case "h3": return value != "3"
        case "h4": return value != "4"
        case "headerprotectionkey":
            return true
        case "randomtrailers":
            let v = value.lowercased()
            return !(v == "off" || v == "0" || v == "false" || v == "no")
        default:
            return false
        }
    }

    /// The first IPv4 entry of an Address list, "/32" appended when it has no
    /// prefix (the provider splits the address on "/" and needs both halves).
    private static func firstIPv4(_ list: String) -> String? {
        for entry in list.split(separator: ",") {
            let e = entry.trimmingCharacters(in: .whitespaces)
            guard isIPv4CIDR(e) else { continue }
            return e.contains("/") ? e : e + "/32"
        }
        return nil
    }

    private static func dnsEntries(_ list: String) -> [String] {
        return list.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
