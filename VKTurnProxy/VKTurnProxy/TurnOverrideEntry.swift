// TurnOverrideEntry.swift
//
// ONE strict reading of an entry of the TURN override list — host:port,
// host:port:quota, host:port:quota:pace — for the validator, the parser and the
// pre-resolution alike, and the same reading Go's parseTURNEntry has.
//
// 🚨 WHY ONE PARSER AND NOT THREE PREDICATES (the user's review of 7271aef,
// 2026-11-07). The validator used to ask isHostPort(s) || quota(s) != nil ||
// pace(s) != nil, and isHostPort splits on the LAST colon: an entry a stricter
// reading refused — `relay.example:19302:10:65536`, a pace above the wire's
// uint16 — fell through to the quota reading, which took 65536 for the quota
// and `relay.example:19302:10` for a host:port. The string then went to Go as
// typed, Go's parser refused it, and the pool kept the refused string as an
// address to dial. A form is decided HERE, once, from the left: the host (a
// name, an IPv4, or a bracketed IPv6 — never a bare colon-bearing host), then
// one to three numeric fields — the port, the quota, the pace — with their
// bounds; anything else is no entry.
import Foundation

enum TurnOverrideEntry {
    struct Fields: Equatable {
        /// host:port as the pool keys on it (the port as typed, digits only).
        let hostPort: String
        /// The relay's limit of allocations per identity; 0 = no quota. nil = absent.
        let quota: Int?
        /// The relay's pace in KiB/s in both directions; 0 = no pacer. nil = absent.
        let pace: Int?
    }

    /// The pace field's ceiling — the declaration's uint16 (Go's paceFieldMax).
    static let paceMax = 65535

    static func parse(_ s: String) -> Fields? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, !t.unicodeScalars.contains(where: { $0.value <= 0x20 || $0.value == 0x7f }) else { return nil }
        let host: Substring
        let rest: Substring
        if t.hasPrefix("[") {
            // A bracketed IPv6 literal: everything up to the "]" is the host.
            guard let close = t.firstIndex(of: "]") else { return nil }
            let inner = t[t.index(after: t.startIndex)..<close]
            guard !inner.isEmpty else { return nil }
            host = t[...close]
            let after = t[t.index(after: close)...]
            guard after.hasPrefix(":") else { return nil }
            rest = after.dropFirst()
        } else {
            // A name or an IPv4: the host ends at the FIRST colon.
            guard let colon = t.firstIndex(of: ":") else { return nil }
            host = t[..<colon]
            guard !host.isEmpty else { return nil }
            rest = t[t.index(after: colon)...]
        }
        let fields = rest.split(separator: ":", omittingEmptySubsequences: false)
        guard (1...3).contains(fields.count) else { return nil }
        var numbers: [Int] = []
        for f in fields {
            guard !f.isEmpty, f.allSatisfy(\.isNumber), let n = Int(f) else { return nil }
            numbers.append(n)
        }
        guard (1...65535).contains(numbers[0]) else { return nil }
        let quota = numbers.count > 1 ? numbers[1] : nil
        let pace = numbers.count > 2 ? numbers[2] : nil
        if let p = pace, p > paceMax { return nil }
        return Fields(hostPort: String(host) + ":" + String(fields[0]), quota: quota, pace: pace)
    }
}
