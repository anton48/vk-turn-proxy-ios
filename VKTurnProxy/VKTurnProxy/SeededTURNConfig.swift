// SeededTURNConfig.swift
//
// The seed the app hands the extension's credential pool — `seeded_turn` in the
// proxy config — and the relay list a fresh probe's answer names.
//
// Until 2026-11-18 the seed named ONE relay although VK returns several with
// a credential: the probe's answer carried `turn_address` alone. On a cold
// cache (no file, a fresh install, a reset) the pool then held one slot with
// one relay, and a relay that answers TURN and does not forward left the
// first connection nothing to move to — four attempts on one address, then
// the bootstrap's timeout. The list now travels with the seed.
//
// Foundation only, so tools/swiftcheck RUNS it.

import Foundation

enum SeededTURNConfig {
    /// The relays a probe's answer names in `turn_addresses`: strings only, no
    /// empty one, none twice, in VK's order. Anything else — a missing key, a
    /// value that is not a list — is no list.
    static func probeAddresses(_ raw: Any?) -> [String] {
        guard let list = raw as? [Any] else { return [] }
        var out: [String] = []
        for item in list {
            guard let s = item as? String, !s.isEmpty, !out.contains(s) else { continue }
            out.append(s)
        }
        return out
    }

    /// The `seeded_turn` object. `addresses` goes in only when the app has a
    /// list (a fresh probe); the relay the seed names stands first in it. With
    /// no list the object is what it always was — a cached seed's twin in the
    /// pool's own cache file carries its relays.
    static func object(address: String, username: String, password: String,
                       addresses: [String]) -> [String: Any] {
        var object: [String: Any] = ["address": address, "username": username, "password": password]
        guard !addresses.isEmpty else { return object }
        var list = [address]
        for a in addresses where !a.isEmpty && !list.contains(a) {
            list.append(a)
        }
        object["addresses"] = list
        return object
    }
}
