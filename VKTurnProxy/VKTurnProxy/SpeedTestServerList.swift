import Foundation

/// One row of the picker.
struct SpeedTestServer: Codable, Identifiable, Hashable {
    let id: String
    let name: String
    let sponsor: String
    let country: String
    let host: String

    /// 🚨 OOKLA'S ESTIMATE, from where Ookla believes this device is — which can
    /// be wrong by a sea. Measured: a user in Funchal was placed on the mainland,
    /// so their own city's server read 1186 km and servers 249 km from nobody
    /// were listed as "near you". The same server read 975 km when fetched by id.
    /// Shown, but never as the reason a server is a good choice.
    let distanceKm: Double

    /// MEASURED by the list fetch, which pings every server it returns. Where the
    /// distance is a guess, this is not — and it is what actually answers "which
    /// of these is near me". Zero means unknown: a lookup by id performs no ping.
    let latencyMs: Double

    enum CodingKeys: String, CodingKey {
        case id, name, sponsor, country, host
        case distanceKm = "distance_km"
        case latencyMs = "latency_ms"
    }

    /// Latency first, because it is the measured one. Never prints a zero as if
    /// it were a sub-millisecond result.
    ///
    /// 🚨 BELOW 10 ms IT KEEPS A DECIMAL. A whole-millisecond format turned a
    /// real 0.3 ms into "0 ms" — indistinguishable from the sentinel this code
    /// uses for "not measured", on exactly the servers worth finding. The user's
    /// own city's server measures 844 µs.
    var proximity: String {
        guard latencyMs > 0 else { return String(format: "%.0f km est.", distanceKm) }
        let latency = latencyMs < 10
            ? String(format: "%.1f ms", latencyMs)
            : String(format: "%.0f ms", latencyMs)
        return String(format: "%@ · %.0f km est.", latency, distanceKm)
    }

    var label: String { sponsor.isEmpty ? name : "\(sponsor) · \(name)" }
}

/// A fetched server list, bound to the path it was fetched on.
///
/// 🚨 THE BINDING IS THE POINT. Ookla selects from the apparent IP, so the list
/// describes servers near the EXIT with the tunnel up and near the USER with it
/// down. The picker's header says which — and it used to compute that from the
/// LIVE tunnel state while showing rows fetched under the old one, so after a
/// VPN → DIRECT switch the header confidently described a neighbourhood the
/// rows did not come from. A header that lies is worse than no header: it is the
/// one piece of the screen a user would rely on to interpret the rest.
struct SpeedTestServerList: Equatable {
    let servers: [SpeedTestServer]
    let fetchedOn: SpeedTestPath

    func isStale(now: SpeedTestPath) -> Bool { fetchedOn != now }

    /// Names whose neighbourhood the ROWS describe — never the current one.
    func header(now: SpeedTestPath) -> String {
        let whose = fetchedOn == .throughVPN ? "Servers near your EXIT" : "Servers near you"
        return isStale(now: now) ? "\(whose) — fetched before the route changed" : whose
    }

    /// The latencies in this list were MEASURED on `fetchedOn`, and latency is
    /// the number the picker now leads with and tells people to choose by. Take
    /// the tunnel down and every one of them describes a path that is no longer
    /// in use — a server that read 5.6 ms through the VPN may read anything at
    /// all without it.
    ///
    /// 🎯 This applies to a SEARCH exactly as it applies to the nearby list,
    /// which is why the search reuses this type rather than growing its own
    /// staleness rule. A second copy of a rule is how the two drift apart.
    func latencyNotice(now: SpeedTestPath) -> String? {
        guard isStale(now: now) else { return nil }
        guard servers.contains(where: { $0.latencyMs > 0 }) else { return nil }
        return "These latencies were measured while the route was "
            + "\"\(fetchedOn.rawValue)\". They describe that path, not the one in use now."
    }

    /// 🚫 A stale list does NOT clear the pin. Only the LIST is out of date; the
    /// pinned server is still reachable and still the right one, because pinning
    /// one id across tunnel states is the entire reason a VPN-on/off pair is
    /// comparable. Clearing it here would destroy the comparison to tidy up a
    /// caption.
    func staleNotice(now: SpeedTestPath) -> String? {
        guard isStale(now: now) else { return nil }
        return "This list was fetched while the route was \"\(fetchedOn.rawValue)\". "
            + "Reload it to see servers near where you are now — your pinned server is unaffected."
    }
}

/// The state of a search against Ookla, as ONE value.
///
/// 🚨 IT IS ONE VALUE ON PURPOSE. The query and the results used to be two
/// separate published properties, which made two wrong screens reachable: from
/// the moment a new search started until it finished, the OLD results were shown
/// under the NEW query's heading; and a late completion could resurrect results
/// after the user had cleared them. Neither is expressible here — a result
/// carries the query it answers, and there is no state that holds one without
/// the other.
///
/// 🚫 It is also kept apart from the nearby list's loading and error state. They
/// are different operations: a failed search used to blank a perfectly good
/// nearby list and offer a "Try again" that retried the OTHER one.
enum SpeedTestSearchState: Equatable {
    case idle
    case searching(query: String)
    /// Carries a SpeedTestServerList, not a bare array, so the path the
    /// latencies were measured on travels with them — the same rule, and the
    /// same code, as the nearby list.
    case results(query: String, list: SpeedTestServerList)
    case failed(query: String, message: String)

    var isSearching: Bool {
        if case .searching = self { return true }
        return false
    }

    /// The query this state is about, if any — so a heading can never name a
    /// query the rows below it did not answer.
    var query: String? {
        switch self {
        case .idle: return nil
        case let .searching(q), let .results(q, _), let .failed(q, _): return q
        }
    }
}
