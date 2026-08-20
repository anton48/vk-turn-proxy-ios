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
    var proximity: String {
        latencyMs > 0
            ? String(format: "%.0f ms · %.0f km est.", latencyMs, distanceKm)
            : String(format: "%.0f km est.", distanceKm)
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
