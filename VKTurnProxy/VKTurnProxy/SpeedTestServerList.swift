import Foundation

/// One row of the picker.
struct SpeedTestServer: Codable, Identifiable, Hashable {
    let id: String
    let name: String
    let sponsor: String
    let country: String
    let host: String
    let distanceKm: Double

    enum CodingKeys: String, CodingKey {
        case id, name, sponsor, country, host
        case distanceKm = "distance_km"
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
