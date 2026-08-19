import Foundation
import NetworkExtension

// MARK: - Wire types (mirror pkg/speedtest's JSON exactly)

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

struct SpeedTestPhase: Codable {
    var libraryMbps: Double = 0
    var rawMbps: Double = 0
    var bytes: Int64 = 0
    var actualSec: Double = 0
    var impliedSec: Double = 0
    var consistent: Bool = false
    var backlogBytes: Int64 = 0
    var confirmedRatio: Double = 0
    var warnings: [String]?

    enum CodingKeys: String, CodingKey {
        case libraryMbps = "library_mbps"
        case rawMbps = "raw_mbps"
        case bytes
        case actualSec = "actual_sec"
        case impliedSec = "implied_sec"
        case consistent
        case backlogBytes = "backlog_bytes"
        case confirmedRatio = "confirmed_ratio"
        case warnings
    }

    var moved: Bool { bytes > 0 }
}

struct SpeedTestProgress: Codable {
    var state: String = "idle"
    var stage: String = ""
    var error: String?
    var serverID: String = ""
    var serverDesc: String = ""
    var serverURL: String = ""
    var ooklaSeesIP: String = ""
    var ooklaSeesISP: String = ""
    var pingMs: Double = 0
    var threads: Int = 0
    var requestedSec: Int = 0
    var download = SpeedTestPhase()
    var upload = SpeedTestPhase()
    var engine: String = ""
    var estimator: String = ""

    enum CodingKeys: String, CodingKey {
        case state, stage, error, threads, engine, estimator
        case serverID = "server_id"
        case serverDesc = "server_desc"
        case serverURL = "server_url"
        case ooklaSeesIP = "ookla_sees_ip"
        case ooklaSeesISP = "ookla_sees_isp"
        case pingMs = "ping_ms"
        case requestedSec = "requested_sec"
        case download, upload
    }
}

/// How the run reached the network. Recorded with the result rather than used to
/// refuse one: a measurement without the VPN is not a spoiled measurement, it is
/// the comparison arm people reach for first. The only defect would be reporting
/// it as VPN speed.
enum SpeedTestPath: String {
    case throughVPN = "Through VPN"
    case directMode = "DIRECT mode — outside the tunnel"
    case vpnOff = "VPN off"
}

// MARK: - Runner

/// 🚨 A SHARED instance, observed with `@ObservedObject` — never a `@StateObject`
/// of the view.
///
/// A run lasts 15-60 s. With the object owned by the screen, navigating back
/// destroys it mid-run, and coming back creates a SECOND runner whose own
/// `guard` cannot see the first — which is build 271's defect verbatim: a guard
/// scoped to one object cannot protect a process-wide resource. The Go side
/// refuses a second concurrent run as well; this is the half that keeps the UI
/// honest about it.
final class SpeedTestRunner: ObservableObject {
    static let shared = SpeedTestRunner()

    @Published private(set) var progress = SpeedTestProgress()
    @Published private(set) var servers: [SpeedTestServer] = []
    @Published private(set) var serversLoading = false
    @Published private(set) var serversError: String?
    @Published private(set) var path: SpeedTestPath = .vpnOff

    /// Set when a start is refused because one run is already in flight. The Go
    /// side refuses too — this is the half that says so out loud instead of the
    /// button doing nothing.
    @Published private(set) var refusal: String?

    var isRunning: Bool { progress.state == "running" }

    private var poller: Timer?

    private init() {}

    // MARK: Server list

    /// The list comes from this device's APPARENT address, so with the tunnel up
    /// it is servers near the EXIT and with it down servers near the user. The
    /// picker says which; see SpeedTestServerPicker.
    func loadServers() {
        guard !serversLoading else { return }
        serversLoading = true
        serversError = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var list: [SpeedTestServer] = []
            var failure: String?
            if let ptr = wgSpeedtestServers() {
                let json = String(cString: ptr)
                free(UnsafeMutableRawPointer(mutating: ptr))
                if let data = json.data(using: .utf8) {
                    if let decoded = try? JSONDecoder().decode([SpeedTestServer].self, from: data) {
                        list = decoded
                    } else if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                              let err = obj["error"] as? String {
                        failure = err
                    } else {
                        failure = "could not read the server list"
                    }
                } else {
                    failure = "empty server list response"
                }
            } else {
                failure = "wgSpeedtestServers returned NULL"
            }
            DispatchQueue.main.async {
                self?.servers = list
                self?.serversError = failure
                self?.serversLoading = false
            }
        }
    }

    // MARK: Run

    @MainActor
    func start(serverID: String, threads: Int, direction: String, durationSec: Int, research: Bool) {
        guard !isRunning else {
            refusal = "A speed test is already running — one at a time, or the two would measure each other."
            return
        }
        refusal = nil
        path = Self.currentPath()

        let cfg: [String: Any] = [
            "server_id": serverID,
            "threads": threads,
            "direction": direction,
            "duration_sec": durationSec,
            "research": research,
            "debug": false,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: cfg),
              let json = String(data: data, encoding: .utf8) else { return }

        var startError: String?
        json.withCString { cstr in
            if let ptr = wgSpeedtestStart(cstr) {
                let msg = String(cString: ptr)
                free(UnsafeMutableRawPointer(mutating: ptr))
                if !msg.isEmpty { startError = msg }
            } else {
                startError = "wgSpeedtestStart returned NULL"
            }
        }
        if let startError {
            var p = SpeedTestProgress()
            p.state = "error"
            p.error = startError
            progress = p
            return
        }
        var p = SpeedTestProgress()
        p.state = "running"
        progress = p
        startPolling()
    }

    func cancel() {
        wgSpeedtestCancel()
    }

    private func startPolling() {
        poller?.invalidate()
        poller = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        guard let ptr = wgSpeedtestPoll() else { return }
        let json = String(cString: ptr)
        free(UnsafeMutableRawPointer(mutating: ptr))
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(SpeedTestProgress.self, from: data) else { return }
        progress = decoded
        if decoded.state == "done" || decoded.state == "error" {
            poller?.invalidate()
            poller = nil
        }
    }

    /// Read at START, not at finish: the tunnel can be toggled while a run is in
    /// flight, and what the result must carry is how the bytes actually left.
    @MainActor
    private static func currentPath() -> SpeedTestPath {
        let tunnel = TunnelManager.shared
        guard tunnel.status == .connected else { return .vpnOff }
        return tunnel.directMode ? .directMode : .throughVPN
    }
}
