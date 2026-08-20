import Foundation
import NetworkExtension

// MARK: - Wire types (mirror pkg/speedtest's JSON exactly)
//
// 🚨 THE CONTRACT IS ASYMMETRIC, and getting it backwards bricks the screen:
//
//   - a field Go sends that Swift does not decode is SILENT and safe (unknown
//     keys are dropped);
//   - a non-Optional CodingKey for a field Go does NOT send is FATAL. The
//     synthesized decoder THROWS — memberwise defaults do not rescue a missing
//     key — `poll()` swallows it, and the screen sits at "running" for ever with
//     the Run button never coming back.
//
// ⇒ Go-side field additions may land ahead of their Swift keys; Swift keys may
// never land ahead of the Go field, and a Go change means rebuilding the
// xcframework BEFORE the Swift half. Anything optional on the wire must be
// Optional here.

struct SpeedTestPhase: Codable {
    var libraryMbps: Double = 0
    var rawMbps: Double = 0
    var bytes: Int64 = 0
    var actualSec: Double = 0
    var warmupSec: Double = 0
    var windowSec: Double = 0
    var impliedSec: Double = 0
    var consistent: Bool = false
    var peakConns: Int = 0
    var dials: Int = 0
    var backlogBytes: Int64 = 0
    var confirmedRatio: Double = 0
    var warnings: [String]?

    enum CodingKeys: String, CodingKey {
        case libraryMbps = "library_mbps"
        case rawMbps = "raw_mbps"
        case bytes
        case actualSec = "actual_sec"
        case warmupSec = "warmup_sec"
        case windowSec = "window_sec"
        case impliedSec = "implied_sec"
        case consistent
        case peakConns = "peak_conns"
        case dials
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
    var direction: String = ""
    var mode: String = ""

    /// Optional, because Go OMITS a direction that did not run. As values they
    /// were always present, so a download-only run carried a complete upload
    /// object of zeros — indistinguishable from a measured 0.0 Mbit/s by anyone
    /// who rendered what they were given.
    var download: SpeedTestPhase?
    var upload: SpeedTestPhase?

    var engine: String = ""
    var estimator: String = ""

    enum CodingKeys: String, CodingKey {
        case state, stage, error, threads, engine, estimator, direction, mode
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
/// Every stored property here is UI state, so the whole type lives on the main
/// actor. That is also what makes the background list fetch honest: it may
/// compute, and it may not touch this object except by hopping back.
@MainActor
final class SpeedTestRunner: ObservableObject {
    static let shared = SpeedTestRunner()

    @Published private(set) var progress = SpeedTestProgress()
    @Published private(set) var serverList: SpeedTestServerList?
    @Published private(set) var serversLoading = false
    @Published private(set) var serversError: String?

    /// Every path the run has been observed on — not just the one it started on.
    @Published private(set) var pathTrace = SpeedTestPathTrace()

    /// The parameters the run in hand was STARTED with. The result renders from
    /// this, never from the screen's live controls.
    @Published private(set) var startedRun: SpeedTestRunConfig?

    /// Set when a start is refused because one run is already in flight. The Go
    /// side refuses too — this is the half that says so out loud instead of the
    /// button doing nothing.
    @Published private(set) var refusal: String?

    var isRunning: Bool { progress.state == "running" }
    var servers: [SpeedTestServer] { serverList?.servers ?? [] }

    private var poller: Timer?

    private init() {}

    // MARK: Server list

    /// 🚨 Fetching the list is NOT a lookup — the engine pings every server in it
    /// concurrently — so Go refuses while a run is in flight and says why. This
    /// side must not paper over that refusal: it is the difference between a
    /// slow measurement and a wrong one.
    func loadServers() {
        guard !serversLoading else { return }
        serversLoading = true
        serversError = nil
        let fetchedOn = Self.currentPath()

        // No `self` in the background closure: capturing a non-Sendable object
        // there is a warning today and a data race the day someone touches a
        // stored property from it. It computes values; the hop back owns the
        // publishing.
        DispatchQueue.global(qos: .userInitiated).async {
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
            let fetched = list
            let err = failure
            Task { @MainActor [weak self] in
                guard let self else { return }
                if err == nil {
                    self.serverList = SpeedTestServerList(servers: fetched, fetchedOn: fetchedOn)
                }
                self.serversError = err
                self.serversLoading = false
            }
        }
    }

    // MARK: Run

    func start(serverID: String, serverLabel: String, threads: Int,
               direction: String, durationSec: Int, research: Bool) {
        guard !isRunning else {
            refusal = "A speed test is already running — one at a time, or the two would measure each other."
            return
        }
        refusal = nil
        pathTrace = SpeedTestPathTrace(Self.currentPath())

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
        startedRun = SpeedTestRunConfig(serverID: serverID, serverLabel: serverLabel,
                                        threads: threads, direction: direction,
                                        durationSec: durationSec)
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
            Task { @MainActor in self?.poll() }
        }
    }

    private func poll() {
        guard let ptr = wgSpeedtestPoll() else { return }
        let json = String(cString: ptr)
        free(UnsafeMutableRawPointer(mutating: ptr))

        guard let data = json.data(using: .utf8) else { return }
        let decoded: SpeedTestProgress
        do {
            decoded = try JSONDecoder().decode(SpeedTestProgress.self, from: data)
        } catch {
            // 🚨 NEVER SILENT. This used to be `try?` with a bare `return`, so a
            // wire mismatch — a Swift key for a field Go stopped sending — froze
            // the screen on its last value, with the poller never invalidated and
            // the Run button never returning. A decode failure is a bug in the
            // pair of binaries and must say so.
            var p = progress
            p.state = "error"
            p.error = "could not read the engine's progress (\(error)) — the app and the "
                + "speed-test engine were built from different versions"
            progress = p
            stopPolling()
            return
        }

        progress = decoded
        pathTrace.record(Self.currentPath())
        if decoded.state == "done" || decoded.state == "error" {
            stopPolling()
        }
    }

    private func stopPolling() {
        poller?.invalidate()
        poller = nil
    }

    /// Sampled repeatedly, not once — see `SpeedTestPathTrace`.
    private static func currentPath() -> SpeedTestPath {
        let tunnel = TunnelManager.shared
        return .current(connected: tunnel.status == .connected, directMode: tunnel.directMode)
    }
}
