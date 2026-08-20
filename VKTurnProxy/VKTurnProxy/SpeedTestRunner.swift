import Foundation
import NetworkExtension

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

    /// An explicit search against Ookla, kept apart from the nearby list's own
    /// loading and error state because they are different operations — a failed
    /// search must not blank a perfectly good list, nor offer to retry the
    /// wrong one.
    @Published private(set) var search: SpeedTestSearchState = .idle

    /// 🚨 Bumped by every start AND by clearing. A completion that does not carry
    /// the current generation is DROPPED, which is what stops a slow search from
    /// resurrecting itself after the user moved on or cleared it. The state type
    /// makes a mismatched query unrepresentable; this makes a stale one
    /// unapplicable.
    private var searchGeneration = 0

    /// Every path the run has been observed on — not just the one it started on.
    ///
    /// 🚨 WHILE THE RUN IS IN FLIGHT this is the WIDE trace, covering everything
    /// since the Run tap, because that is all the screen can honestly say yet.
    /// The moment the engine reports a terminal state it is REPLACED by the
    /// trace over the measurement window alone — see the terminal branch below.
    @Published private(set) var pathTrace = SpeedTestPathTrace()

    /// Every route observation with the instant it was taken, so the final trace
    /// can be built over the measurement window instead of over the whole run.
    /// ⚠️ Sampled by the 0.5s poll, so a flip and flip-back inside one interval
    /// is invisible; that is the resolution of this instrument, not a claim.
    private var pathObservations: [SpeedTestPathObservation] = []

    /// The parameters the run in hand was STARTED with. The result renders from
    /// this, never from the screen's live controls.
    @Published private(set) var startedRun: SpeedTestRunConfig?

    /// The server the previous successful AUTOMATIC run used, snapshotted when
    /// this one started. It is what makes "automatic selection moved" answerable
    /// at all; without it the screen can show which server was used but not that
    /// it changed. See SpeedTestServerChoice.updatesBaseline for why all three
    /// qualifiers are load-bearing.
    @Published private(set) var previousServerID: String?
    private var lastAutomaticServerID: String?

    /// Set when a start is refused because one run is already in flight. The Go
    /// side refuses too — this is the half that says so out loud instead of the
    /// button doing nothing.
    @Published private(set) var refusal: String?

    var isRunning: Bool { progress.state == "running" }
    var servers: [SpeedTestServer] { serverList?.servers ?? [] }

    /// 🚨 ONE GUARD FOR BOTH, because Go has one. The nearby fetch and the
    /// remote search were guarded by SEPARATE flags, so this side happily
    /// started both at once — and Go, which allows one activity at a time,
    /// refused the second with a `busy:` error that then replaced a perfectly
    /// good nearby list. Nothing was corrupted; the screen simply reported a
    /// collision this side had created and could have avoided.
    ///
    /// The two are asked from different places (the picker's list, the picker's
    /// search button), so nothing but a shared predicate keeps them apart.
    var isFetchingServers: Bool { serversLoading || search.isSearching }

    private var poller: Timer?

    /// The build a run was taken on. The engine string names the METHODOLOGY;
    /// only this names the binary.
    static var appBuild: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
    }

    private init() {}

    // MARK: Server list

    /// 🚨 Fetching the list is NOT a lookup — the engine pings every server in it
    /// concurrently — so Go refuses while a run is in flight and says why. This
    /// side must not paper over that refusal: it is the difference between a
    /// slow measurement and a wrong one.
    func loadServers() {
        guard !isFetchingServers else { return }
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

    /// 🚨 Asks OOKLA, instead of filtering rows we already hold. The local filter
    /// cannot reach what the nearby list does not contain — and the nearby list
    /// is built from the apparent IP, so a user whom Ookla places on the wrong
    /// side of a sea never sees their own city's server in it, however they spell
    /// it. Digits are looked up by id.
    func searchServers(_ query: String) {
        let q = query.trimmingCharacters(in: CharacterSet.whitespaces)
        guard !q.isEmpty, !isFetchingServers else { return }
        searchGeneration += 1
        let generation = searchGeneration
        // Captured at the START, like the nearby list's: the latencies about to
        // be measured belong to the route in use right now.
        let fetchedOn = Self.currentPath()
        // One assignment: from here the screen cannot show results under a
        // query they do not answer.
        search = .searching(query: q)

        DispatchQueue.global(qos: .userInitiated).async {
            var found: [SpeedTestServer] = []
            var failure: String?
            q.withCString { cstr in
                if let ptr = wgSpeedtestFindServers(cstr) {
                    let json = String(cString: ptr)
                    free(UnsafeMutableRawPointer(mutating: ptr))
                    if let data = json.data(using: .utf8) {
                        if let decoded = try? JSONDecoder().decode([SpeedTestServer].self, from: data) {
                            found = decoded
                        } else if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                                  let err = obj["error"] as? String {
                            failure = err
                        } else {
                            failure = "could not read the search result"
                        }
                    }
                } else {
                    failure = "wgSpeedtestFindServers returned NULL"
                }
            }
            let results = found
            let err = failure
            Task { @MainActor [weak self] in
                guard let self, generation == self.searchGeneration else { return }
                self.search = err.map { .failed(query: q, message: $0) }
                    ?? .results(query: q,
                                list: SpeedTestServerList(servers: results, fetchedOn: fetchedOn))
            }
        }
    }

    func clearSearch() {
        searchGeneration += 1 // any search still in flight can no longer apply
        search = .idle
    }

    // MARK: Run

    func start(serverID: String, serverLabel: String, threads: Int,
               direction: String, durationSec: Int, research: Bool) {
        guard !isRunning else {
            refusal = "A speed test is already running — one at a time, or the two would measure each other."
            return
        }
        refusal = nil
        let atStart = Self.currentPath()
        pathTrace = SpeedTestPathTrace(atStart)
        pathObservations = [SpeedTestPathObservation(at: Date(), path: atStart)]

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
            // 🚨 A REFUSED START IS NOT A RESULT, and faking one made it
            // invisible. The result section only renders when `startedRun` is
            // set, so on the very first attempt this error appeared NOWHERE —
            // the button simply did nothing — and once a previous run existed it
            // rendered inside THAT run's section, reading as though the finished
            // run had failed. `refusal` already exists for exactly this, is
            // shown above the Run button, and leaves the last real result alone.
            refusal = startError
            return
        }
        previousServerID = lastAutomaticServerID
        let config = SpeedTestRunConfig(serverID: serverID, serverLabel: serverLabel,
                                        threads: threads, direction: direction,
                                        durationSec: durationSec)
        startedRun = config
        // Logged at START, not only at the end: a run that is stopped, fails, or
        // never reports still has to leave its parameters behind — those are
        // exactly the runs someone comes back to the log for.
        SharedLogger.shared.log("[App] " + SpeedTestLog.start(config,
                                                             research: research,
                                                             path: Self.currentPath(),
                                                             build: Self.appBuild))
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
            // 🚨 LOGGED, not only shown. This is the failure a log is MOST needed
            // for — the app and the engine disagreeing about the wire — and it
            // is the one case where the result lines below never run, so
            // without this the log ends at START and says nothing about why.
            let message = "could not read the engine's progress (\(error)) — the app and the "
                + "speed-test engine were built from different versions"
            SharedLogger.shared.log("[App] speedtest: ERROR " + SpeedTestLog.clean(message))
            var p = progress
            p.state = "error"
            p.error = message
            progress = p
            stopPolling()
            return
        }

        progress = decoded
        let now = Self.currentPath()
        if pathObservations.last?.path != now {
            pathObservations.append(SpeedTestPathObservation(at: Date(), path: now))
        }
        pathTrace.record(now)
        if decoded.state == "done" || decoded.state == "error" {
            // 🚨 NARROW THE TRACE TO WHAT WAS ACTUALLY MEASURED. Until here it
            // covers the Run tap to this poll, which is wider than the
            // measurement at BOTH ends: a route change before the window opened,
            // or after it closed while the engine was still unwinding, would
            // otherwise condemn a result that is complete and correct.
            // ⚖️ For a both-direction run the interval spans from the first
            // window's open to the last one's close, so a change in the gap
            // between the phases still counts — the two phases would then have
            // been measured on different routes, and one label cannot describe
            // both.
            pathTrace = SpeedTestPathTrace.overMeasurement(decoded, observations: pathObservations,
                                                          fallback: pathTrace)
            if let run = startedRun {
                let choice = SpeedTestServerChoice.of(pinnedID: run.serverID,
                                                      ranOn: decoded.serverID,
                                                      previous: previousServerID)
                for line in SpeedTestLog.result(run, progress: decoded,
                                                path: pathTrace, serverChoice: choice) {
                    SharedLogger.shared.log("[App] " + line)
                }
            }
            if SpeedTestServerChoice.updatesBaseline(
                state: decoded.state,
                wasAutomatic: startedRun?.serverID.isEmpty ?? false,
                ranOn: decoded.serverID) {
                lastAutomaticServerID = decoded.serverID
            }
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
