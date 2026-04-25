import Foundation
import Network
import NetworkExtension
import UIKit

// MARK: - Tunnel Statistics

struct TunnelStats: Codable {
    var txBytes: Int64 = 0
    var rxBytes: Int64 = 0
    var activeConns: Int32 = 0
    var totalConns: Int32 = 0
    var turnRTTms: Double = 0
    var dtlsHandshakeMs: Double = 0
    var reconnects: Int64 = 0
    var captchaImageURL: String?
    var captchaSID: String?

    enum CodingKeys: String, CodingKey {
        case txBytes = "tx_bytes"
        case rxBytes = "rx_bytes"
        case activeConns = "active_conns"
        case totalConns = "total_conns"
        case turnRTTms = "turn_rtt_ms"
        case dtlsHandshakeMs = "dtls_handshake_ms"
        case reconnects
        case captchaImageURL = "captcha_image_url"
        case captchaSID = "captcha_sid"
    }
}

@MainActor
class TunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .disconnected
    @Published var errorMessage: String?
    @Published var stats = TunnelStats()

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var foregroundObserver: NSObjectProtocol?
    private var statsTimer: Timer?

    // For rate calculation
    private var prevTx: Int64 = 0
    private var prevRx: Int64 = 0
    private var prevTime: Date = Date()
    @Published var txRate: Double = 0  // bytes/sec
    @Published var rxRate: Double = 0  // bytes/sec
    @Published var internetRTTms: Double = 0  // ms, TCP connect to 1.1.1.1
    @Published var captchaPending = false
    @Published var captchaImageURL: String?
    @Published var captchaSID: String?
    // Set true when JS detector in the WebView reports the loaded page is
    // "Attempt limit reached" (no interactive element, error text visible).
    // UI renders an overlay with a progress indicator while this is true.
    // Cleared when the WebView reloads to a working captcha (JS posts
    // state:ready) or when the sheet is dismissed / captcha resolves.
    @Published var captchaLimitReached = false
    // Incremented on each auto-refresh attempt. Shown in the overlay UI.
    @Published var captchaRefreshAttempt = 0
    // Max consecutive auto-refresh attempts before we stop and surface an
    // error. 6 × 10s interval = up to 60s of auto-retries.
    let maxCaptchaRefreshAttempts = 6
    // Interval between auto-refresh attempts (seconds).
    private let captchaRefreshInterval: TimeInterval = 10
    // Timer driving the periodic auto-refresh while captchaLimitReached=true.
    // Created by onCaptchaLimitDetected, invalidated by onCaptchaReady /
    // onCaptchaSheetDismissed / captcha-resolved / max-attempts.
    private var captchaAutoRefreshTimer: Timer?
    private var lastCaptchaShowTime: Date?  // prevent rapid re-show

    init() {
        Task {
            await loadManager()
        }
        // Restart stats polling when app returns from background
        foregroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                if self.status == .connected {
                    self.startStatsPolling(reset: false)
                }
                // If the auto-refresh overlay was up when the app went to
                // background, the scheduled Timer stopped firing (iOS
                // suspends timers in background apps). When we come back
                // the overlay is still visible but no refresh is happening.
                // Re-trigger the auto-refresh from scratch so the timer
                // resumes ticking and immediately fires an initial refresh.
                if self.captchaLimitReached {
                    self.debugLog("captcha auto-refresh: app returned to foreground while overlay still visible — re-triggering auto-refresh (previous attempt=\(self.captchaRefreshAttempt))")
                    self.captchaAutoRefreshTimer?.invalidate()
                    self.captchaAutoRefreshTimer = nil
                    self.captchaLimitReached = false  // reset so onCaptchaLimitDetected doesn't early-return
                    self.onCaptchaLimitDetected()
                }
            }
        }
    }

    // MARK: - Public API

    func connect(config: TunnelConfig) async {
        errorMessage = nil

        do {
            let manager = try await getOrCreateManager()

            // Build UAPI config string for WireGuard. Throws KeyError with a
            // user-readable message if any of the Base64 keys can't be decoded
            // — caught below and surfaced via `errorMessage`, so the user sees
            // "Private Key is not valid Base64…" instead of a cryptic
            // "hex string does not fit the slice" from wireguard-go.
            let wgConfig = try buildUAPIConfig(config: config)

            // Resolve VK API hostnames here, in the main-app process — the
            // extension can't do this reliably itself before
            // setTunnelNetworkSettings (and we defer that until after
            // bootstrap). Run on a background queue so the UI thread isn't
            // blocked by CFHost (~30-100 ms per host on a healthy network).
            let vkHostIPs = await Task.detached(priority: .userInitiated) { [self] in
                self.resolveVKHosts()
            }.value
            if !vkHostIPs.isEmpty {
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: pre-resolved VK hosts: \(vkHostIPs)")
                // Diagnostic: probe whether main app can actually reach
                // these IPs over TCP/443. If main app fails too — the IPs
                // are genuinely unreachable (network/ISP/whitelist). If
                // main app succeeds and extension still fails — it's an
                // extension-process routing issue.
                diagnoseIPReachability(vkHostIPs)
            } else {
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: WARNING — pre-resolved VK hosts list is empty")
            }

            // Build proxy config JSON
            let proxyConfig = buildProxyConfig(config: config, vkHostIPs: vkHostIPs)

            // Pick serverAddress. Prefer the TURN relay IP cached from a
            // previous session by the extension (via AppGroup UserDefaults):
            // this is what iOS exempts from the tunnel per Apple's documented
            // serverAddress-always-excluded rule, so our TURN UDP doesn't
            // loop back through the tunnel once includeAllNetworks=true ships
            // in Step 4. Falls back to the VPS peerAddress on first launch
            // when the extension hasn't recorded a TURN IP yet — bootstrap
            // still works because excludedRoutes (current mode) still covers
            // the TURN relay.
            let shared = UserDefaults(suiteName: "group.com.vkturnproxy.app")
            let savedTurnIP = shared?.string(forKey: "lastTurnServerIP") ?? ""
            let serverAddress: String
            if !savedTurnIP.isEmpty {
                serverAddress = savedTurnIP
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: using cached TURN IP \(savedTurnIP) as serverAddress")
            } else {
                serverAddress = config.peerAddress
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: no cached TURN IP, using peerAddress \(config.peerAddress) as serverAddress")
            }

            // Set provider configuration
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.vkturnproxy.app.tunnel"
            proto.serverAddress = serverAddress
            proto.providerConfiguration = [
                "wg_config": wgConfig,
                "proxy_config": proxyConfig,
                "tunnel_address": config.tunnelAddress,
                "dns_servers": config.dnsServers,
                "mtu": config.mtu
            ]

            // Full-tunnel mode (Step 4 of the APNs-through-tunnel refactor).
            // includeAllNetworks=true is the ONLY documented mechanism that
            // pulls APNs (Apple Push Notification Service) traffic into the
            // VPN on iOS — which is the goal of this whole refactor: pushes
            // keep arriving when the device is on Wi-Fi going through the
            // tunnel.
            //
            // Trade-offs we accept:
            //  - excludedRoutes become inert (Apple ignores them). So the
            //    only always-excluded destinations are: serverAddress
            //    (set to the TURN relay IP above, see Step 3), Apple's
            //    built-in always-excluded list (DHCP, captive networks,
            //    cellular-services-direct…), and — iOS 16.4+ — whatever
            //    we gate with the flags below.
            //  - excludeLocalNetworks=true keeps LAN reachable even with
            //    the full tunnel up (printers, AirPlay, etc.).
            //  - excludeAPNs=false / excludeCellularServices=false
            //    (both iOS 16.4+) override Apple's default where these
            //    system-service categories bypass the tunnel — we want
            //    them IN the tunnel so the user on Wi-Fi keeps receiving
            //    pushes via our VPS.
            //
            // Saving a profile whose includeAllNetworks changed re-prompts
            // iOS for VPN permission on the next connect. This is a
            // one-time UX cost for existing users.
            proto.includeAllNetworks = true
            proto.excludeLocalNetworks = true
            if #available(iOS 16.4, *) {
                proto.excludeAPNs = false
                proto.excludeCellularServices = false
            }

            manager.protocolConfiguration = proto
            manager.localizedDescription = "VK TURN Proxy"
            manager.isEnabled = true

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            try manager.connection.startVPNTunnel()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Ask the extension to hit the VK API again and return a fresh
    /// captcha redirect_uri. Used by the "Attempt limit reached" auto-
    /// refresh loop to rotate the captcha session and by the initial
    /// captcha-detected path to avoid showing a stale URL after the app
    /// spent time in the background.
    ///
    /// Previously this also asked the extension to "suspend DNS" —
    /// remove the tunnel default route so the WebView could reach VK via
    /// the physical interface. In full-tunnel mode (includeAllNetworks=
    /// true, Step 4), excludedRoutes are ignored and there is no default
    /// route to remove: the WebView traffic either goes through the
    /// tunnel (when it's alive — poolCreds keeps at least one conn up)
    /// or is dropped (all conns dead — recoverable only via
    /// Disconnect+Connect). So we just refresh the URL.
    func refreshCaptchaURL() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "refresh_captcha_url".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { [weak self] responseData in
                guard let self = self,
                      let data = responseData,
                      let freshURL = String(data: data, encoding: .utf8),
                      !freshURL.isEmpty else { return }
                DispatchQueue.main.async {
                    self.captchaImageURL = freshURL
                }
            }
        } catch {}
    }

    /// Send debug log message to extension (appears in vpn.log).
    private func debugLog(_ message: String) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let msg = "debug_log:\(message)".data(using: .utf8) else { return }
        try? session.sendProviderMessage(msg) { _ in }
    }

    /// Route captcha-WebView log messages into the same vpn.log stream used
    /// by the extension. The WKWebView lives in the main-app process and has
    /// no direct access to the shared App Group log file, so we tunnel the
    /// string through the provider-session IPC — same mechanism debugLog
    /// uses for TunnelManager's own events.
    func logFromCaptchaView(_ message: String) {
        debugLog("[captcha-view] \(message)")
    }

    // MARK: - Captcha auto-refresh ("Attempt limit reached" recovery)
    //
    // When VK responds to our captcha fetch with the "Attempt limit reached"
    // error page (non-interactive, shows only Done), sitting still does
    // nothing — VK expects us to come back with a fresh client_id / session.
    // The JS detector inside CaptchaWKWebView posts `state:limit` to Swift
    // after 2.5s of page load; that triggers `onCaptchaLimitDetected()` here.
    // We then start a Timer that periodically calls `refreshCaptchaURL()` —
    // which asks the extension for a fresh captcha URL via
    // wgRefreshCaptchaURL. The fresh URL flows back through `captchaImageURL`
    // → SwiftUI rebind → `CaptchaWKWebView.updateUIView` reloads the same
    // WKWebView → JS fires again → either `state:limit` (still bad, timer
    // keeps going) or `state:ready` (working captcha, we stop the timer
    // and hide the overlay).

    /// Called from WebView JS detector when the loaded page is in
    /// limit-reached state. Idempotent — multiple calls while a timer is
    /// already running are no-ops.
    func onCaptchaLimitDetected() {
        if captchaAutoRefreshTimer != nil {
            debugLog("captcha auto-refresh: limit_detected arrived while timer already running, ignoring duplicate")
            return
        }
        debugLog("captcha auto-refresh: limit_detected, starting (interval=\(Int(captchaRefreshInterval))s, max=\(maxCaptchaRefreshAttempts) attempts)")
        captchaLimitReached = true
        captchaRefreshAttempt = 0
        // Kick off the first refresh immediately — no reason to wait 10s on
        // the first one.
        triggerCaptchaRefresh(reason: "initial")
        captchaAutoRefreshTimer = Timer.scheduledTimer(withTimeInterval: captchaRefreshInterval, repeats: true) { [weak self] _ in
            self?.triggerCaptchaRefresh(reason: "timer")
        }
    }

    /// Called from WebView JS detector when the loaded page has a visible
    /// interactive captcha element. Cancels any running auto-refresh timer
    /// and clears the limit-reached UI state.
    func onCaptchaReady() {
        if captchaAutoRefreshTimer == nil && !captchaLimitReached {
            return  // nothing to stop, no log noise
        }
        debugLog("captcha auto-refresh: captcha_ready, stopping timer (attempt was \(captchaRefreshAttempt))")
        stopCaptchaAutoRefresh()
    }

    /// Called from the sheet's onDismiss closure (user pressed Done / X).
    /// Ensures the timer doesn't keep firing after the WebView is gone.
    func onCaptchaSheetDismissed() {
        if captchaAutoRefreshTimer != nil {
            debugLog("captcha auto-refresh: sheet dismissed by user, stopping timer (attempt was \(captchaRefreshAttempt))")
            stopCaptchaAutoRefresh()
        }
    }

    private func stopCaptchaAutoRefresh() {
        captchaAutoRefreshTimer?.invalidate()
        captchaAutoRefreshTimer = nil
        captchaLimitReached = false
        // Clear any "VK временно ограничивает запросы" message set by a
        // previous exhausted cycle. This runs in two recovery cases:
        //   - onCaptchaReady: a subsequent auto-refresh attempt found a
        //     solvable captcha — the rate limit has lifted, so the old
        //     message is stale.
        //   - onCaptchaSheetDismissed: user closed the WebView; the
        //     message served its purpose (explained why they're seeing the
        //     "attempt limit reached" page) and no longer needs to persist.
        // Note: triggerCaptchaRefresh sets errorMessage AFTER calling us, so
        // clearing it here doesn't interfere with the exhausted-cycle path.
        errorMessage = nil
        // captchaRefreshAttempt intentionally not reset — makes it easier to
        // see the final attempt count in logs / debugger. Zeroed on next
        // onCaptchaLimitDetected() call.
    }

    private func triggerCaptchaRefresh(reason: String) {
        captchaRefreshAttempt += 1
        if captchaRefreshAttempt > maxCaptchaRefreshAttempts {
            debugLog("captcha auto-refresh: exhausted (\(maxCaptchaRefreshAttempts) attempts), giving up")
            stopCaptchaAutoRefresh()
            errorMessage = "VK временно ограничивает запросы. Подождите минуту и попробуйте снова."
            return
        }
        debugLog("captcha auto-refresh: attempt \(captchaRefreshAttempt)/\(maxCaptchaRefreshAttempts) (reason: \(reason)) — requesting fresh URL")
        // refreshCaptchaURL() asks the extension to call wgRefreshCaptchaURL
        // and returns the fresh URL via the IPC response, which populates
        // captchaImageURL. SwiftUI then rebinds the sheet content, our
        // updateUIView sees the URL change and reloads the WKWebView.
        // Same mechanism the first-open path uses; we just call it on a
        // schedule while VK is giving us ERROR_LIMIT pages.
        refreshCaptchaURL()
    }

    func solveCaptcha(answer: String) {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "solve_captcha:\(answer)".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { _ in
                // Don't clear captchaPending here — let the stats polling
                // detect the transition (captcha_image_url becomes empty
                // + activeConns > 0) and clear the UI state. In full-tunnel
                // mode there's nothing else to do after captcha: tunnel
                // settings were already applied during bootstrap.
            }
        } catch {
            // Extension might not be running
        }
    }

    // MARK: - Private

    private func loadManager() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                self.manager = existing
                observeStatus(existing)
            }
        } catch {
            errorMessage = "Failed to load VPN config: \(error.localizedDescription)"
        }
    }

    private func getOrCreateManager() async throws -> NETunnelProviderManager {
        if let manager = self.manager {
            return manager
        }
        let manager = NETunnelProviderManager()
        self.manager = manager
        observeStatus(manager)
        return manager
    }

    private func observeStatus(_ manager: NETunnelProviderManager) {
        statusObserver.map { NotificationCenter.default.removeObserver($0) }
        status = manager.connection.status

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                let newStatus = manager.connection.status
                self.debugLog("NEVPNStatus changed: \(newStatus.rawValue) captchaPending=\(self.captchaPending)")
                self.status = newStatus
                switch newStatus {
                case .connected:
                    // (Re)start polling, preserving captcha state across reconnects
                    self.startStatsPolling(reset: false)
                    // Once the tunnel is actually up, any error message left
                    // over from a captcha-limit exhaustion or other transient
                    // failure is stale — clear it so the user isn't told
                    // "VK временно ограничивает запросы" while staring at a
                    // green 10/10 Connected status.
                    self.errorMessage = nil
                case .connecting, .reasserting:
                    // CRITICAL for Step 4 architecture (deferred-setTunnelNetworkSettings):
                    // When the PoW auto-solver fails on a captcha it can't crack, the
                    // proxy goroutine surfaces the captcha redirect_uri via get_stats
                    // and waits (proxy: "captcha required during startup, waiting for
                    // solution"). The wgWaitBootstrapReady call in the extension's
                    // startTunnel blocks for up to 120s on this. If the main-app
                    // WebView path doesn't poll during .connecting, captchaImageURL
                    // is never surfaced, the WebView never appears, and bootstrap
                    // times out — user sees a silent failure with no chance to solve
                    // the captcha. Polling here closes the loop: main-app sees the
                    // URL, shows the WebView, user solves captcha, solve_captcha
                    // message unblocks the goroutine, bootstrap completes.
                    //
                    // .reasserting included for the same reason — when iOS triggers
                    // a tunnel re-establishment mid-session (e.g. network change),
                    // we go through bootstrap again and may need a fresh captcha.
                    self.startStatsPolling(reset: false)
                case .disconnected, .invalid:
                    // Terminal states — full cleanup
                    self.stopStatsPolling()
                    self.resetCaptchaState()
                default:
                    // .disconnecting only — keep polling/state, the tunnel
                    // may recover momentarily (e.g., sleep/wake cycle).
                    break
                }
            }
        }
    }

    private func startStatsPolling(reset: Bool = true) {
        statsTimer?.invalidate()
        statsTimer = nil
        if reset {
            stats = TunnelStats()
            txRate = 0
            rxRate = 0
            internetRTTms = 0
        }
        prevTx = 0
        prevRx = 0
        prevTime = Date()
        // Fetch immediately, then every 2 seconds.
        // Add to .common RunLoop mode so the timer fires even during
        // UI animations (e.g., SwiftUI sheet dismiss transitions).
        fetchStats()
        let timer = Timer(timeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.fetchStats()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        statsTimer = timer
    }

    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
        // Do NOT clear captcha state here — it must survive across
        // transient status changes (sleep/wake, reasserting).
        // Captcha state is cleared in resetCaptchaState() on terminal disconnect.
        stats = TunnelStats()
        txRate = 0
        rxRate = 0
        internetRTTms = 0
    }

    /// Clear all captcha-related state. Only called on terminal disconnect.
    private func resetCaptchaState() {
        captchaPending = false
        captchaImageURL = nil
        captchaSID = nil
        lastCaptchaShowTime = nil
    }

    private var pingCounter: Int = 0

    private func fetchStats() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "get_stats".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { [weak self] response in
                Task { @MainActor in
                    guard let self = self, let data = response else { return }
                    if let newStats = try? JSONDecoder().decode(TunnelStats.self, from: data) {
                        let now = Date()
                        let dt = now.timeIntervalSince(self.prevTime)
                        if dt > 0 && self.prevTx > 0 {
                            self.txRate = Double(newStats.txBytes - self.prevTx) / dt
                            self.rxRate = Double(newStats.rxBytes - self.prevRx) / dt
                        }
                        self.prevTx = newStats.txBytes
                        self.prevRx = newStats.rxBytes
                        self.prevTime = now
                        self.stats = newStats

                        // Captcha detection and route restoration logic.
                        //
                        // Primary trigger: activeConns > 0 means the DTLS/TURN proxy
                        // successfully connected — captcha is truly resolved.
                        // This replaces the fragile 5-second time-based debounce which
                        // failed because Timer.scheduledTimer uses .default RunLoop mode
                        // and doesn't fire during SwiftUI sheet-dismiss animations.
                        let captchaURL = newStats.captchaImageURL
                        let hasCaptcha = captchaURL != nil && !captchaURL!.isEmpty

                        // Debug: log every stats poll when captcha state is relevant
                        if self.captchaPending || hasCaptcha {
                            self.debugLog("stats: hasCaptcha=\(hasCaptcha) pending=\(self.captchaPending) conns=\(newStats.activeConns)")
                        }

                        if hasCaptcha {
                            if !self.captchaPending {
                                // Only show captcha UI if there are NO active connections.
                                // If connections are alive, traffic flows and the Go-side
                                // probe goroutine will handle captcha retry automatically.
                                // Showing captcha sheet with active connections causes
                                // annoying empty-sheet loops (VK returns stale URLs).
                                if newStats.activeConns > 0 {
                                    self.debugLog("captcha DETECTED but activeConns=\(newStats.activeConns), ignoring (connections alive)")
                                } else {
                                    self.captchaPending = true
                                    self.captchaImageURL = captchaURL
                                    self.captchaSID = newStats.captchaSID
                                    self.lastCaptchaShowTime = Date()
                                    // Ask the extension for a fresh URL just in case
                                    // this stats URL is stale (e.g., app spent time in
                                    // background between Go publishing the URL and us
                                    // rendering the WebView). Does not block.
                                    self.refreshCaptchaURL()
                                    self.debugLog("captcha DETECTED, activeConns=0, refreshed URL")
                                    // DIAGNOSTIC: try URLSession to the same URL the
                                    // WebView is about to load. If URLSession works
                                    // while WebView reports "offline", the issue is
                                    // specific to WKWebView's Web Content Process,
                                    // not main-app network access.
                                    if let urlStr = captchaURL {
                                        self.runCaptchaURLSessionDiagnostic(urlString: urlStr)
                                    }
                                }
                            } else if self.captchaImageURL != captchaURL {
                                // URL changed (e.g., periodic probe got a fresh captcha URL)
                                self.captchaImageURL = captchaURL
                                self.captchaSID = newStats.captchaSID
                                self.debugLog("captcha URL CHANGED")
                            }
                        } else if self.captchaPending && newStats.activeConns > 0 {
                            // Captcha URL is empty AND we have active connections.
                            // This is the reliable signal that captcha was resolved
                            // and the proxy reconnected successfully. In full-tunnel
                            // mode there are no deferred routes to restore — tunnel
                            // settings were applied once in the extension's
                            // setTunnelNetworkSettings call after bootstrap-ready.
                            self.debugLog("captcha RESOLVED — activeConns=\(newStats.activeConns)")
                            self.captchaPending = false
                            self.captchaImageURL = nil
                            self.captchaSID = nil
                            self.lastCaptchaShowTime = nil
                            // If the auto-refresh timer is still ticking (e.g. a
                            // token was captured while overlay was visible),
                            // tear it down explicitly so it can't fire after
                            // the sheet has dismissed.
                            if self.captchaAutoRefreshTimer != nil {
                                self.debugLog("captcha auto-refresh: captcha RESOLVED, stopping timer")
                                self.stopCaptchaAutoRefresh()
                            }
                        }
                    }
                }
            }
        } catch {
            // Extension might not be running
        }

        // Measure internet RTT every 5th poll (~10 sec) to avoid flooding
        pingCounter += 1
        if pingCounter % 5 == 0 {
            measureInternetRTT()
        }
    }

    private func measureInternetRTT() {
        let start = CFAbsoluteTimeGetCurrent()
        let connection = NWConnection(
            host: NWEndpoint.Host("1.1.1.1"),
            port: NWEndpoint.Port(integerLiteral: 443),
            using: .tcp
        )
        let queue = DispatchQueue(label: "rtt-ping")
        var done = false
        connection.stateUpdateHandler = { [weak self] state in
            guard !done else { return }
            switch state {
            case .ready:
                done = true
                let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1000
                connection.cancel()
                Task { @MainActor in
                    self?.internetRTTms = elapsed
                }
            case .failed(_):
                done = true
                connection.cancel()
            case .cancelled:
                done = true
            default:
                break
            }
        }
        connection.start(queue: queue)

        // Timeout after 5 seconds
        queue.asyncAfter(deadline: .now() + 5) {
            if !done {
                done = true
                connection.cancel()
            }
        }
    }

    // MARK: - Config Builders

    /// Thrown by parseWireGuardKey when the user-entered key can't be decoded
    /// to a 32-byte WireGuard key. `localizedDescription` is surfaced via
    /// `TunnelManager.errorMessage` and shown in the UI, so it must be
    /// understandable by a non-technical user.
    enum KeyError: Error, LocalizedError {
        case empty(field: String)
        case invalidBase64(field: String)
        case wrongLength(field: String, got: Int)

        var errorDescription: String? {
            switch self {
            case .empty(let f):
                return "\(f) is empty. Paste the Base64 key from your WireGuard config."
            case .invalidBase64(let f):
                return "\(f) is not valid Base64. Expected 44 characters ending with '=' (output of `wg genkey`)."
            case .wrongLength(let f, let got):
                return "\(f) decoded to \(got) bytes, expected 32. Did you paste the wrong key?"
            }
        }
    }

    /// Convert a user-entered WireGuard key from Base64 to hex (required by
    /// wireguard-go UAPI). Tolerant of:
    ///   - leading/trailing whitespace and newlines (common when pasting
    ///     from `.conf` files or `wg genkey | pbcopy`),
    ///   - URL-safe Base64 (`-_` instead of `+/`),
    ///   - internal whitespace (via `.ignoreUnknownCharacters`).
    /// Returns a 64-char hex string on success; throws a KeyError otherwise.
    private func parseWireGuardKey(_ input: String, field: String) throws -> String {
        var cleaned = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.isEmpty {
            throw KeyError.empty(field: field)
        }
        // Accept URL-safe Base64 by normalizing to standard alphabet.
        cleaned = cleaned
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: cleaned, options: [.ignoreUnknownCharacters]) else {
            throw KeyError.invalidBase64(field: field)
        }
        guard data.count == 32 else {
            throw KeyError.wrongLength(field: field, got: data.count)
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private func buildUAPIConfig(config: TunnelConfig) throws -> String {
        var lines: [String] = []
        lines.append("private_key=\(try parseWireGuardKey(config.privateKey, field: "Private Key"))")
        lines.append("replace_peers=true")
        lines.append("public_key=\(try parseWireGuardKey(config.peerPublicKey, field: "Peer Public Key"))")

        // Endpoint -- this is the "fake" endpoint that WireGuard will use.
        // TURNBind intercepts it, so the actual value doesn't matter much,
        // but we set it to the peer server address for correctness.
        lines.append("endpoint=\(config.peerAddress)")

        if config.persistentKeepalive > 0 {
            lines.append("persistent_keepalive_interval=\(config.persistentKeepalive)")
        }

        for allowedIP in config.allowedIPs.split(separator: ",") {
            lines.append("allowed_ip=\(allowedIP.trimmingCharacters(in: .whitespaces))")
        }

        if let psk = config.presharedKey, !psk.isEmpty {
            lines.append("preshared_key=\(try parseWireGuardKey(psk, field: "Preshared Key"))")
        }

        return lines.joined(separator: "\n")
    }

    private func buildProxyConfig(config: TunnelConfig, vkHostIPs: [String: [String]] = [:]) -> String {
        var dict: [String: Any] = [
            "vk_link": config.vkLink,
            "peer_addr": config.peerAddress,
            "use_dtls": config.useDTLS,
            "use_udp": config.useUDP,
            "num_conns": config.numConnections,
            "cred_pool_ttl_seconds": config.credPoolTTLSeconds,
            "turn_server": config.turnServerOverride ?? "",
            "turn_port": config.turnPortOverride ?? ""
        ]
        if !vkHostIPs.isEmpty {
            dict["vk_host_ips"] = vkHostIPs
        }

        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    /// Resolve VK API hostnames in the main-app process, where we have a
    /// fully-populated network context (DHCP/carrier DNS, sandbox-readable
    /// resolv.conf, working SCDynamicStore, etc.). The resulting host→IP
    /// map is passed to the extension via providerConfiguration so it can
    /// dial these hosts by IP — its own DNS resolution is unreliable
    /// before setTunnelNetworkSettings is called, and we deliberately
    /// don't call setTunnelNetworkSettings until after VK bootstrap.
    ///
    /// Synchronous CFHost: each host typically resolves in 10-50 ms on a
    /// healthy network. With three hosts and a strict 2s budget it adds
    /// well under a second to the connect path. If resolution fails for
    /// some host we just skip it — the extension will get whatever subset
    /// resolved and may still succeed (e.g. login.vk.ru resolved, the
    /// rest will be looked up if needed).
    /// Diagnostic: try several network paths from the main-app process
    /// at the moment captcha is detected (status = .connecting, captcha
    /// pending). The extension can clearly reach VK at this point (it's
    /// solving PoW / fetching captcha API), so the question is which
    /// main-app path also works:
    ///
    ///   1. URLSession (default) — uses iOS Reachability monitor, fast-
    ///      fails with -1009 if monitor says "no network". This is what
    ///      WKWebView uses under the hood and what fails today.
    ///   2. URLSession with waitsForConnectivity=true — tells iOS NOT to
    ///      fail on reachability, attempt the connect anyway.
    ///   3. NWConnection raw TCP — Network framework, lowest level the
    ///      main app can reach without dropping to POSIX sockets. If
    ///      this works while (1) fails, we know the network path is
    ///      open and only the Reachability monitor is lying.
    ///
    /// All three fire in parallel so we see which combination works.
    nonisolated private func runCaptchaURLSessionDiagnostic(urlString: String) {
        guard let url = URL(string: urlString), let host = url.host else { return }
        SharedLogger.shared.log("[AppDebug] [diag] starting 3-way diagnostic → \(host)")

        // 1. Default URLSession — same behavior as WKWebView.
        var request1 = URLRequest(url: url)
        request1.timeoutInterval = 8
        let session1 = URLSession(configuration: .ephemeral)
        session1.dataTask(with: request1) { _, response, error in
            if let error = error as NSError? {
                SharedLogger.shared.log("[AppDebug] [diag] (1) URLSession default: FAIL \(error.domain) code=\(error.code) — \(error.localizedDescription)")
            } else if let http = response as? HTTPURLResponse {
                SharedLogger.shared.log("[AppDebug] [diag] (1) URLSession default: OK HTTP \(http.statusCode)")
            }
        }.resume()

        // 2. URLSession with waitsForConnectivity=true — bypass the
        // Reachability fast-fail, attempt connect even if monitor says
        // "offline". timeoutIntervalForResource caps total wait so we
        // don't hang forever if the path really is dead.
        let cfg2 = URLSessionConfiguration.ephemeral
        cfg2.waitsForConnectivity = true
        cfg2.timeoutIntervalForRequest = 8
        cfg2.timeoutIntervalForResource = 10
        let session2 = URLSession(configuration: cfg2)
        var request2 = URLRequest(url: url)
        request2.timeoutInterval = 8
        session2.dataTask(with: request2) { _, response, error in
            if let error = error as NSError? {
                SharedLogger.shared.log("[AppDebug] [diag] (2) URLSession waitsForConnectivity=true: FAIL \(error.domain) code=\(error.code) — \(error.localizedDescription)")
            } else if let http = response as? HTTPURLResponse {
                SharedLogger.shared.log("[AppDebug] [diag] (2) URLSession waitsForConnectivity=true: OK HTTP \(http.statusCode)")
            }
        }.resume()

        // 3. Raw NWConnection TCP — Network framework, sidesteps URLSession's
        // pre-flight Reachability check. Just opens a TLS connection and
        // reports whether it gets to "ready" state.
        let port = NWEndpoint.Port(integerLiteral: UInt16(url.port ?? 443))
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: port)
        let conn = NWConnection(to: endpoint, using: .tls)
        let started = Date()
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ms = Int(Date().timeIntervalSince(started) * 1000)
                SharedLogger.shared.log("[AppDebug] [diag] (3) NWConnection TLS: READY in \(ms)ms")
                conn.cancel()
            case .failed(let err):
                SharedLogger.shared.log("[AppDebug] [diag] (3) NWConnection TLS: FAIL \(err.localizedDescription)")
                conn.cancel()
            case .waiting(let err):
                SharedLogger.shared.log("[AppDebug] [diag] (3) NWConnection TLS: WAITING — \(err.localizedDescription)")
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        // Hard cap — cancel after 8s if we never reached ready/failed.
        DispatchQueue.global().asyncAfter(deadline: .now() + 8) {
            if conn.state != .cancelled {
                SharedLogger.shared.log("[AppDebug] [diag] (3) NWConnection TLS: TIMED OUT in current state \(conn.state)")
                conn.cancel()
            }
        }
    }

    /// Resolve VK API hostnames in the main-app process. Returns the
    /// FULL list of IPv4 addresses for each host so the extension can
    /// fall through them on connect failure — relying on a single IP
    /// is brittle when VK rotates DNS A-records or when an upstream
    /// network path to one specific IP is temporarily unreachable.
    nonisolated private func resolveVKHosts() -> [String: [String]] {
        let hosts = ["login.vk.ru", "api.vk.ru", "id.vk.ru"]
        var resolved: [String: [String]] = [:]

        for host in hosts {
            let cfhost = CFHostCreateWithName(nil, host as CFString).takeRetainedValue()
            var info: DarwinBoolean = false
            guard CFHostStartInfoResolution(cfhost, .addresses, nil),
                  let addrs = CFHostGetAddressing(cfhost, &info)?.takeUnretainedValue() as? [Data] else {
                continue
            }
            var ips: [String] = []
            for addrData in addrs {
                let ip: String? = addrData.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> String? in
                    guard let saPtr = ptr.baseAddress?.assumingMemoryBound(to: sockaddr.self) else {
                        return nil
                    }
                    if saPtr.pointee.sa_family == sa_family_t(AF_INET) {
                        let sin = saPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                        var addr = sin.sin_addr
                        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                        if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                            return String(cString: buf)
                        }
                    }
                    return nil
                }
                if let ip = ip, !ips.contains(ip) {
                    ips.append(ip)
                }
            }
            if !ips.isEmpty {
                resolved[host] = ips
            }
        }

        return resolved
    }

    /// Diagnostic: try a TCP+TLS handshake from the main-app process to
    /// each pre-resolved IP. Logs whether the IP is reachable from this
    /// network. If main app reports the same "no route to host" — the IP
    /// genuinely isn't reachable, not an extension routing bug.
    nonisolated private func diagnoseIPReachability(_ hostIPs: [String: [String]]) {
        for (host, ips) in hostIPs {
            for ip in ips {
                guard let url = URL(string: "https://\(ip)/") else { continue }
                var request = URLRequest(url: url)
                request.setValue(host, forHTTPHeaderField: "Host")
                request.timeoutInterval = 5
                let session = URLSession(configuration: .ephemeral)
                SharedLogger.shared.log("[AppDebug] [diag] reachability ping → \(host) @ \(ip)")
                let task = session.dataTask(with: request) { _, response, error in
                    if let error = error as NSError? {
                        SharedLogger.shared.log("[AppDebug] [diag] \(host) @ \(ip): FAIL \(error.domain) code=\(error.code) — \(error.localizedDescription)")
                    } else if let http = response as? HTTPURLResponse {
                        SharedLogger.shared.log("[AppDebug] [diag] \(host) @ \(ip): OK HTTP \(http.statusCode)")
                    } else {
                        SharedLogger.shared.log("[AppDebug] [diag] \(host) @ \(ip): no response, no error")
                    }
                }
                task.resume()
            }
        }
    }

}

// MARK: - Tunnel Configuration Model

struct TunnelConfig {
    // WireGuard
    var privateKey: String = ""
    var peerPublicKey: String = ""
    var presharedKey: String?
    var tunnelAddress: String = "192.168.102.3/24"
    var dnsServers: String = "1.1.1.1"
    var allowedIPs: String = "0.0.0.0/0"
    var mtu: String = "1280"
    var persistentKeepalive: Int = 25

    // Proxy
    var vkLink: String = ""
    var peerAddress: String = ""  // vk-turn-proxy server host:port
    var useDTLS: Bool = true
    var useUDP: Bool = true
    var numConnections: Int = 10 // configurable from Settings (VK allows max ~10 allocations)
    // Per-entry TTL for the cred pool. Drives when the background grower
    // considers a slot "stale" and tries to refetch it, and when a get()
    // / fallback stops treating a slot as fresh. Default 600s (10 min).
    // Longer = less PoW/VK pressure but more risk of caching creds past
    // their server-side validity.
    var credPoolTTLSeconds: Int = 600
    var turnServerOverride: String?
    var turnPortOverride: String?
}
