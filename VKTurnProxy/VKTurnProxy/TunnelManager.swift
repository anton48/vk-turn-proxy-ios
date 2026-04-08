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
    private var dnsSuspended = false  // true when routes removed for reconnect captcha
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
            }
        }
    }

    // MARK: - Public API

    func connect(config: TunnelConfig) async {
        errorMessage = nil

        do {
            let manager = try await getOrCreateManager()

            // Build UAPI config string for WireGuard
            let wgConfig = buildUAPIConfig(config: config)

            // Build proxy config JSON
            let proxyConfig = buildProxyConfig(config: config)

            // Set provider configuration
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.vkturnproxy.app.tunnel"
            proto.serverAddress = config.peerAddress
            proto.providerConfiguration = [
                "wg_config": wgConfig,
                "proxy_config": proxyConfig,
                "tunnel_address": config.tunnelAddress,
                "dns_servers": config.dnsServers,
                "mtu": config.mtu
            ]

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

    func applyDeferredRoutes() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "apply_routes".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { _ in }
        } catch {
            // Extension might not be running
        }
    }

    /// Temporarily remove VPN DNS settings so system uses provider DNS (cellular/WiFi).
    /// Called when captcha is needed during reconnection (tunnel is dead, DNS to 1.1.1.1
    /// through TUN would fail, preventing WebView from resolving VK hostnames).
    func suspendDNS() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        // Ask extension to refresh captcha URL (fresh VK API call) AND suspend DNS.
        // The extension returns the fresh URL in the response data.
        guard let msg = "refresh_captcha_and_suspend_dns".data(using: .utf8) else { return }
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

    /// Restore VPN DNS settings after captcha is solved.
    func restoreDNS() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "restore_dns".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { _ in }
        } catch {}
    }

    func solveCaptcha(answer: String) {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let msg = "solve_captcha:\(answer)".data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(msg) { _ in
                // Don't clear captchaPending here — let the stats polling
                // detect the transition (captcha_image_url becomes empty)
                // and trigger applyDeferredRoutes().
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
                self.debugLog("NEVPNStatus changed: \(newStatus.rawValue) captchaPending=\(self.captchaPending) dnsSusp=\(self.dnsSuspended)")
                self.status = newStatus
                switch newStatus {
                case .connected:
                    // (Re)start polling, preserving captcha state across reconnects
                    self.startStatsPolling(reset: false)
                case .disconnected, .invalid:
                    // Terminal states — full cleanup
                    self.stopStatsPolling()
                    self.resetCaptchaState()
                default:
                    // Transient states (.connecting, .disconnecting, .reasserting)
                    // Do NOT stop polling or clear captcha state — the tunnel
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
        dnsSuspended = false
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
                            self.debugLog("stats: hasCaptcha=\(hasCaptcha) pending=\(self.captchaPending) dnsSusp=\(self.dnsSuspended) conns=\(newStats.activeConns)")
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
                                if self.status == .connected {
                                    self.suspendDNS()
                                    self.dnsSuspended = true
                                }
                                self.debugLog("captcha DETECTED, activeConns=0, suspendDNS=\(self.status == .connected)")
                                }
                            } else if self.captchaImageURL != captchaURL {
                                // URL changed (e.g., periodic probe got a fresh captcha URL)
                                self.captchaImageURL = captchaURL
                                self.captchaSID = newStats.captchaSID
                                if self.status == .connected && self.dnsSuspended {
                                    self.suspendDNS()
                                }
                                self.debugLog("captcha URL CHANGED")
                            }
                        } else if self.captchaPending && newStats.activeConns > 0 {
                            // Captcha URL is empty AND we have active connections.
                            // This is the reliable signal that captcha was resolved
                            // and the proxy reconnected successfully.
                            self.debugLog("captcha RESOLVED — activeConns=\(newStats.activeConns), restoring routes, dnsSusp=\(self.dnsSuspended)")
                            self.captchaPending = false
                            self.captchaImageURL = nil
                            self.captchaSID = nil
                            self.lastCaptchaShowTime = nil
                            if self.dnsSuspended {
                                self.restoreDNS()
                                self.dnsSuspended = false
                            } else {
                                self.applyDeferredRoutes()
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

    private func buildUAPIConfig(config: TunnelConfig) -> String {
        var lines: [String] = []
        lines.append("private_key=\(hexKey(base64: config.privateKey))")
        lines.append("replace_peers=true")
        lines.append("public_key=\(hexKey(base64: config.peerPublicKey))")

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
            lines.append("preshared_key=\(hexKey(base64: psk))")
        }

        return lines.joined(separator: "\n")
    }

    private func buildProxyConfig(config: TunnelConfig) -> String {
        let dict: [String: Any] = [
            "vk_link": config.vkLink,
            "peer_addr": config.peerAddress,
            "use_dtls": config.useDTLS,
            "use_udp": config.useUDP,
            "num_conns": config.numConnections,
            "turn_server": config.turnServerOverride ?? "",
            "turn_port": config.turnPortOverride ?? ""
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    /// Convert base64 WireGuard key to hex string.
    private func hexKey(base64: String) -> String {
        guard let data = Data(base64Encoded: base64) else { return "" }
        return data.map { String(format: "%02x", $0) }.joined()
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
    var turnServerOverride: String?
    var turnPortOverride: String?
}
