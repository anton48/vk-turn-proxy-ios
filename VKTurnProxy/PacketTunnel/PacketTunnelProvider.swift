import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var tunnelHandle: Int32 = -1
    private let log = OSLog(subsystem: "com.vkturnproxy.tunnel", category: "PacketTunnel")

    // Saved for deferred PHASE 2 (when captcha is pending at startup)
    private var pendingTunnelAddress: String?
    private var pendingDNS: String?
    private var pendingMTU: String?
    private var pendingExcludeHosts: [String] = []

    // VK domains that must bypass the tunnel (for captcha WebView & credential fetching).
    // These are resolved to IPs at startup and excluded from VPN routing.
    private static let vkCaptchaDomains = [
        "id.vk.ru",
        "api.vk.ru",
        "vk.ru",
        "login.vk.ru",
        "api.vk.com",
        "login.vk.com",
        "calls.okcdn.ru"
    ]

    private func logMsg(_ msg: String) {
        os_log("%{public}s", log: log, type: .default, msg)
        NSLog("[PacketTunnel] %@", msg)
        SharedLogger.shared.log("[Tunnel] \(msg)")
    }

    /// Resolve VK captcha/auth domains to IP addresses for route exclusion.
    /// This ensures the captcha WebView and VK credential requests bypass the tunnel.
    private func resolveVKHosts() -> [String] {
        var ips = Set<String>()
        for domain in Self.vkCaptchaDomains {
            let host = CFHostCreateWithName(nil, domain as CFString).takeRetainedValue()
            var resolved = DarwinBoolean(false)
            CFHostStartInfoResolution(host, .addresses, nil)
            if let addresses = CFHostGetAddressing(host, &resolved)?.takeUnretainedValue() as? [Data] {
                for addrData in addresses {
                    addrData.withUnsafeBytes { ptr in
                        let sa = ptr.assumingMemoryBound(to: sockaddr.self).baseAddress!
                        if sa.pointee.sa_family == AF_INET {
                            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                            if let ipStr = String(cString: inet_ntoa(addr.sin_addr), encoding: .ascii) {
                                ips.insert(ipStr)
                            }
                        }
                    }
                }
            }
        }
        logMsg("resolveVKHosts: resolved \(ips.count) unique IPs from \(Self.vkCaptchaDomains.count) domains: \(ips.sorted())")
        return Array(ips)
    }

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {

        logMsg("startTunnel called")

        // Configure Go log file path so Go logs also go to the shared file
        if let path = SharedLogger.shared.logFilePath {
            path.withCString { ptr in
                wgSetLogFilePath(UnsafeMutablePointer(mutating: ptr))
            }
            logMsg("Go log file path set: \(path)")
        }

        // Tell Go the local timezone offset so log timestamps match Swift logs
        let tzOffset = TimeZone.current.secondsFromGMT()
        wgSetTimezoneOffset(Int32(tzOffset))

        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else {
            logMsg("ERROR: no provider configuration")
            completionHandler(VPNError.noConfiguration)
            return
        }

        guard let wgConfig = config["wg_config"] as? String,
              let proxyConfigJSON = config["proxy_config"] as? String else {
            logMsg("ERROR: missing wg_config or proxy_config")
            completionHandler(VPNError.invalidConfiguration)
            return
        }

        let tunnelAddress = config["tunnel_address"] as? String ?? "192.168.102.3/24"
        let dnsServers = config["dns_servers"] as? String ?? "1.1.1.1"
        let mtu = config["mtu"] as? String ?? "1280"

        logMsg("tunnelAddress=\(tunnelAddress) dns=\(dnsServers) mtu=\(mtu)")
        logMsg("proxyConfig=\(proxyConfigJSON)")

        // Parse proxy config to extract peer address for route exclusion
        var peerHost: String?
        if let proxyData = proxyConfigJSON.data(using: .utf8),
           let proxyDict = try? JSONSerialization.jsonObject(with: proxyData) as? [String: Any],
           let peerAddr = proxyDict["peer_addr"] as? String {
            let host = peerAddr.split(separator: ":").first.map(String.init)
            peerHost = host
            logMsg("peerHost=\(host ?? "nil")")
        } else {
            logMsg("WARNING: could not parse peer_addr from proxy config")
        }

        // PHASE 1: Set initial network settings WITHOUT capturing all traffic.
        // This creates the TUN interface so we can get its file descriptor.
        let initialSettings = createTunnelSettings(
            address: tunnelAddress,
            dns: dnsServers,
            mtu: mtu,
            captureTraffic: false,
            excludeHosts: []
        )

        logMsg("PHASE 1: setting initial tunnel settings (no routes)")
        setTunnelNetworkSettings(initialSettings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                self.logMsg("PHASE 1 ERROR: \(error)")
                completionHandler(error)
                return
            }
            self.logMsg("PHASE 1: settings applied OK")

            guard let tunFd = self.findTunFileDescriptor() else {
                self.logMsg("ERROR: could not find TUN fd")
                completionHandler(VPNError.noTunDevice)
                return
            }
            self.logMsg("TUN fd=\(tunFd)")

            // Start WireGuard + TURN proxy
            self.logMsg("calling wgTurnOnWithTURN...")
            let handle = wgConfig.withCString { settingsPtr in
                proxyConfigJSON.withCString { proxyPtr in
                    wgTurnOnWithTURN(
                        UnsafeMutablePointer(mutating: settingsPtr),
                        tunFd,
                        UnsafeMutablePointer(mutating: proxyPtr)
                    )
                }
            }

            if handle < 0 {
                self.logMsg("ERROR: wgTurnOnWithTURN returned \(handle)")
                completionHandler(VPNError.backendFailed(code: handle))
                return
            }

            self.tunnelHandle = handle
            self.logMsg("wgTurnOnWithTURN OK, handle=\(handle)")

            // Check if captcha is pending — if so, skip PHASE 2 so the WebView
            // can load the captcha page over the normal network (not through the
            // non-functional VPN tunnel).
            var captchaPending = false
            if let statsPtr = wgGetStats(handle) {
                let statsJSON = String(cString: statsPtr)
                free(UnsafeMutableRawPointer(mutating: statsPtr))
                if let data = statsJSON.data(using: .utf8),
                   let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let captchaURL = dict["captcha_image_url"] as? String,
                   !captchaURL.isEmpty {
                    captchaPending = true
                    self.logMsg("Captcha pending — deferring PHASE 2 (no routes until captcha solved)")
                }
            }

            // PHASE 2: Set final settings with default route and excluded routes
            // for TURN server, peer server, and VK captcha/auth domain IPs
            // (so their traffic bypasses the tunnel).
            var excludeHosts: [String] = []
            if let peer = peerHost {
                excludeHosts.append(peer)
            }

            if let turnIPPtr = wgGetTURNServerIP(handle) {
                let turnIP = String(cString: turnIPPtr)
                free(UnsafeMutableRawPointer(mutating: turnIPPtr))
                if !turnIP.isEmpty {
                    excludeHosts.append(turnIP)
                    self.logMsg("TURN server IP=\(turnIP)")
                } else {
                    self.logMsg("WARNING: TURN server IP is empty")
                }
            } else {
                self.logMsg("WARNING: wgGetTURNServerIP returned nil")
            }

            // Resolve VK captcha/auth domains and exclude their IPs.
            // This ensures the captcha WebView can load even when the tunnel is dead
            // (e.g., after phone sleep/lock or cell handoff).
            let vkIPs = self.resolveVKHosts()
            for ip in vkIPs {
                if !excludeHosts.contains(ip) {
                    excludeHosts.append(ip)
                }
            }

            if captchaPending {
                // Save settings for later when captcha is solved
                self.pendingTunnelAddress = tunnelAddress
                self.pendingDNS = dnsServers
                self.pendingMTU = mtu
                self.pendingExcludeHosts = excludeHosts
                self.logMsg("PHASE 2 deferred — tunnel started without routes")
                completionHandler(nil)
                return
            }

            self.logMsg("PHASE 2: excludeHosts=\(excludeHosts)")

            let finalSettings = self.createTunnelSettings(
                address: tunnelAddress,
                dns: dnsServers,
                mtu: mtu,
                captureTraffic: true,
                excludeHosts: excludeHosts
            )

            self.logMsg("PHASE 2: applying final settings with default route")
            self.setTunnelNetworkSettings(finalSettings) { error in
                if let error = error {
                    self.logMsg("PHASE 2 ERROR: \(error)")
                    completionHandler(error)
                    return
                }
                self.logMsg("PHASE 2: settings applied OK - tunnel ready")
                completionHandler(nil)
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let msg = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        if msg == "get_stats" {
            guard tunnelHandle >= 0 else {
                completionHandler?(nil)
                return
            }
            if let ptr = wgGetStats(tunnelHandle) {
                let json = String(cString: ptr)
                free(UnsafeMutableRawPointer(mutating: ptr))
                completionHandler?(json.data(using: .utf8))
            } else {
                completionHandler?(nil)
            }
        } else if msg.hasPrefix("solve_captcha:") {
            let answer = String(msg.dropFirst("solve_captcha:".count))
            logMsg("handleAppMessage: captcha answer received (\(answer.count) chars)")
            if tunnelHandle >= 0 {
                answer.withCString { ptr in
                    wgSolveCaptcha(tunnelHandle, UnsafeMutablePointer(mutating: ptr))
                }
            }
            completionHandler?("ok".data(using: .utf8))
        } else if msg == "apply_routes" {
            logMsg("handleAppMessage: apply_routes — applying deferred PHASE 2")
            applyDeferredRoutes { success in
                completionHandler?(success ? "ok".data(using: .utf8) : nil)
            }
        } else if msg == "suspend_dns" {
            logMsg("handleAppMessage: suspend_dns — removing VPN DNS so system uses provider DNS")
            suspendDNSForCaptcha()
            completionHandler?("ok".data(using: .utf8))
        } else if msg == "refresh_captcha_and_suspend_dns" {
            logMsg("handleAppMessage: refresh_captcha_and_suspend_dns — refreshing captcha URL and suspending DNS")
            suspendDNSForCaptcha()
            // Call wgRefreshCaptchaURL to get a fresh captcha URL from VK
            var freshURL = ""
            if tunnelHandle >= 0 {
                if let ptr = wgRefreshCaptchaURL(tunnelHandle) {
                    freshURL = String(cString: ptr)
                    free(UnsafeMutableRawPointer(mutating: ptr))
                    logMsg("refreshCaptchaURL: got fresh URL (\(freshURL.prefix(80))...)")
                }
            }
            completionHandler?(freshURL.data(using: .utf8))
        } else if msg == "restore_dns" {
            logMsg("handleAppMessage: restore_dns — restoring VPN DNS after captcha")
            restoreDNSAfterCaptcha()
            completionHandler?("ok".data(using: .utf8))
        } else {
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        logMsg("sleep() — pausing proxy connections")
        if tunnelHandle >= 0 {
            wgPause(tunnelHandle)
        }
        completionHandler()
    }

    override func wake() {
        logMsg("wake() — resuming proxy connections")
        if tunnelHandle >= 0 {
            wgResume(tunnelHandle)
        }

        // After wake, the network path may have changed (cell handoff, Wi-Fi switch).
        // Re-resolve VK domain IPs and refresh route exclusions so the captcha WebView
        // and credential fetching still work over the new network path.
        if pendingTunnelAddress == nil {
            // Only refresh if PHASE 2 was already applied (not deferred)
            refreshRouteExclusions()
        }
    }

    /// Build the current list of IPs that should bypass the tunnel.
    private func buildCurrentExcludeHosts(proxyConfigJSON: String) -> [String] {
        var excludeHosts: [String] = []

        // Peer host
        if let proxyData = proxyConfigJSON.data(using: .utf8),
           let proxyDict = try? JSONSerialization.jsonObject(with: proxyData) as? [String: Any],
           let peerAddr = proxyDict["peer_addr"] as? String,
           let host = peerAddr.split(separator: ":").first.map(String.init) {
            excludeHosts.append(host)
        }

        // TURN server IP
        if tunnelHandle >= 0, let turnIPPtr = wgGetTURNServerIP(tunnelHandle) {
            let turnIP = String(cString: turnIPPtr)
            free(UnsafeMutableRawPointer(mutating: turnIPPtr))
            if !turnIP.isEmpty && !excludeHosts.contains(turnIP) {
                excludeHosts.append(turnIP)
            }
        }

        // VK captcha/auth domain IPs
        let vkIPs = resolveVKHosts()
        for ip in vkIPs {
            if !excludeHosts.contains(ip) {
                excludeHosts.append(ip)
            }
        }

        return excludeHosts
    }

    /// Re-apply network settings with freshly resolved VK domain IPs.
    /// Called after wake to handle network path changes (cell handoff, Wi-Fi switch).
    private func refreshRouteExclusions() {
        guard tunnelHandle >= 0 else { return }

        // Get current tunnel settings from the saved config
        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let proxyConfigJSON = config["proxy_config"] as? String else {
            logMsg("refreshRouteExclusions: no config available")
            return
        }

        let tunnelAddress = config["tunnel_address"] as? String ?? "192.168.102.3/24"
        let dnsServers = config["dns_servers"] as? String ?? "1.1.1.1"
        let mtu = config["mtu"] as? String ?? "1280"

        let excludeHosts = buildCurrentExcludeHosts(proxyConfigJSON: proxyConfigJSON)

        logMsg("refreshRouteExclusions: excludeHosts=\(excludeHosts)")

        let settings = createTunnelSettings(
            address: tunnelAddress,
            dns: dnsServers,
            mtu: mtu,
            captureTraffic: true,
            excludeHosts: excludeHosts
        )

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logMsg("refreshRouteExclusions ERROR: \(error)")
            } else {
                self?.logMsg("refreshRouteExclusions: routes refreshed OK")
                // Mark PHASE 2 as complete — routes + DNS are now active.
                // This is important: if PHASE 2 was deferred (startup captcha) and
                // restoreDNS called refreshRouteExclusions, we must clear pending state
                // so future suspendDNSForCaptcha calls (reconnect captcha) actually work.
                self?.pendingTunnelAddress = nil
            }
        }
    }

    /// Temporarily remove VPN DNS settings so the system falls back to provider DNS
    /// (cellular/WiFi DHCP). Called when captcha is needed during reconnection — the tunnel
    /// is dead so DNS queries to 1.1.1.1 through TUN would fail, preventing WebView from
    /// resolving VK hostnames. Routes stay intact (VK IPs are already excluded).
    private func suspendDNSForCaptcha() {
        // If PHASE 2 is still deferred (startup captcha), there are no routes or DNS to suspend.
        // The TUN has no includedRoutes, so traffic goes direct — WebView works as-is.
        if pendingTunnelAddress != nil {
            logMsg("suspendDNSForCaptcha: PHASE 2 deferred — no routes/DNS to suspend, skipping")
            return
        }

        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let proxyConfigJSON = config["proxy_config"] as? String else {
            logMsg("suspendDNSForCaptcha: no config available")
            return
        }

        let tunnelAddress = config["tunnel_address"] as? String ?? "192.168.102.3/24"
        let mtu = config["mtu"] as? String ?? "1280"

        // Rebuild current route exclusions (keep routes intact)
        var excludeHosts = buildCurrentExcludeHosts(proxyConfigJSON: proxyConfigJSON)

        logMsg("suspendDNSForCaptcha: keeping routes, excludeHosts=\(excludeHosts)")

        // Create settings WITH routes but WITHOUT DNS — system falls back to provider DNS
        let settings = createTunnelSettings(
            address: tunnelAddress,
            dns: "",  // empty = no VPN DNS override
            mtu: mtu,
            captureTraffic: true,
            excludeHosts: excludeHosts
        )

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logMsg("suspendDNSForCaptcha ERROR: \(error)")
            } else {
                self?.logMsg("suspendDNSForCaptcha: VPN DNS removed — system uses provider DNS")
            }
        }
    }

    /// Restore VPN DNS settings after captcha is solved. Also refreshes route exclusions.
    private func restoreDNSAfterCaptcha() {
        // Just re-apply full settings with DNS — same as refreshRouteExclusions
        refreshRouteExclusions()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if tunnelHandle >= 0 {
            wgTurnOff(tunnelHandle)
            tunnelHandle = -1
        }
        completionHandler()
    }

    // MARK: - Deferred Route Application

    private func applyDeferredRoutes(completion: @escaping (Bool) -> Void) {
        guard let address = pendingTunnelAddress,
              let dns = pendingDNS,
              let mtu = pendingMTU else {
            logMsg("applyDeferredRoutes: no pending settings")
            completion(false)
            return
        }

        // Re-check TURN server IP (may have been resolved after captcha)
        var excludeHosts = pendingExcludeHosts
        if let turnIPPtr = wgGetTURNServerIP(tunnelHandle) {
            let turnIP = String(cString: turnIPPtr)
            free(UnsafeMutableRawPointer(mutating: turnIPPtr))
            if !turnIP.isEmpty && !excludeHosts.contains(turnIP) {
                excludeHosts.append(turnIP)
                logMsg("applyDeferredRoutes: added TURN IP=\(turnIP)")
            }
        }

        // Re-resolve VK captcha/auth domain IPs (may have changed since startup)
        let vkIPs = resolveVKHosts()
        for ip in vkIPs {
            if !excludeHosts.contains(ip) {
                excludeHosts.append(ip)
            }
        }

        let finalSettings = createTunnelSettings(
            address: address,
            dns: dns,
            mtu: mtu,
            captureTraffic: true,
            excludeHosts: excludeHosts
        )

        logMsg("applyDeferredRoutes: excludeHosts=\(excludeHosts)")
        setTunnelNetworkSettings(finalSettings) { [weak self] error in
            if let error = error {
                self?.logMsg("applyDeferredRoutes ERROR: \(error)")
                completion(false)
            } else {
                self?.logMsg("applyDeferredRoutes: routes applied OK — tunnel fully active")
                self?.pendingTunnelAddress = nil
                completion(true)
            }
        }
    }

    // MARK: - Network Settings

    private func createTunnelSettings(
        address: String,
        dns: String,
        mtu: String,
        captureTraffic: Bool,
        excludeHosts: [String]
    ) -> NEPacketTunnelNetworkSettings {
        let parts = address.split(separator: "/")
        let ip = String(parts[0])
        let prefix = parts.count > 1 ? Int(parts[1]) ?? 24 : 24

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: [prefixToSubnet(prefix)])

        if captureTraffic {
            ipv4.includedRoutes = [NEIPv4Route.default()]
            ipv4.excludedRoutes = excludeHosts.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
            }
        }

        settings.ipv4Settings = ipv4

        // Only set DNS in Phase 2 (captureTraffic=true) and when dns is non-empty.
        // Setting DNS in Phase 1 can cause Go HTTP requests to hang
        // because the TUN interface isn't routing traffic yet.
        // Empty dns string = no VPN DNS override (system uses provider DNS).
        if captureTraffic && !dns.isEmpty {
            let dnsAddresses = dns.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
            settings.dnsSettings = NEDNSSettings(servers: dnsAddresses)
        }

        if let mtuInt = Int(mtu) {
            settings.mtu = NSNumber(value: mtuInt)
        }

        return settings
    }

    private func prefixToSubnet(_ prefix: Int) -> String {
        var mask: UInt32 = 0
        for i in 0..<prefix {
            mask |= (1 << (31 - i))
        }
        return "\(mask >> 24).\((mask >> 16) & 0xFF).\((mask >> 8) & 0xFF).\(mask & 0xFF)"
    }

    // MARK: - TUN File Descriptor Discovery

    private func findTunFileDescriptor() -> Int32? {
        var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(buf.count)
            if getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buf, &len) == 0 {
                let name = String(cString: buf)
                if name.hasPrefix("utun") {
                    return fd
                }
            }
        }
        return nil
    }
}

// MARK: - Errors

enum VPNError: Error, LocalizedError {
    case noConfiguration
    case invalidConfiguration
    case noTunDevice
    case backendFailed(code: Int32)

    var errorDescription: String? {
        switch self {
        case .noConfiguration: return "No provider configuration found"
        case .invalidConfiguration: return "Invalid or missing configuration fields"
        case .noTunDevice: return "Could not find TUN file descriptor"
        case .backendFailed(let code): return "WireGuard backend failed with code \(code)"
        }
    }
}
