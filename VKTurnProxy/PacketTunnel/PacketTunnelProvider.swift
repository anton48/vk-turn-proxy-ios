import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var tunnelHandle: Int32 = -1
    private let log = OSLog(subsystem: "com.vkturnproxy.tunnel", category: "PacketTunnel")

    private func logMsg(_ msg: String) {
        os_log("%{public}s", log: log, type: .default, msg)
        NSLog("[PacketTunnel] %@", msg)
        SharedLogger.shared.log("[Tunnel] \(msg)")
    }

    // Shared-state key for the TURN server IP the Go proxy is currently
    // running on. Written by this extension whenever it queries the IP via
    // wgGetTURNServerIP, read by TunnelManager on each connect() to set
    // NEVPNProtocol.serverAddress. Making serverAddress match the actual
    // TURN relay IP puts that address on Apple's always-excluded list,
    // which is the only documented way to keep TURN UDP outside the
    // tunnel when includeAllNetworks=true (Step 4 switches to that mode).
    //
    // Before Step 4 this is belt-and-suspenders: the excludedRoutes
    // machinery still carries TURN IP, so current builds behave the same
    // whether serverAddress matches or not. After Step 4, excludedRoutes
    // is ignored and serverAddress becomes the only mechanism.
    private static let sharedDefaultsSuiteName = "group.com.vkturnproxy.app"
    private static let turnServerIPKey = "lastTurnServerIP"

    private func persistTurnServerIP(_ ip: String) {
        guard !ip.isEmpty else { return }
        guard let shared = UserDefaults(suiteName: Self.sharedDefaultsSuiteName) else {
            logMsg("persistTurnServerIP: UserDefaults(suiteName:) returned nil — AppGroup misconfigured?")
            return
        }
        if shared.string(forKey: Self.turnServerIPKey) != ip {
            shared.set(ip, forKey: Self.turnServerIPKey)
            logMsg("persistTurnServerIP: saved \(ip) to AppGroup for next connect()'s serverAddress")
        }
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

        // ------------------------------------------------------------------
        // Deferred-setTunnelNetworkSettings bootstrap flow (Step 4 of the
        // APNs-through-tunnel refactor). We do NOT call setTunnelNetworkSettings
        // before Go has a live DTLS+TURN session.
        //
        // The reason this matters: iOS treats `setTunnelNetworkSettings(_)` as
        // "tunnel up" — that's the moment includeAllNetworks=true starts
        // capturing main-app traffic into the (still-unattached) TUN. If we
        // were to call it early to give the extension a DNS context, the
        // captcha WebView in the main app would lose all network access
        // ("offline") for the duration of bootstrap. Instead, the extension
        // resolves VK hosts via vkDirectResolver (Cloudflare 1.1.1.1:53 over
        // UDP) — see pkg/proxy/utls.go — bypassing the iOS system resolver
        // entirely. UDP to 1.1.1.1 works fine on the physical interface
        // before any routes are installed.
        //
        // Sequence:
        //   1. wgStartVKBootstrap      — launches the Go proxy in a goroutine
        //                                (VK API + TURN alloc + DTLS). No TUN.
        //   2. wgWaitBootstrapReady    — blocks up to 120s for the first conn
        //                                to report ready. Main-app polls
        //                                get_stats during .connecting status
        //                                so captchaImageURL surfaces in time
        //                                to show the WebView (the WebView
        //                                works because TUN doesn't exist yet,
        //                                so includeAllNetworks=true has
        //                                nothing to enforce — main-app
        //                                traffic flows via the physical
        //                                interface naturally).
        //   3. setTunnelNetworkSettings — applied ONCE with the full routes.
        //                                Only now does iOS honor
        //                                includeAllNetworks=true.
        //   4. wgAttachWireGuard       — opens the TUN fd and hands it to
        //                                WireGuard, which starts forwarding
        //                                packets through the already-live
        //                                TURN session.
        // ------------------------------------------------------------------
        logMsg("wgStartVKBootstrap: launching VK bootstrap goroutine...")
        let handle = proxyConfigJSON.withCString { proxyPtr in
            wgStartVKBootstrap(UnsafeMutablePointer(mutating: proxyPtr))
        }
        if handle < 0 {
            logMsg("ERROR: wgStartVKBootstrap returned \(handle)")
            completionHandler(VPNError.backendFailed(code: handle))
            return
        }
        self.tunnelHandle = handle
        logMsg("wgStartVKBootstrap OK, handle=\(handle)")

        // Wait for bootstrap in the background so completionHandler isn't
        // held for the entire (possibly captcha-solving) duration from the
        // main thread. 120s matches turnbridge's budget and comfortably
        // covers a manual captcha solve in the WebView.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let ready = wgWaitBootstrapReady(handle, 120_000)
            switch ready {
            case 1:
                self.logMsg("wgWaitBootstrapReady: ready")
            case 0:
                self.logMsg("wgWaitBootstrapReady: timeout after 120s — aborting")
                wgTurnOff(handle)
                self.tunnelHandle = -1
                completionHandler(VPNError.bootstrapTimeout)
                return
            default:
                self.logMsg("wgWaitBootstrapReady: failed with code \(ready) — aborting")
                wgTurnOff(handle)
                self.tunnelHandle = -1
                completionHandler(VPNError.backendFailed(code: ready))
                return
            }

            // Read the TURN server IP that Go picked during bootstrap and
            // persist it to the AppGroup so TunnelManager.connect() can use
            // it as NEVPNProtocol.serverAddress on the NEXT connect (Step 3).
            var turnIP = ""
            if let turnIPPtr = wgGetTURNServerIP(handle) {
                turnIP = String(cString: turnIPPtr)
                free(UnsafeMutableRawPointer(mutating: turnIPPtr))
            }
            if turnIP.isEmpty {
                self.logMsg("WARNING: bootstrap ready but TURN IP empty — using placeholder for tunnelRemoteAddress")
            } else {
                self.logMsg("TURN server IP=\(turnIP)")
                self.persistTurnServerIP(turnIP)
            }

            // Apply the full tunnel settings ONCE. With
            // includeAllNetworks=true on the NEVPNProtocol, excludedRoutes
            // are ignored by iOS; the only traffic that stays on the
            // physical interface is what Apple always-excludes (DHCP,
            // captive networks, traffic to serverAddress, and — on
            // iOS 16.4+ with our flags — APNs/CellularServices as
            // configured on the main-app side).
            let finalSettings = self.createTunnelSettings(
                address: tunnelAddress,
                dns: dnsServers,
                mtu: mtu,
                tunnelRemoteAddress: turnIP.isEmpty ? "10.0.0.1" : turnIP
            )

            DispatchQueue.main.async {
                self.logMsg("setTunnelNetworkSettings: applying full routes (single shot)")
                self.setTunnelNetworkSettings(finalSettings) { error in
                    if let error = error {
                        self.logMsg("setTunnelNetworkSettings ERROR: \(error)")
                        wgTurnOff(handle)
                        self.tunnelHandle = -1
                        completionHandler(error)
                        return
                    }
                    self.logMsg("setTunnelNetworkSettings OK — TUN interface live")

                    // TUN fd becomes discoverable only after
                    // setTunnelNetworkSettings returns. Hand it to Go so
                    // WireGuard can attach to the already-running proxy.
                    guard let tunFd = self.findTunFileDescriptor() else {
                        self.logMsg("ERROR: could not find TUN fd after setTunnelNetworkSettings")
                        wgTurnOff(handle)
                        self.tunnelHandle = -1
                        completionHandler(VPNError.noTunDevice)
                        return
                    }
                    self.logMsg("TUN fd=\(tunFd), calling wgAttachWireGuard...")

                    let rc = wgConfig.withCString { cfgPtr in
                        wgAttachWireGuard(handle, UnsafeMutablePointer(mutating: cfgPtr), tunFd)
                    }
                    if rc < 0 {
                        self.logMsg("ERROR: wgAttachWireGuard returned \(rc)")
                        wgTurnOff(handle)
                        self.tunnelHandle = -1
                        completionHandler(VPNError.backendFailed(code: rc))
                        return
                    }
                    self.logMsg("wgAttachWireGuard OK — tunnel fully up")
                    completionHandler(nil)
                }
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
        } else if msg == "refresh_captcha_url" {
            // Main app asks the extension to hit the VK API again and
            // return a fresh captcha redirect_uri. Used by the
            // "Attempt limit reached" auto-refresh loop in the main-app
            // UI to rotate the captcha session without tearing the
            // WebView down.
            logMsg("handleAppMessage: refresh_captcha_url")
            var freshURL = ""
            if tunnelHandle >= 0 {
                if let ptr = wgRefreshCaptchaURL(tunnelHandle) {
                    freshURL = String(cString: ptr)
                    free(UnsafeMutableRawPointer(mutating: ptr))
                    logMsg("refreshCaptchaURL: got fresh URL (\(freshURL.prefix(80))...)")
                }
            }
            completionHandler?(freshURL.data(using: .utf8))
        } else if msg.hasPrefix("debug_log:") {
            let debugMsg = String(msg.dropFirst("debug_log:".count))
            logMsg("[AppDebug] \(debugMsg)")
            completionHandler?(nil)
        } else {
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // iOS calls sleep()/wake() extremely aggressively (observed: 105 times/hour,
        // some cycles as short as 0.5s). Tearing down 10 DTLS+TURN connections on
        // every sleep() and rebuilding them on wake() is catastrophic:
        //   - each rebuild triggers a fresh VK credential fetch (+ slider captcha)
        //   - sleep/wake cycles as short as 0.5s don't give us time to finish
        //   - TURN allocations have a 10-min lifetime — they survive short freezes
        //   - DTLS sessions use connection ID, so they tolerate IP changes too
        //
        // We now completely ignore sleep(). iOS may freeze the process anyway;
        // when thawed, the watchdog (in Go) detects any actually-dead tunnels
        // via lastRecvTime and forces a reconnect. Short freezes don't kill
        // anything because TURN/DTLS state persists across them.
        logMsg("sleep() — ignored (connections persist through iOS freeze)")
        completionHandler()
    }

    override func wake() {
        logMsg("wake() — running fast-path health check")

        // Ask Go to do a quick tunnel-health check with tighter thresholds
        // than the normal 30-second watchdog: if even a couple of pion
        // permission/binding errors accumulated while we were asleep, we'd
        // rather force an immediate reconnect now (~5 seconds) than let
        // the user tap Safari and hit a broken tunnel.
        //
        // In full-tunnel mode (includeAllNetworks=true) there is no
        // excludedRoutes list to refresh on network path changes — Apple
        // ignores excludedRoutes with this flag set, so a cell/Wi-Fi
        // handoff doesn't require re-applying tunnel settings. The Go
        // watchdog handles post-wake reconnect if any TURN session
        // actually died during freeze.
        if tunnelHandle >= 0 {
            wgWakeHealthCheck(tunnelHandle)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if tunnelHandle >= 0 {
            wgTurnOff(tunnelHandle)
            tunnelHandle = -1
        }
        completionHandler()
    }

    // MARK: - Network Settings

    private func createTunnelSettings(
        address: String,
        dns: String,
        mtu: String,
        tunnelRemoteAddress: String,
        includeDefaultRoute: Bool = true
    ) -> NEPacketTunnelNetworkSettings {
        let parts = address.split(separator: "/")
        let ip = String(parts[0])
        let prefix = parts.count > 1 ? Int(parts[1]) ?? 24 : 24

        // tunnelRemoteAddress is a cosmetic label per NEPacketTunnelNetworkSettings
        // docs — the actual always-excluded address for iOS full-tunnel mode is
        // NEVPNProtocol.serverAddress (set in the main app, see Step 3 / the
        // AppGroup-cached TURN IP). We still pass the TURN IP here for
        // consistency and so Settings > VPN shows a sensible value.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)

        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: [prefixToSubnet(prefix)])
        // includeDefaultRoute=false is for the Phase 1 "DNS-only" call: we
        // need iOS to give the extension a DNS resolver context so Go-side
        // dial(login.vk.ru) works during bootstrap, but we don't want to
        // capture system traffic into the tunnel before TUN is actually
        // attached. With includeAllNetworks=true on the VPN profile, an
        // empty includedRoutes here keeps the tunnel routing-inert — iOS
        // doesn't have a default route to enforce yet.
        ipv4.includedRoutes = includeDefaultRoute ? [NEIPv4Route.default()] : []
        // No excludedRoutes: with includeAllNetworks=true on the VPN profile,
        // iOS ignores excludedRoutes entirely (Apple docs). The only
        // always-excluded destination is the serverAddress (see above), plus
        // Apple's built-in list (DHCP, captive networks, cellular services
        // when flagged). Removing excludedRoutes here keeps the intent
        // explicit.
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4

        if !dns.isEmpty {
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
    case bootstrapTimeout

    var errorDescription: String? {
        switch self {
        case .noConfiguration: return "No provider configuration found"
        case .invalidConfiguration: return "Invalid or missing configuration fields"
        case .noTunDevice: return "Could not find TUN file descriptor"
        case .backendFailed(let code): return "WireGuard backend failed with code \(code)"
        case .bootstrapTimeout: return "VK bootstrap did not complete within 120s (captcha may be required)"
        }
    }
}
