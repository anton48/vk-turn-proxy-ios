import NetworkExtension
import Network
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var tunnelHandle: Int32 = -1
    private let log = OSLog(subsystem: "com.vkturnproxy.tunnel", category: "PacketTunnel")

    // The inputs the tunnel settings were built from, kept so DIRECT mode
    // (issue #72) can re-apply them mid-session without a reconnect.
    private var lastSettingsAddress = ""
    private var lastSettingsDNS = ""
    private var lastSettingsMTU = ""
    private var lastSettingsRemote = "10.0.0.1"
    /// The TUN fd handed to Go at attach. 🚨 KEEP LOGGING IT ACROSS EVERY
    /// re-apply: the whole feature rests on iOS keeping the same descriptor, so
    /// if it ever moves, wireguard-go is holding a dead one and the tunnel is
    /// finished in silence. Measured stable across seven applies on 2026-08-17.
    private var attachedTunFd: Int32 = -1
    private var protoObservation: NSKeyValueObservation?

    // NWPathMonitor: passively logs every meaningful network state change so
    // we can correlate "can't assign requested address" / mass-reconnect
    // events with the underlying iOS network reality (DHCP renewal, WiFi
    // handoff, cellular handover, interface flap, etc.). Without this, the
    // Go log only shows the consequence ("socket dead") but not the cause
    // ("interface bounced").
    private var pathMonitor: NWPathMonitor?
    private let pathMonitorQueue = DispatchQueue(label: "com.vkturnproxy.tunnel.pathmonitor")
    private var lastPathDescription: String?
    // Essential identity = status + iface + ssid + unsatisfiedReason. Excludes
    // flag-only attributes (dns/expensive/constrained/v4/v6) that iOS toggles
    // without an actual network change. Used by pathUpdateHandler to gate the
    // wgPathChanged/wgPathInTransition bridge call: log + pathstats snapshot
    // still fire on flag-only flips for diagnostic visibility, but the
    // bridge (which marks slots saturated for 12m) is skipped because no
    // real path change happened.
    //
    // Empirical motivation — vpn.wifi-lte-wifi.2.log 2026-05-15 16:36:
    //   16:36:22.811  satisfied iface=wifi [v4,ssid="..."]      ← no DNS yet
    //   16:36:26.057  satisfied iface=wifi [v4,dns,ssid="..."]  ← DNS came up
    // Without this guard, the second event triggered MarkInUseSlots → 5 slots
    // saturated for 10m30s + cascade detection extending pause to 30s. No
    // conn died and no pool acquire was blocked (conns were happy), but pool
    // capacity was wasted for a phantom event.
    private var lastPathEssentialIdentity: String?
    // Cached SSID of the current WiFi network. Refreshed asynchronously
    // on every wifi-iface path event via NEHotspotNetwork.fetchCurrent
    // (see startPathMonitoring). Cleared when iface switches off wifi.
    // Non-nil → describePath includes ssid="..." in the [PathMonitor]
    // log line. nil → either not on wifi, or fetchCurrent returned nil
    // (which can happen if iOS denies the API for our context — e.g.
    // missing entitlement, or extension lifecycle quirks).
    private var currentWiFiSSID: String?

    // VKAuth background watchdog: polls the Go cookie fatal-auth latch; on a
    // non-empty value (cookie rejected/expired mid-session) it stops the tunnel
    // with a user-readable reason, since a login WebView can't be shown here.
    private var authErrorTimer: DispatchSourceTimer?

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

    // VKAuth: shared-state key the extension writes (with the rejection reason)
    // just before self-stopping, so the main app can show WHY on the next
    // .disconnected transition even if it wasn't polling stats at the time.
    private static let authErrorKey = "vkauth_error"

    private func persistAuthError(_ msg: String) {
        guard let shared = UserDefaults(suiteName: Self.sharedDefaultsSuiteName) else { return }
        shared.set(msg, forKey: Self.authErrorKey)
    }

    // Starts the background cookie-rejection watchdog (cookie mode only). Every
    // 20s it asks Go for the fatal-auth message; on a non-empty value it stops
    // the tunnel with a clear error (cancelTunnelWithError) — the app surfaces
    // the reason via the App Group key + stats auth_error.
    private func startAuthErrorWatchdog() {
        stopAuthErrorWatchdog()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 20, repeating: 20)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            guard let cptr = wgGetAuthError() else { return }
            let msg = String(cString: cptr)
            free(UnsafeMutableRawPointer(mutating: cptr))
            guard !msg.isEmpty else { return }
            self.logMsg("VKAuth: cookie rejected in background (\(msg)) — stopping tunnel")
            self.persistAuthError(msg)
            self.stopAuthErrorWatchdog()
            let err = NSError(domain: "VKTurnProxy", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "VK session rejected or expired. Re-login in Settings."
            ])
            self.cancelTunnelWithError(err)
        }
        timer.resume()
        authErrorTimer = timer
        logMsg("VKAuth: started background cookie-rejection watchdog (20s)")
    }

    private func stopAuthErrorWatchdog() {
        authErrorTimer?.cancel()
        authErrorTimer = nil
    }

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {

        // Log the extension's CFBundleVersion ($(CURRENT_PROJECT_VERSION)
        // from project.yml) on every tunnel start so post-mortem log
        // analysis can verify which binary the system actually loaded.
        // Rationale: 2026-05-10 incident where stale xcframework caused
        // the Swift side to look up-to-date while the Go side carried
        // old code; without per-process version logging the divergence
        // wasn't obvious until grep'ing source vs running binary
        // behavior.
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        logMsg("startTunnel called (build \(build))")
        startPathMonitoring()

        // Set Go timezone BEFORE wgSetLogFilePath so the first Go log line
        // ("wgSetLogFilePath: ...") gets a local-time timestamp. Reversed
        // order leaves the first line stamped in UTC (and any other Go
        // logs that fire between the two calls).
        wgSetTimezoneOffset(Int32(TimeZone.current.secondsFromGMT()))

        // Configure Go log file path so Go logs also go to the shared file
        if let path = SharedLogger.shared.logFilePath {
            path.withCString { ptr in
                wgSetLogFilePath(UnsafeMutablePointer(mutating: ptr))
            }
            logMsg("Go log file path set: \(path)")
        }

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
        // Clamped, not trusted: this arrives from UserDefaults, which an
        // imported backup writes — the same trust boundary that made
        // tunnelAddress and allowedIPs guarded values (build 172).
        let mtu = String(TunnelMTU.resolve(
            TunnelMTU.clamp(Int(config["mtu"] as? String ?? "") ?? TunnelMTU.standard)))
        /// The user set the MTU by hand, so it outranks the WRAP-A server's own.
        let mtuExplicit = (config["mtu_explicit"] as? Bool) ?? false
        // WRAP-A (amurcanov interop): the server provisions WireGuard via
        // GETCONF during bootstrap; when set, we fetch the minted config below
        // (wgWaitWrapAProvision) and override wg_config + address/dns/mtu — the
        // user entered none of those.
        let isWrapA = (config["use_wrap_a"] as? Bool) ?? false

        logMsg("tunnelAddress=\(tunnelAddress) dns=\(dnsServers) mtu=\(mtu)\(mtuExplicit ? " (user-set)" : "")")
        logMsg("proxyConfig=\(proxyConfigJSON)")

        // 🚧 DIAGNOSTIC (issue #72). Watch the PROFILE, not just our own
        // messages: Apple's DTS answer on changing NEVPNProtocol properties
        // mid-session (forums/thread/749321) is "save them and observe
        // protocolConfiguration with KVO; they should come into effect
        // promptly". Whether the extension is actually told is one of the
        // things this experiment exists to find out — so the observation logs
        // and does nothing else.
        // 🎯 THE PROFILE IS THE SOURCE OF TRUTH FOR DIRECT MODE, and this is how
        // the extension learns it changed — the mechanism Apple's DTS answer
        // points at (forums/thread/749321), MEASURED firing on device on
        // 2026-08-17 with the right values. Deriving the routes from what we
        // OBSERVE rather than only from a message means the app and the tunnel
        // cannot end up disagreeing if a message is lost.
        protoObservation = observe(\.protocolConfiguration, options: [.new]) { [weak self] _, _ in
            guard let self = self else { return }
            let p = self.protocolConfiguration
            var enforce = false
            if #available(iOS 14.2, *) { enforce = p.enforceRoutes }
            let direct = !p.includeAllNetworks && enforce
            self.logMsg("KVO protocolConfiguration: includeAllNetworks=\(p.includeAllNetworks) "
                + "enforceRoutes=\(enforce) ⇒ \(direct ? "DIRECT" : "tunnelled")")
            self.applyDirectRoutes(direct, reason: "KVO") { _ in }
        }

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
        // VKAuth: if cookie auth is enabled, read the logged-in cookie from the
        // shared Keychain and push it into the Go runtime BEFORE bootstrap. The
        // cookie is intentionally NOT in proxy_config (so it never persists in
        // the VPN providerConfiguration). With it set, GetVKCreds uses ONLY the
        // cookie path. If disabled, force it off (the process may be reused).
        let useCookieAuth = (config["use_cookie_auth"] as? Bool) ?? false
        let cookieLinks = (config["vk_cookie_links"] as? [String]) ?? []
        let cookieLinksJSON = (try? String(data: JSONSerialization.data(withJSONObject: cookieLinks), encoding: .utf8)) ?? "[]"
        if useCookieAuth, let cookie = VKCookieStore.validCookieHeader() {
            cookie.withCString { cptr in
                cookieLinksJSON.withCString { lptr in
                    wgSetVKCookieAuth(1, cptr, lptr)
                }
            }
            logMsg("VKAuth: pushed Keychain cookie + \(cookieLinks.count) call link(s) to Go runtime")
        } else {
            "".withCString { cptr in
                "[]".withCString { lptr in
                    wgSetVKCookieAuth(0, cptr, lptr)
                }
            }
            if useCookieAuth {
                logMsg("VKAuth: enabled but no valid cookie in Keychain — bootstrap will fail (re-login needed)")
            }
        }

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
                if useCookieAuth {
                    self.startAuthErrorWatchdog()
                }
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

            // WRAP-A: fetch the WireGuard config amurcanov's server minted for
            // us via GETCONF during bootstrap, and override wg_config + the
            // tunnel address/dns/mtu (the user supplied none — the server
            // assigns them). Non-WRAP-A keeps the user-supplied values.
            var effWGConfig = wgConfig
            var effAddress = tunnelAddress
            var effDNS = dnsServers
            var effMTU = mtu
            if isWrapA {
                self.logMsg("WRAP-A: fetching GETCONF provision...")
                guard let provPtr = wgWaitWrapAProvision(handle, 30_000) else {
                    self.logMsg("ERROR: wgWaitWrapAProvision returned null — aborting")
                    wgTurnOff(handle)
                    self.tunnelHandle = -1
                    completionHandler(VPNError.backendFailed(code: -100))
                    return
                }
                let provJSON = String(cString: provPtr)
                free(UnsafeMutableRawPointer(mutating: provPtr))
                guard !provJSON.isEmpty,
                      let provData = provJSON.data(using: .utf8),
                      let prov = (try? JSONSerialization.jsonObject(with: provData)) as? [String: Any],
                      let uapi = prov["uapi"] as? String, !uapi.isEmpty,
                      let addr = prov["address"] as? String, !addr.isEmpty else {
                    self.logMsg("ERROR: WRAP-A provision empty/invalid — aborting")
                    wgTurnOff(handle)
                    self.tunnelHandle = -1
                    completionHandler(VPNError.invalidConfiguration)
                    return
                }
                guard self.isValidTunnelAddress(addr) else {
                    self.logMsg("ERROR: WRAP-A provision address is not a valid ip/prefix — aborting")
                    wgTurnOff(handle)
                    self.tunnelHandle = -1
                    completionHandler(VPNError.invalidConfiguration)
                    return
                }
                effWGConfig = uapi
                effAddress = addr
                if let d = prov["dns"] as? String, !d.isEmpty { effDNS = d }
                // The server's suggestion applies only while the user has not
                // made a choice; otherwise the Advanced setting would silently
                // do nothing on exactly the servers that provision an MTU.
                if !mtuExplicit, let m = prov["mtu"] as? Int, m > 0 {
                    effMTU = String(TunnelMTU.clamp(m))
                }
                self.logMsg("WRAP-A provisioned: address=\(effAddress) dns=\(effDNS) mtu=\(effMTU)")
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
                address: effAddress,
                dns: effDNS,
                mtu: effMTU,
                tunnelRemoteAddress: turnIP.isEmpty ? "10.0.0.1" : turnIP
            )
            // Remember what this was built from, so DIRECT can rebuild it live.
            self.lastSettingsAddress = effAddress
            self.lastSettingsDNS = effDNS
            self.lastSettingsMTU = effMTU
            self.lastSettingsRemote = turnIP.isEmpty ? "10.0.0.1" : turnIP

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
                    self.attachedTunFd = tunFd
                    self.logMsg("TUN fd=\(tunFd), calling wgAttachWireGuard...")

                    let rc = effWGConfig.withCString { cfgPtr in
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
        } else if msg == "get_logs" {
            // Recovery path for the in-app Logs UI when SharedLogger's
            // App Group file is unavailable (improper code signing,
            // iOS-version-specific behaviour, etc): main app sends
            // "get_logs", extension reads its OWN os_log ring buffer
            // (per-process, can't be done from main app on its behalf)
            // and returns the formatted text. Main app concatenates
            // with its own OSLogReader output. Last ~30 minutes of
            // entries — enough to cover what just happened before the
            // user tapped Logs without overflowing providerMessage.
            // Independent of tunnelHandle: works even before
            // wgStartVKBootstrap completes.
            let text = OSLogReader.readOwnLogs(maxAge: 1800)
            completionHandler?(text.data(using: .utf8))
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
        } else if msg.hasPrefix("set_memstats_fast:") {
            // Settings › Advanced › Diagnostics, applied to the RUNNING tunnel.
            // The same value also arrives in proxyConfig at the next start; this
            // path exists so turning it on mid-session does not cost a
            // reconnect, which would re-ramp 30 connections over ~107 s and
            // measure the ramp instead of whatever was being measured.
            // Process-global in Go, so it needs no tunnelHandle.
            let on = msg.hasSuffix("1")
            logMsg("handleAppMessage: memstats fast ticks = \(on)")
            wgSetMemstatsFastTicks(on ? 1 : 0)
            completionHandler?("ok".data(using: .utf8))
        } else if msg.hasPrefix("set_direct:") {
            // 🚧 DIAGNOSTIC, issue #72 — NOT a feature yet. Re-applies the
            // tunnel's ROUTES on a live session: DIRECT drops the default
            // route and the tunnel's DNS, so traffic should fall back to the
            // primary interface while the TURN pool and WireGuard stay up.
            //
            // 🚨 THE ROUTES ARE HALF THE ANSWER AND THE DOCUMENTED HALF SAYS
            // THEY ARE NOT ENOUGH: `enforceRoutes` is what makes iOS honour
            // includes/excludes, and it is IGNORED while `includeAllNetworks`
            // is true (Apple: "routing-your-vpn-network-traffic"). The app
            // flips both profile properties before sending this; what this
            // handler measures is whether the SESSION survives the pair —
            // the TUN fd above all, because Go is holding it.
            let on = msg.hasSuffix("1")
            applyDirectRoutes(on, reason: "message") { ok in
                completionHandler?((ok ? "ok" : "bad").data(using: .utf8))
            }
        } else if msg.hasPrefix("set_uplink_pace:") {
            // The uplink pacer (Settings › Advanced), applied to the RUNNING
            // tunnel for the same reason as the switch above: a reconnect would
            // charge ~107 s of thirty-connection ramp for flipping a switch.
            // The same pair rides proxyConfig for the next start.
            //
            // 🚨 PARSE STRICTLY AND FAIL CLOSED. A malformed message must leave
            // the tunnel as it is rather than pace it at some fraction of the
            // intended rate: a bucket at 1 KiB/s looks like a setting the user
            // chose and throttles the uplink to nothing.
            let parts = msg.dropFirst("set_uplink_pace:".count).split(separator: ",")
            guard parts.count == 2,
                  let kib = Int(parts[0]), let burst = Int(parts[1]),
                  kib >= 0, burst >= 0 else {
                logMsg("handleAppMessage: 🚨 malformed set_uplink_pace \(msg) — ignored")
                completionHandler?("bad".data(using: .utf8))
                return
            }
            logMsg("handleAppMessage: uplink pace = \(kib) KiB/s per allocation, burst \(burst) KiB")
            wgSetUplinkPace(Int32(kib), Int32(burst))
            completionHandler?("ok".data(using: .utf8))
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
        let started = Date()
        let elapsedMs: () -> Int = { Int(Date().timeIntervalSince(started) * 1000) }
        logMsg("stopTunnel: entered (reason=\(reason.rawValue))")
        stopPathMonitoring()
        stopAuthErrorWatchdog()

        // Safety net: ensure completionHandler is called exactly once
        // within 3 seconds even if wgTurnOff hangs. Without this, iOS
        // waits its full 20s NESMVPNSessionStateStopping timeout + 5s
        // Disposing timeout = 26s before user sees Disconnected. The
        // race is harmless: if wgTurnOff completes first, callOnce
        // marks called=true and the timer fires harmlessly later.
        let lock = NSLock()
        var called = false
        let callOnce: (String) -> Void = { [weak self] origin in
            lock.lock()
            let firstCall = !called
            called = true
            lock.unlock()
            if firstCall {
                self?.logMsg("stopTunnel: calling completionHandler from \(origin) (\(elapsedMs())ms)")
                completionHandler()
            }
        }
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 3.0) {
            callOnce("safety-net 3s timeout")
        }

        if tunnelHandle >= 0 {
            logMsg("stopTunnel: calling wgTurnOff(\(tunnelHandle))")
            wgTurnOff(tunnelHandle)
            tunnelHandle = -1
            logMsg("stopTunnel: wgTurnOff returned (\(elapsedMs())ms total)")
        } else {
            logMsg("stopTunnel: no active tunnelHandle, skipping wgTurnOff")
        }
        callOnce("normal path")
    }

    // MARK: - NWPathMonitor (passive network state logging)

    private func startPathMonitoring() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }

            // Process the path event after the (possibly async) SSID
            // refresh completes — describePath reads currentWiFiSSID.
            let process = { [weak self] in
                guard let self = self else { return }
                let desc = self.describePath(path)
                // Deduplicate identical updates — NWPathMonitor sometimes
                // fires multiple times on a single transition (DNS update,
                // IPv6 configuration, etc.) without meaningful change.
                if desc != self.lastPathDescription {
                    self.logMsg("[PathMonitor] \(desc)")
                    self.lastPathDescription = desc
                    // Trigger an out-of-band Go-side pathstats snapshot so
                    // transient interfaces visited between the 60s pathstats
                    // ticks (e.g. ~20s on cellular during a wifi-cellular-wifi
                    // handover, see vpn.wifi-lte-wifi.1.log 2026-05-08) appear
                    // in the log stream. Cheap (one log line) and called on
                    // any desc-change (including flag-only flips, which are
                    // diagnostically interesting even though we skip the
                    // bridge call below).
                    if self.tunnelHandle >= 0 {
                        let label = desc
                        label.withCString { cstr in
                            wgLogPathSnapshot(self.tunnelHandle, cstr)
                        }

                        // Essential-identity gate: skip the bridge call
                        // when only flag attributes (dns/expensive/
                        // constrained/v4/v6) flipped on the same iface +
                        // ssid + status. Such "events" are iOS internal
                        // state updates, not real network changes — see
                        // lastPathEssentialIdentity comment for the
                        // 2026-05-15 16:36 motivating case.
                        let essential = self.pathEssentialIdentity(path)
                        if essential == self.lastPathEssentialIdentity {
                            self.logMsg("[PathMonitor] flag-only change (\(essential)) — bridge call skipped")
                            return
                        }
                        self.lastPathEssentialIdentity = essential

                        // Branch on iface type. `iface=other` satisfied
                        // events almost always mean our own TUN device
                        // (utun*) became os-default during a brief
                        // recursive-routing fallback window between
                        // physical interface changes — Apple DTS has
                        // confirmed VPN tunnels show up as
                        // InterfaceType.other (forum thread 706963).
                        // Observed pattern (vpn.over24h.log 2026-05-13
                        // 15:26 outage):
                        //   T+0      unsatisfied <real-iface>     ← wgPathChanged (mark in-use)
                        //   T+162ms  satisfied iface=other        ← MUST extend pause, NOT re-mark
                        //   T+3.3s   satisfied <new-real-iface>   ← wgPathChanged (mark + extend)
                        //
                        // Without the wgPathInTransition path, the
                        // 500ms pause from the unsatisfied event expires
                        // before the new real interface arrives, so
                        // conns acquire fresh slots during the gap,
                        // their allocations end up dead/486-blocked,
                        // and the pool cascade-saturates.
                        let isOther = path.status == .satisfied
                            && !path.usesInterfaceType(Network.NWInterface.InterfaceType.wifi)
                            && !path.usesInterfaceType(Network.NWInterface.InterfaceType.cellular)
                            && !path.usesInterfaceType(Network.NWInterface.InterfaceType.wiredEthernet)
                            && !path.usesInterfaceType(Network.NWInterface.InterfaceType.loopback)
                            && path.usesInterfaceType(Network.NWInterface.InterfaceType.other)
                        if isOther {
                            // Extend pause-acquire only, no smart-pause
                            // re-marking. See wgPathInTransition in
                            // bridge.go.
                            wgPathInTransition(self.tunnelHandle)
                        } else {
                            // Pre-emptive saturation marking — tell Go
                            // side that a path change just happened so
                            // it marks in-use slots as quota-locked
                            // BEFORE the inevitable 486 burst. See
                            // wgPathChanged in bridge.go.
                            wgPathChanged(self.tunnelHandle)
                        }
                    }
                }
            }

            // SSID enrichment for wifi paths. NEHotspotNetwork.fetchCurrent
            // is async and may return nil if iOS denies our context (e.g.
            // missing entitlement) — we still proceed in either case so
            // path event logging never blocks on the SSID lookup.
            if path.usesInterfaceType(Network.NWInterface.InterfaceType.wifi) {
                NEHotspotNetwork.fetchCurrent { [weak self] network in
                    // Sanitize the network-controlled SSID before it reaches any
                    // log sink (describePath → vpn.log, and describePath →
                    // wgLogPathSnapshot → Go pathstats): an AP named with
                    // embedded CR/LF could otherwise forge log lines.
                    if let rawSSID = network?.ssid {
                        self?.currentWiFiSSID = SharedLogger.sanitizeField(rawSSID, maxLength: 64)
                    } else {
                        self?.currentWiFiSSID = nil
                    }
                    process()
                }
            } else {
                self.currentWiFiSSID = nil
                process()
            }
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        logMsg("[PathMonitor] started")
    }

    private func stopPathMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        lastPathDescription = nil
        lastPathEssentialIdentity = nil
    }

    // pathEssentialIdentity returns a key that captures only the network-
    // identity attributes of a path: status (satisfied/unsatisfied/
    // requiresConnection), interface type (wifi/cellular/wired/loopback/
    // other), SSID for wifi, and unsatisfiedReason for unsatisfied. It
    // EXCLUDES flag attributes (dns/expensive/constrained/v4/v6) that iOS
    // toggles on a fixed network without a real change. Used by the
    // PathMonitor handler to gate the wgPathChanged bridge call so that
    // iOS-internal flag flips don't trigger full smart-pause marking.
    //
    // Safe to call only from the path-handler queue: reads currentWiFiSSID
    // which is updated on the same queue inside the SSID-fetch callback.
    private func pathEssentialIdentity(_ path: Network.NWPath) -> String {
        let status: String
        switch path.status {
        case .satisfied: status = "satisfied"
        case .unsatisfied: status = "unsatisfied"
        case .requiresConnection: status = "requiresConnection"
        @unknown default: status = "unknown"
        }
        var iface = "none"
        if path.usesInterfaceType(Network.NWInterface.InterfaceType.wifi) { iface = "wifi" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.cellular) { iface = "cellular" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.wiredEthernet) { iface = "wired" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.loopback) { iface = "loopback" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.other) { iface = "other" }
        var components = [status, "iface=\(iface)"]
        if iface == "wifi", let ssid = currentWiFiSSID {
            components.append("ssid=\"\(ssid)\"")
        }
        if path.status == .unsatisfied {
            let reason: String
            switch path.unsatisfiedReason {
            case .notAvailable: reason = "n/a"
            case .cellularDenied: reason = "cellular-denied"
            case .wifiDenied: reason = "wifi-denied"
            case .localNetworkDenied: reason = "local-net-denied"
            case .vpnInactive: reason = "vpn-inactive"
            @unknown default: reason = "unknown"
            }
            components.append("reason:\(reason)")
        }
        return components.joined(separator: " ")
    }

    private func describePath(_ path: Network.NWPath) -> String {
        let status: String
        switch path.status {
        case .satisfied: status = "satisfied"
        case .unsatisfied: status = "unsatisfied"
        case .requiresConnection: status = "requiresConnection"
        @unknown default: status = "unknown"
        }
        var iface = "none"
        if path.usesInterfaceType(Network.NWInterface.InterfaceType.wifi) { iface = "wifi" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.cellular) { iface = "cellular" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.wiredEthernet) { iface = "wired" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.loopback) { iface = "loopback" }
        else if path.usesInterfaceType(Network.NWInterface.InterfaceType.other) { iface = "other" }
        var attrs: [String] = []
        if path.isExpensive { attrs.append("expensive") }
        if path.isConstrained { attrs.append("constrained") }
        if path.supportsIPv4 { attrs.append("v4") }
        if path.supportsIPv6 { attrs.append("v6") }
        if path.supportsDNS { attrs.append("dns") }
        // SSID of the current WiFi network if we're on wifi and
        // fetchCurrent succeeded. Useful for "what was that mystery
        // [expensive,constrained] WiFi" diagnosis. Quoted because SSIDs
        // can contain spaces / special chars.
        if iface == "wifi", let ssid = currentWiFiSSID {
            attrs.append("ssid=\"\(ssid)\"")
        }
        // For unsatisfied paths, include Apple's machine-readable reason
        // so post-mortem can distinguish "user denied cellular" from
        // "no available network" etc. iOS 14.2+ API; deploymentTarget 15.0
        // guarantees availability.
        if path.status == .unsatisfied {
            let reason: String
            switch path.unsatisfiedReason {
            case .notAvailable: reason = "n/a"
            case .cellularDenied: reason = "cellular-denied"
            case .wifiDenied: reason = "wifi-denied"
            case .localNetworkDenied: reason = "local-net-denied"
            case .vpnInactive: reason = "vpn-inactive"
            @unknown default: reason = "unknown"
            }
            attrs.append("reason:\(reason)")
        }
        let attrStr = attrs.isEmpty ? "" : " [\(attrs.joined(separator: ","))]"
        return "\(status) iface=\(iface)\(attrStr)"
    }

    // MARK: - Network Settings

    /// True iff `address` is a well-formed `ip` or `ip/prefix` whose host part
    /// is a valid IPv4/IPv6 literal. Guards the WRAP-A GETCONF provision path
    /// against a malicious/compromised server returning "/" or "//" (non-empty,
    /// so it passes the isEmpty check) which would otherwise crash the
    /// extension in createTunnelSettings.
    private func isValidTunnelAddress(_ address: String) -> Bool {
        let parts = address.split(separator: "/", omittingEmptySubsequences: false)
        guard let host = parts.first, !host.isEmpty else { return false }
        let h = String(host)
        return IPv4Address(h) != nil || IPv6Address(h) != nil
    }

    private func createTunnelSettings(
        address: String,
        dns: String,
        mtu: String,
        tunnelRemoteAddress: String,
        includeDefaultRoute: Bool = true
    ) -> NEPacketTunnelNetworkSettings {
        // Defensive: `address` can originate from an untrusted source (the
        // WRAP-A GETCONF provision, or an imported backup's tunnelAddress). A
        // value like "/" splits to an empty array, so index [0] would trap and
        // crash the extension. Fall back to the raw string instead of crashing
        // (the WRAP-A provision path also rejects malformed addresses up front
        // via isValidTunnelAddress).
        let parts = address.split(separator: "/")
        let ip = parts.first.map(String.init) ?? address
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
        // attached.
        //
        // 🚨 THIS COMMENT USED TO CLAIM MORE THAN WE KNOW, AND IT MISLED A
        // DESIGN (2026-08-17). It said an empty `includedRoutes` "keeps the
        // tunnel routing-inert" under `includeAllNetworks=true`. **That was
        // never measured.** What Phase 1 shows is that OUR OWN bootstrap dial
        // works during those few seconds; nobody has ever checked whether
        // other apps' traffic is captured then — and Apple's documentation
        // says the opposite of the convenient reading: with
        // `includeAllNetworks=true` the system routes ALL traffic through the
        // tunnel, `excludedRoutes` have no effect, and `enforceRoutes` — the
        // property that makes includes/excludes binding — is ignored
        // ("routing-your-vpn-network-traffic").
        // ⇒ Treat this parameter as "do not ASK for the default route yet",
        // never as "traffic will stay outside". A DIRECT mode cannot be built
        // on it while IAN is true. *(User-caught: I proposed exactly that.)*
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

    // MARK: - DIRECT mode (DIAGNOSTIC, issue #72)

    /// Re-applies the tunnel settings on a RUNNING session: DIRECT strips the
    /// default route and the tunnel DNS, and back again restores both.
    ///
    /// 🚨 WHAT THIS IS ACTUALLY TESTING, and it is not "does the toggle work":
    ///
    ///   1. **Does the TUN fd survive a second `setTunnelNetworkSettings`?**
    ///      Go was handed the descriptor once, at attach. If iOS builds a new
    ///      utun, wireguard-go holds a dead fd and the tunnel is silently
    ///      finished — so the fd is logged before AND after, and a change is
    ///      shouted rather than mentioned.
    ///   2. **Does the TURN pool survive?** The whole point of the feature is
    ///      that the 30 VK connections are NOT rebuilt, which is the part a
    ///      reconnect cannot give.
    ///   3. **Does the session stay `.connected`?**
    ///
    /// ⚠️ It deliberately does NOT touch `includeAllNetworks` — that lives on
    /// the profile, in the app process. Routes alone cannot deliver DIRECT
    /// while IAN is true; this half only has to prove it costs nothing.
    /// Tracks what the ROUTES are currently set to, so a repeat request is a
    /// no-op instead of a second ~420 ms `setTunnelNetworkSettings`. The
    /// diagnostic had no such guard, and the first field run duly applied the
    /// same mode four times because the buttons gave no feedback.
    private var routesAreDirect = false

    private func applyDirectRoutes(_ direct: Bool, reason: String,
                                   completion: @escaping (Bool) -> Void) {
        guard direct != routesAreDirect else {
            logMsg("direct: routes already \(direct ? "DIRECT" : "tunnelled") (\(reason)) — no-op")
            completion(true)
            return
        }
        guard !lastSettingsAddress.isEmpty else {
            logMsg("direct: no settings recorded yet — the tunnel never finished starting; ignored")
            completion(false)
            return
        }
        let fdBefore = findTunFileDescriptor() ?? -1
        logMsg("direct: \(direct ? "ON" : "OFF") via \(reason); re-applying settings; "
            + "fd before=\(fdBefore) attached=\(attachedTunFd)")

        let settings = createTunnelSettings(
            address: lastSettingsAddress,
            dns: lastSettingsDNS,
            mtu: lastSettingsMTU,
            tunnelRemoteAddress: lastSettingsRemote,
            includeDefaultRoute: !direct
        )
        if direct {
            // A resolver that is only reachable THROUGH the tunnel would make
            // "outside the tunnel" mean "nowhere". Hand DNS back to the system.
            settings.dnsSettings = nil
        }

        let t0 = Date()
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            if let error = error {
                self.logMsg("direct: 🚨 setTunnelNetworkSettings FAILED after \(ms) ms: \(error)")
                completion(false)
                return
            }
            let fdAfter = self.findTunFileDescriptor() ?? -1
            let moved = fdAfter != self.attachedTunFd
            self.routesAreDirect = direct
            self.logMsg("direct: \(direct ? "ON" : "OFF") applied in \(ms) ms; fd after=\(fdAfter) "
                + (moved
                   ? "🚨 THE TUN FD MOVED (attached=\(self.attachedTunFd)) — wireguard-go is holding a "
                     + "dead descriptor and this design is DEAD"
                   : "✅ same fd as attach — Go's descriptor is still valid"))
            completion(true)
        }
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
