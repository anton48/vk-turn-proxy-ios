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
    // Number of slots AVAILABLE for new conn allocations RIGHT NOW:
    // cred is fresh (valid VK expiry, past load cooldown) AND not
    // currently VK-saturated (no active smart-pause from a recent path
    // change or 486). Field name is legacy — populated from
    // countAvailableLocked since build 73 (was countFreshLocked which
    // missed saturatedUntil and showed misleading "8/8/8" when all
    // slots were locked, vpn.wifi-lte-wifi.1.log 2026-05-10).
    var credPoolFilled: Int32 = 0
    // Slots whose cred is still WITHIN the expiry buffer (not expired,
    // not within ~30m of expiring). Includes saturated and load-pending
    // slots — those will recover on their own. Excludes slots with
    // expired or expiring-soon creds, since the background grower
    // would need a successful PoW to refresh them.
    //
    // Field name is legacy ("WithCreds") — semantic was tightened in
    // build 82 to "WithUsableCreds" after vpn.wifi-lte-wifi.1.log on
    // 2026-05-12 showed "6/12/12" while 6 of those 12 slots held
    // expired creds the grower had been failing to refresh for 26+
    // minutes (PoW rate-limited by VK). The looser "any cred" semantic
    // misled the user into thinking the pool was healthier than it was.
    var credPoolWithCreds: Int32 = 0
    var credPoolSize: Int32 = 0
    // Distinct TURN relay addresses held across the pool's filled slots — the 4th
    // "Pool" number. Each relay is an independent ~10-allocation quota bucket, so
    // this is the real spread (esp. in cookie/VKAuth mode).
    var credPoolDistinctRelays: Int32 = 0
    // Seconds since the extension's Proxy was created. Source of truth
    // for the StatsView Uptime box — see fetchStats where it gets
    // converted to a Date origin for the live ticker. Authoritative
    // because the extension survives main-app jetsam/respawn cycles
    // that reset any locally-stamped origin.
    var tunnelUptimeSec: Int64 = 0
    var captchaImageURL: String?
    var captchaSID: String?
    // Non-empty when cookie (VKAuth) auth hit an unrecoverable rejection. The
    // main app reads it during stats polling → shows a message + stops the tunnel.
    var authError: String?

    enum CodingKeys: String, CodingKey {
        case txBytes = "tx_bytes"
        case rxBytes = "rx_bytes"
        case activeConns = "active_conns"
        case totalConns = "total_conns"
        case turnRTTms = "turn_rtt_ms"
        case dtlsHandshakeMs = "dtls_handshake_ms"
        case reconnects
        case credPoolFilled = "cred_pool_filled"
        case credPoolWithCreds = "cred_pool_with_creds"
        case credPoolSize = "cred_pool_size"
        case credPoolDistinctRelays = "cred_pool_distinct_relays"
        case tunnelUptimeSec = "tunnel_uptime_sec"
        case captchaImageURL = "captcha_image_url"
        case captchaSID = "captcha_sid"
        case authError = "auth_error"
    }
}

@MainActor
class TunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .disconnected
    @Published var errorMessage: String?
    @Published var stats = TunnelStats()
    // Set when tunnel transitions into .connected, cleared on any other
    // status. StatsView reads this via TimelineView to show live uptime.
    @Published var connectedAt: Date?

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

    /// Result of a pre-bootstrap WebView captcha session. Reported back
    /// to the connect() probe loop via `preBootstrapResolver`.
    enum PreBootstrapCaptchaResult {
        case solved(token: String)  // user solved → success_token
        case refresh                // JS posted state:limit → re-probe fresh
        case dismissed              // user pressed Done / abort
    }

    // Pre-bootstrap captcha resolver — set when connect() is awaiting a
    // captcha solution from the WebView before calling startVPNTunnel.
    // Reuses the same captchaPending sheet but routes solveCaptcha into
    // the continuation instead of the extension IPC path.
    private var preBootstrapResolver: CheckedContinuation<PreBootstrapCaptchaResult, Never>?

    // True from the moment connect() starts the pre-bootstrap probe loop
    // until either startVPNTunnel is called (NEVPNStatus takes over) or
    // probe fails. The UI checks this OR status==.connecting to render
    // the "Connecting" state — without it, the user sees no visual
    // change for the ~5-15 seconds the probe takes.
    @Published var preBootstrapInProgress = false
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
        // Single-flight: if a connect() is already running (probe loop in
        // progress), drop the new request. Without this, repeatedly tapping
        // Connect during the Preparing phase spawns concurrent probe loops
        // that compete for the captchaPending sheet and burn through VK
        // rate-limit budget in parallel.
        if preBootstrapInProgress {
            SharedLogger.shared.log("[AppDebug] TunnelManager.connect: already in progress, ignoring duplicate")
            return
        }
        errorMessage = nil
        preBootstrapInProgress = true
        defer { preBootstrapInProgress = false }

        // Set Go timezone BEFORE wgSetLogFilePath so the logger's first
        // line ("wgSetLogFilePath: ...") gets a local-time timestamp.
        // Without this, the first ~17 seconds of a session's logs are in
        // UTC because wgSetLogFilePath logs immediately and timezone gets
        // set later by the extension's startTunnel callback.
        wgSetTimezoneOffset(Int32(TimeZone.current.secondsFromGMT()))

        // Redirect Go log output (from wgProbeVKCreds and downstream) to the
        // shared SharedLogger file. The Go runtime in the main-app process is
        // SEPARATE from the one in the Network Extension, and the extension's
        // wgSetLogFilePath call only configures its own runtime. Without this,
        // pre-bootstrap Go logs (vk:, pow:, slider: etc.) go to stderr and
        // disappear. Both processes append to the same file via the AppGroup
        // path — fine for diagnostic logs.
        if let path = SharedLogger.shared.logFilePath {
            path.withCString { ptr in
                wgSetLogFilePath(UnsafeMutablePointer(mutating: ptr))
            }
        }

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
            } else {
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: WARNING — pre-resolved VK hosts list is empty")
            }

            // ----------------------------------------------------------------
            // Pre-bootstrap captcha probe.
            //
            // We solve VK captcha here, in the main-app process, BEFORE
            // calling startVPNTunnel. Two reasons:
            //
            //  1. Step 4 architecture (deferred-setTunnelNetworkSettings +
            //     includeAllNetworks=true) takes the main app's network
            //     stack down at kernel level the moment startVPNTunnel runs
            //     and brings it back only after the tunnel reaches
            //     .connected. The WebView captcha flow needs network in the
            //     main app process — which it has now (status .disconnected,
            //     full physical interface) and won't have during .connecting.
            //
            //  2. The PoW + slider auto-solvers in Go work in 90%+ of cases.
            //     When they don't, we need a human in the loop, and that
            //     loop is only viable here.
            //
            // Loop: probe → if captcha → WebView → user solves → loop with
            // the saved {sid, key, ts, attempt, token1, client_id} state.
            // On success the probe returns TURN credentials we hand to the
            // extension to seed credPool slot 0, so the first conn comes up
            // immediately without another VK round-trip.
            // ----------------------------------------------------------------
            let linkID = URL(string: config.vkLink)?.lastPathComponent ?? ""
            let hostIPsJSONStr: String = {
                if !vkHostIPs.isEmpty,
                   let data = try? JSONSerialization.data(withJSONObject: vkHostIPs),
                   let str = String(data: data, encoding: .utf8) {
                    return str
                }
                return ""
            }()

            var savedSID = ""
            var savedKey = ""
            var savedToken1 = ""
            var savedClientID = ""
            var savedTs: Double = 0
            var savedAttempt: Double = 0
            // Clear the on-disk cred cache when the auth mode (anon vs cookie/
            // VKAuth) changed since the last connect: anon and burner creds must
            // NOT bleed across modes — a burner cred carried into anonymous mode
            // would DEANONYMIZE it (the okcdn user-id IS the burner account). The
            // extension loads creds-pool.json on bootstrap, so we delete it here
            // (main app, before startVPNTunnel) on a mode switch.
            let curAuthMode = config.useCookieAuth ? "cookie" : "anon"
            if let last = UserDefaults.standard.string(forKey: "lastConnectAuthMode"), last != curAuthMode {
                SharedLogger.shared.log("[AppDebug] auth mode changed (\(last) → \(curAuthMode)) — clearing cred cache")
                try? BackupManager.resetTurnCache()
            }
            UserDefaults.standard.set(curAuthMode, forKey: "lastConnectAuthMode")

            var seededTURN: (address: String, username: String, password: String)? = nil

            if config.useCookieAuth {
                // ── VKAuth (non-anonymous cookie) pre-bootstrap ──────────────
                // No captcha here. Ensure a valid logged-in cookie (show the
                // login WebView if missing/expired), push it into the main-app
                // Go runtime, then do ONE cookie-probe to validate it + seed the
                // first TURN cred. NO anonymous fallback (matches the Go side).
                UserDefaults(suiteName: "group.com.vkturnproxy.app")?.removeObject(forKey: "vkauth_error")

                if !VKCookieStore.isValid() {
                    SharedLogger.shared.log("[AppDebug] VKAuth: no valid cookie — presenting login WebView")
                    switch await awaitVKLogin() {
                    case .harvested(let header, let expiry):
                        VKCookieStore.save(cookieHeader: header, expiry: expiry)
                        SharedLogger.shared.log("[AppDebug] VKAuth: cookie harvested (expires \(expiry))")
                    case .cancelled:
                        SharedLogger.shared.log("[AppDebug] VKAuth: login cancelled — aborting")
                        errorMessage = "Вход в VK отменён"
                        return
                    }
                }
                guard let cookieHeader = VKCookieStore.validCookieHeader() else {
                    errorMessage = "Нет действительной VK-сессии. Войдите в Настройках."
                    return
                }
                let linksJSON = (try? String(data: JSONSerialization.data(withJSONObject: config.cookieLinks), encoding: .utf8)) ?? "[]"
                cookieHeader.withCString { cptr in
                    linksJSON.withCString { lptr in
                        wgSetVKCookieAuth(1, cptr, lptr)
                    }
                }

                switch await probeVKCreds(linkID: linkID, vkHostIPsJSON: hostIPsJSONStr) {
                case .ok(let addr, let user, let pass):
                    if let h = config.turnServerOverride, !h.isEmpty,
                       let pt = config.turnPortOverride, !pt.isEmpty {
                        seededTURN = ("\(h):\(pt)", user, pass)
                        SharedLogger.shared.log("[AppDebug] VKAuth: TURN override active — using \(h):\(pt) (VK gave \(addr))")
                    } else {
                        seededTURN = (addr, user, pass)
                        SharedLogger.shared.log("[AppDebug] VKAuth: TURN creds via cookie path (addr=\(addr))")
                    }
                case .cookieRejected:
                    SharedLogger.shared.log("[AppDebug] VKAuth: cookie rejected by VK — aborting")
                    errorMessage = "VK перестал принимать сохранённую сессию. Войдите заново (Настройки → Log in to VK)."
                    return
                case .captcha:
                    SharedLogger.shared.log("[AppDebug] VKAuth: unexpected captcha in cookie mode — aborting")
                    errorMessage = "Не удалось подключиться (неожиданная капча в режиме VK-аккаунта)."
                    return
                case .callUnavailable(let code, let msg):
                    SharedLogger.shared.log("[AppDebug] VKAuth: call unavailable (code=\(code)): \(msg)")
                    errorMessage = "VK returns error: \(msg)"
                    return
                case .error(let msg):
                    SharedLogger.shared.log("[AppDebug] VKAuth: probe error: \(msg)")
                    errorMessage = "Не удалось подключиться: \(msg)"
                    return
                }
            } else {
                // Reset any stale cookie state in the main-app Go runtime so the
                // anonymous probe below isn't accidentally gated on it.
                wgSetVKCookieAuth(0, "", "[]")

            // Cache fast-path: the extension persists every successfully-
            // fetched VK cred to creds-pool.json in the App Group container
            // (see pkg/proxy/creds.go credPool.saveToDisk). On a typical
            // reconnect within the cred's ~8h validity window, we already
            // have a still-valid cred sitting on disk — using it as the
            // seeded TURN cred lets the extension establish the first conn
            // without ANY VK API call, captcha, or rate-limit risk.
            //
            // If loadValidCred() returns nil (no file / expired entries /
            // parse error), we fall through to the normal probe loop and
            // the extension's credPool will repopulate the cache on its
            // first successful fetch.
            if let cached = CredCache.loadValidCred() {
                seededTURN = cached
                SharedLogger.shared.log("[AppDebug] pre-bootstrap: using cached TURN cred from disk (addr=\(cached.address)), skipping captcha probe")
            } else {
                SharedLogger.shared.log("[AppDebug] pre-bootstrap: no usable cached cred (no file or all entries expired), starting captcha probe")
            }

            probeLoop: for attempt in 1...5 where seededTURN == nil {
                SharedLogger.shared.log("[AppDebug] pre-bootstrap probe attempt \(attempt)/5")
                let result = await probeVKCreds(
                    linkID: linkID,
                    vkHostIPsJSON: hostIPsJSONStr,
                    savedSID: savedSID,
                    savedKey: savedKey,
                    savedToken1: savedToken1,
                    savedClientID: savedClientID,
                    savedTs: savedTs,
                    savedAttempt: savedAttempt
                )
                switch result {
                case .ok(let addr, let user, let pass):
                    // A fresh probe is a VK "receive" → honor the TURN override
                    // if set + valid. Cached seeds (above) are NOT overridden.
                    // The cred is relay-agnostic across VK's set, so forcing a
                    // different relay works.
                    if let h = config.turnServerOverride, !h.isEmpty,
                       let pt = config.turnPortOverride, !pt.isEmpty {
                        let ov = "\(h):\(pt)"
                        seededTURN = (ov, user, pass)
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: TURN override active — using \(ov) for the probe seed (VK gave \(addr))")
                    } else {
                        seededTURN = (addr, user, pass)
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: TURN creds acquired (addr=\(addr))")
                    }
                    break probeLoop
                case .captcha(let url, let sid, let ts, let captchaAttempt, let token1, let clientID, let isRateLimit):
                    if isRateLimit {
                        errorMessage = "VK временно ограничивает запросы, попробуйте через минуту"
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: rate limit — aborting")
                        return
                    }
                    SharedLogger.shared.log("[AppDebug] pre-bootstrap: captcha required (sid=\(sid), client_id=\(clientID)), showing WebView")
                    let webViewResult = await awaitPreBootstrapCaptcha(url: url)
                    switch webViewResult {
                    case .solved(let solvedKey):
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: user solved captcha (\(solvedKey.count) chars), retrying probe")
                        savedSID = sid
                        savedKey = solvedKey
                        savedToken1 = token1
                        savedClientID = clientID
                        savedTs = ts
                        savedAttempt = captchaAttempt
                    case .refresh:
                        // VK rate-limited the current session (state:limit
                        // in WebView). Drop saved state — next probe gets
                        // a brand-new VK session via wgProbeVKCreds and
                        // hopefully a non-ERROR_LIMIT captcha.
                        //
                        // Wait 10s before the next probe. The old build's
                        // mid-session auto-refresh used the same cadence and
                        // it eventually got VK to return a non-rate-limited
                        // captcha; spamming probes back-to-back keeps the
                        // rate-limit window active and VK keeps returning
                        // ERROR_LIMIT every time.
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: re-probing with fresh session after state:limit (waiting 10s for VK rate-limit to ease)")
                        savedSID = ""
                        savedKey = ""
                        savedToken1 = ""
                        savedClientID = ""
                        savedTs = 0
                        savedAttempt = 0
                        try? await Task.sleep(nanoseconds: 10_000_000_000)
                    case .dismissed:
                        SharedLogger.shared.log("[AppDebug] pre-bootstrap: user dismissed captcha — aborting")
                        return
                    }
                case .cookieRejected(let msg):
                    // Not expected on the anonymous path; treat as a hard error.
                    SharedLogger.shared.log("[AppDebug] pre-bootstrap: unexpected cookieRejected: \(msg)")
                    errorMessage = "Не удалось подключиться: \(msg)"
                    return
                case .callUnavailable(let code, let msg):
                    SharedLogger.shared.log("[AppDebug] pre-bootstrap: call unavailable (code=\(code)): \(msg)")
                    errorMessage = "VK returns error: \(msg)"
                    return
                case .error(let msg):
                    SharedLogger.shared.log("[AppDebug] pre-bootstrap: error: \(msg)")
                    errorMessage = "Не удалось подключиться: \(msg)"
                    return
                }
            }
            } // end anonymous path (`else` of `if config.useCookieAuth`)

            guard let seeded = seededTURN else {
                SharedLogger.shared.log("[AppDebug] pre-bootstrap: exhausted 5 attempts without success")
                errorMessage = "Не удалось получить креды после 5 попыток captcha"
                return
            }

            // Build proxy config JSON, seeding credPool slot 0 with the
            // pre-fetched TURN creds.
            let proxyConfig = buildProxyConfig(config: config, vkHostIPs: vkHostIPs, seededTURN: seeded)

            // Pick serverAddress. iOS always excludes serverAddress from the
            // tunnel per Apple's documented rule. We set it to the TURN IP we
            // allocate against, by historical convention.
            //
            // CORRECTION 2026-06-08: this used to claim serverAddress MUST
            // match the relay or conns "recursive-route → 0.5 Mbps".
            // EMPIRICALLY FALSE (08.06.2026/vpn.change.address.log): conns on a
            // relay != serverAddress carry full speed idle + speedtest — the
            // extension's own TURN sockets never traverse its own tunnel, so
            // serverAddress's per-IP exemption is NOT load-bearing for the data
            // path. The "155→90 → 0.5 Mbps" anecdote below was almost certainly
            // a DEAD old relay, not recursion. We keep the priority order
            // (harmless) but a mismatch does not break anything. See proxy.go
            // resolveTURNAddr + evaluated_alternatives_turn_endpoint_rotation.md.
            //
            // Priority order:
            //   1. The TURN IP from pre-bootstrap (seeded.address) — what
            //      conn 0 allocates against.
            //   2. The cached TURN IP from a previous session — used only if
            //      pre-bootstrap somehow didn't run (defensive; normally we
            //      always have seeded.address here).
            //   3. The VPS peerAddress as last-resort fallback.
            let shared = UserDefaults(suiteName: "group.com.vkturnproxy.app")
            let savedTurnIP = shared?.string(forKey: "lastTurnServerIP") ?? ""
            // Parse host from seeded.address ("host:port" format).
            let seededHost: String = {
                let parts = seeded.address.split(separator: ":", maxSplits: 1).map(String.init)
                return parts.first ?? ""
            }()
            let serverAddress: String
            if !seededHost.isEmpty {
                serverAddress = seededHost
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: using freshly-fetched TURN IP \(seededHost) as serverAddress")
                // Update the cache so future fallbacks are also fresh.
                if seededHost != savedTurnIP {
                    shared?.set(seededHost, forKey: "lastTurnServerIP")
                }
            } else if !savedTurnIP.isEmpty {
                serverAddress = savedTurnIP
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: using cached TURN IP \(savedTurnIP) as serverAddress (no seeded address)")
            } else {
                serverAddress = config.peerAddress
                SharedLogger.shared.log("[AppDebug] TunnelManager.connect: no TURN IP available, using peerAddress \(config.peerAddress) as serverAddress")
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
                "mtu": config.mtu,
                // WRAP-A: tells the extension to fetch the GETCONF-minted WG
                // config (wgWaitWrapAProvision) and override wg_config +
                // address/dns/mtu after bootstrap, since the user entered none.
                "use_wrap_a": config.useWrapA,
                // VKAuth: tells the extension to read the logged-in cookie from
                // the shared Keychain and push it via wgSetVKCookieAuth before
                // bootstrap (the cookie itself is NOT in this config).
                "use_cookie_auth": config.useCookieAuth,
                // VKAuth call links (cookie mode): the pool spreads conns across
                // each call's 2 TURN relays. Not a secret — just call link IDs.
                "vk_cookie_links": config.cookieLinks
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

            // NECP settle delay before startVPNTunnel.
            //
            // Empirically observed (vpn YESGLITCH 2026-04-30 17:32:48):
            // saveToPreferences() with includeAllNetworks=true triggers iOS
            // NECP rule rebuild that briefly nulls all primary interfaces
            // (en0, pdp_ip0) for ~370 ms. If startVPNTunnel() races into
            // PreparingNetwork during that window, iOS aborts the session
            // with stop reason 4 (NEUnrecoverableNetworkChange / "No
            // network available"). The first extension instance dies, iOS
            // auto-relaunches a second one ~800 ms later — visible as the
            // cosmetic "preparing → connecting → connected → disconnecting
            // → disconnected → connected" UI glitch.
            //
            // 700 ms covers the empirical 370 ms blackout with margin and
            // is unnoticeable on top of the multi-second pre-bootstrap
            // captcha flow that already runs before connect().
            //
            // TEMP for diagnostics — do not commit until verified across
            // a handful of connect/disconnect cycles.
            try await Task.sleep(nanoseconds: 700_000_000)

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


    /// Route captcha-WebView log messages into the vpn.log stream.
    ///
    /// We use TWO paths in parallel because they fail in different
    /// situations:
    ///
    ///  1. `SharedLogger.shared.log(...)` — writes directly to the App
    ///     Group `vpn.log` from the main-app process. The original
    ///     comment for this method claimed main-app has no direct
    ///     access; that's incorrect — both targets have the
    ///     `group.com.vkturnproxy.app` App Group entitlement, and
    ///     `[AppDebug]` lines from TunnelManager have always worked
    ///     this way. This path is critical during PRE-BOOTSTRAP
    ///     captcha (extension not yet running, sendProviderMessage
    ///     can't deliver), which is exactly the case for issue #5
    ///     "blank captcha" reports — vpn.from.github.log on
    ///     2026-05-07 had `pre-bootstrap: captcha required` followed
    ///     by `pre-bootstrap: user dismissed captcha — aborting` 13.6
    ///     seconds later with ZERO `[captcha-view]` events between
    ///     them, masking what the WebView actually did.
    ///
    ///  2. `debugLog(...)` (via sendProviderMessage to extension) —
    ///     redundant once path 1 is in place, kept for symmetry with
    ///     other diagnostic events that go through it. Cost is one
    ///     extra log line per event during mid-session captcha when
    ///     both paths reach the file. Acceptable for diagnostic.
    ///
    /// If we ever drop path 2, drop here. Until then duplicate lines
    /// in the log are accepted as the price of always-visible
    /// captcha-view events.
    func logFromCaptchaView(_ message: String) {
        SharedLogger.shared.log("[captcha-view] \(message)")
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
        // Pre-bootstrap mode owns ALL captcha state — JS in the WebView
        // posts state:limit twice for the same captcha (once from the
        // captchaNotRobot.check fetch hook on ERROR_LIMIT, once from the
        // 2.5s DOM heuristic). The first call resolves the continuation
        // with .refresh and nils the resolver; the second arrives ~470ms
        // later. Without this guard, the second call fell through into
        // the mid-session auto-refresh timer (max 6 × 10s), which then
        // ran in parallel with pre-bootstrap's own 10s wait + next
        // probe — surfacing a stale "3/6 attempts" UI on a captcha that
        // pre-bootstrap had already moved past.
        //
        // Mid-session auto-refresh timer is for the OLD build's
        // mid-session captcha path, where Proxy is already running and
        // wgRefreshCaptchaURL returns a fresh URL from the proxy. In
        // pre-bootstrap mode there's no Proxy yet — wgRefreshCaptchaURL
        // returns "" — and the right re-fetch path is wgProbeVKCreds,
        // which the connect() probe loop already drives.
        if preBootstrapInProgress {
            if let resolver = preBootstrapResolver {
                debugLog("pre-bootstrap captcha: state:limit detected → re-probing with fresh session")
                preBootstrapResolver = nil
                captchaPending = false
                captchaImageURL = nil
                resolver.resume(returning: .refresh)
            } else {
                debugLog("pre-bootstrap captcha: duplicate state:limit ignored (resolver already consumed)")
            }
            return
        }

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
        // Pre-bootstrap path: user gave up. Resolve continuation with
        // .dismissed so connect() unwinds cleanly without leaking the
        // awaiter.
        if let resolver = preBootstrapResolver {
            preBootstrapResolver = nil
            resolver.resume(returning: .dismissed)
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
            // Only surface the error if the tunnel isn't actually up. If
            // we're connected, the captcha refresh was for a stale request
            // that's no longer relevant — showing red "rate-limited" text
            // next to a green Connected status confuses the user. Verified
            // empirically in vpn.wifi.36.log where bootstrap finished
            // successfully and tunnel reached .connected, then auto-refresh
            // (still running for the dismissed pre-bootstrap captcha)
            // exhausted and put the error on screen.
            if status != .connected {
                errorMessage = "VK временно ограничивает запросы. Подождите минуту и попробуйте снова."
            }
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
        // Pre-bootstrap path: connect() is awaiting the answer.
        if let resolver = preBootstrapResolver {
            preBootstrapResolver = nil
            captchaPending = false
            captchaImageURL = nil
            resolver.resume(returning: .solved(token: answer))
            return
        }
        // Existing mid-session path: forward to extension via IPC.
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

    /// Show the captcha WebView and await the user's response. Returns
    /// one of three outcomes (see PreBootstrapCaptchaResult):
    ///   - .solved(token):  user passed the captcha; success_token captured
    ///   - .refresh:        JS detector reported state:limit (VK rate-
    ///                      limited the current session) → connect()'s
    ///                      probe loop should iterate with a fresh probe
    ///                      instead of trying to resolve the stale URL
    ///   - .dismissed:      user pressed Done / aborted
    func awaitPreBootstrapCaptcha(url: String) async -> PreBootstrapCaptchaResult {
        let result: PreBootstrapCaptchaResult = await withCheckedContinuation { (cont: CheckedContinuation<PreBootstrapCaptchaResult, Never>) in
            DispatchQueue.main.async {
                self.preBootstrapResolver = cont
                self.captchaImageURL = url
                self.captchaPending = true
            }
        }
        return result
    }

    // MARK: - VKAuth login WebView (cookie harvest)

    // Drives the embedded VK-login sheet in ContentView during the cookie
    // pre-bootstrap. Mirrors the captcha sheet mechanism (captchaPending +
    // preBootstrapResolver).
    @Published var vkLoginPending = false
    private var vkLoginResolver: CheckedContinuation<VKAuthResult, Never>?

    /// Presents the VK-login WebView and suspends until the user logs in
    /// (cookie harvested) or cancels.
    func awaitVKLogin() async -> VKAuthResult {
        return await withCheckedContinuation { (cont: CheckedContinuation<VKAuthResult, Never>) in
            DispatchQueue.main.async {
                self.vkLoginResolver = cont
                self.vkLoginPending = true
            }
        }
    }

    /// Called by ContentView when the login sheet finishes; resumes awaitVKLogin.
    func onVKLoginResult(_ result: VKAuthResult) {
        vkLoginPending = false
        if let r = vkLoginResolver {
            vkLoginResolver = nil
            r.resume(returning: result)
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
        // App-relaunch case: the tunnel may already be running in
        // .connected when we attach. NEVPNStatusDidChange only fires on
        // future transitions, so the switch below would never run for
        // this initial state and connectedAt would stay nil — making
        // StatsView show "Connected" alongside Uptime "—" until the
        // tunnel happens to bounce. Set connectedAt now so live uptime
        // starts ticking immediately. The clock origin will be "when
        // the app re-attached" rather than the actual tunnel start
        // time (we don't have that — the extension would need to report
        // it via stats), but for a status box that's fine: the user
        // mainly cares about the "is it ticking" visual cue, not the
        // absolute number.
        if status == .connected && connectedAt == nil {
            connectedAt = Date()
        }

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
                    // Stamp the moment we first reach .connected so StatsView
                    // can render a live uptime via TimelineView. Don't reset
                    // on .connecting/.reasserting cycles inside an existing
                    // session — those count as part of the same uptime.
                    if self.connectedAt == nil {
                        self.connectedAt = Date()
                    }
                    // (Re)start polling, preserving captcha state across reconnects
                    self.startStatsPolling(reset: false)
                    // Once the tunnel is actually up, any error message left
                    // over from a captcha-limit exhaustion or other transient
                    // failure is stale — clear it so the user isn't told
                    // "VK временно ограничивает запросы" while staring at a
                    // green 10/10 Connected status.
                    self.errorMessage = nil
                    // Cancel any auto-refresh timer still running for the
                    // pre-bootstrap captcha session: the tunnel got up via
                    // a different path (PoW succeeded on a later probe, or
                    // user solved on a fresh probe iteration), the original
                    // captcha sheet is moot. Without this the timer would
                    // continue ticking until exhaust, then set errorMessage
                    // back to the "rate-limited" text on top of a green
                    // Connected status.
                    if self.captchaAutoRefreshTimer != nil {
                        self.debugLog("captcha auto-refresh: tunnel reached .connected — cancelling pending refresh timer")
                        self.stopCaptchaAutoRefresh()
                    }
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
                    self.connectedAt = nil
                    // If the extension self-stopped due to a rejected VKAuth
                    // cookie, it wrote the reason to the App Group before
                    // cancelling — surface it (and clear it so it shows once).
                    if let shared = UserDefaults(suiteName: "group.com.vkturnproxy.app"),
                       let ae = shared.string(forKey: "vkauth_error"), !ae.isEmpty {
                        self.errorMessage = "Сессия VK отклонена или истекла. Войдите заново в Настройках."
                        shared.removeObject(forKey: "vkauth_error")
                    }
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

    /// Ask the extension to dump its own os_log ring buffer, used as a
    /// fallback by the in-app Logs UI when SharedLogger's App Group
    /// file is unreachable. Per-process os_log entries can only be
    /// read by their own process (iOS sandbox), so we ferry the
    /// extension's tail across via providerMessage. Returns nil on
    /// any RPC error; empty string on RPC success with no entries.
    func fetchExtensionOSLogs() async -> String? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        guard let msg = "get_logs".data(using: .utf8) else { return nil }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(msg) { response in
                    if let data = response, let str = String(data: data, encoding: .utf8) {
                        continuation.resume(returning: str)
                    } else {
                        continuation.resume(returning: "")
                    }
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

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

                        // VKAuth: the extension reports a fatal cookie rejection
                        // via auth_error. Surface it and stop the tunnel (we
                        // can't show a login WebView from the background).
                        if let ae = newStats.authError, !ae.isEmpty {
                            self.debugLog("VKAuth: stats.auth_error='\(ae)' — stopping tunnel")
                            self.errorMessage = "Сессия VK отклонена или истекла. Войдите заново в Настройках."
                            self.disconnect()
                            return
                        }

                        // Sync connectedAt from extension-reported uptime so
                        // the StatsView Uptime ticker reflects how long the
                        // *tunnel* (extension's Proxy instance) has actually
                        // been running, not how long it's been since the main
                        // app last attached. Without this, iOS jetsam'ing the
                        // main app during sleep and re-launching it on next
                        // foreground used to reset the locally-stamped origin
                        // — observed in vpn.lte.0.log on 2026-05-03 where two
                        // "App launched" events at 11:56 and 12:04 collapsed
                        // a 40+ minute connected session into a "0:07" Uptime
                        // display.
                        //
                        // Only sync when the tunnel is actually .connected
                        // and the extension reports a positive uptime. The
                        // observeStatus initial-stamp fallback still seeds
                        // connectedAt for the brief window before the first
                        // stats poll responds; this just refines it once the
                        // authoritative value is available.
                        if self.status == .connected && newStats.tunnelUptimeSec > 0 {
                            let originFromExtension = now.addingTimeInterval(-TimeInterval(newStats.tunnelUptimeSec))
                            // Avoid pointless re-publishes when the value
                            // doesn't move — drift is at most a few hundred
                            // milliseconds per poll due to RPC latency, so
                            // anything <1s is just noise that would force
                            // SwiftUI to re-render TimelineView dependents.
                            if let existing = self.connectedAt,
                               abs(existing.timeIntervalSince(originFromExtension)) < 1 {
                                // close enough, keep current
                            } else {
                                self.connectedAt = originFromExtension
                            }
                        }

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
        // WRAP-A: the user enters no WireGuard keys — amurcanov's server mints
        // them via GETCONF and the extension applies the result
        // (wgWaitWrapAProvision) instead of this string. Return a harmless
        // placeholder so connect() doesn't fail Base64 validation on the empty
        // key fields.
        if config.useWrapA {
            return ""
        }
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

    /// Stable per-install device identifier for WRAP-A GETCONF, persisted in
    /// the App Group so it survives relaunch (the server keys the minted
    /// WireGuard device + IP on it, so it must be constant across reconnects).
    /// NOT included in backups/links — it is device identity, not deployment
    /// config; a fresh install mints a new one so two devices never collide on
    /// amurcanov's server WG-peer pool. Generated lazily on first WRAP-A use.
    private func wrapADeviceID() -> String {
        let suite = UserDefaults(suiteName: "group.com.vkturnproxy.app")
        if let existing = suite?.string(forKey: "wrapADeviceID"), !existing.isEmpty {
            return existing
        }
        let id = UUID().uuidString
        suite?.set(id, forKey: "wrapADeviceID")
        SharedLogger.shared.log("[AppDebug] WRAP-A: generated stable deviceID \(id)")
        return id
    }

    private func buildProxyConfig(
        config: TunnelConfig,
        vkHostIPs: [String: [String]] = [:],
        seededTURN: (address: String, username: String, password: String)? = nil
    ) -> String {
        var dict: [String: Any] = [
            "vk_link": config.vkLink,
            "peer_addr": config.peerAddress,
            "use_dtls": config.useDTLS,
            "use_udp": config.useUDP,
            "force_legacy_captcha": config.forceLegacyCaptcha,
            "use_wrap": config.useWrap,
            "wrap_key_hex": config.wrapKeyHex,
            "use_srtp": config.useSrtp,
            "num_conns": config.numConnections,
            "cred_pool_cooldown_seconds": config.credPoolCooldownSeconds,
            "turn_server": config.turnServerOverride ?? "",
            "turn_port": config.turnPortOverride ?? "",
            "use_cookie_auth": config.useCookieAuth
        ]
        // WRAP-A (amurcanov interop): the server provisions WireGuard via
        // GETCONF, so we send the password + a stable deviceID instead of WG
        // keys. Gated so non-WRAP-A users don't get the keys (or a generated
        // deviceID) in their proxy config at all.
        if config.useWrapA {
            dict["use_wrap_a"] = true
            dict["wrap_a_password"] = config.wrapAPassword
            dict["device_id"] = wrapADeviceID()
        }
        // SRTP-WRAP-S (samosvalishe/free-turn-proxy): obf profile + Client-ID on
        // the SRTP+WRAP data path. wrap_key_hex is already set above.
        if config.useWrapS {
            dict["use_wrap_s"] = true
            dict["obf_profile"] = config.obfProfile
            dict["client_id"] = config.clientID
        }
        if !vkHostIPs.isEmpty {
            dict["vk_host_ips"] = vkHostIPs
        }
        if let s = seededTURN {
            dict["seeded_turn"] = [
                "address": s.address,
                "username": s.username,
                "password": s.password
            ]
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

    // MARK: - Pre-bootstrap captcha probe

    enum ProbeResult {
        case ok(address: String, username: String, password: String)
        case captcha(url: String, sid: String, ts: Double, attempt: Double, token1: String, clientID: String, isRateLimit: Bool)
        case cookieRejected(message: String)
        case callUnavailable(code: Int, message: String)
        case error(message: String)
    }

    /// Calls Go-side wgProbeVKCreds. Returns parsed result. Synchronous,
    /// runs on a background queue (Task.detached) — CFHost / TLS / VK API
    /// over uTLS together can take several seconds.
    nonisolated private func probeVKCreds(
        linkID: String,
        vkHostIPsJSON: String,
        savedSID: String = "",
        savedKey: String = "",
        savedToken1: String = "",
        savedClientID: String = "",
        savedTs: Double = 0,
        savedAttempt: Double = 0
    ) async -> ProbeResult {
        return await Task.detached(priority: .userInitiated) {
            let cResult: UnsafePointer<CChar>? = linkID.withCString { l in
                vkHostIPsJSON.withCString { h in
                    savedSID.withCString { s in
                        savedKey.withCString { k in
                            savedToken1.withCString { t in
                                savedClientID.withCString { c in
                                    wgProbeVKCreds(l, h, s, k, t, c, savedTs, savedAttempt)
                                }
                            }
                        }
                    }
                }
            }
            guard let cResult = cResult else {
                return ProbeResult.error(message: "wgProbeVKCreds returned NULL")
            }
            let jsonStr = String(cString: cResult)
            free(UnsafeMutableRawPointer(mutating: cResult))

            guard let data = jsonStr.data(using: .utf8),
                  let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return ProbeResult.error(message: "wgProbeVKCreds invalid JSON: \(jsonStr.prefix(200))")
            }
            let status = dict["status"] as? String ?? ""
            switch status {
            case "ok":
                return .ok(
                    address: dict["turn_address"] as? String ?? "",
                    username: dict["turn_username"] as? String ?? "",
                    password: dict["turn_password"] as? String ?? ""
                )
            case "captcha":
                return .captcha(
                    url: dict["captcha_url"] as? String ?? "",
                    sid: dict["sid"] as? String ?? "",
                    ts: dict["ts"] as? Double ?? 0,
                    attempt: dict["attempt"] as? Double ?? 0,
                    token1: dict["token1"] as? String ?? "",
                    clientID: dict["client_id"] as? String ?? "",
                    isRateLimit: dict["is_rate_limit"] as? Bool ?? false
                )
            default:
                let msg = dict["message"] as? String ?? "unknown probe error"
                if (dict["cookie_rejected"] as? Bool) == true {
                    return .cookieRejected(message: msg)
                }
                if (dict["call_unavailable"] as? Bool) == true {
                    return .callUnavailable(code: dict["code"] as? Int ?? 0, message: msg)
                }
                return .error(message: msg)
            }
        }.value
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
    var vkLink: String = ""  // primary call link (first line); anon + serverAddress
    // All call links (cookie/VKAuth mode): each adds 2 TURN relays. First == vkLink.
    var cookieLinks: [String] = []
    var peerAddress: String = ""  // vk-turn-proxy server host:port
    var useDTLS: Bool = true
    // WRAP layer: ChaCha20-XOR every UDP packet between DTLS and TURN
    // ChannelData so VK's payload classifier can't recognise DTLS+WG
    // and tag the destination endpoint. Requires the configured
    // peerAddress to be a server running cacggghp/vk-turn-proxy with
    // matching -wrap and -wrap-key — without that, DTLS handshake
    // fails (server XOR's plain bytes, garbage hits DTLS state machine).
    var useWrap: Bool = false
    // 32-byte ChaCha20 key as 64 hex chars; required when useWrap=true,
    // must match the server's -wrap-key value exactly.
    var wrapKeyHex: String = ""
    // SRTP transport: frames tunnel traffic as DTLS+SRTP+RTP so VK's
    // TURN-relay content classifier sees it as legitimate WebRTC media
    // and does not apply the per-allocation shape policy. Requires the
    // peer server (peerAddress above) to be running anton48/vk-turn-
    // proxy add-server-srtp-layer with the -srtp flag — typically on a
    // separate port from the legacy DTLS+WG listener. Empirical 2026-
    // 05-19/20: sustained 200+ KB/s per conn with 0% loss; 30-conn
    // production layout yields ~50 Mbps total tunnel throughput (vs
    // ~2 Mbps for the standard DTLS+WG path).
    var useSrtp: Bool = false
    // WRAP-A (amurcanov-compatible) 4th transport mode. The peer is
    // amurcanov's proxy-turn-vk-android server; it provisions our WireGuard
    // keypair + IP via GETCONF over a WRAP-A+DTLS channel, so the user enters
    // NO WG keys — only peerAddress + wrapAPassword. NOT SRTP despite the UI
    // grouping. See pkg/proxy/wrapa.go + getconf.go; the extension fetches the
    // minted config via wgWaitWrapAProvision after bootstrap.
    var useWrapA: Bool = false
    // Shared secret for WRAP-A: HKDF input for the obfuscation key AND GETCONF
    // authentication. One field. Required when useWrapA=true.
    var wrapAPassword: String = ""
    // SRTP-WRAP-S (samosvalishe/free-turn-proxy interop): obf-profile
    // (rtpopus/rtpopus2/rtpopus3) + a Client-ID record over the SRTP+WRAP data
    // path. Reuses wrapKeyHex as the shared key; the user still enters WG keys.
    var useWrapS: Bool = false
    var obfProfile: String = "rtpopus"
    var clientID: String = ""
    // 2026-05-18 empirical: VK's new per-cred TURN allocation-rate
    // throttle (introduced ~16:00 MSK that day) applies ONLY to UDP-
    // transport allocations. 11×10 = 110 TCP-control allocations on a
    // single cred = 0 quota errors, vs ~36-58% quota errors on UDP for
    // the same cred. Blackhole rate (~58%) and shape rate (~12-17%) are
    // unchanged between transports — those mechanisms operate on the
    // forwarded UDP payload, not on the control channel. Switching to
    // TCP-control client↔relay leg restores pool stability without
    // architectural churn (no need for connsPerSlot=2 / pool=18 etc).
    // Bonus: some ISP whitelists drop UDP entirely but pass TCP, so this
    // also helps for that class of restricted networks.
    var useUDP: Bool = false
    // forceLegacyCaptcha: undocumented on-device captcha-test toggle (build
    // 149) — skip the captcha-free VK Calls path so the legacy
    // captchaNotRobot.* solver runs. Set via a `forceLegacyCaptcha` field in
    // the backup JSON (no Settings UI). Default false → no production effect.
    var forceLegacyCaptcha: Bool = false
    // VKAuth: when true, the cred path uses ONLY the logged-in VK cookie (no
    // anonymous fallback). The cookie itself lives in the Keychain
    // (VKCookieStore); this flag flows to Go via proxy_config use_cookie_auth.
    var useCookieAuth: Bool = false
    var numConnections: Int = 30 // configurable from Settings; VK allows ~10 simultaneous TURN allocations per cred set, so 30 conns spreads over ceil(N/10) = 3 cred sets plus a "+1 reserve" (4 total slots). 30 strikes a useful balance: enough parallelism for high-throughput single sessions, few enough to avoid overwhelming VK's per-IP rate-limit on cred refresh.
    // Per-slot cooldown after a failed fetch (typically captcha required).
    // Slot stays in cooldown for this long before being eligible to retry.
    // Shorter = pool recovers faster when VK cools down, longer = less VK
    // pressure but slower recovery. Default 150s — long enough for VK to
    // forget our captcha-failure rate-limit window without making real
    // failed-cred recovery feel laggy.
    var credPoolCooldownSeconds: Int = 150
    var turnServerOverride: String?
    var turnPortOverride: String?
}
