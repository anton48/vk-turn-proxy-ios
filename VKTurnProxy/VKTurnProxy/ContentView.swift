import SwiftUI
import NetworkExtension
import WebKit
import os.log

private let captchaLog = OSLog(subsystem: "com.vkturnproxy.app", category: "Captcha")

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()

    // All config stored in AppStorage, edited on SettingsView
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("numConnections") private var numConnections = 10
    @AppStorage("credPoolTTLMinutes") private var credPoolTTLMinutes = 10
    @AppStorage("credPoolCooldownSeconds") private var credPoolCooldownSeconds = 120

    var body: some View {
        NavigationView {
            VStack(spacing: 32) {
                Spacer()

                // Status indicator
                Circle()
                    .fill(statusColor)
                    .frame(width: 80, height: 80)
                    .shadow(color: statusColor.opacity(0.5), radius: 12)

                Text(statusText)
                    .font(.title2)
                    .fontWeight(.medium)

                if let error = tunnel.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                // Stats (shown when connected)
                if tunnel.status == .connected {
                    StatsView(tunnel: tunnel)
                        .padding(.horizontal)
                }

                Spacer()

                // Connect / Disconnect button
                Button(action: {
                    if tunnel.status == .connected || tunnel.status == .connecting {
                        tunnel.disconnect()
                    } else {
                        let config = TunnelConfig(
                            privateKey: privateKey,
                            peerPublicKey: peerPublicKey,
                            presharedKey: presharedKey.isEmpty ? nil : presharedKey,
                            tunnelAddress: tunnelAddress,
                            dnsServers: dnsServers,
                            allowedIPs: allowedIPs,
                            vkLink: vkLink,
                            peerAddress: peerAddress,
                            useDTLS: useDTLS,
                            numConnections: numConnections,
                            credPoolTTLSeconds: credPoolTTLMinutes * 60,
                            credPoolCooldownSeconds: credPoolCooldownSeconds
                        )
                        Task {
                            await tunnel.connect(config: config)
                        }
                    }
                }) {
                    Text(buttonText)
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(buttonColor)
                        .cornerRadius(12)
                }
                .padding(.horizontal)

                // Logs & Settings links
                HStack(spacing: 24) {
                    NavigationLink(destination: LogsView()) {
                        Label("Logs", systemImage: "doc.text")
                    }
                    NavigationLink(destination: SettingsView()) {
                        Label("Settings", systemImage: "gear")
                    }
                }
                .padding(.bottom, 24)
            }
            .navigationTitle("VK Turn Proxy")
            .sheet(isPresented: $tunnel.captchaPending) {
                if let urlStr = tunnel.captchaImageURL, let url = URL(string: urlStr) {
                    CaptchaWebView(
                        url: url,
                        captchaSID: tunnel.captchaSID ?? "",
                        onSolved: { token in
                            NSLog("[Captcha] Token received (%d chars), sending to tunnel", token.count)
                            tunnel.solveCaptcha(answer: token)
                        },
                        onDismiss: {
                            // Don't send fake answer — just dismiss the sheet.
                            // The captcha will re-appear on next poll if not actually solved.
                            NSLog("[Captcha] Sheet dismissed without token")
                            tunnel.onCaptchaSheetDismissed()
                            tunnel.captchaPending = false
                            tunnel.captchaImageURL = nil
                        },
                        onLimitDetected: { tunnel.onCaptchaLimitDetected() },
                        onCaptchaReady: { tunnel.onCaptchaReady() },
                        onLog: { tunnel.logFromCaptchaView($0) },
                        tunnel: tunnel
                    )
                }
            }
        }
    }

    // MARK: - Helpers

    private var statusColor: Color {
        // pre-bootstrap captcha probe runs while NEVPNStatus is still
        // .disconnected — show the "connecting" color so the UI reflects
        // that connect() is actually working. See TunnelManager.connect.
        if tunnel.preBootstrapInProgress { return .yellow }
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting: return .orange
        default: return .gray
        }
    }

    private var statusText: String {
        if tunnel.preBootstrapInProgress { return "Preparing..." }
        switch tunnel.status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .reasserting: return "Reconnecting..."
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        @unknown default: return "Unknown"
        }
    }

    private var buttonText: String {
        if tunnel.preBootstrapInProgress { return "Disconnect" }
        switch tunnel.status {
        case .connected, .connecting: return "Disconnect"
        default: return "Connect"
        }
    }

    private var buttonColor: Color {
        if tunnel.preBootstrapInProgress { return .red }
        switch tunnel.status {
        case .connected, .connecting: return .red
        default: return .blue
        }
    }
}

// MARK: - Settings Screen

struct SettingsView: View {
    @AppStorage("privateKey") private var privateKey = ""
    @AppStorage("peerPublicKey") private var peerPublicKey = ""
    @AppStorage("presharedKey") private var presharedKey = ""
    @AppStorage("tunnelAddress") private var tunnelAddress = "192.168.102.3/24"
    @AppStorage("dnsServers") private var dnsServers = "1.1.1.1"
    @AppStorage("allowedIPs") private var allowedIPs = "0.0.0.0/0"
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("peerAddress") private var peerAddress = ""
    @AppStorage("useDTLS") private var useDTLS = true
    @AppStorage("numConnections") private var numConnections = 10
    @AppStorage("credPoolTTLMinutes") private var credPoolTTLMinutes = 10
    @AppStorage("credPoolCooldownSeconds") private var credPoolCooldownSeconds = 120

    var body: some View {
        Form {
            Section("VK TURN Proxy") {
                TextField("VK Call Link", text: $vkLink)
                    .textContentType(.URL)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Proxy Server (host:port)", text: $peerAddress)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                Toggle("DTLS Obfuscation", isOn: $useDTLS)

                Stepper("Connections: \(numConnections)", value: $numConnections, in: 1...64)

                Stepper("Cred pool TTL: \(credPoolTTLMinutes) min", value: $credPoolTTLMinutes, in: 2...60)

                Stepper("Cred pool cooldown: \(credPoolCooldownSeconds) s", value: $credPoolCooldownSeconds, in: 30...600, step: 30)
            }

            Section("WireGuard") {
                SecureField("Private Key (base64)", text: $privateKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Peer Public Key (base64)", text: $peerPublicKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                SecureField("Preshared Key (base64)", text: $presharedKey)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Tunnel Address", text: $tunnelAddress)
                    .autocapitalization(.none)

                TextField("DNS Servers", text: $dnsServers)
                    .autocapitalization(.none)

                TextField("Allowed IPs", text: $allowedIPs)
                    .autocapitalization(.none)
            }
        }
        .navigationTitle("Settings")
    }
}

// MARK: - Stats View

struct StatsView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                StatBox(title: "↑ TX", value: formatBytes(tunnel.stats.txBytes), sub: formatRate(tunnel.txRate))
                StatBox(title: "↓ RX", value: formatBytes(tunnel.stats.rxBytes), sub: formatRate(tunnel.rxRate))
            }

            HStack {
                StatBox(title: "TURN RTT", value: String(format: "%.0f ms", tunnel.stats.turnRTTms), sub: nil)
                StatBox(title: "DTLS HS", value: String(format: "%.0f ms", tunnel.stats.dtlsHandshakeMs), sub: nil)
                StatBox(title: "Internet", value: tunnel.internetRTTms > 0 ? String(format: "%.0f ms", tunnel.internetRTTms) : "—", sub: nil)
            }

            HStack {
                StatBox(title: "Conns", value: "\(tunnel.stats.activeConns)/\(tunnel.stats.totalConns)", sub: nil)
                StatBox(title: "Reconnects", value: "\(tunnel.stats.reconnects)", sub: nil)
            }
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        let b = Double(bytes)
        if b >= 1_073_741_824 { return String(format: "%.1f GB", b / 1_073_741_824) }
        if b >= 1_048_576 { return String(format: "%.1f MB", b / 1_048_576) }
        if b >= 1024 { return String(format: "%.1f KB", b / 1024) }
        return "\(bytes) B"
    }

    private func formatRate(_ bytesPerSec: Double) -> String {
        if bytesPerSec >= 1_048_576 { return String(format: "%.1f MB/s", bytesPerSec / 1_048_576) }
        if bytesPerSec >= 1024 { return String(format: "%.1f KB/s", bytesPerSec / 1024) }
        if bytesPerSec > 0 { return String(format: "%.0f B/s", bytesPerSec) }
        return "0 B/s"
    }
}

struct StatBox: View {
    let title: String
    let value: String
    let sub: String?

    var body: some View {
        VStack(spacing: 2) {
            Text(title)
                .font(.caption2)
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.medium)
            if let sub = sub {
                Text(sub)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(Color(.systemGray6))
        .cornerRadius(8)
    }
}

// MARK: - Captcha WebView (captures token via JS interception)

struct CaptchaWebView: View {
    let url: URL
    let captchaSID: String
    let onSolved: (String) -> Void
    let onDismiss: () -> Void
    let onLimitDetected: () -> Void
    let onCaptchaReady: () -> Void
    let onLog: (String) -> Void
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Solve Captcha")
                    .font(.headline)
                Spacer()
                Button("Done") { onDismiss() }
                    .font(.headline)
            }
            .padding()

            ZStack {
                CaptchaWKWebView(
                    url: url,
                    onTokenCaptured: onSolved,
                    onLimitDetected: onLimitDetected,
                    onCaptchaReady: onCaptchaReady,
                    onLog: onLog
                )

                // Overlay shown ONLY while auto-refresh is hunting for a fresh
                // captcha after JS detected "Attempt limit reached". Goes away
                // as soon as the WebView reloads to a working captcha (JS
                // posts state:ready → tunnel.onCaptchaReady → captchaLimitReached=false).
                if tunnel.captchaLimitReached {
                    VStack(spacing: 16) {
                        ProgressView().scaleEffect(1.3)
                        Text("VK временно не отдаёт капчу")
                            .font(.headline)
                        Text("Ищем рабочую — попытка \(tunnel.captchaRefreshAttempt) из \(tunnel.maxCaptchaRefreshAttempts)")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(32)
                    .background(Color(.systemBackground).opacity(0.97))
                    .cornerRadius(16)
                    .shadow(radius: 12)
                }
            }
        }
    }
}

struct CaptchaWKWebView: UIViewRepresentable {
    let url: URL
    let onTokenCaptured: (String) -> Void
    // Called when JS detector concludes the loaded page is in "Attempt limit
    // reached" state (no interactive element + error text). TunnelManager
    // uses this to start the auto-refresh timer.
    let onLimitDetected: () -> Void
    // Called when JS detector sees a normal interactive captcha. TunnelManager
    // uses this to stop any running auto-refresh timer.
    let onCaptchaReady: () -> Void
    // Routes log lines from the WKWebView coordinator (which lives in the
    // main-app process) into vpn.log — so raw JS bridge messages and
    // state-transition diagnostics land in the same log file as the
    // extension's output instead of only in os_log / Console.app.
    let onLog: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            onTokenCaptured: onTokenCaptured,
            onLimitDetected: onLimitDetected,
            onCaptchaReady: onCaptchaReady,
            onLog: onLog
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true

        // Use an ephemeral data store so every CaptchaWKWebView instance starts
        // with a clean cookie jar. VK's anti-abuse cookies otherwise persist
        // across WebView recreations and cause the captcha page to return a
        // pre-solved state ("green checkmark on open"), which leaves the user
        // stuck — JS hooks never fire because the solve flow never runs.
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()

        let contentController = WKUserContentController()
        contentController.add(context.coordinator, name: "captchaToken")

        // Approach based on https://github.com/cacggghp/vk-turn-proxy/pull/97:
        // Load the captcha page directly (top-level, no iframe needed).
        // Intercept fetch/XHR to captchaNotRobot.check — the response contains
        // success_token which is what VK needs for the retry.
        // No need for postMessage interception or iframe wrapper.
        let js = """
        (function() {
            var h = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.captchaToken;
            if (!h) return;

            // Hook fetch to intercept captchaNotRobot.check response
            var origFetch = window.fetch;
            window.fetch = function() {
                var url = arguments[0];
                if (typeof url === 'object' && url.url) url = url.url;
                var urlStr = String(url);
                var p = origFetch.apply(this, arguments);
                if (urlStr.indexOf('captchaNotRobot.check') !== -1) {
                    p.then(function(response) {
                        return response.clone().json();
                    }).then(function(data) {
                        h.postMessage('check:' + JSON.stringify(data).substring(0, 1000));
                        if (data.response && data.response.success_token) {
                            h.postMessage('token:' + data.response.success_token);
                        } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                            // VK explicitly said "rate limited". Trigger auto-refresh
                            // immediately — don't wait for the 2.5s DOM heuristic
                            // (which would miss the limit state that only appears
                            // AFTER the user clicks the checkbox and the page
                            // dynamically switches to the error screen).
                            h.postMessage('state:limit:api_error_limit');
                        }
                    }).catch(function(e) {
                        h.postMessage('check-err:' + e.message);
                    });
                }
                return p;
            };

            // Hook XMLHttpRequest as fallback
            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._url = url;
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                if (this._url && String(this._url).indexOf('captchaNotRobot.check') !== -1) {
                    xhr.addEventListener('load', function() {
                        try {
                            var data = JSON.parse(xhr.responseText);
                            h.postMessage('xhr-check:' + JSON.stringify(data).substring(0, 1000));
                            if (data.response && data.response.success_token) {
                                h.postMessage('token:' + data.response.success_token);
                            } else if (data.response && data.response.status === 'ERROR_LIMIT') {
                                // Same as fetch path: VK hard-rate-limited us,
                                // trigger auto-refresh without waiting for the
                                // DOM heuristic.
                                h.postMessage('state:limit:api_error_limit');
                            }
                        } catch(e) {}
                    });
                }
                return origSend.apply(this, arguments);
            };

            h.postMessage('init:hooks installed');

            // Page-state detector: 2.5s after first render, look at whether
            // VK showed us an interactive captcha or an "Attempt limit reached"
            // (or equivalent) error. Post state:limit / state:ready to Swift —
            // TunnelManager runs the auto-refresh timer only on state:limit.
            function checkCaptchaState(source) {
                try {
                    var text = (document.body && document.body.innerText) || '';
                    var hasLimitText = /limit.*reached|лимит.*исчерп|превышен|try\\s*again\\s*later|attempt\\s*limit/i.test(text);
                    var hasInteractive = !!document.querySelector(
                        '[role="checkbox"], input[type="checkbox"], .VkIdNotRobotButton, [data-test-id*="captcha"], .vkuiCheckbox'
                    );
                    var state;
                    if (hasLimitText) {
                        state = 'limit';
                    } else if (hasInteractive) {
                        state = 'ready';
                    } else {
                        state = 'unknown';
                    }
                    h.postMessage('state:' + state + ':' + source);
                } catch (e) {
                    h.postMessage('state-err:' + e.message);
                }
            }

            // Run initial detection once DOM is ready + a 2.5s settle.
            function scheduleInitialDetection() {
                setTimeout(function() { checkCaptchaState('initial'); }, 2500);
            }
            if (document.readyState === 'complete' || document.readyState === 'interactive') {
                scheduleInitialDetection();
            } else {
                window.addEventListener('DOMContentLoaded', scheduleInitialDetection);
            }
        })();
        """
        let userScript = WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        contentController.addUserScript(userScript)
        config.userContentController = contentController

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView
        webView.customUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"

        // Load captcha URL directly — no iframe needed
        context.coordinator.lastLoadedURL = url.absoluteString
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // When VK rejects a success_token and the Go side fetches a fresh
        // captcha URL, SwiftUI rebinds this view with a new `url` but keeps
        // the same underlying WKWebView alive. Without an explicit reload the
        // user sees the stale page (still showing the green checkmark from
        // the previous solve) and has no way to interact — the only escape
        // is pressing Done. Detect the URL change and reload so the new
        // captcha appears automatically.
        let newURLStr = url.absoluteString
        if context.coordinator.lastLoadedURL != newURLStr {
            context.coordinator.log("URL changed, reloading WebView (\(String(newURLStr.prefix(80))))")
            context.coordinator.lastLoadedURL = newURLStr
            context.coordinator.resetForNewCaptcha()
            uiView.load(URLRequest(url: url))
        }
    }

    class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
        let onTokenCaptured: (String) -> Void
        let onLimitDetected: () -> Void
        let onCaptchaReady: () -> Void
        let onLog: (String) -> Void
        private var solved = false
        weak var webView: WKWebView?
        // Tracks which URL we last handed to `webView.load(...)`. Used by
        // updateUIView to detect real URL changes vs. SwiftUI re-renders with
        // the same state — avoids redundant reloads.
        var lastLoadedURL: String?

        init(
            onTokenCaptured: @escaping (String) -> Void,
            onLimitDetected: @escaping () -> Void,
            onCaptchaReady: @escaping () -> Void,
            onLog: @escaping (String) -> Void
        ) {
            self.onTokenCaptured = onTokenCaptured
            self.onLimitDetected = onLimitDetected
            self.onCaptchaReady = onCaptchaReady
            self.onLog = onLog
        }

        func log(_ msg: String) {
            // os_log / NSLog visible in Console.app when device is connected
            // to a Mac (useful for live debugging). onLog tunnels the same
            // message through TunnelManager → extension → vpn.log so
            // post-mortem analysis from a vpn.log dump is possible too.
            os_log("%{public}s", log: captchaLog, type: .default, msg)
            NSLog("[Captcha] %@", msg)
            onLog(msg)
        }

        // Called by updateUIView when the captcha URL changes mid-flight
        // (VK rejected a success_token and Go fetched a fresh captcha).
        // Resets the one-shot `solved` guard so the next success_token from
        // the new page is forwarded to the tunnel — otherwise the guard would
        // silently swallow every token after the first.
        func resetForNewCaptcha() {
            solved = false
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let body = message.body as? String else { return }
            log("JS: \(String(body.prefix(400)))")

            if body.hasPrefix("token:") {
                let token = String(body.dropFirst(6))
                log("SUCCESS_TOKEN (\(token.count) chars)")
                captureToken(token)
                return
            }

            // State detector posts `state:<kind>:<source>` — e.g.
            // "state:limit:initial" or "state:ready:initial". We react to
            // `limit` and `ready` kinds; `unknown` is logged for diagnostics
            // but no action taken (auto-refresh doesn't start on unknown to
            // avoid refresh loops on unrecognised layouts).
            if body.hasPrefix("state:") {
                let parts = body.split(separator: ":", maxSplits: 2).map(String.init)
                let kind = parts.count >= 2 ? parts[1] : ""
                switch kind {
                case "limit":
                    log("state=limit — delegating to auto-refresh handler")
                    DispatchQueue.main.async { self.onLimitDetected() }
                case "ready":
                    log("state=ready — delegating to stop-auto-refresh handler")
                    DispatchQueue.main.async { self.onCaptchaReady() }
                case "unknown":
                    log("state=unknown — no action (no interactive element and no known limit text)")
                default:
                    log("state=<unrecognised kind \(kind)>")
                }
                return
            }
        }

        private func captureToken(_ token: String) {
            guard !solved else { return }
            solved = true
            log("TOKEN CAPTURED (\(token.count) chars), sending to tunnel")
            DispatchQueue.main.async {
                self.onTokenCaptured(token)
            }
        }

        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            if let url = navigationAction.request.url {
                log("Nav: \(String(url.absoluteString.prefix(200)))")
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            log("FAIL: \(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            log("FAIL provisional: \(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            log("Loaded: \(String((webView.url?.absoluteString ?? "nil").prefix(150)))")
        }
    }
}

// MARK: - Logs View

struct LogsView: View {
    @State private var logText = ""
    @State private var autoScroll = true
    @State private var showShareSheet = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    /// Maximum characters to display — keeps UI responsive.
    /// The full file is still available via Share.
    private let maxDisplayChars = 100_000

    var body: some View {
        VStack(spacing: 0) {
            LogTextView(text: logText, autoScroll: autoScroll)

            Divider()

            HStack {
                Toggle("Auto-scroll", isOn: $autoScroll)
                    .font(.caption)
                    .toggleStyle(.switch)
                    .fixedSize()

                Spacer()

                Button(action: {
                    SharedLogger.shared.clearLogs()
                    logText = ""
                }) {
                    Label("Clear", systemImage: "trash")
                        .font(.caption)
                }

                Button(action: { showShareSheet = true }) {
                    Label("Share", systemImage: "square.and.arrow.up")
                        .font(.caption)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .navigationTitle("Logs")
        .onAppear { loadLogs() }
        .onReceive(timer) { _ in loadLogs() }
        .sheet(isPresented: $showShareSheet) {
            if let url = SharedLogger.shared.logFileURL,
               FileManager.default.fileExists(atPath: url.path) {
                ShareSheet(activityItems: [url])
            }
        }
    }

    private func loadLogs() {
        var text = SharedLogger.shared.readLogs()
        if text.isEmpty {
            text = "No logs yet"
        } else if text.count > maxDisplayChars {
            // Show only the tail so the most recent logs are visible
            let startIndex = text.index(text.endIndex, offsetBy: -maxDisplayChars)
            text = "… (truncated)\n" + String(text[startIndex...])
        }
        logText = text
    }
}

/// UITextView wrapper — handles large text without SwiftUI layout explosion.
struct LogTextView: UIViewRepresentable {
    let text: String
    let autoScroll: Bool

    func makeUIView(context: Context) -> UITextView {
        let tv = UITextView()
        tv.isEditable = false
        tv.isSelectable = true
        tv.font = UIFont.monospacedSystemFont(ofSize: 10, weight: .regular)
        tv.textColor = .label
        tv.backgroundColor = .systemBackground
        tv.textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
        return tv
    }

    func updateUIView(_ tv: UITextView, context: Context) {
        // Only update if text actually changed to avoid unnecessary work
        if tv.text != text {
            tv.text = text
            if autoScroll && !text.isEmpty {
                let bottom = NSRange(location: text.count - 1, length: 1)
                tv.scrollRangeToVisible(bottom)
            }
        }
    }
}

/// UIActivityViewController wrapper for sharing the log file.
struct ShareSheet: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    ContentView()
}
