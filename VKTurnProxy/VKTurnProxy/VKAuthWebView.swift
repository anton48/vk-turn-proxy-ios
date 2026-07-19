import SwiftUI
import WebKit

/// Outcome of a VKAuthWebView login session.
enum VKAuthResult {
    /// The logged-in pair was captured. `cookieHeader` is the ready-to-send
    /// `Cookie:` header ("remixsid=…; p=…"); `expiry` is the earlier of the two
    /// cookies' expiry dates.
    case harvested(cookieHeader: String, expiry: Date)
    /// The user closed the sheet without completing login.
    case cancelled
}

/// VKAuthWebView — embedded VK login for the non-anonymous "VKAuth" cred path
/// (see pkg/proxy/creds_vkcookie.go + VKCookieStore). The user signs in to a
/// (burner) VK account manually; any 2FA "just works" because this is a real
/// browser session. We watch the webview's own cookie store for the logged-in
/// pair — `remixsid` (.vk.com session) + `p` (.login.vk.com auth token) — and,
/// once BOTH appear, build the Cookie header + the pair's expiry and hand them
/// back via `onResult`. VK's auth cookies are HttpOnly, so they're only visible
/// through WKHTTPCookieStore.getAllCookies() (NOT document.cookie) — harvesting
/// happens here in Swift, not via injected JS.
struct VKAuthWebView: View {
    let onResult: (VKAuthResult) -> Void

    @State private var harvested = false
    @State private var statusText = "Войдите в аккаунт VK (можно burner). 2FA поддерживается."

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Вход в VK").font(.headline)
                Spacer()
                Button("Отмена") { onResult(.cancelled) }
                    .font(.headline)
            }
            .padding()

            VKAuthWKWebView(
                onHarvested: { header, expiry in
                    guard !harvested else { return }
                    harvested = true
                    onResult(.harvested(cookieHeader: header, expiry: expiry))
                },
                onStatus: { statusText = $0 }
            )

            Text(statusText)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(8)
        }
    }
}

/// UIViewRepresentable wrapping a WKWebView that loads VK login and polls its
/// cookie store for the remixsid + p pair.
struct VKAuthWKWebView: UIViewRepresentable {
    let onHarvested: (_ cookieHeader: String, _ expiry: Date) -> Void
    let onStatus: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onHarvested: onHarvested, onStatus: onStatus)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        // Non-persistent store → a clean login each time (no stale cookies from
        // a previous account). We read the harvested cookies from THIS store.
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView
        // vk.ru (VK is migrating vk.com->vk.ru) redirects an unauthenticated
        // session through the VK ID flow (login.vk.ru / id.vk.ru), which sets
        // `p`. The cookie harvest above accepts BOTH .vk.com and .vk.ru domains,
        // so whichever family VK lands the session on is caught.
        if let url = URL(string: "https://vk.ru/") {
            webView.load(URLRequest(url: url))
        }
        context.coordinator.startPolling()
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        coordinator.stopPolling()
    }

    class Coordinator: NSObject, WKNavigationDelegate {
        let onHarvested: (_ cookieHeader: String, _ expiry: Date) -> Void
        let onStatus: (String) -> Void
        weak var webView: WKWebView?
        private var timer: Timer?
        private var done = false

        init(onHarvested: @escaping (_ cookieHeader: String, _ expiry: Date) -> Void,
             onStatus: @escaping (String) -> Void) {
            self.onHarvested = onHarvested
            self.onStatus = onStatus
        }

        func startPolling() {
            // The pair appears only after the full login (and any 2FA)
            // completes; poll the cookie store until it does.
            timer = Timer.scheduledTimer(withTimeInterval: 1.2, repeats: true) { [weak self] _ in
                self?.tryHarvest()
            }
        }

        func stopPolling() {
            timer?.invalidate()
            timer = nil
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            tryHarvest()
        }

        private func tryHarvest() {
            guard !done, let store = webView?.configuration.websiteDataStore.httpCookieStore else { return }
            store.getAllCookies { [weak self] cookies in
                guard let self = self, !self.done else { return }
                // Need BOTH remixsid (.vk.com session) and p (.login.vk.com).
                var remixsid: HTTPCookie?
                var p: HTTPCookie?
                for c in cookies {
                    let domain = c.domain.hasPrefix(".") ? c.domain : "." + c.domain
                    // VK domain migration (vk.com -> vk.ru): accept the session/
                    // auth cookies on EITHER domain — vk.com still issues them today.
                    if c.name == "remixsid", (domain.hasSuffix(".vk.com") || domain.hasSuffix(".vk.ru")) { remixsid = c }
                    if c.name == "p", (domain.hasSuffix(".login.vk.com") || domain.hasSuffix(".login.vk.ru")) { p = c }
                }
                guard let r = remixsid, let pp = p else {
                    self.onStatus("Ожидаю завершения входа…")
                    return
                }
                self.done = true
                self.stopPolling()
                let header = "remixsid=\(r.value); p=\(pp.value)"
                // Pair expiry = the earlier of the two (both normally ~1 year).
                // Fall back to +30 days if a cookie is session-scoped (no
                // expiresDate) — defensive; remixsid/p normally carry one.
                let fallback = Date().addingTimeInterval(30 * 24 * 3600)
                let expiry = min(r.expiresDate ?? fallback, pp.expiresDate ?? fallback)
                self.onStatus("Вход выполнен ✓")
                DispatchQueue.main.async { self.onHarvested(header, expiry) }
            }
        }
    }
}
