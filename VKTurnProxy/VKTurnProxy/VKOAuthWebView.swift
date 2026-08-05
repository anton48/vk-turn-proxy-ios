import SwiftUI
import WebKit

/// Outcome of a VKOAuthWebView session.
enum VKOAuthResult {
    /// A user access token with the `calls` scope. Never persisted anywhere —
    /// the caller uses it immediately and drops it.
    case token(String)
    /// VK showed the sign-in screen instead of "Continue as <user>", i.e. the
    /// cookies we injected did not authenticate the session. The caller must
    /// send the user through the NORMAL login (VKAuthWebView) first — the
    /// sign-in form inside THIS flow is broken (both the phone and the email
    /// variants answer "Unknown method passed [3]"), so retrying here is futile.
    case needsLogin
    case failed(String)
    case cancelled
}

/// Everything about the VK OAuth implicit flow that is worth naming once.
enum VKOAuth {
    /// VK's own web app id. We are borrowing someone else's application, which
    /// is what makes `scope=calls` obtainable without a business profile — and
    /// what makes this the first thing to check if the flow ever starts
    /// failing wholesale. One constant, one place to change.
    static let clientID = "6287487"

    /// Where the flow ends: VK appends `#access_token=…` to this URL.
    static let redirectHost = "oauth.vk.ru"
    static let redirectPath = "/blank.html"

    static var authorizeURL: URL? {
        URL(string: "https://oauth.vk.ru/authorize?client_id=\(clientID)&scope=calls&response_type=token")
    }

    /// Which domain each stored cookie has to be planted on. `VKCookieStore`
    /// keeps a raw `Cookie:` HEADER with no domains, but the flow's identity
    /// gate — `POST login.vk.ru/?act=connect_internal` — only sees a cookie if
    /// its domain covers that host. Measured 2026-08-05 (see the memory note
    /// on VK OAuth cookie scopes): `remixsid` is issued on `.vk.ru`, `p` on
    /// `.login.vk.ru`. Put both on one domain and the gate sees neither.
    ///
    /// `remixnsid` is deliberately absent: it is host-only on `vk.ru`, so it
    /// never reaches ANY host in this flow and cannot matter.
    static func domain(forCookie name: String) -> String? {
        switch name {
        case "remixsid": return ".vk.ru"
        case "p": return ".login.vk.ru"
        default: return nil
        }
    }

    /// Split a stored `Cookie:` header back into per-domain cookies.
    static func cookies(fromHeader header: String, expiry: Date) -> [HTTPCookie] {
        header.split(separator: ";").compactMap { pair in
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { return nil }
            let name = kv[0].trimmingCharacters(in: .whitespaces)
            let value = kv[1].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty, let domain = domain(forCookie: name) else { return nil }
            return HTTPCookie(properties: [
                .name: name,
                .value: value,
                .domain: domain,
                .path: "/",
                .secure: "TRUE",
                .expires: expiry,
            ])
        }
    }

    /// Pull the token out of the redirect URL's fragment.
    static func token(fromRedirect url: URL) -> String? {
        guard url.host == redirectHost, url.path == redirectPath,
              let fragment = url.fragment else { return nil }
        for part in fragment.split(separator: "&") {
            let kv = part.split(separator: "=", maxSplits: 1)
            if kv.count == 2, kv[0] == "access_token", !kv[1].isEmpty {
                return String(kv[1])
            }
        }
        return nil
    }
}

/// VKOAuthWebView — obtains a VK user access token with the `calls` scope, so
/// the app can create a call via `calls.start`. Calls created that way survive
/// their creator leaving; calls created by hand in a browser no longer do
/// (GitHub issue #69).
///
/// The flow is `oauth.vk.ru/authorize` → `id.vk.ru/auth` → tap "Continue as
/// <user>" → `oauth.vk.ru/blank.html#access_token=…`. We plant the stored
/// login cookies first so the middle screen can recognise the account; the tap
/// itself stays with the user, which is also the only moment they are shown
/// WHOSE account is about to own the call.
struct VKOAuthWebView: View {
    let onResult: (VKOAuthResult) -> Void

    @State private var done = false
    @State private var statusText = "Открываем VK ID…"

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Создание звонка VK").font(.headline)
                Spacer()
                Button("Отмена") { finish(.cancelled) }
                    .font(.headline)
            }
            .padding()

            VKOAuthWKWebView(
                onToken: { finish(.token($0)) },
                onNeedsLogin: { finish(.needsLogin) },
                onStatus: { statusText = $0 }
            )

            Text(statusText)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(8)
        }
    }

    private func finish(_ r: VKOAuthResult) {
        guard !done else { return }
        done = true
        onResult(r)
    }
}

/// The webview half: plants the cookies, loads the authorize URL, and watches
/// for the redirect that carries the token.
private struct VKOAuthWKWebView: UIViewRepresentable {
    let onToken: (String) -> Void
    let onNeedsLogin: () -> Void
    let onStatus: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onToken: onToken, onNeedsLogin: onNeedsLogin, onStatus: onStatus)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        // Ephemeral: this webview starts from nothing but the cookies we plant
        // deliberately, so a pass/fail says something about THOSE cookies and
        // not about whatever a previous session left behind.
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()

        let controller = WKUserContentController()
        controller.add(context.coordinator, name: "vkoauth")
        // The identity gate is a single call the page makes at load time —
        // POST login.vk.ru/?act=connect_internal — and its answer is what
        // decides "Continue as <user>" vs the sign-in form. Hooking fetch at
        // documentStart is the only way to see it: by the time a page-level
        // script could run, the call has already gone. This is diagnosis only;
        // the token still arrives via the redirect, in Swift.
        controller.addUserScript(WKUserScript(source: """
        (function() {
            var h = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.vkoauth;
            if (!h) return;
            var of = window.fetch;
            window.fetch = function(input, init) {
                var url = typeof input === 'string' ? input : (input && input.url) || '';
                var p = of.apply(this, arguments);
                if (url.indexOf('act=connect_internal') >= 0) {
                    p.then(function(r) {
                        return r.clone().text();
                    }).then(function(t) {
                        // Report the SHAPE of the answer, never its contents:
                        // this response carries session material.
                        h.postMessage('gate:' + (t.indexOf('"error"') >= 0 ? 'error' : 'ok') + ' len=' + t.length);
                    }).catch(function() { h.postMessage('gate:unreadable'); });
                }
                return p;
            };
        })();
        """, injectionTime: .atDocumentStart, forMainFrameOnly: false))
        config.userContentController = controller

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView
        context.coordinator.plantCookiesAndLoad()
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let onToken: (String) -> Void
        let onNeedsLogin: () -> Void
        let onStatus: (String) -> Void
        weak var webView: WKWebView?
        private var finished = false

        init(onToken: @escaping (String) -> Void,
             onNeedsLogin: @escaping () -> Void,
             onStatus: @escaping (String) -> Void) {
            self.onToken = onToken
            self.onNeedsLogin = onNeedsLogin
            self.onStatus = onStatus
        }

        func plantCookiesAndLoad() {
            guard let webView = webView, let url = VKOAuth.authorizeURL else { return }
            guard let stored = VKCookieStore.load(), stored.expiry > Date() else {
                SharedLogger.shared.log("[vk-oauth] no stored VK cookies — normal login required first")
                onStatus("Нет сохранённого входа в VK. Сначала войдите через «Use VK account (cookie) auth».")
                onNeedsLogin()
                return
            }

            let cookies = VKOAuth.cookies(fromHeader: stored.cookieHeader, expiry: stored.expiry)
            // Names only. The values are login credentials.
            let names = cookies.map { "\($0.name)→\($0.domain)" }.joined(separator: ", ")
            SharedLogger.shared.log("[vk-oauth] planting \(cookies.count) cookie(s): \(names)")

            let store = webView.configuration.websiteDataStore.httpCookieStore
            let group = DispatchGroup()
            for c in cookies {
                group.enter()
                store.setCookie(c) { group.leave() }
            }
            group.notify(queue: .main) { [weak self] in
                self?.onStatus("Открываем VK ID…")
                webView.load(URLRequest(url: url))
            }
        }

        // MARK: - Token capture

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            if let url = navigationAction.request.url, let token = VKOAuth.token(fromRedirect: url) {
                decisionHandler(.cancel)
                guard !finished else { return }
                finished = true
                SharedLogger.shared.log("[vk-oauth] access token acquired (\(token.count) chars)")
                onStatus("Токен получен, создаём звонок…")
                onToken(token)
                return
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            guard let url = webView.url else { return }
            SharedLogger.shared.log("[vk-oauth] loaded \(url.host ?? "?")\(url.path)")
            if url.host == "id.vk.ru" {
                onStatus("Подтвердите аккаунт, от имени которого создаётся звонок.")
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            SharedLogger.shared.log("[vk-oauth] navigation failed: \(error.localizedDescription)")
        }

        // MARK: - Gate verdict (diagnosis only)

        func userContentController(_ controller: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            guard let body = message.body as? String else { return }
            SharedLogger.shared.log("[vk-oauth] \(body)")
        }
    }
}
