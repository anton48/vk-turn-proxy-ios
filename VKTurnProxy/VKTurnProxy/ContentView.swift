import SwiftUI
import UIKit
import NetworkExtension
import WebKit
import UniformTypeIdentifiers
import os.log

private let captchaLog = OSLog(subsystem: "com.vkturnproxy.app", category: "Captcha")

extension View {
    /// Lets a DRAG on empty Form/List space dismiss the keyboard, the way
    /// Apple's own Settings app behaves. Half of a pair: this covers dragging,
    /// `KeyboardDismisser` covers tapping — SwiftUI has no equivalent for the
    /// tap, which is why that one is hand-rolled in UIKit. The two do not
    /// overlap and neither substitutes for the other.
    ///
    /// iOS 16+ only; the app's floor is iOS 15.0, so pre-16 keeps the original
    /// behaviour (dismiss via return/back) for drags — the tap path works on
    /// every version.
    @ViewBuilder
    func dismissKeyboardOnDrag() -> some View {
        if #available(iOS 16.0, *) {
            self.scrollDismissesKeyboard(.interactively)
        } else {
            self
        }
    }
}

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager.shared


    // 🚨 THIS VIEW HOSTS THE `NavigationView`, SO IT SUBSCRIBES TO NOTHING BUT
    // THE TUNNEL. Re-rendering this body tears down whatever is pushed (build
    // 177, GitHub #65), so everything that follows the ACTIVE SERVER lives in
    // `ActiveServerControls` below, which owns its own observation. An
    // `@AppStorage` here would be the same trap — it subscribes even unread.
    //
    // Until build 350 the server name was a `@State` snapshot refreshed in
    // `.onAppear` (plus a `willEnterForeground` hook for the Live Activity's
    // picker). That is sound only while the active server can change nowhere
    // but on a screen you have to come BACK from — and a tapped connection
    // link applies while THIS screen is on top, so the snapshot went stale:
    // the subtitle named the old server while Connect, which reads the store
    // live, used the new one. Reading the store at render time in a child
    // removes the class, not the case.
    var body: some View {
        NavigationView {
            // ScrollView is the safety net for very small screens
            // (iPhone SE etc.). When the stats grid grows enough that
            // it would push Logs/Settings below the visible area, the
            // user can scroll instead of losing access to them. On
            // larger screens the content fits without scrolling.
            ScrollView {
                VStack(spacing: 16) {
                    // Status indicator — compact size so the rest of the
                    // controls stay visible on small screens.
                    Circle()
                        .fill(statusColor)
                        .frame(width: 44, height: 44)
                        .shadow(color: statusColor.opacity(0.5), radius: 8)
                        .padding(.top, 8)

                    Text(statusText)
                        .font(.headline)

                    // Everything that depends on the ACTIVE SERVER — its name,
                    // the blocking-validation caption, the stats and the Connect
                    // button — is one child that observes `ServerStore`, so a
                    // link import or a Live Activity switch re-renders THAT and
                    // not the NavigationView host.
                    ActiveServerControls(tunnel: tunnel)

                    // Logs & Settings links
                    MainNavigationLinks(tunnel: tunnel)
                        .padding(.bottom, 8)
                }
                .frame(maxWidth: .infinity)
                .padding(.top, 8)
            }
            .navigationTitle("VK Turn Proxy")
            .navigationBarTitleDisplayMode(.inline)
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
            // VKAuth login during cookie pre-bootstrap (connect flow). Driven by
            // tunnel.vkLoginPending; on result, resume awaitVKLogin().
            .sheet(isPresented: $tunnel.vkLoginPending) {
                VKAuthWebView { result in
                    tunnel.onVKLoginResult(result)
                }
            }
            // The root consumer for tapped vkturnproxy:// links. A separate
            // view so that its inbox observation cannot re-render this body.
            // → ConnectionLinkImport.swift.
            .background(ConnectionLinkImporter())
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
}

/// The two links out of the main screen, deliberately in a view of their own.
///
/// `tunnel` is held but NOT observed (plain `let`, no `@ObservedObject`), so
/// this subtree's value never changes and SwiftUI leaves it — and the screens
/// pushed from it — untouched when ContentView re-renders. Belt and braces
/// alongside the TunnelLiveStats split: build 177 already popped this app's
/// pushed screens once via a different publisher (@AppStorage writes), and
/// keeping the links out of the churning body makes that class of regression
/// harmless rather than a repeat bug. LogsView observes the manager itself, so
/// it still updates live once pushed.
private struct MainNavigationLinks: View {
    let tunnel: TunnelManager

    var body: some View {
        HStack(spacing: 24) {
            NavigationLink(destination: LogsView(tunnel: tunnel)) {
                Label("Logs", systemImage: "doc.text")
            }
            NavigationLink(destination: SpeedTestView(tunnel: tunnel)) {
                Label("Speed test", systemImage: "speedometer")
            }
            NavigationLink(destination: SettingsView()) {
                Label("Settings", systemImage: "gear")
            }
        }
    }
}

/// The part of the main screen that depends on the ACTIVE SERVER: its name, the
/// blocking-validation caption, the stats grid and the Connect button.
///
/// 🚨 IT IS A SEPARATE VIEW SO THAT IT CAN OBSERVE `ServerStore`. `ContentView`
/// hosts the `NavigationView` and must not: observing the store there re-renders
/// the host on every edit keystroke and tears down whatever is pushed (build
/// 177, GitHub #65). Same isolation as `MainNavigationLinks` and
/// `TunnelLiveStats`, and the same reason `ConnectionLinkImporter` exists.
///
/// 🎯 WHY IT IS READ AT RENDER TIME AND NOT SNAPSHOT. `ContentView` used to keep
/// the name in `@State`, refreshed in `.onAppear` — which fires when Settings is
/// popped, and that covered every way the active server could change, because
/// changing it required going to Settings and coming back. A tapped connection
/// link applies while the main screen is on top and nothing pops, so the
/// snapshot survived the change: the subtitle kept naming the previous server
/// while the Connect action, which reads `ServerStore.shared.activeServer` live,
/// used the new one. The validation gate had the same split — it reads the store
/// live but was only recomputed when something ELSE re-rendered the host, so a
/// link that writes no `vkLink` (freeturn://, or an unchanged call link) left
/// Connect greyed out on a config that had just become valid.
private struct ActiveServerControls: View {
    @ObservedObject private var store = ServerStore.shared

    /// Observed rather than passed-and-read: this body branches on
    /// `tunnel.status`, and SwiftUI may skip re-evaluating a child whose stored
    /// properties are unchanged — which a class reference is, by definition.
    /// `MainNavigationLinks` can take a plain `let` because it only forwards it.
    @ObservedObject var tunnel: TunnelManager

    /// vkLink is the one GLOBAL setting this screen validates (it is not
    /// per-server). It lives here rather than on the host for the reason above:
    /// an `@AppStorage` subscribes whether or not the value is read, so on the
    /// host it re-renders the NavigationView on every write.
    @AppStorage("vkLink") private var vkLink = ""

    /// First BLOCKING (.error) validation issue for the ACTIVE server mode, or
    /// nil if the config is good enough to attempt a connection. Gates the
    /// Connect button — a malformed required field would otherwise just fail
    /// the handshake silently. Mode-aware: WRAP-A validates the password (WG
    /// keys are server-provisioned via GETCONF); the other modes validate the
    /// WG keys instead. Format / optional-field issues are surfaced as
    /// non-blocking hints in Settings, not here. Mirrors serverModeBinding's
    /// precedence (useWrapA > useSrtp > useWrap).
    private var configValidationError: String? {
        // Per-server fields come from the ACTIVE server (read from the store,
        // NOT from the flat @AppStorage keys — those are no longer projected
        // during Settings, which is what caused the NavigationView pop on iOS
        // 26). vkLink is global.
        let s = store.activeServer
        var issues: [ConfigValidation.Issue?] = [
            ConfigValidation.vkLink(vkLink),
            ConfigValidation.peerAddress(s.peerAddress),
            ConfigValidation.turnOverride(s.turnServerOverride),
        ]
        if s.useWrapA {
            issues.append(ConfigValidation.wrapAPassword(s.wrapAPassword))
        } else {
            issues.append(ConfigValidation.wgKey(s.privateKey, label: "Private key", required: true))
            issues.append(ConfigValidation.wgKey(s.peerPublicKey, label: "Peer public key", required: true))
            issues.append(ConfigValidation.wgKey(s.presharedKey, label: "Preshared key", required: false))
            issues.append(ConfigValidation.tunnelAddress(s.tunnelAddress))
            // SRTP+WRAP / SRTP-WRAP-S also need the hex key.
            if (!s.useSrtp && s.useWrap) || s.useWrapS {
                issues.append(ConfigValidation.wrapKeyHex(s.wrapKeyHex))
            }
        }
        return issues.compactMap { $0 }.first { $0.severity == .error }?.message
    }

    /// True when Connect is blocked by a required field being empty/invalid.
    /// Named once and used by BOTH `.disabled` and the button colour: while
    /// they disagreed the button stayed a confident blue that swallowed taps
    /// with no explanation, which reads as a broken app rather than as
    /// "something above is missing".
    private var connectBlocked: Bool {
        tunnel.status != .connected && tunnel.status != .connecting && configValidationError != nil
    }

    private var buttonText: String {
        if tunnel.preBootstrapInProgress { return "Disconnect" }
        switch tunnel.status {
        case .connected, .connecting: return "Disconnect"
        default: return "Connect"
        }
    }

    private var buttonColor: Color {
        if connectBlocked { return .gray }
        if tunnel.preBootstrapInProgress { return .red }
        switch tunnel.status {
        case .connected, .connecting: return .red
        default: return .blue
        }
    }

    var body: some View {
        let server = store.activeServer
        return VStack(spacing: 16) {
            // Which named server this status refers to.
            Text(tunnel.status == .connected
                 ? "Connected to \(server.serverName)"
                 : "Server: \(server.serverName)")
                .font(.subheadline)
                .foregroundColor(.secondary)

            if let error = tunnel.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            // Blocking config-validation error for the active server mode —
            // shown only while disconnected (it gates the Connect button
            // below). Required-field errors only; non-blocking format hints
            // live inline in Settings.
            if tunnel.status != .connected, tunnel.status != .connecting,
               let v = configValidationError {
                Text(v)
                    .font(.caption)
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            // Stats (shown when connected)
            if tunnel.status == .connected {
                StatsView(live: tunnel.live)
                    .padding(.horizontal)
            }

            // Connect / Disconnect button
            Button(action: {
                if tunnel.status == .connected || tunnel.status == .connecting {
                    // Log user-initiated stop so we can later distinguish
                    // "user pressed Disconnect" from iOS-side stops with
                    // the same reason=1 (.userInitiated) NEProviderStopReason.
                    // iOS occasionally fires stopTunnel(reason=1) for non-
                    // user-initiated reasons (network change with
                    // includeAllNetworks=true being the suspected case);
                    // having this log line lets us differentiate at triage
                    // time rather than guessing.
                    NSLog("[UI] user pressed Disconnect button (status=\(tunnel.status.rawValue))")
                    SharedLogger.shared.log("[UI] user pressed Disconnect button (status=\(tunnel.status.rawValue))")
                    tunnel.disconnect()
                } else {
                    // Per-server fields come from the ACTIVE server (read from
                    // the same store this view renders, so the button and the
                    // name above can never disagree); vkLink / VKAuth /
                    // forceLegacyCaptcha are global.
                    let active = store.activeServer
                    NSLog("[UI] user pressed Connect button (status=\(tunnel.status.rawValue), server=\"\(active.serverName)\" [\(active.modeLabel)])")
                    SharedLogger.shared.log("[UI] user pressed Connect button (status=\(tunnel.status.rawValue), server=\"\(active.serverName)\" [\(active.modeLabel)])")
                    let config = TunnelConfig.make(for: active)
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
            .padding(.top, 8)
            // Block Connect when a required field for the active mode is
            // empty/invalid (e.g. WRAP-A without a password → Go disables
            // WRAP-A → broken direct fallback; or a malformed peerAddress /
            // WG key). Never disables the Disconnect action.
            .disabled(connectBlocked)
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Server Mode

/// Tri-state server transport selector.
///
/// Persisted as the existing pair of @AppStorage booleans (useSrtp +
/// useWrap) for backward compatibility with the JSON contract bridged
/// to Go, with old backups, and with Connection Links generated by
/// quick_link.py. The Binding<ServerMode> below maps the two flags to
/// one selected case at render time and writes both back when the user
/// changes the Picker — guaranteeing mutual exclusion in the UI without
/// changing AppConfig / TunnelConfig field names.
///
/// Old backup mapping:
///   useSrtp=true,  useWrap=false  → .srtp     (current production)
///   useSrtp=false, useWrap=true   → .srtpWrap (new SRTP+WRAP path)
///   useSrtp=false, useWrap=false  → .legacy   (raw DTLS+WG)
///   useSrtp=true,  useWrap=true   → .srtp     (treat as SRTP, see Binding)
enum ServerMode: Int, CaseIterable, Identifiable {
    case legacy = 0
    case srtp = 1
    case srtpWrap = 2
    // srtpWrapA: interop with amurcanov's proxy-turn-vk-android server.
    // Gated by a separate @AppStorage("useWrapA") flag (the (useSrtp,useWrap)
    // pair is already saturated). NOT SRTP despite the grouping — WRAP-A
    // RTP-obfs → plain DTLS → GETCONF auto-provisioning → WireGuard.
    case srtpWrapA = 3
    // srtpWrapS: interop with samosvalishe/free-turn-proxy. Gated by the
    // @AppStorage("useWrapS") flag; carries an obf-profile (rtpopus/rtpopus2/
    // rtpopus3) + a Client-ID record inside DTLS. Same DTLS+WireGuard data path
    // as SRTP+WRAP (the user still enters WG keys), just a richer obf layer.
    case srtpWrapS = 4

    var id: Int { rawValue }

    var label: String {
        switch self {
        case .legacy: return "Legacy (DTLS+WG)"
        case .srtp: return "SRTP"
        case .srtpWrap: return "SRTP+WRAP"
        case .srtpWrapA: return "SRTP-WRAP-A"
        case .srtpWrapS: return "SRTP-WRAP-S"
        }
    }
}

// MARK: - Settings Screen

struct SettingsView: View {
    // Only the two GLOBAL settings live here. Every per-server field moved to
    // ServerEditView (build 173-180) and is edited through ServerStore; the 20
    // per-server @AppStorage keys this view still declared were dead weight
    // that also kept it subscribed to writes it has no interest in.
    @AppStorage("vkLink") private var vkLink = ""
    // VKAuth: the non-anonymous "VK account (cookie)" cred-path toggle. When ON,
    // the app uses ONLY the cookie path (no anonymous fallback). The cookies
    // themselves live in the Keychain (VKCookieStore), NOT here and NOT in
    // backups — this is just the on/off switch. Turning it OFF does not delete
    // the cookies.
    @AppStorage("VKAuth") private var vkAuthEnabled = false

    // Named-server store (M2). The active server's fields are projected into the
    // flat @AppStorage keys above by ServerStore, so ContentView's connect path
    // stays unchanged. This view now edits only the GLOBAL vkLink/VKAuth here;
    // per-server fields live in ServerEditView.
    @ObservedObject private var store = ServerStore.shared

    // Backup & Restore state. exportURL drives the share sheet; the
    // sheet only appears when this is non-nil so the URL is guaranteed
    // valid by the time UIActivityViewController is constructed. Each
    // confirm alert and the document picker are gated by their own
    // `show*` flag — keeping them independent prevents any one of them
    // from blocking the others if the user rapid-taps.
    //
    // Wrapped in IdentifiableURL because sheet(item:) requires the bound
    // type to be Identifiable, and we deliberately avoid extending URL
    // itself — Apple may ship that conformance in a future Foundation
    // and the resulting silent override would be a debugging trap.
    @State private var exportURL: IdentifiableURL? = nil
    @State private var showImportPicker = false
    @State private var pendingImportConfig: AppConfig? = nil
    @State private var showImportConfirm = false
    @State private var showResetConfirm = false
    @State private var showResetProfileConfirm = false
    // VKAuth (cookie login) UI state.
    @State private var showVKAuthLogin = false
    @State private var showVKCallCreate = false
    @State private var vkCallStatus = ""
    @State private var showDeleteCookiesConfirm = false
    @State private var vkCookieInfo: VKCookieStore.Stored? = nil
    @State private var alertMessage: String? = nil
    @State private var alertTitle: String = ""

    // 1-Click Connection Link import, PASTE PATH ONLY. Same flow as Full
    // Backup but with a separate state pair so a user juggling both never gets
    // confusing alert collisions. 🚫 This screen is NOT a consumer of
    // `ConnectionLinkInbox` — a tapped vkturnproxy:// / wdtt:// / freeturn://
    // URL is handled by `ConnectionLinkImporter` at the root, and re-attaching
    // the inbox here would give the app two consumers (double prompt, or one
    // swallowing the other's URL). → ConnectionLinkImport.swift.
    @State private var pendingConnectionLink: ConnectionLink? = nil
    @State private var showConnectionLinkConfirm = false

    // serverModeBinding lived here until the server-mode Picker moved into
    // ServerEditView, which has its own draft-backed equivalent. It survived as
    // dead code that still WROTE the flat mode keys — the one thing this screen
    // must never do while a child is pushed. Removed in build 196.

    /// Inline validation caption shown under a field. Red for blocking
    /// (.error) issues, orange for non-blocking (.warning) ones; renders
    /// nothing when the field is OK. Uses the shared ConfigValidation so the
    /// inline hint and the Connect-gate in ContentView always agree.
    @ViewBuilder
    private func hint(_ issue: ConfigValidation.Issue?) -> some View {
        if let issue {
            Text(issue.message)
                .font(.caption)
                .foregroundColor(issue.severity == .error ? .red : .orange)
        }
    }

    // VKAuth multi-call helpers. vkLink is multiline: anonymous mode uses the
    // FIRST line; cookie (VKAuth) mode uses ALL lines (each call = 2 TURN relays).
    private var vkLinkLines: [String] {
        vkLink.split(whereSeparator: { $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
    private var vkLinkPrimary: String { vkLinkLines.first ?? "" }

    /// Create a call with the freshly-obtained token and put its link FIRST in
    /// the field. First, not appended: `TunnelConfig.make` treats line one as
    /// the primary call, so a call created just now is the one the next
    /// connection uses — which is the whole point of pressing the button.
    /// Existing lines are kept (cookie mode spreads across all of them).
    @MainActor
    private func createVKCall(token: String) async {
        switch await VKCallsAPI.startCall(accessToken: token) {
        case let .success(created):
            let link = created.joinLink.trimmingCharacters(in: .whitespacesAndNewlines)
            if vkLinkLines.contains(link) {
                vkCallStatus = "VK returned a link that is already in the list."
                return
            }
            vkLink = ([link] + vkLinkLines).joined(separator: "\n")
            vkCallStatus = "Call created and added as the first link."
        case let .failure(err):
            vkCallStatus = err.userMessage
        }
    }
    // Cookie-mode connection cap. Shared with the value connect() actually
    // applies (TunnelConfig.effectiveNumConnections) so the label can't drift
    // from what the tunnel does — it did exactly that from build 163 to 181.
    private var cookieConnCap: Int { TunnelConfig.cookieConnCap(callLinks: vkLinkLines.count) }
    var body: some View {
        Form {
            Section("VK Call Link") {
                VStack(alignment: .leading, spacing: 4) {
                    Text(vkAuthEnabled
                         ? "VK Call Link(s) — one per line (currently \(vkLinkLines.count))"
                         : "VK Call Link")
                        .font(.caption).foregroundColor(.secondary)
                    TextEditor(text: $vkLink)
                        // 38pt was ~1 line — a real join link (vk.ru/call/join/<hash>)
                        // wraps to 2-3 lines at typical widths and got clipped inside
                        // the field with no visual hint there was more to scroll to.
                        .frame(minHeight: vkAuthEnabled ? 110 : 70)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                if vkAuthEnabled {
                    let n = vkLinkLines.count
                    Text(n == 0
                         ? "Add at least one call link (one per line). Each adds 2 TURN relays (~20 connections); the first line is also anonymous mode."
                         : "\(n) link\(n == 1 ? "" : "s") → \(n * 2) TURN relays, up to \(cookieConnCap) connections. First line is also the anonymous-mode call.")
                        .font(.caption2).foregroundColor(.secondary)
                }
                hint(ConfigValidation.vkLink(vkLinkPrimary))

                // Create a call through VK's API instead of by hand in a
                // browser. VK now ends a hand-made call the moment its creator
                // leaves, so links made today die immediately (older ones keep
                // working) — GitHub issue #69. A call started via calls.start
                // survives with nobody in it.
                Button {
                    vkCallStatus = ""
                    showVKCallCreate = true
                } label: {
                    Label("Get VK call URL", systemImage: "phone.badge.plus")
                }
                if !vkCallStatus.isEmpty {
                    Text(vkCallStatus)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                Text("Creates a new VK call FROM YOUR VK ACCOUNT and puts its link at the top of the field above. This is not anonymous: the call belongs to the account you confirm on the next screen, so a burner is recommended. Uses the saved VK login if there is one.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            // One NavigationLink per server (stable identity) — avoids the
            // iOS-15 NavigationView "first tap after a state change is dropped"
            // flakiness that a single link tied to the changing activeServerId
            // had. The leading circle (a .borderless Button, so its tap is
            // isolated from the row's navigation) sets the active server; the
            // name navigates into the editor.
            Section {
                ForEach(store.servers) { server in
                    HStack {
                        Button {
                            store.activate(server.id)
                        } label: {
                            Image(systemName: server.id == store.activeServerId
                                  ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(server.id == store.activeServerId ? .accentColor : .secondary)
                                .imageScale(.large)
                        }
                        .buttonStyle(.borderless)
                        NavigationLink {
                            ServerEditView(serverId: server.id)
                        } label: {
                            Text(server.serverName)
                        }
                    }
                }
            } header: {
                Text("Servers")
            } footer: {
                Text("Tap the circle to make a server active; tap the name to edit it. The active server's settings are used when you connect.")
            }

            // VK Account Auth (non-anonymous cookie path). Default OFF. When ON,
            // GetVKCreds uses ONLY the logged-in cookie (no anonymous fallback).
            Section {
                Toggle("Use VK account (cookie) auth", isOn: $vkAuthEnabled)

                if vkAuthEnabled {
                    HStack {
                        Text("Session")
                        Spacer()
                        Text(vkCookieStatusText)
                            .foregroundColor(vkCookieStatusColor)
                    }
                    .font(.subheadline)

                    Button {
                        showVKAuthLogin = true
                    } label: {
                        Label(vkCookieInfo == nil ? "Log in to VK…" : "Re-login to VK…",
                              systemImage: "person.crop.circle.badge.checkmark")
                    }

                    if vkCookieInfo != nil {
                        Button(role: .destructive) { showDeleteCookiesConfirm = true } label: {
                            Label("Delete saved cookies", systemImage: "trash")
                        }
                    }
                }
            } header: {
                Text("VK Account Auth")
            } footer: {
                Text("Non-anonymous fallback for when VK disables anonymous call join. Log in to a VK account (a burner is recommended) in an embedded browser — 2FA works. Only the session cookies are stored, in the Keychain, never in a backup. When ON the app uses ONLY this path (no anonymous fallback). Turning it OFF keeps the saved cookies for later.")
            }

            Section {
                NavigationLink(destination: AdvancedView()) {
                    Label("Advanced", systemImage: "slider.horizontal.3")
                }
            }

            Section {
                Button(action: handleExport) {
                    Label("Export Full Backup…", systemImage: "square.and.arrow.up")
                }

                Button(action: { showImportPicker = true }) {
                    Label("Import Full Backup…", systemImage: "square.and.arrow.down")
                }

                // 1-Click connection link. Reads a vkturnproxy://… URL
                // (or its bare base64 payload) from the system clipboard.
                // The same parse path also runs from .onOpenURL when the
                // user taps a vkturnproxy:// URL anywhere on iOS — see
                // VKTurnProxyApp.swift. quick_link.py at the repo root
                // is the generator script.
                Button(action: handleConnectionLinkPaste) {
                    Label("Import from Connection Link…", systemImage: "link.badge.plus")
                }

                Button(role: .destructive, action: { showResetConfirm = true }) {
                    Label("Reset TURN Cache", systemImage: "trash")
                }

                Button(role: .destructive, action: { showResetProfileConfirm = true }) {
                    Label("Reset Captured Browser Profile", systemImage: "trash")
                }
            } header: {
                Text("Backup & Restore")
            } footer: {
                // Make the sensitivity explicit. Settings + WireGuard
                // private/preshared keys + cached VK TURN credentials
                // + captured browser profile give whoever holds the file
                // the same VPN access the user has — there's no
                // encryption layer.
                Text("Backup contains all settings, WireGuard keys, TURN credentials, and the captured browser profile. Treat the exported file as a secret.")
            }
        }
        .dismissKeyboardOnDrag()
        .navigationTitle("Settings")
        // Share sheet for the freshly-exported temp file. Bound to a
        // sheet(item:) so the file is in scope while the sheet is open
        // and gets cleaned up implicitly when SwiftUI sets the binding
        // back to nil after dismissal.
        .sheet(item: $exportURL) { wrapped in
            ShareSheet(activityItems: [wrapped.url])
        }
        // Document picker for Import. Four UTTypes accepted:
        //   .json — explicit application/json files
        //   .text — JSON conforms to text/plain; covers cases where iOS
        //           Files lost the .json UTI (e.g. transferred via AirDrop
        //           or Mail and arrived as text/plain)
        //   .data — generic binary fallback
        //   .item — root UTI of EVERYTHING. Accepts even files that iOS
        //           classified with a dynamic UTI (dyn.ah62d4rv4...) —
        //           that happens when a file was transferred via apps
        //           that strip UTI metadata or when iOS-version-specific
        //           detection bugs misclassify a perfectly valid JSON.
        //
        // Filter history:
        //   build 67: [.json] → [.json, .text, .data] after issue #8
        //             reporter saw greyed-out file (2026-05-09)
        //   build 80: + .item after the same reporter confirmed the
        //             three-type widening still didn't unblock his
        //             backup (2026-05-12). Per UTType hierarchy,
        //             everything conforms to .item, so the picker now
        //             accepts any file. BackupManager.importFromFileURL
        //             rejects non-AppConfig content with a clear error,
        //             so the cost is one wasted error alert if the user
        //             picks a wrong file.
        .sheet(isPresented: $showImportPicker) {
            DocumentPicker(contentTypes: [.json, .text, .data, .item]) { url in
                handleImportPicked(url: url)
            }
        }
        // Import confirm — shown after the picker hands us a valid file
        // we successfully parsed. pendingImportConfig is the parsed
        // AppConfig waiting to be applied; the alert's primary button
        // does the apply.
        .alert("Import Backup?", isPresented: $showImportConfirm, presenting: pendingImportConfig) { config in
            Button("Import", role: .destructive) {
                applyPendingImport(config)
            }
            Button("Cancel", role: .cancel) {
                pendingImportConfig = nil
            }
        } message: { config in
            let date = Date(timeIntervalSince1970: TimeInterval(config.exportedAt))
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .short
            let credCount = config.turnPool?.creds.count ?? 0
            let profileMark = (config.vkProfile != nil) ? " + browser profile" : ""
            // Pre-179 backups carry no `servers` array — they restore as one server.
            let serverCount = config.settings.servers?.count ?? 1
            return Text("Backup from \(formatter.string(from: date)) with \(serverCount) server(s) and \(credCount) cached TURN cred(s)\(profileMark). This will overwrite all current settings.")
        }
        // Connection link confirm — same shape as the full-backup import
        // alert but applies only the deployment definition (WG keys,
        // vkLink, peerAddress, WRAP key, etc.) without touching the TURN
        // cache or captured browser profile.
        .alert("Import Connection Link?", isPresented: $showConnectionLinkConfirm, presenting: pendingConnectionLink) { link in
            Button("Import", role: .destructive) {
                // ONE apply path, shared with the tapped-link importer. This was
                // a private copy that duplicated the call, the title AND the
                // body — exactly the drift the extraction exists to prevent.
                let msg = ConnectionLinkPrompt.apply(link)
                pendingConnectionLink = nil
                alertTitle = ConnectionLinkPrompt.importedTitle
                alertMessage = msg
            }
            Button("Cancel", role: .cancel) {
                pendingConnectionLink = nil
            }
        } message: { link in
            // Shared with the tapped-link path so the two cannot drift apart.
            Text(ConnectionLinkPrompt.message(for: link))
        }
        // Reset confirm — destructive button on the alert removes the
        // creds-pool.json. UserDefaults are untouched.
        .alert("Reset TURN Cache?", isPresented: $showResetConfirm) {
            Button("Reset", role: .destructive) {
                handleReset()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Deletes the cached TURN credentials. The pool will be rebuilt on next connect via the regular VK API + captcha flow.")
        }
        // Reset confirm for vk_profile.json (captured browser fingerprint).
        // The auto-PoW solver falls back to its generated browser_fp until
        // the next manual captcha solve in CaptchaWKWebView re-captures
        // fresh values.
        .alert("Reset Captured Browser Profile?", isPresented: $showResetProfileConfirm) {
            Button("Reset", role: .destructive) {
                handleResetProfile()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Deletes the captured browser fingerprint used by the auto-PoW captcha solver. Until the next manual captcha solve, the solver will use generated values which VK detects as bot far more often.")
        }
        // VK account login — embedded WKWebView. On success, harvest remixsid+p
        // into the Keychain (VKCookieStore); the status row flips to Active.
        .sheet(isPresented: $showVKAuthLogin) {
            VKAuthWebView { result in
                showVKAuthLogin = false
                if case let .harvested(cookieHeader, expiry) = result {
                    VKCookieStore.save(cookieHeader: cookieHeader, expiry: expiry)
                    refreshVKCookieInfo()
                }
            }
        }
        // Call creation — the OAuth half. M2 stops at the token; creating the
        // call and writing the link into the field above land in M3/M4.
        .sheet(isPresented: $showVKCallCreate) {
            VKOAuthWebView { result in
                showVKCallCreate = false
                switch result {
                case let .token(t):
                    vkCallStatus = "Creating the call…"
                    Task { await createVKCall(token: t) }
                case .needsLogin:
                    vkCallStatus = "VK did not recognise the saved login. Log in with “Use VK account (cookie) auth” below, then try again."
                case let .failed(msg):
                    vkCallStatus = msg
                case .cancelled:
                    vkCallStatus = ""
                }
            }
        }
        // Delete-cookies confirm — mirrors the Reset TURN Cache pattern.
        .alert("Delete saved cookies?", isPresented: $showDeleteCookiesConfirm) {
            Button("Delete", role: .destructive) { handleDeleteCookies() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Removes the stored VK session cookies. You'll need to log in again to use VK account auth.")
        }
        // Keep the session-status row fresh; auto-present login on first enable.
        .onAppear { refreshVKCookieInfo() }
        .onChange(of: vkAuthEnabled) { enabled in
            // Non-destructive: do NOT clamp the stored Connections value — the cap
            // is applied to the EFFECTIVE conn count at connect (see ContentView).
            if enabled && !VKCookieStore.isValid() {
                showVKAuthLogin = true
            }
        }
        // Result alert — shared across export/import/reset success and
        // error paths since the message is what differs, not the
        // presentation. Dismiss is just OK.
        .alert(alertTitle, isPresented: Binding(
            get: { alertMessage != nil },
            set: { if !$0 { alertMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            if let msg = alertMessage {
                Text(msg)
            }
        }
        // 🚫 The inbox is not consumed here — the alert above is the PASTE
        // path only. → ConnectionLinkImport.swift.
    }

    // MARK: - Backup actions

    private func handleExport() {
        do {
            let url = try BackupManager.exportToTempFile()
            exportURL = IdentifiableURL(url: url)
        } catch {
            alertTitle = "Export Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func handleImportPicked(url: URL) {
        do {
            let config = try BackupManager.importFromFileURL(url)
            pendingImportConfig = config
            showImportConfirm = true
        } catch {
            alertTitle = "Import Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func applyPendingImport(_ config: AppConfig) {
        do {
            try BackupManager.applyConfig(config)
            pendingImportConfig = nil
            alertTitle = "Import Complete"
            let credCount = config.turnPool?.creds.count ?? 0
            alertMessage = "Settings restored. TURN cache: \(credCount) slot(s)."
        } catch {
            alertTitle = "Import Failed"
            alertMessage = error.localizedDescription
        }
    }

    // MARK: - Connection Link actions

    /// Reads a vkturnproxy:// link (or its bare base64 payload) from
    /// the system clipboard, parses it, and routes the result into the
    /// confirm alert. Empty or wrong-shape clipboard surfaces as a
    /// single error alert; success populates pendingConnectionLink
    /// and shows the confirm alert.
    private func handleConnectionLinkPaste() {
        let raw = UIPasteboard.general.string ?? ""
        if raw.isEmpty {
            alertTitle = "Clipboard Empty"
            alertMessage = "Copy a vkturnproxy://, wdtt:// or freeturn:// link to the clipboard first, then tap this again."
            return
        }
        do {
            let link = try BackupManager.parseConnectionLinkString(raw)
            pendingConnectionLink = link
            showConnectionLinkConfirm = true
        } catch {
            alertTitle = ConnectionLinkPrompt.invalidTitle
            alertMessage = error.localizedDescription
        }
    }

    // MARK: - Reset actions

    private func handleReset() {
        do {
            try BackupManager.resetTurnCache()
            alertTitle = "TURN Cache Cleared"
            alertMessage = "creds-pool.json deleted. The pool will be rebuilt on next connect."
        } catch {
            alertTitle = "Reset Failed"
            alertMessage = error.localizedDescription
        }
    }

    private func handleResetProfile() {
        do {
            try BackupManager.resetCapturedProfile()
            alertTitle = "Captured Browser Profile Cleared"
            alertMessage = "vk_profile.json deleted. The auto-PoW solver will use generated values until the next manual captcha solve re-captures fresh ones."
        } catch {
            alertTitle = "Reset Failed"
            alertMessage = error.localizedDescription
        }
    }

    // MARK: - VK account (cookie) auth

    private var vkCookieStatusText: String {
        guard let info = vkCookieInfo else { return "Not logged in" }
        if info.expiry <= Date() { return "Expired — re-login" }
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return "Active · expires \(f.string(from: info.expiry))"
    }

    private var vkCookieStatusColor: Color {
        guard let info = vkCookieInfo else { return .orange }
        return info.expiry <= Date() ? .orange : .green
    }

    private func refreshVKCookieInfo() {
        vkCookieInfo = VKCookieStore.load()
    }

    private func handleDeleteCookies() {
        VKCookieStore.delete()
        refreshVKCookieInfo()
        alertTitle = "Cookies Deleted"
        alertMessage = "Stored VK session cookies removed."
    }
}

/// Wraps a URL so sheet(item:) can use it without us conforming URL itself
/// to Identifiable — see exportURL's comment for why we avoid the
/// retroactive conformance.
struct IdentifiableURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

// MARK: - Document Picker (Import file)

/// UIDocumentPickerViewController wrapper for picking a JSON backup file.
/// The picker hands back a security-scoped URL that the caller must
/// access via startAccessingSecurityScopedResource — BackupManager.importFromFileURL
/// handles that internally so this wrapper just forwards the URL.
///
/// contentTypes is `[UTType]` rather than `[String]` so callers pass the
/// type-safe `UTType.json` (or similar) directly — earlier code took a
/// `[String]` of UTI identifiers and converted via the failable
/// `UTType(_:)` init. When that init returned nil for any reason, the
/// resulting empty filter let the picker show every file as selectable
/// AND failed to highlight the genuine JSON ones — observed empirically
/// during the schema migration test where vkturnproxy-backup-*.json sat
/// un-highlighted in Files.app's Downloads view and had to be located by
/// search instead of by browsing.
struct DocumentPicker: UIViewControllerRepresentable {
    let contentTypes: [UTType]
    let onPicked: (URL) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPicked: onPicked)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: contentTypes
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPicked: (URL) -> Void
        init(onPicked: @escaping (URL) -> Void) {
            self.onPicked = onPicked
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            onPicked(url)
        }
    }
}

// MARK: - Stats View

struct StatsView: View {
    /// Observes ONLY the poll-driven counters, never the TunnelManager itself.
    /// This view sits under ContentView's NavigationView, so re-rendering it is
    /// harmless — but observing the manager from anywhere in ContentView's own
    /// body is not. See TunnelLiveStats for why (GitHub #65).
    @ObservedObject var live: TunnelLiveStats

    /// Every counter below comes from the extension over NE IPC. Until a reply
    /// has actually arrived, `live.stats` is the all-zero initial value, and
    /// rendering it claims "0 connections, 0 bytes" about a tunnel that may
    /// well be carrying traffic — which is what a third-party re-signed build
    /// shows forever, since the OS refuses that channel outright.
    ///
    /// Gated on "have we ever received", not on "has the watchdog tripped", so
    /// the blanks appear on the first frame rather than seconds later. On a
    /// healthy build the immediate first poll answers in milliseconds, so this
    /// is imperceptible there.
    private var statsAreReal: Bool {
        live.statsReceivedOnce && !live.statsChannelDown
    }
    private func dashed(_ value: @autoclosure () -> String) -> String {
        statsAreReal ? value() : "—"
    }

    var body: some View {
        VStack(spacing: 6) {
            // Deliberately NOT an `if`. Inserting and removing a view here
            // changes the shape of the tree inside the NavigationView, and in
            // this app that is the trap that popped whatever screen was pushed
            // and cost four rebuild rounds in build 177. The banner is always
            // in the hierarchy and collapses to nothing instead, so a flapping
            // flag can never restructure anything while the user is deep in
            // Settings. Reported 2026-07-28: entering a server from Settings
            // bounced back to Settings at random intervals, but only while
            // connected — i.e. only while this flag could move at all.
            Text("Statistics unavailable — the app can't reach the tunnel extension. The VPN itself is unaffected; see Logs for the reason.")
                .font(.caption)
                .foregroundColor(.orange)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
                .opacity(live.statsChannelDown ? 1 : 0)
                .frame(height: live.statsChannelDown ? nil : 0)
                .clipped()
                .accessibilityHidden(!live.statsChannelDown)
            HStack {
                StatBox(title: "↑ TX", value: dashed(formatBytes(live.stats.txBytes)), sub: statsAreReal ? formatRate(live.txRate) : nil)
                StatBox(title: "↓ RX", value: dashed(formatBytes(live.stats.rxBytes)), sub: statsAreReal ? formatRate(live.rxRate) : nil)
            }

            HStack {
                StatBox(title: "TURN RTT", value: dashed(String(format: "%.0f ms", live.stats.turnRTTms)), sub: nil)
                StatBox(title: "DTLS HS", value: dashed(String(format: "%.0f ms", live.stats.dtlsHandshakeMs)), sub: nil)
                // Internet RTT is measured by the main app itself, so it stays
                // real even when the extension is unreachable — that contrast
                // is a useful signal, not an inconsistency.
                StatBox(title: "Internet", value: live.internetRTTms > 0 ? String(format: "%.0f ms", live.internetRTTms) : "—", sub: nil)
            }

            HStack {
                StatBox(title: "Conns", value: dashed("\(live.stats.activeConns)/\(live.stats.totalConns)"), sub: nil)
                StatBox(title: "Reconnects", value: dashed("\(live.stats.reconnects)"), sub: nil)
            }

            HStack {
                // Uptime updates live via TimelineView ticking once a second.
                // Falls back to "—" if the tunnel hasn't reached .connected
                // yet (briefly visible during the .connecting → .connected
                // transition since StatsView is gated on .connected).
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    StatBox(
                        title: "Uptime",
                        value: formatUptime(live.connectedAt.map { context.date.timeIntervalSince($0) }),
                        sub: nil
                    )
                }
                StatBox(
                    // Three numbers: available / with-usable-creds / total.
                    //   available: slots usable for new conn allocations
                    //              RIGHT NOW — fresh creds AND not in a
                    //              VK-saturation cooldown (e.g. from
                    //              smart-pause after a path change).
                    //   with-usable-creds: slots whose cred hasn't crossed
                    //                      the expiry buffer. Includes
                    //                      saturated and load-pending
                    //                      (those recover on their own);
                    //                      EXCLUDES slots whose creds
                    //                      expired and the grower is
                    //                      failing to refresh.
                    //   total: configured pool capacity.
                    // available ≤ with-usable-creds ≤ total. After a
                    // back-to-back path transition all slots can become
                    // saturated, showing e.g. "0/12/12" until the first
                    // smart-pause cooldown expires (~10 min). When the
                    // middle number drops below total, some slots have
                    // dead creds and the grower can't refresh them
                    // (typically PoW rate-limited).
                    title: "Pool",
                    value: dashed("\(live.stats.credPoolFilled)/\(live.stats.credPoolWithCreds)/\(live.stats.credPoolSize)/\(live.stats.credPoolDistinctRelays)"),
                    sub: nil
                )
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

    private func formatUptime(_ seconds: TimeInterval?) -> String {
        guard let s = seconds, s >= 0 else { return "—" }
        let total = Int(s)
        let h = total / 3600
        let m = (total % 3600) / 60
        let sec = total % 60
        if h > 0 {
            return String(format: "%d:%02d:%02d", h, m, sec)
        }
        return String(format: "%d:%02d", m, sec)
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

    // First-content-visible overlay state. Replaces the blank white WebView
    // that the user stares at while the captcha page is parsing <head> and
    // hasn't put any bytes in <body> yet — observed up to 86s on cold cache
    // in 2026-05-07 vpn-export-megafon.log (issue #5). Signal: JS heartbeat
    // posts body=N; transitioning from N==0 to N>0 means DOM has rendered
    // something. We also drop the overlay when didFinish fires, as a
    // fallback in case JS hooks didn't install.
    @State private var pageHasContent: Bool = false
    @State private var loadingStartedAt: Date = .init()
    @State private var elapsedSec: Int = 0
    private let tickTimer = Timer.publish(every: 1.0, on: .main, in: .common).autoconnect()

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
                    onLog: onLog,
                    onPageLoadStarted: {
                        pageHasContent = false
                        loadingStartedAt = Date()
                        elapsedSec = 0
                    },
                    onPageContentVisible: {
                        pageHasContent = true
                    }
                )

                // Loading overlay: shown while the WebView's body is still
                // empty (cold-cache subresource fetch hangs the parser).
                // Hides as soon as DOM renders any content. Without this
                // the user just sees a blank white square for up to 90s
                // and assumes the app is broken.
                if !pageHasContent {
                    VStack(spacing: 16) {
                        ProgressView().scaleEffect(1.3)
                        Text("Loading captcha…")
                            .font(.headline)
                        Text("\(elapsedSec)s")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                    .padding(32)
                    .background(Color(.systemBackground).opacity(0.97))
                    .cornerRadius(16)
                    .shadow(radius: 12)
                }

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
            .onReceive(tickTimer) { _ in
                if !pageHasContent {
                    elapsedSec = Int(Date().timeIntervalSince(loadingStartedAt))
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
    // Called when a fresh main-frame navigation starts (didStartProvisional).
    // Parent uses this to reset its loading-overlay state — show the
    // "Loading captcha…" spinner and start counting elapsed time.
    let onPageLoadStarted: () -> Void
    // Called once per navigation, the first moment we observe non-empty body
    // content (heartbeat reports body>0) or didFinish fires. Parent hides
    // the loading overlay on this signal.
    let onPageContentVisible: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            onTokenCaptured: onTokenCaptured,
            onLimitDetected: onLimitDetected,
            onCaptchaReady: onCaptchaReady,
            onLog: onLog,
            onPageLoadStarted: onPageLoadStarted,
            onPageContentVisible: onPageContentVisible
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
        // The block below replaces window.fetch and XMLHttpRequest.prototype
        // .open/.send inside VK's captcha page, which is how we read
        // success_token out of the captchaNotRobot.check response. A patched
        // native is one of the oldest bot tells there is — `window.fetch
        // .toString()` stops saying "[native code]" — so build 214 ran the page
        // passively, with the hooks off, to see whether WE were the reason a
        // real human tap got BOT.
        //
        // DISPROVED (30.07): passive made no difference, still BOT. And on
        // 31.07 the same hooks were installed in a real Chrome, on a passing
        // captcha, and it kept passing. Patching fetch is not what VK objects
        // to. Hooks stay on — without them a solve cannot yield success_token
        // and the WebView fallback cannot complete a connect at all.
        let installNetworkHooks = true

        let js = """
        (function() {
            var h = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.captchaToken;
            if (!h) return;

            var INSTALL_NET_HOOKS = \(installNetworkHooks);

            // Helper: extract whichever of device + browser_fp are non-empty
            // from a form-encoded body and post 'profile-capture:' to Swift.
            // Empirically (vpn.wifi.[1-3].log 2026-05-08): VK's
            // captchaNotRobot.componentDone body has device populated but
            // browser_fp EMPTY. browser_fp gets a real value only in the
            // captchaNotRobot.check body — so we have to intercept BOTH
            // requests and accumulate fields across them. Swift side
            // merges via VKProfileCache.update (preserves existing field
            // on empty input).
            function captureProfileFromBody(bodyStr, source) {
                try {
                    if (!bodyStr) {
                        h.postMessage('profile-capture-err:empty body (' + source + ')');
                        return;
                    }
                    var fields = [];
                    var deviceMatch = /(?:^|&)device=([^&]*)/.exec(bodyStr);
                    if (deviceMatch && deviceMatch[1].length > 0) {
                        fields.push('device=' + deviceMatch[1]);
                    }
                    var fpMatch = /(?:^|&)browser_fp=([^&]*)/.exec(bodyStr);
                    if (fpMatch && fpMatch[1].length > 0) {
                        fields.push('browser_fp=' + fpMatch[1]);
                    }
                    if (fields.length === 0) {
                        h.postMessage('profile-capture-err:both fields empty/absent in body len=' + bodyStr.length + ' (' + source + ')');
                        return;
                    }
                    fields.push('ua=' + encodeURIComponent(navigator.userAgent || ''));
                    h.postMessage('profile-capture:' + fields.join('&'));
                } catch (e) {
                    h.postMessage('profile-capture-err:' + e.message + ' (' + source + ')');
                }
            }

            // Hook fetch to intercept:
            //   - captchaNotRobot.check RESPONSE (for success_token)
            //   - captchaNotRobot.check REQUEST body (for browser_fp)
            //   - captchaNotRobot.componentDone REQUEST body (for device)
            // Profile fields accumulate on the Swift side via
            // VKProfileCache.update — componentDone gives device, check
            // gives browser_fp; merging produces a complete saved profile.
            if (INSTALL_NET_HOOKS) {
            var origFetch = window.fetch;
            window.fetch = function() {
                var url = arguments[0];
                var init = arguments[1];
                if (typeof url === 'object' && url.url) url = url.url;
                var urlStr = String(url);
                var p = origFetch.apply(this, arguments);
                if (urlStr.indexOf('captchaNotRobot.check') !== -1) {
                    captureProfileFromBody(init && init.body ? String(init.body) : '', 'fetch-check');
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
                if (urlStr.indexOf('captchaNotRobot.componentDone') !== -1) {
                    captureProfileFromBody(init && init.body ? String(init.body) : '', 'fetch-componentDone');
                }
                return p;
            };

            // Hook XMLHttpRequest as fallback (same triple capture as fetch).
            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._url = url;
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                var xhr = this;
                var urlStr = this._url ? String(this._url) : '';
                if (urlStr.indexOf('captchaNotRobot.componentDone') !== -1) {
                    captureProfileFromBody(arguments[0] ? String(arguments[0]) : '', 'xhr-componentDone');
                }
                if (urlStr.indexOf('captchaNotRobot.check') !== -1) {
                    captureProfileFromBody(arguments[0] ? String(arguments[0]) : '', 'xhr-check');
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
            } // if (INSTALL_NET_HOOKS)

            // The UA rides along so the log shows what the page ACTUALLY sees,
            // not what we believe we configured — the version token is the
            // thing under test here.
            h.postMessage((INSTALL_NET_HOOKS
                ? 'init:hooks installed'
                : 'init:PASSIVE — natives untouched') + ' ua=' + navigator.userAgent);

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

            // Diagnostic heartbeat: every 1s while page hasn't reached
            // 'complete', post readyState + content sizes. Diagnoses the
            // "white captcha" symptom from issue #5 — when WKWebView
            // navigates but no didFinish/didFail fires, we need to know
            // whether DOM is stuck in 'loading', sitting empty in
            // 'interactive', or what. Stops itself on 'complete' or after
            // 180s (whichever first) so it can't spam the log indefinitely.
            // The 180s cap covers the worst observed cold-cache load
            // (86s on issue #5 vpn-export-megafon.log, build 49) with
            // headroom — earlier 60s cap cut visibility short.
            (function() {
                var startTime = Date.now();
                var heartbeatId = setInterval(function() {
                    var elapsed = Date.now() - startTime;
                    var ready = document.readyState || 'null';
                    var bodyLen = (document.body && document.body.innerHTML.length) || 0;
                    var titleLen = (document.title || '').length;
                    var url = (location && location.href || '').substring(0, 80);
                    h.postMessage('heartbeat:elapsed=' + elapsed + 'ms readyState=' + ready
                        + ' body=' + bodyLen + ' title=' + titleLen + ' url=' + url);
                    if (ready === 'complete' || elapsed > 180000) {
                        clearInterval(heartbeatId);
                    }
                }, 1000);
            })();

            // Diagnostic: log per-resource timing as it completes. Reveals
            // exactly which subresource(s) hang during cold-cache slow
            // first-load (issue #5 — body=0 for 60-86s while parser is
            // blocked on a synchronous <script src>). Each fetched
            // resource gets one log line with DNS / TCP / TLS / TTFB /
            // body-bytes phases broken out — so we can tell whether the
            // bottleneck is name resolution, connection setup, or actual
            // bytes flowing slow. Stays on for the lifetime of the page;
            // overhead is one postMessage per resource (~10-30 per
            // captcha load, manageable). Query strings stripped from
            // names for log brevity, names truncated at 120 chars.
            if (typeof PerformanceObserver !== 'undefined') {
                try {
                    var po = new PerformanceObserver(function(list) {
                        list.getEntries().forEach(function(entry) {
                            if (entry.entryType !== 'resource') return;
                            var name = entry.name || '';
                            var qIdx = name.indexOf('?');
                            if (qIdx > 0) name = name.substring(0, qIdx);
                            if (name.length > 120) name = name.substring(0, 120) + '...';
                            var dns = Math.round(entry.domainLookupEnd - entry.domainLookupStart);
                            var tcp = Math.round(entry.connectEnd - entry.connectStart);
                            var tls = entry.secureConnectionStart > 0
                                ? Math.round(entry.connectEnd - entry.secureConnectionStart)
                                : 0;
                            var ttfb = Math.round(entry.responseStart - entry.requestStart);
                            var bodyMs = Math.round(entry.responseEnd - entry.responseStart);
                            var total = Math.round(entry.duration);
                            var size = entry.transferSize || 0;
                            h.postMessage('perf:' + (entry.initiatorType || '?')
                                + ' total=' + total + 'ms'
                                + ' dns=' + dns + 'ms'
                                + ' tcp=' + tcp + 'ms'
                                + ' tls=' + tls + 'ms'
                                + ' ttfb=' + ttfb + 'ms'
                                + ' bodyMs=' + bodyMs + 'ms'
                                + ' size=' + size + 'B'
                                + ' name=' + name);
                        });
                    });
                    po.observe({entryTypes: ['resource']});
                } catch (e) {
                    h.postMessage('perf-err:' + e.message);
                }
            } else {
                h.postMessage('perf-err:PerformanceObserver unavailable');
            }

            // Catch JS errors and unhandled promise rejections so we can
            // see if the page is failing on its own scripts (e.g. a
            // sub-resource referenced by VK's captcha JS that the
            // network blocks).
            window.addEventListener('error', function(e) {
                var src = (e.filename || '?');
                if (src.length > 80) src = src.substring(0, 80) + '…';
                h.postMessage('js-error:' + (e.message || 'unknown')
                    + ' at ' + src + ':' + (e.lineno || '?'));
            });
            window.addEventListener('unhandledrejection', function(e) {
                var reason = e.reason ? String(e.reason).substring(0, 200) : 'unknown';
                h.postMessage('js-rejection:' + reason);
            });
        })();
        """
        let userScript = WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        contentController.addUserScript(userScript)
        config.userContentController = contentController

        // Do NOT pin a whole User-Agent here. A hardcoded one froze us at
        // "CPU iPhone OS 17_0 ... Version/17.0" while the WebKit actually
        // running this page is whatever the device's iOS ships — and VK's
        // fingerprint script executes INSIDE that engine, so it can compare the
        // version we claim against the capabilities it can see. Claiming to be
        // a Safari we are not is the one thing our two failing clients have in
        // common (the Go solver contradicts it at the TLS layer, this WebView
        // contradicted it at the version).
        //
        // applicationNameForUserAgent only APPENDS to the UA WebKit builds for
        // itself, so the platform and engine tokens stay truthful and only the
        // Safari marketing version — which tracks the iOS version — is added.
        let os = ProcessInfo.processInfo.operatingSystemVersion
        config.applicationNameForUserAgent =
            "Version/\(os.majorVersion).\(os.minorVersion) Mobile/15E148 Safari/604.1"

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView

        // iOS 16.4+ no longer auto-enables Safari Web Inspector for WKWebViews
        // even in Debug builds; explicit opt-in required. Wrapped in #if DEBUG
        // so Release/TestFlight IPAs don't expose the WebView to USB-attached
        // dev tools. Enables: Mac Safari → Develop → iPhone → captcha WebView,
        // then Network tab shows the real HTTP/2 headers Safari mobile sends
        // to id.vk.ru. Needed for matching our Go-side PoW client to the
        // captured Safari fingerprint.
        #if DEBUG
        if #available(iOS 16.4, *) {
            webView.isInspectable = true
        }
        #endif

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
        let onPageLoadStarted: () -> Void
        let onPageContentVisible: () -> Void
        private var solved = false
        // One-shot guard for onPageContentVisible — first heartbeat with
        // body>0 (or didFinish, whichever first) fires it; subsequent
        // heartbeats stay quiet. Reset on every fresh navigation.
        private var contentVisibleFired = false
        weak var webView: WKWebView?
        // Tracks which URL we last handed to `webView.load(...)`. Used by
        // updateUIView to detect real URL changes vs. SwiftUI re-renders with
        // the same state — avoids redundant reloads.
        var lastLoadedURL: String?

        init(
            onTokenCaptured: @escaping (String) -> Void,
            onLimitDetected: @escaping () -> Void,
            onCaptchaReady: @escaping () -> Void,
            onLog: @escaping (String) -> Void,
            onPageLoadStarted: @escaping () -> Void,
            onPageContentVisible: @escaping () -> Void
        ) {
            self.onTokenCaptured = onTokenCaptured
            self.onLimitDetected = onLimitDetected
            self.onCaptchaReady = onCaptchaReady
            self.onLog = onLog
            self.onPageLoadStarted = onPageLoadStarted
            self.onPageContentVisible = onPageContentVisible
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
        // silently swallow every token after the first. Also resets the
        // contentVisibleFired guard so the loading overlay shows again
        // for the new page.
        func resetForNewCaptcha() {
            solved = false
            contentVisibleFired = false
        }

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard let body = message.body as? String else { return }
            log("JS: \(String(body.prefix(400)))")

            // First non-empty body in a heartbeat fires onPageContentVisible
            // exactly once per navigation, dropping the loading overlay.
            // Heartbeat format: "heartbeat:elapsed=Xms readyState=Y body=N title=M url=..."
            if !contentVisibleFired && body.hasPrefix("heartbeat:") {
                if let r = body.range(of: "body=") {
                    let after = body[r.upperBound...]
                    let digits = after.prefix(while: { $0.isNumber })
                    if let n = Int(digits), n > 0 {
                        contentVisibleFired = true
                        DispatchQueue.main.async { self.onPageContentVisible() }
                    }
                }
            }

            if body.hasPrefix("token:") {
                let token = String(body.dropFirst(6))
                log("SUCCESS_TOKEN (\(token.count) chars)")
                captureToken(token)
                return
            }

            // Browser-profile capture from intercepted VK API request bodies.
            // Format: "profile-capture:[device=URLENC&][browser_fp=URLENC&]ua=URLENC".
            // device and browser_fp are OPTIONAL (each captured from a
            // different request type — componentDone has device, check has
            // browser_fp). Empty/absent fields are not overwritten on disk;
            // VKProfileCache.update merges with whatever's already saved.
            //
            // Important: device and browser_fp are stored in their RAW
            // URL-encoded form (as VK's JS originally serialized them
            // into the request body). Go-side splices them back into a
            // form-encoded body verbatim — re-encoding would double-escape.
            // Only `ua` (which we add ourselves via encodeURIComponent in
            // JS) gets percent-decoded for human-readable storage.
            if body.hasPrefix("profile-capture:") {
                let payload = String(body.dropFirst("profile-capture:".count))
                var raw: [String: String] = [:]
                for pair in payload.split(separator: "&") {
                    let kv = pair.split(separator: "=", maxSplits: 1)
                    if kv.count == 2 {
                        raw[String(kv[0])] = String(kv[1])
                    }
                }
                let deviceRaw = raw["device"] ?? ""
                let browserFpRaw = raw["browser_fp"] ?? ""
                let uaDecoded = (raw["ua"] ?? "").removingPercentEncoding ?? ""
                log("profile-capture received: device=\(deviceRaw.count)c browser_fp=\(browserFpRaw.count)c ua=\(uaDecoded.count)c")
                VKProfileCache.update(device: deviceRaw, browserFp: browserFpRaw, userAgent: uaDecoded)
                return
            }
            if body.hasPrefix("profile-capture-err:") {
                log("profile capture error: \(String(body.dropFirst("profile-capture-err:".count)))")
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

        // Diagnostic: confirms the request was actually sent to the server
        // (between Nav (decision) and didStartProvisional (sent on the wire)
        // there's a window where iOS could drop the request without firing
        // any other event). Added 2026-05-07 for issue #5 "white captcha"
        // diagnosis — vpn.from.github.1.log on build 48 had Nav fire then
        // 7.4s of silence with no Loaded / didFail. Need to know which
        // network-layer stage hangs.
        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            log("StartProvisional: request sent on wire")
            // Fresh main-frame navigation — reset the loading overlay state
            // so the parent view shows the spinner again for this attempt.
            // Iframe / subresource navigations don't fire this delegate
            // method, so this fires exactly once per top-level captcha load.
            contentVisibleFired = false
            DispatchQueue.main.async { self.onPageLoadStarted() }
        }

        // Diagnostic: HTTP redirect mid-navigation. Logged so we can see if
        // VK is sending us through some redirect chain that hangs.
        func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
            log("Redirect: \(String((webView.url?.absoluteString ?? "nil").prefix(200)))")
        }

        // Diagnostic: response headers received, body about to start. If
        // didCommit fires but didFinish doesn't, the body load is hanging
        // (server stops sending / TLS issue / sub-resource block). If
        // didCommit doesn't fire at all, the request is stuck before
        // headers arrived (TCP / TLS handshake / server unresponsive).
        func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
            log("Commit: response headers received")
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            let nsErr = error as NSError
            log("FAIL: \(error.localizedDescription) (domain=\(nsErr.domain) code=\(nsErr.code))")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            let nsErr = error as NSError
            log("FAIL provisional: \(error.localizedDescription) (domain=\(nsErr.domain) code=\(nsErr.code))")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            log("Loaded: \(String((webView.url?.absoluteString ?? "nil").prefix(150)))")
            // Fallback: if heartbeat never reported body>0 (e.g. JS hooks
            // failed to install for some reason), at least drop the
            // loading overlay when the page fully loads.
            if !contentVisibleFired {
                contentVisibleFired = true
                DispatchQueue.main.async { self.onPageContentVisible() }
            }
        }
    }
}

// MARK: - Logs View

struct LogsView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var logText = ""
    @State private var autoScroll = true
    @State private var showShareSheet = false
    @State private var usingOSLogFallback = false
    // Cached fallback content + last-fetch timestamp + in-flight guard.
    // Without these the fallback path (OSLogReader.readOwnLogs +
    // sendProviderMessage) ran on EVERY 2-second timer tick whenever the
    // file was empty, blocking the main thread on the synchronous
    // OSLogStore query for hundreds of milliseconds-to-seconds depending
    // on ring-buffer size. Symptom: tapping "Clear" emptied the file,
    // then the UI lagged badly because every tick re-ran the heavy
    // fallback query. With caching: query runs at most once per
    // fallbackTTL seconds, off the main thread.
    @State private var fallbackText: String = ""
    @State private var fallbackFetchedAt: Date = .distantPast
    @State private var fallbackInFlight = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()
    private let fallbackTTL: TimeInterval = 4.0

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
                    // Wipe the fallback cache too — otherwise after
                    // clearing the on-disk log the next loadLogs() tick
                    // would still show the stale cached fallback content
                    // until the TTL elapses, which looks like Clear
                    // didn't work.
                    fallbackText = ""
                    fallbackFetchedAt = .distantPast
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
            // Export the COMBINED log (archive .1 + current) as a single
            // temp file so the user gets the full history, not just the
            // tail since the last rotation. If SharedLogger is empty
            // (App Group unavailable), Share the os_log fallback text
            // by writing it to a temp file first so the user can still
            // attach a log file to a bug report.
            if let url = exportShareableLogURL(),
               FileManager.default.fileExists(atPath: url.path) {
                ShareSheet(activityItems: [url])
            }
        }
    }

    private func loadLogs() {
        let snapshot = SharedLogger.shared.readSnapshot()
        if !snapshot.text.isEmpty {
            usingOSLogFallback = false
            // 🚨 STATES THE FACT, NAMES NO CAUSE. The first version said "a
            // writer overwrote part of a line" — my hypothesis at the time, and
            // the wrong one: the byte that actually did this came from a
            // byte-indexed truncation of remote text (2f18b1a), not from the
            // writer race. A banner that asserts a cause sends the next reader
            // to the wrong file, and it is the one line they will believe
            // without checking.
            let banner = snapshot.repairedSequences > 0
                ? "[logdiag] \(snapshot.repairedSequences) invalid byte sequence(s) in this log were "
                  + "replaced with \u{FFFD} so it could be shown. The RAW bytes are in the Share "
                  + "export; the text around each \u{FFFD} is what names the writer.\n\n"
                : ""
            logText = banner + truncated(snapshot.text)
            return
        }
        // Empty result. Distinguish "intentionally empty" (Clear was
        // pressed, or extension just rotated/started) from "broken"
        // (App Group container unreachable, or the file never existed).
        // The first case is normal user state — Clear is used routinely
        // — and showing a fallback banner there surprises the user with
        // os_log content unrelated to the fresh-start they just asked
        // for. Only fall back when the file storage itself is missing.
        let status = SharedLogger.shared.inspectStorage()
        if status.hasContainer && status.currentExists {
            usingOSLogFallback = false
            // Wipe stale fallback cache so a subsequent failure path
            // doesn't render leftover content.
            fallbackText = ""
            fallbackFetchedAt = .distantPast
            // DIAGNOSTIC (build 154): surface the storage facts inline so we
            // can see WHY the file reads empty — truly 0 bytes vs path skew —
            // and compare the container path with the extension's
            // "wgSetLogFilePath: <path>" line in os_log (USB syslog). A
            // mismatch means the main app and the PacketTunnel extension
            // resolved DIFFERENT App Group containers (provisioning skew), so
            // the extension's writes never reach the file the app reads.
            // 🚨 The headline must not claim the log is EMPTY over a file that
            // holds bytes. On 2026-08-20 this screen said "waiting for new
            // activity" over 829 072 bytes for the length of a whole sweep,
            // because the reader threw the file away on one invalid character
            // and the branch could not tell "nothing written" from "nothing
            // read". The bytes were in `status` all along, one line below the
            // sentence that contradicted them.
            let headline = status.currentBytes > 0
                ? "(NOT empty — the file holds \(status.currentBytes) bytes and NONE of them could be read: "
                  + "this is a READ failure)"
                : "(log is empty — waiting for new activity)"
            logText = headline + "\n\n" +
                "[logdiag] container = \(status.containerPath)\n" +
                "[logdiag] vpn.log   exists=\(status.currentExists) bytes=\(status.currentBytes)\n" +
                "[logdiag] vpn.log.1 exists=\(status.archivedExists) bytes=\(status.archivedBytes)"
            return
        }

        // Genuine fallback: no container (entitlement / provisioning
        // issue) or file never existed (fresh install before any
        // SharedLogger.log call landed). Read per-process os_log: main
        // app reads its own ring buffer, extension reads its own via
        // providerMessage. Surface a banner explaining the source.
        //
        // Both the OSLogStore query and the providerMessage round-trip
        // can take hundreds of milliseconds each — running them on every
        // 2-second timer tick on the main thread caused noticeable UI
        // lag. So: cache the result for `fallbackTTL` seconds, refresh
        // in a background task, and only one fetch may be in flight at
        // a time.
        usingOSLogFallback = true

        // Show last-cached content immediately if we have any; otherwise
        // a minimal placeholder so the user knows fetching is in progress.
        if !fallbackText.isEmpty {
            logText = truncated(fallbackText)
        } else if logText.isEmpty {
            logText = "Loading os_log fallback…"
        }

        let cacheStale = Date().timeIntervalSince(fallbackFetchedAt) > fallbackTTL
        guard !fallbackInFlight && cacheStale else { return }
        fallbackInFlight = true

        Task.detached(priority: .userInitiated) {
            // OSLogReader.readOwnLogs is the heavy synchronous call —
            // running it on a detached task moves it off the main thread.
            // Subsequent awaits (providerMessage, MainActor.run) come
            // back to MainActor naturally because tunnel is @MainActor.
            let mainAppLogs = OSLogReader.readOwnLogs(maxAge: 1800)
            let extensionLogs = await tunnel.fetchExtensionOSLogs() ?? ""

            // Pick a precise banner reason from SharedLogger storage state
            // instead of conflating "container unavailable" with "file empty"
            // and "file unreadable" — each has a different cause and remedy.
            // Also include container path so the reader can compare with
            // wgSetLogFilePath in the extension's os_log output (mismatching
            // paths would indicate a provisioning/entitlement skew between
            // main app and extension processes).
            let status = SharedLogger.shared.inspectStorage()
            let reason: String
            if !status.hasContainer {
                // Name the actual cause instead of "entitlement missing or
                // provisioning issue", which told nobody anything. Reading our
                // own code signature turns this into a self-diagnosing report:
                // it states which team signed the build and which App Groups it
                // really has. See AppEntitlements.swift for why this is the
                // common case (GitHub #7, #8, #59).
                reason = "App Group container unavailable to main app.\n"
                       + AppEntitlements.appGroupDiagnosis(required: "group.com.vkturnproxy.app")
            } else if !status.currentExists && !status.archivedExists {
                reason = "Log file doesn't exist yet at \(status.containerPath)/vpn.log (fresh install or container reset)"
            } else if status.currentBytes == 0 && status.archivedBytes <= 0 {
                reason = "Log file is empty (\(status.containerPath)/vpn.log: 0 bytes; recently cleared, or extension hasn't written since clear)"
            } else if status.currentBytes < 0 {
                reason = "Log file unreadable despite existing (\(status.containerPath)/vpn.log; permissions / corruption?)"
            } else {
                reason = "Log file present but readLogs returned empty (current=\(status.currentBytes)B, archived=\(status.archivedBytes)B at \(status.containerPath))"
            }

            // The extension's os_log entries can only reach us over the SAME
            // providerMessage channel the stats use. On a re-signed build the OS
            // refuses it ("process N is not entitled to establish IPC with
            // plugins of type com.vkturnproxy.app"), so this fallback then shows
            // main-app lines ONLY. Say so — otherwise the export looks like the
            // extension is silent, and the reader concludes the tunnel is dead
            // when it is running fine. (Verified 2026-07-25: the extension does
            // emit its own App-Group diagnosis; it is visible in a device-wide
            // idevicesyslog capture and absent from this screen.)
            let extensionNote = extensionLogs.isEmpty
                ? "\nNOTE: no lines from the tunnel extension below — the app "
                + "could not reach it (same channel as the statistics). Everything "
                + "shown is from the app process. The extension may well be "
                + "running; a device-wide log capture would show its lines.\n"
                : ""

            var combined = mainAppLogs + extensionLogs
            if combined.isEmpty {
                combined = "No logs available.\n\nReason: \(reason)\n\n" +
                    "Try reconnecting the tunnel, or — if the issue persists — " +
                    "Reset TURN Cache and reconnect to force a fresh log session."
            } else {
                combined = "⚠️ Showing os_log fallback (recent ~30 min only, " +
                    "may be incomplete and out of order).\n" +
                    "Reason: \(reason)\n" + extensionNote + "\n" +
                    combined
            }

            await MainActor.run {
                fallbackText = combined
                fallbackFetchedAt = Date()
                fallbackInFlight = false
                if usingOSLogFallback {
                    logText = truncated(combined)
                }
            }
        }
    }

    private func truncated(_ text: String) -> String {
        guard text.count > maxDisplayChars else { return text }
        let startIndex = text.index(text.endIndex, offsetBy: -maxDisplayChars)
        return "… (truncated)\n" + String(text[startIndex...])
    }

    /// Decide what URL to hand to the Share sheet. Default path: the
    /// file-backed export (archive + current). Fallback path: write
    /// the current `logText` (which is the os_log fallback view) to
    /// a temp file so the user can still attach a log to a bug report
    /// even when the App Group file is empty.
    private func exportShareableLogURL() -> URL? {
        if let url = SharedLogger.shared.exportSnapshotURL(),
           let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? Int, size > 0 {
            return url
        }
        // SharedLogger empty — write the on-screen fallback text to a
        // temp file so Share has something to attach.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("vpn-export-oslog.log")
        try? logText.write(to: tmp, atomically: true, encoding: .utf8)
        return FileManager.default.fileExists(atPath: tmp.path) ? tmp : nil
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
