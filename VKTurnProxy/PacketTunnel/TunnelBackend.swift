// TunnelBackend.swift
//
// The ONE place the extension talks to a tunnel handle. A handle is a number
// in one of TWO Go registries — the WireGuard one behind the wg* exports and
// the csqtt one behind the csqtt* exports (stage 5, variant B) — and the
// number alone does not say which. This enum carries the kind with the
// number, so every per-handle call in PacketTunnelProvider goes through here
// and a csqtt handle can never reach a wg* function or the other way round.
//
// 🚨 The provider must not call a wg*(handle) / csqtt*(handle) export
// directly; swiftcheck counts them. Process-global calls (wgSetLogFilePath,
// wgSetVKCookieAuth, wgSetUplinkPace, wgGetAuthError, …) take no handle and
// stay where they are.
//
// The native path's execution is byte-for-byte what it was: each `.wireguard`
// case calls the same export with the same arguments the provider used to.

import Foundation

enum TunnelBackend {
    case wireguard(Int32)
    case csqtt(Int32)

    /// Starts a tunnel of the requested kind from the SAME proxy_config JSON
    /// (csqtt reads its own fields out of it; the WireGuard path ignores
    /// them). Returns the backend, or nil with the bridge's negative code.
    static func start(csqtt: Bool, proxyConfigJSON: String) -> (TunnelBackend?, Int32) {
        let handle: Int32 = proxyConfigJSON.withCString { ptr in
            csqtt ? csqttStart(ptr) : wgStartVKBootstrap(UnsafeMutablePointer(mutating: ptr))
        }
        if handle < 0 { return (nil, handle) }
        return (csqtt ? .csqtt(handle) : .wireguard(handle), handle)
    }

    var isCSQTT: Bool {
        if case .csqtt = self { return true }
        return false
    }

    /// The raw handle, for log lines only.
    var handle: Int32 {
        switch self {
        case .wireguard(let h), .csqtt(let h): return h
        }
    }

    /// Bootstrap outcome: 1 ready, 0 timeout, negative failure — both
    /// backends use the same convention.
    func waitReady(timeoutMs: Int32) -> Int32 {
        switch self {
        case .wireguard(let h): return wgWaitBootstrapReady(h, timeoutMs)
        case .csqtt(let h): return csqttWaitReady(h, timeoutMs)
        }
    }

    /// Attaches the TUN. WireGuard applies `wgConfig` (UAPI) to its device;
    /// csqtt has no device and ignores it.
    func attach(wgConfig: String, tunFd: Int32) -> Int32 {
        switch self {
        case .wireguard(let h):
            return wgConfig.withCString { cfgPtr in
                wgAttachWireGuard(h, UnsafeMutablePointer(mutating: cfgPtr), tunFd)
            }
        case .csqtt(let h):
            return csqttAttach(h, tunFd)
        }
    }

    func turnOff() {
        switch self {
        case .wireguard(let h): wgTurnOff(h)
        case .csqtt(let h): csqttTurnOff(h)
        }
    }

    func pathChanged() {
        switch self {
        case .wireguard(let h): wgPathChanged(h)
        case .csqtt(let h): csqttPathChanged(h)
        }
    }

    /// A real interface is UP (satisfied wifi/cellular/wired). WireGuard: the
    /// proxy rotates its group id and restarts the old sessions after a settle
    /// (the post-switch downlink hole). csqtt: nothing extra — its pathChanged
    /// already replaces the whole session under a new identity, which is the
    /// same cure done by the protocol itself.
    func pathUp() {
        switch self {
        case .wireguard(let h): wgPathUp(h)
        case .csqtt: break
        }
    }

    func pathInTransition() {
        switch self {
        case .wireguard(let h): wgPathInTransition(h)
        case .csqtt(let h): csqttPathInTransition(h)
        }
    }

    func wakeHealthCheck() {
        switch self {
        case .wireguard(let h): wgWakeHealthCheck(h)
        case .csqtt(let h): csqttWakeHealthCheck(h)
        }
    }

    func logPathSnapshot(_ label: String) {
        label.withCString { cstr in
            switch self {
            case .wireguard(let h): wgLogPathSnapshot(h, cstr)
            case .csqtt(let h): csqttLogPathSnapshot(h, cstr)
            }
        }
    }

    /// Stats JSON in TunnelStats' shape, or nil.
    func stats() -> String? {
        let ptr: UnsafePointer<CChar>?
        switch self {
        case .wireguard(let h): ptr = wgGetStats(h)
        case .csqtt(let h): ptr = csqttGetStats(h)
        }
        return Self.take(ptr)
    }

    /// The relay host the tunnel runs on, for serverAddress next time; "" if
    /// not known yet.
    func relayIP() -> String {
        let ptr: UnsafePointer<CChar>?
        switch self {
        case .wireguard(let h): ptr = wgGetTURNServerIP(h)
        case .csqtt(let h): ptr = csqttGetRelayIP(h)
        }
        return Self.take(ptr) ?? ""
    }

    /// WRAP-A only: the GETCONF-minted WireGuard config as JSON. nil on the
    /// csqtt backend, which provisions through `csqttProvision` instead.
    func waitWrapAProvision(timeoutMs: Int32) -> String? {
        switch self {
        case .wireguard(let h): return Self.take(wgWaitWrapAProvision(h, timeoutMs))
        case .csqtt: return nil
        }
    }

    /// csqtt only: {"address","dns","mtu","stream"} once ready. nil on the
    /// WireGuard backend.
    func csqttProvisionJSON() -> String? {
        switch self {
        case .wireguard: return nil
        case .csqtt(let h): return Self.take(csqttProvision(h))
        }
    }

    /// csqtt only: the terminal error, "" while healthy. The WireGuard backend
    /// reports its terminal state through the cookie watchdog and stats.
    func terminalError() -> String {
        switch self {
        case .wireguard: return ""
        case .csqtt(let h): return Self.take(csqttGetError(h)) ?? ""
        }
    }

    /// Captcha answers go to the WireGuard proxy; csqtt has no captcha flow
    /// (a captcha is terminal there — see csqtt_bridge.go).
    func solveCaptcha(_ answer: String) {
        switch self {
        case .wireguard(let h):
            answer.withCString { ptr in
                wgSolveCaptcha(h, UnsafeMutablePointer(mutating: ptr))
            }
        case .csqtt:
            break
        }
    }

    func refreshCaptchaURL() -> String {
        switch self {
        case .wireguard(let h): return Self.take(wgRefreshCaptchaURL(h)) ?? ""
        case .csqtt: return ""
        }
    }

    /// Takes ownership of a C string the bridge malloc'd: copies and frees.
    private static func take(_ ptr: UnsafePointer<CChar>?) -> String? {
        guard let ptr = ptr else { return nil }
        let s = String(cString: ptr)
        free(UnsafeMutableRawPointer(mutating: ptr))
        return s
    }
}
