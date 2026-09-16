// UnseededStartPolicy.swift
//
// The ONE rule for a tunnel start the app could not seed — the server switch
// from the Live Activity's picker and the DIRECT repair, both of which run in
// the background, where the captcha WebView cannot be shown.
//
// csqtt cannot show VK's captcha from inside its extension: a captcha on its
// first credential is TERMINAL there (csqttTerminalCredError), so an unseeded
// csqtt start that the probe already knows will meet a captcha only dies a few
// seconds later with "csqtt cannot show it here". By then the old session is
// gone (the switch stops it before it probes — the probe must not run through
// the tunnel), so the honest outcome is: stay stopped, say why in the app, and
// wait for Connect, whose probe shows the captcha. Native goes on unseeded as
// before — the extension's own captcha path (captcha-pending + the WebView from
// stats, up to 120 s) is that transport's business; the transport is a
// parameter so native can join by one line here. A transient probe failure is
// not a captcha: the extension retries those itself, so the start goes ahead.
// (The user's decisions, 2026-09-16 §168: csqtt only; the reason in the app,
// not on the card; no auto-connect — Connect is the user's; no Go change.)

import Foundation

enum UnseededStartPolicy {
    enum Transport: Equatable {
        case native
        case csqtt
    }

    /// Who is starting — for the reason's wording.
    enum Entry: Equatable {
        case pickerSwitch(serverName: String)
        case directRepair
    }

    /// What the app's UI-less probe found.
    enum Probe: Equatable {
        case seeded   // a credential is in hand (the cache or the probe)
        case captcha  // VK asked for a captcha — an unseeded start WILL meet it
        case failed   // a transient failure — the extension retries those itself
    }

    enum Decision: Equatable {
        case start
        case stopAndWait(reason: String)
    }

    static func decide(transport: Transport, entry: Entry, probe: Probe) -> Decision {
        guard transport == .csqtt, probe == .captcha else { return .start }
        return .stopAndWait(reason: reason(for: entry))
    }

    /// What the app says: the cause, the transport's limit, and the way out.
    static func reason(for entry: Entry) -> String {
        let what: String
        switch entry {
        case .pickerSwitch(let serverName):
            what = "Switching to “\(serverName)”"
        case .directRepair:
            what = "Restoring the tunnel after the routing change"
        }
        return what + " needs a VK captcha, which csqtt cannot show from here. The tunnel is stopped — press Connect to continue; the captcha will be shown."
    }
}
