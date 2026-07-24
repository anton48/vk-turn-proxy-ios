// ServerStore.swift
//
// Canonical store of named server profiles (Option A architecture). The ACTIVE
// profile is PROJECTED into the flat @AppStorage/UserDefaults keys that
// ContentView's TunnelConfig build + TunnelManager already read — so connect(),
// buildProxyConfig and buildUAPIConfig need no changes.
//
// ServerStore is the ONLY writer of the per-server flat keys. The GLOBAL keys
// (vkLink, VKAuth, forceLegacyCaptcha) are NEVER touched by projection.
//
// The store is instantiated at launch: first-launch migration captures the
// existing single config as "Server1", then load() projects the active server
// onto the flat @AppStorage keys that ContentView / TunnelManager read.

import Foundation

final class ServerStore: ObservableObject {
    static let shared = ServerStore()

    @Published private(set) var servers: [ServerProfile] = []
    @Published private(set) var activeServerId: UUID = UUID()

    private let d = UserDefaults.standard
    private let serversKey = "servers_v1"
    private let activeKey = "activeServerId"

    // The flat per-server keys projected/migrated. GLOBAL keys (vkLink, VKAuth,
    // forceLegacyCaptcha) are deliberately absent from these tables.
    private static let stringKeyPaths: [(String, WritableKeyPath<ServerProfile, String>)] = [
        ("privateKey", \.privateKey), ("peerPublicKey", \.peerPublicKey),
        ("presharedKey", \.presharedKey), ("tunnelAddress", \.tunnelAddress),
        ("peerAddress", \.peerAddress), ("dnsServers", \.dnsServers),
        ("turnServerOverride", \.turnServerOverride), ("wrapKeyHex", \.wrapKeyHex),
        ("obfProfile", \.obfProfile), ("clientID", \.clientID),
        ("wrapAPassword", \.wrapAPassword),
    ]
    private static let boolKeyPaths: [(String, WritableKeyPath<ServerProfile, Bool>, Bool)] = [
        ("useUDP", \.useUDP, false), ("useDTLS", \.useDTLS, true),
        ("useSrtp", \.useSrtp, true), ("useWrap", \.useWrap, false),
        ("useWrapA", \.useWrapA, false), ("useWrapS", \.useWrapS, false),
    ]
    private static let intKeyPaths: [(String, WritableKeyPath<ServerProfile, Int>, Int)] = [
        ("numConnections", \.numConnections, 30),
        ("credPoolCooldownSeconds", \.credPoolCooldownSeconds, 150),
    ]

    private init() { load() }

    var activeServer: ServerProfile {
        servers.first(where: { $0.id == activeServerId }) ?? servers[0]
    }

    // MARK: - Persistence + first-launch migration

    private func load() {
        if let data = d.data(forKey: serversKey),
           let decoded = try? JSONDecoder().decode([ServerProfile].self, from: data),
           !decoded.isEmpty {
            servers = decoded
            if let s = d.string(forKey: activeKey), let id = UUID(uuidString: s),
               decoded.contains(where: { $0.id == id }) {
                activeServerId = id
            } else {
                activeServerId = decoded[0].id
            }
        } else {
            // First launch (or an unreadable store): capture the user's existing
            // single config from the flat keys as "Server1".
            let s = Self.serverFromFlatKeys(name: "Server1")
            servers = [s]
            activeServerId = s.id
            persist()
        }
        // Project the active server onto the flat @AppStorage keys so ContentView
        // / TunnelManager always read the active server's config. On first launch
        // this is a no-op (Server1 was built from those very keys).
        projectToFlatKeys(activeServer)
        let s = activeServer
        SharedLogger.shared.log("[AppDebug] servers: \(servers.count) configured, active = \"\(s.serverName)\" [\(s.modeLabel)]")
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(servers) {
            d.set(data, forKey: serversKey)
        }
        d.set(activeServerId.uuidString, forKey: activeKey)
    }

    /// Build a ServerProfile from the current flat @AppStorage keys, matching
    /// each key's @AppStorage default when the key was never written.
    static func serverFromFlatKeys(name: String) -> ServerProfile {
        let d = UserDefaults.standard
        var p = ServerProfile()
        p.serverName = name
        for (key, kp) in stringKeyPaths {
            if let v = d.string(forKey: key) { p[keyPath: kp] = v }
        }
        for (key, kp, def) in boolKeyPaths {
            p[keyPath: kp] = d.object(forKey: key) == nil ? def : d.bool(forKey: key)
        }
        for (key, kp, def) in intKeyPaths {
            p[keyPath: kp] = d.object(forKey: key) == nil ? def : d.integer(forKey: key)
        }
        return p
    }

    // MARK: - Projection (active profile -> flat keys). ONLY writer of these keys.

    func projectToFlatKeys(_ p: ServerProfile) {
        for (key, kp) in Self.stringKeyPaths { d.set(p[keyPath: kp], forKey: key) }
        for (key, kp, _) in Self.boolKeyPaths { d.set(p[keyPath: kp], forKey: key) }
        for (key, kp, _) in Self.intKeyPaths { d.set(p[keyPath: kp], forKey: key) }
        d.set("0.0.0.0/0", forKey: "allowedIPs")   // always pinned
        // GLOBAL keys (vkLink, VKAuth, forceLegacyCaptcha) intentionally untouched.
    }

    // MARK: - Mutations (wired to the UI in M2 / link import in M4)

    func activate(_ id: UUID) {
        guard servers.contains(where: { $0.id == id }) else { return }
        activeServerId = id
        persist()
        let s = activeServer
        SharedLogger.shared.log("[AppDebug] active server → \"\(s.serverName)\" [\(s.modeLabel)]")
    }

    func update(_ profile: ServerProfile) {
        guard let i = servers.firstIndex(where: { $0.id == profile.id }) else { return }
        servers[i] = profile
        persist()
    }

    /// Project the ACTIVE server onto the flat @AppStorage keys. Called at
    /// launch and when the Settings flow closes (SettingsView.onDisappear) —
    /// NOT during editing / active-server switching. Reason: writing these keys
    /// re-renders ContentView (it observes them via @AppStorage), and in a
    /// NavigationView that pops any pushed child (ServerEditView / SettingsView).
    /// Deferring projection to "leaving Settings" keeps editing stable; the flat
    /// keys are only consumed on ContentView's main screen (validation + connect),
    /// which is exactly where the user lands after Settings closes.
    func projectActive() {
        projectToFlatKeys(activeServer)
    }

    @discardableResult
    func addNew() -> ServerProfile {
        var p = ServerProfile()
        p.serverName = nextDefaultName()
        servers.append(p)
        persist()
        return p
    }

    @discardableResult
    func copy(_ id: UUID) -> ServerProfile? {
        guard var p = servers.first(where: { $0.id == id }) else { return nil }
        p.id = UUID()
        p.serverName = uniqueName(p.serverName + " copy")
        servers.append(p)
        persist()
        return p
    }

    func delete(_ id: UUID) {
        guard servers.count > 1 else { return }   // can't delete the last server
        let wasActive = (id == activeServerId)
        servers.removeAll { $0.id == id }
        if wasActive { activate(servers[0].id) } else { persist() }
    }

    // MARK: - Full-backup import (M3)

    /// Replace the whole set from a backup that carries `servers`. The active
    /// server is picked by name (falling back to the first entry) and projected
    /// onto the flat keys, since an import lands the user back on the main
    /// screen where those keys are read.
    func replaceAll(_ profiles: [ServerProfile], activeName: String?) {
        guard !profiles.isEmpty else { return }
        servers = profiles
        let active = activeName.flatMap { name in profiles.first { $0.serverName == name } }
                     ?? profiles[0]
        activeServerId = active.id
        persist()
        projectToFlatKeys(active)
        SharedLogger.shared.log("[AppDebug] Backup: restored \(profiles.count) server(s), active = \"\(active.serverName)\" [\(active.modeLabel)]")
    }

    /// Rebuild the set as a single server from the flat @AppStorage keys. Used
    /// when importing a pre-179 backup, whose settings were just written to
    /// those keys — no projection needed, they already hold these values.
    func resetFromFlatKeys(name: String = "Server1") {
        let p = Self.serverFromFlatKeys(name: name)
        servers = [p]
        activeServerId = p.id
        persist()
        SharedLogger.shared.log("[AppDebug] Backup: legacy single-server backup imported as \"\(p.serverName)\" [\(p.modeLabel)]")
    }

    /// M4: import a connection link as a NEW server and make it active.
    @discardableResult
    func addAndActivate(_ profile: ServerProfile) -> ServerProfile {
        var p = profile
        p.serverName = p.serverName.isEmpty ? nextDefaultName() : uniqueName(p.serverName)
        servers.append(p)
        activate(p.id)
        return p
    }

    // MARK: - Naming helpers

    private func nextDefaultName() -> String {
        let names = Set(servers.map { $0.serverName })
        var n = 1
        while names.contains("Server\(n)") { n += 1 }
        return "Server\(n)"
    }

    private func uniqueName(_ base: String) -> String {
        let names = Set(servers.map { $0.serverName })
        if !names.contains(base) { return base }
        var n = 2
        while names.contains("\(base) \(n)") { n += 1 }
        return "\(base) \(n)"
    }
}
