// ServerEditView.swift
//
// Edit screen for a single named ServerProfile (M2). Reached from SettingsView
// via a NavigationLink. It edits a local `draft` copy and persists every change
// through ServerStore.update() (which projects onto the flat @AppStorage keys
// when the edited server is the active one). New / Copy / Delete manage the set;
// the last remaining server cannot be deleted.
//
// vkLink and VK account auth are GLOBAL (edited on SettingsView), not here.

import SwiftUI

struct ServerEditView: View {
    @ObservedObject private var store = ServerStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ServerProfile

    // Global (not per-server) — read only to compute the cookie-mode conn cap.
    @AppStorage("vkLink") private var vkLink = ""
    @AppStorage("VKAuth") private var vkAuthEnabled = false

    init(serverId: UUID) {
        let s = ServerStore.shared.servers.first { $0.id == serverId }
                ?? ServerStore.shared.activeServer
        _draft = State(initialValue: s)
    }

    // Mode <-> draft flags, mutually exclusive (mirrors serverModeBinding).
    private var mode: Binding<ServerMode> {
        Binding(
            get: {
                if draft.useWrapS { return .srtpWrapS }
                if draft.useWrapA { return .srtpWrapA }
                if draft.useSrtp { return .srtp }
                if draft.useWrap { return .srtpWrap }
                return .legacy
            },
            set: { m in
                draft.useWrapS = (m == .srtpWrapS)
                draft.useWrapA = (m == .srtpWrapA)
                draft.useSrtp  = (m == .srtp)
                draft.useWrap  = (m == .srtpWrap)
                if m == .srtpWrapS && draft.clientID.isEmpty {
                    draft.clientID = UUID().uuidString
                }
            }
        )
    }

    @ViewBuilder
    private func hint(_ issue: ConfigValidation.Issue?) -> some View {
        if let issue {
            Text(issue.message)
                .font(.caption)
                .foregroundColor(issue.severity == .error ? .red : .orange)
        }
    }

    // Cookie-mode connection cap (mirrors SettingsView): 2 relays/call × 10, max 50.
    private var vkLinkLines: [String] {
        vkLink.split(whereSeparator: { $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
    private var cookieConnCap: Int { min(50, max(2, vkLinkLines.count * 20)) }
    private var connectionsUpperBound: Int {
        vkAuthEnabled ? max(cookieConnCap, draft.numConnections) : max(50, draft.numConnections)
    }
    private var connectionsLabel: String {
        if vkAuthEnabled && draft.numConnections > cookieConnCap {
            return "Connections: \(draft.numConnections) → \(cookieConnCap) (add call links)"
        }
        if vkAuthEnabled { return "Connections: \(draft.numConnections) (max \(cookieConnCap))" }
        return "Connections: \(draft.numConnections)"
    }

    var body: some View {
        Form {
            Section("Server name") {
                TextField("Server name", text: $draft.serverName)
                    .disableAutocorrection(true)
            }

            Section("Transport") {
                if mode.wrappedValue != .srtpWrapA {
                    TextField("Proxy Server (host:port)", text: $draft.peerAddress)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    hint(ConfigValidation.peerAddress(draft.peerAddress))
                }

                TextField("TURN server (IP:port, optional)", text: $draft.turnServerOverride)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .keyboardType(.numbersAndPunctuation)
                hint(ConfigValidation.turnOverride(draft.turnServerOverride))

                Picker("Server mode", selection: mode) {
                    ForEach(ServerMode.allCases) { m in Text(m.label).tag(m) }
                }

                if mode.wrappedValue == .srtpWrap {
                    SecureField("WRAP key (64 hex chars)", text: $draft.wrapKeyHex)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wrapKeyHex(draft.wrapKeyHex))
                }
                if mode.wrappedValue == .srtpWrapA {
                    SecureField("Server password", text: $draft.wrapAPassword)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wrapAPassword(draft.wrapAPassword))
                }
                if mode.wrappedValue == .srtpWrapS {
                    SecureField("WRAP key (64 hex chars)", text: $draft.wrapKeyHex)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wrapKeyHex(draft.wrapKeyHex))
                    Picker("Obfuscation profile", selection: $draft.obfProfile) {
                        Text("rtpopus").tag("rtpopus")
                        Text("rtpopus2").tag("rtpopus2")
                        Text("rtpopus3").tag("rtpopus3")
                    }
                    TextField("Client ID", text: $draft.clientID)
                        .autocapitalization(.none).disableAutocorrection(true)
                }

                Toggle("Use UDP transport to TURN", isOn: $draft.useUDP)
                Stepper(connectionsLabel, value: $draft.numConnections, in: 1...connectionsUpperBound)
                Stepper("Cred pool cooldown: \(draft.credPoolCooldownSeconds) s",
                        value: $draft.credPoolCooldownSeconds, in: 30...600, step: 30)
            }

            // WireGuard keys/address are user-entered for Legacy / SRTP /
            // SRTP+WRAP / SRTP-WRAP-S. In SRTP-WRAP-A they are minted by the
            // server via GETCONF, so hide the whole section in that mode.
            if mode.wrappedValue != .srtpWrapA {
                Section("WireGuard") {
                    SecureField("Private Key (base64)", text: $draft.privateKey)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wgKey(draft.privateKey, label: "Private key", required: true))
                    TextField("Peer Public Key (base64)", text: $draft.peerPublicKey)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wgKey(draft.peerPublicKey, label: "Peer public key", required: true))
                    SecureField("Preshared Key (base64)", text: $draft.presharedKey)
                        .autocapitalization(.none).disableAutocorrection(true)
                    hint(ConfigValidation.wgKey(draft.presharedKey, label: "Preshared key", required: false))
                    TextField("Tunnel Address", text: $draft.tunnelAddress)
                        .autocapitalization(.none)
                    hint(ConfigValidation.tunnelAddress(draft.tunnelAddress))
                    TextField("DNS Servers", text: $draft.dnsServers)
                        .autocapitalization(.none)
                    hint(ConfigValidation.dnsServers(draft.dnsServers))
                }
            }

            Section {
                Button {
                    draft = store.addNew()
                } label: { Label("New server", systemImage: "plus") }

                Button {
                    if let c = store.copy(draft.id) { draft = c }
                } label: { Label("Copy server", systemImage: "doc.on.doc") }

                Button(role: .destructive) {
                    store.delete(draft.id)
                    dismiss()
                } label: { Label("Delete server", systemImage: "trash") }
                    .disabled(store.servers.count <= 1)
            } footer: {
                Text("New creates a server with default settings. Copy duplicates this one. The last server can't be deleted. vkLink and VK account auth are global (Settings screen), not per-server.")
            }
        }
        .navigationTitle(draft.serverName.isEmpty ? "Server" : draft.serverName)
        .navigationBarTitleDisplayMode(.inline)
        // Persist every edit through the store (projects onto the flat keys when
        // this is the active server). onChange does not fire on first render.
        .onChange(of: draft) { store.update($0) }
    }
}
