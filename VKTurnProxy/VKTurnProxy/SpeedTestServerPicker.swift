import SwiftUI

/// Choosing the server, and saying WHOSE neighbourhood the list describes.
///
/// 🚨 The header text is the point, not decoration. Ookla builds this list from
/// the device's APPARENT address, so with the tunnel up it is servers near the
/// EXIT and with it down servers near the user. The same "Auto" therefore
/// measures two different paths, silently — and comparing "with VPN" against
/// "without" is the first thing anyone does. Pinning one server is what makes
/// that pair mean anything, which is why the pin survives the tunnel state.
struct SpeedTestServerPicker: View {
    @Binding var serverID: String
    @Binding var serverLabel: String

    @ObservedObject private var runner = SpeedTestRunner.shared
    @ObservedObject private var tunnel = TunnelManager.shared
    @Environment(\.presentationMode) private var presentation

    @State private var query = ""

    /// The route RIGHT NOW — used only to ask the list whether it is stale, never
    /// to describe the rows.
    private var livePath: SpeedTestPath {
        .current(connected: tunnel.status == .connected, directMode: tunnel.directMode)
    }

    /// 🚨 Asked of the LIST, which knows what it was fetched under. This used to
    /// be computed from the live tunnel state while the rows below were whatever
    /// had been fetched earlier, so after a VPN → DIRECT switch the header
    /// described a neighbourhood the rows did not come from.
    private var neighbourhood: String {
        runner.serverList?.header(now: livePath) ?? "Servers"
    }

    private var filtered: [SpeedTestServer] {
        guard !query.isEmpty else { return runner.servers }
        let q = query.lowercased()
        return runner.servers.filter {
            $0.name.lowercased().contains(q)
                || $0.sponsor.lowercased().contains(q)
                || $0.country.lowercased().contains(q)
                || $0.id == query
        }
    }

    var body: some View {
        List {
            Section {
                Button {
                    serverID = ""
                    serverLabel = ""
                    presentation.wrappedValue.dismiss()
                } label: {
                    HStack {
                        Text("Auto (nearest)")
                        Spacer()
                        if serverID.isEmpty { Image(systemName: "checkmark") }
                    }
                }
            }

            Section {
                if runner.serversLoading {
                    HStack { ProgressView(); Text("Loading…").foregroundColor(.secondary) }
                } else if let err = runner.serversError {
                    Label(err, systemImage: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                    Button("Try again") { runner.loadServers() }
                } else {
                    if let notice = runner.serverList?.staleNotice(now: livePath) {
                        VStack(alignment: .leading, spacing: 6) {
                            Label(notice, systemImage: "arrow.triangle.branch")
                                .font(.caption)
                                .foregroundColor(.orange)
                            Button("Reload for this route") { runner.loadServers() }
                                .font(.caption)
                        }
                    }
                    ForEach(filtered) { server in
                        Button {
                            serverID = server.id
                            serverLabel = server.label
                            presentation.wrappedValue.dismiss()
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(server.label)
                                    Text(String(format: "id %@ · %.0f km", server.id, server.distanceKm))
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                if serverID == server.id { Image(systemName: "checkmark") }
                            }
                        }
                    }
                }
            } header: {
                Text(neighbourhood)
            } footer: {
                Text("The list comes from the address the internet sees for this device, "
                     + "so it changes when the VPN does. Pin one server if you want to "
                     + "compare with the VPN on and off — otherwise the two runs measure "
                     + "different paths.")
            }
        }
        .searchable(text: $query, prompt: "Name, city or sponsor")
        .navigationTitle("Server")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if runner.servers.isEmpty { runner.loadServers() } }
    }
}
