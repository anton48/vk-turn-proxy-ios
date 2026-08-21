// AppEntitlements.swift
//
// Reads the entitlements THIS process was actually signed with, by parsing the
// code-signature blob embedded in its own Mach-O executable.
//
// Why this exists
// ---------------
// iOS offers no public API for runtime entitlement access (macOS has
// SecTaskCopyValueForEntitlement; iOS does not). We need it for exactly one
// reason: diagnostics. A large share of our users install a re-signed IPA,
// because an App Store-signed build cannot be installed outside the App Store
// and a NetworkExtension cannot be signed with a free Apple ID. The re-signer
// substitutes its own team, App ID and App Groups — our
// `group.com.vkturnproxy.app` is simply not among them, since an App Group is
// globally unique and owned by the team that registered it. Everything that
// crosses the app↔extension boundary through that container then fails
// silently: no vpn.log, no cred cache, no captured captcha profile. Verified
// on device 2026-07-25 (GitHub issues #7, #8, #59): the OS logs
// `container_create_or_lookup_app_group_path_by_app_group_identifier: client
// is not entitled` and `securityd … is only entitled for ( "4FN8R4RQZT.*",
// "group.f8b3894f16fd4600.1" … )`.
//
// Without this reader the app can only say "the container is unavailable".
// With it, it can say WHO signed the build and WHICH groups it does have —
// which turns an unactionable bug report into a self-diagnosing one.
//
// This is DIAGNOSTIC ONLY. Nothing here changes which container we use; we
// still ask for `group.com.vkturnproxy.app` and degrade when it is absent.
//
// Implementation notes
// --------------------
// Approach borrowed from wiedem/app-entitlements (MIT), reimplemented in ~200
// dependency-free lines. That package is fine, but it pulls in apple/swift-asn1
// to decode the DER flavour of the entitlements blob, and this project has no
// SPM dependencies at all. Empirically both flavours are present in every
// binary we care about — our own App Store build AND the third-party re-signed
// one each carry exactly one `0xfade7171` (XML plist) blob alongside the DER
// one — so reading the plist flavour alone is sufficient and needs no ASN.1.
// If some future signer ever emits DER only, `current.error` is set and the
// diagnosis degrades to what it says today. No private API is used: this reads
// a file inside our own bundle and parses it.
//
// Everything is bounds-checked and returns nil rather than trapping — this runs
// inside a NetworkExtension, where a crash takes the user's VPN down.

import Foundation

struct AppEntitlements: Sendable {
    /// e.g. "CDMQ33VFQC.com.vkturnproxy.app". The part before the first dot is
    /// the team; the rest must equal the bundle id for NE IPC to be permitted.
    let applicationIdentifier: String?
    let teamIdentifier: String?
    let applicationGroups: [String]
    let keychainAccessGroups: [String]
    /// The modes granted by `com.apple.developer.networking.networkextension`,
    /// e.g. ["packet-tunnel-provider"]. EMPTY on a build whose signature does
    /// not carry the entitlement at all — which is the state this file exists
    /// to name, because iOS then refuses every NEVPNManager /
    /// NETunnelProviderManager operation and the user only sees the framework's
    /// own "permission denied".
    let networkExtensionModes: [String]
    /// nil when parsing succeeded; otherwise why it didn't.
    let error: String?

    /// Parsed once per process, lazily, on first use.
    static let current: AppEntitlements = load()

    func hasAppGroup(_ identifier: String) -> Bool {
        applicationGroups.contains(identifier)
    }

    /// Whether this binary may run a packet tunnel at all.
    ///
    /// The mode string is matched EXACTLY. `com.apple.developer.networking.networkextension`
    /// also grants unrelated modes (app-proxy-provider, content-filter-provider,
    /// dns-proxy-provider …), and a build holding one of those but not ours is
    /// as unable to start the tunnel as one holding none — so "the array is
    /// non-empty" would be the wrong test.
    var hasPacketTunnelProvider: Bool {
        networkExtensionModes.contains("packet-tunnel-provider")
    }

    /// Team the binary is signed by, preferring the explicit entitlement and
    /// falling back to the application-identifier prefix (re-signers often set
    /// one but not the other).
    var effectiveTeam: String? {
        if let t = teamIdentifier, !t.isEmpty { return t }
        guard let appID = applicationIdentifier,
              let dot = appID.firstIndex(of: ".") else { return nil }
        return String(appID[appID.startIndex..<dot])
    }

    /// Multi-line explanation for the Logs banner and the os_log stream:
    /// states plainly whether this build can reach `required`, and if not, what
    /// it was signed with instead. Kept short enough to paste into an issue.
    static func appGroupDiagnosis(required: String) -> String {
        let e = current
        if let err = e.error {
            return "Could not read this build's entitlements (\(err)). "
                 + "Cannot tell whether \(required) was granted."
        }
        let team = e.effectiveTeam ?? "unknown team"
        let groups = e.applicationGroups.isEmpty
            ? "none" : e.applicationGroups.joined(separator: ", ")
        if e.hasAppGroup(required) {
            return "This build IS entitled to \(required) (team \(team)), "
                 + "so the container should exist — an unexpected state worth reporting."
        }
        return """
        This build is NOT entitled to \(required).
        Signed by team \(team)\(e.applicationIdentifier.map { " (app id \($0))" } ?? "").
        App Groups it does have: \(groups).
        That means the IPA was re-signed by a third party: an App Group belongs to \
        the team that registered it, so a re-signer cannot carry ours over. Shared \
        logging, the TURN credential cache and the captured captcha profile are \
        disabled in this build. Install via TestFlight for a fully working build.
        DELETE THIS APP FIRST: iOS refuses to install an official build over a \
        re-signed one, because the signing identity differs — TestFlight only \
        reports "An error occurred while installing". Deleting the app erases its \
        settings, so export a Full Backup from Settings beforehand and import it \
        into the fresh install.
        """
    }

    /// Why a VPN-configuration call was refused — read off THIS binary's own
    /// signature rather than guessed from the error.
    ///
    /// NetworkExtension answers every preferences operation on an unentitled
    /// build with its own `configurationPermissionDenied`, whose localized
    /// description is the bare words "permission denied". That string is the
    /// whole message a user gets today, and it names neither the cause nor
    /// anything they can act on — while the cause is sitting in the code
    /// signature we can already read.
    ///
    /// 🚨 The entitled branch must NOT accuse the signature. If the entitlement
    /// IS present the refusal came from somewhere else entirely (a leftover VPN
    /// profile owned by a different signing identity, a supervised/MDM device,
    /// or a prompt the user answered with "Don't Allow"), and telling that user
    /// to re-sign would send them to rebuild a thing that is already correct.
    func vpnPermissionDiagnosis() -> String {
        if let err = error {
            return "Could not read this build's entitlements (\(err)), so this "
                 + "cannot say whether the VPN entitlement is present. "
                 + "Please report the model and iOS version."
        }
        let team = effectiveTeam ?? "unknown team"
        let signer = "Signed by team \(team)"
                   + (applicationIdentifier.map { " (app id \($0))" } ?? "") + "."
        guard hasPacketTunnelProvider else {
            let modes = networkExtensionModes.isEmpty
                ? "none" : networkExtensionModes.joined(separator: ", ")
            return """
            This build CANNOT create a VPN configuration: its signature does not \
            carry com.apple.developer.networking.networkextension = \
            packet-tunnel-provider. Network Extension modes it does have: \(modes).
            \(signer)
            iOS refuses every VPN-configuration call on such a build, which is why \
            no "would like to add VPN configurations" prompt ever appears and every \
            attempt ends in "permission denied". Nothing in the app can work around \
            this — the entitlement is granted by the provisioning profile the IPA \
            was signed with, and only a paid Apple Developer account can enable \
            Network Extensions on an App ID. A free Apple ID signature (Personal \
            Team — what 3uTools, AltStore and Sideloadly produce by default) cannot.
            Install via TestFlight, or re-sign with a paid developer account.
            DELETE THIS APP FIRST: iOS refuses to install a differently-signed \
            build over this one and only reports "An error occurred while \
            installing". Export a Full Backup from Settings beforehand.
            """
        }
        // 🚨 NOT lowercased. A team identifier is case-significant and is exactly
        // what a reader compares against a provisioning profile — "cdmq33vfqc"
        // matches nothing and reads as a different team.
        return """
        This build IS entitled to run a packet tunnel. \(signer)
        So the refusal did NOT come from how the IPA was signed, and re-signing \
        it will not help.
        Worth checking instead: a leftover "VK Turn Proxy" entry under Settings › \
        General › VPN & Device Management left by an earlier, differently-signed \
        install (delete it, then reinstall); whether the device is supervised or \
        managed by an MDM profile that forbids creating VPN configurations; and \
        whether a previous "would like to add VPN configurations" prompt was \
        answered with "Don't Allow".
        """
    }

    /// One line for the main screen; the full text above goes to the log.
    ///
    /// The status area is a centered `.caption` under the connection circle —
    /// eight lines of red there is what a user crops OUT of the screenshot they
    /// attach to an issue. So the screen states the cause and points at the
    /// Logs screen, which is copyable and is where the pasteable version lives.
    func vpnPermissionHeadline() -> String {
        if error != nil {
            return "VPN config refused; this build's entitlements are unreadable — see Logs."
        }
        return hasPacketTunnelProvider
            ? "VPN config refused, though this build IS entitled to a tunnel — see Logs."
            : "This build was signed without the VPN entitlement, so it cannot create a VPN configuration — see Logs."
    }

    /// Convenience over the running process. The rules themselves live on the
    /// value above so they can be tested without a real signature.
    static func vpnPermissionDiagnosis() -> String {
        current.vpnPermissionDiagnosis()
    }

    static func vpnPermissionHeadline() -> String {
        current.vpnPermissionHeadline()
    }

    // MARK: - Parsing

    // Both initialisers are internal, not private, so the swiftcheck harness can
    // drive `vpnPermissionDiagnosis()` with fixtures. The diagnosis is the part
    // that must be right — it is what a user pastes into an issue — and a rule
    // reachable only through the live process signature could not be exercised
    // at all. Same reasoning as SpeedTestPathTrace: put the rule on the TYPE.
    init(dict: [String: Any]) {
        applicationIdentifier = dict["application-identifier"] as? String
        teamIdentifier = dict["com.apple.developer.team-identifier"] as? String
        applicationGroups = (dict["com.apple.security.application-groups"] as? [String]) ?? []
        keychainAccessGroups = (dict["keychain-access-groups"] as? [String]) ?? []
        networkExtensionModes =
            (dict["com.apple.developer.networking.networkextension"] as? [String]) ?? []
        error = nil
    }

    init(error: String) {
        applicationIdentifier = nil
        teamIdentifier = nil
        applicationGroups = []
        keychainAccessGroups = []
        networkExtensionModes = []
        self.error = error
    }

    private static func load() -> AppEntitlements {
        // Bundle.main is the .app in the host process and the .appex in the
        // extension process, so each side reads its OWN signature — which is
        // the point: they can disagree, and that disagreement is a finding.
        guard let url = Bundle.main.executableURL else {
            return AppEntitlements(error: "no executable URL")
        }
        guard let data = try? Data(contentsOf: url, options: .alwaysMapped) else {
            return AppEntitlements(error: "executable unreadable")
        }
        guard let plist = entitlementsPlist(in: data) else {
            return AppEntitlements(error: "no XML entitlements blob in code signature")
        }
        guard let obj = try? PropertyListSerialization.propertyList(
                from: plist, options: [], format: nil),
              let dict = obj as? [String: Any] else {
            return AppEntitlements(error: "entitlements blob is not a plist dictionary")
        }
        return AppEntitlements(dict: dict)
    }

    // MARK: - Mach-O / code signature walk
    //
    // Header fields are in the file's own byte order (little-endian on every
    // Apple ARM/Intel target, byte-swapped for the CIGAM magics). The code
    // signature is ALWAYS big-endian regardless of the host — a detail that is
    // easy to get wrong and produces silent garbage rather than an error.

    private static let fatMagic: UInt32       = 0xcafe_babe
    private static let fatCigam: UInt32       = 0xbeba_feca
    private static let machMagic64: UInt32    = 0xfeed_facf
    private static let machCigam64: UInt32    = 0xcffa_edfe
    private static let machMagic32: UInt32    = 0xfeed_face
    private static let machCigam32: UInt32    = 0xcefa_edfe
    private static let lcCodeSignature: UInt32 = 0x1d
    private static let csSuperBlob: UInt32    = 0xfade_0cc0
    private static let csEntitlements: UInt32 = 0xfade_7171

    /// Bounds-checked big-endian / little-endian 32-bit read.
    private static func u32(_ d: Data, _ offset: Int, swapped: Bool) -> UInt32? {
        guard offset >= 0, offset &+ 4 > offset, d.count >= offset &+ 4 else { return nil }
        let i = d.startIndex &+ offset
        let raw = UInt32(d[i]) << 24 | UInt32(d[i &+ 1]) << 16
                | UInt32(d[i &+ 2]) << 8 | UInt32(d[i &+ 3])
        // `raw` is assembled big-endian; swap when the field is little-endian.
        return swapped ? raw.byteSwapped : raw
    }

    private static func entitlementsPlist(in data: Data) -> Data? {
        guard let magic = u32(data, 0, swapped: false) else { return nil }

        // Universal binary: try each slice, return the first that yields a blob.
        // Device builds are thin arm64, but a fat file is legal and cheap to handle.
        if magic == fatMagic || magic == fatCigam {
            guard let count = u32(data, 4, swapped: false), count < 64 else { return nil }
            for i in 0..<Int(count) {
                let archOffset = 8 + i * 20
                guard let sliceOffset = u32(data, archOffset + 8, swapped: false),
                      let sliceSize = u32(data, archOffset + 12, swapped: false) else { continue }
                let start = Int(sliceOffset), size = Int(sliceSize)
                guard start >= 0, size > 0, start &+ size <= data.count else { continue }
                let slice = data.subdata(in: (data.startIndex + start)..<(data.startIndex + start + size))
                if let found = entitlementsPlist(in: slice) { return found }
            }
            return nil
        }

        let is64: Bool
        let swapped: Bool
        switch magic {
        case machMagic64: is64 = true;  swapped = false
        case machCigam64: is64 = true;  swapped = true
        case machMagic32: is64 = false; swapped = false
        case machCigam32: is64 = false; swapped = true
        default: return nil
        }

        guard let ncmds = u32(data, 16, swapped: swapped), ncmds < 4096 else { return nil }
        var cursor = is64 ? 32 : 28   // sizeof(mach_header_64) / sizeof(mach_header)

        for _ in 0..<Int(ncmds) {
            guard let cmd = u32(data, cursor, swapped: swapped),
                  let cmdSize = u32(data, cursor + 4, swapped: swapped),
                  cmdSize >= 8 else { return nil }
            if cmd == lcCodeSignature {
                // struct linkedit_data_command { cmd, cmdsize, dataoff, datasize }
                guard let dataOff = u32(data, cursor + 8, swapped: swapped),
                      let dataSize = u32(data, cursor + 12, swapped: swapped) else { return nil }
                return entitlementsPlist(inSignature: data,
                                         offset: Int(dataOff), size: Int(dataSize))
            }
            cursor = cursor &+ Int(cmdSize)
            guard cursor > 0, cursor < data.count else { return nil }
        }
        return nil
    }

    /// Walk the CS_SuperBlob index and return the payload of the XML
    /// entitlements blob. All fields here are big-endian by definition.
    private static func entitlementsPlist(inSignature data: Data, offset: Int, size: Int) -> Data? {
        guard offset >= 0, size > 8, offset &+ size <= data.count,
              let magic = u32(data, offset, swapped: false), magic == csSuperBlob,
              let count = u32(data, offset + 8, swapped: false), count < 128 else { return nil }

        for i in 0..<Int(count) {
            // struct CS_BlobIndex { uint32 type; uint32 offset; } — offset is
            // relative to the START of the SuperBlob, not to the file.
            let indexOffset = offset + 12 + i * 8
            guard let blobOffset = u32(data, indexOffset + 4, swapped: false) else { continue }
            let blobStart = offset &+ Int(blobOffset)
            guard blobStart > offset, blobStart &+ 8 <= offset &+ size,
                  let blobMagic = u32(data, blobStart, swapped: false),
                  blobMagic == csEntitlements,
                  let blobLength = u32(data, blobStart + 4, swapped: false),
                  blobLength > 8 else { continue }
            let payloadStart = blobStart &+ 8
            let payloadEnd = blobStart &+ Int(blobLength)
            guard payloadEnd > payloadStart, payloadEnd <= data.count else { continue }
            return data.subdata(in: (data.startIndex + payloadStart)..<(data.startIndex + payloadEnd))
        }
        return nil
    }
}
