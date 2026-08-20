import Foundation

/// The parameters a run was STARTED with.
///
/// 🚨 The result used to be rendered from the screen's live `@AppStorage`
/// bindings, so changing the Direction picker after a run silently changed which
/// rows the finished result displayed — a completed download-only run would grow
/// an "Upload 0.0 Mbit/s" row on a tap that measured nothing. The knobs are
/// inputs; once a run has started they are history, and history does not move.
///
/// 🚫 There is deliberately NO `research` field. The mode label comes back from
/// Go, authored by the function that actually calls `SetEarlyStop`, so it cannot
/// disagree with the setting that was applied. A copy of the REQUEST here would
/// be a second source for one statement.
struct SpeedTestRunConfig: Equatable {
    let serverID: String
    let serverLabel: String
    let threads: Int
    let direction: String
    let durationSec: Int

    var ranDownload: Bool { direction != "upload" }
    var ranUpload: Bool { direction != "download" }
}

/// How the server for a run was chosen, and whether that undermines comparing it
/// with the run before.
///
/// 🚨 THE TRAP THIS EXISTS FOR IS NOT HYPOTHETICAL. Ookla selects from the
/// apparent IP, and three runs on an unchanged path minutes apart picked
/// `31309 MEO Lisboa`, `31309` again, then `69521 MEO LAB Oeiras`. The first
/// thing anyone does with this screen is press Run twice and compare — and with
/// `auto` the second number can be from a different server, silently.
///
/// 🚫 IT DOES NOT WARN ON EVERY AUTO RUN. `auto` is the default and most people
/// will never pin anything; painting every result orange would teach them that
/// orange means nothing. The warning fires when the trap actually bites — when
/// the server moved between two runs — and the rest of the time it is a quiet
/// note saying what to do about it.
enum SpeedTestServerChoice: Equatable {
    /// The user pinned an id, so repeat runs are comparable by construction.
    case pinned
    /// Chosen automatically, and it landed where the previous run did (or there
    /// was no previous run).
    case automatic
    /// Chosen automatically and it MOVED. The two runs measured different paths.
    case automaticMoved(from: String, to: String)

    /// `ranOn` is the id the run actually used; `previous` is the id of the last
    /// completed run, or nil if this is the first.
    static func of(pinnedID: String, ranOn: String, previous: String?) -> SpeedTestServerChoice {
        if !pinnedID.isEmpty { return .pinned }
        guard !ranOn.isEmpty else { return .automatic }
        if let previous, !previous.isEmpty, previous != ranOn {
            return .automaticMoved(from: previous, to: ranOn)
        }
        return .automatic
    }

    /// True only for the case that actually costs the user something.
    var isWarning: Bool {
        if case .automaticMoved = self { return true }
        return false
    }

    var note: String? {
        switch self {
        case .pinned:
            return nil
        case .automatic:
            return "Server chosen automatically. Pin one if you want to compare runs — "
                + "with the VPN on and off especially, since the list is built from the "
                + "address the internet sees for this device."
        case let .automaticMoved(from, to):
            return "Automatic selection moved from server \(from) to \(to) since the last run, "
                + "so these two results measured different servers and are not comparable. "
                + "Pin one to compare."
        }
    }
}
