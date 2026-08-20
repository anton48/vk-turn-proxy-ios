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
