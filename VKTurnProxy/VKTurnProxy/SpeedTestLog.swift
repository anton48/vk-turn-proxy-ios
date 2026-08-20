import Foundation

/// Turns a finished (or starting) speed test into log lines.
///
/// 🚨 A PURE TYPE, so the format can be tested. It is also why the formatting
/// lives here rather than inside the runner: a log line is a thing people will
/// later parse, compare across weeks and paste into a report, and one built
/// inline in a completion handler is one nobody can exercise without a network,
/// a device and a stopwatch.
///
/// 🎯 THE POINT OF THESE LINES IS TO REPLACE A SCREENSHOT. So they carry every
/// field the result screen shows and the two it cannot: the app build and the
/// engine's methodology revisions. A number without those cannot be compared
/// with a number from another week — which is the whole reason both exist.
enum SpeedTestLog {
    /// Written when Run is pressed, so a run that is stopped, fails, or never
    /// reports still leaves its parameters behind.
    static func start(_ run: SpeedTestRunConfig, path: SpeedTestPath, build: String) -> String {
        let server = run.serverID.isEmpty ? "auto" : "\(run.serverID) (pinned)"
        return "speedtest: START server=\(server) threads=\(run.threads) "
            + "direction=\(run.direction) duration=\(run.durationSec)s "
            + "path=\"\(path.rawValue)\" build=\(build)"
    }

    /// The whole result, one line per phase plus a trailer that identifies the
    /// conditions. Empty when there is nothing to report.
    static func result(_ run: SpeedTestRunConfig,
                       progress: SpeedTestProgress,
                       path: SpeedTestPathTrace) -> [String] {
        var lines: [String] = []
        if run.ranDownload, let down = progress.download {
            lines.append(phase("DOWNLOAD", down, threads: run.threads))
        }
        if run.ranUpload, let up = progress.upload {
            lines.append(phase("UPLOAD", up, threads: run.threads))
        }
        if let error = progress.error {
            lines.append("speedtest: ERROR \(error)")
        }
        guard !lines.isEmpty else { return [] }

        var trailer = "speedtest: DONE server=\(progress.serverID)"
        if !progress.serverDesc.isEmpty { trailer += " \"\(progress.serverDesc)\"" }
        trailer += String(format: " ping=%.0fms", progress.pingMs)
        // 🚨 The PATH is not decoration and it is a TRACE, not a state: a run
        // whose route changed belongs to neither, and a log that printed one of
        // them would be inventing an attribution the screen refuses to make.
        trailer += " path=\"\(path.label)\""
        if !progress.mode.isEmpty { trailer += " mode=\"\(progress.mode)\"" }
        if !progress.ooklaSeesIP.isEmpty { trailer += " ookla-sees=\(progress.ooklaSeesIP)" }
        trailer += " engine=\"\(progress.engine)\""
        lines.append(trailer)
        return lines
    }

    private static func phase(_ name: String, _ p: SpeedTestPhase, threads: Int) -> String {
        var s = String(format: "speedtest: %@ raw=%.1f engine=%.1f Mbit/s", name, p.rawMbps, p.libraryMbps)
        // Both durations, always: the window is what the raw figure covers and
        // the actual is what the phase took. In research mode they differ by the
        // discarded warm-up, and a reader given only one of them cannot tell
        // which they have.
        s += String(format: " actual=%.1fs window=%.1fs", p.actualSec, p.windowSec)
        if p.warmupSec > 0 { s += String(format: " warmup=%.1fs", p.warmupSec) }
        s += String(format: " bytes=%.1fMB", Double(p.bytes) / 1e6)
        s += " threads=\(threads) conns=\(p.connsUsed)/\(p.dials)"
        if p.confirmedRatio > 0 { s += String(format: " confirmed=%.1f%%", p.confirmedRatio * 100) }
        if p.backlogBytes > 0 { s += String(format: " backlog=%.1fMB", Double(p.backlogBytes) / 1e6) }
        s += " consistent=\(p.consistent)"
        // 🚨 Warnings LAST and always: they are the reason a figure above them
        // may not mean what it looks like, and a log kept to replace a
        // screenshot that dropped them would be strictly worse than the
        // screenshot.
        for w in p.warnings ?? [] { s += " ⚠️ \(w)" }
        return s
    }
}
