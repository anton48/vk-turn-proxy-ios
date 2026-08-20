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
    static func start(_ run: SpeedTestRunConfig,
                      research: Bool,
                      path: SpeedTestPath,
                      build: String) -> String {
        let server = run.serverID.isEmpty ? "auto" : "\(clean(run.serverID)) (pinned)"
        // 🚨 `research` is passed in rather than read back from the engine's
        // `mode`, because `mode` only arrives WITH THE RESULT — and this line
        // exists for the runs that never produce one. Without it a hung run
        // leaves no way to tell which methodology was asked for, which is the
        // difference between a fixed window and an early stop.
        //
        // ⚖️ It is the REQUEST; the DONE line still carries the engine's own
        // `mode`, which is what was actually applied. Two fields on purpose.
        return "speedtest: START server=\(server) threads=\(run.threads) "
            + "direction=\(clean(run.direction)) duration=\(run.durationSec)s "
            + "research=\(research) path=\"\(path.rawValue)\" build=\(clean(build))"
    }

    /// 🚨 EVERYTHING FROM THE NETWORK GOES THROUGH THIS. Server names, sponsors,
    /// the mode string and Ookla's own fields are remote input landing in a
    /// ONE-LINE, quote-delimited format: a newline in a sponsor name splits a
    /// record in two, and a quote closes a field early. Both make a log that
    /// parses cleanly and says something that never happened, which is worse
    /// than one that fails to parse.
    static func clean(_ s: String) -> String {
        let collapsed = s.unicodeScalars.map {
            CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0)
                ? " " : Character($0)
        }
        var out = String(String.UnicodeScalarView(collapsed.map { $0.unicodeScalars.first! }))
        out = out.replacingOccurrences(of: "\"", with: "'")
        while out.contains("  ") { out = out.replacingOccurrences(of: "  ", with: " ") }
        out = out.trimmingCharacters(in: CharacterSet.whitespaces)
        return out.count > 120 ? String(out.prefix(117)) + "..." : out
    }

    /// The whole result, one line per phase plus a trailer that identifies the
    /// conditions. Empty when there is nothing to report.
    static func result(_ run: SpeedTestRunConfig,
                       progress: SpeedTestProgress,
                       path: SpeedTestPathTrace,
                       serverChoice: SpeedTestServerChoice = .pinned) -> [String] {
        var lines: [String] = []
        if run.ranDownload, let down = progress.download {
            lines.append(phase("DOWNLOAD", down, threads: run.threads))
        }
        if run.ranUpload, let up = progress.upload {
            lines.append(phase("UPLOAD", up, threads: run.threads))
        }
        if let error = progress.error {
            // 🚨 THROUGH clean() LIKE EVERYTHING ELSE — and this is the field
            // most likely to need it. Engine errors WRAP remote text: a server
            // name, a sponsor, an endpoint's own response. It was the last
            // interpolation in this file that bypassed the policy, which is
            // exactly where such a thing survives: on the path nobody exercises
            // when everything works.
            lines.append("speedtest: ERROR \(clean(error))")
        }
        guard !lines.isEmpty else { return [] }

        var trailer = "speedtest: DONE server=\(clean(progress.serverID))"
        if !progress.serverDesc.isEmpty { trailer += " \"\(clean(progress.serverDesc))\"" }
        trailer += String(format: " ping=%.0fms", progress.pingMs)
        if !progress.estimator.isEmpty { trailer += " estimator=\(clean(progress.estimator))" }
        // 🚨 The PATH is not decoration and it is a TRACE, not a state: a run
        // whose route changed belongs to neither, and a log that printed one of
        // them would be inventing an attribution the screen refuses to make.
        trailer += " path=\"\(path.label)\""
        if !progress.mode.isEmpty { trailer += " mode=\"\(clean(progress.mode))\"" }
        if !progress.ooklaSeesIP.isEmpty {
            trailer += " ookla-sees=\(clean(progress.ooklaSeesIP))"
            if !progress.ooklaSeesISP.isEmpty { trailer += " (\(clean(progress.ooklaSeesISP)))" }
        }
        trailer += " engine=\"\(clean(progress.engine))\""
        lines.append(trailer)
        // 🚨 LAST AND SEPARATE: the automatic-selection warning is the one that
        // says two runs are NOT COMPARABLE. A log kept so that runs can be
        // compared, which drops the line saying they cannot be, is worse than no
        // log — it invites exactly the comparison it should prevent.
        if serverChoice.isWarning, let note = serverChoice.note {
            lines.append("speedtest: ⚠️ \(clean(note))")
        }
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
        // 🚨 In research mode `bytes` is the WHOLE phase and the rate covers the
        // window, so a reader checking bytes/window against raw on a CORRECT
        // line concludes the tool is lying. Log what the rate was computed from,
        // and the phase total beside it only when they differ.
        s += String(format: " window-bytes=%.1fMB", Double(p.windowBytes) / 1e6)
        if p.windowBytes != p.bytes {
            s += String(format: " phase-bytes=%.1fMB(incl. warm-up)", Double(p.bytes) / 1e6)
        }
        s += " threads=\(threads) conns=\(p.connsUsed)/\(p.dials)"
        // 🚨 BOTH ARE SCOPED TO THE WINDOW, like every other figure on this line
        // except the explicitly-marked phase-bytes. A phase-scoped ratio printed
        // beside window bytes made a CORRECT line fail its own arithmetic —
        // measured on a research run: 98.0% reported against 97.5% implied by
        // the bytes next to it. One scope per line, one marked exception.
        if p.confirmedRatio > 0 { s += String(format: " confirmed=%.1f%%", p.confirmedRatio * 100) }
        if p.backlogBytes > 0 { s += String(format: " backlog=%.1fMB", Double(p.backlogBytes) / 1e6) }
        s += " consistent=\(p.consistent)"
        // 🚨 Warnings LAST and always: they are the reason a figure above them
        // may not mean what it looks like, and a log kept to replace a
        // screenshot that dropped them would be strictly worse than the
        // screenshot.
        for w in p.warnings ?? [] { s += " ⚠️ \(clean(w))" }
        return s
    }
}
