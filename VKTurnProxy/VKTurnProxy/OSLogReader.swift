import Foundation
import OSLog

/// In-process os_log reader, used as a fallback for the in-app Logs UI
/// when the SharedLogger file (in the App Group container) is empty or
/// unavailable.
///
/// The classic case is a process where
/// `FileManager.default.containerURL(forSecurityApplicationGroupIdentifier:)`
/// returns nil — improper code signing on a sideloaded IPA, an iOS
/// behaviour change, etc. In that state SharedLogger silently no-ops on
/// every `log()` call and `readLogs()` returns an empty string, so the
/// in-app Logs view shows nothing — even though every log line ALSO went
/// to os_log via `os_log()` (Swift) and `os_log_create + os_log` (Go via
/// the cgo bridge). This reader gives us a way to recover those entries
/// from the live in-memory ring buffer iOS keeps per process.
///
/// Limitations:
///   - Per-process only. Each process can read its OWN os_log entries
///     via `OSLogStore(scope: .currentProcessIdentifier)`. To get the
///     extension's entries from the main app, the extension must be
///     asked over `sendProviderMessage` to read its own and return them.
///   - In-memory ring buffer. Once the process restarts (jetsam,
///     normal disconnect, system reboot), the previous entries are
///     gone. Persistent archive (`OSLogStore.local()`) requires
///     entitlements iOS apps don't get.
///   - iOS 15+. Returns "" on older systems (deployment target is 15
///     so this is a non-issue today, kept for safety).
enum OSLogReader {
    /// Read this process's recent os_log entries filtered to our
    /// subsystems, returning them formatted one line per entry.
    ///
    /// `maxAge` bounds the lookback window. Default 30 minutes covers
    /// "what just happened before the user opened the Logs view" while
    /// keeping the providerMessage payload small enough to round-trip
    /// comfortably (typical density is ~5-50 entries/min, so 30 min
    /// ≈ 150-1500 lines ≈ tens of KB).
    ///
    /// Subsystems queried: `com.vkturnproxy.tunnel` (extension Swift +
    /// extension Go via cgo bridge, plus the main app's brief Go
    /// usage in pre-bootstrap captcha probe) and `com.vkturnproxy.app`
    /// (main app Swift). The OR predicate matches entries from either.
    ///
    /// Returns "" on any error or if OSLogStore is unavailable.
    static func readOwnLogs(maxAge: TimeInterval = 1800) -> String {
        do {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            let position = store.position(date: Date(timeIntervalSinceNow: -maxAge))
            let predicate = NSPredicate(
                format: "subsystem == %@ OR subsystem == %@",
                "com.vkturnproxy.tunnel",
                "com.vkturnproxy.app"
            )
            let entries = try store.getEntries(at: position, matching: predicate)

            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
            formatter.locale = Locale(identifier: "en_US_POSIX")

            // Tag by PROCESS, not by subsystem. The store we just opened is
            // scoped to .currentProcessIdentifier, so every entry in it belongs
            // to whoever called this — the main app when LogsView reads its own
            // logs, the extension when it answers get_logs.
            //
            // Tagging by subsystem was actively misleading: the Go bridge
            // hardcodes the `com.vkturnproxy.tunnel` subsystem in WHICHEVER
            // process loads it, and the main app links the same xcframework for
            // the pre-bootstrap VK probe. So the app's own `wgProbeVKCreds` /
            // `vkcalls:` lines were being labelled "[Tunnel]", and a reader
            // (twice, including us, 2026-07-25) concluded the extension was
            // alive and talking when it was not — which matters most on exactly
            // the builds where the extension is unreachable and every line in
            // the export is in fact the app's.
            let processTag = Bundle.main.bundlePath.hasSuffix(".appex") ? "[Tunnel] " : "[App] "
            var out = ""
            out.reserveCapacity(64 * 1024)
            for entry in entries {
                guard let logEntry = entry as? OSLogEntryLog else { continue }
                let ts = formatter.string(from: logEntry.date)
                // Go-side entries keep their own "[Go] HH:mm:ss.SSSSSS" prefix
                // AFTER the process tag rather than instead of it: the Go
                // library runs in both processes, so "[Go]" alone never said
                // which one produced the line.
                out += "[\(ts)] \(processTag)\(logEntry.composedMessage)\n"
            }
            return out
        } catch {
            return ""
        }
    }
}
