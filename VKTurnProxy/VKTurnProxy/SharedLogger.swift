import Foundation

/// Shared file logger for VPN logs.
/// Both the main app and the Network Extension write to the same file
/// in the App Group container, so logs can be viewed in-app or exported.
class SharedLogger {
    static let shared = SharedLogger()

    private let fileURL: URL?
    private let queue = DispatchQueue(label: "com.vkturnproxy.logger", qos: .utility)
    // Per-file rotation threshold. When current vpn.log exceeds this size,
    // it's renamed to vpn.log.1 (atomic move; previous .1 is discarded) and
    // a fresh vpn.log starts. Total on-disk worst case = 2 × maxFileSize.
    //
    // Was 5 MB with an in-memory "drop first half" rotation that consumed
    // ~4× file size in peak Swift String allocation — ate the extension's
    // ~50 MB memory ceiling at higher limits and dropped a chunk of every
    // night's log around 5 MB (e.g. 2026-04-29 vpn.wifi.4.log lost roughly
    // 2.5 hours overnight). With file rotation, peak memory during rotate
    // is ~0 (just FS rename) so 20 MB is safe and gives ~20 hours per file
    // at typical idle rates (~1 MB/h) plus another ~20 hours in .1.
    private let maxFileSize = 20 * 1024 * 1024 // 20 MB
    private let dateFormatter: DateFormatter

    private init() {
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")

        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.vkturnproxy.app"
        ) {
            fileURL = container.appendingPathComponent("vpn.log")
        } else {
            fileURL = nil
        }
    }

    /// Append a timestamped log line to the shared log file.
    func log(_ message: String) {
        guard let url = fileURL else { return }
        let ts = dateFormatter.string(from: Date())
        let line = "[\(ts)] \(message)\n"
        queue.async { [self] in
            appendData(line.data(using: .utf8)!, to: url)
        }
    }

    /// Append raw data (used by Go bridge for already-timestamped log lines).
    func logRaw(_ data: Data) {
        guard let url = fileURL else { return }
        queue.async { [self] in
            appendData(data, to: url)
        }
    }

    /// Read the full log: archived rotation first, then current — so
    /// the consumer sees a single chronological stream.
    func readLogs() -> String {
        guard let url = fileURL else { return "" }
        let archived = (try? String(contentsOf: rotatedURL(for: url), encoding: .utf8)) ?? ""
        let current = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        return archived + current
    }

    /// Delete all log contents (current and rotated).
    func clearLogs() {
        guard let url = fileURL else { return }
        let archive = rotatedURL(for: url)
        queue.async {
            try? Data().write(to: url)
            try? FileManager.default.removeItem(at: archive)
        }
    }

    /// URL of the log file (for sharing via UIActivityViewController).
    var logFileURL: URL? { fileURL }

    /// Absolute path string (for passing to Go bridge).
    var logFilePath: String? { fileURL?.path }

    // MARK: - Private

    private func appendData(_ data: Data, to url: URL) {
        // Rotate first (move-away if oversized) so the create/open below
        // sees the post-rotation state. The previous order
        // (create → check size → rotate) lost the FIRST write after a
        // rotation: rotate moved the file out, then FileHandle(forWriting:)
        // returned nil because the path no longer existed, and the write
        // was silently dropped until the next call's create step.
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? Int, size > maxFileSize {
            rotate(at: url)
        }

        // Create fresh empty file if missing (true after rotate, or on
        // first ever write).
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }

        guard let handle = FileHandle(forWritingAtPath: url.path) else { return }
        handle.seekToEndOfFile()
        handle.write(data)
        handle.closeFile()
    }

    /// Rotation strategy: rename current → .1 (overwriting any existing
    /// .1) and let the next write recreate the current file. Atomic FS
    /// move, no memory load. Total retained = 2 × maxFileSize on disk.
    ///
    /// The previous implementation read the whole file into a Swift
    /// String, split by newlines, kept the latter half, wrote back —
    /// quadratic in file size and ate ~4× peak memory, blowing the
    /// extension's ~50 MB ceiling at sizes above ~10 MB. File rename
    /// avoids both costs.
    private func rotate(at url: URL) {
        let archive = rotatedURL(for: url)
        try? FileManager.default.removeItem(at: archive)
        try? FileManager.default.moveItem(at: url, to: archive)
    }

    /// vpn.log → vpn.log.1 alongside it.
    private func rotatedURL(for url: URL) -> URL {
        let dir = url.deletingLastPathComponent()
        let name = url.lastPathComponent + ".1"
        return dir.appendingPathComponent(name)
    }
}
