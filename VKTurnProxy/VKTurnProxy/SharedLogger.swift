import Foundation
import os.log

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
            // Every file-backed log line from here on is a no-op, so say WHY
            // exactly once, through the one channel that still works: os_log.
            // That is what the Logs screen falls back to reading, and what
            // idevicesyslog shows. Entitlements are parsed only on this path —
            // a correctly signed build never pays for it.
            Self.logAppGroupFailure()
        }
    }

    /// Emit the App-Group diagnosis to this process's os_log subsystem.
    private static func logAppGroupFailure() {
        let who = Bundle.main.bundlePath.hasSuffix(".appex") ? "extension" : "main app"
        logDiagnostic("App Group unavailable to \(who). "
                    + AppEntitlements.appGroupDiagnosis(required: "group.com.vkturnproxy.app"),
                      category: "AppGroup")
    }

    /// Write a diagnostic that must survive an unusable App Group: straight to
    /// this process's os_log (which the Logs screen falls back to reading, and
    /// which `idevicesyslog` shows) plus the shared file when there is one.
    ///
    /// The subsystem is picked per process so the Logs view tags it correctly:
    /// the Go bridge hardcodes the `.tunnel` subsystem in whatever process
    /// loads it, which is why main-app lines historically showed up labelled
    /// "[Tunnel]" and misled us into thinking the extension was talking.
    static func logDiagnostic(_ text: String, category: String) {
        let isExtension = Bundle.main.bundlePath.hasSuffix(".appex")
        let log = OSLog(subsystem: isExtension ? "com.vkturnproxy.tunnel" : "com.vkturnproxy.app",
                        category: category)
        for line in text.split(separator: "\n") {
            os_log("%{public}s", log: log, type: .error, String(line))
        }
        NSLog("[%@] %@", category, text)
        // Deliberately does NOT touch `shared`: logAppGroupFailure() calls this
        // from inside init(), and re-entering a `static let` initializer while
        // it is running is undefined behaviour. Everything routed here is a
        // failure the shared file cannot record anyway.
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

    /// Neutralize an untrusted value before it is interpolated into a log line:
    /// strip ASCII control characters (CR/LF/etc. that could forge additional
    /// log lines) plus DEL, and cap the length. Used for network-supplied
    /// fields such as the WiFi SSID that end up in the exportable vpn.log.
    static func sanitizeField(_ s: String, maxLength: Int = 128) -> String {
        var out = s.filter { ch in
            !ch.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7f }
        }
        if out.count > maxLength {
            out = String(out.prefix(maxLength)) + "…"
        }
        return out
    }

    /// Append raw data (used by Go bridge for already-timestamped log lines).
    func logRaw(_ data: Data) {
        guard let url = fileURL else { return }
        queue.async { [self] in
            appendData(data, to: url)
        }
    }

    /// What a read of the log actually found.
    ///
    /// `text` ALWAYS decodes — an invalid byte sequence becomes U+FFFD instead
    /// of throwing the file away — and `repairedSequences` says how many there
    /// were, which is the evidence that names the writer that corrupted it.
    struct Snapshot {
        let text: String
        let bytesOnDisk: Int        // archive + current; -1 when there is no container
        let repairedSequences: Int
    }

    /// Read the full log: archived rotation first, then current — so
    /// the consumer sees a single chronological stream.
    ///
    /// 🚨 DECODED LENIENTLY, AND THAT IS THE WHOLE POINT OF THIS FUNCTION.
    /// It used to be `(try? String(contentsOf:encoding:.utf8)) ?? ""`, which
    /// throws on the FIRST invalid byte anywhere in the file — so ONE clobbered
    /// character turned an 829 KB log into `""`, the Logs screen reported
    /// "(log is empty — waiting for new activity)" while the file kept growing,
    /// and Share exported an empty file (2026-08-20, device). It survived app
    /// restarts and disconnect/reconnect because nothing about the file changed.
    /// Measured: 848 891 bytes with a single 0xFF inserted read as
    /// NSCocoaErrorDomain 259; the same bytes decoded leniently give every line
    /// back plus one U+FFFD.
    /// 🎯 **A log reader must degrade one character at a time, never all at
    /// once** — it is the instrument you reach for when something else is
    /// already broken.
    func readLogs() -> String { readSnapshot().text }

    func readSnapshot() -> Snapshot {
        guard let url = fileURL else {
            return Snapshot(text: "", bytesOnDisk: -1, repairedSequences: 0)
        }
        return SharedLogger.decode(
            archive: (try? Data(contentsOf: rotatedURL(for: url))) ?? Data(),
            current: (try? Data(contentsOf: url)) ?? Data()
        )
    }

    /// How many byte sequences in `data` are not valid UTF-8 — i.e. how many
    /// U+FFFD the lenient decode had to invent. Pure, so the harness can drive
    /// it with bytes it builds itself.
    static func invalidSequences(in data: Data) -> Int {
        var iterator = data.makeIterator()
        var codec = UTF8()
        var count = 0
        decoding: while true {
            switch codec.decode(&iterator) {
            case .scalarValue:
                continue
            case .emptyInput:
                break decoding
            case .error:
                count += 1
            }
        }
        return count
    }

    /// The decoding rule, as a PURE function over bytes.
    ///
    /// Extracted so it can be tested without an App Group container: inline in
    /// the file read, the only apparent way to reach it was to have a container
    /// and a corrupted file on disk — the same shape that once made an id-lookup
    /// test stand up an HTTP server to reach a rule that needed none.
    static func decode(archive: Data, current: Data) -> Snapshot {
        // Decoded SEPARATELY: they are two files, so a byte sequence never
        // straddles the boundary and one corrupt archive cannot shift the
        // current file's decoding.
        let text = String(decoding: archive, as: UTF8.self)
            + String(decoding: current, as: UTF8.self)
        // 🚨 COUNTED FROM THE BYTES, NOT FROM THE TEXT. Counting U+FFFD in the
        // decoded string cannot tell a sequence WE repaired from one that was
        // legitimately in the file — and since build 336 the Go side writes
        // U+FFFD deliberately, as its marker for remote text it had to repair
        // before logging. A healthy log now contains that scalar, so the
        // text-side count would report corruption on a perfectly good file and
        // the banner would accuse a writer of overwriting nothing.
        let repaired = SharedLogger.invalidSequences(in: archive)
            + SharedLogger.invalidSequences(in: current)
        return Snapshot(text: text,
                        bytesOnDisk: archive.count + current.count,
                        repairedSequences: repaired)
    }

    /// Diagnostic snapshot of the log-file storage state. Used by the
    /// LogsView fallback path to surface an accurate reason when
    /// readLogs returned empty: was the App Group container unavailable
    /// (no entitlement / wrong provisioning), or did the file just not
    /// exist yet (fresh install or the user just hit Clear), or did it
    /// exist but with zero bytes? The previous code conflated all three
    /// into a single misleading "App Group container unavailable"
    /// banner.
    struct StorageStatus {
        let hasContainer: Bool
        let containerPath: String   // empty if hasContainer == false
        let currentExists: Bool
        let currentBytes: Int       // -1 if currentExists == false
        let archivedExists: Bool
        let archivedBytes: Int      // -1 if archivedExists == false
    }

    func inspectStorage() -> StorageStatus {
        guard let url = fileURL else {
            return StorageStatus(
                hasContainer: false, containerPath: "",
                currentExists: false, currentBytes: -1,
                archivedExists: false, archivedBytes: -1
            )
        }
        let containerPath = url.deletingLastPathComponent().path
        let fm = FileManager.default

        let currentExists = fm.fileExists(atPath: url.path)
        var currentBytes = -1
        if currentExists, let attrs = try? fm.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? Int {
            currentBytes = size
        }

        let archive = rotatedURL(for: url)
        let archivedExists = fm.fileExists(atPath: archive.path)
        var archivedBytes = -1
        if archivedExists, let attrs = try? fm.attributesOfItem(atPath: archive.path),
           let size = attrs[.size] as? Int {
            archivedBytes = size
        }

        return StorageStatus(
            hasContainer: true, containerPath: containerPath,
            currentExists: currentExists, currentBytes: currentBytes,
            archivedExists: archivedExists, archivedBytes: archivedBytes
        )
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

    /// URL of the live log file. Used by the Go bridge as the write
    /// target — must point at the SAME file appendData writes to (i.e.
    /// the current, non-archived one), so do NOT use this for export.
    var logFileURL: URL? { fileURL }

    /// Absolute path string (for passing to Go bridge).
    var logFilePath: String? { fileURL?.path }

    /// Build a single-file snapshot containing archive (.1) + current
    /// log, suitable for Share-sheet export. Returns the URL of a temp
    /// file owned by the app's tmp directory; iOS reaps tmp files
    /// automatically, no cleanup needed by the caller. Synchronous —
    /// called from the UI thread when the user taps Share.
    ///
    /// Without this, Share-sheet sent ONLY the current vpn.log and
    /// silently dropped vpn.log.1, hiding however-many hours of
    /// pre-rotation history the archive still held.
    ///
    /// queue.sync barrier: flushes pending writes from the logger
    /// queue before reading. Without it, events that happened in the
    /// last fraction of a second before Share was tapped (typically
    /// disconnect-related lines from a "Disconnect → Share" flow) sat
    /// in the queue and didn't make it into the exported snapshot.
    /// The queue is serial, so an empty sync block runs after every
    /// previously-queued write has finished. Safe because this method
    /// is called from the UI thread, never from inside the queue
    /// itself — no risk of deadlock.
    func exportSnapshotURL() -> URL? {
        guard let url = fileURL else { return nil }
        queue.sync {} // flush pending appendData writes
        // 🚨 Export the RAW BYTES, not a decoded-and-re-encoded copy. If the
        // file holds a corrupted sequence, this export is the only way to see
        // it off-device, and re-encoding would silently replace the evidence
        // with U+FFFD before anyone could look at it.
        var combined = (try? Data(contentsOf: rotatedURL(for: url))) ?? Data()
        combined.append((try? Data(contentsOf: url)) ?? Data())
        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("vpn-export.log")
        try? combined.write(to: dst, options: .atomic)
        return FileManager.default.fileExists(atPath: dst.path) ? dst : url
    }

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

        // 🚨 O_APPEND, NOT seek-then-write. The EXTENSION's Go writer holds its
        // own fd on this same file (`bridge.go` startLogWriter, O_APPEND), so
        // "seek to the end, then write there" races it: Go appends between our
        // seek and our write, and we then write at the STALE offset,
        // OVERWRITING the line Go just appended. Two consequences, both real —
        // the extension's line is silently LOST, and if our write ends inside a
        // multi-byte character the file stops being valid UTF-8, which is what
        // made the Logs screen read empty over an 829 KB file (2026-08-20).
        // Demonstrated by clobbering one line at 60 different write lengths: 4
        // of them left the file undecodable.
        // O_APPEND makes "seek to end" and "write" ONE atomic step for writes
        // up to PIPE_BUF, and every log line is far below it.
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o644)
        guard fd >= 0 else { return }
        defer { close(fd) }
        data.withUnsafeBytes { raw in
            guard var p = raw.baseAddress else { return }
            var left = raw.count
            while left > 0 {
                let n = write(fd, p, left)
                if n > 0 {
                    p = p.advanced(by: n)
                    left -= n
                } else if n < 0 && errno == EINTR {
                    continue        // interrupted before any byte moved
                } else {
                    break           // real error: drop the line rather than spin
                }
            }
        }
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
