// TurnCacheFiles.swift
//
// The on-disk TURN credential caches, as ONE list.
//
// The extension keeps two: the native transports' pool writes creds-pool.json
// and csqtt's standalone pool writes creds-pool-csqtt.json (WireGuardBridge —
// bridge.go and csqtt_bridge.go; two pool objects living in one reused
// extension process each save whole snapshots, so they do not share a file).
// Same schema, same kind of data. Every app-side action that means "forget the
// cached credentials" has to reach BOTH:
//
//   • Reset TURN Cache in Settings, and
//   • the auth-mode change (anonymous ↔ VKAuth cookie) before a connect: a
//     burner credential surviving in EITHER file is loaded by the next session
//     of that transport, and in an anonymous session it deanonymises it — the
//     okcdn user-id IS the burner account.
//
// A reset that names one file is therefore a privacy defect for the other
// transport, not an untidiness — which is why the list lives here, once, and
// the names are pinned against the Go side by tools/swiftcheck.
//
// Foundation-only, so the harness can run it on a scratch directory.

import Foundation

enum TurnCacheFiles {
    /// Every cache file the extension may write, by the names the Go side uses.
    static let names = ["creds-pool.json", "creds-pool-csqtt.json"]

    struct ResetResult: Equatable {
        var deleted: [String] = []
        var absent: [String] = []
        /// name → the error's text. Non-empty means the file is STILL THERE.
        var failed: [String: String] = [:]
    }

    /// Deletes every cache file in `directory`. EVERY file is attempted even
    /// when one fails: after an auth-mode change the point is that no file
    /// survives, and stopping at the first error would leave the next one
    /// untouched. The post-condition is "the file does not exist", so a file
    /// that was already gone is success (idempotent), whatever error the
    /// removal reported for it.
    static func reset(in directory: URL, fileManager: FileManager = .default) -> ResetResult {
        var result = ResetResult()
        for name in names {
            let url = directory.appendingPathComponent(name)
            let existed = fileManager.fileExists(atPath: url.path)
            do {
                try fileManager.removeItem(at: url)
                result.deleted.append(name)
            } catch {
                if !existed || !fileManager.fileExists(atPath: url.path) {
                    result.absent.append(name)
                } else {
                    result.failed[name] = error.localizedDescription
                }
            }
        }
        return result
    }
}
