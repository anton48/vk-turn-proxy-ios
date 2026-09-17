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
// The second half of the same rule is below: AuthModeCacheGuard. A reset that
// FAILED is not a reset — the caches are still on disk and the extension
// loads them whatever the mode — so the guard blocks the connect and keeps
// the mode marker where it was.
//
// Foundation-only, so the harness can run both on scratch directories.

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
    /// untouched. A file that was already gone is success (idempotent) — but
    /// ONLY on a confirmed "no such file" from the removal itself.
    ///
    /// 🚨 Absence is never inferred from `fileExists`: it answers false when
    /// the path cannot be EXAMINED too (a directory without search permission),
    /// so a permission failure would read as "already absent" with both files
    /// still on disk; and a check made before the removal says nothing about a
    /// file that appeared in between. Every error that is not ENOENT is a
    /// survivor and goes to `failed`.
    static func reset(in directory: URL, fileManager: FileManager = .default) -> ResetResult {
        var result = ResetResult()
        for name in names {
            let url = directory.appendingPathComponent(name)
            do {
                try fileManager.removeItem(at: url)
                result.deleted.append(name)
            } catch {
                if isNoSuchFile(error) {
                    result.absent.append(name)
                } else {
                    result.failed[name] = error.localizedDescription
                }
            }
        }
        return result
    }

    /// A removal's error that CONFIRMS the file is not there: ENOENT, as POSIX
    /// says it or as Foundation translates it. Nothing else qualifies — not a
    /// permission error, not an unknown one.
    static func isNoSuchFile(_ error: Error) -> Bool {
        let e = error as NSError
        if e.domain == NSPOSIXErrorDomain { return e.code == Int(ENOENT) }
        if e.domain == NSCocoaErrorDomain {
            return e.code == NSFileNoSuchFileError || e.code == NSFileReadNoSuchFileError
        }
        return false
    }
}

/// The auth-mode guard's decision, as a value: what happens to the caches and
/// to the stored marker when a connect's auth mode (anonymous vs VKAuth cookie)
/// differs from the last connect's.
///
/// The marker means "the caches on disk belong to THIS mode". It may move to
/// the new mode only once the old mode's caches are verifiably gone. A reset
/// that failed leaves them on disk; the extension loads its cache whatever the
/// mode is (the Go pool took a cached cookie-mode identity in preference to a
/// fresh anonymous seed); and a marker already moved would make the NEXT
/// attempt skip the clear altogether. So a failed reset BLOCKS the connect and
/// leaves the marker where it was — the next attempt tries the clear again.
enum AuthModeCacheGuard {
    enum Outcome: Equatable {
        /// The same mode as the last connect, or no record of one: nothing to clear.
        case unchanged
        /// The mode changed and every cache file is gone.
        case cleared
        /// The mode changed and a cache file SURVIVED: this connect must not start.
        case blocked(reason: String)
    }

    struct Decision: Equatable {
        let outcome: Outcome
        /// The marker to store; nil = leave the stored one untouched.
        let marker: String?
    }

    static func run(last: String?, current: String, reset: () throws -> Void) -> Decision {
        guard let last, last != current else {
            return Decision(outcome: .unchanged, marker: current)
        }
        do {
            try reset()
            return Decision(outcome: .cleared, marker: current)
        } catch {
            return Decision(outcome: .blocked(reason: blockedReason(from: last, to: current, error: error)), marker: nil)
        }
    }

    static func blockedReason(from last: String, to current: String, error: Error) -> String {
        "The TURN credentials cached in \(label(last)) mode could not be deleted (\(error.localizedDescription)). "
            + "Not connecting: the tunnel would reuse them in \(label(current)) mode. "
            + "Try Settings → Reset TURN Cache, then Connect again."
    }

    private static func label(_ mode: String) -> String {
        mode == "cookie" ? "VK-account (cookie)" : "anonymous"
    }
}
