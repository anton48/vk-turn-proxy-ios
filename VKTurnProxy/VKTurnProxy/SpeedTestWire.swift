import Foundation

// MARK: - Wire types (mirror pkg/speedtest's JSON exactly)
//
// 🚨 THE CONTRACT IS ASYMMETRIC, and getting it backwards bricks the screen:
//
//   - a field Go sends that Swift does not decode is SILENT and safe (unknown
//     keys are dropped);
//   - a non-Optional CodingKey for a field Go does NOT send is FATAL. The
//     synthesized decoder THROWS — memberwise defaults do not rescue a missing
//     key — `poll()` swallows it, and the screen sits at "running" for ever with
//     the Run button never coming back.
//
// ⇒ Go-side field additions may land ahead of their Swift keys; Swift keys may
// never land ahead of the Go field, and a Go change means rebuilding the
// xcframework BEFORE the Swift half. Anything optional on the wire must be
// Optional here.

struct SpeedTestPhase: Codable {
    var libraryMbps: Double = 0
    var rawMbps: Double = 0
    var bytes: Int64 = 0
    var actualSec: Double = 0
    var warmupSec: Double = 0
    var windowSec: Double = 0
    /// What rawMbps was computed from. `bytes` is the WHOLE phase, warm-up
    /// included, so in research mode these differ and only this one checks out
    /// against the rate.
    var windowBytes: Int64 = 0
    var impliedSec: Double = 0
    var consistent: Bool = false
    var connsUsed: Int = 0
    var dials: Int = 0
    var backlogBytes: Int64 = 0
    var confirmedRatio: Double = 0
    /// Whether a ratio was MEASURED at all. 🚨 Zero is a real answer here — it
    /// is the Frankfurt-307 answer — so presence cannot be inferred from the
    /// value being non-zero.
    var confirmedKnown: Bool = false
    /// The DELIBERATE part of the tail: the engine is given a deadline slightly
    /// later than the window so the two do not race, and it keeps pushing for
    /// that long after the window closed.
    var guardSec: Double = 0
    /// Time between the ENGINE'S OWN deadline and its return — blocked workers
    /// unwinding. It used to be counted inside the window (a "fixed 30s" arm
    /// came back as 35.0s), and then it briefly contained the guard as well,
    /// which reported a constant we chose as the engine being slow.
    var cleanupSec: Double = 0
    /// How much of the backlog a NORMAL end of phase explains: one in-flight
    /// chunk per worker, cancelled when the capture time expires. Travels with
    /// the phase so the line can qualify its own backlog instead of leaving it
    /// to read as bytes the server refused.
    var backlogTailBytes: Int64 = 0
    var warnings: [String]?

    enum CodingKeys: String, CodingKey {
        case libraryMbps = "library_mbps"
        case rawMbps = "raw_mbps"
        case bytes
        case actualSec = "actual_sec"
        case warmupSec = "warmup_sec"
        case windowSec = "window_sec"
        case windowBytes = "window_bytes"
        case impliedSec = "implied_sec"
        case consistent
        case connsUsed = "conns_used"
        case dials
        case backlogBytes = "backlog_bytes"
        case confirmedRatio = "confirmed_ratio"
        case confirmedKnown = "confirmed_known"
        case guardSec = "guard_sec"
        case cleanupSec = "cleanup_sec"
        case backlogTailBytes = "backlog_tail_bytes"
        case warnings
    }

    var moved: Bool { bytes > 0 }
}

struct SpeedTestProgress: Codable {
    var state: String = "idle"
    var stage: String = ""
    var error: String?
    var serverID: String = ""
    var serverDesc: String = ""
    var serverURL: String = ""
    var ooklaSeesIP: String = ""
    var ooklaSeesISP: String = ""
    var pingMs: Double = 0
    var threads: Int = 0
    var requestedSec: Int = 0
    var direction: String = ""
    var mode: String = ""

    /// Optional, because Go OMITS a direction that did not run. As values they
    /// were always present, so a download-only run carried a complete upload
    /// object of zeros — indistinguishable from a measured 0.0 Mbit/s by anyone
    /// who rendered what they were given.
    var download: SpeedTestPhase?
    var upload: SpeedTestPhase?

    var engine: String = ""
    var estimator: String = ""

    enum CodingKeys: String, CodingKey {
        case state, stage, error, threads, engine, estimator, direction, mode
        case serverID = "server_id"
        case serverDesc = "server_desc"
        case serverURL = "server_url"
        case ooklaSeesIP = "ookla_sees_ip"
        case ooklaSeesISP = "ookla_sees_isp"
        case pingMs = "ping_ms"
        case requestedSec = "requested_sec"
        case download, upload
    }
}
