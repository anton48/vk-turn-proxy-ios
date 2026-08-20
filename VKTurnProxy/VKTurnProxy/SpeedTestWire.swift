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
    var impliedSec: Double = 0
    var consistent: Bool = false
    var connsUsed: Int = 0
    var dials: Int = 0
    var backlogBytes: Int64 = 0
    var confirmedRatio: Double = 0
    var warnings: [String]?

    enum CodingKeys: String, CodingKey {
        case libraryMbps = "library_mbps"
        case rawMbps = "raw_mbps"
        case bytes
        case actualSec = "actual_sec"
        case warmupSec = "warmup_sec"
        case windowSec = "window_sec"
        case impliedSec = "implied_sec"
        case consistent
        case connsUsed = "conns_used"
        case dials
        case backlogBytes = "backlog_bytes"
        case confirmedRatio = "confirmed_ratio"
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
