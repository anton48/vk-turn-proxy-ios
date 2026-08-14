import Foundation

/// Uplink duplication — the falsification test for systematic FEC over
/// WireGuard packets. The Swift side of `pkg/proxy/uplinkdup.go`; the two clamps
/// must agree, so the range lives in one place per language and Go clamps again
/// at the sink in case a malformed provider message ever reaches it.
///
/// 🚨 THIS IS NOT A PRODUCTION MODE AND CANNOT BECOME ONE. At 100% redundancy
/// the useful ceiling is half the allocation budget — N × 2.07 / 2 ≈ 31 Mbit/s
/// at N=30. It exists to answer one question before an XOR block scheme and a
/// server-side recovery path get built: if the receiver gets the EARLIEST of two
/// independent draws, does the >155 ms hole tail shrink and does throughput
/// rise? The server resequencer already showed how large that effect can be
/// (one flow 4.2 → 10.7 Mbit/s, +155%) and that a hold timer cannot collect it
/// (F=8 −36%, F=32 −42%). FEC would fill the hole without holding anything.
///
/// 🚨 THREE MODES, NOT TWO, AND THE MIDDLE ONE IS THE POINT. Duplicating over
/// two groups of 15 changes redundancy AND halves the paths each copy races. A
/// two-mode null could not tell "earliest-of-two does not help" from "each copy
/// lost half its fan-out". `singleGroup` is the width control: same 15
/// connections, one copy. The duplication effect is (dup − single), and
/// (single − off) prices the width change on its own.
enum UplinkDup {
    /// Today's behaviour: one shared queue, all N writers competing per packet.
    /// The control arm, and the value the A/B runner restores on every exit.
    static let off = 0

    /// Bulk traffic on group 0 only (the even-indexed connections) — the width
    /// control. Half the pool still carries keepalives, so nothing idles out.
    static let singleGroup = 1

    /// Every bulk packet sent twice, over two disjoint groups. The second copy
    /// is dropped by the server's WireGuard as an anti-replay duplicate, so the
    /// inner stream sees the earliest of the two.
    static let both = 2

    /// The picker's values, in the order they are offered.
    static let choices = [off, singleGroup, both]

    /// Snap an arbitrary integer to a supported value. Anything unrecognised
    /// becomes `off`: an experiment must fail CLOSED, never into an arm nobody
    /// chose.
    static func clamp(_ value: Int) -> Int {
        (value < off || value > both) ? off : value
    }

    /// What the user has chosen, already snapped. An unwritten key reads 0 =
    /// off, so the sentinel and the real default coincide.
    static func stored(in defaults: UserDefaults = .standard) -> Int {
        clamp(defaults.integer(forKey: "uplinkDupMode"))
    }

    /// Label for the picker and the settings summary.
    static func label(_ mode: Int) -> String {
        switch clamp(mode) {
        case singleGroup: return "15 paths, one copy"
        case both: return "2 × 15 paths, duplicated"
        default: return "Off (all paths)"
        }
    }

    /// The short name that appears in the log, matching `UplinkDupModeName` in
    /// Go exactly. The scorer cuts arms on it, so the two spellings are one
    /// contract — build 257 renamed a field on one side only and its own parser
    /// went blind to a session with 154 engaged ticks.
    static func logName(_ mode: Int) -> String {
        switch clamp(mode) {
        case singleGroup: return "g15"
        case both: return "dup"
        default: return "off"
        }
    }
}
