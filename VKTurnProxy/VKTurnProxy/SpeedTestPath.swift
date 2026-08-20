import Foundation

/// How a run reached the network.
///
/// Recorded with the result rather than used to refuse one: a measurement
/// without the VPN is not a spoiled measurement, it is the comparison arm people
/// reach for first. The only defect would be reporting it as VPN speed.
///
/// 🎯 THE RULE THIS FILE EXISTS TO STATE, because two nearby decisions look
/// contradictory and are not:
///
/// > **The result must describe the run. For an input the run was GIVEN, the run
/// > is its start instant. For a condition the run EXPERIENCED, the run is the
/// > whole interval.**
///
/// `direction` and `threads` are the first kind — snapshot them at start
/// (see `SpeedTestRunConfig`). The network path is the second: it can be
/// switched while a run is in flight, so sampling it once at the start records
/// something that may simply not be true of the bytes that were measured.
enum SpeedTestPath: String, Codable {
    case throughVPN = "Through VPN"
    case directMode = "DIRECT mode — outside the tunnel"
    case vpnOff = "VPN off"

    /// Pure, so the harness can test it. The caller supplies the two facts;
    /// reading them from `TunnelManager` is the view's job, not this type's.
    static func current(connected: Bool, directMode: Bool) -> SpeedTestPath {
        guard connected else { return .vpnOff }
        return directMode ? .directMode : .throughVPN
    }
}

/// Every path the run was observed on, in the order first seen.
///
/// 🚨 A run outlives the screen and can outlive the route it started on. The
/// previous version read the path once, at start, under a comment that argued
/// for exactly that — *"the tunnel can be toggled while a run is in flight, and
/// what the result must carry is how the bytes actually left"* — which is the
/// argument AGAINST reading it once. If the route flips mid-run the number
/// belongs to neither path, and the honest answer is to say so, not to pick one.
struct SpeedTestPathTrace: Equatable {
    private(set) var seen: [SpeedTestPath] = []

    init(_ first: SpeedTestPath? = nil) {
        if let first { seen = [first] }
    }

    /// Appends on any change, including a return to an earlier path — going
    /// VPN → DIRECT → VPN is two changes, not zero, and the run spanned both.
    mutating func record(_ path: SpeedTestPath) {
        if seen.last != path { seen.append(path) }
    }

    /// False when the run spanned more than one path, i.e. the figure cannot be
    /// attributed to any of them.
    var isAttributable: Bool { seen.count == 1 }

    /// What goes on the result, and it is mandatory — this is the
    /// "label it, do not refuse it" decision made visible.
    var label: String {
        switch seen.count {
        case 0: return "path unknown"
        case 1: return seen[0].rawValue
        default:
            let names = seen.map(Self.short).joined(separator: " → ")
            return "PATH CHANGED DURING THE RUN (\(names)) — this figure belongs to neither"
        }
    }

    private static func short(_ p: SpeedTestPath) -> String {
        switch p {
        case .throughVPN: return "VPN"
        case .directMode: return "DIRECT"
        case .vpnOff: return "no VPN"
        }
    }
}
