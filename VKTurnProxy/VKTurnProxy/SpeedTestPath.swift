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

/// One observation of the route, with the instant it was made.
///
/// The route is piecewise constant, so an observation means *from `at` onward
/// the route was `path`, until the next observation says otherwise*.
struct SpeedTestPathObservation: Equatable {
    let at: Date
    let path: SpeedTestPath
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

    /// Builds the trace for ONE interval: the route in force when it opened,
    /// plus every change inside it.
    ///
    /// 🚨 THE INTERVAL IS THE MEASUREMENT WINDOW, NOT THE RUN. The trace used to
    /// cover everything from the Run tap to the terminal poll being processed,
    /// which is wider than the measurement at both ends — so flipping the VPN
    /// after the window had closed, while the engine was still unwinding,
    /// condemned a result that was already complete. `PATH CHANGED` has to mean
    /// *the route moved during the interval whose bytes produced this rate*.
    ///
    /// 🚫 And "just don't record on the terminal poll" is NOT the same fix: it
    /// leaves the gap between the last running poll and the window's real close
    /// unobserved, so a change in there would still be missed — in the direction
    /// that hides a real defect rather than inventing one.
    ///
    /// ⚖️ Deliberately INCLUSIVE of the state in force at the open: that state
    /// is what the first bytes were measured on. And a change landing exactly on
    /// a boundary counts as inside — a rate cannot be attributed to a route that
    /// was replaced at the instant it started.
    static func over(_ window: ClosedRange<Date>,
                     observations: [SpeedTestPathObservation]) -> SpeedTestPathTrace {
        var trace = SpeedTestPathTrace()
        let sorted = observations.sorted { $0.at < $1.at }
        // The route in force when the window opened: the last observation at or
        // before the open. Without it a window with no change inside it would
        // have NO path at all, which reads as "path unknown" on a perfectly
        // attributable run.
        if let inForce = sorted.last(where: { $0.at <= window.lowerBound }) {
            trace.record(inForce.path)
        }
        for o in sorted where o.at > window.lowerBound && o.at <= window.upperBound {
            trace.record(o.path)
        }
        return trace
    }


    /// The trace over the measurement window(s) the ENGINE reported, rather than
    /// over the run.
    ///
    /// 🚨 It lives here, on the type, and not on the runner: the runner cannot be
    /// compiled without the bridge, so a rule kept there is reachable only
    /// through a live poll timer — and this project has twice ended up testing a
    /// COPY of a rule for exactly that reason.
    ///
    /// 🚨 PER PHASE, NOT OVER THEIR UNION. Spanning the first open to the last
    /// close also covers the gap between the phases — time nothing is measured
    /// in — so a DIRECT round trip that starts and ENDS inside that gap flagged
    /// a run in which both phases were measured on the same route and neither
    /// number was touched.
    ///
    /// What matters is: was each phase's own window quiet, and did the phases
    /// agree with each other? A change that PERSISTS across the gap still shows
    /// up, because the phases then disagree — one label cannot describe two
    /// routes.
    ///
    /// ⚖️ Falls back to the wide trace when the engine reported no usable window
    /// — an errored run has no phases at all. A fallback that is WIDER errs
    /// toward flagging a result nobody can attribute, which is the safe
    /// direction; the unsafe one is silently blessing a number.
    static func overMeasurement(_ p: SpeedTestProgress,
                                observations: [SpeedTestPathObservation],
                                fallback: SpeedTestPathTrace) -> SpeedTestPathTrace {
        let windows = [p.download, p.upload].compactMap { $0 }
            .filter { $0.windowStartedAt > 0 && $0.windowClosedAt >= $0.windowStartedAt }
            .map { Date(timeIntervalSince1970: $0.windowStartedAt)...Date(timeIntervalSince1970: $0.windowClosedAt) }
        guard !windows.isEmpty else { return fallback }

        var merged = SpeedTestPathTrace()
        for w in windows {
            let t = over(w, observations: observations)
            // A phase whose own window saw a change settles it for the run.
            guard t.isAttributable, let only = t.seen.first else { return t }
            merged.record(only)
        }
        // Every phase was quiet on ONE path; the run is attributable only if
        // they were all the SAME path. Otherwise the change fell in the gap and
        // persisted, which leaves two phases on two routes.
        return merged
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
            return "PATH CHANGED DURING THE MEASUREMENT (\(names)) — this figure belongs to neither"
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
