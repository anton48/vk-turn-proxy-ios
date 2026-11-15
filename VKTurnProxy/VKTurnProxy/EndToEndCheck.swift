// EndToEndCheck.swift
//
// Does the internet ANSWER through the tunnel? The extension asks once a minute
// of its awake time and says the answer in the log as ONE line:
//
//   end to end: tcp 1.1.1.1:443 answered in 63ms; tls gateway.icloud.com:443
//   answered in 412ms (dns 31ms, tcp 70ms, tls 190ms); udp dns answered in 48ms
//
// Why it exists: on a csqtt 2.5 tunnel over a cellular path the requests of
// iOS's own daemons were found timing out for hours while every stream of the
// tunnel read ready and heard (two phones in one night, 2026-11-15). A
// transport's liveness asks the transport's SERVER; it says nothing of what
// lies behind that server. This asks the far side.
//
// Three questions, because they fail apart:
//   tcp — a TCP connect to a public ADDRESS: no name to resolve, three packets;
//   tls — a name lookup, a TCP connect and a TLS handshake with a public host:
//         what a daemon's request needs before it can be sent, and a reply of
//         several full-size packets;
//   udp — one DNS question over UDP to the tunnel's own resolver.
//
// 🚨 A round the phone went to sleep under has NO verdict. It is cut, counted,
// and the count is said by the next line that completes — never «no answer»: a
// process that did not run heard nothing for a reason of its own.
// 🚨 Behind a sleep() NO round begins before wake(). The timer's tick reaches
// the check by a hop through another queue, so a tick that fired before the
// sleep can arrive behind it — and a round begun then has nobody left to cut it.
// 🚨 A round the routes change under has no verdict either: DIRECT mode takes
// the default route out of the tunnel, and what a connection met in between is
// the change, not the tunnel. It is dropped where the re-apply BEGINS, not at
// the next minute's tick.
// (EndToEndDesk below keeps these rules; the sockets only follow it.)
// 🚨 The line carries state words and numeric codes, never an error's text.
// 🚨 The period is AWAKE time: the timer's clock stands still while the phone
// sleeps, so a sleeping night has a round now and then and an awake stretch has
// one a minute.
//
// Foundation only, so tools/swiftcheck RUNS it. The sockets are EndToEndProber's
// (PacketTunnel/), which makes every one of them through the tunnel's interface.

import Foundation

enum EndToEndCheck {
    /// The questions of a round, in the line's order.
    enum Probe: Int, CaseIterable {
        case tcp, tls, udp
    }

    static let tcpHost = "1.1.1.1"
    static let tlsHost = "gateway.icloud.com"
    static let port: UInt16 = 443

    /// Between two rounds, in the extension's awake time.
    static let period: TimeInterval = 60
    /// How long a round waits for its answers.
    static let patience: TimeInterval = 10

    enum Outcome: Equatable {
        /// `detail` is the stretches of the set-up when the system reports them, or "".
        case answered(milliseconds: Int, detail: String)
        /// `state` is where the question stood: a state word and a numeric code.
        case unanswered(state: String)
        case notAsked(why: String)
    }

    static func label(_ probe: Probe) -> String {
        switch probe {
        case .tcp: return "tcp \(tcpHost):\(port)"
        case .tls: return "tls \(tlsHost):\(port)"
        case .udp: return "udp dns"
        }
    }

    /// The one line of a round. A question with no outcome reads as unanswered.
    static func line(_ results: [Probe: Outcome], cutBefore: Int) -> String {
        var parts: [String] = []
        for probe in Probe.allCases {
            let what = label(probe)
            switch results[probe] ?? .unanswered(state: "no word") {
            case .answered(let ms, let detail):
                parts.append("\(what) answered in \(ms)ms" + (detail.isEmpty ? "" : " (\(detail))"))
            case .unanswered(let state):
                parts.append("\(what) NO ANSWER in \(Int(patience))s (\(state))")
            case .notAsked(let why):
                parts.append("\(what) not asked (\(why))")
            }
        }
        var text = "end to end: " + parts.joined(separator: "; ")
        if cutBefore > 0 {
            text += " — \(cutBefore) round(s) before it cut by a sleep"
        }
        return text
    }

    /// The line that says why no round is asked at all.
    static func skipLine(_ why: String) -> String {
        "end to end: not asked — \(why)"
    }

    /// The line of a round that ended without a verdict while the process ran
    /// (a sleep's cut says nothing at the time — it is counted for the next line).
    static func droppedLine(_ why: String) -> String {
        "end to end: a round under way dropped without a verdict — \(why)"
    }

    /// Why nothing is asked between a sleep() and its wake().
    static let asleepWhy = "sleep() was called and no wake() since"
    /// Why a round under way is dropped when DIRECT mode is switched.
    static let routesWhy = "the routes are being re-applied"

    /// Whole milliseconds between two readings of one clock in nanoseconds; a
    /// reading that went backwards is zero.
    static func milliseconds(from: UInt64, to: UInt64) -> Int {
        to > from ? Int((to - from) / 1_000_000) : 0
    }

    /// The first server of the tunnel's DNS setting ("a, b"), or nil.
    static func firstResolver(_ list: String) -> String? {
        list.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty }
    }

    /// One standard question for `name`'s A record, recursion desired. Nil for a
    /// name that is not one (an empty label, a label over 63 bytes, over 253 in all).
    static func dnsQuestion(id: UInt16, name: String) -> Data? {
        guard !name.isEmpty, name.utf8.count <= 253 else { return nil }
        var packet = Data([UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = Array(label.utf8)
            guard (1...63).contains(bytes.count) else { return nil }
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(contentsOf: [0, 0, 1, 0, 1])
        return packet
    }

    /// Is `data` a RESPONSE to the question `id`? Any response code counts — the
    /// resolver spoke; the question come back unchanged does not.
    static func dnsAnswers(_ data: Data, id: UInt16) -> Bool {
        let head = [UInt8](data.prefix(12))
        guard head.count == 12 else { return false }
        return head[0] == UInt8(id >> 8) && head[1] == UInt8(id & 0xff) && head[2] & 0x80 != 0
    }
}

/// One round's bookkeeping: the first outcome of each question stands, the
/// round speaks ONCE — when its last question is answered or its patience is
/// over — and a round a sleep cut never speaks.
final class EndToEndRound {
    private let lock = NSLock()
    private var results: [EndToEndCheck.Probe: EndToEndCheck.Outcome] = [:]
    private var closed = false
    private let cutBefore: Int

    init(cutBefore: Int) {
        self.cutBefore = cutBefore
    }

    /// Records an outcome; the line when it was the last one missing.
    func note(_ probe: EndToEndCheck.Probe, _ outcome: EndToEndCheck.Outcome) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard !closed, results[probe] == nil else { return nil }
        results[probe] = outcome
        guard results.count == EndToEndCheck.Probe.allCases.count else { return nil }
        closed = true
        return EndToEndCheck.line(results, cutBefore: cutBefore)
    }

    /// The patience is over: what is still open is unanswered, with the state it
    /// stood in. The line, unless the round has spoken or was cut.
    func expire(_ states: [EndToEndCheck.Probe: String]) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return nil }
        closed = true
        for probe in EndToEndCheck.Probe.allCases where results[probe] == nil {
            results[probe] = .unanswered(state: states[probe] ?? "no word")
        }
        return EndToEndCheck.line(results, cutBefore: cutBefore)
    }

    /// A sleep: the round ends without a verdict. True when it was still open.
    func cut() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return false }
        closed = true
        return true
    }
}

/// WHEN a round may begin and what ends one without a verdict — the check's
/// bookkeeping between rounds. The prober owns one and only follows it: its
/// sockets live exactly as long as `round` is there.
///
/// Not thread-safe on purpose: every call comes from its owner's ONE serial
/// queue, in the order the events were handed to that queue. That order is the
/// guarantee — a sleep() handed over before a late tick is seen before it.
final class EndToEndDesk {
    /// The round under way, or nil.
    private(set) var round: EndToEndRound?
    /// Rounds a sleep cut since the last line that completed.
    private var cutBySleep = 0
    private var saidSkip: String?
    /// Between sleep() and wake(): no round begins.
    private var asleep = false
    private var saidAsleep = false
    private var stopped = false

    /// A tick: the round to ask — or none, with the line to say if there is one.
    func begin() -> (round: EndToEndRound?, say: String?) {
        guard !stopped, round == nil else { return (nil, nil) }
        if asleep {
            // Said once a sleep: a wake() that never comes must not read as a
            // check that simply went quiet.
            guard !saidAsleep else { return (nil, nil) }
            saidAsleep = true
            return (nil, EndToEndCheck.skipLine(EndToEndCheck.asleepWhy))
        }
        saidSkip = nil
        let fresh = EndToEndRound(cutBefore: cutBySleep)
        round = fresh
        return (fresh, nil)
    }

    /// Nothing is asked this minute. A round still under way ends without a
    /// verdict — what it would say is no longer about the tunnel. The lines to
    /// say; the reason itself once, until a round runs again.
    func skip(_ why: String) -> [String] {
        guard !stopped else { return [] }
        var lines: [String] = []
        if drop() { lines.append(EndToEndCheck.droppedLine(why)) }
        if saidSkip != why {
            saidSkip = why
            lines.append(EndToEndCheck.skipLine(why))
        }
        return lines
    }

    /// sleep(): the round under way ends without a verdict and is counted, and
    /// none begins until woke().
    func slept() {
        if drop() { cutBySleep += 1 }
        asleep = true
    }

    /// wake(): rounds may begin again.
    func woke() {
        asleep = false
        saidAsleep = false
    }

    /// The routes are about to be re-applied. The line to say when a round was
    /// under way.
    func routesChanging() -> String? {
        drop() ? EndToEndCheck.droppedLine(EndToEndCheck.routesWhy) : nil
    }

    /// stopTunnel: no more rounds, no line from the one under way.
    func stop() {
        stopped = true
        _ = drop()
    }

    /// An outcome of one of `current`'s questions; the round's line when it was
    /// the last one missing. A round that is no longer the one under way was
    /// cut when it left (drop) and says nothing — that is the round's own rule.
    func note(_ current: EndToEndRound, _ probe: EndToEndCheck.Probe, _ outcome: EndToEndCheck.Outcome) -> String? {
        current.note(probe, outcome).map(spoke)
    }

    /// `current`'s patience is over; its line — nothing for a round that was cut.
    func expire(_ current: EndToEndRound, _ states: [EndToEndCheck.Probe: String]) -> String? {
        current.expire(states).map(spoke)
    }

    private func spoke(_ line: String) -> String {
        round = nil
        cutBySleep = 0
        return line
    }

    /// Ends the round under way without a verdict. True when there was one.
    private func drop() -> Bool {
        guard let open = round else { return false }
        round = nil
        return open.cut()
    }
}
