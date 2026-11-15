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
