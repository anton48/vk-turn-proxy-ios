// EndToEndProber.swift
//
// The sockets of EndToEndCheck (VKTurnProxy/EndToEndCheck.swift has the rule
// and the line; read its header first).
//
// 🚨 EVERY connection here is made THROUGH the tunnel's interface — `through()`.
// A socket the extension opens leaves by the physical network unless it is told
// otherwise (that is how the tunnel's own transport gets out), and a check that
// leaves that way answers whatever the tunnel does: it would read «answered»
// over a tunnel that carries nothing.
//
// One serial queue owns everything below: the round, its connections, the
// counter of rounds a sleep cut. A sleep's cut is queued when sleep() is called
// and so runs ahead of anything that arrives after the thaw.

import Foundation
import Network

final class EndToEndProber {
    private let queue = DispatchQueue(label: "end-to-end")
    private let interface: NWInterface
    private let resolver: String?
    private let say: (String) -> Void

    private var round: EndToEndRound?
    private var connections: [NWConnection] = []
    private var states: [EndToEndCheck.Probe: String] = [:]
    private var cutBefore = 0
    private var saidSkip: String?
    private var serial = UInt16.random(in: 1...0xfffe)
    private var stopped = false

    /// `resolver` is the tunnel's own DNS server (nil: the udp question is not asked).
    init(interface: NWInterface, resolver: String?, say: @escaping (String) -> Void) {
        self.interface = interface
        self.resolver = resolver
        self.say = say
    }

    /// The timer's tick: a new round, unless one is still open.
    func tick() {
        queue.async { self.begin() }
    }

    /// Nothing is asked this minute; the reason is said once, until a round runs again.
    func skip(_ why: String) {
        queue.async {
            guard !self.stopped, self.saidSkip != why else { return }
            self.saidSkip = why
            self.say(EndToEndCheck.skipLine(why))
        }
    }

    /// sleep(): the round under way ends without a verdict and is counted.
    func cutBySleep() {
        queue.async {
            if self.round?.cut() == true {
                self.cutBefore += 1
            }
            self.finish()
        }
    }

    /// stopTunnel: no more rounds, no line from the one under way.
    func stop() {
        queue.async {
            self.stopped = true
            _ = self.round?.cut()
            self.finish()
        }
    }

    private func through(_ parameters: NWParameters) -> NWParameters {
        parameters.requiredInterface = interface
        return parameters
    }

    private func finish() {
        connections.forEach { $0.cancel() }
        connections = []
        states = [:]
        round = nil
    }

    private func begin() {
        guard !stopped, round == nil else { return }
        saidSkip = nil
        let current = EndToEndRound(cutBefore: cutBefore)
        round = current
        let started = DispatchTime.now().uptimeNanoseconds
        let elapsed: () -> Int = {
            EndToEndCheck.milliseconds(from: started, to: DispatchTime.now().uptimeNanoseconds)
        }
        let port = NWEndpoint.Port(rawValue: EndToEndCheck.port) ?? .https

        connect(.tcp, current, elapsed,
                NWConnection(host: NWEndpoint.Host(EndToEndCheck.tcpHost), port: port, using: through(.tcp)))
        connect(.tls, current, elapsed,
                NWConnection(host: NWEndpoint.Host(EndToEndCheck.tlsHost), port: port, using: through(.tls)))
        if let resolver = resolver, let question = EndToEndCheck.dnsQuestion(id: serial, name: EndToEndCheck.tlsHost) {
            ask(current, elapsed, question, serial,
                NWConnection(host: NWEndpoint.Host(resolver), port: 53, using: through(.udp)))
        } else {
            deliver(current, .udp, .notAsked(why: "no resolver in the tunnel's settings"))
        }
        serial = serial == 0xfffe ? 1 : serial + 1

        queue.asyncAfter(deadline: .now() + EndToEndCheck.patience) { [weak self] in
            guard let self = self, self.round === current else { return }
            if let line = current.expire(self.states) {
                self.say(line)
                self.cutBefore = 0
            }
            self.finish()
        }
    }

    private func deliver(_ current: EndToEndRound, _ probe: EndToEndCheck.Probe, _ outcome: EndToEndCheck.Outcome) {
        guard round === current else { return }
        if let line = current.note(probe, outcome) {
            say(line)
            cutBefore = 0
            finish()
        }
    }

    /// A connect (tcp) or a connect and a handshake (tls): answered when ready.
    private func connect(_ probe: EndToEndCheck.Probe, _ current: EndToEndRound, _ elapsed: @escaping () -> Int,
                         _ connection: NWConnection) {
        connections.append(connection)
        states[probe] = "setup"
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self = self, let connection = connection, self.round === current else { return }
            switch state {
            case .ready:
                let took = elapsed()
                guard probe == .tls else {
                    self.deliver(current, probe, .answered(milliseconds: took, detail: ""))
                    return
                }
                connection.requestEstablishmentReport(queue: self.queue) { report in
                    self.deliver(current, probe, .answered(milliseconds: took, detail: Self.stretches(report)))
                }
            case .failed(let failure):
                self.deliver(current, probe, .unanswered(state: "failed " + Self.code(failure)))
            case .waiting(let failure):
                self.states[probe] = "waiting " + Self.code(failure)
            case .preparing:
                self.states[probe] = "preparing"
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// One DNS question over UDP: answered by a response to its id.
    private func ask(_ current: EndToEndRound, _ elapsed: @escaping () -> Int, _ question: Data, _ id: UInt16,
                     _ connection: NWConnection) {
        connections.append(connection)
        states[.udp] = "setup"
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self = self, let connection = connection, self.round === current else { return }
            switch state {
            case .ready:
                self.states[.udp] = "asked"
                connection.send(content: question, completion: .contentProcessed { _ in })
                connection.receiveMessage { data, _, _, _ in
                    guard let data = data, EndToEndCheck.dnsAnswers(data, id: id) else { return }
                    self.deliver(current, .udp, .answered(milliseconds: elapsed(), detail: ""))
                }
            case .failed(let failure):
                self.deliver(current, .udp, .unanswered(state: "failed " + Self.code(failure)))
            case .waiting(let failure):
                self.states[.udp] = "waiting " + Self.code(failure)
            case .preparing:
                self.states[.udp] = "preparing"
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// The set-up's stretches as the system reports them: the name lookup, then
    /// each protocol's handshake by the protocol's own name.
    private static func stretches(_ report: NWConnection.EstablishmentReport?) -> String {
        guard let report = report else { return "" }
        var parts: [String] = []
        if let lookup = report.resolutions.first {
            parts.append("dns \(Int(lookup.duration * 1000))ms")
        }
        for handshake in report.handshakes {
            parts.append("\(handshake.definition.name) \(Int(handshake.handshakeDuration * 1000))ms")
        }
        return parts.joined(separator: ", ")
    }

    /// A failure as its kind and its number.
    private static func code(_ failure: NWError) -> String {
        switch failure {
        case .posix(let number): return "posix \(number.rawValue)"
        case .dns(let number): return "dns \(number)"
        case .tls(let number): return "tls \(number)"
        @unknown default: return "other"
        }
    }
}
