// UplinkCwndProbe.swift
//
// A diagnostic that answers ONE question the pcaps could only approach
// indirectly: is each inner TCP flow's congestion window held flat (growth
// starved by near-permanent disorder) or sawtoothing (loss-limited AIMD)?
//
// It opens N plain BSD TCP flows from the MAIN APP to a discard sink at the far
// end of the tunnel and blasts data, then reads the KERNEL'S OWN view of each
// socket via getsockopt(TCP_CONNECTION_INFO) every ~100 ms: snd_cwnd, ssthresh,
// srtt, and — the point — the tcpi_flags bits inLossRecovery (0x1) and
// reorderingDetected (0x2). That is the sender-side, vantage-clean instrument;
// the pcaps were receiver-side and their throughput SERIES was muddied by
// reorder clumping.
//
// WHY THE MAIN APP, NOT THE EXTENSION: under a full-tunnel VPN the app's own
// sockets route through utun -> the extension -> the 30 TURN connections, so
// this exercises the real inner-TCP-over-tunnel path. The extension's own
// traffic would NOT traverse its own tunnel, and synth.go bypasses inner TCP by
// design. The kernel-read approach mirrors pkg/proxy/sockstats_darwin.go
// (build 233), which reads the same struct on the OUTER sockets; here we point
// it at our own INNER socket.
//
// HOW TO USE: connect the tunnel, keep the app in the FOREGROUND, start a sink
// on the far end (`nc -lk 5202 >/dev/null` on the WG host 192.168.102.1, or the
// tools/cwndsink binary for delivered-throughput), tap Run. Rows land in the
// exportable log prefixed `cwndprobe`; grep them out. Run a naked control
// (VPN off, an internet sink) in the same minutes — the line moves fast.
//
// 🚨 Diagnostic only. Default off, no production path, no Go/extension change.

import Foundation
import Combine
import Darwin

final class UplinkCwndProbe: ObservableObject {
    @Published var running = false
    /// Set by stop(); the send loop checks it every tick. Without this the A/B
    /// runner could stop ITSELF but not the traffic it started, so pressing Stop
    /// looked like nothing happened for up to a minute.
    private let stopped = AtomicFlag()
    /// True once the flows are up and bytes are actually moving — i.e. when the
    /// CSV's t_ms starts counting. 🚨 NOT the same as `running`, which is set the
    /// moment start() is called: connecting the flows through the tunnel took
    /// **25.8 s** in one recorded run, and anything that schedules against
    /// `running` would spend that time measuring an idle link. The A/B runner
    /// waits on THIS.
    @Published var sending = false
    @Published var status = "idle"

    // TCP_CONNECTION_INFO from <netinet/tcp.h>. Byte offsets into the returned
    // struct, validated on Darwin against a loopback transfer (M1 gate).
    private let optTCPConnectionInfo: Int32 = 0x106

    /// Ask the run to end early. Safe from any thread; the loop notices within a
    /// tick and tears the flows down through its normal path.
    func stop() { stopped.set(true) }

    func start(host: String, port: UInt16, flows: Int, durationSec: Int) {
        guard !running else { return }
        stopped.set(false)
        running = true
        status = "connecting…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.run(host: host, port: port,
                      flows: max(1, min(flows, 64)),
                      durationSec: max(1, min(durationSec, 120)))
        }
    }

    private func publish(_ s: String, running r: Bool? = nil) {
        DispatchQueue.main.async {
            self.status = s
            if let r = r { self.running = r }
        }
    }

    // One read of the kernel's connection info. Read-only and safe on a socket
    // another thread is blocked writing to (same guarantee sockstats_darwin.go
    // relies on).
    // 🚨 `rxRtxPkts` USED TO BE CALLED `rtxPkts` AND THE CSV COLUMN `rtx`, AND
    // THAT WAS A MISLABEL. The u64 block was pinned by driving 10 MB through a
    // loopback socket: offset 64 came back EXACTLY equal to the bytes handed to
    // send(), which fixes the ordering — 56 txpackets, 64 txbytes, 72
    // txretransmitBYTES, 80 rxpackets, 88 rxbytes, 96 rxoutoforder, 104
    // rxretransmitPACKETS. So offset 104 is the RECEIVE side and reads ~0 by
    // construction on an upload-only flow: the old `rtx` column could never have
    // shown sender retransmits. `txRtxBytes` (72) is the sender-side one. The
    // old column is kept in place, honestly named, so the parser's fixed 13-field
    // prefix still matches and old logs stay readable.
    private struct Info {
        var cwnd, ssthresh, sndwnd, sbbytes, rttcurMs, srttMs, flags, mss: UInt32
        var txbytes, rxRtxPkts, txRtxBytes: UInt64
    }
    private func sample(_ fd: Int32) -> Info? {
        let cap = 256
        let raw = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 8)
        defer { raw.deallocate() }
        var len = socklen_t(cap)
        if getsockopt(fd, Int32(IPPROTO_TCP), optTCPConnectionInfo, raw, &len) != 0 { return nil }
        func u32(_ o: Int) -> UInt32 { raw.load(fromByteOffset: o, as: UInt32.self) }
        func u64(_ o: Int) -> UInt64 { raw.load(fromByteOffset: o, as: UInt64.self) }
        return Info(cwnd: u32(24), ssthresh: u32(20), sndwnd: u32(28), sbbytes: u32(32),
                    rttcurMs: u32(40), srttMs: u32(44), flags: u32(8), mss: u32(16),
                    txbytes: u64(64), rxRtxPkts: u64(104), txRtxBytes: u64(72))
    }

    // The kernel's view of a socket that is still HANDSHAKING: `tcpi_state` at
    // offset 0 (2 = SYN_SENT, 4 = ESTABLISHED, per <netinet/tcp_fsm.h>) and
    // `tcpi_rto` at 12, the retransmit timeout in ms.
    //
    // 🚨 THE FIELD CHOICE IS MEASURED, NOT ASSUMED, AND THE OBVIOUS CHOICE WAS
    // BLIND. Driven against a black hole (192.0.2.1, RFC 5737 TEST-NET-1, which
    // answers nothing) on Darwin, with the SYN provably being retransmitted:
    //
    //   tcpi_rto (12)                 1000 → 2000 → 4000 ms   ← doubles, USABLE
    //   tcpi_txpackets (56)           0 for 10 s              ← starts only at ESTABLISHED
    //   offset 104                    0 for 10 s              ← receive-side, see below
    //
    // So a stalled handshake is read off the BACKOFF, not off a packet counter:
    //   state 2, rto DOUBLING   — the SYN left this socket and nobody answered;
    //                             it dies at or below utun.
    //   state 2, rto PINNED at its initial value for seconds — the kernel is not
    //                             even retransmitting, i.e. nothing went out.
    // A `state` of 0 while mid-connect would mean the option or the offset is
    // wrong, so the value is logged raw rather than decoded.
    private func handshakeState(_ fd: Int32) -> (state: UInt8, rto: UInt32)? {
        let cap = 256
        let raw = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 8)
        defer { raw.deallocate() }
        var len = socklen_t(cap)
        if getsockopt(fd, Int32(IPPROTO_TCP), optTCPConnectionInfo, raw, &len) != 0 { return nil }
        return (raw.load(fromByteOffset: 0, as: UInt8.self),
                raw.load(fromByteOffset: 12, as: UInt32.self))
    }

    /// Opens all `flows` sockets and handshakes them CONCURRENTLY, then hands
    /// back blocking fds for the send phase.
    ///
    /// 🚨 THIS REPLACES A SERIAL BLOCKING LOOP, AND THE DEFECT IS WORTH NAMING
    /// BECAUSE IT CORRUPTED THE ONE NUMBER A WHOLE INVESTIGATION TURNED ON. The
    /// old version called a blocking `connect()` per flow in a `for` loop, so
    /// flow i+1 did not start its handshake until flow i finished. What it
    /// reported as "the flows took 26-39 s to come up" is therefore a **SUM over
    /// F flows**, not the wall clock a real workload pays — Ookla opens its four
    /// upload flows at once. A per-flow cost of a few seconds reads as half a
    /// minute at F=8 purely through the loop. Every recorded connect-stall number
    /// predates this fix and must be re-read as Σ.
    ///
    /// So this is a fix and an instrument at once: `wall` vs `sum` in the summary
    /// line is exactly the discriminator, printed by the thing being accused.
    ///
    /// It also resolves ONCE. The serial version called `getaddrinfo` per flow,
    /// so with a hostname sink F blocking lookups were themselves inside the
    /// "connect time" it reported.
    /// Close a LOADED socket so the run ends when it ends.
    ///
    /// 🚨 Why this is not a plain `close()`. Each flow carries `SO_SNDBUF` = 2 MB
    /// on purpose (keep it cwnd-limited, not sndbuf-limited), and a graceful
    /// close hands that backlog to the kernel to deliver in the background. On
    /// 2026-08-14 (`udptest4`) that was measured: the probe printed DONE, seven
    /// of eight flows closed, and the eighth kept delivering **0.08 Mbit/s =
    /// exactly one MSS per RTT** — `cwnd` had collapsed in its last second — so
    /// its 2 MB would have taken ~200 s to drain, with the sink counting it as a
    /// live connection the whole time. A run that follows would then be scored
    /// against a stale flow it cannot see.
    ///
    /// `SO_LINGER {1, 0}` makes `close()` send RST and discard the backlog: the
    /// flow stops when the measurement stops. Nothing is lost that we measure —
    /// the sender-side truth is the probe's own `txbytes`, and the sink's
    /// delivered figure SHOULD NOT include a post-run tail.
    private func abortClose(_ fd: Int32) {
        var lg = linger(l_onoff: 1, l_linger: 0)
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, socklen_t(MemoryLayout<linger>.size))
        close(fd)
    }

    private func connectAll(host: String, port: UInt16, flows: Int,
                            deadlineSec: Double) -> [Int32] {
        let log = SharedLogger.shared
        let t0 = Date()

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let ai = res else {
            log.log("cwndprobe ERROR: cannot resolve \(host):\(port)")
            return []
        }
        defer { freeaddrinfo(res) }
        let resolveMs = Int(Date().timeIntervalSince(t0) * 1000)

        var pending: [Int32] = []
        var connected: [Int32] = []
        var connectMs: [Int] = []
        var startedAt: [Int32: Date] = [:]

        for _ in 0..<flows {
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd < 0 { continue }
            var sb: Int32 = 2 << 20 // 2 MB: keep the flow cwnd-limited, not sndbuf-limited
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, socklen_t(MemoryLayout<Int32>.size))
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
            startedAt[fd] = Date()
            if connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen) == 0 {
                connected.append(fd)
                connectMs.append(0)
            } else if errno == EINPROGRESS {
                pending.append(fd)
            } else {
                log.log("cwndprobe CONNECT-FAIL immediate errno=\(errno)")
                close(fd)
            }
        }

        let deadline = Date().addingTimeInterval(deadlineSec)
        var lastReport = Date.distantPast
        while !pending.isEmpty && Date() < deadline && !stopped.get() {
            var pfds = pending.map { pollfd(fd: $0, events: Int16(POLLOUT), revents: 0) }
            _ = poll(&pfds, nfds_t(pfds.count), 100)
            var stillPending: [Int32] = []
            for p in pfds {
                if p.revents == 0 { stillPending.append(p.fd); continue }
                var err: Int32 = 0
                var el = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(p.fd, SOL_SOCKET, SO_ERROR, &err, &el)
                let ms = Int(Date().timeIntervalSince(startedAt[p.fd] ?? t0) * 1000)
                if err == 0 {
                    let rto = handshakeState(p.fd)?.rto ?? 0
                    log.log("cwndprobe CONNECT flow=\(connected.count) ms=\(ms) rto=\(rto)")
                    connected.append(p.fd)
                    connectMs.append(ms)
                } else {
                    log.log("cwndprobe CONNECT-FAIL ms=\(ms) err=\(err)")
                    close(p.fd)
                }
            }
            pending = stillPending

            // THE INSTRUMENT. While anything is still handshaking, print the
            // kernel's own view of it once a second. A stall now names itself.
            if !pending.isEmpty && Date().timeIntervalSince(lastReport) >= 1.0 {
                lastReport = Date()
                for fd in pending {
                    guard let hs = handshakeState(fd) else {
                        log.log("cwndprobe CONNECTING fd=\(fd) — TCP_CONNECTION_INFO unreadable")
                        continue
                    }
                    let ms = Int(Date().timeIntervalSince(startedAt[fd] ?? t0) * 1000)
                    log.log("cwndprobe CONNECTING fd=\(fd) ms=\(ms) state=\(hs.state) rto=\(hs.rto)")
                }
            }
        }

        for fd in pending {
            let ms = Int(Date().timeIntervalSince(startedAt[fd] ?? t0) * 1000)
            if let hs = handshakeState(fd) {
                log.log("cwndprobe CONNECT-TIMEOUT ms=\(ms) state=\(hs.state) rto=\(hs.rto)")
            } else {
                log.log("cwndprobe CONNECT-TIMEOUT ms=\(ms) — state unreadable")
            }
            close(fd)
        }

        // The send phase wants BLOCKING sockets: a blocked send() is the
        // measurement (it means the flow is cwnd/sndbuf-limited).
        for fd in connected {
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK)
        }

        let wallMs = Int(Date().timeIntervalSince(t0) * 1000)
        let sumMs = connectMs.reduce(0, +)
        let maxMs = connectMs.max() ?? 0
        log.log("cwndprobe CONNECTED \(connected.count)/\(flows) wall=\(wallMs)ms "
            + "max=\(maxMs)ms sum=\(sumMs)ms resolve=\(resolveMs)ms — 🚨 the serial "
            + "version reported SUM; wall is what a parallel workload actually pays")
        return connected
    }

    private func run(host: String, port: UInt16, flows: Int, durationSec: Int) {
        let log = SharedLogger.shared

        // 45 s, deliberately under the A/B runner's 60 s abort, so a slow
        // handshake is reported by the probe — with per-flow kernel state — and
        // not by the runner, which can only say "they never came up".
        let fds = connectAll(host: host, port: port, flows: flows, deadlineSec: 45)
        if stopped.get() {
            for fd in fds { abortClose(fd) }
            DispatchQueue.main.async { self.sending = false }
            publish("stopped during connect", running: false)
            return
        }
        if fds.isEmpty {
            log.log("cwndprobe ERROR: 0/\(flows) connected to \(host):\(port) — is the tunnel up and the sink listening?")
            DispatchQueue.main.async { self.sending = false }
        publish("failed: 0/\(flows) connected", running: false)
            return
        }
        var eff: Int32 = 0
        var el = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &eff, &el)
        log.log("cwndprobe START host=\(host):\(port) flows=\(fds.count)/\(flows) dur=\(durationSec)s effSndBuf=\(eff)")
        log.log("cwndprobe CSV t_ms,flow,cwnd,ssthresh,sndwnd,sbbytes,srtt_ms,rttcur_ms,loss,reord,mss,txbytes,rxrtx_pkts,deliv_mbit,winuse,txrtx_bytes")
        publish("running: \(fds.count) flows for \(durationSec)s")
        DispatchQueue.main.async { self.sending = true }

        let deadline = Date().addingTimeInterval(Double(durationSec))

        // One shared read-only send buffer (a raw pointer is Sendable; a [UInt8]
        // captured by many threads is not).
        let bufSize = 128 << 10
        let bufPtr = UnsafeMutableRawPointer.allocate(byteCount: bufSize, alignment: 16)
        memset(bufPtr, 0x61, bufSize)

        // One blocking sender per flow. A blocked send() IS the measurement —
        // it means the flow is cwnd/sndbuf-limited, which is what we want.
        var senders: [Thread] = []
        for fd in fds {
            let t = Thread {
                while Date() < deadline && !self.stopped.get() {
                    let n = send(fd, bufPtr, bufSize, 0)
                    if n <= 0 {
                        if n < 0 && errno == EINTR { continue }
                        break
                    }
                }
            }
            t.stackSize = 512 << 10
            t.start()
            senders.append(t)
        }

        // Sampler on this thread. Darwin's tcp_connection_info has NO
        // delivery-rate field (tcpi_delivery_rate is Linux-only), so we derive
        // it: deliv = Δtxbytes/Δt, and winuse = deliv ÷ (cwnd/srtt) = the % of
        // its own window the flow actually uses. winuse ≪ 100 = paced /
        // ACK-clock-limited (window slack); ≈ 100 = at the window edge.
        let start = Date()
        var lossTicks = 0, reordTicks = 0, totalTicks = 0
        let sampleInterval = 0.1
        var prevTx = [UInt64](repeating: 0, count: fds.count)
        var prevMs = [Int](repeating: 0, count: fds.count)
        while Date() < deadline && !stopped.get() {
            let tms = Int(Date().timeIntervalSince(start) * 1000)
            for (i, fd) in fds.enumerated() {
                guard let s = sample(fd) else { continue }
                let loss = (s.flags & 0x1) != 0 ? 1 : 0
                let reord = (s.flags & 0x2) != 0 ? 1 : 0
                if i == 0 {
                    totalTicks += 1
                    lossTicks += loss
                    reordTicks += reord
                }
                let dms = tms - prevMs[i]
                let dtx = s.txbytes >= prevTx[i] ? s.txbytes - prevTx[i] : 0
                let deliv = dms > 0 ? Double(dtx) * 8 / (Double(dms) / 1000.0) / 1e6 : 0        // Mbit/s
                let winRate = s.srttMs > 0 ? Double(s.cwnd) * 8 / (Double(s.srttMs) / 1000.0) / 1e6 : 0
                let winuse = winRate > 0 ? Int((100.0 * deliv / winRate).rounded()) : 0
                prevTx[i] = s.txbytes; prevMs[i] = tms
                log.log("cwndprobe \(tms),\(i),\(s.cwnd),\(s.ssthresh),\(s.sndwnd),\(s.sbbytes),\(s.srttMs),\(s.rttcurMs),\(loss),\(reord),\(s.mss),\(s.txbytes),\(s.rxRtxPkts),\(String(format: "%.2f", deliv)),\(winuse),\(s.txRtxBytes)")
            }
            Thread.sleep(forTimeInterval: sampleInterval)
        }

        // RST rather than a graceful close: see abortClose. It also unblocks
        // any sender parked in send().
        for fd in fds { abortClose(fd) }
        // Make the teardown VISIBLE. Without this line the property is silent —
        // nothing in either log says whether the run's backlog was discarded or
        // handed to the kernel to dribble out for minutes. With it, the sink's
        // conn count dropping to 0 within a second of this line is the check.
        log.log("cwndprobe TEARDOWN flows=\(fds.count) aborted with SO_LINGER 0 — the sink should show conns=0 at once; any connection still delivering after this line is NOT ours")
        for t in senders { while !t.isFinished { Thread.sleep(forTimeInterval: 0.01) } }
        bufPtr.deallocate()

        let pctLoss = totalTicks > 0 ? 100 * lossTicks / totalTicks : 0
        let pctReord = totalTicks > 0 ? 100 * reordTicks / totalTicks : 0
        log.log("cwndprobe DONE flows=\(fds.count) dur=\(durationSec)s — flow0 was inLossRecovery \(pctLoss)% of ticks, reorderingSeen \(pctReord)% of ticks. Grep 'cwndprobe' from the exported log; a FLAT cwnd with reord set and loss clear = growth-starvation, a sawtooth with loss set = AIMD.")
        DispatchQueue.main.async { self.sending = false }
        publish("done: \(fds.count) flows, \(durationSec)s — grep 'cwndprobe' in logs", running: false)
    }
}


/// A boolean shared between the UI thread and the probe's worker threads. Small
/// enough to hand-roll, and a plain Bool here would be a data race — the kind
/// that works in testing and stops working on a loaded phone.
final class AtomicFlag {
    private let lock = NSLock()
    private var value = false
    func set(_ v: Bool) { lock.lock(); value = v; lock.unlock() }
    func get() -> Bool { lock.lock(); defer { lock.unlock() }; return value }
}
