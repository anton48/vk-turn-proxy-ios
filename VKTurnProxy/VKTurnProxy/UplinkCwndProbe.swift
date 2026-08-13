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

    func start(host: String, port: UInt16, flows: Int, durationSec: Int) {
        guard !running else { return }
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
    private struct Info {
        var cwnd, ssthresh, sndwnd, sbbytes, rttcurMs, srttMs, flags, mss: UInt32
        var txbytes, rtxPkts: UInt64
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
                    txbytes: u64(64), rtxPkts: u64(104))
    }

    // Resolves a numeric IP OR a hostname via getaddrinfo (the earlier
    // inet_addr() accepted only dotted-quad, so `fra10.48.org` failed with
    // "0/8 connected"). Runs on the background run() thread, so the blocking
    // resolve is fine. Tries each returned address; v4 or v6.
    private func connectOne(host: String, port: UInt16) -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        if getaddrinfo(host, String(port), &hints, &res) != 0 { return -1 }
        defer { if res != nil { freeaddrinfo(res) } }
        var ai = res
        while let a = ai {
            let fd = socket(a.pointee.ai_family, a.pointee.ai_socktype, a.pointee.ai_protocol)
            if fd >= 0 {
                var sb: Int32 = 2 << 20 // 2 MB: keep the flow cwnd-limited, not sndbuf-limited
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, socklen_t(MemoryLayout<Int32>.size))
                if connect(fd, a.pointee.ai_addr, a.pointee.ai_addrlen) == 0 { return fd }
                close(fd)
            }
            ai = a.pointee.ai_next
        }
        return -1
    }

    private func run(host: String, port: UInt16, flows: Int, durationSec: Int) {
        let log = SharedLogger.shared

        var fds: [Int32] = []
        for _ in 0..<flows {
            let fd = connectOne(host: host, port: port)
            if fd >= 0 { fds.append(fd) }
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
        log.log("cwndprobe CSV t_ms,flow,cwnd,ssthresh,sndwnd,sbbytes,srtt_ms,rttcur_ms,loss,reord,mss,txbytes,rtx,deliv_mbit,winuse")
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
                while Date() < deadline {
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
        while Date() < deadline {
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
                log.log("cwndprobe \(tms),\(i),\(s.cwnd),\(s.ssthresh),\(s.sndwnd),\(s.sbbytes),\(s.srttMs),\(s.rttcurMs),\(loss),\(reord),\(s.mss),\(s.txbytes),\(s.rtxPkts),\(String(format: "%.2f", deliv)),\(winuse)")
            }
            Thread.sleep(forTimeInterval: sampleInterval)
        }

        for fd in fds { close(fd) } // unblocks any sender parked in send()
        for t in senders { while !t.isFinished { Thread.sleep(forTimeInterval: 0.01) } }
        bufPtr.deallocate()

        let pctLoss = totalTicks > 0 ? 100 * lossTicks / totalTicks : 0
        let pctReord = totalTicks > 0 ? 100 * reordTicks / totalTicks : 0
        log.log("cwndprobe DONE flows=\(fds.count) dur=\(durationSec)s — flow0 was inLossRecovery \(pctLoss)% of ticks, reorderingSeen \(pctReord)% of ticks. Grep 'cwndprobe' from the exported log; a FLAT cwnd with reord set and loss clear = growth-starvation, a sawtooth with loss set = AIMD.")
        DispatchQueue.main.async { self.sending = false }
        publish("done: \(fds.count) flows, \(durationSec)s — grep 'cwndprobe' in logs", running: false)
    }
}
