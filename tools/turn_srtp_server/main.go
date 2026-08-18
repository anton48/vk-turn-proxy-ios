// turn_srtp_server — server-side counterpart of tools/turn_srtp_test.
//
// Listens on a UDP port, accepts DTLS-SRTP sessions (one per source
// address), decrypts incoming RTP packets, and prints per-source +
// aggregate throughput. Used to measure what fraction of traffic
// SRTP-framed by turn_srtp_test actually reaches the server through
// VK's TURN relay.
//
// Usage on VPS:
//   ./turn_srtp_server -listen 0.0.0.0:9998 -duration 30s
//
// Or cross-compile for FreeBSD/Linux:
//   CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 \
//     go build -o turn_srtp_server-freebsd-amd64 ./tools/turn_srtp_server/

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy/srtpwrap"
)

// --- anti-replay window simulation -------------------------------------
//
// WireGuard keeps ONE replay window per security association, not per path.
// When a single WG session is striped over N TURN allocations (our design),
// a packet arriving from a slow path can be so far behind the newest counter
// that the filter silently discards it — AFTER it has crossed the relay and
// been received, so a tcpdump-based packet count cannot see the loss at all.
// That blind spot is what this simulates.
//
// wireguard-go's replay.Filter (RFC 6479) rejects when last-counter exceeds
// windowSize = (ringBlocks-1)*blockBits = 127*64 = 8128. Duplicates cannot
// occur here (the client's counter is a shared atomic), so the only rejection
// mode that matters is "behind the window", which is these three lines.

const defaultReplayWindow = 8128

// rejectRec attributes one over-window packet to its path and moment.
//
// ⚠️ This is the control for the instrument's own worst artefact: observe()
// serialises on a mutex, so it orders OBSERVATIONS, not arrivals. If one of
// the 30 reader goroutines is descheduled between its Read and its observe(),
// its packet looks late by (stall × aggregate rate) even though the network
// delivered it on time. The discriminator is the source: a genuine path stall
// puts every rejection on ONE source in ONE burst; a scheduler artefact
// scatters them across sources.
type rejectRec struct {
	src  string
	disp uint64
	at   time.Time
}

type replaySim struct {
	mu       sync.Mutex
	enabled  bool
	window   uint64
	last     uint64
	analysed int64
	ooo      int64 // arrived behind the newest counter at all
	rejected int64 // displacement exceeded the window
	maxDisp  uint64
	maxSrc   string
	disps    []uint64
	rejects  []rejectRec
	perSrc   map[string]int64
}

func (r *replaySim) observe(seq uint64, src string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analysed++
	if seq > r.last {
		r.last = seq
		return
	}
	d := r.last - seq
	r.ooo++
	if d > r.maxDisp {
		r.maxDisp, r.maxSrc = d, src
	}
	if d > r.window {
		r.rejected++
		if r.perSrc == nil {
			r.perSrc = make(map[string]int64)
		}
		r.perSrc[src]++
		if len(r.rejects) < 5000 {
			r.rejects = append(r.rejects, rejectRec{src: src, disp: d, at: time.Now()})
		}
	}
	if len(r.disps) < 4_000_000 {
		r.disps = append(r.disps, d)
	}
}

func (r *replaySim) report() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled || r.analysed == 0 {
		return
	}
	fmt.Println()
	fmt.Printf("Anti-replay window simulation (RFC 6479, window=%d — wireguard-go's value):\n", r.window)
	fmt.Printf("  packets analysed:     %d\n", r.analysed)
	fmt.Printf("  arrived out of order: %d  (%.3f%%)\n",
		r.ooo, 100*float64(r.ooo)/float64(r.analysed))
	if r.ooo == 0 {
		fmt.Println("  displacement:         0 — the stream arrived in order; nothing could be replay-dropped")
	} else {
		s := append([]uint64(nil), r.disps...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		p := func(q float64) uint64 { return s[int(float64(len(s)-1)*q)] }
		fmt.Printf("  displacement p50/p99: %d / %d packets\n", p(0.50), p(0.99))
		fmt.Printf("  displacement MAX:     %d packets   (%.1f%% of the window)  src=%s\n",
			r.maxDisp, 100*float64(r.maxDisp)/float64(r.window), r.maxSrc)
	}
	frac := 100 * float64(r.rejected) / float64(r.analysed)
	fmt.Printf("  WOULD BE REJECTED:    %d  (%.4f%%)\n", r.rejected, frac)

	// Attribution — the control against this instrument's own artefact.
	if r.rejected > 0 {
		fmt.Printf("  rejections by source: %d distinct source(s)\n", len(r.perSrc))
		type kv struct {
			s string
			n int64
		}
		var ks []kv
		for s, n := range r.perSrc {
			ks = append(ks, kv{s, n})
		}
		sort.Slice(ks, func(i, j int) bool { return ks[i].n > ks[j].n })
		for i, k := range ks {
			if i >= 8 {
				fmt.Printf("      … and %d more source(s)\n", len(ks)-8)
				break
			}
			fmt.Printf("      %-25s %d\n", k.s, k.n)
		}
		if len(r.rejects) > 0 {
			span := r.rejects[len(r.rejects)-1].at.Sub(r.rejects[0].at)
			fmt.Printf("  rejections spanned:   %s (first → last)\n", span.Round(time.Millisecond))
			if len(r.perSrc) == 1 {
				fmt.Println("  → attribution: ONE source, so this is a genuine stall on one path,")
				fmt.Println("    not a scheduling artefact in this tool (which would scatter sources).")
			} else {
				fmt.Println("  → attribution: SEVERAL sources — suspect a stall of THIS PROCESS")
				fmt.Println("    (GC / descheduled reader) rather than of any one network path.")
			}
		}
	}

	switch {
	case r.rejected == 0 && r.ooo == 0:
		fmt.Println("  → verdict: nothing arrived late at all. The blind spot is CLOSED for this run.")
	case r.rejected == 0:
		fmt.Printf("  → verdict: the worst packet stayed %.0fx inside the window. CLOSED for this run.\n",
			float64(r.window)/math.Max(float64(r.maxDisp), 1))
	case frac < 0.01:
		fmt.Printf("  → verdict: the blind spot is REAL but negligible (%.4f%%) — orders of magnitude\n", frac)
		fmt.Println("    below the 10-22% congestion loss it was proposed to explain. It explains nothing.")
	default:
		fmt.Println("  → verdict: material invisible loss. Relay-crossing packet counts understate it.")
	}
}

type sourceStats struct {
	addr      string
	bytesRecv atomic.Int64
	pktsRecv  atomic.Int64
	bytesEcho atomic.Int64
	pktsEcho  atomic.Int64
	firstRecv time.Time
	firstPkt  atomic.Int64 // unix nanos of the FIRST data packet (0 = none yet)
	lastRecv  atomic.Int64 // unix nanos
}

// activeWindow — span from the first data packet to the last, per source.
// The server is started before the client and outlives it, so dividing by the
// server's own wall clock dilutes every rate it prints; that is how a previous
// run reported 1.8 Mbit/s for a 2.07 Mbit/s policer. Rate over this window is
// the number to read.
func (s *sourceStats) activeWindow() time.Duration {
	first, last := s.firstPkt.Load(), s.lastRecv.Load()
	if first == 0 || last <= first {
		return 0
	}
	return time.Duration(last - first)
}

func main() {
	var (
		listen   = flag.String("listen", "0.0.0.0:9998", "listen address (UDP)")
		duration = flag.Duration("duration", 0, "auto-exit after this duration (0 = run until SIGINT)")
		quiet    = flag.Bool("q", false, "don't print per-tick rate (only final summary)")
		// echo N copies back per received packet. The point is NOT symmetry:
		// the relay→client leg is the one we have never measured, and with a
		// 1:1 echo you cannot load it past its limit without first pushing the
		// client→relay leg past ITS limit, which confounds the two. Run the
		// client comfortably UNDER the upstream cap and set -echo=4 or so:
		// then only the return leg is saturated, and what the client counts is
		// that leg's ceiling.
		echo = flag.Int("echo", 0, "send N copies of every received packet back to the source (0 = receive only)")
		// Reads the shared sequence number turn_srtp_test stamps into the
		// first 8 bytes and replays it through WireGuard's replay filter.
		// Both binaries must be rebuilt together for this to mean anything.
		replayWindow = flag.Uint64("replay-window", defaultReplayWindow,
			"anti-replay window in packets for the simulation (0 = disable; wireguard-go uses 8128)")
	)
	flag.Parse()

	sim := &replaySim{enabled: *replayWindow > 0, window: *replayWindow}

	la, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("resolve listen addr: %v", err)
	}
	srv, err := srtpwrap.Listen(la)
	if err != nil {
		log.Fatalf("srtpwrap.Listen: %v", err)
	}
	defer srv.Close()
	log.Printf("listening on %s (DTLS-SRTP)", srv.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	if *duration > 0 {
		var cancelTimer context.CancelFunc
		ctx, cancelTimer = context.WithTimeout(ctx, *duration)
		defer cancelTimer()
	}
	defer cancel()

	// SIGINT/SIGTERM → graceful exit
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("signal received, shutting down")
		cancel()
	}()

	var (
		statsMu sync.Mutex
		stats   = make(map[string]*sourceStats)
	)

	getStats := func(addr string) *sourceStats {
		statsMu.Lock()
		s, ok := stats[addr]
		if !ok {
			s = &sourceStats{addr: addr, firstRecv: time.Now()}
			stats[addr] = s
		}
		statsMu.Unlock()
		return s
	}

	// Accept loop
	go func() {
		for {
			c, err := srv.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("accept: %v", err)
				continue
			}
			s := getStats(c.RemoteAddr().String())
			log.Printf("new SRTP session from %s", c.RemoteAddr())
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
							return
						}
						log.Printf("[%s] read: %v", s.addr, err)
						return
					}
					if n == 0 {
						continue
					}
					now := time.Now().UnixNano()
					s.bytesRecv.Add(int64(n))
					s.pktsRecv.Add(1)
					s.firstPkt.CompareAndSwap(0, now)
					s.lastRecv.Store(now)
					// Global across ALL sources — WireGuard's filter is
					// per-SA, so every path feeds one counter space.
					if sim.enabled && n >= 8 {
						sim.observe(binary.BigEndian.Uint64(buf[:8]), s.addr)
					}
					for i := 0; i < *echo; i++ {
						m, werr := c.Write(buf[:n])
						if werr != nil {
							// One log line, then stop echoing on this
							// session — a write error here is a dead
							// session, not a rate signal.
							log.Printf("[%s] echo write: %v", s.addr, werr)
							return
						}
						s.bytesEcho.Add(int64(m))
						s.pktsEcho.Add(1)
					}
				}
			}()
		}
	}()

	// Print tick
	startTime := time.Now()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

PRINT:
	for {
		select {
		case <-tick.C:
			if !*quiet {
				printRate(&statsMu, stats, time.Since(startTime))
			}
		case <-ctx.Done():
			break PRINT
		}
	}

	fmt.Println()
	fmt.Println("=== FINAL ===")
	printRate(&statsMu, stats, time.Since(startTime))
	printSummary(&statsMu, stats, time.Since(startTime))
	sim.report()
}

func printRate(mu *sync.Mutex, stats map[string]*sourceStats, elapsed time.Duration) {
	mu.Lock()
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	mu.Unlock()
	sort.Strings(keys)

	fmt.Printf("\n[%6.2fs]  per-source rate (%d sources):\n", elapsed.Seconds(), len(keys))
	for _, k := range keys {
		mu.Lock()
		s := stats[k]
		mu.Unlock()
		secs := elapsed.Seconds()
		if secs <= 0 {
			secs = 0.001
		}
		bps := float64(s.bytesRecv.Load()) / secs
		line := fmt.Sprintf("  %-25s   %.1f KB/s   pkts=%d   cum=%d B",
			s.addr, bps/1024, s.pktsRecv.Load(), s.bytesRecv.Load())
		if e := s.pktsEcho.Load(); e > 0 {
			line += fmt.Sprintf("   |  echoed %.1f KB/s   pkts=%d",
				float64(s.bytesEcho.Load())/secs/1024, e)
		}
		fmt.Println(line)
	}
}

func printSummary(mu *sync.Mutex, stats map[string]*sourceStats, elapsed time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	var total int64
	var pkts int64
	for _, s := range stats {
		total += s.bytesRecv.Load()
		pkts += s.pktsRecv.Load()
	}
	secs := elapsed.Seconds()
	if secs <= 0 {
		secs = 0.001
	}
	fmt.Println()
	fmt.Printf("Aggregate:  %.1f KB/s  (%.2f Mbit/s)   %d pkts   from %d sources   %s  (server wall clock — DILUTED, do not quote)\n",
		float64(total)/1024/secs,
		float64(total)*8/1_000_000/secs,
		pkts, len(stats), elapsed.Round(100*time.Millisecond))

	// The numbers to actually read: each source's own first-packet→last-packet
	// window. pkt/s is printed beside KB/s because those are the two units the
	// policer might be metering in; at a single packet size they cannot be told
	// apart, so sweep -pkt-size and see which of the two columns stays flat.
	fmt.Println()
	fmt.Println("Per-source, over each source's ACTIVE window (first packet → last packet):")
	for _, s := range stats {
		w := s.activeWindow()
		if w <= 0 {
			fmt.Printf("  %-25s   (no data)\n", s.addr)
			continue
		}
		ws := w.Seconds()
		fmt.Printf("  %-25s   %.1f KB/s  (%.3f Mbit/s)   %d pkts  (%.1f pkt/s)   window %s\n",
			s.addr,
			float64(s.bytesRecv.Load())/1024/ws,
			float64(s.bytesRecv.Load())*8/1_000_000/ws,
			s.pktsRecv.Load(),
			float64(s.pktsRecv.Load())/ws,
			w.Round(100*time.Millisecond))
	}
}
