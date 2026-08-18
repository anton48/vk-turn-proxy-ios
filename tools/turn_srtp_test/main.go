// turn_srtp_test — measures TURN allocation throughput with traffic
// wrapped as DTLS+SRTP (RTP PayloadType 100, mimics VP8 WebRTC video).
//
// Mirror of tools/turn_bw_test but every byte sent through TURN is
// framed as an SRTP-encrypted RTP packet instead of raw bytes. Used
// to test the hypothesis that VK's per-allocation shape policy is
// content-aware: if SRTP frames fall into a "recognized media" bucket
// that's not throttled, this tool will report ~full-speed throughput
// where the raw bw_test gets ~9 KB/s shape.
//
// Setup is identical to turn_bw_test, except the server must be the
// matching turn_srtp_server (it terminates DTLS-SRTP and decrypts).
//
// Usage (single allocation, baseline):
//   go run ./tools/turn_srtp_test -creds=backup.json -slot=0 \
//       -dst-ip=217.168.246.242 -dst-port=9998 \
//       -duration=30s
//
// Usage (parallel across distinct creds):
//   go run ./tools/turn_srtp_test -creds=backup.json -parallel=10 \
//       -dst-ip=217.168.246.242 -dst-port=9998 -duration=30s
//
// Usage (production-like — many allocations per cred, matching iOS
// app's connsPerSlot=10 pattern). With -allocs-per-cred=K each cred
// supports up to K simultaneous TURN allocations (VK per-cred quota
// is 10); total worker count = parallel * allocs-per-cred.
// Example: 3 creds × 10 allocs-per-cred = 30 workers, matches
// NumConns=30 production layout.
//   go run ./tools/turn_srtp_test -creds=backup.json -parallel=3 \
//       -allocs-per-cred=10 -spacing=5ms \
//       -dst-ip=217.168.246.242 -dst-port=9998 -duration=60s

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy/srtpwrap"
)

// seqCounter is shared by EVERY worker, so the stream of sequence numbers
// leaving this process across all allocations is exactly what WireGuard's
// per-SA send counter looks like when one tunnel is striped over N paths.
// The server replays it through a replay-window simulation; see -replay-window
// there. First 8 bytes of each payload carry it, big-endian.
var seqCounter atomic.Uint64

type backupCred struct {
	Address    string `json:"address"`
	LastUsedAt int64  `json:"last_used_at"`
	Password   string `json:"password"`
	Slot       int    `json:"slot"`
	Username   string `json:"username"`
}

type backupFile struct {
	TurnPool struct {
		Creds []backupCred `json:"creds"`
	} `json:"turn_pool"`
}

type workerStats struct {
	slot      int // backup cred index
	subIdx    int // 0..allocs-per-cred-1; 0 when allocs-per-cred=1
	relayAddr string
	bytesSent atomic.Int64
	pktsSent  atomic.Int64
	sendErrs  atomic.Int64
	bytesRecv atomic.Int64 // only non-zero when the server runs with -echo
	pktsRecv  atomic.Int64
	startTime time.Time
	hsOK      atomic.Bool
	hsErr     atomic.Value // error
}

func main() {
	var (
		credsPath     = flag.String("creds", "", "path to vkturnproxy-backup-*.json")
		slot          = flag.Int("slot", 0, "slot index to use when -parallel=1")
		parallel      = flag.Int("parallel", 1, "number of distinct creds to use (each cred opens -allocs-per-cred allocations)")
		allocsPerCred = flag.Int("allocs-per-cred", 1, "TURN allocations per cred (VK quota is 10; matches iOS app's connsPerSlot). Total workers = parallel * allocs-per-cred.")
		dstIP         = flag.String("dst-ip", "", "destination IP (server hosting turn_srtp_server)")
		dstPort       = flag.Int("dst-port", 0, "destination port (turn_srtp_server -port)")
		relayAddr     = flag.String("relay-addr", "", "override TURN relay addr (host:port); default = cred.Address")
		duration      = flag.Duration("duration", 30*time.Second, "test duration")
		pktSize       = flag.Int("pkt-size", 1200, "user payload size per RTP packet (before SRTP/RTP overhead)")
		spacing       = flag.Duration("spacing", 0, "delay between Writes per worker (0 = as fast as possible)")
		burst         = flag.Int("burst", 1, "packets written back-to-back per -spacing tick; offered rate ≈ burst/spacing. Needed to overload the policer at small -pkt-size, where time.Sleep granularity caps -spacing alone at ~900 pkt/s.")
		transport     = flag.String("transport", "udp", "TURN control transport: udp or tcp (relayed data is always UDP via Allocate())")
		readyTimeout  = flag.Duration("ready-timeout", 180*time.Second, "how long to wait for ALL workers to reach READY (allocation+permission+handshake) before refusing to start")
		grace         = flag.Duration("grace", 20*time.Second, "how long after -duration to wait for workers to unwind before cancelling them. Measured from the barrier release, so a fast barrier does not append its unused slack to the run.")
		arm           = flag.String("arm", "", "which leg this run measures: uplink (server -echo=0) or downlink (server -echo=4). Sets nothing by itself — it declares the EXPECTED return ratio so the run can refuse to be scored as the arm it is not. Empty = no check.")
		verbose       = flag.Bool("v", false, "enable pion debug logs")
	)
	flag.Parse()

	// Reject an unknown -arm HERE, before a single allocation is made. The check
	// used to live in checkArm, i.e. after the whole run — so a typo cost the
	// entire test and was reported once the data it was meant to label had
	// already been collected.
	switch *arm {
	case "", "uplink", "downlink":
	default:
		log.Fatalf("unknown -arm=%q (want uplink, downlink, or empty for no check)", *arm)
	}

	if *credsPath == "" || *dstIP == "" || *dstPort == 0 {
		log.Fatal("required flags: -creds, -dst-ip, -dst-port")
	}
	if *allocsPerCred < 1 {
		log.Fatal("-allocs-per-cred must be >= 1")
	}
	if *allocsPerCred > 10 {
		log.Printf("warning: -allocs-per-cred=%d exceeds VK per-cred quota of 10; expect 486 Allocation Quota Reached", *allocsPerCred)
	}

	creds, err := loadCreds(*credsPath)
	if err != nil {
		log.Fatalf("loadCreds: %v", err)
	}
	if len(creds) == 0 {
		log.Fatal("no creds in backup")
	}

	// Pick workers
	var picked []backupCred
	if *parallel <= 1 {
		var found *backupCred
		for i := range creds {
			if creds[i].Slot == *slot {
				found = &creds[i]
				break
			}
		}
		if found == nil {
			log.Fatalf("slot %d not found in backup", *slot)
		}
		picked = []backupCred{*found}
	} else {
		sorted := make([]backupCred, len(creds))
		copy(sorted, creds)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slot < sorted[j].Slot })
		if *parallel > len(sorted) {
			log.Fatalf("requested %d parallel workers but backup has only %d creds", *parallel, len(sorted))
		}
		picked = sorted[:*parallel]
	}

	dstAddr := &net.UDPAddr{IP: net.ParseIP(*dstIP), Port: *dstPort}
	if dstAddr.IP == nil {
		log.Fatalf("invalid -dst-ip=%q", *dstIP)
	}

	// The deadline must cover the barrier wait AS WELL AS the run: bringing 60
	// allocations up takes real time, and a ctx sized to duration+30s would
	// expire mid-run once a genuine barrier is in front of it — shortening the
	// arm silently, which reads exactly like a completed one.
	ctx, cancel := context.WithTimeout(context.Background(), *readyTimeout+*duration+60*time.Second)
	defer cancel()

	totalWorkers := len(picked) * *allocsPerCred
	stats := make([]*workerStats, 0, totalWorkers)
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})
	readyCh := make(chan int, totalWorkers)

	log.Printf("config: parallel=%d, allocs-per-cred=%d → %d total workers, transport=%s",
		len(picked), *allocsPerCred, totalWorkers, *transport)

	for credIdx, c := range picked {
		for sub := 0; sub < *allocsPerCred; sub++ {
			workerIdx := credIdx**allocsPerCred + sub
			ws := &workerStats{slot: c.Slot, subIdx: sub}
			stats = append(stats, ws)
			wg.Add(1)
			go func(wIdx, sub int, cred backupCred, ws *workerStats) {
				defer wg.Done()
				relay := *relayAddr
				if relay == "" {
					relay = cred.Address
				}
				if err := runWorker(ctx, cred, relay, dstAddr, ws, startBarrier, readyCh, *duration, *pktSize, *spacing, *burst, *transport, *verbose, wIdx); err != nil {
					log.Printf("[w%d slot=%d.%d] worker error: %v", wIdx, cred.Slot, sub, err)
				}
			}(workerIdx, sub, c, ws)
		}
	}

	// A REAL barrier. The previous version slept 500 ms and closed the channel
	// unconditionally, while the DTLS/SRTP handshake sat AFTER the wait — so the
	// load began with allocations still coming up and handshakes still running,
	// and the "N loaded allocations" the measurement is about did not exist at
	// the start of it. That is not a weaker arm, it is a DIFFERENT one, and it
	// still produces a number. Now: allocation → permission → handshake → READY,
	// main waits for ALL of them, and only then releases.
	log.Printf("barrier: waiting for %d/%d workers to reach READY (allocate + permission + handshake), timeout %s…",
		totalWorkers, totalWorkers, *readyTimeout)
	ready := 0
	deadline := time.After(*readyTimeout)
BARRIER:
	for ready < totalWorkers {
		select {
		case <-readyCh:
			ready++
			if ready%10 == 0 || ready == totalWorkers {
				log.Printf("barrier: %d/%d READY", ready, totalWorkers)
			}
		case <-deadline:
			break BARRIER
		case <-ctx.Done():
			break BARRIER
		}
	}
	if ready < totalWorkers {
		log.Printf("🚨 REFUSING TO START: only %d of %d workers reached READY within %s.",
			ready, totalWorkers, *readyTimeout)
		log.Printf("🚨 A run on a short pool is a DIFFERENT ARM at an intensity nobody asked for — and it would still print a plausible number.")
		cancel()
		wg.Wait()
		os.Exit(1)
	}
	log.Printf("barrier: all %d READY — releasing, load starts now", totalWorkers)
	close(startBarrier)
	testStart := time.Now()

	// 🚨 The teardown deadline must be measured from HERE, not from process
	// start. The up-front ctx has to be generous enough for a slow barrier
	// (readyTimeout + duration + slack), and the barrier is usually FAST — so on
	// a blackhole, where every worker is parked in Write and only ctx
	// cancellation frees it, that leftover slack becomes dead time appended to
	// the run: minutes of it, with no bytes moving, before the final report
	// appears. Re-arming from testStart bounds the tail at exactly one grace
	// period however long the barrier took.
	time.AfterFunc(*duration+*grace, cancel)

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()

PRINT:
	for {
		select {
		case <-tick.C:
			printRate(stats, time.Since(testStart))
		case <-doneCh:
			break PRINT
		}
	}

	// Average over the LOAD WINDOW, not over wall time to teardown. Each worker
	// stops sending at exactly -duration after the barrier, so any time spent
	// unwinding afterwards — a grace period, a blocked Write being cancelled —
	// carries no bytes and would deflate every rate it were divided into. If the
	// run ended EARLY (cancelled, or every worker died) the elapsed time is the
	// shorter one and is the honest window, so take the smaller of the two.
	window := time.Since(testStart)
	if window > *duration {
		window = *duration
	}
	fmt.Println()
	fmt.Println("=== FINAL ===")
	fmt.Printf("(rates averaged over the %s load window; wall time to teardown was %s)\n",
		window.Round(time.Second), time.Since(testStart).Round(time.Second))
	printRate(stats, window)
	printSummary(stats, window)
	checkArm(stats, *arm)
}

// checkArm scores the arm's LABEL against what the wire actually did.
//
// The uplink and downlink arms differ by ONE setting that lives in another
// process: the server's -echo. Nothing on this side can read it, so a downlink
// arm run against a server left at -echo=0 is simply an uplink arm wearing the
// wrong label — and it produces a full set of plausible numbers. This turns that
// into a loud failure rather than a silent mislabel.
func checkArm(stats []*workerStats, arm string) {
	if arm == "" {
		return
	}
	var sent, recv int64
	zeroBack := 0
	for _, ws := range stats {
		sent += ws.pktsSent.Load()
		r := ws.pktsRecv.Load()
		recv += r
		if r == 0 {
			zeroBack++
		}
	}
	ratio := 0.0
	if sent > 0 {
		ratio = float64(recv) / float64(sent)
	}
	fmt.Printf("\nARM CHECK (%s): sent=%d recv=%d  observed echo ratio=%.2f, workers with nothing back=%d/%d\n",
		arm, sent, recv, ratio, zeroBack, len(stats))
	switch arm {
	case "uplink":
		if ratio > 0.1 {
			fmt.Printf("🚨 ARM MISMATCH: declared uplink (server -echo=0) but %.2f× came back — the server is echoing. This run is NOT an uplink arm.\n", ratio)
		}
	case "downlink":
		if ratio < 2.0 {
			fmt.Printf("🚨 ARM MISMATCH: declared downlink (server -echo=4) but only %.2f× came back. Either the server is not at -echo=4, or the return leg was lost — do NOT score this as a downlink arm without deciding which.\n", ratio)
		}
	default:
		fmt.Printf("🚨 unknown -arm=%q (want uplink or downlink) — no check performed\n", arm)
	}
}

func loadCreds(path string) ([]backupCred, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bf backupFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, err
	}
	return bf.TurnPool.Creds, nil
}

func runWorker(ctx context.Context, cred backupCred, relayAddr string, dst *net.UDPAddr,
	ws *workerStats, startBarrier chan struct{}, readyCh chan<- int, dur time.Duration,
	pktSize int, spacing time.Duration, burst int, transport string, verbose bool, idx int,
) error {
	ws.startTime = time.Now()

	// Set up the underlying conn that pion/turn uses to talk to the
	// relay (control plane). Two modes:
	//   - "udp": local UDP socket. Control + relay→peer both UDP.
	//   - "tcp": TCP dial to relay, wrapped in turn.NewSTUNConn so it
	//     looks like a PacketConn. Control TCP (bypasses VK's per-cred
	//     UDP allocate-rate quota), relay→peer still UDP via Allocate().
	//     Matches what the iOS app uses since build 109.
	var (
		ctlConn   net.PacketConn
		ctlCloser func()
	)
	switch transport {
	case "udp":
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return fmt.Errorf("local udp listen: %w", err)
		}
		ctlConn = uc
		ctlCloser = func() { _ = uc.Close() }
	case "tcp":
		dialer := net.Dialer{Timeout: 5 * time.Second}
		tcp, err := dialer.Dial("tcp", relayAddr)
		if err != nil {
			return fmt.Errorf("local tcp dial to relay: %w", err)
		}
		ctlConn = turn.NewSTUNConn(tcp)
		ctlCloser = func() { _ = tcp.Close() }
	default:
		return fmt.Errorf("unknown transport %q (want udp or tcp)", transport)
	}
	defer ctlCloser()

	// 🚨 The watcher that makes a REPRODUCED defect reportable.
	//
	// srtpwrap's SetWriteDeadline is a silent no-op (srtp.go: `return nil`), so
	// nothing in the write path can time out. Under the very blackhole this tool
	// exists to catch — outer TCP accepted, never acknowledged — a worker parks
	// forever inside Write, never reaches its defers, and the run ends with no
	// final report: SUCCESS at reproducing the defect would look like a hung
	// program. Closing the underlying conn from outside is what unblocks it.
	go func() {
		<-ctx.Done()
		ctlCloser()
	}()

	logFactory := logging.NewDefaultLoggerFactory()
	if !verbose {
		logFactory.DefaultLogLevel = logging.LogLevelError
	}

	tc, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr:         relayAddr,
		Conn:                   ctlConn,
		Username:               cred.Username,
		Password:               cred.Password,
		Realm:                  "okcdn.ru", // VK TURN uses OK CDN realm, NOT vkontakte.com
		Software:               "vk-turn-srtp-test",
		LoggerFactory:          logFactory,
		RequestedAddressFamily: turn.RequestedAddressFamilyIPv4,
	})
	if err != nil {
		return fmt.Errorf("turn.NewClient: %w", err)
	}
	defer tc.Close()

	if err := tc.Listen(); err != nil {
		return fmt.Errorf("turn listen: %w", err)
	}

	allocStart := time.Now()
	relayedConn, err := tc.Allocate()
	if err != nil {
		return fmt.Errorf("turn allocate: %w", err)
	}
	defer relayedConn.Close()
	allocDur := time.Since(allocStart)
	ws.relayAddr = relayedConn.LocalAddr().String()
	log.Printf("[w%d slot=%d.%d] allocated relay=%s in %s", idx, cred.Slot, ws.subIdx, ws.relayAddr, allocDur)

	// CreatePermission for the destination so relay forwards our writes.
	if err := tc.CreatePermission(dst); err != nil {
		return fmt.Errorf("turn create permission: %w", err)
	}

	// Perform DTLS+SRTP handshake on top of the relayed conn — BEFORE the
	// barrier, not after it. The handshake is part of bringing an allocation up;
	// doing it after the release meant the first seconds of every run had
	// allocations still negotiating rather than carrying load.
	hsCtx, hsCancel := context.WithTimeout(ctx, srtpwrap.HandshakeTimeout)
	srtpConn, err := srtpwrap.Client(hsCtx, relayedConn, dst, nil)
	hsCancel()
	if err != nil {
		ws.hsErr.Store(err)
		return fmt.Errorf("srtp handshake: %w", err)
	}
	ws.hsOK.Store(true)
	defer srtpConn.Close()
	log.Printf("[w%d slot=%d.%d] DTLS+SRTP handshake done — READY", idx, cred.Slot, ws.subIdx)

	// READY: this allocation is fully up. Only when every worker has said so
	// does main release the barrier.
	select {
	case readyCh <- idx:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Wait for the start barrier so all workers begin sending at the
	// same time (cleaner aggregate measurement).
	select {
	case <-startBarrier:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Reader. Silent unless the server was started with -echo, but always
	// running: without draining the session the return path would just fill
	// buffers, and the point of the echo mode is to measure exactly what the
	// relay lets BACK through — the leg the plain send-only test never sees.
	go func() {
		rbuf := make([]byte, 4096)
		for {
			n, rerr := srtpConn.Read(rbuf)
			if rerr != nil {
				return
			}
			if n > 0 {
				ws.bytesRecv.Add(int64(n))
				ws.pktsRecv.Add(1)
			}
		}
	}()

	// Send loop.
	payload := make([]byte, pktSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	deadline := time.Now().Add(dur)
	if burst < 1 {
		burst = 1
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// A -spacing tick can carry several packets. time.Sleep bottoms out
		// around 1 ms, so -spacing alone caps a worker at ~900 pkt/s — fine at
		// 1200 B (over 1 MB/s) but far short of what it takes to overload the
		// policer at 200 B, where the same byte rate needs six times the
		// packets. The bucket smooths the burst out over the run.
		failed := false
		for b := 0; b < burst; b++ {
			// Stamp the shared counter. Drawn per packet, across all
			// workers, so reordering seen at the server is the reordering
			// WireGuard's replay filter would see.
			if len(payload) >= 8 {
				binary.BigEndian.PutUint64(payload[:8], seqCounter.Add(1))
			}
			n, err := srtpConn.Write(payload)
			if err != nil {
				ws.sendErrs.Add(1)
				failed = true
				break
			}
			ws.bytesSent.Add(int64(n))
			ws.pktsSent.Add(1)
		}
		if failed {
			// short backoff to avoid hot-spin on persistent error
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if spacing > 0 {
			time.Sleep(spacing)
		}
	}
	return nil
}

func printRate(stats []*workerStats, elapsed time.Duration) {
	fmt.Printf("\n[%6.2fs]  per-worker rate:\n", elapsed.Seconds())
	for _, ws := range stats {
		hs := "hs-pending"
		if ws.hsOK.Load() {
			hs = "hs-OK"
		} else if e := ws.hsErr.Load(); e != nil {
			hs = "hs-FAIL"
		}
		secs := elapsed.Seconds()
		if secs <= 0 {
			secs = 0.001
		}
		bps := float64(ws.bytesSent.Load()) / secs
		line := fmt.Sprintf("  slot=%-2d.%-2d relay=%-25s %s   %.1f KB/s   pkts=%d  errs=%d",
			ws.slot, ws.subIdx, ws.relayAddr, hs, bps/1024,
			ws.pktsSent.Load(), ws.sendErrs.Load())
		if r := ws.pktsRecv.Load(); r > 0 {
			line += fmt.Sprintf("   |  back %.1f KB/s   pkts=%d",
				float64(ws.bytesRecv.Load())/secs/1024, r)
		}
		fmt.Println(line)
	}
}

func printSummary(stats []*workerStats, elapsed time.Duration) {
	var total int64
	var pkts int64
	hsOK, hsFail, hsPending := 0, 0, 0
	for _, ws := range stats {
		total += ws.bytesSent.Load()
		pkts += ws.pktsSent.Load()
		if ws.hsOK.Load() {
			hsOK++
		} else if e := ws.hsErr.Load(); e != nil {
			hsFail++
		} else {
			hsPending++
		}
	}
	secs := elapsed.Seconds()
	if secs <= 0 {
		secs = 0.001
	}
	fmt.Println()
	// pkt/s is printed next to KB/s because they are the two candidate units
	// the policer could be metering in, and at 1200 B they are numerically
	// indistinguishable — only a size sweep separates them.
	fmt.Printf("Aggregate:  %.1f KB/s  (%.2f Mbit/s)   %d pkts  (%.0f pkt/s)   %s\n",
		float64(total)/1024/secs,
		float64(total)*8/1_000_000/secs,
		pkts, float64(pkts)/secs, elapsed.Round(100*time.Millisecond))
	fmt.Printf("Handshakes: OK=%d  FAIL=%d  PENDING=%d  (total %d workers)\n",
		hsOK, hsFail, hsPending, len(stats))

	var backBytes, backPkts int64
	for _, ws := range stats {
		backBytes += ws.bytesRecv.Load()
		backPkts += ws.pktsRecv.Load()
	}
	if backPkts > 0 {
		fmt.Printf("Return leg:  %.1f KB/s  (%.2f Mbit/s)   %d pkts  (%.0f pkt/s)   (server -echo)\n",
			float64(backBytes)/1024/secs, float64(backBytes)*8/1_000_000/secs,
			backPkts, float64(backPkts)/secs)
	}
}
