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

	"github.com/cacggghp/vk-turn-proxy/tools/srtpwrap"
)

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
		transport     = flag.String("transport", "udp", "TURN control transport: udp or tcp (relayed data is always UDP via Allocate())")
		verbose       = flag.Bool("v", false, "enable pion debug logs")
	)
	flag.Parse()

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

	ctx, cancel := context.WithTimeout(context.Background(), *duration+30*time.Second)
	defer cancel()

	totalWorkers := len(picked) * *allocsPerCred
	stats := make([]*workerStats, 0, totalWorkers)
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

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
				if err := runWorker(ctx, cred, relay, dstAddr, ws, startBarrier, *duration, *pktSize, *spacing, *transport, *verbose, wIdx); err != nil {
					log.Printf("[w%d slot=%d.%d] worker error: %v", wIdx, cred.Slot, sub, err)
				}
			}(workerIdx, sub, c, ws)
		}
	}

	// Wait for all workers to reach the barrier (handshakes done)
	// then start the print loop and release barrier.
	time.Sleep(500 * time.Millisecond) // give workers a head start to begin allocate
	close(startBarrier)
	testStart := time.Now()

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

	fmt.Println()
	fmt.Println("=== FINAL ===")
	printRate(stats, time.Since(testStart))
	printSummary(stats, time.Since(testStart))
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
	ws *workerStats, startBarrier chan struct{}, dur time.Duration,
	pktSize int, spacing time.Duration, transport string, verbose bool, idx int,
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

	// Wait for the start barrier so all workers begin sending at the
	// same time (cleaner aggregate measurement).
	select {
	case <-startBarrier:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Perform DTLS+SRTP handshake on top of the relayed conn.
	hsCtx, hsCancel := context.WithTimeout(ctx, srtpwrap.HandshakeTimeout)
	srtpConn, err := srtpwrap.Client(hsCtx, relayedConn, dst)
	hsCancel()
	if err != nil {
		ws.hsErr.Store(err)
		return fmt.Errorf("srtp handshake: %w", err)
	}
	ws.hsOK.Store(true)
	defer srtpConn.Close()
	log.Printf("[w%d slot=%d.%d] DTLS+SRTP handshake done", idx, cred.Slot, ws.subIdx)

	// Send loop.
	payload := make([]byte, pktSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := srtpConn.Write(payload)
		if err != nil {
			ws.sendErrs.Add(1)
			// short backoff to avoid hot-spin on persistent error
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ws.bytesSent.Add(int64(n))
		ws.pktsSent.Add(1)
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
		fmt.Printf("  slot=%-2d.%-2d relay=%-25s %s   %.1f KB/s   pkts=%d  errs=%d\n",
			ws.slot, ws.subIdx, ws.relayAddr, hs, bps/1024,
			ws.pktsSent.Load(), ws.sendErrs.Load())
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
	fmt.Printf("Aggregate:  %.1f KB/s  (%.2f Mbit/s)   %d pkts   %s\n",
		float64(total)/1024/secs,
		float64(total)*8/1_000_000/secs,
		pkts, elapsed.Round(100*time.Millisecond))
	fmt.Printf("Handshakes: OK=%d  FAIL=%d  PENDING=%d  (total %d workers)\n",
		hsOK, hsFail, hsPending, len(stats))
}
