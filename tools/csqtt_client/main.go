// SPDX-License-Identifier: MIT

// tools/csqtt_client — a console client for a csqtt server over VK TURN, the
// staging ground for pkg/csqtt before it becomes a transport of the iOS app.
//
// Stage 2 (this file): ONE worker. Mint VK TURN credentials the way the app
// does, allocate a relay, GETCONF → TUNCONF, READY → READY_OK, then send
// hand-built ICMP echoes through the tunnel and read the replies back. No
// TUN device is involved, so this runs anywhere Go does; the independent
// instrument is the server's own log ("GETCONF … -> TUNCONF" for our
// device id).
//
//	go build -o /tmp/csqtt_client ./tools/csqtt_client
//	/tmp/csqtt_client -server elizabeth.48.org:46000 -password <pw> \
//	    -vk-link https://vk.ru/call/join/<id>
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"crypto/rand"

	"github.com/pion/logging"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

func main() {
	server := flag.String("server", "", "csqtt server host:port (the TURN peer)")
	password := flag.String("password", "", "connection password (HKDF key material AND GETCONF auth)")
	vkLink := flag.String("vk-link", "", "VK call link for minting TURN credentials, e.g. https://vk.ru/call/join/<id>")
	turnCreds := flag.String("turn-creds", "", "DIAGNOSTIC: skip VK and use user:pass@host:port for the relay")
	deviceID := flag.String("device-id", "", "device id (default: random 16 hex; the server binds the password to the first one it sees)")
	generation := flag.Uint64("gen", 0, "generation id (default: from the clock); a new (gen, salt) pair replaces every older session of this device")
	salt := flag.String("salt", "", "session salt (default: random 16 hex)")
	modeName := flag.String("mode", "audio", "obfuscation mode: audio (PT 111, ChaCha) or video (PT 96, SRTP-like)")
	revision := flag.String("revision", csqtt.WireRevision, "wire revision to announce ("+csqtt.WireRevision+" or "+csqtt.LegacyWireRevision+")")
	workers := flag.Int("workers", 1, "desired worker count announced in GETCONF (this stage runs worker 1 only)")
	pings := flag.Int("pings", 5, "ICMP echoes to send through the tunnel")
	pingTarget := flag.String("ping", "", "ICMP echo target (default: the tunnel gateway, .1 of our /24)")
	pingInterval := flag.Duration("ping-interval", time.Second, "interval between echoes")
	stay := flag.Duration("stay", 0, "keep the session open this long after the echoes (0 = disconnect at once)")
	verbose := flag.Bool("v", false, "hex-dump every datagram")
	turnTransport := flag.String("turn-transport", "udp", "control transport to the VK relay: udp (the reference client's default) or tcp (what the iOS app ships)")
	turnDebug := flag.Bool("turn-debug", false, "trace every STUN/TURN transaction (pion logger at trace level)")
	tunMode := flag.Bool("tun", false, "stage 3: bring up a real tun with -workers workers and route -route hosts through it (FreeBSD)")
	// 🚨 NOT "tun": wireguard-go creates tun0 and RENAMES it to the requested
	// name, and renaming to the bare clone prefix double-faults the FreeBSD
	// 15.1 kernel ("tun0: changing name to 'tun'" → "panic: double fault",
	// 2026-09-04, the whole host rebooted). A normal name like wg0/csqtt0 is
	// the path every wireguard-go user takes.
	tunName := flag.String("tun-name", "csqtt0", "tun interface name; never a bare clone prefix such as \"tun\"")
	mtu := flag.Int("mtu", 1300, "tunnel MTU (the server's TUN is 1300)")
	routes := flag.String("route", "", "comma-separated hosts to route through the tunnel (IPs or names, resolved once)")
	duration := flag.Duration("duration", 0, "-tun: stop after this long (0 = until Ctrl-C)")
	statsEvery := flag.Duration("stats-every", 10*time.Second, "-tun: stats line interval")
	allocsPerCred := flag.Int("allocs-per-cred", 8, "-tun: workers served by one minted VK credential before minting the next")
	dupTCP := flag.Bool("dup-tcp", false, "EXPERIMENT: send a copy of every CQF1-framed TCP packet through a second worker")
	faultWorker := flag.Int("fault-worker", 0, "FAULT INJECTION: blackhole this worker id (1-based) -fault-after after the tunnel is up")
	faultAfter := flag.Duration("fault-after", 0, "FAULT INJECTION: when to blackhole -fault-worker")
	defaultRoute := flag.Bool("default-route", false, "-tun: send the DEFAULT route through the tunnel; relay hosts, -keep-hosts and $SSH_CLIENT are pinned to the old gateway and everything is restored on exit")
	keepHosts := flag.String("keep-hosts", "", "-default-route: comma-separated IPs that must stay on the old gateway (your SSH source, monitoring)")
	relayPolicy := flag.String("relay", "first", "which relay each worker gets: first (one relay host for all, as the app does anonymously) or rotate (spread over the addresses VK returned)")
	chunksFlag := flag.String("chunks", "", "-tun: striping chunks small,medium,bulk (default 4,16,32); 1,1,1 is pure per-packet round robin")
	flag.Parse()
	genSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "gen" {
			genSet = true
		}
	})

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if *server == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "-server and -password are required")
		flag.Usage()
		os.Exit(64)
	}
	if *vkLink == "" && *turnCreds == "" {
		fmt.Fprintln(os.Stderr, "one of -vk-link or -turn-creds is required")
		os.Exit(64)
	}
	mode, err := csqtt.ParseMode(*modeName)
	if err != nil {
		log.Fatal(err)
	}
	if *deviceID == "" {
		*deviceID = randomHex(8)
	}
	if *salt == "" || !genSet {
		// A new connection carries a new (generation, salt) pair; the salt
		// alone is not enough for the server's epoch rule.
		gen, s := csqtt.NewIdentity(0)
		if *salt == "" {
			*salt = s
		}
		if !genSet {
			*generation = gen
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	peer, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		log.Fatalf("resolve server: %v", err)
	}
	log.Printf("server %s → %s  device=%s gen=%d salt=%s mode=%s revision=%s", *server, peer, *deviceID, *generation, *salt, *modeName, *revision)

	if *tunMode {
		var manual *proxy.TURNCreds
		if *turnCreds != "" {
			if manual, err = parseManualCreds(*turnCreds); err != nil {
				log.Fatal(err)
			}
		}
		var hosts []string
		for _, h := range strings.Split(*routes, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			ips, err := net.LookupIP(h)
			if err != nil {
				log.Fatalf("resolve -route %s: %v", h, err)
			}
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					hosts = append(hosts, ip4.String())
					break
				}
			}
		}
		var chunks [3]int
		if *chunksFlag != "" {
			if _, err := fmt.Sscanf(*chunksFlag, "%d,%d,%d", &chunks[0], &chunks[1], &chunks[2]); err != nil {
				log.Fatalf("-chunks must be three integers: %v", err)
			}
		}
		os.Exit(runTunnel(ctx, tunnelOptions{
			server: peer, password: *password, deviceID: *deviceID, generation: *generation, salt: *salt,
			mode: mode, revision: *revision, workers: *workers, turnTransport: *turnTransport, turnDebug: *turnDebug,
			vkLink: *vkLink, manualCreds: manual, allocsPerCred: *allocsPerCred,
			tunName: *tunName, mtu: *mtu, routes: hosts, duration: *duration, statsEvery: *statsEvery, chunks: chunks, dupTCP: *dupTCP, relayPolicy: *relayPolicy,
			faultWorker: *faultWorker, faultAfter: *faultAfter,
			defaultRoute: *defaultRoute, keepHosts: splitCSV(*keepHosts),
		}))
	}

	// ── credentials ──────────────────────────────────────────────────────
	var creds *proxy.TURNCreds
	if *turnCreds != "" {
		creds, err = parseManualCreds(*turnCreds)
	} else {
		linkID := path.Base(mustURL(*vkLink).Path)
		log.Printf("vk: minting TURN credentials for link id %s…", linkID)
		creds, err = proxy.GetVKCreds(linkID, nil, "", "", 0, 0, "", "")
	}
	if err != nil {
		log.Fatalf("credentials: %v", err)
	}
	log.Printf("turn: relay %s (of %d) user=%s", creds.Address, len(creds.Addresses), creds.Username)

	// ── allocation ───────────────────────────────────────────────────────
	lvl := logging.LogLevelWarn
	if *turnDebug {
		lvl = logging.LogLevelTrace
	}
	t0 := time.Now()
	relay, err := csqtt.DialRelay(csqtt.TURNCredentials{Username: creds.Username, Password: creds.Password, Address: creds.Address}, peer, *turnTransport, lvl)
	if err != nil {
		log.Fatalf("allocate: %v", err)
	}
	defer relay.Close()
	log.Printf("turn: allocated %s in %d ms (%s control, local %s)", relay.Conn.LocalAddr(), time.Since(t0).Milliseconds(), *turnTransport, relay.Local)

	// ── obfuscation ──────────────────────────────────────────────────────
	key, err := csqtt.DeriveKey(*password)
	if err != nil {
		log.Fatal(err)
	}
	cipher, err := csqtt.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	wrapper, err := csqtt.NewWrapper(cipher, mode)
	if err != nil {
		log.Fatal(err)
	}
	s := &session{
		relay: relay.Conn, peer: peer, cipher: cipher, wrapper: wrapper, mode: mode,
		inbound: make(chan []byte, 256), verbose: *verbose,
		wireBuf: make([]byte, 0, 2048),
	}
	go s.readLoop()

	// ── handshake ────────────────────────────────────────────────────────
	req := csqtt.ConfigRequest("9000", *deviceID, *password, *generation, *salt, 1, *workers, *revision)
	log.Printf("→ %s", strings.Replace(req, *password, "***", 1))
	conf, err := s.getconf(ctx, req)
	if err != nil {
		log.Fatalf("GETCONF: %v", err)
	}
	log.Printf("tunnel ip %s, dns %s, frames=%v", conf.TunnelIP, conf.DNS, conf.FramesData())

	if err := s.send([]byte(csqtt.ReadyRequest)); err != nil {
		log.Fatalf("READY: %v", err)
	}
	if p := s.waitFor(ctx, 3*time.Second, func(p []byte) bool { return string(p) == csqtt.ReadyOK }); p == nil {
		log.Printf("no READY_OK within 3 s (not a gate; the server also sets the tunnel up on first data)")
	}

	// ── ICMP through the tunnel ──────────────────────────────────────────
	src := net.ParseIP(conf.TunnelIP).To4()
	if src == nil {
		log.Fatalf("tunnel ip %q is not IPv4", conf.TunnelIP)
	}
	dst := gatewayOf(src)
	if *pingTarget != "" {
		if dst = net.ParseIP(*pingTarget).To4(); dst == nil {
			log.Fatalf("-ping %q is not IPv4", *pingTarget)
		}
	}
	id := uint16(binary.BigEndian.Uint16(randomBytes(2)))
	log.Printf("icmp: %s → %s, id %#x, %d echoes", src, dst, id, *pings)
	var okCount int
	for i := 1; i <= *pings && ctx.Err() == nil; i++ {
		pkt := icmpEcho(src, dst, id, uint16(i), 56)
		t0 := time.Now()
		if err := s.send(pkt); err != nil {
			log.Printf("echo %d: send: %v", i, err)
			continue
		}
		reply := s.waitFor(ctx, *pingInterval, func(p []byte) bool {
			rid, rseq, ok := icmpEchoReply(p, dst, src)
			return ok && rid == id && rseq == uint16(i)
		})
		if reply != nil {
			okCount++
			log.Printf("echo %d: reply from %s in %.1f ms (%d B)", i, dst, float64(time.Since(t0).Microseconds())/1000, len(reply))
		} else {
			log.Printf("echo %d: no reply within %s", i, *pingInterval)
		}
	}
	log.Printf("icmp: %d/%d replies", okCount, *pings)

	if *stay > 0 {
		log.Printf("staying %s (Ctrl-C to disconnect)…", *stay)
		s.idle(ctx, *stay)
	}

	// ── disconnect ───────────────────────────────────────────────────────
	dreq := csqtt.DisconnectRequest(*deviceID, *salt)
	log.Printf("→ %s", dreq)
	if err := s.send([]byte(dreq)); err == nil {
		s.waitFor(context.Background(), time.Second, func(p []byte) bool { return string(p) == csqtt.DisconnectedResponse })
	}
	log.Printf("stats: sent=%d recv=%d non-rtp-dropped=%d unwrap-errors=%d control=%d data=%d",
		s.sent.Load(), s.recv.Load(), s.nonRTP.Load(), s.unwrapErr.Load(), s.control.Load(), s.data.Load())
	if okCount == 0 && *pings > 0 {
		os.Exit(1)
	}
}

// ─── session ─────────────────────────────────────────────────────────────

type session struct {
	relay   net.PacketConn
	peer    *net.UDPAddr
	cipher  *csqtt.Cipher
	wrapper *csqtt.Wrapper
	mode    csqtt.Mode
	inbound chan []byte
	verbose bool
	wireBuf []byte

	sent, recv, nonRTP, unwrapErr, control, data atomic.Int64
}

// send wraps one plaintext and writes it to the server through the relay.
// The wrapper is not concurrency-safe; every send goes through this method
// from the main goroutine.
func (s *session) send(plain []byte) error {
	wire, err := s.wrapper.Wrap(s.wireBuf, plain)
	if err != nil {
		return err
	}
	if s.verbose {
		log.Printf("tx %d B: %s", len(wire), hex.EncodeToString(wire))
	}
	if _, err := s.relay.WriteTo(wire, s.peer); err != nil {
		return err
	}
	s.sent.Add(1)
	return nil
}

// readLoop turns relay datagrams into plaintexts. Every control message is
// logged HERE and nowhere else, so the log shows exactly what arrived —
// including the server's duplicates: it sends each control reply twice,
// back to back (its selective-FEC duplication covers control strings), so
// TUNCONF and READY_OK legitimately appear in pairs and the main loop must
// take the first and tolerate the second.
func (s *session) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.relay.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("relay read: %v", err)
			}
			close(s.inbound)
			return
		}
		wire := buf[:n]
		if s.verbose {
			log.Printf("rx %d B from %s: %s", n, from, hex.EncodeToString(wire))
		}
		if !csqtt.IsRTP(wire) {
			s.nonRTP.Add(1)
			continue
		}
		plain, _, err := s.cipher.Unwrap(s.mode, wire)
		if err != nil {
			s.unwrapErr.Add(1)
			log.Printf("unwrap: %v", err)
			continue
		}
		s.recv.Add(1)
		if csqtt.IsControl(plain) || csqtt.IsIdleKeepalive(plain) {
			s.control.Add(1)
			s.logControl(plain)
		} else {
			s.data.Add(1)
		}
		cp := append([]byte(nil), plain...)
		select {
		case s.inbound <- cp:
		default:
			log.Printf("inbound queue full, dropping %d B", len(cp))
		}
	}
}

func (s *session) logControl(p []byte) {
	switch {
	case csqtt.IsPanelRestart(p):
		log.Printf("← PANEL_RESTART (server restarting)")
	case len(p) > 0 && p[0] == 0xff:
		if cmd, ok := csqtt.ParseStreamRepair(p); ok {
			log.Printf("← STREAM_REPAIR seq=%d desired=%d restart=%v", cmd.Sequence, cmd.DesiredCount, cmd.WorkerIDs)
		} else if cmd, ok := csqtt.ParseStreamAlive(p); ok {
			log.Printf("← STREAM_ALIVE seq=%d desired=%d alive=%v", cmd.Sequence, cmd.DesiredCount, cmd.WorkerIDs)
		} else if csqtt.IsIdleKeepalive(p) {
			log.Printf("← keepalive (%d B)", len(p))
		} else {
			log.Printf("← unknown control %x", p)
		}
	default:
		log.Printf("← %s", p)
	}
}

// waitFor drains inbound until match accepts a plaintext or the timeout.
func (s *session) waitFor(ctx context.Context, timeout time.Duration, match func([]byte) bool) []byte {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case p, ok := <-s.inbound:
			if !ok {
				return nil
			}
			if match(p) {
				return p
			}
		}
	}
}

// getconf follows the reference client's schedule: three attempts with
// 750 / 1500 / 3000 ms waits, ignoring anything that is not a config reply.
func (s *session) getconf(ctx context.Context, req string) (csqtt.ConfigResponse, error) {
	for _, wait := range []time.Duration{750 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second} {
		if err := s.send([]byte(req)); err != nil {
			return csqtt.ConfigResponse{}, err
		}
		if p := s.waitFor(ctx, wait, csqtt.IsConfigResponse); p != nil {
			return csqtt.ParseConfigResponse(p)
		}
		log.Printf("GETCONF: no reply within %s, retrying", wait)
	}
	return csqtt.ConfigResponse{}, errors.New("the server did not answer GETCONF (wrong password is silence; check the server log)")
}

// idle keeps the session alive with the server-side keepalive payload and
// logs whatever the server pushes meanwhile.
func (s *session) idle(ctx context.Context, d time.Duration) {
	end := time.After(d)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-end:
			return
		case <-tick.C:
			if err := s.send(csqtt.IdleKeepalive); err != nil {
				log.Printf("keepalive: %v", err)
			}
		case p, ok := <-s.inbound:
			if !ok {
				return
			}
			if !csqtt.IsControl(p) && !csqtt.IsIdleKeepalive(p) {
				log.Printf("← data %d B (unsolicited)", len(p))
			}
		}
	}
}

func parseManualCreds(s string) (*proxy.TURNCreds, error) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return nil, errors.New("-turn-creds must be user:pass@host:port")
	}
	user, pass, ok := strings.Cut(s[:at], ":")
	if !ok {
		return nil, errors.New("-turn-creds must be user:pass@host:port")
	}
	addr := s[at+1:]
	return &proxy.TURNCreds{Username: user, Password: pass, Address: addr, Addresses: []string{addr}}, nil
}

// ─── ICMP ─────────────────────────────────────────────────────────────────

// icmpEcho builds an IPv4 ICMP echo request from src to dst with a payload
// of the given length, checksums filled.
func icmpEcho(src, dst net.IP, id, seq uint16, payloadLen int) []byte {
	pkt := make([]byte, 20+8+payloadLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	icmp := pkt[20:]
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	for i := 8; i < len(icmp); i++ {
		icmp[i] = byte(i)
	}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return pkt
}

// icmpEchoReply parses an IPv4 packet and reports the id/seq of an ICMP echo
// reply from `from` to `to`.
func icmpEchoReply(p []byte, from, to net.IP) (id, seq uint16, ok bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 {
		return 0, 0, false
	}
	hl := int(p[0]&0x0f) * 4
	if hl < 20 || len(p) < hl+8 {
		return 0, 0, false
	}
	if !net.IP(p[12:16]).Equal(from) || !net.IP(p[16:20]).Equal(to) {
		return 0, 0, false
	}
	icmp := p[hl:]
	if icmp[0] != 0 { // echo reply
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(icmp[4:6]), binary.BigEndian.Uint16(icmp[6:8]), true
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// gatewayOf is .1 of the tunnel's /24 — the server side of the TUN.
func gatewayOf(ip net.IP) net.IP {
	gw := append(net.IP(nil), ip.To4()...)
	gw[3] = 1
	return gw
}

// ─── misc ─────────────────────────────────────────────────────────────────

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("-vk-link: %v", err)
	}
	return u
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func randomHex(n int) string { return hex.EncodeToString(randomBytes(n)) }

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
