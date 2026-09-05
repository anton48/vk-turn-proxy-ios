// SPDX-License-Identifier: MIT

// tools/native_client — a console client of the app's NATIVE transport:
// DTLS-SRTP over VK TURN → our server (anton48/vk-turn-proxy with -srtp) →
// WireGuard. It is WireGuardBridge/bridge.go's two-phase sequence without
// cgo — proxy.NewProxy → Start → WaitBootstrap → turnbind → tun →
// device.NewDevice → IpcSet → Up — so the udpreorder/h3get matrix that ran
// against a csqtt server (tools/csqtt_client) can run against ours from the
// same FreeBSD stand, and the two protocols can be compared on one path.
//
// The stand:
//
//	go build -o /root/native_client ./tools/native_client
//	/root/native_client -server 161.104.59.236:56000 \
//	    -vk-link https://vk.ru/call/join/<id> \
//	    -wg-key-file /root/wg_client.key -wg-peer-key <server pubkey> \
//	    -conns 30 -route 77.88.8.8
//
// Secrets never travel on the command line or into the log: the WireGuard
// keys are read from files, and the TURN credentials are minted by the
// proxy itself exactly as the app does.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/cacggghp/vk-turn-proxy/pkg/turnbind"
)

func main() {
	server := flag.String("server", "", "our server's SRTP listener host:port — the proxy's PeerAddr, i.e. the TURN ChannelBind peer")
	vkLink := flag.String("vk-link", "", "VK call link for minting TURN credentials, e.g. https://vk.ru/call/join/<id>")
	conns := flag.Int("conns", 30, "TURN allocations; the app's default is 30 and its ceiling 60")
	turnTransport := flag.String("turn-transport", "tcp", "transport to the VK relay: tcp (what the app ships) or udp")
	keyFile := flag.String("wg-key-file", "", "file holding the WireGuard private key (base64, one line)")
	peerKey := flag.String("wg-peer-key", "", "the server's WireGuard public key (base64)")
	pskFile := flag.String("wg-psk-file", "", "optional file holding the WireGuard preshared key (base64)")
	address := flag.String("address", "10.10.0.2/24", "tunnel address in CIDR form; the gateway is the first host of that network")
	// 🚨 NOT "tun": wireguard-go creates tun0 and RENAMES it to the requested
	// name, and renaming to the bare clone prefix double-faults the FreeBSD
	// 15.1 kernel (2026-09-04, the whole host rebooted).
	tunName := flag.String("tun-name", "vktp0", "tun interface name; never a bare clone prefix such as \"tun\"")
	mtu := flag.Int("mtu", 1280, "tunnel MTU (the app's standard)")
	keepalive := flag.Int("keepalive", 25, "WireGuard persistent keepalive in seconds (0 = none); the app uses 25")
	routes := flag.String("route", "", "comma-separated hosts to route through the tunnel (IPs or names, resolved once)")
	defaultRoute := flag.Bool("default-route", false, "send the DEFAULT route through the tunnel once every connection is up; the relay host, -keep-hosts and $SSH_CLIENT are pinned to the old gateway and everything is restored on exit")
	keepHosts := flag.String("keep-hosts", "", "-default-route: comma-separated IPs that must stay on the old gateway (your SSH source, a direct-control target)")
	defaultRouteWait := flag.Duration("default-route-wait", 3*time.Minute, "-default-route: how long to wait for ALL connections before switching anyway (the app's credential pool grows 30 connections in ~2 min from a cold start)")
	duration := flag.Duration("duration", 0, "stop after this long (0 = until Ctrl-C)")
	statsEvery := flag.Duration("stats-every", 10*time.Second, "stats line interval")
	bootstrapTimeout := flag.Duration("bootstrap-timeout", 90*time.Second, "how long to wait for the first connection")
	handshakeTimeout := flag.Duration("handshake-timeout", 30*time.Second, "how long to wait for the first WireGuard handshake after Up")
	uplinkPace := flag.Int("uplink-pace", 0, "client uplink pacer, KiB/s per connection (0 = off, the app's default; 247 is the measured knee, burst 16 KiB)")
	credCache := flag.String("cred-cache", defaultCredCache(), "credential cache file, as the app's creds-pool.json; empty disables")
	wgVerbose := flag.Bool("wg-verbose", false, "wireguard-go device log at verbose level")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if *server == "" || *vkLink == "" || *keyFile == "" || *peerKey == "" {
		fmt.Fprintln(os.Stderr, "-server, -vk-link, -wg-key-file and -wg-peer-key are required")
		flag.Usage()
		os.Exit(64)
	}
	if *turnTransport != "tcp" && *turnTransport != "udp" {
		log.Fatalf("-turn-transport must be tcp or udp, not %q", *turnTransport)
	}
	if _, _, err := net.SplitHostPort(*server); err != nil {
		log.Fatalf("-server: %v", err)
	}
	privHex, err := keyHexFromFile(*keyFile)
	if err != nil {
		log.Fatalf("-wg-key-file: %v", err)
	}
	pubHex, err := keyHex(*peerKey)
	if err != nil {
		log.Fatalf("-wg-peer-key: %v", err)
	}
	var pskHex string
	if *pskFile != "" {
		if pskHex, err = keyHexFromFile(*pskFile); err != nil {
			log.Fatalf("-wg-psk-file: %v", err)
		}
	}
	gw, err := gatewayOf(*address)
	if err != nil {
		log.Fatalf("-address: %v", err)
	}
	var routeHosts []string
	for _, h := range splitCSV(*routes) {
		ips, err := net.LookupIP(h)
		if err != nil {
			log.Fatalf("resolve -route %s: %v", h, err)
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				routeHosts = append(routeHosts, ip4.String())
				break
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, options{
		server: *server, vkLink: *vkLink, conns: *conns, useUDP: *turnTransport == "udp",
		uapi:    uapiConfig(privHex, pubHex, pskHex, *server, *keepalive),
		address: *address, gateway: gw, tunName: *tunName, mtu: *mtu,
		routes: routeHosts, defaultRoute: *defaultRoute, keepHosts: splitCSV(*keepHosts), defaultRouteWait: *defaultRouteWait,
		duration: *duration, statsEvery: *statsEvery,
		bootstrapTimeout: *bootstrapTimeout, handshakeTimeout: *handshakeTimeout,
		uplinkPace: *uplinkPace, credCache: *credCache, wgVerbose: *wgVerbose,
	}))
}

type options struct {
	server, vkLink   string
	conns            int
	useUDP           bool
	uapi             string
	address, gateway string
	tunName          string
	mtu              int
	routes           []string
	defaultRoute     bool
	keepHosts        []string
	defaultRouteWait time.Duration
	duration         time.Duration
	statsEvery       time.Duration
	bootstrapTimeout time.Duration
	handshakeTimeout time.Duration
	uplinkPace       int
	credCache        string
	wgVerbose        bool
}

func run(ctx context.Context, o options) int {
	// The pacer is package state applied at both connect sites in the bridge;
	// one site here. 16 KiB is the settled burst (VKTurnProxy's UplinkPace.burstKiB).
	if o.uplinkPace > 0 {
		proxy.SetUplinkPace(o.uplinkPace, 16)
	}
	// Phase 1 — the proxy, as wgStartVKBootstrap builds it for the SRTP mode.
	// Start() blocks until the first connection is up, so it runs in its own
	// goroutine and WaitBootstrap observes the outcome; it also pins
	// GOMAXPROCS to 2, as the app does on iOS.
	p := proxy.NewProxy(proxy.Config{
		PeerAddr:      o.server,
		VKLink:        o.vkLink,
		UseDTLS:       true,
		UseSrtp:       true,
		UseUDP:        o.useUDP,
		NumConns:      o.conns,
		CredCachePath: o.credCache,
	})
	t0 := time.Now()
	log.Printf("proxy: SRTP over VK TURN (%s) → %s, %d connections, pacer %s", transportName(o.useUDP), o.server, o.conns, paceName(o.uplinkPace))
	go func() {
		if err := p.Start(); err != nil {
			log.Printf("proxy.Start: %v", err)
		}
	}()
	// Stop order is wgTurnOff's: the proxy FIRST, the device second — a
	// device closed first blocks on goroutines that are waiting on proxy I/O.
	var dev *device.Device
	defer func() {
		ps := time.Now()
		p.StopWithTimeout(2 * time.Second)
		log.Printf("proxy stopped in %s", time.Since(ps).Round(time.Millisecond))
		if dev != nil {
			ds := time.Now()
			dev.Close()
			log.Printf("device closed in %s", time.Since(ds).Round(time.Millisecond))
		}
	}()
	if err := p.WaitBootstrap(o.bootstrapTimeout); err != nil {
		log.Printf("bootstrap: %v", err)
		return 1
	}
	log.Printf("bootstrap: first connection up in %d ms via relay %s", time.Since(t0).Milliseconds(), p.TURNServerIP())

	// Phase 2 — wgAttachWireGuard: the tun, the bind over the proxy, the device.
	tdev, name, err := openTUN(o.tunName, o.mtu)
	if err != nil {
		log.Printf("tun: %v", err)
		return 1
	}
	if err := configureTUN(name, o.address, o.mtu); err != nil {
		tdev.Close()
		log.Printf("tun configure: %v", err)
		return 1
	}
	log.Printf("tun: %s %s → %s mtu %d", name, o.address, o.gateway, o.mtu)
	lvl := device.LogLevelError
	if o.wgVerbose {
		lvl = device.LogLevelVerbose
	}
	dev = device.NewDevice(proxy.WrapTUNForStats(tdev), turnbind.NewTURNBind(p), device.NewLogger(lvl, "(wireguard) "))
	if err := dev.IpcSet(o.uapi); err != nil {
		log.Printf("IpcSet: %v", err)
		return 1
	}
	if err := dev.Up(); err != nil {
		log.Printf("Up: %v", err)
		return 1
	}
	// The tunnel is not up until WireGuard has handshaken through the whole
	// chain; that is the moment that corresponds to csqtt's TUNCONF.
	hs, err := waitHandshake(ctx, dev, o.handshakeTimeout)
	if err != nil {
		log.Printf("wireguard: %v", err)
		return 1
	}
	log.Printf("wireguard: handshake in %d ms (%d ms after start)", hs.Milliseconds(), time.Since(t0).Milliseconds())

	var added []string
	defer func() {
		for _, h := range added {
			_ = deleteHostRoute(h)
		}
	}()
	for _, h := range o.routes {
		if err := addHostRoute(h, o.gateway); err != nil {
			log.Printf("route %s: %v", h, err)
			continue
		}
		added = append(added, h)
	}
	if len(added) > 0 {
		log.Printf("routes via %s: %s", o.gateway, strings.Join(added, ", "))
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if o.duration > 0 {
		rctx, cancel = context.WithTimeout(rctx, o.duration)
		defer cancel()
	}

	if o.defaultRoute {
		if restore := switchDefaultRoute(rctx, p, o); restore != nil {
			defer restore()
		}
	}

	tick := time.NewTicker(o.statsEvery)
	defer tick.Stop()
	for {
		select {
		case <-rctx.Done():
			printStats(p, dev)
			return 0
		case <-tick.C:
			printStats(p, dev)
		}
	}
}

// switchDefaultRoute moves the default route into the tunnel once EVERY
// connection is up (until then credentials are still being minted, and a
// default route through the tunnel would send those VK API calls through the
// tunnel itself — seen on the csqtt stand: 4/30 ready at the switch). Pinned
// to the old gateway first: the relay host, -keep-hosts and the SSH source.
// Returns the function that undoes it, or nil when nothing was changed.
func switchDefaultRoute(ctx context.Context, p *proxy.Proxy, o options) func() {
	waitAll := time.NewTimer(o.defaultRouteWait)
	defer waitAll.Stop()
	for {
		s := p.GetStats()
		if int(s.ActiveConns) >= o.conns {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-waitAll.C:
			log.Printf("default route: only %d/%d connections up after %s — switching anyway", s.ActiveConns, o.conns, o.defaultRouteWait)
		case <-time.After(500 * time.Millisecond):
			continue
		}
		break
	}
	oldGW, err := defaultGateway()
	if err != nil {
		log.Printf("default route: %v — not changing it", err)
		return nil
	}
	pinned := map[string]bool{}
	pin := func(h string) {
		if h == "" || pinned[h] {
			return
		}
		if err := addHostRoute(h, oldGW); err != nil {
			log.Printf("pin %s via %s: %v", h, oldGW, err)
			return
		}
		pinned[h] = true
	}
	// Anonymously the app puts every allocation on ONE relay host, and the
	// proxy reports that host; a reconnect that lands on another relay after
	// the switch would reach it through the tunnel, which works but is slower.
	pin(p.TURNServerIP())
	for _, h := range o.keepHosts {
		pin(h)
	}
	if sc := os.Getenv("SSH_CLIENT"); sc != "" {
		pin(strings.Fields(sc)[0])
	}
	if err := setDefaultGateway(o.gateway); err != nil {
		log.Printf("default route → %s: %v", o.gateway, err)
		for h := range pinned {
			_ = deleteHostRoute(h)
		}
		return nil
	}
	log.Printf("DEFAULT ROUTE → %s (old %s); pinned to the old gateway: %v", o.gateway, oldGW, keys(pinned))
	return func() {
		if err := setDefaultGateway(oldGW); err != nil {
			log.Printf("RESTORE default route → %s FAILED: %v", oldGW, err)
		} else {
			log.Printf("default route restored → %s", oldGW)
		}
		for h := range pinned {
			_ = deleteHostRoute(h)
		}
	}
}

// wgState is what the device reports over UAPI for its single peer.
type wgState struct {
	rxBytes, txBytes int64
	lastHandshake    time.Time
}

func readWG(dev *device.Device) wgState {
	var st wgState
	out, err := dev.IpcGet()
	if err != nil {
		return st
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "rx_bytes":
			st.rxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			st.txBytes, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_sec":
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 {
				st.lastHandshake = time.Unix(sec, 0)
			}
		}
	}
	return st
}

// waitHandshake polls the device until its peer reports a handshake.
func waitHandshake(ctx context.Context, dev *device.Device, timeout time.Duration) (time.Duration, error) {
	t0 := time.Now()
	deadline := time.After(timeout)
	for {
		if !readWG(dev).lastHandshake.IsZero() {
			return time.Since(t0), nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline:
			return 0, fmt.Errorf("no handshake within %s (keys, server -srtp listener, wg0 peer?)", timeout)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func printStats(p *proxy.Proxy, dev *device.Device) {
	s := p.GetStats()
	w := readWG(dev)
	hs := "never"
	if !w.lastHandshake.IsZero() {
		hs = time.Since(w.lastHandshake).Round(time.Second).String() + " ago"
	}
	log.Printf("stats: conns %d/%d · proxy tx=%.1f MB rx=%.1f MB reconnects=%d · pool filled=%d creds=%d size=%d relays=%d · turn rtt %.0f ms · wg tx=%.1f MB rx=%.1f MB handshake %s · relay %s",
		s.ActiveConns, s.TotalConns, mb(s.TxBytes), mb(s.RxBytes), s.Reconnects,
		s.CredPoolFilled, s.CredPoolWithCreds, s.CredPoolSize, s.CredPoolDistinctRelays,
		s.TurnRTTms, mb(w.txBytes), mb(w.rxBytes), hs, p.TURNServerIP())
}

func mb(b int64) float64 { return float64(b) / 1e6 }

// uapiConfig is TunnelManager.buildUAPIConfig in Go: hex keys, the peer
// address as the (ignored) endpoint, everything routed to the one peer.
func uapiConfig(privHex, pubHex, pskHex, endpoint string, keepalive int) string {
	lines := []string{
		"private_key=" + privHex,
		"replace_peers=true",
		"public_key=" + pubHex,
		"endpoint=" + endpoint,
	}
	if keepalive > 0 {
		lines = append(lines, "persistent_keepalive_interval="+strconv.Itoa(keepalive))
	}
	lines = append(lines, "allowed_ip=0.0.0.0/0")
	if pskHex != "" {
		lines = append(lines, "preshared_key="+pskHex)
	}
	return strings.Join(lines, "\n")
}

// keyHex turns a base64 WireGuard key into the hex form UAPI wants.
func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key is %d bytes, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func keyHexFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return keyHex(string(b))
}

// gatewayOf is the first host of the address's network — the server side of
// the WireGuard subnet (10.10.0.1 for 10.10.0.2/24).
func gatewayOf(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return "", errors.New("IPv4 only")
	}
	gw := append(net.IP(nil), ip4...)
	gw[3]++
	return gw.String(), nil
}

func defaultCredCache() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".native_client-creds.json")
}

func transportName(udp bool) string {
	if udp {
		return "udp"
	}
	return "tcp"
}

func paceName(kib int) string {
	if kib <= 0 {
		return "off"
	}
	return strconv.Itoa(kib) + " KiB/s"
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
