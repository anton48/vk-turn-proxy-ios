// SPDX-License-Identifier: MIT

// vk-turn-proxy-console — the app's native transport as a console client for
// macOS, Linux and FreeBSD: WireGuard over DTLS-SRTP over VK's TURN relays to
// our server (anton48/vk-turn-proxy, -srtp), with the default route and the
// system DNS through the tunnel.
//
//	sudo ./vk-turn-proxy-console                    # vk-turn-proxy-console.json here
//	sudo ./vk-turn-proxy-console -config ~/backup.json -server Home
//	sudo ./vk-turn-proxy-console -default-route=false -route 192.0.2.10
//	sudo ./vk-turn-proxy-console -cleanup           # after a crash: take the changes back
//
// The config is the app's full backup (config.go). The credentials are minted
// by the proxy exactly as in the app — the VK Calls path and the automatic
// captcha solver; the console has no WebView, so a captcha the solver cannot
// pass is asked again every two minutes. -vk-cookie-file turns on the
// authenticated (VKAuth) mode from a browser's cookies.txt.
//
// The proxy's own traffic stays off the tunnel by /32 routes via the physical
// gateway made when each destination is dialled (pins.go); every change to the
// system is journaled with its undo before it is made (state.go).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/cacggghp/vk-turn-proxy/pkg/turnbind"
)

// version is set by the release build: -ldflags "-X main.version=<tag>".
var version = "dev"

type options struct {
	configPath, serverName string
	list, cleanup, version bool

	peer, turnTransport, dns, vkLink, turnServer string
	conns, poolReserve, mtu, uplinkPace          int

	defaultRoute     bool
	defaultRouteWait time.Duration
	blockIPv6        bool
	keepHosts, route string

	credCache, stateFile, cookieFile string
	logFile                          string
	gomaxprocs, keepalive            int
	statsEvery                       time.Duration
	tunName                          string
	wgVerbose                        bool

	set map[string]bool // the flags given on the command line
}

func parseFlags(args []string) (*options, error) {
	o := &options{set: map[string]bool{}}
	fs := flag.NewFlagSet("vk-turn-proxy-console", flag.ContinueOnError)
	fs.StringVar(&o.configPath, "config", "vk-turn-proxy-console.json", "the app's full backup (Backup & Restore → Export Full Backup…)")
	fs.StringVar(&o.serverName, "server", "", "the server's NAME in the backup (default: the first server of the native SRTP mode)")
	fs.BoolVar(&o.list, "list", false, "list the backup's servers and exit")
	fs.StringVar(&o.peer, "peer", "", "override the server's address (host:port of its SRTP listener)")
	fs.IntVar(&o.conns, "conns", 0, fmt.Sprintf("connections (TURN allocations), 1…%d; default: the server's own (30 when it has none)", maxConns))
	fs.IntVar(&o.poolReserve, "pool-reserve", 1, "reserve credential sets: the pool holds (1 + R) × ceil(conns/10) identities; one set rides a network change without a mint, 3 is the app's layout")
	fs.StringVar(&o.turnTransport, "turn-transport", "", "tcp or udp to the VK relay (default: the server's setting; the app ships tcp)")
	fs.IntVar(&o.mtu, "mtu", 0, "tunnel MTU (default: the backup's; 1280 when automatic)")
	fs.StringVar(&o.dns, "dns", "", "DNS while the default route is in the tunnel: a comma-separated list replacing the server's dnsServers, or false to leave the system's alone")
	fs.IntVar(&o.uplinkPace, "uplink-pace", -1, "uplink pacer, KiB/s per connection (0 = off; default: the backup's; 247 is the measured knee)")
	fs.StringVar(&o.vkLink, "vk-link", "", "a VK call link replacing the backup's list")
	fs.StringVar(&o.turnServer, "turn-server", "", "override the TURN relay (host:port), as the server's turnServerOverride")
	fs.BoolVar(&o.defaultRoute, "default-route", true, "send everything through the tunnel (false: only the tunnel's subnet and -route)")
	fs.DurationVar(&o.defaultRouteWait, "default-route-wait", 2*time.Second, "after the first WireGuard handshake, wait this long for every connection before moving the default route anyway")
	fs.BoolVar(&o.blockIPv6, "block-ipv6", false, "send IPv6 into the tunnel too, where it is dropped (the tunnel carries IPv4 only; without it IPv6 goes around the tunnel)")
	fs.StringVar(&o.keepHosts, "keep-hosts", "", "comma-separated hosts that stay on the physical path (the SSH client is kept by itself)")
	fs.StringVar(&o.route, "route", "", "-default-route=false: comma-separated hosts routed into the tunnel")
	fs.StringVar(&o.credCache, "cred-cache", ".vk-turn-proxy-console-creds.json", "the console's own TURN credential cache (never the backup's)")
	fs.StringVar(&o.stateFile, "state-file", ".vk-turn-proxy-console-state.json", "where the changes to the system are journaled with their undo")
	fs.BoolVar(&o.cleanup, "cleanup", false, "take back what a crashed run left (the state file) and exit")
	fs.StringVar(&o.logFile, "log", "", "write the log to this file as well as to stderr (appended; created 0600 and handed to the sudo user)")
	fs.StringVar(&o.cookieFile, "vk-cookie-file", "", "a VK login as Netscape cookies.txt: the authenticated (VKAuth) mode")
	fs.IntVar(&o.gomaxprocs, "gomaxprocs", 0, "scheduler threads (0 = every core, Go's default)")
	fs.DurationVar(&o.statsEvery, "stats-every", 30*time.Second, "stats line interval (0 = none)")
	fs.StringVar(&o.tunName, "tun-name", defaultTunName, "the tunnel interface (macOS: utun, numbered by the system)")
	fs.IntVar(&o.keepalive, "keepalive", 25, "WireGuard persistent keepalive, seconds (the app's 25)")
	fs.BoolVar(&o.wgVerbose, "wg-verbose", false, "wireguard-go's own log, verbose")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	return o, nil
}

// dnsPlan: whether the console points the system at the tunnel's DNS, and at
// which servers.
type dnsPlan struct {
	managed bool
	servers []string
}

// applyTo puts the command line's overrides over the backup's settings — only
// the flags actually given.
func (o *options) applyTo(st *settings) (dnsPlan, error) {
	if o.set["peer"] {
		st.PeerAddress = o.peer
	}
	if o.set["conns"] {
		st.NumConns = o.conns
	}
	if o.set["turn-transport"] {
		switch o.turnTransport {
		case "tcp":
			st.UseUDP = false
		case "udp":
			st.UseUDP = true
		default:
			return dnsPlan{}, fmt.Errorf("-turn-transport %q: tcp or udp", o.turnTransport)
		}
	}
	if o.set["mtu"] {
		st.MTU = resolveMTU(o.mtu)
	}
	if o.set["uplink-pace"] && o.uplinkPace >= 0 {
		st.UplinkPaceKiB = o.uplinkPace
	}
	if o.set["vk-link"] {
		st.VKLinks = splitLinks(o.vkLink)
	}
	if o.set["turn-server"] {
		h, p, ok := parseTurnOverride(o.turnServer)
		if !ok {
			return dnsPlan{}, fmt.Errorf("-turn-server %q: host:port", o.turnServer)
		}
		st.TurnServer, st.TurnPort = h, p
	}
	if o.set["pool-reserve"] && o.poolReserve < 0 {
		return dnsPlan{}, errors.New("-pool-reserve: 0 or more")
	}
	plan := dnsPlan{managed: o.defaultRoute, servers: st.DNSServers}
	if o.set["dns"] {
		switch strings.ToLower(strings.TrimSpace(o.dns)) {
		case "false", "off", "no", "none":
			plan.managed = false
		default:
			var list []string
			for _, f := range strings.Split(o.dns, ",") {
				if f = strings.TrimSpace(f); f == "" {
					continue
				}
				if net.ParseIP(f) == nil {
					return dnsPlan{}, fmt.Errorf("-dns: %q is not an IP address", f)
				}
				list = append(list, f)
			}
			plan.servers = list
		}
	}
	if len(plan.servers) == 0 {
		plan.managed = false
	}
	return plan, nil
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	ignoreBrokenPipe() // before the first byte is written: see the function
	o, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if o.version {
		fmt.Println("vk-turn-proxy-console", version)
		return 0
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if o.logFile != "" {
		f, err := openLog(o.logFile, os.Getenv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-log: %v\n", err)
			return 2
		}
		// Never closed: the proxy's goroutines go on logging behind its stop
		// — the last connection stats — until the process exits, and the file
		// holds every line stderr does (a close here cut that block short).
		log.SetOutput(fanout{os.Stderr, f})
		log.Printf("vk-turn-proxy-console %s started %s (pid %d), log %s", version, time.Now().Format("2006-01-02 15:04:05 -0700"), os.Getpid(), o.logFile)
	}
	if o.cleanup {
		if err := requireRoot(); err != nil {
			log.Print(err)
			return 1
		}
		if _, err := recoverLeftovers(o.stateFile, quiet(runCmd), log.Printf); err != nil {
			log.Printf("cleanup: %v", err)
			return 1
		}
		log.Printf("cleanup: nothing left to take back (%s)", o.stateFile)
		return 0
	}
	b, err := loadBackup(o.configPath)
	if err != nil {
		log.Print(err)
		return 2
	}
	if o.list {
		for _, s := range b.servers() {
			mark := " "
			if s.native() {
				mark = "*"
			}
			fmt.Printf("%s %-24q %-18s %d connections\n", mark, s.Name, s.mode(), s.NumConnections)
		}
		fmt.Println("* = the native SRTP mode, the one the console carries")
		return 0
	}
	srv, err := selectServer(b.servers(), o.serverName)
	if err != nil {
		log.Print(err)
		return 2
	}
	st := buildSettings(b, srv)
	plan, err := o.applyTo(&st)
	if err != nil {
		log.Print(err)
		return 2
	}
	if err := st.validate(); err != nil {
		log.Print(err)
		return 2
	}
	if configReadableByOthers(o.configPath) {
		log.Printf("WARNING: %s is readable by other users and holds the WireGuard private key — chmod 600 it", o.configPath)
	}
	cookie := ""
	if o.cookieFile != "" {
		f, err := os.Open(o.cookieFile)
		if err != nil {
			log.Printf("-vk-cookie-file: %v", err)
			return 2
		}
		cookies, err := parseNetscapeCookies(f)
		f.Close()
		if err != nil {
			log.Printf("-vk-cookie-file: %v", err)
			return 2
		}
		var exp time.Time
		if cookie, exp, err = vkCookieHeader(cookies, time.Now()); err != nil {
			log.Printf("-vk-cookie-file: %v", err)
			return 2
		}
		st.VKAuth = true
		if !exp.IsZero() {
			log.Printf("VK login from %s, valid until %s", o.cookieFile, exp.Format("2006-01-02"))
		}
	} else if st.VKAuth {
		log.Printf("the backup has the VK login (vkAuth) on and the console has no login of its own: give -vk-cookie-file <cookies.txt> exported from a browser logged in to VK")
		return 2
	}
	if err := requireRoot(); err != nil {
		log.Print(err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	c := &console{o: o, st: st, dnsPlan: plan, cookie: cookie}
	return c.run(ctx)
}

// ignoreBrokenPipe: a dead log must not kill a process that owes a cleanup.
// A write to a closed pipe on stdout or stderr ends a Go program with SIGPIPE
// unless the signal is ignored — and that is what Ctrl-C does to
// `console 2>&1 | tee file`: the terminal signals the whole foreground
// group, tee dies of it, and the console's next log line is a write to a
// broken pipe. It died in the middle of its shutdown, the DNS and the split
// routes taken back and the pins left — pointing at the gateway of a network
// the machine then left, with that network's own DNS servers among them (the
// field, 2026-09-30; reproduced on a stand: exit 141). With the signal
// ignored the write fails, the log package drops the line, and the shutdown
// goes on to its end.
func ignoreBrokenPipe() {
	signal.Ignore(syscall.SIGPIPE)
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run it as root (sudo): the console creates a tunnel interface and changes the routing table and the DNS")
	}
	return nil
}

// quiet adapts runCmd to the undo runner's shape.
func quiet(run func([]string) (string, error)) func([]string) error {
	return func(argv []string) error {
		_, err := run(argv)
		return err
	}
}

// noCaptchaUI is the proxy's captcha solver in a console: there is no WebView
// to show VK's «I'm not a robot» page in. Unreachable today — every pool path
// asks VK with the solver off and publishes a captcha instead of blocking
// (proxy.fetchFreshCreds, allowCaptchaBlock=false) — and set all the same:
// NewProxy's default would wait for an answer from a UI that does not exist.
func noCaptchaUI(string) (string, error) {
	return "", errors.New("the console has no captcha UI")
}

type console struct {
	o       *options
	st      settings
	dnsPlan dnsPlan
	cookie  string

	j     *journal
	pin   *pinner
	dns   systemDNS
	src   *dnsSource
	p     *proxy.Proxy
	dev   *device.Device
	tun   string
	ticks int // the network monitor's, for the DNS refresh's pace
}

func (c *console) run(ctx context.Context) int {
	if why := v6BlockRefusal(c.o.blockIPv6, c.o.defaultRoute, sshPeers(), ipv6Networks()); why != "" {
		log.Print(why)
		return 2
	}
	prev, err := recoverLeftovers(c.o.stateFile, quiet(runCmd), log.Printf)
	if err != nil {
		log.Printf("state: %v", err)
		return 1
	}
	if trustCachedIdentities(prev) {
		if n := forgetLastUse(c.o.credCache); n > 0 {
			log.Printf("credentials: %d cached identities usable at once — the previous run closed its allocations", n)
		}
	}
	c.j = newJournal(c.o.stateFile)
	c.j.setTransport(transportName(c.st.UseUDP))
	if err := c.j.save(); err != nil {
		log.Printf("state: %v — the console journals every change before it makes it, and cannot", err)
		return 1
	}
	defer c.shutdown()

	// The network as it is, before anything changes: its default route and
	// its own DNS servers (the proxy resolves VK through them).
	gw, up := readDefaultRoute()
	if up {
		log.Printf("network: via %s", gw)
	} else {
		log.Printf("network: no default route yet — waiting for one")
	}
	c.dns = newSystemDNS(c.j, runCmd, log.Printf)
	c.src = &dnsSource{}
	c.src.set(c.dns.refresh(gw))

	_, tunnelNet, _ := net.ParseCIDR(c.st.TunnelAddress)
	c.pin = newPinner(hostCmds, runCmd, c.j, log.Printf)
	c.pin.tunnel = tunnelNet
	if c.dnsPlan.managed {
		for _, s := range c.dnsPlan.servers {
			c.pin.never[s] = true
		}
	}
	c.pin.blockV6 = c.o.blockIPv6 && c.o.defaultRoute
	c.pin.enable(c.o.defaultRoute)
	c.pin.setGateway(gw, up, interfaceSubnets(gw.Iface))
	proxy.SetDialHook(c.pin.hook)
	installResolver(c.src, c.pin.ensure)
	if c.o.defaultRoute {
		c.prePin()
	}

	if err := c.startProxy(); err != nil {
		log.Print(err)
		return 1
	}
	if err := c.waitFirstSession(ctx); err != nil {
		if ctx.Err() == nil {
			log.Print(err)
			return 1
		}
		return 0
	}
	if err := c.attach(); err != nil {
		log.Print(err)
		return 1
	}
	if !c.waitHandshake(ctx) {
		return 0
	}
	if c.o.defaultRoute {
		if !c.switchDefaultRoute(ctx) {
			return 0
		}
	} else {
		c.routeHosts()
	}

	mon := newNetMonitor(2*time.Second, readDefaultRoute, networkIdentity, gw, up, time.Now())
	mctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go mon.run(mctx, c.onNetwork)

	return c.serve(ctx)
}

// prePin pins, before the first dial, what must stay on the physical path
// whatever the proxy does: the SSH client (a public source on the macOS
// stands), -keep-hosts, the network's DNS servers and the relays the
// credential cache names.
func (c *console) prePin() {
	ssh, _ := byFamily(sshPeers()) // sudo drops $SSH_CLIENT: the socket table knows every session
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if ip := sshClientIP(os.Getenv(env)); ip != "" {
			ssh = appendUnique(ssh, ip)
		}
	}
	for _, ip := range ssh {
		_ = c.pin.ensure(ip)
	}
	for _, h := range splitCSV(c.o.keepHosts) {
		ips, err := net.LookupIP(h)
		if err != nil {
			log.Printf("-keep-hosts %s: %v", h, err)
			continue
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				_ = c.pin.ensure(ip.String())
			}
		}
	}
	for _, s := range c.src.list() {
		_ = c.pin.ensure(s)
	}
	for _, h := range relayHostsFromCache(c.o.credCache) {
		_ = c.pin.ensure(h)
	}
	log.Printf("pins: %d route(s) via the physical gateway so far", c.pin.count())
}

func (c *console) startProxy() error {
	st := c.st
	proxy.SetForceLegacyCaptcha(st.ForceLegacyCaptcha)
	if st.UplinkPaceKiB > 0 {
		proxy.SetUplinkPace(st.UplinkPaceKiB, 16) // 16 KiB: the app's burst (UplinkPace.burstKiB)
	} else {
		proxy.SetUplinkPace(0, 0)
	}
	if c.cookie != "" {
		proxy.SetVKCookieAuth(true, c.cookie, st.VKLinks) // before NewProxy: the pool is sized by it
	} else {
		proxy.SetVKCookieAuth(false, "", nil)
	}
	gomax := -1 // Go's default: every core
	if c.o.gomaxprocs > 0 {
		gomax = c.o.gomaxprocs
	}
	size := poolSize(st.NumConns, c.o.poolReserve)
	c.p = proxy.NewProxy(proxy.Config{
		PeerAddr:         st.PeerAddress,
		TurnServer:       st.TurnServer,
		TurnPort:         st.TurnPort,
		VKLink:           st.VKLinks[0],
		UseDTLS:          true,
		UseSrtp:          true,
		UseUDP:           st.UseUDP,
		NumConns:         st.NumConns,
		CredPoolCooldown: st.CredPoolCooldown,
		CredCachePath:    c.o.credCache,
		CaptchaSolver:    noCaptchaUI,
		GOMAXPROCS:       gomax,
		CredPoolSize:     size,
	})
	mode := "anonymous"
	if c.cookie != "" {
		mode = fmt.Sprintf("VK login, %d call link(s)", len(st.VKLinks))
	}
	log.Printf("vk-turn-proxy-console %s: server %q, %d connections over %s, pool %d identities (%s), pacer %s",
		version, st.ServerName, st.NumConns, transportName(st.UseUDP), size, mode, paceName(st.UplinkPaceKiB))
	go func() {
		if err := c.p.Start(); err != nil {
			log.Printf("proxy: %v", err)
		}
	}()
	return nil
}

// waitFirstSession waits, with no limit, for the first TURN session: a
// bootstrap that fails is retried by the proxy's own watchdog. Only what no
// retry can mend ends the wait — a dead call link, a VK login VK refused.
func (c *console) waitFirstSession(ctx context.Context) error {
	t0 := time.Now()
	boot := make(chan error, 1)
	go func() { boot <- c.p.WaitBootstrap(100 * 365 * 24 * time.Hour) }()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	poll := time.NewTicker(500 * time.Millisecond)
	defer poll.Stop()
	captchaSaid := false
	for {
		if msg := proxy.CookieAuthFatalError(); msg != "" {
			return fmt.Errorf("VK refused the login: %s — export the cookies anew", msg)
		}
		s := c.p.GetStats()
		if s.ActiveConns > 0 {
			log.Printf("proxy: first connection up in %s", time.Since(t0).Round(time.Millisecond))
			return nil
		}
		if s.CaptchaImageURL != "" && !captchaSaid {
			log.Printf("proxy: VK asks for a captcha its automatic solver could not pass; the console has no WebView — the proxy asks VK again every 2 min (10 under a rate limit)")
			captchaSaid = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-boot:
			if err == nil {
				continue // the next poll sees the connection
			}
			if strings.HasPrefix(err.Error(), "resolve peer") {
				return fmt.Errorf("the server's address: %v", err) // Start stops there; no watchdog runs to retry
			}
			var dead *proxy.CallUnavailableError
			if errors.As(err, &dead) {
				return fmt.Errorf("the call link is dead (VK %d: %s) — make a new call and put its link into the app's settings, or give -vk-link", dead.Code, dead.Message)
			}
			log.Printf("proxy: %v — its watchdog retries; waiting", err)
		case <-tick.C:
			log.Printf("waiting for the first connection (%s): pool %d/%d identities", time.Since(t0).Round(time.Second), s.CredPoolWithCreds, s.CredPoolSize)
		case <-poll.C:
		}
	}
}

// attach is the bridge's second phase: the tunnel interface, WireGuard over
// the proxy's bind.
func (c *console) attach() error {
	if _, err := net.InterfaceByName(c.o.tunName); err == nil { // macOS's "utun" is a request for a number, never a name that exists
		return fmt.Errorf("an interface named %s exists and the state file does not name it as ours — remove it (FreeBSD: ifconfig %s destroy) or give -tun-name", c.o.tunName, c.o.tunName)
	}
	tdev, name, err := openTUN(c.o.tunName, c.st.MTU)
	if err != nil {
		return err
	}
	c.tun = name
	if destroy := hostCmds.destroy(name); destroy != nil {
		if err := c.j.add(undoStep{Key: "iface " + name, Argv: destroy}); err != nil {
			_ = tdev.Close()
			return err
		}
	}
	if err := runAll(hostCmds.addrUp(name, c.st.TunnelAddress, c.st.MTU)); err != nil {
		_ = tdev.Close()
		return err
	}
	if add, del := hostCmds.subnetRoute(name, c.st.TunnelAddress); add != nil {
		if err := c.j.add(undoStep{Key: "route subnet " + c.st.TunnelAddress, Argv: del}); err != nil {
			return err
		}
		if _, err := runCmd(add); err != nil {
			log.Printf("tunnel subnet route: %v", err)
		}
	}
	uapi, err := uapiConfig(c.st.PrivateKey, c.st.PeerPublicKey, c.st.PresharedKey, c.st.PeerAddress, c.o.keepalive)
	if err != nil {
		_ = tdev.Close()
		return fmt.Errorf("server %q: %w", c.st.ServerName, err)
	}
	c.dev = device.NewDevice(proxy.WrapTUNForStats(tdev), turnbind.NewTURNBind(c.p), wgLogger(c.o.wgVerbose))
	if err := c.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wireguard: %v", err)
	}
	if err := c.dev.Up(); err != nil {
		return fmt.Errorf("wireguard: %v", err)
	}
	log.Printf("tunnel: %s %s mtu %d", name, c.st.TunnelAddress, c.st.MTU)
	return nil
}

// waitHandshake waits for WireGuard's first handshake through the whole chain
// — the moment the tunnel carries traffic — warning once after 30 s.
func (c *console) waitHandshake(ctx context.Context) bool {
	t0 := time.Now()
	warned := false
	for readWG(c.dev).lastHandshake.IsZero() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
		if !warned && time.Since(t0) > 30*time.Second {
			log.Printf("wireguard: no handshake after 30 s — the server's keys, its -srtp listener, its WireGuard peer for this key? still waiting")
			warned = true
		}
	}
	log.Printf("wireguard: handshake in %s", time.Since(t0).Round(time.Millisecond))
	return true
}

// switchDefaultRoute moves everything into the tunnel once every connection
// is up, or after -default-route-wait: the two halves, the IPv6 block, the DNS.
func (c *console) switchDefaultRoute(ctx context.Context) bool {
	deadline := time.Now().Add(c.o.defaultRouteWait)
	for int(c.p.GetStats().ActiveConns) < c.st.NumConns && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, r := range hostCmds.splitRoutes(c.tun) {
		if err := c.j.add(undoStep{Key: "route split " + r.key, Argv: r.del}); err != nil {
			log.Printf("state: %v — the default route stays where it is", err)
			return true
		}
		if _, err := runCmd(r.add); err != nil {
			log.Printf("default route: %v — it stays where it is", err)
			c.j.undoPrefix("route split ", quiet(runCmd), log.Printf)
			return true
		}
	}
	if c.pin.blockV6 {
		for _, r := range hostCmds.ipv6Block(c.tun) {
			if err := c.j.add(undoStep{Key: "route ipv6 " + r.key, Argv: r.del}); err != nil {
				break
			}
			if _, err := runCmd(r.add); err != nil {
				log.Printf("-block-ipv6: %v", err)
			}
		}
	}
	dnsNote := "the system's DNS left alone"
	if c.dnsPlan.managed {
		if err := c.dns.apply(c.tun, c.dnsPlan.servers); err != nil {
			log.Printf("dns: %v", err)
		} else {
			dnsNote = "DNS " + strings.Join(c.dnsPlan.servers, ", ")
		}
	}
	s := c.p.GetStats()
	log.Printf("DEFAULT ROUTE → the tunnel (%d/%d connections up); %s; %d pin(s) via the physical gateway", s.ActiveConns, c.st.NumConns, dnsNote, c.pin.count())
	return true
}

// routeHosts: split mode — -route hosts into the tunnel.
func (c *console) routeHosts() {
	for _, h := range splitCSV(c.o.route) {
		ips, err := net.LookupIP(h)
		if err != nil {
			log.Printf("-route %s: %v", h, err)
			continue
		}
		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			add, del := hostCmds.viaTunnel(c.tun, ip.String())
			if err := c.j.add(undoStep{Key: "route via " + ip.String(), Argv: del}); err != nil {
				log.Printf("state: %v", err)
				return
			}
			if _, err := runCmd(add); err != nil {
				log.Printf("-route %s: %v", h, err)
			}
		}
	}
	log.Printf("split mode: the tunnel's subnet and -route go through the tunnel, everything else as before")
}

// onNetwork moves the pins and the network's DNS with the network, and tells
// the proxy what the monitor saw — ONE path change per handover (paths.go).
func (c *console) onNetwork(ev netEvents) {
	if ev.slept > 0 {
		log.Printf("woke after about %s — health check", ev.slept.Round(time.Second))
	}
	switch {
	case ev.changed && !ev.up:
		log.Printf("network: gone (was via %s)", ev.prev)
		c.pin.setGateway(gateway{}, false, nil)
	case ev.changed:
		was := "none"
		if ev.prevUp {
			was = ev.prev.String()
		}
		log.Printf("network: via %s (was %s)", ev.cur, was)
		c.pin.setGateway(ev.cur, true, interfaceSubnets(ev.cur.Iface))
		c.src.set(c.dns.refresh(ev.cur))
		for _, s := range c.src.list() {
			_ = c.pin.ensure(s)
		}
	default:
		if c.ticks++; ev.up && c.ticks%5 == 0 {
			c.src.set(c.dns.refresh(ev.cur)) // every ~10 s: a rewritten resolv.conf, a new DHCP server
		}
	}
	tellPath(c.p, proxy.RotateVKSessionClient, ev)
}

// serve prints the stats and waits for a signal or a failure no retry mends.
func (c *console) serve(ctx context.Context) int {
	var stats <-chan time.Time
	if c.o.statsEvery > 0 {
		t := time.NewTicker(c.o.statsEvery)
		defer t.Stop()
		stats = t.C
	}
	check := time.NewTicker(5 * time.Second)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping")
			c.printStats()
			return 0
		case <-stats:
			c.printStats()
		case <-check.C:
			if msg := proxy.CookieAuthFatalError(); msg != "" {
				log.Printf("VK refused the login: %s — export the cookies anew", msg)
				return 1
			}
		}
	}
}

func (c *console) printStats() {
	log.Print(statsLine(c.p.GetStats(), c.st.NumConns, readWG(c.dev).lastHandshake, c.pin.count(), time.Now()))
}

// statsLine is the periodic line. "conns" is the connections that are up out
// of the number CONFIGURED; the proxy's total_conns — every session
// established since the process started, 80 after one restart of forty — is
// "sessions", and its reconnects — the watchdog's full restarts alone — are
// named as that. (Printed as "conns 40/80 · reconnects 0" the two read as a
// half-dead tunnel that had never reconnected.)
func statsLine(s proxy.Stats, configured int, lastHandshake time.Time, pins int, now time.Time) string {
	hs := "never"
	if !lastHandshake.IsZero() {
		hs = now.Sub(lastHandshake).Round(time.Second).String() + " ago"
	}
	extra := ""
	if s.CaptchaImageURL != "" {
		extra += " · captcha pending"
	}
	if s.CredPoolQuotaRefusals > 0 {
		extra += fmt.Sprintf(" · 486 ×%d", s.CredPoolQuotaRefusals)
	}
	return fmt.Sprintf("stats: conns %d/%d · sessions %d since start · tx %.1f MB rx %.1f MB · watchdog restarts %d · pool %d/%d (relays %d) · turn rtt %.0f ms · wg handshake %s · pins %d%s",
		s.ActiveConns, configured, s.TotalConns, mb(s.TxBytes), mb(s.RxBytes), s.Reconnects,
		s.CredPoolWithCreds, s.CredPoolSize, s.CredPoolDistinctRelays, s.TurnRTTms, hs, pins, extra)
}

// shutdown takes everything back in the order that keeps the machine usable:
// the DNS first (the system resolves again), the routes into the tunnel next
// (traffic back on the physical path), the pins right behind them — with the
// default route physical again they change nothing, and whatever ends this
// process later (the proxy's stop is where it writes most of its log) must
// not find them in the table: a pin outlives the network it was made on, and
// on the next network it cuts off what it names — then the proxy and the
// device (on FreeBSD the interface goes with it), whatever is left.
func (c *console) shutdown() {
	run := quiet(runCmd)
	if c.j.hasPrefix("dns ") {
		c.j.undoPrefix("dns ", run, log.Printf)
		afterDNSChange()
	}
	c.j.undoPrefix("route ", run, log.Printf)
	proxy.SetDialHook(nil) // no dial pins anything from here on
	if c.pin != nil {
		c.pin.removeAll()
	}
	if c.p != nil {
		c.p.StopWithTimeout(2 * time.Second) // the proxy first, the device second — wgTurnOff's order
	}
	if c.dev != nil {
		c.dev.Close()
		if c.tun != "" && c.j.has("iface "+c.tun) {
			if _, err := net.InterfaceByName(c.tun); err != nil {
				_ = c.j.done("iface " + c.tun) // gone with the device
			}
		}
	}
	c.j.undoPrefix("", run, log.Printf)
	if err := c.j.remove(); err != nil {
		log.Printf("state: %v", err)
		return
	}
	log.Printf("stopped; every change taken back")
}

// wgState is what the device reports over UAPI for its peer.
type wgState struct {
	rxBytes, txBytes int64
	lastHandshake    time.Time
}

func readWG(dev *device.Device) wgState {
	var st wgState
	if dev == nil {
		return st
	}
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

func mb(b int64) float64 { return float64(b) / 1e6 }

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
