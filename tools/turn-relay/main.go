// SPDX-License-Identifier: GPL-3.0-only

// turn-relay is a TURN relay for the first entry of the app's TURN override
// list (issue #105): the user's own relay, dialled while it answers, VK's
// relays after it (`myrelay.example:3478:0,$vkurls`). The client signs its
// requests with the credentials VK issued, a password this relay cannot know,
// so it runs on a fork of pion/turn that does not check the request's
// MESSAGE-INTEGRITY (third_party/pion-turn, FORK.md). What keeps it from being
// an open relay: it sends only to the peers named by -peer (the WireGuard /
// SRTP server), and it holds at most -max-allocs allocations at once.
//
//	turn-relay -listen 127.0.0.1:3478 -peer 203.0.113.5           # a self-test on a stand
//	turn-relay -listen 0.0.0.0:3478 -public-ip 198.51.100.7 -peer 203.0.113.5
//
// Every -listen address gets a TCP listener and a UDP socket (the app dials
// TCP; the console follows the server's setting). The relay sockets (one UDP
// port per allocation, the peers' answers come to them) are bound in
// -relay-ports on the listen address — open that range in the firewall for
// the peers. The range is walked, not drawn from: the server names a session by
// the address it arrives from, and a port handed out again while the server
// still holds the session that had it is that old session to the server (the
// new one's handshake goes unanswered) — so keep the range much wider than the
// allocations the server can hold (portWalk).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/pion/turn/v5"
)

type config struct {
	listen    []string // host:port each
	relayIP   string   // the IP the relay sockets are bound on (0.0.0.0: every interface — the peers are elsewhere even when the listener is loopback)
	publicIP  net.IP
	peers     []net.IP
	maxAllocs int64
	minPort   uint16
	maxPort   uint16
	realm     string
	logAllocs bool
	logf      func(format string, args ...any)
}

// relay is a running server with the addresses it bound (ports resolved
// when 0 was asked for — the tests).
type relay struct {
	server *turn.Server
	udp    []net.Addr
	tcp    []net.Addr
	active atomic.Int64
	closes []func() error
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3478", "comma-separated host:port — each gets a TCP listener and a UDP socket")
	publicIP := flag.String("public-ip", "", "the IP the relay is reached at (sent to clients as the relay address); default: the listen address's IP, which then must not be 0.0.0.0")
	relayIP := flag.String("relay-ip", "0.0.0.0", "the IP the relay sockets (one per allocation, towards the peers) are bound on — every interface by default, even when -listen is loopback")
	peers := flag.String("peer", "", "comma-separated IPs the relay may send to — the WireGuard / SRTP server(s); REQUIRED")
	maxAllocs := flag.Int64("max-allocs", 64, "allocations held at once, over all clients; the next one is refused (486)")
	relayPorts := flag.String("relay-ports", "49152-65535", "the UDP port range the relay sockets are bound in, walked in turn (open it in the firewall for the peers' answers; keep it much wider than -max-allocs: a port reused while the server still holds its session is lost)")
	realm := flag.String("realm", "vk-turn-relay", "the realm in the 401 (the client signs with it; the signature is not checked)")
	quiet := flag.Bool("quiet", false, "no line per allocation")
	flag.Parse()

	cfg, err := parseConfig(*listen, *publicIP, *peers, *maxAllocs, *relayPorts, *realm, !*quiet, log.Printf)
	if err == nil {
		if net.ParseIP(*relayIP) == nil {
			err = fmt.Errorf("-relay-ip %q: not an IP", *relayIP)
		} else {
			cfg.relayIP = *relayIP
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-relay:", err)
		flag.Usage()
		os.Exit(2)
	}
	r, err := start(cfg)
	if err != nil {
		log.Fatalf("turn-relay: %v", err)
	}
	for _, a := range r.udp {
		log.Printf("turn-relay: UDP %s", a)
	}
	for _, a := range r.tcp {
		log.Printf("turn-relay: TCP %s", a)
	}
	log.Printf("turn-relay: relay address %s, relay sockets on %s ports %d-%d, peers %s, at most %d allocation(s); the request's signature is NOT checked (third_party/pion-turn)",
		cfg.publicIP, cfg.relayIP, cfg.minPort, cfg.maxPort, ipList(cfg.peers), cfg.maxAllocs)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	if err := r.close(); err != nil {
		log.Printf("turn-relay: close: %v", err)
	}
}

func parseConfig(listen, publicIP, peers string, maxAllocs int64, relayPorts, realm string, logAllocs bool, logf func(string, ...any)) (*config, error) {
	cfg := &config{relayIP: "0.0.0.0", maxAllocs: maxAllocs, realm: realm, logAllocs: logAllocs, logf: logf}
	for _, a := range strings.Split(listen, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, fmt.Errorf("-listen %q: %v", a, err)
		}
		cfg.listen = append(cfg.listen, a)
	}
	if len(cfg.listen) == 0 {
		return nil, errors.New("-listen: no address")
	}
	if publicIP != "" {
		cfg.publicIP = net.ParseIP(publicIP)
		if cfg.publicIP == nil {
			return nil, fmt.Errorf("-public-ip %q: not an IP", publicIP)
		}
	} else {
		host, _, _ := net.SplitHostPort(cfg.listen[0])
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() {
			return nil, fmt.Errorf("-public-ip is required when -listen is %q", cfg.listen[0])
		}
		cfg.publicIP = ip
	}
	for _, p := range strings.Split(peers, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("-peer %q: not an IP", p)
		}
		cfg.peers = append(cfg.peers, ip)
	}
	if len(cfg.peers) == 0 {
		return nil, errors.New("-peer is required: the relay sends to these IPs and no other")
	}
	if maxAllocs < 1 {
		return nil, errors.New("-max-allocs: at least 1")
	}
	lo, hi, ok := strings.Cut(relayPorts, "-")
	a, errA := strconv.Atoi(lo)
	b, errB := strconv.Atoi(hi)
	if !ok || errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
		return nil, fmt.Errorf("-relay-ports %q: want min-max within 1-65535", relayPorts)
	}
	cfg.minPort, cfg.maxPort = uint16(a), uint16(b)
	if realm == "" {
		return nil, errors.New("-realm: empty")
	}
	return cfg, nil
}

func ipList(ips []net.IP) string {
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return strings.Join(s, ", ")
}

// start binds every listen address (TCP and UDP) and runs the server.
func start(cfg *config) (*relay, error) {
	r := &relay{}
	allowed := func(_ net.Addr, peerIP net.IP) bool {
		for _, p := range cfg.peers {
			if p.Equal(peerIP) {
				return true
			}
		}
		if cfg.logAllocs {
			cfg.logf("turn-relay: permission for peer %s REFUSED (not in -peer)", peerIP)
		}
		return false
	}
	var pcs []turn.PacketConnConfig
	var lcs []turn.ListenerConfig
	fail := func(err error) (*relay, error) {
		_ = r.close()
		return nil, err
	}
	// The relay sockets are bound on cfg.relayIP, not on the listen host: a
	// loopback listener (the stand's self-test) still relays to a peer on the
	// Internet (the first run of 2026-10-30: loopback-bound sockets, no
	// handshake). One walk for every listener: they share the ports.
	ports := newPortWalk(cfg)
	for _, a := range cfg.listen {
		udp, err := net.ListenPacket("udp", a)
		if err != nil {
			return fail(fmt.Errorf("udp %s: %w", a, err))
		}
		r.closes = append(r.closes, udp.Close)
		r.udp = append(r.udp, udp.LocalAddr())
		pcs = append(pcs, turn.PacketConnConfig{PacketConn: udp, RelayAddressGenerator: ports, PermissionHandler: allowed})
		tcp, err := net.Listen("tcp", a)
		if err != nil {
			return fail(fmt.Errorf("tcp %s: %w", a, err))
		}
		r.closes = append(r.closes, tcp.Close)
		r.tcp = append(r.tcp, tcp.Addr())
		lcs = append(lcs, turn.ListenerConfig{Listener: tcp, RelayAddressGenerator: ports, PermissionHandler: allowed})
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: cfg.realm,
		// The user is whoever signs — the key handed back signs the responses,
		// which the pion client never checks; the request's signature is not
		// checked at all (the fork).
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, turn.GenerateAuthKey(ra.Username, cfg.realm, "unverified"), true
		},
		QuotaHandler: func(userID, _ string, srcAddr net.Addr) bool {
			if r.active.Load() >= cfg.maxAllocs {
				cfg.logf("turn-relay: allocation for %s (%s) REFUSED: %d held, the limit", srcAddr, userID, cfg.maxAllocs)
				return false
			}
			return true
		},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(srcAddr, _ net.Addr, protocol, userID, _ string, relayAddr net.Addr, _ int) {
				n := r.active.Add(1)
				if cfg.logAllocs {
					cfg.logf("turn-relay: allocation %s for %s (%s, %s) — %d held", relayAddr, srcAddr, userID, protocol, n)
				}
			},
			OnAllocationDeleted: func(srcAddr, _ net.Addr, protocol, userID, _ string) {
				n := r.active.Add(-1)
				if cfg.logAllocs {
					cfg.logf("turn-relay: allocation of %s (%s, %s) gone — %d held", srcAddr, userID, protocol, n)
				}
			},
		},
		PacketConnConfigs: pcs,
		ListenerConfigs:   lcs,
	})
	if err != nil {
		return fail(err)
	}
	r.server = server
	return r, nil
}

// portWalk hands the relay ports out in turn, so that a port comes back only
// when the whole range has been used — pion's own generator draws at random,
// and in a range of a hundred ports every fifth re-dial landed on a port the
// server still held a session for. It starts at a random place: a relay
// restarted within the server's reaping time must not begin on the same ports.
type portWalk struct {
	*turn.RelayAddressGeneratorPortRange
	mu   sync.Mutex
	next int // the offset in the range to try first
}

func newPortWalk(cfg *config) *portWalk {
	return &portWalk{
		RelayAddressGeneratorPortRange: &turn.RelayAddressGeneratorPortRange{RelayAddress: cfg.publicIP, MinPort: cfg.minPort, MaxPort: cfg.maxPort, Address: cfg.relayIP},
		next:                           rand.IntN(int(cfg.maxPort) - int(cfg.minPort) + 1),
	}
}

// AllocatePacketConn takes the next free port of the range; a port something
// else holds is passed over.
func (w *portWalk) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	if conf.RequestedPort != 0 {
		return w.RelayAddressGeneratorPortRange.AllocatePacketConn(conf)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	span := int(w.MaxPort) - int(w.MinPort) + 1
	var err error
	for i := 0; i < span; i++ {
		offset := (w.next + i) % span
		conf.RequestedPort = int(w.MinPort) + offset
		var conn net.PacketConn
		var addr net.Addr
		if conn, addr, err = w.RelayAddressGeneratorPortRange.AllocatePacketConn(conf); err == nil {
			w.next = (offset + 1) % span
			return conn, addr, nil
		}
	}
	return nil, nil, fmt.Errorf("no free relay port in %d-%d: %w", w.MinPort, w.MaxPort, err)
}

func (r *relay) close() error {
	var first error
	if r.server != nil {
		first = r.server.Close()
	}
	for _, c := range r.closes {
		if err := c(); err != nil && first == nil && !errors.Is(err, net.ErrClosed) {
			first = err
		}
	}
	return first
}
