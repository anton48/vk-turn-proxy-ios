package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// vkHostIPs is a host→IP map populated by the main app right before
// startVPNTunnel. It lets the extension dial VK API endpoints by IP
// without doing DNS resolution, saving the ~30-50ms round-trip per host
// (latency optimization). Originally it was thought to be a structural
// requirement; empirical testing 2026-05-13 disproved that.
//
// Empirical results (build with `ProbeDNS` in pkg/proxy/dns_probe.go,
// running both pre-bootstrap from wgStartVKBootstrap and post-bootstrap
// via fetchAdFpPing):
//
//   - **Pure-Go resolver** (`net.Resolver{PreferGo: true}`): fails in
//     BOTH pre- and post-bootstrap with `lookup ... on [::1]:53: read
//     udp ...: connection refused`. Extension sandbox has no usable
//     /etc/resolv.conf, so pure-Go falls back to [::1]:53 where nothing
//     is listening. Don't rely on this path.
//
//   - **System resolver** (cgo getaddrinfo via libsystem_info →
//     mDNSResponder XPC): WORKS in both windows. Pre-bootstrap returned
//     9 IPs for api.vk.ru in 37ms before setTunnelNetworkSettings was
//     called. Post-bootstrap resolves arbitrary hosts (including
//     non-VK like privacy-cs.mail.ru) through tunnel-routed DNS.
//
//   - **net.Dialer.Dial**: succeeds in both windows. Uses system
//     resolver internally, so its success corroborates system DNS
//     working end-to-end (resolution + TCP connect).
//
// So `vk_host_ips` is NOT structurally required. The extension could
// fall back to system DNS for any VK host and bootstrap would still
// succeed. We keep the pre-resolution path as:
//
//   - Latency optimization: ~30-50ms saved per VK host call (DNS
//     round-trip avoided). Adds up across many calls during bootstrap.
//   - Defense in depth: if system DNS ever stops working in some future
//     iOS version or in a particular network, pre-resolved IPs continue
//     to work.
//   - Whitelist resilience: on networks where iOS-configured DNS may not
//     resolve VK hosts (some restrictive corporate / public networks),
//     IPs pre-resolved by the main app via its own DNS context still
//     work for the extension.
//
// The main-app process, in contrast, always has a fully-populated
// network context — its standard CFHost / getaddrinfo resolves through
// whichever DNS the system is currently using (DHCP / carrier), which
// is by definition reachable in the user's environment. The main app
// pre-resolves VK hosts and passes the IPs through providerConfig; the
// extension dials by IP for these specific hosts while keeping the
// original hostname in TLS SNI / Host headers.
var (
	vkHostIPsMu sync.RWMutex
	vkHostIPs   = make(map[string][]string) // host (no port) → list of IPs (all A-records)
)

// SetVKHostIPs replaces the host→[]IP map. Called from bridge.go's
// wgStartVKBootstrap when proxyConfig is unmarshalled.
func SetVKHostIPs(m map[string][]string) {
	vkHostIPsMu.Lock()
	defer vkHostIPsMu.Unlock()
	vkHostIPs = make(map[string][]string, len(m))
	for h, ips := range m {
		cp := make([]string, len(ips))
		copy(cp, ips)
		vkHostIPs[h] = cp
	}
}

// resolvedVKHostIPs returns the pre-resolved IPs for host, or nil if the
// host wasn't pre-resolved by the main app.
func resolvedVKHostIPs(host string) []string {
	vkHostIPsMu.RLock()
	defer vkHostIPsMu.RUnlock()
	return vkHostIPs[host]
}

// chromeRoundTripper routes requests through HTTP/2 or HTTP/1.1 based
// on what the server negotiates via ALPN. Uses uTLS to mimic Chrome's
// TLS fingerprint for both protocols.
type chromeRoundTripper struct {
	h2 *http2.Transport // HTTP/2 transport (Chrome ALPN: h2, http/1.1)
	h1 *http.Transport  // HTTP/1.1 fallback (Chrome ALPN forced to http/1.1)
}

// newChromeTransport creates an http.RoundTripper that uses uTLS to mimic
// Chrome's TLS fingerprint and supports HTTP/2.
//
// How it works:
//  1. Tries HTTP/2 first — dials with Chrome ALPN (h2, http/1.1),
//     verifies h2 was negotiated, uses http2.Transport for framing.
//  2. Falls back to HTTP/1.1 — if h2 negotiation fails (server doesn't
//     support h2), re-dials with ALPN forced to http/1.1 only,
//     uses standard http.Transport.
//
// This gives us:
//   - JA3/JA4 fingerprint matching the requested browser (Chrome or Safari iOS)
//   - Proper h2 protocol when server supports it (VK does)
//   - Automatic fallback for h1-only servers
//
// helloID picks the browser fingerprint. Use utls.HelloChrome_Auto for
// Chrome desktop UA flows (creds.go / proxy.go VK API calls), and
// utls.HelloIOS_Auto for the captcha session (UA = Safari iOS, must
// match TLS fingerprint or VK detects mismatch). Pre-build-95 we used
// Chrome TLS for everything including captcha — confirmed BOT signal
// during 2026-05-15 PoW regression: Safari UA + Chrome JA3 = trivial
// detection.
func newBrowserTransport(helloID utls.ClientHelloID) http.RoundTripper {
	rt := &chromeRoundTripper{}

	rt.h2 = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialBrowserTLS(ctx, network, addr, false, helloID)
			if err != nil {
				return nil, err
			}
			proto := conn.ConnectionState().NegotiatedProtocol
			if proto != "h2" {
				_ = conn.Close()
				return nil, fmt.Errorf("utls: server %s negotiated %q, not h2", addr, proto)
			}
			return conn, nil
		},
	}

	rt.h1 = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialBrowserTLS(ctx, network, addr, true, helloID)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 5,
	}

	return rt
}

// newChromeTransport — Chrome JA3 fingerprint. Use for Chrome-UA flows.
func newChromeTransport() http.RoundTripper {
	return newBrowserTransport(utls.HelloChrome_Auto)
}

// newSafariTransport — Safari iOS JA3 fingerprint. Use for Safari-UA flows
// (the captcha session, where we send iPhone Safari UA + captured iOS
// browser_fp). Phase 4 of 2026-05-15 PoW regression investigation:
// matches the TLS fingerprint to the User-Agent so VK can't detect
// us as bot via UA+JA3 mismatch.
func newSafariTransport() http.RoundTripper {
	return newBrowserTransport(utls.HelloIOS_Auto)
}

func (rt *chromeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.h2.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// h2 failed — fall back to h1 (re-dials with http/1.1-only ALPN)
	log.Printf("utls: h2 failed for %s: %v — falling back to h1", req.URL.Host, err)
	return rt.h1.RoundTrip(req)
}

// dialBrowserTLS establishes a TLS connection using uTLS with the
// specified browser ClientHello fingerprint.
//
// If forceH1 is true, ALPN is overridden to only advertise http/1.1
// (for use with Go's http.Transport which can't handle h2 frames).
// If forceH1 is false, ALPN keeps the browser's default: ["h2", "http/1.1"].
func dialBrowserTLS(ctx context.Context, network, addr string, forceH1 bool, helloID utls.ClientHelloID) (*utls.UConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host:port %q: %w", addr, err)
	}

	// Build the list of dial addresses. If the main app pre-resolved
	// this host, walk all A-records in order — first reachable IP wins.
	// Otherwise just dial the original addr (lets system DNS try; will
	// usually fail in the extension, but this is consistent fallback
	// behavior rather than a hidden silent path).
	var dialAddrs []string
	if ips := resolvedVKHostIPs(host); len(ips) > 0 {
		for _, ip := range ips {
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
		}
	} else {
		dialAddrs = []string{addr}
	}

	dialer := &net.Dialer{
		// Per-IP connect timeout — short enough that walking 4-5 IPs
		// stays well under the outer request budget.
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var rawConn net.Conn
	var lastErr error
	for _, da := range dialAddrs {
		rawConn, err = dialer.DialContext(ctx, network, da)
		if err == nil {
			break
		}
		log.Printf("utls: dial %s (%s) failed: %v — trying next IP", da, host, err)
		lastErr = err
		rawConn = nil
	}
	if rawConn == nil {
		return nil, fmt.Errorf("dial %s: all %d IPs failed, last error: %w", host, len(dialAddrs), lastErr)
	}

	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("get TLS spec for %v: %w", helloID, err)
	}

	if forceH1 {
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				break
			}
		}
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
	}, utls.HelloCustom)

	if err := tlsConn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("apply Chrome spec: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake with %s: %w", host, err)
	}

	return tlsConn, nil
}
