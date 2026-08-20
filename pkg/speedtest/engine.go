package speedtest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	stgo "github.com/showwin/speedtest-go/speedtest"
)

// UserAgent names US, not the library, because the run is ours: our transport,
// our connection policy, our thread count. A server operator reading a log
// should be able to tell this apart from the stock CLI.
var UserAgent = "vkturn-speedtest/1 (showwin/speedtest-go " + stgo.Version() + ")"

// engine is a speedtest client that measures over a transport WE control.
//
// 🚨 THE WHOLE POINT IS THE TRANSPORT. The library builds its own with
// ForceAttemptHTTP2, and since resolveUploadURL rewrites the target to the
// endpoint's https redirect, N workers negotiated h2 and multiplexed onto ONE
// TCP connection. "Threads" then swept nothing at all. Measured against an h2
// test server before this: threads=4 -> peak 1 conn; threads=8 -> peak 1 conn.
type engine struct {
	*stgo.Speedtest
	conns *connCounter
}

// newEngine wires the client so that every request goes through our transport.
//
// 🚨 OPTION ORDER IS LOAD-BEARING. WithUserConfig ends with
// `s.doer.Transport = s`, which would point our client back at the LIBRARY's
// transport. Passing WithDoer LAST installs our client — with our transport —
// after that has happened. The library's comment says the same thing from the
// other side ("may be overwritten again by WithDoer") and it is the only reason
// this composes.
//
// The cost, stated because it is silent: bypassing Speedtest.RoundTrip drops the
// User-Agent it would add (restored below) and makes UserConfig's Source /
// Proxy / DialerControl / DnsBindSource inert. Nothing sets them today; if
// anything ever does, it has to move onto this transport.
func newEngine(threads int, debug bool) *engine {
	conns := &connCounter{}
	doer := &http.Client{Transport: newRoundTripper(conns)}

	client := stgo.New(
		stgo.WithUserConfig(&stgo.UserConfig{MaxConnections: threads, Debug: debug}),
		stgo.WithDoer(doer), // LAST — see above
	)
	return &engine{Speedtest: client, conns: conns}
}

// newRoundTripper builds the transport every measured request goes through.
// Split out so the redirect probe can use the SAME policy without constructing a
// whole engine — a probe on a different transport than the run it configures is
// a trap waiting for the first person who measures with it. Pass a nil counter
// when nothing should be counted.
func newRoundTripper(conns *connCounter) http.RoundTripper {
	base := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	dial := base.DialContext
	if conns != nil {
		dial = conns.wrapDial(dial)
	}

	tr := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dial,

		// 🚨 HTTP/2 DISABLED, DELIBERATELY, AND IT TAKES BOTH LINES.
		// ForceAttemptHTTP2:false alone is not a ban — net/http still configures
		// h2 when the transport looks default-ish — while a NON-NIL EMPTY
		// TLSNextProto is the actual off switch, and it wins even with
		// ForceAttemptHTTP2 true. Measured, Go 1.26:
		//     force=T next=nil -> HTTP/2.0     force=F next=nil -> HTTP/1.1
		//     force=F next={}  -> HTTP/1.1     force=T next={}  -> HTTP/1.1
		// Under h2 one connection carries every worker, so Threads stops being a
		// flow count — which is the only reason this instrument exists.
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},

		// Without a raised per-host idle cap (the default is 2) HTTP/1.1 closes
		// every connection past the second the moment a worker pauses between
		// chunks, so the pool churns and the dial count measures the cap rather
		// than the concurrency.
		MaxIdleConns:          2 * maxThreads,
		MaxIdleConnsPerHost:   2 * maxThreads,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &userAgentRoundTripper{next: tr}
}

// userAgentRoundTripper restores the header Speedtest.RoundTrip used to add.
// It clones rather than mutating: a RoundTripper must not modify the request it
// is given, and the library's own version does exactly that.
type userAgentRoundTripper struct{ next http.RoundTripper }

func (u *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", UserAgent)
	return u.next.RoundTrip(r)
}

// connCounter counts the TCP connections a phase actually opens and how many
// were open at once.
//
// Why both numbers: Dials answers "did the pool churn", PeakConns answers "did
// Threads mean flows". Under HTTP/2 the peak is 1 however many workers run, so
// the peak is the figure that catches the defect this package exists to prevent.
type connCounter struct {
	mu    sync.Mutex
	live  int
	peak  int
	dials int
}

func (c *connCounter) wrapDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		c.opened()
		return &countedConn{Conn: conn, c: c}, nil
	}
}

func (c *connCounter) opened() {
	c.mu.Lock()
	c.live++
	c.dials++
	if c.live > c.peak {
		c.peak = c.live
	}
	c.mu.Unlock()
}

func (c *connCounter) closed() {
	c.mu.Lock()
	if c.live > 0 {
		c.live--
	}
	c.mu.Unlock()
}

// reset starts a new phase's accounting.
//
// 🚨 peak starts at the number of connections ALREADY OPEN, not at zero: an idle
// connection kept alive from the previous phase is a real connection this phase
// can reuse, and zeroing would under-report a phase that reuses the whole pool.
// The converse is a known, accepted overshoot — connections still tearing down
// from the previous phase are counted too, which inflates the peak and can only
// ever hide a defect by making the number LOOK healthy... which it cannot,
// because the defect this catches (h2) drives the peak to 1.
//
// 🚫 It deliberately does NOT call CloseIdleConnections: emptying the pool
// manufactures a fresh dial per worker and would make the peak assertion pass
// even under a transport that multiplexes.
func (c *connCounter) reset() {
	c.mu.Lock()
	c.peak = c.live
	c.dials = 0
	c.mu.Unlock()
}

func (c *connCounter) stats() (peak, dials int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peak, c.dials
}

// countedConn decrements exactly once, however many times Close is called.
type countedConn struct {
	net.Conn
	c    *connCounter
	once sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.c.closed)
	return err
}
