package speedtest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// h2Server is a test server that OFFERS HTTP/2. A client that is merely
// *configured* not to use h2 proves nothing against a server that never offered
// it, so the offer is the whole point.
func h2Server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// trustingRoundTripper is our real transport with the test server's CA added.
// Everything else — the HTTP/2 ban, the dialer, the counter — is production.
func trustingRoundTripper(t *testing.T, srv *httptest.Server, conns *connCounter) http.RoundTripper {
	t.Helper()
	rt, ok := newRoundTripper(conns).(*userAgentRoundTripper)
	if !ok {
		t.Fatal("newRoundTripper no longer returns *userAgentRoundTripper — fix this anchor, " +
			"the assertions below would be testing nothing")
	}
	tr, ok := rt.next.(*http.Transport)
	if !ok {
		t.Fatal("the User-Agent wrapper no longer wraps an *http.Transport — fix this anchor")
	}
	tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	return rt
}

// TestThreadsMeansTCPConnections is the guard for the defect this package was
// re-audited for: N workers must be N TCP connections, not N streams on one.
//
// 🚨 THE PRIMING REQUEST IS LOAD-BEARING. With an empty connection pool Go dials
// once per concurrent request even under HTTP/2 — the thundering herd — so a
// test that fires N requests cold PASSES under a transport that multiplexes.
// One request first, so the pool holds a usable connection, is what makes the
// assertion able to fail.
//
// Seen RED under its own sabotage (TLSNextProto: nil + ForceAttemptHTTP2: true):
//
//	proto HTTP/2.0, peak 1 connection for 8 workers
func TestThreadsMeansTCPConnections(t *testing.T) {
	const workers = 8

	var mu sync.Mutex
	protos := map[string]int{}
	srv := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos[r.Proto]++
		mu.Unlock()
		fmt.Fprint(w, "ok")
	})

	conns := &connCounter{}
	client := &http.Client{Transport: trustingRoundTripper(t, srv, conns)}

	// Prime the pool — see above.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("priming request: %v", err)
	}
	_ = resp.Body.Close()

	conns.reset()
	var wg sync.WaitGroup
	block := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			r, err := client.Do(req)
			if err != nil {
				return
			}
			<-block // hold the connection so the peak is observable
			_ = r.Body.Close()
		}()
	}
	// Let the requests reach the server and be counted before releasing them.
	for {
		mu.Lock()
		n := 0
		for _, c := range protos {
			n += c
		}
		mu.Unlock()
		if n >= workers+1 {
			break
		}
	}
	peak, _ := conns.stats()
	close(block)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if n := protos["HTTP/2.0"]; n > 0 {
		t.Errorf("%d requests were served over HTTP/2 — the thread count stops being a flow "+
			"count the moment the transport multiplexes; protos=%v", n, protos)
	}
	if peak < workers {
		t.Errorf("peak was %d TCP connections for %d concurrent workers, want >= %d; protos=%v",
			peak, workers, workers, protos)
	}
}

// TestUserAgentSurvivesOurTransport: bypassing Speedtest.RoundTrip drops the
// header it used to add, which would otherwise be a silent change in what the
// endpoint sees.
func TestUserAgentSurvivesOurTransport(t *testing.T) {
	got := make(chan string, 1)
	srv := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("User-Agent"):
		default:
		}
	})
	client := &http.Client{Transport: trustingRoundTripper(t, srv, nil)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if ua := <-got; ua != UserAgent {
		t.Errorf("server saw User-Agent %q, want %q", ua, UserAgent)
	}
}

// TestConnCounterCountsUseNotPresence is the guard for a FALSE NEGATIVE that
// was live in the shipped counter, and that no other check here could see.
//
// The old counter counted connections OPEN during a phase and started its peak
// at whatever was already live. Server discovery leaves a pool full of idle
// sockets, so a phase that actually ran on ONE multiplexed HTTP/2 connection
// reported a healthy "8 of 8" — measured exactly:
//
//	7 idle discovery sockets + 1 measurement socket -> peak 8, dials 1, NO warning
//
// Counting USE removes it: an idle socket that carries nothing is not counted,
// and h2 reads 1 whatever else is in the pool.
//
// Seen RED by restoring the old accounting (reset() setting peak = live, and
// registration on dial instead of on first Read/Write).
func TestConnCounterCountsUseNotPresence(t *testing.T) {
	c := &connCounter{}
	dial := c.wrapDial(func(context.Context, string, string) (net.Conn, error) {
		return &fakeConn{}, nil
	})

	// Discovery opens seven connections and leaves them idle in the pool.
	var idle []net.Conn
	for i := 0; i < 7; i++ {
		conn, err := dial(context.Background(), "tcp", "example:443")
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, conn)
	}

	// Phase boundary, then ONE connection carries the whole measurement.
	c.reset()
	work, _ := dial(context.Background(), "tcp", "target:443")
	_, _ = work.Write([]byte("x"))
	_, _ = work.Read(make([]byte, 1))

	used, dials := c.stats()
	if used != 1 {
		t.Errorf("counted %d connections for a phase that used ONE; the idle pool is being "+
			"counted as measurement capacity (dials=%d)", used, dials)
	}
	p := applyConnStats(Phase{}, used, dials, 8)
	if len(p.Warnings) == 0 {
		t.Error("🚨 8 threads on one connection passed WITHOUT a warning — this is the exact " +
			"false negative that made every thread-count comparison meaningless")
	}
	for _, conn := range idle {
		_ = conn.Close()
	}
}

// A connection reused across a phase boundary must be counted again — it is
// carrying THIS phase's data, whoever opened it.
func TestConnCounterRecountsAReusedConnection(t *testing.T) {
	c := &connCounter{}
	dial := c.wrapDial(func(context.Context, string, string) (net.Conn, error) {
		return &fakeConn{}, nil
	})
	conn, _ := dial(context.Background(), "tcp", "target:443")

	c.reset()
	_, _ = conn.Write([]byte("phase one"))
	if used, _ := c.stats(); used != 1 {
		t.Fatalf("phase one used %d, want 1", used)
	}

	c.reset()
	if used, _ := c.stats(); used != 0 {
		t.Fatalf("a fresh phase starts at %d, want 0 — the count describes THIS phase", used)
	}
	_, _ = conn.Write([]byte("phase two"))
	if used, dials := c.stats(); used != 1 || dials != 0 {
		t.Fatalf("phase two used=%d dials=%d, want 1/0 — a reused connection is still a flow", used, dials)
	}
}

// fakeConn is a net.Conn that does nothing, so the counter can be exercised
// without a network.
type fakeConn struct{ net.Conn }

func (f *fakeConn) Read(b []byte) (int, error)  { return len(b), nil }
func (f *fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeConn) Close() error                { return nil }

var _ = tls.VersionTLS12
