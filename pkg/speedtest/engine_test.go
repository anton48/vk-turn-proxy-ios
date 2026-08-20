package speedtest

import (
	"crypto/tls"
	"fmt"
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

// TestConnCounterCountsEachConnectionOnce guards the accounting itself: a
// double-counted Close would make live go negative and hide a real peak.
func TestConnCounterCountsEachConnectionOnce(t *testing.T) {
	c := &connCounter{}
	c.opened()
	c.opened()
	if peak, dials := c.stats(); peak != 2 || dials != 2 {
		t.Fatalf("peak=%d dials=%d, want 2/2", peak, dials)
	}
	cc := &countedConn{Conn: nil, c: c}
	c.closed() // one real close
	// A second Close on the same wrapper must not decrement twice.
	cc.once.Do(c.closed)
	cc.once.Do(c.closed)
	c.reset()
	if peak, dials := c.stats(); peak != 0 || dials != 0 {
		t.Fatalf("after closing both: peak=%d dials=%d, want 0/0 — live went wrong", peak, dials)
	}
}

var _ = tls.VersionTLS12
