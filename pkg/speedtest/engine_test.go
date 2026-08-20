package speedtest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

// waitFor blocks until cond() is true, or FAILS the test.
//
// 🚨 It replaced two unbounded `for { ... }` busy-loops. Those spun forever when
// a request failed — and the workers swallowed their errors, so the only symptom
// was the whole suite sitting there until `go test` panicked at ten minutes,
// naming a goroutine dump instead of the failure. A test that cannot fail
// promptly is a test nobody will run.
func waitFor(t *testing.T, werr *workerErrors, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			// 🚨 REPORT BEFORE FAILING. A first version pointed at "the collected
			// worker errors above" and then called t.Fatalf, which aborts before
			// anything prints them — a message naming evidence that does not
			// exist is worse than no message, because the reader goes looking.
			werr.report(t)
			t.Fatalf("timed out after 5s waiting for %s — see the worker errors above "+
				"(none listed means the requests succeeded and the count is simply wrong)", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// workerErrors collects what the concurrent requests hit, so a failure says why
// instead of only that a count never arrived.
type workerErrors struct {
	mu   sync.Mutex
	errs []error
}

func (w *workerErrors) add(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	w.errs = append(w.errs, err)
	w.mu.Unlock()
}

func (w *workerErrors) report(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, err := range w.errs {
		t.Errorf("worker request failed: %v", err)
	}
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
	var werr workerErrors
	block := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			r, err := client.Do(req)
			if err != nil {
				werr.add(err)
				return
			}
			<-block // hold the connection so the peak is observable
			_ = r.Body.Close()
		}()
	}
	// Let the requests reach the server and be counted before releasing them.
	waitFor(t, &werr, "all workers to reach the server", func() bool {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range protos {
			n += c
		}
		return n >= workers+1
	})
	peak, _ := conns.stats()
	close(block)
	wg.Wait()
	werr.report(t)

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

// TestUnprimedPhaseCannotSeeHTTP2 is a guard on the GUARD.
//
// It asserts the limitation that makes priming mandatory, so that nobody
// "simplifies" engine.prime away on the reasoning that the connection count
// would catch h2 anyway. It would not:
//
//	primed   + h2 -> 1 connection used, warning fires
//	unprimed + h2 -> 8 connections used, NOTHING fires
//
// Found by the first run on a device, where download printed "8 carried data ·
// 7 opened" (primed by the ping) and upload printed 8 and 8 from a pool the
// download had torn down — a number h2 would have produced identically.
func TestUnprimedPhaseCannotSeeHTTP2(t *testing.T) {
	const workers = 8

	run := func(primed bool) (used, dials int) {
		t.Helper()
		var mu sync.Mutex
		served := 0
		srv := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			served++
			mu.Unlock()
			_, _ = w.Write([]byte("ok"))
		})
		conns := &connCounter{}
		rt := trustingRoundTripper(t, srv, conns).(*userAgentRoundTripper)
		// h2 ALLOWED — the defect state the counter is supposed to expose.
		tr := rt.next.(*http.Transport)
		tr.ForceAttemptHTTP2 = true
		tr.TLSNextProto = nil
		client := &http.Client{Transport: rt}

		if primed {
			r, err := client.Get(srv.URL)
			if err != nil {
				t.Fatalf("priming: %v", err)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		conns.reset()

		var wg sync.WaitGroup
		var werr workerErrors
		block := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := client.Get(srv.URL)
				if err != nil {
					werr.add(err)
					return
				}
				<-block
				_ = r.Body.Close()
			}()
		}
		waitFor(t, &werr, "all workers to reach the server", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return served >= workers
		})
		used, dials = conns.stats()
		close(block)
		wg.Wait()
		werr.report(t)
		return used, dials
	}

	usedPrimed, _ := run(true)
	if usedPrimed != 1 {
		t.Errorf("primed under h2: %d connections used, want 1 — the guard has stopped working", usedPrimed)
	}
	if len(applyConnStats(Phase{}, usedPrimed, 0, workers, true).Warnings) == 0 {
		t.Error("primed under h2 raised no warning — the whole guard is inert")
	}

	usedCold, _ := run(false)
	if usedCold != workers {
		t.Errorf("unprimed under h2: %d used, want %d — if this changed, re-read "+
			"engine.prime's comment; the reason it exists may have gone away", usedCold, workers)
	}
	// warm=true on purpose: this isolates the NUMERIC question — can the counts
	// alone tell an unprimed h2 phase from an unprimed HTTP/1.1 one? They cannot,
	// which is why the `warm` flag exists and why priming is mandatory rather
	// than nice to have. TestUnprimedPhaseIsNotReadableAsAFlowCount covers what
	// happens once the flag says the pool was cold.
	if len(applyConnStats(Phase{}, usedCold, usedCold, workers, true).Warnings) != 0 {
		t.Error("unprimed under h2 DID warn from the numbers alone — good news, but then " +
			"engine.prime's stated reason is wrong and both must be revisited together")
	}
}

// TestPrimeAsksForSomethingTheServerActuallyServes reproduces a live defect and
// its fix.
//
// 🚨 Priming used to GET the MEASUREMENT url. Measured against the real
// endpoint on 2026-08-20:
//
//	GET .../speedtest/upload.php   -> 404 Not Found, Connection: Close
//	GET .../speedtest/latency.txt  -> 200 OK,        Connection: Keep-Alive
//
// The 404 reused the connection the ping had already pooled and the server then
// closed it, so priming EMPTIED the pool instead of warming it — the download
// phase went from 7 dials on build 316 to 8 on 317, and both phases printed the
// cold-pool disclaimer on a device.
//
// The test server below mimics exactly that pair, so the fix is verified against
// behaviour that was observed rather than against a guess.
//
// 🎯 Note what found it: the disclaimer added one build earlier. Without it the
// screen would have shown a healthy-looking "8 of 8" and the regression would
// have been invisible.
func TestPrimeAsksForSomethingTheServerActuallyServes(t *testing.T) {
	srv := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "latency.txt") {
			_, _ = w.Write([]byte("test=test\n"))
			return
		}
		// Everything else behaves like the real upload endpoint under a GET.
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNotFound)
	})

	conns := &connCounter{}
	e := &engine{
		conns: conns,
		doer:  &http.Client{Transport: trustingRoundTripper(t, srv, conns)},
	}

	measurementURL := srv.URL + "/speedtest/upload.php"
	if !e.prime(context.Background(), measurementURL) {
		t.Error("🚨 priming left the pool cold — it is asking the server for something it does " +
			"not serve, so the phase cannot be read as a flow count at all")
	}
	if got := primeURL(measurementURL); strings.HasSuffix(got, "upload.php") {
		t.Errorf("primeURL returned %q — priming the measurement endpoint is what killed the "+
			"pooled connection", got)
	}
}

// TestPrimeReportsAnEmptyPoolEvenWhenTheRequestSucceeds.
//
// 🚨 "The request worked" is NOT "the pool is warm". A server answering
// `Connection: close` returns a perfectly good response and leaves nothing
// behind — so priming must OBSERVE the pool, not the error.
//
// Seen RED by returning `err == nil` from prime instead of the observation.
func TestPrimeReportsAnEmptyPoolEvenWhenTheRequestSucceeds(t *testing.T) {
	closing := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = w.Write([]byte("ok"))
	})
	keeping := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	for _, tc := range []struct {
		name string
		srv  string
		want bool
	}{
		{"a server that closes the connection leaves the pool cold", closing.URL, false},
		{"a server that keeps it alive leaves the pool warm", keeping.URL, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conns := &connCounter{}
			e := &engine{
				conns: conns,
				doer:  &http.Client{Transport: trustingRoundTripper(t, keeping, conns)},
			}
			if got := e.prime(context.Background(), tc.srv+"/speedtest/latency.txt"); got != tc.want {
				t.Errorf("prime reported warm=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestUnprimedPhaseIsNotReadableAsAFlowCount: when the pool was cold, the
// connection figure must be disclaimed rather than presented.
func TestUnprimedPhaseIsNotReadableAsAFlowCount(t *testing.T) {
	cold := applyConnStats(Phase{}, 8, 8, 8, false)
	if len(cold.Warnings) == 0 {
		t.Error("🚨 a phase that started on an empty pool reported 8 of 8 threads without a word — " +
			"that number is what HTTP/2 prints too")
	}
	warm := applyConnStats(Phase{}, 8, 7, 8, true)
	if len(warm.Warnings) != 0 {
		t.Errorf("a healthy primed phase was disclaimed: %v", warm.Warnings)
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
	p := applyConnStats(Phase{}, used, dials, 8, true)
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
