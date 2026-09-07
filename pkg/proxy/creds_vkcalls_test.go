package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/proxy"
)

// fakeVK is a local TLS server standing in for api.vk.me, reached through the
// session client's test seam: a dialer factory that leads EVERY dial to the
// fake whatever host the request names, counting dials. The server speaks
// HTTP/2 — the pooled-connection shape the fix is about — and the tests
// assert that it did. A connection named in hangConn answers nothing until
// the test ends: the dead Wi-Fi-bound connection of 2026-09-07.
type fakeVK struct {
	srv        *httptest.Server
	dials      atomic.Int32
	requests   atomic.Int32
	garbage    atomic.Bool            // answer a non-JSON body: VK's side, not the network's
	hangAll    atomic.Bool            // answer nothing on ANY connection
	setCookie  atomic.Bool            // answer with Set-Cookie: remixstid=sess1
	lastCookie atomic.Pointer[string] // the Cookie header of the last answered request
	firstConn  atomic.Pointer[string] // RemoteAddr of the first request's connection
	hangConn   atomic.Pointer[string]
	release    chan struct{}
	h1seen     atomic.Bool
}

func newFakeVK(t *testing.T) *fakeVK {
	t.Helper()
	f := &fakeVK{release: make(chan struct{})}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			f.h1seen.Store(true)
		}
		addr := r.RemoteAddr
		f.firstConn.CompareAndSwap(nil, &addr)
		if h := f.hangConn.Load(); f.hangAll.Load() || (h != nil && *h == r.RemoteAddr) {
			<-f.release
			return
		}
		f.requests.Add(1)
		ck := r.Header.Get("Cookie")
		f.lastCookie.Store(&ck)
		if f.setCookie.Load() {
			http.SetCookie(w, &http.Cookie{Name: "remixstid", Value: "sess1", Path: "/"})
		}
		if f.garbage.Load() {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>not json</html>"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"ok":1}}`))
	}))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(func() { close(f.release); f.srv.Close() })
	return f
}

type fakeVKDialer struct{ f *fakeVK }

func (d fakeVKDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.f.dials.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.f.srv.Listener.Addr().String())
}

func (f *fakeVK) options() []tls_client.HttpClientOption {
	return []tls_client.HttpClientOption{
		tls_client.WithTimeoutMilliseconds(700),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithProxyDialerFactory(func(string, time.Duration, *net.TCPAddr, fhttp.Header, tls_client.Logger) (proxy.ContextDialer, error) {
			return fakeVKDialer{f}, nil
		}),
	}
}

// useFakeVK resets the process singleton and routes its next construction to
// the fake. The reset is the test's, not production's: nothing else in the
// package builds the client.
func useFakeVK(t *testing.T, f *fakeVK) {
	t.Helper()
	resetSessionClientForTest()
	vkSessionClientExtraOptions = f.options
	t.Cleanup(func() {
		vkSessionClientExtraOptions = nil
		resetSessionClientForTest()
	})
}

func resetSessionClientForTest() {
	sessionClientOnce = new(sync.Once)
	sessionClient.Store(nil)
}

const fakeVKURL = "https://api.vk.me/method/auth.getAnonymToken?v=5.276"

func (f *fakeVK) mustBeHTTP2(t *testing.T) {
	t.Helper()
	if f.h1seen.Load() {
		t.Fatal("the fake negotiated HTTP/1.1 — the pooled-connection case did not run")
	}
}

// A request that fails at the network level is retried ONCE on a fresh
// connection. The fake hangs every request on the connection the first call
// warmed — a dead pooled HTTP/2 connection — so without the retry, or with a
// retry that reuses the pool, the second call can only time out.
//
// Sabotage seen red: the retry dropped (two timeouts, an error, one dial);
// the rotation replaced by CloseIdleConnections is caught by the overlap test.
func TestVKCallsPostRetriesOnceOnAFreshConnection(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if GetSessionClient() == nil {
		t.Fatal("no session client")
	}
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	f.mustBeHTTP2(t)
	if f.dials.Load() != 1 {
		t.Fatalf("warm-up dialed %d times, want 1", f.dials.Load())
	}
	f.hangConn.Store(f.firstConn.Load()) // the pooled connection is dead from here on

	started := time.Now()
	resp, err := vkCallsPost(fakeVKURL, "ua")
	took := time.Since(started)
	if err != nil {
		t.Fatalf("request on a dead pooled connection failed after %s: %v — want one retry on a fresh connection", took.Round(time.Millisecond), err)
	}
	if resp["response"] == nil {
		t.Fatalf("unexpected answer %v", resp)
	}
	if f.dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2 (the warm-up and the retry)", f.dials.Load())
	}
	if took < 600*time.Millisecond || took > 3*time.Second {
		t.Fatalf("took %s — want one client timeout (700 ms) plus a fresh request", took.Round(time.Millisecond))
	}
}

// RotateVKSessionClient makes the next request dial afresh: two requests
// share one pooled connection, a third after the rotation needs a new one.
//
// Sabotage seen red: RotateVKSessionClient made a no-op (the third request
// reuses the pool: one dial).
func TestRotateVKSessionClientForcesAFreshDial(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	for i := 0; i < 2; i++ {
		if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	f.mustBeHTTP2(t)
	if f.dials.Load() != 1 {
		t.Fatalf("two requests dialed %d times, want 1 (pooled)", f.dials.Load())
	}
	RotateVKSessionClient()
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("request after the close: %v", err)
	}
	if f.dials.Load() != 2 {
		t.Fatalf("dials after RotateVKSessionClient = %d, want 2", f.dials.Load())
	}
}

// After a path change two mints run at once (the pool's cold-start cap), and
// on 2026-09-07 both went out on the same dead connection 91 ms apart. Each
// one's retry must reach a fresh connection although the OTHER one's stream
// is still open on the dead one — which is exactly what a close of idle
// connections cannot do (tls-client shuts only connections with no stream in
// flight). Three overlapping requests on one dead pooled connection: all
// three succeed after one timeout each, one rotation between them.
//
// Sabotage seen red: the rotation replaced by client.CloseIdleConnections
// (all three fail after two timeouts, one dial in total).
func TestOverlappingMintsAllRecoverFromOneDeadConnection(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	f.mustBeHTTP2(t)
	f.hangConn.Store(f.firstConn.Load())

	const n = 3
	var wg sync.WaitGroup
	errs := make([]error, n)
	tooks := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 90 * time.Millisecond) // the log's spacing
			started := time.Now()
			_, errs[i] = vkCallsPost(fakeVKURL, "ua")
			tooks[i] = time.Since(started)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("overlapping mint %d failed after %s: %v — its retry stayed on the dead connection", i, tooks[i].Round(time.Millisecond), errs[i])
		}
		if tooks[i] < 600*time.Millisecond || tooks[i] > 3*time.Second {
			t.Fatalf("overlapping mint %d took %s — want one timeout and a fresh request", i, tooks[i].Round(time.Millisecond))
		}
	}
	if d := f.dials.Load(); d < 2 || d > 1+n {
		t.Fatalf("dials = %d, want between 2 (the warm-up and one rotation) and %d", d, 1+n)
	}
}

// The path hook with a mint in flight on the dead connection: the request
// that follows the hook must dial afresh at once (a closed pool would still
// carry the dead connection while that stream is open), and the in-flight
// request recovers through its own retry on the rotated client.
//
// Sabotage seen red: RotateVKSessionClient implemented as CloseIdleConnections.
func TestPathHookWithAMintInFlightStillGivesTheNextRequestAFreshConnection(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	f.mustBeHTTP2(t)
	f.hangConn.Store(f.firstConn.Load())

	inFlight := make(chan error, 1)
	go func() {
		_, err := vkCallsPost(fakeVKURL, "ua")
		inFlight <- err
	}()
	time.Sleep(100 * time.Millisecond) // its stream is open on the dead connection
	RotateVKSessionClient()            // the path event
	started := time.Now()
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("request after the hook: %v", err)
	}
	if took := time.Since(started); took > 500*time.Millisecond {
		t.Fatalf("the request after the hook took %s — it landed on the dead connection beside the in-flight stream", took.Round(time.Millisecond))
	}
	if err := <-inFlight; err != nil {
		t.Fatalf("the in-flight request did not recover on the rotated client: %v", err)
	}
	if d := f.dials.Load(); d < 2 || d > 3 {
		t.Fatalf("dials = %d, want 2 or 3", d)
	}
}

// VK's own answer is not the network's: a body that does not parse reaches the
// caller after ONE request — no retry, no rotation.
//
// Sabotage seen red: the retry taken on every error.
func TestVKSideErrorsAreNotRetried(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	f.garbage.Store(true)
	before := f.requests.Load()
	dials := f.dials.Load()
	_, err := vkCallsPost(fakeVKURL, "ua")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("a non-JSON answer returned %v, want the unmarshal error", err)
	}
	if got := f.requests.Load() - before; got != 1 {
		t.Fatalf("VK's answer was requested %d times, want exactly 1 — a VK-side error must not be retried", got)
	}
	if f.dials.Load() != dials {
		t.Fatalf("a VK-side error rotated the client (dials %d → %d)", dials, f.dials.Load())
	}
}

// The path event's hook never BUILDS the client: with no singleton there is
// nothing to close, and constructing one (it logs the TLS profile and would
// exist in a tunnel that never minted) is not the hook's business.
//
// Sabotage seen red: RotateVKSessionClient reading GetSessionClient().
func TestRotateVKSessionClientNeverBuildsTheClient(t *testing.T) {
	resetSessionClientForTest()
	t.Cleanup(resetSessionClientForTest)
	RotateVKSessionClient()
	if sessionClientIfCreated() != nil {
		t.Fatal("RotateVKSessionClient built the session client")
	}
}

// Both path-change hooks — the native proxy's and the exported pool's (the
// csqtt adapter's path) — drop the pooled connections.
//
// Sabotage seen red: the RotateVKSessionClient call dropped from either
// hook (that hook's request reuses the pool: no new dial).
func TestPathChangeHooksDropTheVKConnectionPool(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatal(err)
	}
	f.mustBeHTTP2(t)

	p := NewProxy(Config{VKLink: "https://vk.ru/call/join/abc123", PeerAddr: "127.0.0.1:1"})
	defer p.StopWithTimeout(time.Second)
	p.OnPathChange()
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatal(err)
	}
	if f.dials.Load() != 2 {
		t.Fatalf("after Proxy.OnPathChange dials = %d, want 2 — the native hook did not drop the pool", f.dials.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := NewCredPool(ctx, CredPoolConfig{VKLink: "abc123", NumConns: 30, Fetch: func(bool, int) (string, *TURNCreds, error) {
		return "", nil, errors.New("no mint in this test")
	}})
	defer pool.Close()
	pool.OnPathChange()
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatal(err)
	}
	if f.dials.Load() != 3 {
		t.Fatalf("after CredPool.OnPathChange dials = %d, want 3 — the pool's hook (csqtt's path) did not drop the pool", f.dials.Load())
	}
}

// What is and is not a network-class error: the socket's and the timer's are,
// VK's answers are not — those must reach the caller's fallback unchanged.
func TestIsNetworkClassError(t *testing.T) {
	for text, want := range map[string]bool{
		`Post "https://api.vk.me/x": context deadline exceeded`:                                                   true,
		`Post "https://api.vk.me/x": net/http: request canceled (Client.Timeout exceeded while awaiting headers)`: true,
		`read tcp 192.168.4.37:59321->87.240.137.208:443: read: can't assign requested address`:                   true,
		`dial tcp: lookup api.vk.me: no such host`:                                                                true,
		`write tcp 10.0.0.2:1->1.2.3.4:443: write: broken pipe`:                                                   true,
		`unmarshal: invalid character '<', body: <html>`:                                                          false,
		`vkcalls step2 (calls.start): VK error 14: Captcha need`:                                                  false,
		`vkcalls: no session client`:                                                                              false,
	} {
		if got := isNetworkClassError(errors.New(text)); got != want {
			t.Errorf("isNetworkClassError(%q) = %v, want %v", text, got, want)
		}
	}
	if isNetworkClassError(nil) {
		t.Error("nil is not a network error")
	}
	// EADDRNOTAVAIL has two shapes: the established socket that lost its
	// source address (retry and legacy-wave transient) and the dial on an
	// IPv6-only Wi-Fi without an IPv4 source (fails in 30–200 ms every time —
	// a fresh client may retry it once, the legacy loop must NOT wait 12 waves).
	readShape := errors.New(`read tcp 192.168.4.37:59321->87.240.137.208:443: read: can't assign requested address`)
	connectShape := errors.New(`dial tcp 87.240.137.208:443: connect: can't assign requested address`)
	if !isTransientNetworkError(readShape) || isTransientNetworkError(connectShape) {
		t.Errorf("isTransientNetworkError: read shape %v, connect shape %v — want true, false", isTransientNetworkError(readShape), isTransientNetworkError(connectShape))
	}
	if !isNetworkClassError(readShape) || !isNetworkClassError(connectShape) {
		t.Error("isNetworkClassError must accept both EADDRNOTAVAIL shapes")
	}
	if k := networkErrorKind(errors.New(`Post "https://api.vk.me/x?link=secret": context deadline exceeded`)); k != "context deadline exceeded" {
		t.Errorf("networkErrorKind = %q", k)
	}
}

// The session's cookies are the reason the client is a singleton (the
// bootstrap and the captcha flow share one jar): a rotation must carry the
// jar — the cookie VK set before the rotation rides on the first request
// after it, and on the retry's rotation alike.
//
// Sabotage seen red: the rotation built around a NEW jar.
func TestCookiesSurviveARotation(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	f.setCookie.Store(true)
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("warm-up request: %v", err)
	}
	f.mustBeHTTP2(t)
	f.setCookie.Store(false)

	RotateVKSessionClient() // the path event
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatal(err)
	}
	if ck := f.lastCookie.Load(); ck == nil || !strings.Contains(*ck, "remixstid=sess1") {
		t.Fatalf("after the path-event rotation the request carried Cookie %q — the jar was not shared", deref(ck))
	}

	f.hangConn.Store(f.firstConn.Load()) // no effect: that connection is the old client's
	cur := f.lastConnOf(t)
	f.hangConn.Store(&cur) // the rotated client's connection is dead now
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("request through the retry's rotation: %v", err)
	}
	if ck := f.lastCookie.Load(); ck == nil || !strings.Contains(*ck, "remixstid=sess1") {
		t.Fatalf("after the retry's rotation the request carried Cookie %q — the jar was not shared", deref(ck))
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// lastConnOf returns the RemoteAddr of the connection the last answered
// request arrived on — recorded by the handler through a probe request.
func (f *fakeVK) lastConnOf(t *testing.T) string {
	t.Helper()
	var got atomic.Pointer[string]
	prev := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := r.RemoteAddr
		got.Store(&addr)
		prev.ServeHTTP(w, r)
	})
	defer func() { f.srv.Config.Handler = prev }()
	if _, err := vkCallsPost(fakeVKURL, "ua"); err != nil {
		t.Fatalf("probe request: %v", err)
	}
	if got.Load() == nil {
		t.Fatal("the probe request reached no handler")
	}
	return *got.Load()
}

// A rotation is a compare-and-swap on the holder it was asked to replace: two
// goroutines that lost the same dead connection rotate ONCE between them, and
// the loser moves to the winner's client instead of discarding it.
//
// Sabotage seen red: the CAS replaced by an unconditional store.
func TestRotationIsACompareAndSwap(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	if GetSessionClient() == nil {
		t.Fatal("no session client")
	}
	h0 := sessionClient.Load()
	h1 := rotateVKSessionClient(h0, "test")
	if h1 == nil || h1 == h0 {
		t.Fatalf("the first rotation of h0 gave %p (h0 %p)", h1, h0)
	}
	h2 := rotateVKSessionClient(h0, "test again")
	if h2 != h1 {
		t.Fatalf("a second rotation of the SAME old holder replaced the first rotation's client (%p → %p) — not a compare-and-swap", h1, h2)
	}
	if cur := sessionClient.Load(); cur != h1 {
		t.Fatalf("current holder %p, want the first rotation's %p", cur, h1)
	}

	// The race the CAS is for: a second rotation of the same holder lands
	// between the first one's check and its swap. The loser must adopt the
	// winner's client, not overwrite it.
	h1 = sessionClient.Load()
	var inner *sessionClientHolder
	vkRotateBeforeSwap = func() {
		vkRotateBeforeSwap = nil // one-shot: the nested rotation must not recurse
		inner = rotateVKSessionClient(h1, "inner")
	}
	t.Cleanup(func() { vkRotateBeforeSwap = nil })
	outer := rotateVKSessionClient(h1, "outer")
	if inner == nil || inner == h1 {
		t.Fatalf("the nested rotation did not replace the holder (inner %p, h1 %p)", inner, h1)
	}
	if outer != inner {
		t.Fatalf("the rotation that lost the race installed its own client (%p) over the winner's (%p) — the swap is not a compare-and-swap", outer, inner)
	}
	if cur := sessionClient.Load(); cur != inner {
		t.Fatalf("current holder %p, want the race winner's %p", cur, inner)
	}
}

// A client that never completed a request cannot hold a dead pooled
// connection: a failure on it is the network's verdict, and no retry follows
// — the caller's fallback comes after one timeout, not two.
//
// Sabotage seen red: the retry taken regardless of `used`.
func TestANeverUsedClientDoesNotRetry(t *testing.T) {
	f := newFakeVK(t)
	useFakeVK(t, f)
	f.hangAll.Store(true)
	if GetSessionClient() == nil {
		t.Fatal("no session client")
	}
	h0 := sessionClient.Load()
	started := time.Now()
	_, err := vkCallsPost(fakeVKURL, "ua")
	took := time.Since(started)
	if err == nil || !isNetworkClassError(err) {
		t.Fatalf("a request on a dead network returned %v, want the network error", err)
	}
	if f.dials.Load() != 1 || sessionClient.Load() != h0 {
		t.Fatalf("a never-used client was rotated and retried (dials %d, holder changed %v) — one timeout was the answer", f.dials.Load(), sessionClient.Load() != h0)
	}
	if took > 1200*time.Millisecond {
		t.Fatalf("took %s — want one client timeout, not two", took.Round(time.Millisecond))
	}
}
