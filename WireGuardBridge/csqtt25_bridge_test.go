package main

// csqtt 2.5 behind the csqtt handle: which engine a config starts, and what
// the adapter owes the pool, the pumps and Swift. A fake engine in place of
// csqtt25.Dial and a fake relay in place of csqtt.DialRelay — the engine has
// its own tests against a fake server (pkg/csqtt25); here is what stands
// between it and the bridge.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt"
	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

type fakeEngine struct {
	sent    chan []byte
	done    chan struct{}
	closed  atomic.Bool
	errMu   sync.Mutex
	err     error
	conf    csqtt25.ConfigResponse
	stats   csqtt25.Stats
	pathChg atomic.Int32
	wakes   atomic.Int32
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{
		sent: make(chan []byte, 64), done: make(chan struct{}),
		conf: csqtt25.ConfigResponse{TunnelIP: "192.0.2.7", DNS: "192.0.2.1", Port: "9000", Stream: "stream-v1", Workers: 18, Raw: "raw"},
		// Every counter another number, so that a line or a key that takes the
		// wrong one says so.
		stats: csqtt25.Stats{Workers: 30, Target: 18, Ready: 17, Live: 15, TxBytes: 1111, RxBytes: 2222, Sessions: 40, Restarts: 22,
			Handshakes: 39, Fallbacks: 1, Probes: 86, Repairs: 2, PanelRestarts: 9, Unsettled: 3, PathChanges: 4, NoStream: 5, AuthFailures: 6, FragsTx: 7, FragsRx: 8,
			Freezes: 11, Wakes: 12, WakeDeaf: 13, WriteStalls: 14, DeadWrites: 16},
	}
}

func (f *fakeEngine) Send(p []byte) error {
	select {
	case f.sent <- append([]byte(nil), p...):
		return nil
	default:
		return errors.New("fake engine: nobody takes packets")
	}
}
func (f *fakeEngine) Close() {
	if f.closed.CompareAndSwap(false, true) {
		close(f.done)
	}
}
func (f *fakeEngine) Stats() csqtt25.Stats           { return f.stats }
func (f *fakeEngine) Config() csqtt25.ConfigResponse { return f.conf }
func (f *fakeEngine) OnPathChange()                  { f.pathChg.Add(1) }
func (f *fakeEngine) Wake()                          { f.wakes.Add(1) }
func (f *fakeEngine) Done() <-chan struct{}          { return f.done }
func (f *fakeEngine) Err() error                     { f.errMu.Lock(); defer f.errMu.Unlock(); return f.err }
func (f *fakeEngine) stop(err error)                 { f.errMu.Lock(); f.err = err; f.errMu.Unlock(); f.Close() }

// installFakeEngine makes csqtt25DialEngine hand out fe and keep what it was
// asked with; calls counts the dials.
func installFakeEngine(t *testing.T, fe *fakeEngine) (asked func() csqtt25.ClientConfig, calls *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	var got csqtt25.ClientConfig
	calls = &atomic.Int32{}
	prev := csqtt25DialEngine
	csqtt25DialEngine = func(_ context.Context, cfg csqtt25.ClientConfig) (csqtt25Engine, error) {
		mu.Lock()
		got = cfg
		mu.Unlock()
		calls.Add(1)
		return fe, nil
	}
	t.Cleanup(func() { csqtt25DialEngine = prev })
	return func() csqtt25.ClientConfig { mu.Lock(); defer mu.Unlock(); return got }, calls
}

// installCountingOldDial makes the 2.1.9 dial hand out a fake and count.
func installCountingOldDial(t *testing.T) (asked func() csqtt.Config, calls *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	var got csqtt.Config
	calls = &atomic.Int32{}
	fc := newFakeClient()
	prev := csqttDial
	csqttDial = func(_ context.Context, cfg csqtt.Config) (csqttClient, error) {
		mu.Lock()
		got = cfg
		mu.Unlock()
		calls.Add(1)
		return fc, nil
	}
	t.Cleanup(func() { csqttDial = prev })
	return func() csqtt.Config { mu.Lock(); defer mu.Unlock(); return got }, calls
}

const gen25Extra = `,"csqtt_generation":"2.5"`

func start25(t *testing.T, fe *fakeEngine, extra string) (int32, func() csqtt25.ClientConfig) {
	t.Helper()
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	asked, _ := installFakeEngine(t, fe)
	csqttSeededSettle = 0
	h := startCsqtt(t, gen25Extra+extra)
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("a 2.5 tunnel did not become ready: rc=%d err=%q", rc, csqttGetErrorImpl(h))
	}
	return h, asked
}

// The config's generation picks the engine: absent or "2.1.9" is pkg/csqtt as
// before the field, "2.5" is pkg/csqtt25 with the profile's password and
// count, the reference's key mode and shaping, and the adapter's dial and
// deliver; a name this build does not know is REFUSED before anything is made.
func TestCsqttGenerationPicksTheEngine(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		want25      bool
	}{
		{"absent", ``, false},
		{"2.1.9", `,"csqtt_generation":"2.1.9"`, false},
		{"2.5", gen25Extra + `,"csqtt_password":"pw-of-the-25-profile"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mints atomic.Int32
			installFakePool(t, mintingFetch(&mints))
			_, oldCalls := installCountingOldDial(t)
			asked, newCalls := installFakeEngine(t, newFakeEngine())
			csqttSeededSettle = 0
			h := startCsqtt(t, tc.extra)
			if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
				t.Fatalf("not ready: rc=%d err=%q", rc, csqttGetErrorImpl(h))
			}
			if tc.want25 {
				if oldCalls.Load() != 0 || newCalls.Load() != 1 {
					t.Fatalf("generation 2.5 dialled 2.1.9 %d time(s) and 2.5 %d time(s), want 0 and 1", oldCalls.Load(), newCalls.Load())
				}
				cfg := asked()
				if cfg.Password != "pw-of-the-25-profile" || cfg.Workers != 30 || cfg.Keys != csqtt25.KeysAuto || cfg.Mode != csqtt25.ModeUnified {
					t.Fatalf("the 2.5 engine was asked with workers=%d keys=%v mode=%v, password as in the profile: %v — want 30, auto, unified, true",
						cfg.Workers, cfg.Keys, cfg.Mode, cfg.Password == "pw-of-the-25-profile")
				}
				if cfg.Dial == nil || cfg.Deliver == nil || cfg.Logf == nil {
					t.Fatalf("the 2.5 engine was handed no dial / deliver / log: %v %v %v", cfg.Dial == nil, cfg.Deliver == nil, cfg.Logf == nil)
				}
				// The engine's lines say whose they are themselves; the bridge
				// writes them as they come.
				var out lockedLog
				prevW := log.Writer()
				log.SetOutput(&out)
				cfg.Logf("csqtt25: a line of the engine's, %d", 7)
				log.SetOutput(prevW)
				written := false
				for _, l := range out.lines() {
					if strings.Contains(l, "csqtt25: csqtt25:") {
						t.Fatalf("the bridge put its own prefix in front of the engine's: %q", l)
					}
					written = written || strings.HasSuffix(l, "csqtt25: a line of the engine's, 7")
				}
				if !written {
					t.Fatalf("the engine's line did not reach the log as it was given")
				}
				return
			}
			if oldCalls.Load() != 1 || newCalls.Load() != 0 {
				t.Fatalf("generation %q dialled 2.1.9 %d time(s) and 2.5 %d time(s), want 1 and 0", tc.name, oldCalls.Load(), newCalls.Load())
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		var mints atomic.Int32
		fp := installFakePool(t, mintingFetch(&mints))
		_, oldCalls := installCountingOldDial(t)
		_, newCalls := installFakeEngine(t, newFakeEngine())
		h := csqttStartImpl(`{"peer_addr":"192.0.2.10:46000","csqtt_password":"pw","vk_link":"abc","num_conns":30,"csqtt_generation":"2.6"}`)
		if h != -2 {
			if h > 0 {
				csqttTurnOffImpl(h)
			}
			t.Fatalf("a generation this build does not know was started: handle %d, want -2", h)
		}
		time.Sleep(100 * time.Millisecond)
		fp.mu.Lock()
		made := fp.pool != nil
		fp.mu.Unlock()
		if made || oldCalls.Load() != 0 || newCalls.Load() != 0 {
			t.Fatalf("the refused start made a pool: %v, dialled 2.1.9 %d and 2.5 %d time(s)", made, oldCalls.Load(), newCalls.Load())
		}
	})
}

// Each generation keeps the asked count inside what ITS server takes.
func TestCsqttWorkerCountIsBoundedByTheGenerationsOwnLimits(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		want        int
	}{
		{"2.5, too few", gen25Extra + `,"num_conns":1`, csqtt25.MinWorkers},
		{"2.5, too many", gen25Extra + `,"num_conns":500`, csqtt25.MaxWorkers},
		{"2.5, as asked", gen25Extra + `,"num_conns":40`, 40},
		{"2.1.9, none", `,"num_conns":0`, 1},
		{"2.1.9, too many", `,"num_conns":500`, csqtt.MaxWorkers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mints atomic.Int32
			installFakePool(t, mintingFetch(&mints))
			oldAsked, _ := installCountingOldDial(t)
			newAsked, _ := installFakeEngine(t, newFakeEngine())
			csqttSeededSettle = 0
			h := startCsqtt(t, tc.extra)
			if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
				t.Fatalf("not ready: rc=%d", rc)
			}
			got := oldAsked().Workers
			if strings.HasPrefix(tc.name, "2.5") {
				got = newAsked().Workers
			}
			if got != tc.want {
				t.Fatalf("the engine was asked for %d worker(s), want %d", got, tc.want)
			}
		})
	}
}

// A 2.5 tunnel is provisioned with ITS MTU; 2.1.9's 1300 stays 2.1.9's (the
// lifecycle test pins that one).
func TestCsqtt25ProvisionCarriesItsOwnMTU(t *testing.T) {
	h, _ := start25(t, newFakeEngine(), "")
	var pv struct {
		Address string `json:"address"`
		DNS     string `json:"dns"`
		MTU     int    `json:"mtu"`
		Stream  string `json:"stream"`
	}
	prov := csqttProvisionImpl(h)
	if err := json.Unmarshal([]byte(prov), &pv); err != nil || pv.Address != "192.0.2.7/24" || pv.DNS != "192.0.2.1" || pv.MTU != 1500 || pv.Stream != "stream-v1" {
		t.Fatalf("the 2.5 provision: %+v (err %v), want the server's address /24, its DNS, MTU 1500, stream-v1", pv, err)
	}
}

// The pumps carry packets both ways through the adapter, and the stop closes
// the engine.
func TestCsqtt25PumpsCarryPacketsAndTheStopClosesTheEngine(t *testing.T) {
	fe := newFakeEngine()
	installPairTun(t)
	h, asked := start25(t, fe, "")
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	defer unix.Close(mine)
	if rc := csqttAttachImpl(h, mine); rc != 1 {
		t.Fatalf("attach: %d", rc)
	}
	up := ipv4Packet("up through 2.5")
	if _, err := unix.Write(theirs, append([]byte{0, 0, 0, unix.AF_INET}, up...)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-fe.sent:
		if string(got) != string(up) {
			t.Fatalf("the engine was sent another packet than the TUN gave")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the packet from the TUN never reached the engine")
	}
	down := ipv4Packet("down through 2.5")
	asked().Deliver(append([]byte(nil), down...))
	rbuf := make([]byte, 4096)
	unix.SetNonblock(theirs, false)
	if err := unix.SetsockoptTimeval(theirs, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	n, err := unix.Read(theirs, rbuf)
	if err != nil || n != 4+len(down) || string(rbuf[4:n]) != string(down) {
		t.Fatalf("what the engine delivered did not reach the TUN: n=%d err=%v", n, err)
	}
	csqttTurnOffImpl(h)
	if !fe.closed.Load() {
		t.Fatal("the stop left the 2.5 engine open")
	}
}

// Deliver never waits for the TUN: past the queue's bound a packet is dropped
// and counted, and what was queued comes out in order.
func TestCsqtt25DeliverNeverWaitsAndCountsWhatItDrops(t *testing.T) {
	fe := newFakeEngine()
	a := &csqtt25Client{eng: fe, down: make(chan []byte, csqtt25DownQueue)}
	const over = 10
	filled := make(chan struct{})
	go func() {
		for i := 0; i < csqtt25DownQueue+over; i++ {
			a.deliver([]byte{byte(i), byte(i >> 8)})
		}
		close(filled)
	}()
	select {
	case <-filled:
	case <-time.After(2 * time.Second):
		t.Fatal("deliver waited for a reader")
	}
	if got := a.dropped.Load(); got != over {
		t.Fatalf("dropped %d packet(s) past the queue's bound, want %d", got, over)
	}
	if got := a.Stats().Dropped; got != over {
		t.Fatalf("the stats say %d dropped, want %d", got, over)
	}
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 3; i++ {
		p, err := a.ReadPacket(ctx)
		if err != nil || len(p) != 2 || int(p[0])|int(p[1])<<8 != i {
			t.Fatalf("packet %d out of the queue: %v, err %v", i, p, err)
		}
	}
	for len(a.down) > 0 {
		<-a.down
	}
	cancel()
	stopped := make(chan error, 1)
	go func() { _, err := a.ReadPacket(ctx); stopped <- err }()
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a read under a cancelled context: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a read outlived its context")
	}
	fe.Close()
	ended := make(chan error, 1)
	go func() { _, err := a.ReadPacket(context.Background()); ended <- err }()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("a read from an engine that is over returned a packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a read outlived the engine")
	}
}

type leaseLog struct {
	mu     sync.Mutex
	events []string
}

func (l *leaseLog) add(s string) { l.mu.Lock(); l.events = append(l.events, s); l.mu.Unlock() }
func (l *leaseLog) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.events, " → ")
}

// A stream's socket and its credential lease, in the 2.1.9 worker's order:
// the lease, then the dial — whose beginning is taken BEHIND the lease —
// Allocated the moment the relay accepts, a refusal told before the lease
// goes back, and at the end the relay closed BEFORE the lease is released.
func TestCsqtt25DialLeasesTellsAndGivesBackInTheWorkersOrder(t *testing.T) {
	server := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 46000}
	prev := csqtt25OpenRelay
	t.Cleanup(func() { csqtt25OpenRelay = prev })

	newLease := func(l *leaseLog, leased, told *time.Time) func(context.Context, int) (csqtt.Credential, error) {
		return func(_ context.Context, id int) (csqtt.Credential, error) {
			time.Sleep(40 * time.Millisecond) // a wait on the pool
			l.add(fmt.Sprintf("lease %d", id))
			*leased = time.Now()
			return csqtt.Credential{
				TURNCredentials: csqtt.TURNCredentials{Username: "u", Password: "p", Address: "192.0.2.20:3478"},
				Release:         func() { l.add("released") },
				Failed:          func(err error, began time.Time) { *told = began; l.add("failed: " + err.Error()) },
				Allocated:       func(began time.Time) { *told = began; l.add("allocated") },
			}, nil
		}
	}

	t.Run("accepted", func(t *testing.T) {
		var l leaseLog
		var leased, told, opened time.Time
		conn, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		defer conn.Close()
		csqtt25OpenRelay = func(_ context.Context, creds csqtt.TURNCredentials, to *net.UDPAddr, transport string, allocated func()) (net.PacketConn, func(), error) {
			opened = time.Now()
			l.add("open " + creds.Username + "@" + creds.Address + " " + transport + " to the server: " + fmt.Sprint(to == server))
			time.Sleep(30 * time.Millisecond)
			allocated()
			return conn, func() { l.add("relay closed") }, nil
		}
		a := &csqtt25Client{eng: newFakeEngine(), down: make(chan []byte, 1)}
		got, peer, closeConn, err := a.dialer(server, "tcp", newLease(&l, &leased, &told))(context.Background(), 3)
		if err != nil || got != conn || peer != net.Addr(server) {
			t.Fatalf("the dial: err %v, the relay's conn handed on: %v, the peer the server: %v", err, got == conn, peer == net.Addr(server))
		}
		if want := "lease 3 → open u@192.0.2.20:3478 tcp to the server: true → allocated"; l.all() != want {
			t.Fatalf("the dial went:\n  %s\nwant:\n  %s", l.all(), want)
		}
		if told.Before(leased) || told.After(opened) {
			t.Fatalf("the lease was told the dial began %v before the lease was had and %v after the relay was asked — want between the two",
				leased.Sub(told), told.Sub(opened))
		}
		if rtt := time.Duration(a.allocRTT.Load()); rtt < 30*time.Millisecond || rtt > 2*time.Second {
			t.Fatalf("the allocation's time was kept as %v, want the dial's own ≈30 ms", rtt)
		}
		if got := a.Stats().AllocateRTT; got != time.Duration(a.allocRTT.Load()) {
			t.Fatalf("the stats carry %v as the allocation's time", got)
		}
		closeConn()
		if want := "lease 3 → open u@192.0.2.20:3478 tcp to the server: true → allocated → relay closed → released"; l.all() != want {
			t.Fatalf("the end went:\n  %s\nwant:\n  %s", l.all(), want)
		}
	})

	t.Run("refused", func(t *testing.T) {
		var l leaseLog
		var leased, told time.Time
		refusal := errors.New("the relay said no")
		csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
			l.add("open")
			return nil, nil, refusal
		}
		a := &csqtt25Client{eng: newFakeEngine(), down: make(chan []byte, 1)}
		_, _, closeConn, err := a.dialer(server, "udp", newLease(&l, &leased, &told))(context.Background(), 7)
		if !errors.Is(err, refusal) || closeConn != nil {
			t.Fatalf("a refused dial returned err %v and a close: %v", err, closeConn != nil)
		}
		if want := "lease 7 → open → failed: the relay said no → released"; l.all() != want {
			t.Fatalf("the refusal went:\n  %s\nwant:\n  %s", l.all(), want)
		}
		if told.Before(leased) {
			t.Fatalf("the refusal was dated %v before the lease was had", leased.Sub(told))
		}
	})

	t.Run("ended", func(t *testing.T) {
		// A dial ended by its context — the path changed under it — is not the
		// relay's failure: the lease goes back and hears of none.
		var l leaseLog
		var leased, told time.Time
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		csqtt25OpenRelay = func(ctx context.Context, _ csqtt.TURNCredentials, _ *net.UDPAddr, _ string, _ func()) (net.PacketConn, func(), error) {
			l.add("open")
			cancel()
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
				t.Errorf("the relay's opener was not given the dial's context")
			}
			return nil, nil, fmt.Errorf("turn allocate: %w", context.Canceled)
		}
		a := &csqtt25Client{eng: newFakeEngine(), down: make(chan []byte, 1)}
		_, _, closeConn, err := a.dialer(server, "tcp", newLease(&l, &leased, &told))(ctx, 5)
		if err == nil || closeConn != nil {
			t.Fatalf("an ended dial returned %v (a closer: %v)", err, closeConn != nil)
		}
		if want := "lease 5 → open → released"; l.all() != want {
			t.Fatalf("the lease heard %q, want %q: an ended dial says nothing about the relay", l.all(), want)
		}
	})

	t.Run("no lease", func(t *testing.T) {
		opened := false
		csqtt25OpenRelay = func(context.Context, csqtt.TURNCredentials, *net.UDPAddr, string, func()) (net.PacketConn, func(), error) {
			opened = true
			return nil, nil, errors.New("unreachable")
		}
		noLease := errors.New("the pool has nothing")
		a := &csqtt25Client{eng: newFakeEngine(), down: make(chan []byte, 1)}
		_, _, _, err := a.dialer(server, "tcp", func(context.Context, int) (csqtt.Credential, error) { return csqtt.Credential{}, noLease })(context.Background(), 1)
		if !errors.Is(err, noLease) || opened {
			t.Fatalf("without a lease: err %v, the relay asked: %v", err, opened)
		}
	})
}

// What the app shows and what the log says for a 2.5 tunnel: connections are
// the LIVE streams of the count the server agreed to, and the counters' line
// is 2.5's own wording at the path-event snapshot and at the stop alike.
func TestCsqtt25StatsReachTheAppAndTheLog(t *testing.T) {
	fe := newFakeEngine()
	var out lockedLog
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	h, _ := start25(t, fe, "")

	var st proxy.Stats
	if err := json.Unmarshal([]byte(csqttGetStatsImpl(h)), &st); err != nil {
		t.Fatal(err)
	}
	if st.ActiveConns != 15 || st.TotalConns != 18 || st.Reconnects != 22 || st.TxBytes != 1111 || st.RxBytes != 2222 {
		t.Fatalf("the app's stats: active %d (want the 15 live), total %d (want the 18 agreed), reconnects %d (want 22), tx %d rx %d (want 1111, 2222)",
			st.ActiveConns, st.TotalConns, st.Reconnects, st.TxBytes, st.RxBytes)
	}
	csqttLogPathSnapshotImpl(h, "probe")
	csqttTurnOffImpl(h)
	const counters = "2.5: workers 17/18 ready (15 heard from lately; 30 asked), sessions 40, ended 22, dtls 39, fallbacks 1, probes 86, repairs 2, server restarts 9 (found out behind one 3), path changes 4, freezes 11, wakes 12 (silent behind either 13), write stalls 14, dead writes 16, no stream 5, auth failures 6, fragments tx=7 rx=8, dropped 0; tun in=0 out=0"
	var atEvent, atStop bool
	for _, l := range out.lines() {
		if strings.HasSuffix(l, "csqtt: pathstats probe: "+counters) {
			atEvent = true
		}
		if strings.HasSuffix(l, "csqtt: pathstats at stop: "+counters) {
			atStop = true
		}
	}
	if !atEvent || !atStop {
		t.Fatalf("2.5's counters in the log: at the path event %v, at the stop %v — want both, worded:\n  %s", atEvent, atStop, counters)
	}
}

// A path change and a wake each reach the engine as what they are: a wake is
// not a path change (it replaces nobody that answers), a path change is not a
// wake.
func TestCsqtt25PathChangeAndWakeReachTheEngineEachAsItself(t *testing.T) {
	fe := newFakeEngine()
	h, _ := start25(t, fe, "")
	csqttWakeHealthCheckImpl(h)
	if p, w := fe.pathChg.Load(), fe.wakes.Load(); p != 0 || w != 1 {
		t.Fatalf("a wake reached the engine as %d path change(s) and %d wake(s), want 0 and 1", p, w)
	}
	csqttPathChangedImpl(h)
	if p, w := fe.pathChg.Load(), fe.wakes.Load(); p != 1 || w != 1 {
		t.Fatalf("a path change then: %d path change(s) and %d wake(s) at the engine, want 1 and 1", p, w)
	}
}

// The engine is given a bound for its writes and a socket whose write deadline
// is real — the relayed conn's own is a stub, and a bound set on it bounds
// nothing.
func TestCsqtt25WritesAreBoundedOnASocketThatHonoursTheBound(t *testing.T) {
	src, err := os.ReadFile("csqtt25_bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "r, err := csqtt25DialRelay(ctx, creds, server, transport, allocated)") ||
		!strings.Contains(s, "return r.packetConn(), r.Close, nil") || strings.Contains(s, "csqtt.DialRelay(") {
		t.Fatal("the engine's socket is not the bridge's own allocation with a real write deadline (csqtt25_relay.go)")
	}
	var got csqtt25.ClientConfig
	prev := csqtt25DialEngine
	t.Cleanup(func() { csqtt25DialEngine = prev })
	csqtt25DialEngine = func(_ context.Context, cfg csqtt25.ClientConfig) (csqtt25Engine, error) {
		got = cfg
		return newFakeEngine(), nil
	}
	c, err := csqtt25Start(context.Background(), csqttConfig{Password: "pw", NumConns: 3}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 46000}, "tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got.WriteBound != csqtt25.DefaultWriteBound || got.WriteBound <= 0 {
		t.Fatalf("the engine's write bound is %s, want %s", got.WriteBound, csqtt25.DefaultWriteBound)
	}
}

// 2.5's terminal reasons are told to the user in the words of the same reason
// under 2.1.9 — at the dial and when a running client is denied.
func TestCsqtt25DenialsReadAsTheSameReasonsDo(t *testing.T) {
	if got := csqtt25Err(nil); got != nil {
		t.Fatalf("no error became %v", got)
	}
	plain := errors.New("something else")
	if got := csqtt25Err(plain); got != plain {
		t.Fatalf("another error was rewritten: %v", got)
	}
	if got := csqtt25Err(csqtt25.ErrNoConfig); !errors.Is(got, csqtt.ErrNoConfig) {
		t.Fatalf("NOCONF became %v", got)
	}
	var d *csqtt.DeniedError
	if got := csqtt25Err(fmt.Errorf("wrapped: %w", &csqtt25.DeniedError{Reason: "expired"})); !errors.As(got, &d) || d.Reason != "expired" {
		t.Fatalf("a denial became %v", got)
	}

	t.Run("at the dial", func(t *testing.T) {
		var mints atomic.Int32
		installFakePool(t, mintingFetch(&mints))
		prev := csqtt25DialEngine
		csqtt25DialEngine = func(context.Context, csqtt25.ClientConfig) (csqtt25Engine, error) {
			return nil, &csqtt25.DeniedError{Reason: "wrong_password"}
		}
		t.Cleanup(func() { csqtt25DialEngine = prev })
		csqttSeededSettle = 0
		h := startCsqtt(t, gen25Extra)
		if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != -1 {
			t.Fatalf("a denied dial answered %d, want -1", rc)
		}
		if got, want := csqttGetErrorImpl(h), csqttReason(&csqtt.DeniedError{Reason: "wrong_password"}); got != want {
			t.Fatalf("the denial at the dial reads %q, want the 2.1.9 words for the reason: %q", got, want)
		}
	})
	t.Run("no address at the dial", func(t *testing.T) {
		var mints atomic.Int32
		installFakePool(t, mintingFetch(&mints))
		prev := csqtt25DialEngine
		csqtt25DialEngine = func(context.Context, csqtt25.ClientConfig) (csqtt25Engine, error) {
			return nil, csqtt25.ErrNoConfig
		}
		t.Cleanup(func() { csqtt25DialEngine = prev })
		csqttSeededSettle = 0
		h := startCsqtt(t, gen25Extra)
		if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != -1 {
			t.Fatalf("a dial the server had no address for answered %d, want -1", rc)
		}
		if got, want := csqttGetErrorImpl(h), csqttReason(csqtt.ErrNoConfig); got != want {
			t.Fatalf("NOCONF at the dial reads %q, want the 2.1.9 words for it: %q", got, want)
		}
	})
	t.Run("while running", func(t *testing.T) {
		fe := newFakeEngine()
		h, _ := start25(t, fe, "")
		fe.stop(&csqtt25.DeniedError{Reason: "expired"})
		want := csqttReason(&csqtt.DeniedError{Reason: "expired"})
		waitFor(t, "the denial to reach Swift", func() bool { return csqttGetErrorImpl(h) == want })
	})
}

// On a TCP relay leg the window a stream has to answer in behind a wake is
// ten seconds — the kernel's repeats of what was written into a link still
// coming back need most of that; on a UDP leg it is the engine's own.
func TestCsqtt25WakeWindowIsLongerOnATCPLeg(t *testing.T) {
	if csqtt25WakeWindowTCP != 10*time.Second {
		t.Fatalf("the TCP leg's wake window is %s, want 10s", csqtt25WakeWindowTCP)
	}
	var got csqtt25.ClientConfig
	prev := csqtt25DialEngine
	t.Cleanup(func() { csqtt25DialEngine = prev })
	csqtt25DialEngine = func(_ context.Context, cfg csqtt25.ClientConfig) (csqtt25Engine, error) {
		got = cfg
		return newFakeEngine(), nil
	}
	server := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 46000}
	for transport, want := range map[string]time.Duration{"tcp": 10 * time.Second, "udp": 0} {
		c, err := csqtt25Start(context.Background(), csqttConfig{Password: "pw", NumConns: 3}, server, transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if got.WakeWindow != want {
			t.Fatalf("over %s the engine is given a wake window of %s, want %s", transport, got.WakeWindow, want)
		}
	}
}
