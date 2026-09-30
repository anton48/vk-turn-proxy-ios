package main

// WireGuard after a sleep. Sabotage seen red: the handshake asked without the
// keys being dropped (wireguard-go's 5-second limit swallows it — data at the
// wake has asked already); the keys dropped and nothing asked; the handshake
// asked into the sessions a forced reconnect is still replacing; asked again
// on the heels of the last ask, or never again when that one was lost; a
// handshake made after the wake not taken for the end; one from before the
// sleep taken for it; the proxy's state read AFTER its health check; the wake
// not told to WireGuard at all; the peer not found by the backup's key; the
// keys left in place until the first ask (a wake into no network never asks);
// the new keys of a handshake WireGuard made itself at the wake dropped — or
// that handshake not taken for the wake's because the poll's lag was left
// out; two runners asking after a wake inside a wake.

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// stats: the two counters the wake reads — sessions established since the
// start, and the watchdog's forced reconnects.
func stats(total int32, forced int64) proxy.Stats {
	return proxy.Stats{TotalConns: total, Reconnects: forced}
}

func TestTheWakeAsksWireGuardWhenASessionCanCarryIt(t *testing.T) {
	woke := time.Date(2026, 9, 30, 18, 48, 19, 0, time.UTC) // wall clock
	before := woke.Add(-13 * time.Minute)                   // the handshake the sleep found
	at := func(ms int) time.Time { return woke.Add(time.Duration(ms) * time.Millisecond) }
	type tick struct {
		ms        int
		s         proxy.Stats
		handshake time.Time
		kick      bool
		done      bool
	}
	for _, tc := range []struct {
		name  string
		ticks []tick
	}{
		{"the field run: the health check forced a reconnect — wait for the first new session, ask once", []tick{
			{100, stats(40, 1), before, false, false}, // every session is being replaced: an initiation now is lost, the next 5 s away
			{200, stats(40, 1), before, false, false},
			{300, stats(41, 1), before, true, false}, // the first new session is up
			{400, stats(60, 1), before, false, false},
			{500, stats(80, 1), at(450), false, true}, // the handshake came: over
		}},
		{"the first ask was lost: again through a session that came up since — not before the last one had its time", []tick{
			{100, stats(41, 1), before, true, false},
			{600, stats(60, 1), before, false, false},  // new sessions, but 0.5 s after the ask
			{2000, stats(60, 1), before, false, false}, // 1.9 s
			{2200, stats(60, 1), before, true, false},  // 2.1 s and sessions newer than the ask
			{2300, stats(60, 1), before, false, false},
			{4400, stats(60, 1), before, false, false}, // no session since the second ask: WireGuard's own retry has it
			{4500, stats(61, 1), before, true, false},
			{4600, stats(61, 1), at(4550), false, true},
		}},
		{"a short sleep, no reconnect: the sessions are what they were — ask at once", []tick{
			{100, stats(40, 0), before, true, false},
			{200, stats(40, 0), before, false, false},
			{300, stats(40, 0), at(250), false, true},
		}},
		{"no reconnect, and the sessions were dead after all: the probes replace them — ask again through a new one", []tick{
			{100, stats(40, 0), before, true, false},
			{1000, stats(40, 0), before, false, false},
			{5100, stats(43, 0), before, true, false},
			{5300, stats(43, 0), at(5250), false, true},
		}},
		{"WireGuard made the handshake itself before the wake was noticed: nothing to ask", []tick{
			{100, stats(40, 0), at(-900), false, true},
		}},
		{"the network is gone at the wake: no session, nothing asked, for as long as it takes", []tick{
			{100, stats(40, 1), before, false, false},
			{60000, stats(40, 1), before, false, false},
			{300000, stats(40, 1), before, false, false},
			{300100, stats(41, 1), before, true, false},
		}},
		{"ten minutes on, WireGuard's own timers have it", []tick{
			{100, stats(41, 1), before, true, false},
			{597000, stats(41, 1), before, false, false},
			{599000, stats(41, 1), before, false, true}, // ten minutes from the wake itself, a poll before it was noticed
		}},
	} {
		k := &wakeKick{since: woke.Add(-netPoll), before: stats(40, 0)}
		for i, tk := range tc.ticks {
			kick, done := k.step(at(tk.ms), tk.s, tk.handshake)
			if kick != tk.kick || done != tk.done {
				t.Errorf("%s — tick %d (+%d ms, %d sessions, %d forced): ask=%v over=%v, want ask=%v over=%v",
					tc.name, i, tk.ms, tk.s.TotalConns, tk.s.Reconnects, kick, done, tk.kick, tk.done)
			}
		}
	}
}

// recordingPeer is WireGuard's side, written down.
type recordingPeer struct {
	mu    sync.Mutex
	calls []string
}

func (p *recordingPeer) note(what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, what)
}

func (p *recordingPeer) did() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.calls, ",")
}

func (p *recordingPeer) ExpireCurrentKeypairs() { p.note("expire") }
func (p *recordingPeer) SendHandshakeInitiation(isRetry bool) error {
	if isRetry {
		p.note("initiate(retry)")
	} else {
		p.note("initiate")
	}
	return nil
}

func TestRekeyDropsTheKeysThenAsks(t *testing.T) {
	var p recordingPeer
	if err := rekey(&p); err != nil {
		t.Fatal(err)
	}
	if got := p.did(); got != "expire,initiate" {
		t.Errorf("rekey did %q, want expire,initiate — the keys go first (that is also what lifts the 5-second limit), and the ask is a first ask, not a retry", got)
	}
}

// The keys go at the wake itself, not with the first ask. A wake whose health
// check forced a reconnect asks nothing until a session is back — and a wake
// into no network may never see one inside the ten minutes the asking lasts:
// with the keys left for the first ask, the network's return would meet
// WireGuard still sending with the key the server dropped long ago.
func TestAWakeDropsTheKeysBeforeAnythingCanCarryAHandshake(t *testing.T) {
	buf := captureLog(t)
	p := proxy.NewProxy(proxy.Config{NumConns: 1}) // never started: no session comes up
	t.Cleanup(p.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var wg recordingPeer
	c := &console{p: p, peer: &wg, mctx: ctx}
	found := p.GetStats()
	found.Reconnects-- // as the wake found the proxy: its health check has forced a reconnect since
	c.rekeyAfterWake(found, time.Now())
	if got := wg.did(); got != "expire" {
		t.Fatalf("at the wake WireGuard was told %q, want expire — the keys are dropped at once, before anything is asked", got)
	}
	if !strings.Contains(buf.String(), "its keys did not see the sleep") {
		t.Errorf("the keys were dropped without a line:\n%s", buf.String())
	}
	time.Sleep(4 * wakeKickTick)
	if got := wg.did(); got != "expire" {
		t.Errorf("with every session being replaced and none back, WireGuard was told %q — a handshake asked into the dead ones is lost", got)
	}
}

// initCounter counts the handshake initiations a device sends.
type initCounter struct {
	conn.Bind
	n atomic.Int32
}

func (b *initCounter) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, p := range bufs {
		if len(p) == device.MessageInitiationSize && p[0] == device.MessageInitiationType {
			b.n.Add(1)
		}
	}
	return b.Bind.Send(bufs, ep)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// wgPair is a console-side device — configured by the console's own
// uapiConfig — and a server for it, joined by wireguard-go's channel bind.
func wgPair(t *testing.T) (client *device.Device, serverKey string, sent *initCounter) {
	t.Helper()
	newKey := func() *ecdh.PrivateKey {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	ck, sk := newKey(), newKey()
	binds := bindtest.NewChannelBinds()
	sent = &initCounter{Bind: binds[0]}
	quiet := device.NewLogger(device.LogLevelSilent, "")
	client = device.NewDevice(tuntest.NewChannelTUN().TUN(), sent, quiet)
	server := device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[1], quiet)
	t.Cleanup(func() { client.Close(); server.Close() })

	// The server first: the channel tun brings a device up the moment it is
	// made, and the client's peer — it has a keepalive — asks for its first
	// handshake as soon as it is configured.
	srv := "private_key=" + hex.EncodeToString(sk.Bytes()) + "\nreplace_peers=true\npublic_key=" + hex.EncodeToString(ck.PublicKey().Bytes()) + "\nallowed_ip=192.168.102.3/32\n"
	if err := server.IpcSet(srv); err != nil {
		t.Fatal(err)
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	// The channel bind reaches its twin as port 1 (IPv4).
	cfg, err := uapiConfig(b64(ck.Bytes()), b64(sk.PublicKey().Bytes()), "", "127.0.0.1:1", 25)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}
	return client, b64(sk.PublicKey().Bytes()), sent
}

// until waits for cond, a second at most.
func until(cond func() bool) bool {
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// The same through wireguard-go itself: the console's peer is found by the
// backup's key, and every rekey puts a handshake initiation on the wire and
// ends in a new handshake — the second one too, asked a moment after the
// first, which without the expiry wireguard-go's 5-second limit would drop.
func TestAWakesHandshakeGoesOutThroughWireGuardItself(t *testing.T) {
	client, serverKey, sent := wgPair(t)
	peer := findPeer(client, serverKey)
	if peer == nil {
		t.Fatal("findPeer: the device's peer not found by the backup's own key")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if p := findPeer(client, b64(other.PublicKey().Bytes())); p != nil {
		t.Error("findPeer: a peer found for a key the device does not have")
	}
	if p := findPeer(client, "not a key"); p != nil {
		t.Error("findPeer: a peer found for a string that is no key")
	}

	// The first handshake is the peer's own (its keepalive asked for it).
	if !until(func() bool { return !readWG(client).lastHandshake.IsZero() }) {
		t.Fatal("fixture: the pair never made its first handshake")
	}
	for i := 1; i <= 2; i++ {
		// Longer than the responder's flood guard (20 ms) and its timestamp's
		// grain: two initiations inside it are one to the server. A wake's asks
		// are 2 s apart.
		time.Sleep(60 * time.Millisecond)
		n0, h0 := sent.n.Load(), readWG(client).lastHandshake
		sincePrevious := time.Since(h0).Milliseconds()
		if err := rekey(peer); err != nil {
			t.Fatal(err)
		}
		if !until(func() bool { return sent.n.Load() > n0 }) {
			t.Fatalf("rekey %d: no handshake initiation left the device — asked %d ms after the previous handshake, inside wireguard-go's 5-second limit, which only the expiry lifts", i, sincePrevious)
		}
		if !until(func() bool { return readWG(client).lastHandshake.After(h0) }) {
			t.Fatalf("rekey %d: the initiation went out and no new handshake followed (still %s)", i, h0.Format("15:04:05.000000"))
		}
	}
}

// The runner, whole: a console with the pair's device and a proxy that was
// never started (no sessions, no forced reconnect: the «short sleep» case)
// asks once, sees the handshake and says so.
func TestAWakeRunsItsHandshakeToTheEnd(t *testing.T) {
	buf := captureLog(t)
	client, serverKey, sent := wgPair(t)
	if !until(func() bool { return !readWG(client).lastHandshake.IsZero() }) {
		t.Fatal("fixture: the pair never made its first handshake")
	}
	time.Sleep(60 * time.Millisecond) // past the responder's flood guard
	p := proxy.NewProxy(proxy.Config{NumConns: 1})
	t.Cleanup(p.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &console{p: p, dev: client, peer: findPeer(client, serverKey), mctx: ctx}
	n0, h0 := sent.n.Load(), readWG(client).lastHandshake
	// The wake is "noticed" a poll from now, so that the handshake the pair
	// already has lies before the wake and the one asked for lies after it.
	c.rekeyAfterWake(p.GetStats(), time.Now().Add(netPoll))
	if !until(func() bool { return strings.Contains(buf.String(), "wireguard: handshake ") }) {
		t.Fatalf("the wake's handshake was not run to its end in a second; %d initiation(s) sent; the log:\n%s", sent.n.Load()-n0, buf.String())
	}
	if n := sent.n.Load() - n0; n != 1 {
		t.Errorf("%d initiation(s) sent for one wake, want 1", n)
	}
	if !readWG(client).lastHandshake.After(h0) {
		t.Error("no new handshake behind the wake's ask")
	}
	for _, want := range []string{"its keys did not see the sleep", "after the wake was noticed (asked 1 time(s))"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the log lacks %q:\n%s", want, buf.String())
		}
	}

	// A console that holds no peer says so instead of doing nothing in silence.
	buf.Reset()
	(&console{p: p, mctx: ctx}).rekeyAfterWake(p.GetStats(), time.Now())
	if !strings.Contains(buf.String(), "NOT told to WireGuard") {
		t.Errorf("a wake with no peer to ask passed in silence: %q", buf.String())
	}
}

// A handshake WireGuard made by itself as the machine woke — between the wake
// and the poll that noticed it, up to netPoll before — is the wake's: those
// keys are new on both sides, and they stay. (The pair's first handshake is a
// moment old when the wake is "noticed" here.)
func TestAHandshakeWireGuardMadeAtTheWakeIsTheWakes(t *testing.T) {
	buf := captureLog(t)
	client, _, _ := wgPair(t)
	if !until(func() bool { return !readWG(client).lastHandshake.IsZero() }) {
		t.Fatal("fixture: the pair never made its first handshake")
	}
	p := proxy.NewProxy(proxy.Config{NumConns: 1})
	t.Cleanup(p.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var wg recordingPeer
	(&console{p: p, dev: client, peer: &wg, mctx: ctx}).rekeyAfterWake(p.GetStats(), time.Now())
	time.Sleep(2 * wakeKickTick)
	if got := wg.did(); got != "" {
		t.Errorf("WireGuard had made its handshake at the wake and was told %q all the same — new keys dropped for nothing", got)
	}
	if !strings.Contains(buf.String(), "made a handshake by itself") {
		t.Errorf("a wake that needed nothing of WireGuard passed without a line: %q", buf.String())
	}
}

// A wake inside a wake replaces the earlier one: ONE runner asks, not two.
func TestAWakeInsideAWakeReplacesTheEarlierOne(t *testing.T) {
	captureLog(t)
	p := proxy.NewProxy(proxy.Config{NumConns: 1}) // never started: no reconnect forced, no new session — one ask, at once
	t.Cleanup(p.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var wg recordingPeer
	c := &console{p: p, peer: &wg, mctx: ctx}
	c.rekeyAfterWake(p.GetStats(), time.Now())
	c.rekeyAfterWake(p.GetStats(), time.Now())
	if !until(func() bool { return strings.Contains(wg.did(), "initiate") }) {
		t.Fatalf("fixture: nothing asked in a second (%q)", wg.did())
	}
	time.Sleep(3 * wakeKickTick)
	if got := wg.did(); got != "expire,expire,expire,initiate" {
		t.Errorf("two wakes in a row told WireGuard %q, want expire,expire,expire,initiate — the keys dropped at each wake, and ONE runner asking", got)
	}
}

// onNetwork reads the proxy's state BEFORE its health check forces a
// reconnect, and tells WireGuard after — both only at a wake; attach keeps the
// peer and run the monitor's context, without which the wake has nobody to
// ask. Read in the source: running any of them would change this machine.
func TestOnNetworkHasWireGuardHandshakeAfterASleep(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var on *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "onNetwork" {
			on = fd
		}
	}
	if on == nil {
		t.Fatal("no onNetwork in main.go")
	}
	// Is the node inside an `if ev.slept > 0 { … }`?
	var sleptIfs []*ast.IfStmt
	ast.Inspect(on, func(n ast.Node) bool {
		if s, ok := n.(*ast.IfStmt); ok {
			if b, ok := s.Cond.(*ast.BinaryExpr); ok && b.Op == token.GTR {
				if x, ok := b.X.(*ast.SelectorExpr); ok && x.Sel.Name == "slept" {
					sleptIfs = append(sleptIfs, s)
				}
			}
		}
		return true
	})
	atWake := func(p token.Pos) bool {
		for _, s := range sleptIfs {
			if p >= s.Body.Pos() && p < s.Body.End() {
				return true
			}
		}
		return false
	}
	var statsAt, tellAt, rekeyAt token.Pos
	ast.Inspect(on, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "tellPath" {
				tellAt = call.Pos()
			}
		case *ast.SelectorExpr:
			switch fn.Sel.Name {
			case "GetStats":
				statsAt = call.Pos()
				if !atWake(call.Pos()) {
					t.Errorf("onNetwork reads the proxy's stats at %s outside `if ev.slept > 0`", fset.Position(call.Pos()))
				}
			case "rekeyAfterWake":
				rekeyAt = call.Pos()
				if !atWake(call.Pos()) {
					t.Errorf("onNetwork has WireGuard handshake at %s outside `if ev.slept > 0` — every network event would drop the keys", fset.Position(call.Pos()))
				}
			}
		}
		return true
	})
	// attach: c.peer = findPeer(c.dev, c.st.PeerPublicKey), after the device
	// has its configuration; run: c.mctx = mctx, before the monitor starts.
	assigned := func(fn, field string) (call *ast.CallExpr, rhs ast.Expr, pos token.Pos) {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				if l, ok := as.Lhs[0].(*ast.SelectorExpr); ok && l.Sel.Name == field {
					rhs, pos = as.Rhs[0], as.Pos()
					call, _ = as.Rhs[0].(*ast.CallExpr)
				}
				return true
			})
		}
		return
	}
	firstCall := func(fn, name string) token.Pos {
		var at token.Pos
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok && at == token.NoPos {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == name {
						at = c.Pos()
					}
				}
				return true
			})
		}
		return at
	}
	peerCall, _, peerAt := assigned("attach", "peer")
	if id, _ := func() (*ast.Ident, bool) {
		if peerCall == nil {
			return nil, false
		}
		i, ok := peerCall.Fun.(*ast.Ident)
		return i, ok
	}(); id == nil || id.Name != "findPeer" || len(peerCall.Args) != 2 {
		t.Error("attach does not keep the device's peer (c.peer = findPeer(c.dev, <the server's key>)) — a wake would have nobody to ask")
	} else if k, ok := peerCall.Args[1].(*ast.SelectorExpr); !ok || k.Sel.Name != "PeerPublicKey" {
		t.Error("attach looks the peer up by something other than the server's public key")
	} else if set := firstCall("attach", "IpcSet"); set == token.NoPos || peerAt < set {
		t.Error("attach looks for the peer before the device has its configuration — there is none to find yet")
	}
	_, ctxRHS, ctxAt := assigned("run", "mctx")
	if id, ok := ctxRHS.(*ast.Ident); !ok || id.Name != "mctx" {
		t.Error("run does not keep the monitor's context (c.mctx = mctx) — the wake's handshake would not start")
	} else if mon := firstCall("run", "run"); mon == token.NoPos || ctxAt > mon {
		t.Error("run keeps the monitor's context after the monitor has started — the first wake may find none")
	}
	switch {
	case statsAt == token.NoPos || tellAt == token.NoPos || rekeyAt == token.NoPos:
		t.Errorf("onNetwork: stats read %v, tellPath %v, rekeyAfterWake %v — want all three: WireGuard is not told of the wake", statsAt != token.NoPos, tellAt != token.NoPos, rekeyAt != token.NoPos)
	case !(statsAt < tellAt && tellAt < rekeyAt):
		t.Errorf("onNetwork's order is wrong — want the proxy's stats read, THEN tellPath (its health check forces the reconnect the stats must not yet show), THEN the handshake")
	}
}
