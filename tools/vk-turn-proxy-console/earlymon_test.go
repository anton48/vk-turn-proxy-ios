package main

// The network monitor watches the connect phase too. Sabotage seen red: the
// monitor not started before the waits for the first session and the
// handshake (a network that changes there left the pins and the proxy's DNS
// on the old one, and the connection waited for the monitor that waited for
// the connection); the system DNS unlocked while the monitor refreshes it
// beside the switch's apply; the wake reading WireGuard past the lock; attach
// writing the device outside it.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

func funcDecl(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("%s not found in %s", name, file)
	return nil
}

// firstCallAt: the position of the first call of a method (or function)
// named name inside fd, NoPos if none.
func firstCallAt(fd *ast.FuncDecl, name string) token.Pos {
	at := token.NoPos
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || at != token.NoPos {
			return true
		}
		switch fn := c.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == name {
				at = c.Pos()
			}
		case *ast.Ident:
			if fn.Name == name {
				at = c.Pos()
			}
		}
		return true
	})
	return at
}

func TestTheMonitorWatchesTheConnectPhase(t *testing.T) {
	run := funcDecl(t, "main.go", "run")
	mon := firstCallAt(run, "startMonitor")
	start := firstCallAt(run, "startProxy")
	if mon == token.NoPos || start == token.NoPos {
		t.Fatalf("run: startMonitor %v, startProxy %v — want both", mon != token.NoPos, start != token.NoPos)
	}
	if mon < start {
		t.Fatal("the monitor starts before the proxy — its handler tells the proxy of a path change")
	}
	for _, wait := range []string{"waitFirstSession", "attach", "waitHandshake", "switchDefaultRoute"} {
		if at := firstCallAt(run, wait); at == token.NoPos || mon > at {
			t.Errorf("the monitor starts after %s (or %s is gone) — a network that changes while the console waits there is not seen", wait, wait)
		}
	}
	// c.dns is the locked one: the monitor refreshes it from its goroutine.
	locked := false
	ast.Inspect(run.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if l, ok := as.Lhs[0].(*ast.SelectorExpr); ok && l.Sel.Name == "dns" {
			if u, ok := as.Rhs[0].(*ast.UnaryExpr); ok {
				if cl, ok := u.X.(*ast.CompositeLit); ok {
					if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "lockedDNS" {
						locked = true
					}
				}
			}
		}
		return true
	})
	if !locked {
		t.Error("run's c.dns is not a lockedDNS — the monitor's refresh would race the switch's apply")
	}
}

// What the monitor's handler does before attach: the pins and the proxy's
// DNS follow the network; a wake says WireGuard is not up yet.
func TestTheMonitorsHandlerWorksBeforeAttach(t *testing.T) {
	p, _, _ := testPinner(t)
	px := proxy.NewProxy(proxy.Config{NumConns: 1}) // never started
	t.Cleanup(px.Stop)
	dns := &oneAtATime{servers: []string{"192.0.2.53"}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &console{p: px, pin: p, dns: &lockedDNS{d: dns}, src: &dnsSource{}, mctx: ctx}
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)

	gw1 := gateway{IP: "192.168.1.1", Iface: "en0"}
	gw2 := gateway{IP: "172.20.10.1", Iface: "en5"}
	dns.servers = []string{"172.20.10.53"}
	c.onNetwork(netEvents{changed: true, up: true, prev: gw1, prevUp: true, cur: gw2})
	if p.pinned["203.0.113.50"] != gw2 {
		t.Errorf("before attach the pin stayed via %v — want it moved to %v", p.pinned["203.0.113.50"], gw2)
	}
	if got := strings.Join(c.src.list(), ","); got != "172.20.10.53" {
		t.Errorf("the proxy's DNS before attach: %q — want the new network's", got)
	}
	c.onNetwork(netEvents{up: true, cur: gw2, prev: gw2, prevUp: true, slept: 5 * time.Minute})
	if !strings.Contains(logs.String(), "wireguard: not up yet at this wake") {
		t.Errorf("a wake before attach: %q", logs.String())
	}
}

// oneAtATime is a systemDNS that notices two calls inside it at once.
type oneAtATime struct {
	mu      sync.Mutex
	servers []string
	inside  atomic.Int32
	overlap atomic.Bool
}

func (o *oneAtATime) enter() func() {
	if o.inside.Add(1) > 1 {
		o.overlap.Store(true)
	}
	time.Sleep(5 * time.Millisecond)
	return func() { o.inside.Add(-1) }
}

func (o *oneAtATime) originals() []string          { defer o.enter()(); return o.list() }
func (o *oneAtATime) apply(string, []string) error { defer o.enter()(); return nil }
func (o *oneAtATime) refresh(gateway) []string     { defer o.enter()(); return o.list() }
func (o *oneAtATime) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.servers...)
}

func TestTheSystemDNSTakesOneCallAtATime(t *testing.T) {
	inner := &oneAtATime{}
	l := &lockedDNS{d: inner}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_ = l.apply("vktp0", []string{"192.0.2.53"})
			case 1:
				_ = l.refresh(gateway{})
			default:
				_ = l.originals()
			}
		}(i)
	}
	wg.Wait()
	if inner.overlap.Load() {
		t.Fatal("two calls were inside the system DNS at once")
	}
}

// The wake reads WireGuard as attach left it through wgNow, never the fields;
// attach writes them under the lock.
func TestWireGuardIsReadAndWrittenUnderItsLock(t *testing.T) {
	wake := funcDecl(t, "wake.go", "rekeyAfterWake")
	ast.Inspect(wake.Body, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == "c" && (s.Sel.Name == "dev" || s.Sel.Name == "peer") {
				t.Errorf("rekeyAfterWake reads c.%s past the lock — the monitor runs while attach writes it", s.Sel.Name)
			}
		}
		return true
	})
	attach := funcDecl(t, "main.go", "attach")
	list := attach.Body.List
	for i, st := range list {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for _, lhs := range as.Lhs {
			s, ok := lhs.(*ast.SelectorExpr)
			if !ok || (s.Sel.Name != "dev" && s.Sel.Name != "peer") {
				continue
			}
			locked := false
			if i > 0 {
				if es, ok := list[i-1].(*ast.ExprStmt); ok {
					if c, ok := es.X.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Lock" {
							locked = true
						}
					}
				}
			}
			if !locked {
				t.Errorf("attach writes c.%s outside the lock", s.Sel.Name)
			}
		}
	}
}
