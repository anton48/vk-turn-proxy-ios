package main

// What the proxy is told about the network. Sabotage seen red: the second
// half of a handover told as a path change of its own (the defect of the
// field run: two path changes 2 s apart are the pool's cascade, 30 s); the
// loss of the network not told; the acquires not held while it is gone; the
// VK client not rotated when a network is back; a replacement in one reading
// told without its path change; a wake not told; onNetwork reaching the proxy
// past tellPath, or handing it a rotation that does nothing.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// toldPaths records what the proxy was told, in order.
type toldPaths struct{ calls []string }

func (r *toldPaths) WakeHealthCheck()  { r.calls = append(r.calls, "wake") }
func (r *toldPaths) OnPathChange()     { r.calls = append(r.calls, "change") }
func (r *toldPaths) OnPathTransition() { r.calls = append(r.calls, "hold") }
func (r *toldPaths) OnPathUp()         { r.calls = append(r.calls, "up") }
func (r *toldPaths) rotate()           { r.calls = append(r.calls, "rotate") }

// take returns what was told since the last take.
func (r *toldPaths) take() string {
	s := strings.Join(r.calls, ",")
	r.calls = nil
	return s
}

// A network as the monitor reads it: the default route and the interface's
// own address (another Wi-Fi behind the same router address is another
// network).
type netReading struct {
	gw   gateway
	up   bool
	addr string
}

var (
	homeNet    = netReading{gateway{IP: "192.168.1.1", Iface: "en0"}, true, "192.168.1.5/24"}
	hotspotNet = netReading{gateway{IP: "172.20.10.1", Iface: "en0"}, true, "172.20.10.4/28"}
	noNet      = netReading{}
)

// monitored drives the REAL monitor over a scripted network, one reading per
// tick, and returns what the proxy was told at each tick.
func monitored(t *testing.T, start netReading, gaps []time.Duration, readings ...netReading) []string {
	t.Helper()
	cur := start
	identity := func(g gateway, up bool) string {
		if !up {
			return "down"
		}
		return g.String() + " " + cur.addr
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	m := newNetMonitor(2*time.Second, func() (gateway, bool) { return cur.gw, cur.up }, identity, start.gw, start.up, now)
	var told toldPaths
	var out []string
	for i, r := range readings {
		cur = r
		gap := 2 * time.Second
		if i < len(gaps) && gaps[i] > 0 {
			gap = gaps[i]
		}
		now = now.Add(gap)
		tellPath(&told, told.rotate, m.step(now))
		out = append(out, told.take())
	}
	return out
}

func TestOneHandoverIsOnePathChange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		start    netReading
		gaps     []time.Duration
		readings []netReading
		want     []string
	}{
		{"nothing happens", homeNet, nil, []netReading{homeNet, homeNet}, []string{"", ""}},
		{"the field run: Wi-Fi gone, the hotspot at the next reading", homeNet, nil,
			[]netReading{noNet, hotspotNet, hotspotNet}, []string{"change", "rotate,up", ""}},
		{"gone for three readings", homeNet, nil,
			[]netReading{noNet, noNet, noNet, hotspotNet}, []string{"change", "hold", "hold", "rotate,up"}},
		{"the same network back", homeNet, nil,
			[]netReading{noNet, homeNet}, []string{"change", "rotate,up"}},
		{"one network replaced by another between two readings", homeNet, nil,
			[]netReading{hotspotNet, hotspotNet}, []string{"change,up", ""}},
		{"there and back: two handovers, each its own path change", homeNet, nil,
			[]netReading{noNet, hotspotNet, noNet, homeNet}, []string{"change", "rotate,up", "change", "rotate,up"}},
		{"a wake on the same network", homeNet, []time.Duration{5 * time.Minute},
			[]netReading{homeNet}, []string{"wake"}},
		{"a wake with the network gone, then another one", homeNet, []time.Duration{5 * time.Minute, 0},
			[]netReading{noNet, hotspotNet}, []string{"wake,change", "rotate,up"}},
	} {
		got := monitored(t, tc.start, tc.gaps, tc.readings...)
		if strings.Join(got, " | ") != strings.Join(tc.want, " | ") {
			t.Errorf("%s:\n  told %q\n  want %q", tc.name, got, tc.want)
		}
		// The property the table rows are instances of: between two "up"s the
		// pool hears exactly one path change, however long the gap.
		changes, ups := 0, 0
		for _, step := range got {
			for _, c := range strings.Split(step, ",") {
				switch c {
				case "change":
					changes++
				case "up":
					ups++
				}
			}
		}
		if ups > 0 && changes != ups {
			t.Errorf("%s: %d path change(s) for %d handover(s) — the pool reads two path changes 0.5–90 s apart as a cascade and pauses every acquire for 30 s", tc.name, changes, ups)
		}
	}
}

// The same through the proxy itself: *proxy.Proxy IS the sink, and its own
// lines say what reached it — one path change and one path-up for a handover
// with a gap.
func TestTheProxyHearsOnePathChangePerHandover(t *testing.T) {
	var buf bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })

	p := proxy.NewProxy(proxy.Config{NumConns: 1})
	t.Cleanup(p.Stop)
	var _ pathSink = p

	cur := homeNet
	identity := func(g gateway, up bool) string {
		if !up {
			return "down"
		}
		return g.String() + " " + cur.addr
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	m := newNetMonitor(2*time.Second, func() (gateway, bool) { return cur.gw, cur.up }, identity, homeNet.gw, true, now)
	for _, r := range []netReading{noNet, noNet, hotspotNet, hotspotNet} {
		cur = r
		now = now.Add(2 * time.Second)
		tellPath(p, proxy.RotateVKSessionClient, m.step(now))
	}
	out := buf.String()
	// An idle pool says so at every path change, and the proxy at every path-up
	// before its first session: the two lines count the calls.
	if n := strings.Count(out, "credpool: path event with nothing live"); n != 1 {
		t.Errorf("the pool heard %d path change(s) for one handover, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "proxy: path up before the first session"); n != 1 {
		t.Errorf("the proxy heard %d path-up(s) for one handover, want 1:\n%s", n, out)
	}
	if strings.Count(out, "cascade detected") != 0 {
		t.Errorf("a cascade on one handover:\n%s", out)
	}
}

// onNetwork reaches the proxy through tellPath alone, with the proxy itself
// and the real rotation — read in the source: running onNetwork would move
// this machine's routes.
func TestOnNetworkTellsTheProxyThroughTellPathAlone(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sel := func(e ast.Expr) string {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		x, _ := s.X.(*ast.Ident)
		if x == nil {
			return "." + s.Sel.Name
		}
		return x.Name + "." + s.Sel.Name
	}
	tells := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch s.Sel.Name {
			case "OnPathChange", "OnPathUp", "OnPathTransition", "WakeHealthCheck", "RotateVKSessionClient":
				t.Errorf("main.go calls %s itself (%s) — the proxy is told about the path in tellPath alone", s.Sel.Name, fset.Position(call.Pos()))
			}
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "tellPath" {
			tells++
			if len(call.Args) != 3 || sel(call.Args[0]) != "c.p" || sel(call.Args[1]) != "proxy.RotateVKSessionClient" {
				t.Errorf("tellPath at %s is not handed the proxy and proxy.RotateVKSessionClient", fset.Position(call.Pos()))
			}
		}
		return true
	})
	if tells != 1 {
		t.Errorf("main.go calls tellPath %d time(s), want once — in onNetwork", tells)
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
	inOn := false
	ast.Inspect(on, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "tellPath" {
				inOn = true
			}
		}
		return true
	})
	if !inOn {
		t.Error("onNetwork does not call tellPath")
	}
}
