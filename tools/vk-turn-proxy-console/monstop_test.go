package main

// The stop and the network monitor. Sabotage seen red: the stop cancelling
// the monitor without waiting for it (a refresh under way wrote the tunnel's
// DNS back over the restored resolv.conf and journaled it anew — the state
// file came back); not waiting for what the monitor spawned; an unbounded
// wait; a tick that was ready beside the cancel still handled; pinning left
// on after the pins are gone.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stopping builds a console whose DNS is a resolv.conf the console has
// rewritten, journaled, as it is right before a stop.
func stopping(t *testing.T) (c *console, rc, orig string, d *resolvConfDNS) {
	t.Helper()
	saved := afterDNSChange
	afterDNSChange = func() {}
	t.Cleanup(func() { afterDNSChange = saved })
	dir := t.TempDir()
	rc = filepath.Join(dir, "resolv.conf")
	orig = "nameserver 192.0.2.1\nsearch example.test\n"
	if err := os.WriteFile(rc, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	j := newJournal(filepath.Join(dir, "state.json"))
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	d = newResolvConfDNS(rc, j, t.Logf)
	if err := d.apply("", []string{"198.51.100.53"}); err != nil {
		t.Fatal(err)
	}
	f := &fakeRun{exists: map[string]bool{}, j: j, table: map[string]string{}}
	c = &console{j: j, dns: d, pin: newPinner(linuxCmds{}, f.run, j, t.Logf)}
	return c, rc, orig, d
}

// cancelledOrLate waits for the cancel — or two seconds, so that a stop that
// never cancels shows up as a late write, not as a hung test.
func cancelledOrLate(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
}

func cleanAfterTheStop(t *testing.T, c *console, rc, orig string) {
	t.Helper()
	if b, _ := os.ReadFile(rc); string(b) != orig {
		t.Fatalf("resolv.conf after the stop:\n%s\nwant the original back:\n%s", b, orig)
	}
	if _, err := os.Stat(c.j.path); !os.IsNotExist(err) {
		t.Fatalf("the state file is there after the stop (%v) — a late change was journaled anew", err)
	}
}

// The user's case: a handler is under way when the stop begins, and its
// refresh comes after the cancel.
func TestTheStopWaitsForTheMonitorsHandler(t *testing.T) {
	c, rc, orig, d := stopping(t)
	inHandler, loopDone := make(chan struct{}), make(chan struct{})
	c.startMonitor(context.Background(), func(ctx context.Context) {
		defer close(loopDone)
		close(inHandler)     // a handler is running
		cancelledOrLate(ctx) // the stop has begun
		time.Sleep(100 * time.Millisecond)
		d.refresh(gateway{}) // the handler's refresh, late
	})
	<-inHandler
	c.shutdown()
	<-loopDone
	cleanAfterTheStop(t, c, rc, orig)
}

// What the monitor started — the wake's handshake runs through spawn — is
// waited for too: it can outlive the handler that started it.
func TestTheStopWaitsForWhatTheMonitorSpawned(t *testing.T) {
	c, rc, orig, d := stopping(t)
	spawned, bgDone := make(chan struct{}), make(chan struct{})
	c.startMonitor(context.Background(), func(ctx context.Context) {
		c.spawn(func() {
			defer close(bgDone)
			close(spawned)
			cancelledOrLate(ctx)
			time.Sleep(100 * time.Millisecond)
			d.refresh(gateway{})
		})
		cancelledOrLate(ctx) // the monitor itself returns at the cancel
	})
	<-spawned
	c.shutdown()
	<-bgDone
	cleanAfterTheStop(t, c, rc, orig)
}

// A handler that hangs does not hang the stop: it waits monitorStopWait and
// says so.
func TestTheStopsWaitForTheMonitorIsBounded(t *testing.T) {
	c, _, _, _ := stopping(t)
	saved := monitorStopWait
	monitorStopWait = 50 * time.Millisecond
	defer func() { monitorStopWait = saved }()
	release := make(chan struct{})
	defer close(release)
	c.startMonitor(context.Background(), func(context.Context) { <-release })
	logs := captureLog(t)
	returned := make(chan struct{})
	go func() { c.stopMonitor(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("stopMonitor still waits for a hung handler after 3 s — want about monitorStopWait")
	}
	if !strings.Contains(logs.String(), "network monitor: still busy") {
		t.Fatalf("a stop that gave up waiting says nothing:\n%s", logs)
	}
}

// select picks either of two ready cases: a tick that was ready beside the
// cancel must not run the handler once more.
func TestTheMonitorHandlesNoTickAfterItsCancel(t *testing.T) {
	gw := gateway{IP: "192.0.2.1", Iface: "eth0"}
	read := func() (gateway, bool) { return gw, true }
	identity := func(g gateway, up bool) string { return g.String() }
	for i := 0; i < 200; i++ {
		m := newNetMonitor(time.Millisecond, read, identity, gw, true, time.Now())
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		m.run(ctx, func(netEvents) {
			if calls.Add(1) == 1 {
				time.Sleep(5 * time.Millisecond) // a tick is waiting by now
				cancel()
			}
		})
		cancel()
		if n := calls.Load(); n != 1 {
			t.Fatalf("round %d: the handler ran %d times — a tick after the cancel was handled", i, n)
		}
	}
}

// After the pins are gone nothing makes one: not a late dial, not a gateway
// change.
func TestNothingPinsAfterThePinsAreGone(t *testing.T) {
	p, f, j := testPinner(t)
	if err := p.ensure("198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	p.removeAll()
	before := len(f.list())
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	p.setGateway(gateway{IP: "192.168.2.1", Iface: "en1"}, true, nil)
	if cmds := f.list()[before:]; len(cmds) != 0 {
		t.Fatalf("commands after removeAll: %q — want none", cmds)
	}
	if j.hasPrefix("pin ") {
		t.Fatalf("pins journaled after removeAll: %+v", j.doc.Undo)
	}
}

// The wake's handshake is the one thing the monitor starts that outlives its
// handler: it is started through spawn, which the stop waits for — never by a
// go statement of its own. Read in the source.
func TestTheWakesHandshakeRunsThroughSpawn(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "wake.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found, spawns, gos := false, 0, 0
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "rekeyAfterWake" {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.GoStmt:
				gos++
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "spawn" {
					spawns++
				}
			}
			return true
		})
	}
	if !found || spawns != 1 || gos != 0 {
		t.Fatalf("rekeyAfterWake: found %v, spawn calls %d, go statements %d — want its goroutine through c.spawn alone (the stop waits for nothing else)", found, spawns, gos)
	}
}
