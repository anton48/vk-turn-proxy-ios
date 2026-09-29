package proxy

// The dial hook (dialhook.go) is the console's only way to keep the proxy's
// own traffic off a tunnel that holds the default route: every destination is
// pinned to the physical gateway the moment it is dialled. Three properties:
//
//  1. the hook is told the relay's address by all four TURN control sockets
//     (runTURN and setupSRTPSession, TCP and UDP) and by the VK and
//     browser-TLS dialers;
//  2. it is asked BEFORE the socket talks: a refusal aborts the dial and not
//     one packet or connection reaches the far end — the ordering the console
//     relies on (the route must exist before the first SYN / datagram);
//  3. no socket in the package bypasses it — a scan over the AST, since a new
//     dial site without the hook would leak only in the field.
//
// Sabotage seen red: the hook call dropped at each of the four TURN sites
// (the refusal no longer aborts, the far end sees the dial); vkDiagDialer's or
// browserDialer's Control not chained; the scan's own targets (a zero
// net.Dialer, a DialUDP with no hook before it).

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

// hookLog records what the hook was told.
type hookLog struct {
	mu   sync.Mutex
	seen []string
}

func (h *hookLog) hook(network, address string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, network+" "+address)
	return nil
}

func (h *hookLog) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.seen...)
}

func installHook(t *testing.T, h func(network, address string) error) {
	t.Helper()
	SetDialHook(h)
	t.Cleanup(func() { SetDialHook(nil) })
}

// hookStandProxy is allocmark_test's proxy: one pool slot holding the stand's
// credential, the relay leg's counters sized for one connection.
func hookStandProxy(t *testing.T, addr string, udp bool) (*Proxy, *credPool, *TURNCreds) {
	t.Helper()
	creds := &TURNCreds{Username: "u", Password: "pw", Address: addr, Addresses: []string{addr}}
	var mints atomic.Int32
	cp := breakerPool(t, &mints)
	cp.mu.Lock()
	cp.pool[0] = credPoolEntry{addr: addr, ts: time.Now(), active: 1, creds: creds}
	cp.mu.Unlock()
	p := &Proxy{
		config:      Config{UseUDP: udp},
		peer:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, // nobody answers a handshake there
		credPool:    cp,
		connTxBytes: make([]atomic.Int64, 1),
		lastTxAt:    make([]atomic.Int64, 1),
	}
	return p, cp, creds
}

func slotAllocated(cp *credPool) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.pool[0].allocated
}

// The four TURN control sockets tell the hook the relay's address — the
// session goes on to allocate, so the hook's answer (nil) let it through.
func TestTheDialHookIsToldTheRelayByEveryTURNSocket(t *testing.T) {
	for _, tc := range []struct {
		name string
		udp  bool
		srtp bool
	}{
		{"runTURN over TCP", false, false},
		{"runTURN over UDP", true, false},
		{"setupSRTPSession over TCP", false, true},
		{"setupSRTPSession over UDP", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addr string
			if tc.udp {
				addr, _ = udpQuotaTURN(t, 10)
			} else {
				addr = loopbackTURN(t)
			}
			var log hookLog
			installHook(t, log.hook)
			p, cp, creds := hookStandProxy(t, addr, tc.udp)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			if tc.srtp {
				go func() {
					c, err := p.setupSRTPSession(ctx, addr, creds, 0, 0, nil)
					if c != nil {
						_ = c.Close()
					}
					done <- err
				}()
			} else {
				conn1, conn2 := connutil.AsyncPacketPipe()
				defer conn1.Close()
				defer conn2.Close()
				go func() { done <- p.runTURN(ctx, addr, creds, conn2, 0, 0, nil) }()
			}
			waitUntil(t, "the relay to accept the allocation", 5*time.Second, func() bool { return slotAllocated(cp) == 1 })
			cancel()
			<-done
			want := "tcp4 " + addr
			if tc.udp {
				want = "udp4 " + addr
			}
			got := log.calls()
			if len(got) == 0 || got[0] != want {
				t.Fatalf("the hook was told %q, want %q first — the console pins the relay from this call", got, want)
			}
		})
	}
}

var errRefusedByTest = errors.New("refused by the test's hook")

// countingTCP accepts and counts connections; nothing is ever answered.
func countingTCP(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &n
}

// countingUDP counts the datagrams that reach it.
func countingUDP(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			n.Add(1)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String(), &n
}

// A refusal aborts the dial before the socket talks: the far end sees no
// connection and no datagram. This is the ordering the console needs — its
// hook adds the route, and the first packet must follow the route.
func TestADialHookRefusalAbortsTheDialBeforeAnythingIsSent(t *testing.T) {
	for _, tc := range []struct {
		name string
		udp  bool
		srtp bool
	}{
		{"runTURN over TCP", false, false},
		{"runTURN over UDP", true, false},
		{"setupSRTPSession over TCP", false, true},
		{"setupSRTPSession over UDP", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addr string
			var reached *atomic.Int32
			if tc.udp {
				addr, reached = countingUDP(t)
			} else {
				addr, reached = countingTCP(t)
			}
			var asked atomic.Int32
			installHook(t, func(network, address string) error {
				asked.Add(1)
				return errRefusedByTest
			})
			p, _, creds := hookStandProxy(t, addr, tc.udp)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var err error
			if tc.srtp {
				var c net.Conn
				c, err = p.setupSRTPSession(ctx, addr, creds, 0, 0, nil)
				if c != nil {
					_ = c.Close()
				}
			} else {
				conn1, conn2 := connutil.AsyncPacketPipe()
				defer conn1.Close()
				defer conn2.Close()
				err = p.runTURN(ctx, addr, creds, conn2, 0, 0, nil)
			}
			if !errors.Is(err, errRefusedByTest) {
				t.Fatalf("err = %v, want the hook's refusal", err)
			}
			if asked.Load() == 0 {
				t.Fatal("the hook was never asked")
			}
			time.Sleep(150 * time.Millisecond) // a dial that went out anyway would have landed by now
			if n := reached.Load(); n != 0 {
				t.Fatalf("the far end saw %d connection(s)/datagram(s) — the socket talked before (or despite) the hook", n)
			}
		})
	}
}

// The VK session clients and the browser-TLS transport dial through
// net.Dialers whose Control carries the hook.
func TestTheVKAndBrowserDialersAskTheHook(t *testing.T) {
	var log hookLog
	installHook(t, log.hook)
	vk := vkDiagDialer()
	if err := vk.Control("tcp4", "203.0.113.7:443", nil); err != nil {
		t.Fatalf("vkDiagDialer's Control: %v", err)
	}
	br := browserDialer()
	if err := br.Control("tcp4", "203.0.113.8:443", nil); err != nil {
		t.Fatalf("browserDialer's Control: %v", err)
	}
	want := []string{"tcp4 203.0.113.7:443", "tcp4 203.0.113.8:443"}
	if got := log.calls(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the hook was told %q, want %q", got, want)
	}
	installHook(t, func(string, string) error { return errRefusedByTest })
	if err := vk.Control("tcp4", "203.0.113.7:443", nil); !errors.Is(err, errRefusedByTest) {
		t.Fatalf("vkDiagDialer's Control swallowed the refusal: %v", err)
	}
	if err := br.Control("tcp4", "203.0.113.8:443", nil); !errors.Is(err, errRefusedByTest) {
		t.Fatalf("browserDialer's Control swallowed the refusal: %v", err)
	}
}

// With no hook — the app — nothing is refused and nothing is resolved.
func TestNoHookIsANoOp(t *testing.T) {
	SetDialHook(nil)
	if err := beforeDial("tcp4", "203.0.113.7:443"); err != nil {
		t.Fatal(err)
	}
	if err := beforeDialUDP("no-such-host.invalid:3478"); err != nil {
		t.Fatalf("beforeDialUDP resolved (or refused) with no hook: %v", err)
	}
}

// No socket in the package bypasses the hook. Read on the AST of every
// non-test file of pkg/proxy (not the srtpwrap server's listener, a
// sub-package):
//   - every net.Dialer composite literal sets Control;
//   - no zero net.Dialer is declared (`var d net.Dialer` dials around it);
//   - every net.Dial / DialUDP / DialTCP / DialTimeout / ListenUDP /
//     ListenPacket call is preceded, in its function, by beforeDial or
//     beforeDialUDP — except pathSnapshotOSDefault, whose UDP "connect" sends
//     nothing (it asks the kernel which source address a route would use);
//   - every tls_client.WithDialer is given vkDiagDialer().
func TestNoSocketInThePackageBypassesTheDialHook(t *testing.T) {
	exempt := map[string]bool{"pathSnapshotOSDefault": true}
	socketCalls := map[string]bool{"Dial": true, "DialUDP": true, "DialTCP": true, "DialTimeout": true, "ListenUDP": true, "ListenPacket": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var problems []string
	sites := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		isNet := func(e ast.Expr, name string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Name == "net" && sel.Sel.Name == name
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var hookAt []token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && (id.Name == "beforeDial" || id.Name == "beforeDialUDP") {
						hookAt = append(hookAt, c.Pos())
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					if isNet(x.Type, "Dialer") {
						sites++
						hasControl := false
						for _, el := range x.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Control" {
									hasControl = true
								}
							}
						}
						if !hasControl {
							problems = append(problems, fset.Position(x.Pos()).String()+": a net.Dialer without Control")
						}
					}
				case *ast.ValueSpec:
					if x.Type != nil && isNet(x.Type, "Dialer") && len(x.Values) == 0 {
						problems = append(problems, fset.Position(x.Pos()).String()+": a zero net.Dialer — it dials around the hook")
					}
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "net" && socketCalls[sel.Sel.Name] {
							sites++
							if exempt[fn.Name.Name] {
								return true
							}
							before := false
							for _, h := range hookAt {
								if h < x.Pos() {
									before = true
								}
							}
							if !before {
								problems = append(problems, fset.Position(x.Pos()).String()+": net."+sel.Sel.Name+" in "+fn.Name.Name+" with no beforeDial/beforeDialUDP before it")
							}
						}
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "tls_client" && sel.Sel.Name == "WithDialer" {
							sites++
							ok := len(x.Args) == 1
							if ok {
								c, isCall := x.Args[0].(*ast.CallExpr)
								ok = isCall
								if isCall {
									id, isID := c.Fun.(*ast.Ident)
									ok = isID && id.Name == "vkDiagDialer"
								}
							}
							if !ok {
								problems = append(problems, fset.Position(x.Pos()).String()+": tls_client.WithDialer not given vkDiagDialer()")
							}
						}
					}
				}
				return true
			})
		}
	}
	if sites < 8 {
		t.Fatalf("the scan found only %d dial sites — it no longer reads what it was written for", sites)
	}
	if len(problems) > 0 {
		t.Fatalf("sockets that bypass the dial hook:\n  %s", strings.Join(problems, "\n  "))
	}
}
