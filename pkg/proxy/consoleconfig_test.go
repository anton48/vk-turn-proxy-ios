package proxy

// Two Config fields the console sets and the app never does (0 = the app's
// behaviour, pinned here with the console's):
//   - GOMAXPROCS: Start pins the scheduler to 2 threads for the iOS
//     extension's wake-up budget; the console leaves Go's default (< 0) or sets
//     its own (> 0).
//   - CredPoolSize: the console's pool is (1 + R) reserve sets instead of the
//     app's four identities per ten connections — in anonymous mode; cookie
//     mode keeps one slot per relay.
//
// Sabotage seen red: applyGOMAXPROCS pinning 2 whatever it is told; Start
// calling runtime.GOMAXPROCS(2) again; the override ignored; the override
// applied after the cookie branch (cookie mode's size lost).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"runtime"
	"strings"
	"testing"
)

func TestStartsThreadCountComesFromTheConfig(t *testing.T) {
	prev := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
	for _, tc := range []struct {
		cfg, before, want int
	}{
		{0, 5, 2},  // the app: two threads, whatever Go chose
		{3, 5, 3},  // the console's -gomaxprocs 3
		{-1, 5, 5}, // the console's default: Go's own count left alone
	} {
		runtime.GOMAXPROCS(tc.before)
		applyGOMAXPROCS(tc.cfg)
		if got := runtime.GOMAXPROCS(0); got != tc.want {
			t.Errorf("applyGOMAXPROCS(%d) from %d → %d threads, want %d", tc.cfg, tc.before, got, tc.want)
		}
	}
}

// Start takes its thread count from the config, and nothing else in the
// package sets one: a runtime.GOMAXPROCS call with an argument other than 0
// (0 only reads) lives in applyGOMAXPROCS alone, and Start calls it with
// p.config.GOMAXPROCS.
func TestOnlyTheConfigSetsTheThreadCount(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	startCalls := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					c, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "runtime" && sel.Sel.Name == "GOMAXPROCS" {
							reads := len(c.Args) == 1
							if lit, ok := c.Args[0].(*ast.BasicLit); !ok || lit.Value != "0" {
								reads = false
							}
							if !reads && fn.Name.Name != "applyGOMAXPROCS" {
								t.Errorf("%s: runtime.GOMAXPROCS set in %s — the thread count belongs to applyGOMAXPROCS", fset.Position(c.Pos()), fn.Name.Name)
							}
						}
					}
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "applyGOMAXPROCS" && fn.Name.Name == "Start" && fn.Recv != nil {
						if len(c.Args) == 1 {
							if sel, ok := c.Args[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "GOMAXPROCS" {
								if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "config" {
									startCalls++
								}
							}
						}
					}
					return true
				})
			}
		}
	}
	if startCalls != 1 {
		t.Fatalf("Start calls applyGOMAXPROCS(p.config.GOMAXPROCS) %d times, want 1", startCalls)
	}
}

func TestTheConsolesPoolSizeReplacesTheFormulaInAnonymousModeOnly(t *testing.T) {
	SetVKCookieAuth(false, "", nil)
	t.Cleanup(func() { SetVKCookieAuth(false, "", nil) })
	size := func(cfg Config) int {
		cfg.PeerAddr = "127.0.0.1:1"
		p := NewProxy(cfg)
		t.Cleanup(p.Stop)
		return p.credPool.size
	}
	if got := size(Config{NumConns: 30}); got != 12 {
		t.Errorf("the app's pool at 30 connections = %d slots, want 12 (poolSizeForNumConns)", got)
	}
	if got := size(Config{NumConns: 30, CredPoolSize: 6}); got != 6 {
		t.Errorf("the console's pool at 30 connections, one reserve set = %d slots, want 6", got)
	}
	if got := size(Config{NumConns: 120, CredPoolSize: 24}); got != 24 {
		t.Errorf("the console's pool at 120 connections = %d slots, want 24", got)
	}
	SetVKCookieAuth(true, "remixsid=x; p=y", []string{"https://vk.ru/call/join/aaa", "https://vk.ru/call/join/bbb"})
	if got := size(Config{NumConns: 30, CredPoolSize: 6}); got != 4 {
		t.Errorf("cookie mode with the console's override = %d slots, want 4 — one per relay, two per link, whatever the override says", got)
	}
}
