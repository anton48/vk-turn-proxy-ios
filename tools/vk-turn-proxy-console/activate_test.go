package main

// The default route's switch (activate). Sabotage seen red: an IPv6 route
// that cannot be made only logged and the switch carried on (the defect of
// 2026-10: IPv4 into the tunnel, IPv6 on the physical path the user asked to
// block); the IPv6 routes made not taken back; the halves not taken back;
// the error not handed to the caller; run going on after it; a failed
// journal entry passed over; the DNS applied before the block.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// routeTable stands for the kernel: it holds what was added, refuses the
// adds it is told to refuse, and answers a delete of a route it does not
// hold as Linux does — the wording alreadyGone takes for done.
type routeTable struct {
	routes map[string]bool
	refuse map[string]bool // an add argv (joined) the kernel refuses
	ran    []string
	onAdd  func(key string) // after a successful add
}

func newRouteTable(refuse ...[]string) *routeTable {
	t := &routeTable{routes: map[string]bool{}, refuse: map[string]bool{}}
	for _, r := range refuse {
		t.refuse[joined(r)] = true
	}
	return t
}

func (t *routeTable) run(argv []string) (string, error) {
	j := joined(argv)
	t.ran = append(t.ran, j)
	if len(argv) < 5 {
		return "", errors.New("unexpected command: " + j)
	}
	key := strings.Join(argv[len(argv)-3:], " ") // "<prefix> dev <if>"
	switch argv[3] {
	case "add":
		if t.refuse[j] {
			return "", errors.New(j + ": exit status 2: RTNETLINK answers: Permission denied")
		}
		t.routes[key] = true
		if t.onAdd != nil {
			t.onAdd(key)
		}
		return "", nil
	case "del":
		if !t.routes[key] {
			return "", errors.New(j + ": exit status 2: RTNETLINK answers: No such process")
		}
		delete(t.routes, key)
		return "", nil
	}
	return "", errors.New("unexpected command: " + j)
}

func (t *routeTable) held() []string {
	var out []string
	for k := range t.routes {
		out = append(out, k)
	}
	return out
}

type recordingDNS struct{ applied int }

func (d *recordingDNS) originals() []string          { return nil }
func (d *recordingDNS) apply(string, []string) error { d.applied++; return nil }
func (d *recordingDNS) refresh(gateway) []string     { return nil }

// switching builds a console at the moment of the switch: the tunnel up, a
// journal on disk, the DNS to manage.
func switching(t *testing.T, blockV6 bool) (*console, *recordingDNS, *journal) {
	t.Helper()
	j := newJournal(filepath.Join(t.TempDir(), "state.json"))
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	dns := &recordingDNS{}
	c := &console{j: j, tun: "vktp0", dns: dns,
		dnsPlan: dnsPlan{managed: true, servers: []string{"203.0.113.53"}},
		pin:     newPinner(linuxCmds{}, func([]string) (string, error) { return "", nil }, j, t.Logf)}
	c.st.NumConns = 2
	c.pin.blockV6 = blockV6
	return c, dns, j
}

func two() int { return 2 }

func TestAnIPv6BlockThatCannotBeMadeEndsTheActivation(t *testing.T) {
	v6 := linuxCmds{}.ipv6Block("vktp0")
	for _, tc := range []struct {
		name   string
		refuse [][]string
	}{
		{"both IPv6 routes refused", [][]string{v6[0].add, v6[1].add}},
		{"the first refused", [][]string{v6[0].add}},
		{"the second refused, the first made", [][]string{v6[1].add}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, dns, j := switching(t, true)
			table := newRouteTable(tc.refuse...)
			logs := captureLog(t)
			err := c.activate(linuxCmds{}, table.run, two)
			if err == nil || !strings.Contains(err.Error(), "-block-ipv6") {
				t.Fatalf("activate = %v, want the -block-ipv6 error that stops the console", err)
			}
			if held := table.held(); len(held) != 0 {
				t.Fatalf("routes left in the table: %v — every route the switch made is to be taken back", held)
			}
			if j.hasPrefix("route ") {
				t.Fatalf("the journal still records routes: %+v", j.doc.Undo)
			}
			if dns.applied != 0 {
				t.Fatalf("the DNS was applied %d time(s) — an activation that ends touches no DNS", dns.applied)
			}
			if strings.Contains(logs.String(), "DEFAULT ROUTE") {
				t.Fatalf("the log announces the default route in the tunnel:\n%s", logs)
			}
		})
	}
}

func TestAJournalThatCannotRecordTheIPv6BlockEndsTheActivation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	c, dns, j := switching(t, true)
	dir := filepath.Dir(j.path)
	table := newRouteTable()
	table.onAdd = func(key string) {
		if strings.HasPrefix(key, "128.0.0.0/1") { // the second half made: the journal can write no more
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := c.activate(linuxCmds{}, table.run, two)
	if err == nil || !strings.Contains(err.Error(), "-block-ipv6") {
		t.Fatalf("activate = %v, want the -block-ipv6 error", err)
	}
	for _, r := range table.ran {
		if strings.Contains(r, "-6 route add") {
			t.Fatalf("an IPv6 route made with no undo journaled for it: %q", r)
		}
	}
	if held := table.held(); len(held) != 0 {
		t.Fatalf("routes left in the table: %v", held)
	}
	if dns.applied != 0 {
		t.Fatalf("the DNS was applied")
	}
}

func TestTheActivationMakesEveryRouteAndThenTheDNS(t *testing.T) {
	for _, block := range []bool{true, false} {
		c, dns, j := switching(t, block)
		// Without -block-ipv6 the IPv6 routes are not asked for at all: a
		// kernel that would refuse them changes nothing.
		v6 := linuxCmds{}.ipv6Block("vktp0")
		table := newRouteTable()
		if !block {
			table = newRouteTable(v6[0].add, v6[1].add)
		}
		logs := captureLog(t)
		if err := c.activate(linuxCmds{}, table.run, two); err != nil {
			t.Fatalf("block=%v: activate = %v", block, err)
		}
		want := 2
		if block {
			want = 4
		}
		if n := len(table.held()); n != want {
			t.Fatalf("block=%v: %d route(s) in the table, want %d: %v", block, n, want, table.held())
		}
		if dns.applied != 1 || !strings.Contains(logs.String(), "DEFAULT ROUTE → the tunnel") {
			t.Fatalf("block=%v: dns applied %d, log:\n%s", block, dns.applied, logs)
		}
		if !j.hasPrefix("route split ") || j.hasPrefix("route ipv6 ") != block {
			t.Fatalf("block=%v: the journal: %+v", block, j.doc.Undo)
		}
	}
}

func TestAHalfThatCannotBeMadeKeepsTheDefaultRoutePhysical(t *testing.T) {
	c, dns, _ := switching(t, true)
	split := linuxCmds{}.splitRoutes("vktp0")
	table := newRouteTable(split[1].add)
	logs := captureLog(t)
	if err := c.activate(linuxCmds{}, table.run, two); err != nil {
		t.Fatalf("activate = %v — a half that cannot be made leaves the console running, as before", err)
	}
	if held := table.held(); len(held) != 0 {
		t.Fatalf("routes left: %v", held)
	}
	for _, r := range table.ran {
		if strings.Contains(r, "-6 route add") {
			t.Fatalf("the IPv6 block asked with the halves gone: %q", r)
		}
	}
	if dns.applied != 0 || strings.Contains(logs.String(), "DEFAULT ROUTE") {
		t.Fatalf("dns applied %d, log:\n%s", dns.applied, logs)
	}
}

// run hands an activation that ends to its deferred shutdown with a non-zero
// exit — read in the source, as the stop's order is (stop_test.go).
func TestRunStopsWhenTheActivationEnds(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run, sw *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil {
			switch fd.Name.Name {
			case "run":
				run = fd
			case "switchDefaultRoute":
				sw = fd
			}
		}
	}
	if run == nil || sw == nil {
		t.Fatal("console.run or console.switchDefaultRoute not found")
	}
	// switchDefaultRoute returns activate's error itself.
	handsOn := false
	ast.Inspect(sw.Body, func(n ast.Node) bool {
		if r, ok := n.(*ast.ReturnStmt); ok && len(r.Results) == 2 {
			if call, ok := r.Results[1].(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "activate" {
					handsOn = true
				}
			}
		}
		return true
	})
	if !handsOn {
		t.Fatal("switchDefaultRoute does not return activate's error")
	}
	// In run: the statement right behind the call checks ITS error and that
	// branch returns a non-zero code (run has many other err checks).
	stops := false
	ast.Inspect(run.Body, func(n ast.Node) bool {
		blk, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, st := range blk.List {
			as, ok := st.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 2 || len(as.Rhs) != 1 || i+1 >= len(blk.List) {
				continue
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "switchDefaultRoute" {
				continue
			}
			errName := as.Lhs[1].(*ast.Ident).Name
			ifs, ok := blk.List[i+1].(*ast.IfStmt)
			if !ok {
				continue
			}
			be, ok := ifs.Cond.(*ast.BinaryExpr)
			if !ok || be.Op != token.NEQ {
				continue
			}
			if id, ok := be.X.(*ast.Ident); !ok || id.Name != errName {
				continue
			}
			for _, b := range ifs.Body.List {
				if r, ok := b.(*ast.ReturnStmt); ok && len(r.Results) == 1 {
					if lit, ok := r.Results[0].(*ast.BasicLit); ok && lit.Value != "0" {
						stops = true
					}
				}
			}
		}
		return true
	})
	if !stops {
		t.Fatal("run goes on (or exits 0) when switchDefaultRoute reports that the activation ended")
	}
}
