package main

// The stop. Sabotage seen red: SIGPIPE not ignored (the console killed by its
// own log line once the log's reader is gone — what Ctrl-C did through
// `| tee`); ignored only after the first output; the pins taken back after
// the proxy's stop instead of before it; the dial hook left on while they go.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	brokenPipeOut  = "VKTPC_BROKEN_PIPE_OUT"
	brokenPipeArgs = "VKTPC_BROKEN_PIPE_ARGS"
)

// The helper process of the test below: this test binary re-executed with its
// stdout and stderr on a pipe nobody reads. It waits for the parent's word
// that the pipe is broken, runs realMain and leaves the exit code in a file.
func TestHelperRealMainOnABrokenPipe(t *testing.T) {
	out := os.Getenv(brokenPipeOut)
	if out == "" {
		return // not the helper
	}
	var one [1]byte
	_, _ = os.Stdin.Read(one[:])
	code := realMain(strings.Split(os.Getenv(brokenPipeArgs), "|"))
	if err := os.WriteFile(out, []byte(strconv.Itoa(code)), 0o600); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestABrokenLogPipeDoesNotKillTheConsole(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
		want string // realMain's own exit code
	}{
		{"the first line on stdout", []string{"-version"}, "0"},
		{"a log line on stderr", []string{"-config", filepath.Join(dir, "missing.json")}, "2"},
	} {
		out := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperRealMainOnABrokenPipe$")
		cmd.Env = append(os.Environ(), brokenPipeOut+"="+out, brokenPipeArgs+"="+strings.Join(tc.args, "|"))
		cmd.Stdout, cmd.Stderr = w, w
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// Nobody reads the pipe from here on: whatever the child writes to its
		// stdout or stderr is a write to a broken pipe — tee after Ctrl-C.
		w.Close()
		r.Close()
		if _, err := stdin.Write([]byte{1}); err != nil {
			t.Fatalf("%s: fixture: the helper was not told to go: %v", tc.name, err)
		}
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("%s: the console died of its own output (%v) — a write to a closed stdout / stderr ends a Go program with SIGPIPE unless the signal is ignored BEFORE the first byte is written; a process that owes a cleanup must outlive its log", tc.name, err)
			continue
		}
		b, err := os.ReadFile(out)
		if err != nil || string(b) != tc.want {
			t.Errorf("%s: realMain returned %q (%v), want %s — fixture: it must run to its own return", tc.name, b, err, tc.want)
		}
	}
}

// The shutdown's order, read in the source (running it would change this
// machine's routes): the split routes, the dial hook off, the pins, and only
// then the proxy's stop — where the log is written most, and where the field
// run died with the pins still in the table.
func TestThePinsAreTakenBackBeforeTheProxyStops(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "shutdown" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("no shutdown in main.go")
	}
	// The position of the first call of each step, by what is called.
	at := map[string]token.Pos{}
	note := func(name string, pos token.Pos) {
		if _, seen := at[name]; !seen {
			at[name] = pos
		}
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		s, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch s.Sel.Name {
		case "undoPrefix":
			if lit, ok := call.Args[0].(*ast.BasicLit); ok {
				note("undo "+lit.Value, call.Pos())
			}
		case "SetDialHook":
			if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "nil" {
				note("hook off", call.Pos())
			}
		case "removeAll", "StopWithTimeout":
			note(s.Sel.Name, call.Pos())
		}
		return true
	})
	order := []string{`undo "dns "`, `undo "route "`, "hook off", "removeAll", "StopWithTimeout", `undo ""`}
	for i, step := range order {
		if at[step] == token.NoPos {
			t.Fatalf("shutdown has no step %s", step)
		}
		if i > 0 && at[order[i-1]] >= at[step] {
			t.Errorf("shutdown runs %s before %s — want the order %v: the pins leave with the routes into the tunnel, before anything that can end the process", step, order[i-1], order)
		}
	}
}
