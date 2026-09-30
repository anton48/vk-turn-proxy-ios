//go:build unix

package main

// The pid file. Sabotage seen red: no lock taken (a bare number: a second
// console starts beside the first); the refusal not said as "running"; the
// pid not written; the file left behind a clean stop; a lock on a file that
// is no longer at the path accepted; guarded running its function without
// the lock, or letting the lock go before the function has returned; the
// console or the -cleanup run outside the guard.

import (
	"bufio"
	"errors"
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

const pidFileHold = "VKTPC_PIDFILE_HOLD"

// The helper process of the tests below: this test binary re-executed to BE
// another console as far as the pid file goes — it takes the file, says so,
// and holds it until its stdin ends or it is killed.
func TestHelperHoldThePidFile(t *testing.T) {
	path := os.Getenv(pidFileHold)
	if path == "" {
		return // not the helper
	}
	if _, err := takePidFile(path); err != nil {
		os.Stdout.WriteString("refused: " + err.Error() + "\n")
		os.Exit(3)
	}
	os.Stdout.WriteString("holding\n")
	var one [1]byte
	_, _ = os.Stdin.Read(one[:])
	os.Exit(0) // without a release: the file stays, as behind a kill
}

// holder starts the helper and waits until it holds the pid file.
func holder(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldThePidFile$")
	cmd.Env = append(os.Environ(), pidFileHold+"="+path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cmd.StdinPipe(); err != nil { // held open: the helper waits on it
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "holding" {
		t.Fatalf("fixture: the helper says %q, want it to hold the pid file", line)
	}
	return cmd
}

func pidIn(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no pid file: %v", err)
	}
	if !strings.HasSuffix(string(b), "\n") {
		t.Errorf("the pid file holds %q — a pid and a newline, as every pid file", b)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func TestASecondConsoleIsRefusedWhileTheFirstHoldsThePidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.pid")
	first, err := takePidFile(path)
	if err != nil {
		t.Fatalf("the first console: %v", err)
	}
	if pid := pidIn(t, path); pid != os.Getpid() {
		t.Errorf("the pid file names %d, want this process, %d", pid, os.Getpid())
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the pid file's mode: %v (%v), want 644 — it is read by whoever asks who runs", fi.Mode().Perm(), err)
	}
	_, err = takePidFile(path)
	var running *runningError
	if !errors.As(err, &running) {
		t.Fatalf("a second console beside the first: %v — want it refused as RUNNING: two consoles fight over the default route and the DNS", err)
	}
	if running.pid != os.Getpid() || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Errorf("the refusal %q names neither the holder's pid (%d) nor the file", err, os.Getpid())
	}
	first.release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the pid file is still there after a clean stop (%v)", err)
	}
	again, err := takePidFile(path)
	if err != nil {
		t.Fatalf("after the first console stopped: %v", err)
	}
	again.release()
}

// The lock says "running", not the number: it goes with the process however
// it dies. A file a kill -9 left behind stops nobody — and a live holder
// stops everybody, whatever its name.
func TestAPidFileLeftByADeadProcessStopsNobody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.pid")
	writeFile(t, path, "999999\n") // a number and no lock: a run that died long ago
	pf, err := takePidFile(path)
	if err != nil {
		t.Fatalf("a stale pid file stopped the console: %v", err)
	}
	if pid := pidIn(t, path); pid != os.Getpid() {
		t.Errorf("the stale file names %d after the take, want %d", pid, os.Getpid())
	}
	pf.release()

	other := holder(t, path)
	_, err = takePidFile(path)
	var running *runningError
	if !errors.As(err, &running) || running.pid != other.Process.Pid {
		t.Fatalf("beside a live holder (pid %d): %v — want it refused, naming that pid", other.Process.Pid, err)
	}
	if err := other.Process.Kill(); err != nil { // kill -9: no release runs
		t.Fatal(err)
	}
	_ = other.Wait()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture: the killed holder's file is gone (%v) — the case is the file that STAYS", err)
	}
	pf, err = takePidFile(path)
	if err != nil {
		t.Fatalf("the file of a killed console stopped the next one: %v", err)
	}
	pf.release()
}

// A console that is just stopping removes its file. A taker that opened the
// file before that and locked it after holds a file nobody can find: it must
// notice and take the one at the path.
func TestTheLockIsOnTheFileThatIsAtThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.pid")
	writeFile(t, path, "")
	swapped := 0
	betweenOpenAndLock = func() {
		if swapped++; swapped > 1 {
			return
		}
		if err := os.Remove(path); err != nil { // the stopping console's release …
			t.Errorf("fixture: %v", err)
		}
		writeFile(t, path, "") // … and the file of whoever comes next
	}
	t.Cleanup(func() { betweenOpenAndLock = nil })
	pf, err := takePidFile(path)
	betweenOpenAndLock = nil
	if err != nil {
		t.Fatal(err)
	}
	if swapped == 0 {
		t.Fatal("fixture: the file was never replaced under the taker")
	}
	if pid := pidIn(t, path); pid != os.Getpid() {
		t.Errorf("the file AT the path names %d, want %d — the taker holds a file that is no longer the pid file", pid, os.Getpid())
	}
	if _, err := takePidFile(path); err == nil {
		t.Error("a second console took the pid file at the path — the first one's lock is on a file that was removed")
	}
	pf.release()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !stillAt(f, path) {
		t.Error("stillAt: the open file IS the one at the path")
	}
	os.Remove(path)
	if stillAt(f, path) {
		t.Error("stillAt: true for a path that is gone")
	}
	writeFile(t, path, "")
	if stillAt(f, path) {
		t.Error("stillAt: true for another file under the same name")
	}
}

func TestAPidFileThatCannotBeMadeIsAnErrorNotARunningConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-directory", "console.pid")
	_, err := takePidFile(path)
	var running *runningError
	if err == nil || errors.As(err, &running) {
		t.Fatalf("a pid file in a directory that is not there: %v — want an error that is not «running»", err)
	}
	if !strings.Contains(err.Error(), "-pid-file") {
		t.Errorf("the error %q does not say what to do", err)
	}
}

func TestGuardedRunsNothingBesideARunningConsole(t *testing.T) {
	buf := captureLog(t)
	path := filepath.Join(t.TempDir(), "console.pid")
	other := holder(t, path)
	ran := false
	if code := guarded(path, func() int { ran = true; return 0 }); code != 1 || ran {
		t.Errorf("beside a running console guarded returned %d and ran its function: %v — want 1 and nothing run: a -cleanup there takes a live tunnel's routes away", code, ran)
	}
	if !strings.Contains(buf.String(), "another vk-turn-proxy-console is running (pid "+strconv.Itoa(other.Process.Pid)+")") {
		t.Errorf("the refusal is not in the log: %q", buf.String())
	}
	_ = other.Process.Kill()
	_ = other.Wait()

	heldInside := false
	code := guarded(path, func() int {
		_, err := takePidFile(path)
		var running *runningError
		heldInside = errors.As(err, &running)
		return 7
	})
	if code != 7 || !heldInside {
		t.Errorf("guarded returned %d, the lock held while its function ran: %v — want the function's own code, under the lock", code, heldInside)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the pid file is still there after guarded returned (%v)", err)
	}
}

// Everything that changes the machine runs under the guard: the console
// itself and the -cleanup — read in the source (both need root to run).
func TestTheConsoleAndTheCleanupRunUnderTheGuard(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	type span struct{ from, to token.Pos }
	var zones []span // the function literals handed to guarded(…)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "guarded" {
			for _, a := range call.Args {
				if lit, ok := a.(*ast.FuncLit); ok {
					zones = append(zones, span{lit.Pos(), lit.End()})
				}
			}
		}
		return true
	})
	guardedAt := func(p token.Pos) bool {
		for _, z := range zones {
			if p >= z.from && p < z.to {
				return true
			}
		}
		return false
	}
	runs, recovers := 0, 0
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		inConsoleRun := fd.Name.Name == "run" && fd.Recv != nil
		ast.Inspect(fd, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "c" && fn.Sel.Name == "run" {
					runs++
					if !guardedAt(call.Pos()) {
						t.Errorf("c.run at %s is not under guarded(…) — a second console would start beside the first", fset.Position(call.Pos()))
					}
				}
			case *ast.Ident:
				if fn.Name == "recoverLeftovers" {
					recovers++
					if !inConsoleRun && !guardedAt(call.Pos()) {
						t.Errorf("recoverLeftovers at %s is not under guarded(…) — it would take back a LIVE console's changes", fset.Position(call.Pos()))
					}
				}
			}
			return true
		})
	}
	if runs != 1 || recovers != 2 {
		t.Errorf("main.go calls c.run %d time(s) and recoverLeftovers %d — want 1 and 2 (the run's own, the -cleanup's): the scan must see them to vouch for them", runs, recovers)
	}
}
