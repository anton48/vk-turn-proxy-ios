package main

// The console's own log file. Sabotage seen red: the file behind a failed
// stderr gets nothing (io.MultiWriter's way); an earlier run's lines wiped;
// the file readable by others; wireguard's errors written past the log; the
// file not made the log's output; garbage read as the sudo user; the file
// closed at realMain's return, under goroutines that still log.

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type brokenWriter struct{ writes int }

func (b *brokenWriter) Write(p []byte) (int, error) {
	b.writes++
	return 0, errors.New("write |1: broken pipe")
}

func TestTheLogFileOutlivesADeadStderr(t *testing.T) {
	var dead brokenWriter
	var file bytes.Buffer
	l := log.New(fanout{&dead, &file}, "", 0)
	l.Print("first")
	l.Print("second")
	if got := file.String(); got != "first\nsecond\n" {
		t.Errorf("the file got %q behind a stderr that fails every write — want both lines: a dead terminal or pipe must not stop the log", got)
	}
	if dead.writes != 2 {
		t.Errorf("stderr was tried %d time(s), want 2 — it is still written to while it is there", dead.writes)
	}
}

func TestTheLogFileIsAppendedAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "console.log")
	noSudo := func(string) string { return "" }
	for _, line := range []string{"run 1\n", "run 2\n"} {
		f, err := openLog(path, noSudo)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	b, _ := os.ReadFile(path)
	if string(b) != "run 1\nrun 2\n" {
		t.Errorf("the file holds %q — an earlier run's lines stay", b)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("the log is created %o, want 600: it names the relays and the identities", perm)
	}
	if _, err := openLog(t.TempDir(), noSudo); err == nil {
		t.Error("a directory opened as the log")
	}
}

func TestTheSudoUserIsReadFromSudosEnvironment(t *testing.T) {
	env := func(uid, gid string) func(string) string {
		return func(k string) string {
			switch k {
			case "SUDO_UID":
				return uid
			case "SUDO_GID":
				return gid
			}
			return ""
		}
	}
	if uid, gid, ok := sudoOwner(env("501", "20")); !ok || uid != 501 || gid != 20 {
		t.Errorf("sudoOwner(501, 20) = %d, %d, %v", uid, gid, ok)
	}
	for _, bad := range [][2]string{{"", ""}, {"501", ""}, {"", "20"}, {"root", "wheel"}, {"-1", "20"}, {"501", "-5"}} {
		if uid, gid, ok := sudoOwner(env(bad[0], bad[1])); ok {
			t.Errorf("sudoOwner(%q, %q) = %d, %d — not a user to hand a file to", bad[0], bad[1], uid, gid)
		}
	}
}

// captureLog points the log package at a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })
	return &buf
}

func TestWireguardLogsThroughTheLogPackage(t *testing.T) {
	buf := captureLog(t)
	quiet := wgLogger(false)
	quiet.Errorf("handshake %d failed", 3)
	quiet.Verbosef("a verbose line")
	if out := buf.String(); !strings.Contains(out, "(wireguard) ERROR: handshake 3 failed") || strings.Contains(out, "a verbose line") {
		t.Errorf("without -wg-verbose the log holds %q — want the error, and only the error (device.NewLogger writes to stdout, past the log file)", out)
	}
	buf.Reset()
	wgLogger(true).Verbosef("peer %s", "up")
	if out := buf.String(); !strings.Contains(out, "(wireguard) peer up") {
		t.Errorf("with -wg-verbose the log holds %q", out)
	}
}

// -log through realMain: a run that ends at its config leaves the start line
// and the error in the file, and a second run appends.
func TestTheLogFlagPutsTheRunIntoTheFile(t *testing.T) {
	captureLog(t) // restores the log's output after realMain has pointed it at the file
	dir := t.TempDir()
	path := filepath.Join(dir, "console.log")
	missing := filepath.Join(dir, "missing.json")
	for run := 1; run <= 2; run++ {
		if code := realMain([]string{"-log", path, "-config", missing}); code != 2 {
			t.Fatalf("fixture: realMain = %d, want 2 (no such config)", code)
		}
	}
	// What is logged behind realMain's return — the proxy's goroutines print
	// their last stats there — still reaches the file.
	log.Print("a line behind the stop")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no log file: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, "a line behind the stop") {
		t.Errorf("a line logged after realMain returned is not in the file — the file was closed under goroutines that still log:\n%s", out)
	}
	if n := strings.Count(out, "vk-turn-proxy-console "+version+" started "); n != 2 {
		t.Errorf("%d start line(s) in the file after two runs, want 2:\n%s", n, out)
	}
	if n := strings.Count(out, "missing.json"); n < 2 {
		t.Errorf("the config error reached the file %d time(s), want each run's:\n%s", n, out)
	}
	if code := realMain([]string{"-log", dir, "-version"}); code != 0 {
		t.Errorf("-version with an unusable -log = %d, want 0: the version is printed before any file is opened", code)
	}
	if code := realMain([]string{"-log", dir, "-config", missing}); code != 2 {
		t.Errorf("a log that cannot be opened = %d, want 2", code)
	}
}
