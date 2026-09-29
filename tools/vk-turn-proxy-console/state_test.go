package main

// The state file. Sabotage seen red: the undos replayed oldest first; a
// failed undo dropped from the file; the file removed with changes still
// recorded; a leftover not taken back at the next start; a file content not
// put back.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUndosRunNewestFirstAndAFailureStaysRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	j := newJournal(path)
	for _, k := range []string{"a", "b", "c"} {
		if err := j.add(undoStep{Key: k, Argv: []string{"undo", k}}); err != nil {
			t.Fatal(err)
		}
	}
	var ran []string
	failed := j.undoAll(func(argv []string) error {
		ran = append(ran, argv[1])
		if argv[1] == "b" {
			return os.ErrPermission
		}
		return nil
	}, t.Logf)
	if strings.Join(ran, "") != "cba" {
		t.Fatalf("ran %q, want newest first", ran)
	}
	if len(failed) != 1 || !j.has("b") || j.has("a") || j.has("c") {
		t.Fatalf("after the undo: %v, failed %v", j.doc.Undo, failed)
	}
	if err := j.remove(); err == nil {
		t.Fatal("the file removed with a change still recorded")
	}
	d, err := readState(path)
	if err != nil || d == nil || len(d.Undo) != 1 || d.Undo[0].Key != "b" {
		t.Fatalf("the file: %+v, %v", d, err)
	}
}

func TestALeftoverIsTakenBackAtTheNextStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	conf := filepath.Join(dir, "resolv.conf")
	writeFile(t, conf, "nameserver 1.1.1.1\n")
	j := newJournal(path)
	j.doc.PID = 999999 // a process that is not running
	_ = j.add(undoStep{Key: "dns " + conf, File: conf, Content: "nameserver 192.168.1.1\n", Perm: 0o644})
	_ = j.add(undoStep{Key: "pin 203.0.113.50", Argv: []string{"route", "delete", "203.0.113.50/32"}})
	var ran []string
	_, err := recoverLeftovers(path, func(argv []string) error { ran = append(ran, strings.Join(argv, " ")); return nil }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "nameserver 192.168.1.1\n" {
		t.Fatalf("resolv.conf = %q, not put back", b)
	}
	if strings.Join(ran, "|") != "route delete 203.0.113.50/32" {
		t.Fatalf("ran %q", ran)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the state file stays after everything was taken back")
	}
	if _, err := recoverLeftovers(path, nil, t.Logf); err != nil {
		t.Fatalf("no state file: %v", err)
	}
}

func TestADuplicateKeyIsRecordedOnce(t *testing.T) {
	j := newJournal(filepath.Join(t.TempDir(), "state.json"))
	_ = j.add(undoStep{Key: "pin 203.0.113.50", Argv: []string{"x"}})
	_ = j.add(undoStep{Key: "pin 203.0.113.50", Argv: []string{"y"}})
	if len(j.doc.Undo) != 1 || j.doc.Undo[0].Argv[0] != "x" {
		t.Fatalf("undo = %v", j.doc.Undo)
	}
}

func TestUndoPrefixTakesBackOneKind(t *testing.T) {
	j := newJournal(filepath.Join(t.TempDir(), "state.json"))
	_ = j.add(undoStep{Key: "dns x", Argv: []string{"dns"}})
	_ = j.add(undoStep{Key: "route split 0.0.0.0/1", Argv: []string{"r1"}})
	_ = j.add(undoStep{Key: "route split 128.0.0.0/1", Argv: []string{"r2"}})
	var ran []string
	j.undoPrefix("route ", func(argv []string) error { ran = append(ran, argv[0]); return nil }, t.Logf)
	if strings.Join(ran, ",") != "r2,r1" || !j.has("dns x") || j.hasPrefix("route ") {
		t.Fatalf("ran %q, left %v", ran, j.doc.Undo)
	}
}

// An undo whose target is already gone is done: on FreeBSD the two halves go
// with the tun when the process dies (the stand, 2026-09-29), and a step that
// insisted kept the state file — every later start would have refused.
func TestAnUndoWhoseTargetIsGoneIsDone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	j := newJournal(path)
	j.doc.PID = 999999
	_ = j.add(undoStep{Key: "route split 0.0.0.0/1", Argv: []string{"route", "delete"}})
	_ = j.add(undoStep{Key: "iface vktp0", Argv: []string{"ifconfig", "destroy"}})
	_ = j.add(undoStep{Key: "pin 203.0.113.50", Argv: []string{"ip", "del"}})
	_ = j.add(undoStep{Key: "dns resolvectl vktp0", Argv: []string{"resolvectl", "revert"}})
	_ = j.add(undoStep{Key: "route subnet 192.168.102.0/24", Argv: []string{"route-darwin", "delete"}})
	_ = j.add(undoStep{Key: "route split 128.0.0.0/1", Argv: []string{"really", "fails"}})
	_ = j.add(undoStep{Key: "pin 203.0.113.51", Argv: []string{"route-malformed", "delete"}})
	gone := map[string]string{
		"route":           "route: route has not been found",
		"route-darwin":    "route: bad address: utun8",
		"ifconfig":        "ifconfig: interface vktp0 does not exist",
		"ip":              "RTNETLINK answers: No such process",
		"resolvectl":      `Failed to resolve interface "vktp0": No such device`,
		"really":          "permission denied",
		"route-malformed": "route: bad address: 203.0.113",
	}
	failed := j.undoAll(func(argv []string) error { return errors.New(argv[0] + ": exit status 68: " + gone[argv[0]]) }, t.Logf)
	var keys []string
	for _, f := range failed {
		keys = append(keys, f.Key)
	}
	if strings.Join(keys, ",") != "pin 203.0.113.51,route split 128.0.0.0/1" {
		t.Fatalf("failed = %v — a target already gone is taken back (a utun that died with its process too); a real failure is not, nor a bad address that is not a utun", keys)
	}
}

// The state file carries the run's transport — after a crash it says whether
// the kernel's close freed the seats (cache.go). The source says where it is
// set: in run, before the journal's first save.
func TestTheRunRecordsItsTransport(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	set := strings.Index(s, "c.j.setTransport(transportName(c.st.UseUDP))")
	save := strings.Index(s, "if err := c.j.save(); err != nil {")
	if set < 0 || save < 0 || set > save {
		t.Fatalf("the journal's transport is set at %d, its first save at %d — it must be set before the file is first written", set, save)
	}
	j := newJournal(filepath.Join(t.TempDir(), "state.json"))
	j.setTransport("udp")
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	d, err := readState(j.path)
	if err != nil || d.Transport != "udp" {
		t.Fatalf("the saved state: %+v, %v", d, err)
	}
}
