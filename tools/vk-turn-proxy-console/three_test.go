package main

// Three of the user's remarks of 2026-10-18 (the second list). Sabotage seen
// red: a loss of the path not remembered (pins recorded via a gateway that
// came back the same were trusted though they went with the interface); the
// recheck skipped, or answering «there» for a route that is gone, or run at
// every gateway reading; the stop not closing the system's DNS, a closed DNS
// still refreshing or applying (a late monitor handler wrote the tunnel's DNS
// over the restored file after «stopped»); commands unbounded; a journal entry
// kept in memory after its save failed (the next ask found it «recorded» and
// made the change with no undo on disk).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 1. The interface went and came back with the same address and name.
func TestPinsAreRecheckedWhenThePathComesBackTheSame(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmds    netCmds
		freebsd bool
	}{
		{"macOS", darwinCmds{}, false},
		{"FreeBSD", freebsdCmds{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, f, _ := bsdPinner(t, tc.cmds, tc.freebsd)
			gw := p.gw
			if err := p.ensure("203.0.113.50"); err != nil {
				t.Fatal(err)
			}
			p.setGateway(gateway{}, false, nil) // the interface went …
			f.vanish("203.0.113.50")            // … and its routes with it
			p.setGateway(gw, true, nil)         // back, the same gateway
			if _, ok := f.via("203.0.113.50"); !ok {
				t.Fatal("the pin is not in the table after the path came back — the next dial would go into the tunnel")
			}
			if f.coverChanged != 0 {
				t.Fatalf("a missing /32 was «changed»: %d covering route(s) re-pointed", f.coverChanged)
			}
			before := len(f.list())
			if err := p.ensure("203.0.113.50"); err != nil || len(f.list()) != before {
				t.Fatalf("an ask after the recheck ran %q (%v)", f.list()[before:], err)
			}
		})
	}
}

func TestLinuxRecheckIsAReplaceAndNoneWithoutALoss(t *testing.T) {
	p, f, _ := testPinner(t)
	p.cmds = linuxCmds{}
	gw := p.gw
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	before := len(f.list())
	p.setGateway(gw, true, nil) // a reading with no loss in between: nothing to check
	if cmds := f.list()[before:]; len(cmds) != 0 {
		t.Fatalf("a gateway reading with no loss ran %q — want nothing", cmds)
	}
	p.setGateway(gateway{}, false, nil)
	p.setGateway(gw, true, nil)
	got := strings.Join(f.list()[before:], "\n")
	if !strings.Contains(got, "ip -4 route replace 203.0.113.50/32 via 192.168.1.1 dev en0") {
		t.Fatalf("after the loss Linux's recheck ran:\n%s\nwant a replace (it makes a route that is gone)", got)
	}
}

func TestARouteStillThereIsOnlyAsked(t *testing.T) {
	p, f, _ := bsdPinner(t, darwinCmds{}, false)
	gw := p.gw
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	before := len(f.list())
	p.setGateway(gateway{}, false, nil)
	p.setGateway(gw, true, nil) // the route survived (a Wi-Fi blip)
	for _, c := range f.list()[before:] {
		if !strings.Contains(c, " get ") {
			t.Fatalf("a pin still in the table was touched: %q", c)
		}
	}
}

// 2. A handler the stop could not wait out changes the DNS no more.
func TestAHandlerPastTheStopsWaitChangesTheDNSNoMore(t *testing.T) {
	c, rc, orig, d := stopping(t)
	c.dns = &lockedDNS{d: d}
	saved := monitorStopWait
	monitorStopWait = 50 * time.Millisecond
	defer func() { monitorStopWait = saved }()
	inHandler, loopDone := make(chan struct{}), make(chan struct{})
	c.startMonitor(context.Background(), func(ctx context.Context) {
		defer close(loopDone)
		close(inHandler)
		time.Sleep(300 * time.Millisecond) // a command hanging past the stop's wait
		c.dns.refresh(gateway{})           // the handler's refresh, after «stopped»
	})
	<-inHandler
	c.shutdown()
	<-loopDone
	cleanAfterTheStop(t, c, rc, orig)
}

func TestAClosedSystemDNSRefusesToApply(t *testing.T) {
	inner := &listDNS{network: []string{"192.0.2.53"}}
	l := &lockedDNS{d: inner}
	_ = l.refresh(gateway{})
	l.close()
	if err := l.apply("vktp0", []string{"9.9.9.9"}); err == nil || len(inner.applied) != 0 {
		t.Fatalf("apply after the close: %v, applied %v — want refused, nothing applied", err, inner.applied)
	}
	if got := strings.Join(l.refresh(gateway{}), ","); got != "192.0.2.53" {
		t.Fatalf("refresh after the close: %q — want the last answer", got)
	}
}

func TestACommandIsKilledAtItsBound(t *testing.T) {
	saved := cmdTimeout
	cmdTimeout = 200 * time.Millisecond
	defer func() { cmdTimeout = saved }()
	t0 := time.Now()
	_, err := runCmd([]string{"sleep", "5"})
	if took := time.Since(t0); err == nil || took > 3*time.Second || !strings.Contains(err.Error(), "killed after") {
		t.Fatalf("a hanging command: %v after %s — want it killed at the bound", err, took)
	}
}

// 3. A save that failed leaves nothing «recorded».
func TestAJournalEntryWhoseSaveFailedIsNotKept(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	dir := t.TempDir()
	j := newJournal(filepath.Join(dir, "state.json"))
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := j.add(undoStep{Key: pinKey("203.0.113.50"), Argv: []string{"route", "delete"}}); err == nil {
		t.Fatal("fixture: the save did not fail")
	}
	if j.has(pinKey("203.0.113.50")) {
		t.Fatal("an entry whose save failed is kept in memory — the next add would find it «recorded» and write nothing")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := j.add(undoStep{Key: pinKey("203.0.113.50"), Argv: []string{"route", "delete"}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(j.path)
	if err != nil || !strings.Contains(string(b), pinKey("203.0.113.50")) {
		t.Fatalf("the file after the second add (%v):\n%s\nwant the undo on disk", err, b)
	}
}

func TestAPinRetriedAfterAFailedSaveHasItsUndoOnDisk(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	p, f, j := testPinner(t)
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(j.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := p.ensure("203.0.113.50"); err == nil {
		t.Fatal("fixture: the journal did not fail")
	}
	if _, ok := f.via("203.0.113.50"); ok {
		t.Fatal("a pin made with its undo not on disk")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.ensure("203.0.113.50"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(j.path)
	if _, ok := f.via("203.0.113.50"); !ok || !strings.Contains(string(b), pinKey("203.0.113.50")) {
		t.Fatalf("after the retry: the pin in the table %v, the file:\n%s\nwant both", ok, b)
	}
}
