// SPDX-License-Identifier: MIT

package main

// The state file: every change the console makes to the system, with its undo,
// written BEFORE the change. A clean exit takes the changes back and deletes
// the file; a crash (kill -9, a panic, a power cut) leaves it, and the next
// start — or `-cleanup` — replays the undos, newest first. What outlives the
// process is exactly what needs it: the pins (/32 routes via the physical
// gateway), the system DNS (networksetup on macOS persists across a reboot;
// a rewritten resolv.conf), FreeBSD's cloned tun and the routes into it.
//
// The file lives in the working directory by default, beside the credential
// cache: a start from another directory does not see it (-state-file).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// undoStep takes one change back: a command to run, or a file to put back.
type undoStep struct {
	Key     string   `json:"key"`               // what the change is — the handle to drop the step by
	Argv    []string `json:"argv,omitempty"`    // a command, or …
	File    string   `json:"file,omitempty"`    // … a file whose content goes back
	Content string   `json:"content,omitempty"` // the content it had
	Perm    uint32   `json:"perm,omitempty"`
}

type stateDoc struct {
	PID     int        `json:"pid"`
	Started string     `json:"started"`
	Undo    []undoStep `json:"undo"`
}

type journal struct {
	path string
	mu   sync.Mutex
	doc  stateDoc
}

func newJournal(path string) *journal {
	return &journal{path: path, doc: stateDoc{PID: os.Getpid(), Started: time.Now().Format(time.RFC3339)}}
}

// add records a change's undo — before the change is made.
func (j *journal) add(s undoStep) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, x := range j.doc.Undo {
		if x.Key == s.Key {
			return nil // recorded already (a pin re-pointed keeps its one undo)
		}
	}
	j.doc.Undo = append(j.doc.Undo, s)
	return j.writeLocked()
}

// done drops the undo of a change taken back.
func (j *journal) done(key string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := j.doc.Undo[:0]
	for _, x := range j.doc.Undo {
		if x.Key != key {
			kept = append(kept, x)
		}
	}
	j.doc.Undo = kept
	return j.writeLocked()
}

// has reports whether an undo is recorded under key.
func (j *journal) has(key string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, x := range j.doc.Undo {
		if x.Key == key {
			return true
		}
	}
	return false
}

// writeLocked replaces the file atomically: a crash mid-write leaves the old
// state or the new, never half of one.
func (j *journal) writeLocked() error {
	b, err := json.MarshalIndent(j.doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

// remove deletes the file once every change is taken back.
func (j *journal) remove() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.doc.Undo) > 0 {
		return fmt.Errorf("%d change(s) not taken back — the state file stays for the next start or -cleanup", len(j.doc.Undo))
	}
	if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// alreadyGone: the undo failed because what it takes back is not there any
// more — the route went with its interface when the process died (FreeBSD's
// halves, seen on the stand 2026-09-29; on macOS the utun itself dies with
// the process, and route(8) cannot even name it: "bad address: utun8", seen
// on the stand 2026-09-30), the interface was destroyed, the link vanished. The change is taken back; a step that insisted would keep the
// state file for ever and refuse every later start.
func alreadyGone(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"route has not been found", // BSD route(8)
		"not in table",             // BSD route(8), older wording
		"bad address: utun",        // macOS route(8): -interface names a utun that died with its process
		"No such process",          // Linux: ip route del of a route that is gone
		"Cannot find device",       // Linux: the interface is gone
		"does not exist",           // FreeBSD ifconfig: no such interface
		"No such device",           // resolvectl: the link is gone
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// runUndo carries one step out; run executes a command.
func runUndo(s undoStep, run func(argv []string) error) error {
	if s.File != "" {
		perm := os.FileMode(s.Perm)
		if perm == 0 {
			perm = 0o644
		}
		return os.WriteFile(s.File, []byte(s.Content), perm)
	}
	if len(s.Argv) == 0 {
		return nil
	}
	return run(s.Argv)
}

// undoAll takes every recorded change back, newest first; a step that fails
// is reported and the rest still run. Returns the steps that failed.
func (j *journal) undoAll(run func(argv []string) error, logf func(string, ...any)) []undoStep {
	j.mu.Lock()
	steps := append([]undoStep(nil), j.doc.Undo...)
	j.mu.Unlock()
	var failed []undoStep
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		if err := runUndo(s, run); err != nil && !alreadyGone(err) {
			logf("undo %s: %v", s.Key, err)
			failed = append(failed, s)
			continue
		}
		_ = j.done(s.Key)
	}
	return failed
}

// undoPrefix takes back the recorded changes whose key starts with prefix,
// newest first — the shutdown's order is DNS, then the routes into the
// tunnel, then the rest.
func (j *journal) undoPrefix(prefix string, run func(argv []string) error, logf func(string, ...any)) {
	j.mu.Lock()
	var steps []undoStep
	for _, s := range j.doc.Undo {
		if strings.HasPrefix(s.Key, prefix) {
			steps = append(steps, s)
		}
	}
	j.mu.Unlock()
	for i := len(steps) - 1; i >= 0; i-- {
		if err := runUndo(steps[i], run); err != nil && !alreadyGone(err) {
			logf("undo %s: %v", steps[i].Key, err)
			continue
		}
		_ = j.done(steps[i].Key)
	}
}

// hasPrefix reports whether an undo is recorded under a key with prefix.
func (j *journal) hasPrefix(prefix string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, x := range j.doc.Undo {
		if strings.HasPrefix(x.Key, prefix) {
			return true
		}
	}
	return false
}

// save writes the file now — at the start, to learn that it can be written
// before anything is changed.
func (j *journal) save() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.writeLocked()
}

// readState reads a state file a previous run left; nil, nil when there is none.
func readState(path string) (*stateDoc, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d stateDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s is not a state file: %v", path, err)
	}
	return &d, nil
}

// recoverLeftovers takes back what a crashed run left. 🚨 Its caller holds the
// pid file's lock (guarded, main.go): no other console is alive on this
// machine, so a state file found here is a dead run's — whatever pid it
// names. (The pid in it was once asked of ps, by name; the kernel cuts a
// process name — 15 characters on Linux, 19 on FreeBSD — the name never
// matched there, and a -cleanup beside a LIVE console took its routes away
// and left it running, its traffic direct: a stand, 2026-09-30.)
func recoverLeftovers(path string, run func([]string) error, logf func(string, ...any)) error {
	d, err := readState(path)
	if err != nil || d == nil {
		return err
	}
	if len(d.Undo) > 0 {
		logf("state: a run started %s (pid %d) did not clean up — taking back %d change(s)", d.Started, d.PID, len(d.Undo))
	}
	old := &journal{path: path, doc: *d}
	if failed := old.undoAll(run, logf); len(failed) > 0 {
		return fmt.Errorf("%d leftover change(s) could not be taken back (see above); %s kept", len(failed), path)
	}
	return old.remove()
}
