// SPDX-License-Identifier: MIT

//go:build unix

package main

// The pid file — the standard guard against a second instance, with the
// standard lock on it (pidfile(3), flock).
//
// The number in the file says who; the LOCK says "running". It is held for
// the life of the process and goes with it however it dies, so a file a
// kill -9 left behind stops nobody, and a pid that was handed to another
// process meanwhile is never mistaken for a console: nothing is asked of ps,
// no name is compared. A bare number could not tell those cases apart — the
// state file has always carried the pid.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type pidFile struct {
	f    *os.File
	path string
}

// runningError: another console holds the pid file's lock.
type runningError struct {
	pid  int // 0: the file does not say
	path string
}

func (e *runningError) Error() string {
	who := "another vk-turn-proxy-console is running"
	if e.pid > 0 {
		who += " (pid " + strconv.Itoa(e.pid) + ")"
	}
	return who + ": it holds " + e.path + " — stop it first"
}

// betweenOpenAndLock is a test's hold on the taker, between its open and its
// lock; nil in production.
var betweenOpenAndLock func()

// takePidFile locks the pid file and writes this process's pid into it, or
// says who holds it.
func takePidFile(path string) (*pidFile, error) {
	for attempt := 0; attempt < 5; attempt++ {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, fmt.Errorf("pid file: %w — the console keeps one so that a second instance cannot start; give -pid-file if %s cannot be written", err, filepath.Dir(path))
		}
		if betweenOpenAndLock != nil {
			betweenOpenAndLock()
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			pid := readPid(f)
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, &runningError{pid: pid, path: path}
			}
			return nil, fmt.Errorf("pid file %s: %w", path, err)
		}
		// A console that was just stopping removes its file; if that fell
		// between our open and our lock, what we hold is a file nobody can
		// find any more, and the next console would lock a new one beside us.
		if !stillAt(f, path) {
			f.Close()
			continue
		}
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, fmt.Errorf("pid file %s: %w", path, err)
		}
		if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
			f.Close()
			return nil, fmt.Errorf("pid file %s: %w", path, err)
		}
		return &pidFile{f: f, path: path}, nil
	}
	return nil, fmt.Errorf("pid file %s kept being replaced under the lock", path)
}

// release removes the file — while the lock is still held — and lets the
// lock go.
func (p *pidFile) release() {
	if p == nil || p.f == nil {
		return
	}
	if stillAt(p.f, p.path) {
		_ = os.Remove(p.path)
	}
	_ = p.f.Close()
	p.f = nil
}

// stillAt: is the open file the one the path names now?
func stillAt(f *os.File, path string) bool {
	held, err1 := f.Stat()
	named, err2 := os.Stat(path)
	return err1 == nil && err2 == nil && os.SameFile(held, named)
}

func readPid(f *os.File) int {
	var b [32]byte
	n, _ := f.ReadAt(b[:], 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b[:n])))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
