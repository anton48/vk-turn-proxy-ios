// SPDX-License-Identifier: MIT

package main

// The console's own log file (-log): what `2>&1 | tee file` was used for,
// without a second process whose death on Ctrl-C takes the log — and, before
// SIGPIPE was ignored, the console — with it.

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/device"
)

// fanout writes every log line to each of its writers and tells the logger
// that all went well. 🚫 Not io.MultiWriter: that stops at the first writer
// that fails — a terminal that went away, a closed pipe on stderr — and the
// file behind it would get nothing from then on.
type fanout []io.Writer

func (f fanout) Write(p []byte) (int, error) {
	for _, w := range f {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// openLog opens the log file for appending — an earlier run's lines stay —
// and creates it readable by its owner alone: the proxy's lines name the
// relays and the identities it minted. A file the console created under sudo
// is handed to the user who ran sudo, as tee would have made it; one that was
// there already keeps its owner.
func openLog(path string, getenv func(string) string) (*os.File, error) {
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if os.IsNotExist(statErr) {
		if uid, gid, ok := sudoOwner(getenv); ok && os.Geteuid() == 0 {
			if err := f.Chown(uid, gid); err != nil {
				fmt.Fprintf(os.Stderr, "-log: %s stays root's: %v\n", path, err)
			}
		}
	}
	return f, nil
}

// sudoOwner: the user behind sudo, from the environment sudo sets.
func sudoOwner(getenv func(string) string) (uid, gid int, ok bool) {
	uid, err1 := strconv.Atoi(getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// wgLogger is wireguard-go's logger through the log package — and so into
// the log file too: device.NewLogger writes to stdout past it.
func wgLogger(verbose bool) *device.Logger {
	l := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { log.Printf("(wireguard) ERROR: "+format, args...) },
	}
	if verbose {
		l.Verbosef = func(format string, args ...any) { log.Printf("(wireguard) "+format, args...) }
	}
	return l
}
