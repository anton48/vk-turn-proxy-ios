package main

// The credential cache is the pool's. Sabotage seen red: the console naming
// the pool's last-use stamp again (the day it cleared them at a start); the
// cache rewritten by reading it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A slot used in its last ten minutes loads as pending — the pool's rule,
// the app's, and the user's decision for the console (2026-09-30). Nothing
// here may touch the stamp that rule reads: no source of the console names it.
func TestTheConsoleLeavesThePoolsStampsAlone(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("fixture: no sources (%v)", err)
	}
	read := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		read++
		if strings.Contains(string(b), "last_"+"used_at") {
			t.Errorf("%s names the pool's last-use stamp — the console does not decide when an identity is free again: only the pool knows what the relay was told, and it waits the ten minutes out as the app does", f)
		}
	}
	if read < 10 {
		t.Fatalf("fixture: %d sources read — the scan is not looking at the console", read)
	}

	// And reading the cache for the relays' addresses leaves it as it was.
	p := filepath.Join(t.TempDir(), "creds.json")
	content := `{"version":2,"saved_at":1789820566,"creds":[{"slot":0,"address":"203.0.113.50:19302","username":"1790000000:a","password":"pa","last_used_at":1789820500}]}`
	writeFile(t, p, content)
	if got := strings.Join(relayHostsFromCache(p), ","); got != "203.0.113.50" {
		t.Fatalf("fixture: relays = %q", got)
	}
	if b, _ := os.ReadFile(p); string(b) != content {
		t.Errorf("the cache changed under a read: %s", b)
	}
}
