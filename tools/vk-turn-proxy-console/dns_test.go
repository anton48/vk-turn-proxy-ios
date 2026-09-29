package main

// resolv.conf as the system's DNS (Linux without resolved, FreeBSD).
// Sabotage seen red: the old content not journaled before the write; search /
// options lines dropped; a file rewritten by a DHCP client not taken for the
// network's servers.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvConfIsRewrittenAndPutBack(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	orig := "search lan\nnameserver 192.168.1.1\noptions edns0\n"
	writeFile(t, conf, orig)
	j := newJournal(filepath.Join(dir, "state.json"))
	d := newResolvConfDNS(conf, j, t.Logf)
	if got := strings.Join(d.originals(), ","); got != "192.168.1.1" {
		t.Fatalf("originals = %q", got)
	}
	if err := d.apply("vktp0", []string{"1.1.1.1", "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(conf)
	if s := string(b); !strings.Contains(s, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n") || strings.Contains(s, "192.168.1.1") ||
		!strings.Contains(s, "search lan") || !strings.Contains(s, "options edns0") {
		t.Fatalf("written:\n%s", s)
	}
	if !j.has("dns " + conf) {
		t.Fatal("the old content is not journaled")
	}
	// A DHCP client rewrites the file: its servers are the network's now.
	writeFile(t, conf, "nameserver 172.20.10.1\n")
	if got := strings.Join(d.refresh(gateway{}), ","); got != "172.20.10.1" {
		t.Fatalf("after a rewrite the network's servers = %q", got)
	}
	b, _ = os.ReadFile(conf)
	if !strings.Contains(string(b), "nameserver 1.1.1.1") {
		t.Fatalf("the tunnel's servers not written back:\n%s", b)
	}
	j.undoAll(func([]string) error { return nil }, t.Logf)
	b, _ = os.ReadFile(conf)
	if string(b) != "nameserver 172.20.10.1\n" {
		t.Fatalf("put back %q, want the network's latest file", b)
	}
}
