package main

// The network's DNS read live when the console does not manage the system's
// (-dns=false, split mode, before the switch). Sabotage seen red: refresh
// answering the start's list while the file says another; the change not
// said; said on every refresh.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resolvConfAt(t *testing.T, content string) (*resolvConfDNS, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	j := newJournal(filepath.Join(dir, "state.json"))
	return newResolvConfDNS(p, j, t.Logf), p
}

// The user's case: the file replaced, the console not managing it.
func TestAResolvConfNotOursIsReadEveryTime(t *testing.T) {
	d, p := resolvConfAt(t, "nameserver 192.0.2.1\n")
	if got := strings.Join(d.refresh(gateway{}), ","); got != "192.0.2.1" {
		t.Fatalf("the first read: %q", got)
	}
	if err := os.WriteFile(p, []byte("search example.test\nnameserver 198.51.100.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.refresh(gateway{}), ","); got != "198.51.100.1" {
		t.Fatalf("after the network wrote a new file the refresh answers %q — want the new server", got)
	}
	// A later apply puts back the latest content, not the start's.
	if err := d.apply("", []string{"9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range d.j.doc.Undo {
		if s.Key == "dns "+p && !strings.Contains(s.Content, "198.51.100.1") {
			t.Fatalf("the undo puts back %q — want the network's latest file", s.Content)
		}
	}
}

func TestTheProxysDNSFollowsTheFileInSplitModeAndWithDNSOff(t *testing.T) {
	for _, defaultRoute := range []bool{false, true} { // split mode; -dns=false with the default route
		d, p := resolvConfAt(t, "nameserver 192.0.2.1\n")
		pin, _, j := testPinner(t)
		pin.enable(defaultRoute)
		c := &console{j: j, pin: pin, dns: &lockedDNS{d: d}, src: &dnsSource{}} // dnsPlan.managed false
		logs := captureLog(t)
		c.applyDNSSplit(c.dns.refresh(gateway{}))
		if err := os.WriteFile(p, []byte("nameserver 198.51.100.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		c.applyDNSSplit(c.dns.refresh(gateway{}))
		c.applyDNSSplit(c.dns.refresh(gateway{})) // nothing new
		if got := strings.Join(c.src.list(), ","); got != "198.51.100.1" {
			t.Fatalf("default-route=%v: the proxy asks %q — want the network's new server", defaultRoute, got)
		}
		if n := strings.Count(logs.String(), "the network's servers are now"); n != 1 || !strings.Contains(logs.String(), "now 198.51.100.1 (were 192.0.2.1)") {
			t.Fatalf("default-route=%v: the change said %d times — want once:\n%s", defaultRoute, n, logs)
		}
	}
}
