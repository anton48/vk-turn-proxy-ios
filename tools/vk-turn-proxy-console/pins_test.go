package main

// The pinner — the dial hook's console side. Sabotage seen red: an on-link
// host pinned; the tunnel's DNS server pinned (everyone's DNS would go around
// the tunnel); IPv6 refused although not blocked; the same host pinned twice;
// a pin not journaled before it is made; a pin not re-pointed at a new
// gateway; an address asked while the network was down never pinned; a route
// that existed before taken as ours (and deleted on exit).

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeRun records every command; exists names hosts whose pin is refused as
// already there.
type fakeRun struct {
	mu     sync.Mutex
	cmds   []string
	exists map[string]bool
	j      *journal
	// journaledFirst: the pin's undo was in the journal when its add ran.
	journaledFirst []bool
}

func (f *fakeRun) run(argv []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(argv, " ")
	f.cmds = append(f.cmds, cmd)
	if len(argv) > 5 && argv[3] == "add" && strings.HasSuffix(argv[5], "/32") && f.j != nil {
		f.journaledFirst = append(f.journaledFirst, f.j.has(pinKey(strings.TrimSuffix(argv[5], "/32"))))
	}
	for h := range f.exists {
		if strings.Contains(cmd, " add ") && strings.Contains(cmd, h+"/32") {
			return "route: writing to routing socket: File exists", errors.New("exit status 1")
		}
	}
	return "", nil
}

func (f *fakeRun) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func testPinner(t *testing.T) (*pinner, *fakeRun, *journal) {
	t.Helper()
	j := newJournal(filepath.Join(t.TempDir(), "state.json"))
	f := &fakeRun{exists: map[string]bool{}, j: j}
	p := newPinner(darwinCmds{}, f.run, j, t.Logf)
	_, p.tunnel, _ = net.ParseCIDR("10.66.66.2/24")
	p.never["1.1.1.1"] = true
	_, lan, _ := net.ParseCIDR("192.168.1.5/24")
	p.enable(true)
	p.setGateway(gateway{IP: "192.168.1.1", Iface: "en0"}, true, []*net.IPNet{lan})
	return p, f, j
}

func TestThePinnerPinsWhatTheProxyDialsAndNothingElse(t *testing.T) {
	p, f, j := testPinner(t)
	for _, a := range []string{"203.0.113.50:19302", "203.0.113.50:19302", "198.51.100.7:443", "192.168.1.20:53",
		"10.66.66.1:53", "127.0.0.1:53", "169.254.1.1:80", "1.1.1.1:53"} {
		if err := p.hook("tcp4", a); err != nil {
			t.Fatalf("hook(%s): %v", a, err)
		}
	}
	got := f.list()
	want := []string{"route -q -n add -inet 203.0.113.50/32 192.168.1.1", "route -q -n add -inet 198.51.100.7/32 192.168.1.1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s\n(each relay once; the LAN, the tunnel's subnet, loopback, link-local and the tunnel's DNS never)", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for i, first := range f.journaledFirst {
		if !first {
			t.Fatalf("pin %d was made before its undo was journaled — a crash in between would leave it for good", i)
		}
	}
	if !j.has(pinKey("203.0.113.50")) || !j.has(pinKey("198.51.100.7")) || p.count() != 2 {
		t.Fatalf("pins not journaled / counted: %d", p.count())
	}
}

func TestIPv6IsLeftAloneUnlessBlocked(t *testing.T) {
	p, f, _ := testPinner(t)
	if err := p.hook("tcp6", "[2001:db8::5]:443"); err != nil {
		t.Fatalf("IPv6 refused although not blocked: %v", err)
	}
	p.blockV6 = true
	if err := p.hook("tcp6", "[2001:db8::5]:443"); !errors.Is(err, errIPv6Blocked) {
		t.Fatalf("IPv6 with -block-ipv6: %v — the dialer must fall back to IPv4", err)
	}
	if len(f.list()) != 0 {
		t.Fatalf("IPv6 pinned: %q", f.list())
	}
}

func TestSplitModePinsNothing(t *testing.T) {
	p, f, _ := testPinner(t)
	p.enable(false)
	if err := p.hook("tcp4", "203.0.113.50:19302"); err != nil || len(f.list()) != 0 {
		t.Fatalf("split mode pinned: %q (%v)", f.list(), err)
	}
}

func TestPinsFollowTheGateway(t *testing.T) {
	p, f, _ := testPinner(t)
	_ = p.hook("tcp4", "203.0.113.50:19302")
	p.setGateway(gateway{}, false, nil) // the network goes
	_ = p.hook("udp4", "203.0.113.60:3478")
	if n := len(f.list()); n != 1 {
		t.Fatalf("a pin made with no gateway: %q", f.list())
	}
	_, lte, _ := net.ParseCIDR("172.20.10.2/28")
	p.setGateway(gateway{IP: "172.20.10.1", Iface: "en5"}, true, []*net.IPNet{lte})
	got := strings.Join(f.list()[1:], "\n")
	for _, want := range []string{"route -q -n change -inet 203.0.113.50/32 172.20.10.1", "route -q -n add -inet 203.0.113.60/32 172.20.10.1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("after the new network:\n%s\nmissing %q (a pin re-pointed; an address asked while down pinned now)", got, want)
		}
	}
}

func TestARouteThatExistedIsNotOurs(t *testing.T) {
	p, f, j := testPinner(t)
	f.exists["203.0.113.70"] = true
	if err := p.hook("tcp4", "203.0.113.70:443"); err != nil {
		t.Fatalf("an existing route is an error: %v", err)
	}
	if j.has(pinKey("203.0.113.70")) || p.count() != 0 {
		t.Fatal("a route the console did not make is journaled as its own — it would be deleted on exit")
	}
	p.removeAll()
	for _, c := range f.list() {
		if strings.Contains(c, "delete") {
			t.Fatalf("deleted a route it did not make: %q", c)
		}
	}
}

func TestRemoveAllTakesOurPinsBack(t *testing.T) {
	p, f, j := testPinner(t)
	_ = p.hook("tcp4", "203.0.113.50:19302")
	_ = p.hook("tcp4", "198.51.100.7:443")
	p.removeAll()
	dels := 0
	for _, c := range f.list() {
		if strings.HasPrefix(c, "route -q -n delete -inet ") {
			dels++
		}
	}
	if dels != 2 || p.count() != 0 || j.has(pinKey("203.0.113.50")) {
		t.Fatalf("removeAll: %d deletes, %d pins left, journal %v", dels, p.count(), j.doc.Undo)
	}
}

func TestConcurrentDialsPinOnce(t *testing.T) {
	p, f, _ := testPinner(t)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ { // thirty connections dial one relay at once
		wg.Add(1)
		go func() { defer wg.Done(); _ = p.hook("tcp4", "203.0.113.50:19302") }()
	}
	wg.Wait()
	if n := len(f.list()); n != 1 {
		t.Fatalf("%d commands for one relay, want 1", n)
	}
}
