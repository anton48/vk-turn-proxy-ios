package main

// Where the network's DNS servers and the tunnel's cross (dnsplan.go).
// Sabotage seen red: the proxy asking a shared server while the network has
// others; the system kept on a shared server when the tunnel has others; a
// shared server left unpinned (its queries into the tunnel once the default
// route is there); a server that is the tunnel's again left pinned; the
// system's list not re-applied after the network changed; the switch applying
// the profile's list instead of the split's; the crossing's line on every
// refresh; onNetwork past the split; the resolver dialling a server whose pin
// failed.

import (
	"context"
	"errors"
	"go/ast"
	"strings"
	"testing"
)

func TestTheCrossingOfTheNetworksAndTheTunnelsDNS(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		network, tunnel      []string
		proxy, system, never string
		note                 string // a word the note must carry, "" for none
	}{
		{"split mode / DNS not managed", []string{"192.0.2.53"}, nil, "192.0.2.53", "", "", ""},
		{"no crossing", []string{"192.0.2.53"}, []string{"9.9.9.9"}, "192.0.2.53", "9.9.9.9", "9.9.9.9", ""},
		{"1: shared, the network has others", []string{"192.0.2.53", "1.1.1.1"}, []string{"1.1.1.1", "9.9.9.9"}, "192.0.2.53", "1.1.1.1,9.9.9.9", "1.1.1.1,9.9.9.9", "both"},
		{"2: only shared, the tunnel has others", []string{"1.1.1.1"}, []string{"1.1.1.1", "9.9.9.9"}, "1.1.1.1", "9.9.9.9", "9.9.9.9", "the tunnel's others"},
		{"3: only shared, the tunnel has no other", []string{"1.1.1.1"}, []string{"1.1.1.1"}, "1.1.1.1", "1.1.1.1", "", "AROUND the tunnel"},
		{"the network's servers unknown", nil, []string{"1.1.1.1"}, "", "1.1.1.1", "1.1.1.1", ""},
		{"duplicates", []string{"1.1.1.1", "1.1.1.1"}, []string{"1.1.1.1", "9.9.9.9", "9.9.9.9"}, "1.1.1.1", "9.9.9.9", "9.9.9.9", "the tunnel's others"},
	} {
		sp := crossDNS(tc.network, tc.tunnel)
		j := func(l []string) string { return strings.Join(l, ",") }
		if j(sp.proxy) != tc.proxy || j(sp.system) != tc.system || j(sp.never) != tc.never {
			t.Errorf("%s: proxy %q system %q never %q — want %q %q %q", tc.name, j(sp.proxy), j(sp.system), j(sp.never), tc.proxy, tc.system, tc.never)
		}
		if (tc.note == "") != (sp.note == "") || !strings.Contains(sp.note, tc.note) {
			t.Errorf("%s: note %q — want one carrying %q", tc.name, sp.note, tc.note)
		}
	}
}

// listDNS is a systemDNS whose network servers the test sets and whose last
// applied list it records.
type listDNS struct {
	network []string
	applied [][]string
}

func (d *listDNS) originals() []string { return d.network }
func (d *listDNS) apply(_ string, servers []string) error {
	d.applied = append(d.applied, append([]string(nil), servers...))
	return nil
}
func (d *listDNS) refresh(gateway) []string { return d.network }

func crossing(t *testing.T, tunnel, network []string) (*console, *listDNS, *fakeRun) {
	t.Helper()
	p, f, j := testPinner(t)
	dns := &listDNS{network: network}
	c := &console{j: j, pin: p, dns: dns, src: &dnsSource{}, tun: "utun7",
		dnsPlan: dnsPlan{managed: true, servers: tunnel}}
	return c, dns, f
}

func TestASharedServerIsPinnedAndTheSystemKeptInside(t *testing.T) {
	c, dns, f := crossing(t, []string{"1.1.1.1", "9.9.9.9"}, []string{"1.1.1.1"})
	logs := captureLog(t)
	c.applyDNSSplit(dns.network)
	if got := strings.Join(c.src.list(), ","); got != "1.1.1.1" {
		t.Fatalf("the proxy asks %q — want the shared server", got)
	}
	if err := c.pin.ensure("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.via("1.1.1.1"); !ok {
		t.Fatal("the shared server is not pinned — the proxy's queries to it go into the tunnel")
	}
	if _, err := c.applySystemDNS(); err != nil || strings.Join(dns.applied[len(dns.applied)-1], ",") != "9.9.9.9" {
		t.Fatalf("the system pointed at %v (%v) — want the tunnel's other server alone", dns.applied, err)
	}
	c.applyDNSSplit(dns.network) // a refresh with nothing new
	if n := strings.Count(logs.String(), "the tunnel's too"); n != 1 {
		t.Fatalf("the crossing said %d times over two refreshes — want once", n)
	}

	// The network changes: it hands out a server of its own as well.
	dns.network = []string{"192.0.2.53", "1.1.1.1"}
	c.applyDNSSplit(dns.network)
	if _, ok := f.via("1.1.1.1"); ok || c.j.has(pinKey("1.1.1.1")) {
		t.Fatal("the shared server is still pinned with the system about to be pointed at it — everyone's DNS would go around the tunnel")
	}
	if got := strings.Join(dns.applied[len(dns.applied)-1], ","); got != "1.1.1.1,9.9.9.9" {
		t.Fatalf("after the network change the system is pointed at %q — want the tunnel's whole list again", got)
	}
	if got := strings.Join(c.src.list(), ","); got != "192.0.2.53" {
		t.Fatalf("after the network change the proxy asks %q — want the network's own server", got)
	}
}

func TestTheTunnelsOnlyServerSharedIsPinnedAndSaid(t *testing.T) {
	c, dns, f := crossing(t, []string{"1.1.1.1"}, []string{"1.1.1.1"})
	logs := captureLog(t)
	c.applyDNSSplit(dns.network)
	if err := c.pin.ensure("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.via("1.1.1.1"); !ok {
		t.Fatal("the only shared server is not pinned — recovery would wait on the tunnel")
	}
	if !strings.Contains(logs.String(), "AROUND the tunnel") {
		t.Fatalf("the price is not said:\n%s", logs)
	}
}

// The switch points the system at the split's list — through activate.
func TestTheSwitchAppliesTheSplitsList(t *testing.T) {
	c, _, _ := switching(t, false)
	dns := &listDNS{network: []string{"1.1.1.1"}}
	c.dns, c.src = dns, &dnsSource{}
	c.dnsPlan = dnsPlan{managed: true, servers: []string{"1.1.1.1", "9.9.9.9"}}
	if err := c.activate(linuxCmds{}, newRouteTable().run, two); err != nil {
		t.Fatal(err)
	}
	if len(dns.applied) != 1 || strings.Join(dns.applied[0], ",") != "9.9.9.9" {
		t.Fatalf("the switch pointed the system at %v — want [9.9.9.9], the shared 1.1.1.1 left out", dns.applied)
	}
}

// A server whose pin failed is not dialled: the query would go into the
// tunnel. Go's resolver asks the next one.
func TestTheResolverDoesNotDialAServerWhosePinFailed(t *testing.T) {
	src := &dnsSource{}
	src.set([]string{"192.0.2.53"})
	refused := errors.New("pin refused")
	dial := resolverDial(src, func(string) error { return refused })
	if _, err := dial(context.Background(), "udp", "192.0.2.1:53"); !errors.Is(err, refused) {
		t.Fatalf("dial = %v — want the pin's error, no query sent", err)
	}
}

// onNetwork and run take the network's DNS through the split alone.
func TestTheNetworksDNSGoesThroughTheSplit(t *testing.T) {
	for _, fn := range []string{"onNetwork", "run"} {
		fd := funcDecl(t, "main.go", fn)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "src" && sel.Sel.Name == "set" {
				t.Errorf("%s sets the proxy's DNS past the split (c.src.set)", fn)
			}
			return true
		})
		if firstCallAt(fd, "applyDNSSplit") == 0 {
			t.Errorf("%s does not take the network's DNS through applyDNSSplit", fn)
		}
	}
}
