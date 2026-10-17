package main

// A pin whose command failed is not a pin. Sabotage seen red: ensure answering
// from wanted (the asked set) — the user's «two calls, one attempt, zero
// pins», after which a dial goes into the tunnel; a re-point that failed at a
// gateway change never tried again; the DNS server's note on every dial.

import (
	"strings"
	"testing"
)

func adds(cmds []string, host string) int {
	n := 0
	for _, c := range cmds {
		if (strings.Contains(c, " add ") || strings.Contains(c, " change ")) && strings.Contains(c, host+"/32") {
			n++
		}
	}
	return n
}

func TestAPinThatFailedIsTriedAgainOnEveryAsk(t *testing.T) {
	p, f, j := testPinner(t)
	f.fail["203.0.113.9"] = 1 << 30 // the route cannot be made at all
	for i := 0; i < 2; i++ {
		if err := p.hook("tcp4", "203.0.113.9:443"); err == nil {
			t.Fatalf("dial %d: the hook let it through with no pin — it would go into the tunnel", i+1)
		}
	}
	if n := adds(f.list(), "203.0.113.9"); n != 2 {
		t.Fatalf("two asks made %d attempt(s) — want one per ask", n)
	}
	if p.count() != 0 || j.has(pinKey("203.0.113.9")) {
		t.Fatalf("a pin counted (%d) or journaled (%v) although no command succeeded", p.count(), j.has(pinKey("203.0.113.9")))
	}

	f.mu.Lock()
	f.fail["203.0.113.9"] = 0 // the route can be made now
	f.mu.Unlock()
	if err := p.hook("tcp4", "203.0.113.9:443"); err != nil {
		t.Fatalf("the third ask, with the route possible: %v", err)
	}
	if p.count() != 1 || !j.has(pinKey("203.0.113.9")) {
		t.Fatalf("after a successful attempt: pins %d, journaled %v — want 1, true", p.count(), j.has(pinKey("203.0.113.9")))
	}
	before := len(f.list())
	if err := p.hook("tcp4", "203.0.113.9:443"); err != nil || len(f.list()) != before {
		t.Fatalf("an ask for a confirmed pin ran %q (err %v) — want nothing", f.list()[before:], err)
	}
}

func TestARePointThatFailedIsTriedAgain(t *testing.T) {
	p, f, _ := testPinner(t)
	if err := p.ensure("198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.fail["198.51.100.7"] = 1 // the re-point at the gateway change fails once
	f.mu.Unlock()
	gw2 := gateway{IP: "192.168.2.1", Iface: "en1"}
	p.setGateway(gw2, true, nil)
	if p.pinned["198.51.100.7"] == gw2 {
		t.Fatal("a re-point that failed recorded as via the new gateway")
	}
	if err := p.ensure("198.51.100.7"); err != nil {
		t.Fatalf("the ask after the failed re-point: %v", err)
	}
	if p.pinned["198.51.100.7"] != gw2 {
		t.Fatalf("the pin is via %v after the ask — want it re-pointed at %v", p.pinned["198.51.100.7"], gw2)
	}
}

func TestTheTunnelsDNSServerIsNotedOnce(t *testing.T) {
	p, _, _ := testPinner(t)
	var notes int
	p.logf = func(format string, _ ...any) {
		if strings.Contains(format, "not pinned") {
			notes++
		}
	}
	for i := 0; i < 3; i++ {
		if err := p.ensure("1.1.1.1"); err != nil {
			t.Fatal(err)
		}
	}
	if notes != 1 {
		t.Fatalf("the tunnel's DNS server noted %d times over three dials — want once", notes)
	}
}
