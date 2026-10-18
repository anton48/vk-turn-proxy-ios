package main

// A failure in repinLocked marks the pin unsure (the user's remark of
// 2026-10-18, on f9c5ed9): the monitor sees A → B → A with no loss in between,
// the route went with A's interface, and the `route get` at the move to B
// fails — the pin stayed via A unmarked, and A's return found the gateway the
// same and checked nothing: a dial with no route around the tunnel. Sabotage
// seen red: the failed query not marked; the failed re-point not marked; the
// mark not cleared by a successful re-point or a confirming check.

import (
	"testing"
)

var gwB = gateway{IP: "172.20.10.1", Iface: "en5"}

// TestAFailedQueryAtARePointIsCheckedWhenTheGatewayReturns is the user's
// scenario on the macOS and FreeBSD table models.
func TestAFailedQueryAtARePointIsCheckedWhenTheGatewayReturns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmds    netCmds
		freebsd bool
	}{
		{"macOS", darwinCmds{}, false},
		{"FreeBSD", freebsdCmds{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const host = "203.0.113.50"
			p, f, j := bsdPinner(t, tc.cmds, tc.freebsd)
			gwA := p.gw
			if err := p.ensure(host); err != nil {
				t.Fatal(err)
			}
			f.vanish(host) // A's interface went, and the route with it
			f.mu.Lock()
			f.failQ[host] = 1
			f.mu.Unlock()
			p.setGateway(gwB, true, nil) // → B: the query fails
			if via, ours := p.pinned[host]; !ours || via != gwA || p.foreign[host] || !j.has(pinKey(host)) {
				t.Fatalf("after the failed query: ours %v via %v, foreign %v, journaled %v — want ours via A, journaled", ours, via, p.foreign[host], j.has(pinKey(host)))
			}
			from := len(f.list())
			p.setGateway(gwA, true, nil) // → A again, no loss seen in between
			if n := countCmds(f, from, " get ", host); n < 1 {
				t.Fatal("the gateway returned and the pin was not checked")
			}
			if via, there := f.via(host); !there || via != gwA.IP {
				t.Fatalf("the pin via %q, there %v after A's return — want made again via A", via, there)
			}
			if via, ours := p.pinned[host]; !ours || via != gwA || p.foreign[host] || !j.has(pinKey(host)) {
				t.Fatalf("after the return: ours %v via %v, foreign %v, journaled %v", ours, via, p.foreign[host], j.has(pinKey(host)))
			}
			// Confirmed: the next ask runs nothing.
			from = len(f.list())
			if err := p.ensure(host); err != nil {
				t.Fatal(err)
			}
			if n := len(f.list()) - from; n != 0 {
				t.Fatalf("%d command(s) at an ask after the pin was made again — want none", n)
			}
			p.removeAll()
			if _, there := f.via(host); there {
				t.Fatal("the pin is left behind at the stop")
			}
		})
	}
}

// TestAFailedQueryAtARePointIsCheckedAtTheNextAsk: the same, the return's
// own check failing too — the ask after it checks and remakes.
func TestAFailedQueryAtARePointIsCheckedAtTheNextAsk(t *testing.T) {
	const host = "203.0.113.50"
	p, f, _ := bsdPinner(t, freebsdCmds{}, true)
	gwA := p.gw
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	f.vanish(host)
	f.mu.Lock()
	f.failQ[host] = 2 // at B, and at A's return
	f.mu.Unlock()
	p.setGateway(gwB, true, nil)
	p.setGateway(gwA, true, nil)
	if _, there := f.via(host); there {
		t.Fatal("the table answered a query that was made to fail")
	}
	if err := p.ensure(host); err != nil { // the dial: checked, found gone, made again
		t.Fatal(err)
	}
	if via, there := f.via(host); !there || via != gwA.IP {
		t.Fatalf("the pin via %q, there %v at the ask after a failed check — want made again via A", via, there)
	}
}

// TestAFailedRePointMarksThePinUnsure: the change / replace itself fails (not
// «not found») — the route's state is nobody's word: checked when the old
// gateway returns, on the BSD models and on Linux's commands.
func TestAFailedRePointMarksThePinUnsure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmds    netCmds
		freebsd bool
		verb    string
	}{
		{"macOS", darwinCmds{}, false, " get "},
		{"FreeBSD", freebsdCmds{}, true, " get "},
		{"Linux", linuxCmds{}, false, " replace "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const host = "203.0.113.50"
			p, f, j := bsdPinner(t, tc.cmds, tc.freebsd)
			gwA := p.gw
			if err := p.ensure(host); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.fail[host] = 1 // the change / replace at B fails
			f.mu.Unlock()
			p.setGateway(gwB, true, nil)
			if via, ours := p.pinned[host]; !ours || via != gwA || !j.has(pinKey(host)) {
				t.Fatalf("after the failed re-point: ours %v via %v, journaled %v — want ours via A", ours, via, j.has(pinKey(host)))
			}
			from := len(f.list())
			p.setGateway(gwA, true, nil)
			if n := countCmds(f, from, tc.verb, host); n < 1 {
				t.Fatalf("A returned after a failed re-point and the pin was not checked (no%scommand)", tc.verb)
			}
			// Confirmed by the check: the next ask runs nothing.
			from = len(f.list())
			if err := p.ensure(host); err != nil {
				t.Fatal(err)
			}
			if n := len(f.list()) - from; n != 0 {
				t.Fatalf("%d command(s) at an ask after the pin was confirmed — want none", n)
			}
		})
	}
}

// TestASuccessfulRePointClearsTheMark: the query at B fails, the next ask
// re-points and succeeds — from then on the pin is confirmed, asked nothing.
func TestASuccessfulRePointClearsTheMark(t *testing.T) {
	const host = "203.0.113.50"
	p, f, _ := bsdPinner(t, darwinCmds{}, false)
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failQ[host] = 1
	f.mu.Unlock()
	p.setGateway(gwB, true, nil)           // the query fails: unsure, via A
	if err := p.ensure(host); err != nil { // re-pointed now
		t.Fatal(err)
	}
	if via, _ := f.via(host); via != gwB.IP {
		t.Fatalf("the pin via %q after the re-point — want B", via)
	}
	if p.unsure[host] {
		t.Fatal("the mark stands after a successful re-point")
	}
	from := len(f.list())
	if err := p.ensure(host); err != nil {
		t.Fatal(err)
	}
	if n := len(f.list()) - from; n != 0 {
		t.Fatalf("%d command(s) at an ask after a successful re-point — want none", n)
	}
}
