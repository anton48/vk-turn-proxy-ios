package main

// A local resolver as the network's DNS is said, not mended (the user's word,
// 2026-10-18: its forwarders may not exist — a recursor has nothing to pin;
// the whole answer is the pre-resolution). Sabotage seen red: the line never
// said; said in split mode; said on every refresh; a loopback address other
// than 127.0.0.1 (127.0.0.53, ::1) not seen.

import (
	"strings"
	"testing"
)

func TestALocalResolverIsSaidInTheDefaultRouteMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network []string
		dr      bool
		want    string // a word the note carries; "" for no note
	}{
		{"127.0.0.1 in the default-route mode", []string{"127.0.0.1"}, true, "127.0.0.1"},
		{"another loopback (a stub resolver's)", []string{"127.0.0.53"}, true, "127.0.0.53"},
		{"IPv6 loopback", []string{"::1"}, true, "::1"},
		{"a local one among others", []string{"192.0.2.53", "127.0.0.1"}, true, "127.0.0.1"},
		{"split mode", []string{"127.0.0.1"}, false, ""},
		{"no local resolver", []string{"192.0.2.53"}, true, ""},
	} {
		got := localResolverNote(tc.network, tc.dr)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q — want a note carrying %q", tc.name, got, tc.want)
		}
	}
}

func TestTheLocalResolversLineIsSaidOnce(t *testing.T) {
	c, dns, _ := crossing(t, []string{"9.9.9.9"}, []string{"127.0.0.1"})
	logs := captureLog(t)
	for i := 0; i < 3; i++ {
		c.applyDNSSplit(dns.network)
	}
	if n := strings.Count(logs.String(), "a resolver on this machine"); n != 1 {
		t.Fatalf("the local resolver said %d times over three refreshes — want once", n)
	}
	logs.Reset()
	c2, dns2, _ := crossing(t, []string{"9.9.9.9"}, []string{"127.0.0.1"})
	c2.pin.enable(false)
	c2.applyDNSSplit(dns2.network)
	if strings.Contains(logs.String(), "a resolver on this machine") {
		t.Fatalf("said in split mode:\n%s", logs)
	}
}
