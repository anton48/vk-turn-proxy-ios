package proxy

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A phone, 2026-11-18: no cache file, the app's probe mints a credential for
// which VK names two relays, the seed carries the first alone, and that relay
// answers TURN and does not forward. The pool holds one slot with one relay —
// conn 0 makes four attempts on it and the bootstrap times out. With the
// seed carrying every relay VK named, the first failed handshake plans the
// other one.

func TestSeedCredsCarriesEveryRelayTheAppNames(t *testing.T) {
	for _, c := range []struct {
		name      string
		addresses []string
		want      []string
	}{
		{"no list: the seed as it always was", nil, nil},
		{"an empty list is no list", []string{}, nil},
		{"VK's two relays", []string{relayA, relayB}, []string{relayA, relayB}},
		{"the seed's own relay stands first whatever the order", []string{relayB, relayA}, []string{relayA, relayB}},
		{"each relay once", []string{relayA, relayB, relayB, relayA}, []string{relayA, relayB}},
		{"an entry that is not host:port is dropped", []string{"", "no-port", relayB}, []string{relayA, relayB}},
		{"nothing but refused entries is no list", []string{"", "no-port"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := SeedCreds(relayA, "user", "pw", c.addresses)
			if got.Address != relayA || got.Username != "user" || got.Password != "pw" {
				t.Fatalf("the seed's own fields: %+v", *got)
			}
			if !reflect.DeepEqual(got.Addresses, c.want) {
				t.Fatalf("Addresses = %v, want %v", got.Addresses, c.want)
			}
		})
	}
}

// The cold start itself, through the pool: the seed alone, conn 0's
// handshake through its relay times out — is there anywhere to go?
func TestAColdPoolsSeedCanFailOverOnlyIfItNamesEveryRelay(t *testing.T) {
	for _, c := range []struct {
		name      string
		addresses []string
		wantNext  string
	}{
		{"the seed names VK's two relays: the next attempt takes the other", []string{relayA, relayB}, relayB},
		{"the seed names one relay: nothing to move to (the phone's cold start)", nil, relayA},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp, mints, clock := relayPoolN(t, "", 4, relayA, relayB)
			cp.seedSlot(0, relayA, SeedCreds(relayA, futureUser("seed"), "pw", c.addresses))

			addr, creds, slot := mustGet(t, cp, 0)
			if addr != relayA {
				t.Fatalf("fixture: conn 0 was handed %s first, want the seed's relay %s", addr, relayA)
			}
			cp.notePeerHandshakeResult(context.Background(), 0, cp.handStampOf(0), relayA,
				handshakeObservation{started: *clock, lastRetry: clock.Add(7 * time.Second), ended: clock.Add(10 * time.Second), timedOut: true},
				context.DeadlineExceeded, nil)
			cp.release(slot, creds, relayA)

			if planned := cp.peerProbe.pending && cp.peerProbe.alternate == relayB; planned != (c.wantNext == relayB) {
				t.Fatalf("an alternate planned: %v (probe %+v), want %v", planned, cp.peerProbe, c.wantNext == relayB)
			}
			next, creds2, slot2 := mustGet(t, cp, 0)
			if next != c.wantNext {
				t.Fatalf("conn 0's next attempt was handed %s, want %s", next, c.wantNext)
			}
			cp.release(slot2, creds2, next)
			if n := mints.Load(); n != 0 {
				t.Fatalf("the cold pool minted %d credential(s) — the bootstrap's connection is alone, nothing mints for it", n)
			}
		})
	}
}

// The wiring on the Go side, both start paths: the probe's answer names every
// relay, the bridge's config takes the list, and the seed is built by
// SeedCreds from it — never as a bare TURNCreds with Address alone.
func TestTheBridgesHandTheSeedsRelayListToThePool(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile("../../WireGuardBridge/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	native := read("bridge.go")
	if !strings.Contains(native, `resp["turn_addresses"] = creds.Addresses`) {
		t.Error("bridge.go: the probe's answer does not name every relay (turn_addresses)")
	}
	for name, src := range map[string]string{"bridge.go": native, "csqtt_bridge.go": read("csqtt_bridge.go")} {
		at := strings.Index(src, "SeededTURN ")
		if at < 0 {
			t.Errorf("%s: no SeededTURN in the config", name)
			continue
		}
		end := strings.Index(src[at:], `json:"seeded_turn`)
		if end < 0 || !strings.Contains(src[at:at+end], "Addresses []string `json:\"addresses,omitempty\"`") {
			t.Errorf("%s: seeded_turn has no addresses list", name)
		}
		if !strings.Contains(src, "proxy.SeedCreds(") || !strings.Contains(src, "SeededTURN.Addresses") {
			t.Errorf("%s: the seed is not built by proxy.SeedCreds from the config's list", name)
		}
		if strings.Contains(src, "&proxy.TURNCreds{") && strings.Contains(src[strings.Index(src, "&proxy.TURNCreds{"):], "SeededTURN.Address") {
			t.Errorf("%s: a seed is still built as a bare TURNCreds — its relay list is lost", name)
		}
	}
}
