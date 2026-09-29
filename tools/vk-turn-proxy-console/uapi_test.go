package main

// The WireGuard config: the app's, and no key in an error.

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestTheUAPIConfigIsTheApps(t *testing.T) {
	priv, pub := testKey(1), testKey(2)
	got, err := uapiConfig(priv, pub, "", "192.0.2.10:56004", 25)
	if err != nil {
		t.Fatal(err)
	}
	privHex, _ := keyHex(priv)
	pubHex, _ := keyHex(pub)
	want := "private_key=" + privHex + "\nreplace_peers=true\npublic_key=" + pubHex + "\nendpoint=192.0.2.10:56004\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0"
	if got != want {
		t.Fatalf("uapi:\n%s\nwant:\n%s", got, want)
	}
	withPSK, _ := uapiConfig(priv, pub, testKey(3), "192.0.2.10:56004", 0)
	if !strings.HasSuffix(withPSK, "preshared_key="+hex.EncodeToString(mustB64(testKey(3)))) || strings.Contains(withPSK, "persistent_keepalive") {
		t.Fatalf("psk / no keepalive:\n%s", withPSK)
	}
	for _, bad := range []string{"bm90LWEta2V5", "bm90 not base64!"} { // the wrong length; not base64
		if _, err := uapiConfig(bad, pub, "", "192.0.2.10:56004", 25); err == nil || strings.Contains(err.Error(), "bm90") {
			t.Fatalf("a bad key: %v — refused, and never quoted", err)
		}
	}
	if _, err := uapiConfig(priv, pub, "", "192.0.2.10:56004\nprivate_key=00", 25); err == nil {
		t.Fatal("a peer address that injects a UAPI line accepted")
	}
}

func mustB64(s string) []byte {
	h, _ := keyHex(s)
	b, _ := hex.DecodeString(h)
	return b
}
