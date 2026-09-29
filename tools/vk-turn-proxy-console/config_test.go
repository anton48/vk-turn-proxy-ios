package main

// The backup as the console's config: the server chosen, the app's defaults
// for absent keys, the globals, the command line over them. Sabotage seen red:
// the first server taken whatever its mode; a named server of another mode
// accepted; useSrtp's default flipped; the vkLink list's first line not the
// anonymous link; the MTU rule; the pool size formula; a flag applied although
// not given; -dns=false ignored; the conns ceiling.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testKey is a well-formed WireGuard key that is nobody's: 32 counting bytes.
func testKey(seed byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// writeBackup writes a backup of the app's shape with the given servers and
// returns its path (mode 0600).
func writeBackup(t *testing.T, settings map[string]any) string {
	t.Helper()
	doc := map[string]any{"version": 1, "type": "full", "exported_at": 1789820574, "settings": settings,
		"turn_pool":  map[string]any{"version": 2, "creds": []any{map[string]any{"address": "203.0.113.50:19302", "username": "x", "password": "y", "slot": 0}}},
		"vk_profile": map[string]any{"user_agent": "ua", "browser_fp": "fp"}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "vk-turn-proxy-console.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func srtpServer(name string) map[string]any {
	return map[string]any{"serverName": name, "privateKey": testKey(1), "peerPublicKey": testKey(2),
		"presharedKey": "", "tunnelAddress": "10.66.66.2/24", "peerAddress": "192.0.2.10:56004",
		"dnsServers": "1.1.1.1, 8.8.8.8", "numConnections": 40, "credPoolCooldownSeconds": 150,
		"turnServerOverride": "", "useUDP": false, "useDTLS": true, "useSrtp": true,
		"useWrap": false, "useWrapA": false, "useWrapS": false, "useCsqtt": false}
}

func globals(servers ...map[string]any) map[string]any {
	list := make([]any, len(servers))
	for i, s := range servers {
		list[i] = s
	}
	return map[string]any{"servers": list, "activeServer": "x", "vkAuth": false, "uplinkPaceKiB": 247,
		"tunnelMTU": 0, "forceLegacyCaptcha": false,
		"vkLink": "https://vk.ru/call/join/first\n\n  https://vk.ru/call/join/second  \nhttps://vk.ru/call/join/third\n"}
}

func TestTheFirstNativeServerIsChosenAndAnotherModeIsRefused(t *testing.T) {
	wdtt := srtpServer("Wdtt")
	wdtt["useSrtp"], wdtt["useWrapA"] = false, true
	csq := srtpServer("Csq")
	csq["useCsqtt"] = true
	b, err := loadBackup(writeBackup(t, globals(wdtt, csq, srtpServer("Home"), srtpServer("Work"))))
	if err != nil {
		t.Fatal(err)
	}
	list := b.servers()
	s, err := selectServer(list, "")
	if err != nil || s.Name != "Home" {
		t.Fatalf("no -server: got %q (%v), want the first native SRTP server Home", s.Name, err)
	}
	if s, err := selectServer(list, "Work"); err != nil || s.Name != "Work" {
		t.Fatalf("-server Work: got %q (%v)", s.Name, err)
	}
	if s, err := selectServer(list, "work"); err != nil || s.Name != "Work" {
		t.Fatalf("-server work (a unique match by case): got %q (%v)", s.Name, err)
	}
	if _, err := selectServer(list, "Wdtt"); err == nil || !strings.Contains(err.Error(), "SRTP-WRAP-A") {
		t.Fatalf("-server Wdtt: err = %v, want a refusal naming its mode", err)
	}
	if _, err := selectServer(list, "Nope"); err == nil {
		t.Fatal("-server Nope: no error")
	}
	if _, err := selectServer(list[:2], ""); err == nil || !strings.Contains(err.Error(), "native SRTP") {
		t.Fatalf("a backup without a native server: err = %v", err)
	}
}

// An absent key takes the app's default — and useSrtp's is TRUE: a server
// saved before the key existed is SRTP (ServerProfile.swift).
func TestAbsentKeysTakeTheAppsDefaults(t *testing.T) {
	sparse := map[string]any{"serverName": "Old", "privateKey": testKey(1), "peerPublicKey": testKey(2), "peerAddress": "192.0.2.10:56004"}
	b, err := loadBackup(writeBackup(t, globals(sparse)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := selectServer(b.servers(), "")
	if err != nil {
		t.Fatalf("a server with only its keys and address is native SRTP by the defaults: %v", err)
	}
	if s.TunnelAddress != defaultTunnelAddress || s.DNSServers != defaultDNSServers || s.NumConnections != 30 || s.CredPoolCooldownSeconds != 150 || s.UseUDP {
		t.Fatalf("defaults not applied: %+v", s)
	}
}

func TestALegacySingleServerBackupIsOneServer(t *testing.T) {
	g := map[string]any{"vkLink": "https://vk.ru/call/join/legacy", "privateKey": testKey(1), "peerPublicKey": testKey(2),
		"peerAddress": "192.0.2.10:56004", "tunnelAddress": "10.66.66.2/24", "useSrtp": true}
	b, err := loadBackup(writeBackup(t, g))
	if err != nil {
		t.Fatal(err)
	}
	s, err := selectServer(b.servers(), "")
	if err != nil || s.PeerAddress != "192.0.2.10:56004" {
		t.Fatalf("legacy backup: %+v, %v", s, err)
	}
}

func TestTheSettingsCarryTheBackupsGlobals(t *testing.T) {
	b, err := loadBackup(writeBackup(t, globals(srtpServer("Home"))))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := selectServer(b.servers(), "")
	st := buildSettings(b, s)
	if strings.Join(st.VKLinks, " ") != "https://vk.ru/call/join/first https://vk.ru/call/join/second https://vk.ru/call/join/third" {
		t.Fatalf("links = %q — one per line, blanks and padding dropped, the FIRST line the anonymous link", st.VKLinks)
	}
	if st.NumConns != 40 || st.MTU != 1280 || st.UplinkPaceKiB != 247 || st.CredPoolCooldown != 150*time.Second {
		t.Fatalf("settings = %+v", st)
	}
	if strings.Join(st.DNSServers, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("dns = %q", st.DNSServers)
	}
	if err := st.validate(); err != nil {
		t.Fatalf("a good server: %v", err)
	}
}

func TestTheMTURuleIsTheApps(t *testing.T) {
	for in, want := range map[int]int{0: 1280, 1200: 1200, 900: 1000, 1500: 1400} {
		if got := resolveMTU(in); got != want {
			t.Errorf("resolveMTU(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestValidateNamesTheFieldAndNeverTheValue(t *testing.T) {
	b, _ := loadBackup(writeBackup(t, globals(srtpServer("Home"))))
	s, _ := selectServer(b.servers(), "")
	good := buildSettings(b, s)
	for name, mutate := range map[string]func(*settings){
		"privateKey":    func(st *settings) { st.PrivateKey = "c2VjcmV0LW5vdC1hLWtleQ==" }, // base64, the wrong length
		"peerPublicKey": func(st *settings) { st.PeerPublicKey = "c2VjcmV0 not base64!" },  // not base64
		"presharedKey":  func(st *settings) { st.PresharedKey = "c2hvcnQ=" },
		"tunnelAddress": func(st *settings) { st.TunnelAddress = "10.66.66.2" },
		"peerAddress":   func(st *settings) { st.PeerAddress = "192.0.2.10" },
		"connections":   func(st *settings) { st.NumConns = 121 },
		"vkLink":        func(st *settings) { st.VKLinks = nil },
	} {
		st := good
		mutate(&st)
		err := st.validate()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "c2VjcmV0") || strings.Contains(err.Error(), "c2hvcnQ") {
			t.Errorf("%s: the error carries the value: %v", name, err)
		}
	}
	st := good
	st.NumConns = 120
	if err := st.validate(); err != nil {
		t.Errorf("120 connections is the console's ceiling, allowed: %v", err)
	}
}

func TestThePoolIsOneReserveSetPerDefault(t *testing.T) {
	for _, tc := range []struct{ conns, reserve, want int }{
		{30, 1, 6}, {40, 1, 8}, {120, 1, 24}, {1, 1, 2}, {30, 0, 3}, {30, 3, 12}, {35, 1, 8},
	} {
		if got := poolSize(tc.conns, tc.reserve); got != tc.want {
			t.Errorf("poolSize(%d, %d) = %d, want %d", tc.conns, tc.reserve, got, tc.want)
		}
	}
}

func TestOnlyTheFlagsGivenOverrideTheBackup(t *testing.T) {
	b, _ := loadBackup(writeBackup(t, globals(srtpServer("Home"))))
	s, _ := selectServer(b.servers(), "")

	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := buildSettings(b, s)
	plan, err := o.applyTo(&st)
	if err != nil {
		t.Fatal(err)
	}
	if st.NumConns != 40 || st.UplinkPaceKiB != 247 || st.MTU != 1280 || st.PeerAddress != "192.0.2.10:56004" || st.UseUDP {
		t.Fatalf("no flags: the backup's settings changed: %+v", st)
	}
	if !plan.managed || strings.Join(plan.servers, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("no flags: dns plan %+v, want the server's servers, managed", plan)
	}

	o, err = parseFlags([]string{"-conns", "120", "-peer", "198.51.100.20:443", "-turn-transport", "udp", "-mtu", "1300",
		"-uplink-pace", "0", "-vk-link", "https://vk.ru/call/join/other", "-turn-server", "203.0.113.9:3478", "-dns", "9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	st = buildSettings(b, s)
	plan, err = o.applyTo(&st)
	if err != nil {
		t.Fatal(err)
	}
	if st.NumConns != 120 || st.PeerAddress != "198.51.100.20:443" || !st.UseUDP || st.MTU != 1300 || st.UplinkPaceKiB != 0 ||
		strings.Join(st.VKLinks, ",") != "https://vk.ru/call/join/other" || st.TurnServer != "203.0.113.9" || st.TurnPort != "3478" {
		t.Fatalf("flags not applied: %+v", st)
	}
	if strings.Join(plan.servers, ",") != "9.9.9.9" || !plan.managed {
		t.Fatalf("-dns list: %+v", plan)
	}

	for _, off := range []string{"false", "off", "no", "none"} {
		o, _ = parseFlags([]string{"-dns", off})
		st = buildSettings(b, s)
		if plan, _ := o.applyTo(&st); plan.managed {
			t.Errorf("-dns %s: the system's DNS still managed", off)
		}
	}
	o, _ = parseFlags([]string{"-default-route=false"})
	st = buildSettings(b, s)
	if plan, _ := o.applyTo(&st); plan.managed {
		t.Error("split mode manages the system's DNS")
	}
	for _, bad := range [][]string{{"-turn-transport", "quic"}, {"-dns", "1.1.1.1,resolver"}, {"-turn-server", "nohost"}, {"-pool-reserve", "-1"}} {
		o, err := parseFlags(bad)
		if err != nil {
			continue
		}
		st = buildSettings(b, s)
		if _, err := o.applyTo(&st); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := parseFlags([]string{"stray"}); err == nil {
		t.Error("a stray argument accepted")
	}
}

func TestAConfigOthersCanReadIsNoticed(t *testing.T) {
	p := writeBackup(t, globals(srtpServer("Home")))
	if configReadableByOthers(p) {
		t.Fatal("0600 reported as readable by others")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if !configReadableByOthers(p) {
		t.Fatal("0644 not reported — the file holds the WireGuard private key")
	}
}

func TestParseTurnOverrideIsTheApps(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.9:3478": "203.0.113.9|3478", " relay.example:19302 ": "relay.example|19302", "": "", "host": "", "host:": "", ":80": "", "host:x": ""} {
		h, p, ok := parseTurnOverride(in)
		got := ""
		if ok {
			got = h + "|" + p
		}
		if got != want {
			t.Errorf("parseTurnOverride(%q) = %q, want %q", in, got, want)
		}
	}
}
