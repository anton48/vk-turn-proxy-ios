package main

// The OS tools' output. Sabotage seen red: the highest metric chosen; a
// "link#N" gateway taken for an address; the legend line of networksetup
// kept; a disabled service kept; resolvectl's suffixes kept.

import (
	"strings"
	"testing"
)

func TestTheBSDDefaultRouteIsRead(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
	if g, ok := parseBSDRouteGet(out); !ok || g.IP != "192.168.1.1" || g.Iface != "en0" {
		t.Fatalf("got %+v %v", g, ok)
	}
	p2p := "   route to: default\ndestination: default\n    gateway: link#12\n  interface: ppp0\n"
	if g, ok := parseBSDRouteGet(p2p); !ok || g.IP != "" || g.Iface != "ppp0" {
		t.Fatalf("point-to-point: got %+v %v", g, ok)
	}
	if _, ok := parseBSDRouteGet("route: route has not been found\n"); ok {
		t.Fatal("no default route read as one")
	}
}

func TestTheLinuxDefaultRouteIsTheLowestMetric(t *testing.T) {
	out := "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.5 metric 600\n" +
		"default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n"
	if g, ok := parseLinuxDefaultRoutes(out); !ok || g.IP != "10.0.0.1" || g.Iface != "eth0" {
		t.Fatalf("got %+v %v", g, ok)
	}
	if g, ok := parseLinuxDefaultRoutes("default dev ppp0 scope link\n"); !ok || g.IP != "" || g.Iface != "ppp0" {
		t.Fatalf("dev-only: got %+v %v", g, ok)
	}
	if g, ok := parseLinuxDefaultRoutes("default via 10.0.0.1 dev eth0\n"); !ok || g.IP != "10.0.0.1" {
		t.Fatalf("no metric: got %+v %v", g, ok)
	}
	if _, ok := parseLinuxDefaultRoutes(""); ok {
		t.Fatal("no default route read as one")
	}
}

func TestTheDNSToolsAreRead(t *testing.T) {
	rc := "# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%en0\nnameserver 8.8.8.8\noptions edns0\n"
	if got := strings.Join(parseResolvConf(rc), ","); got != "192.168.1.1,8.8.8.8" {
		t.Errorf("resolv.conf: %q — IPv4 nameservers only", got)
	}
	svcs := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB 10/100/1000 LAN\nThunderbolt Bridge\n"
	if got := strings.Join(parseNetworkServices(svcs), "|"); got != "Wi-Fi|USB 10/100/1000 LAN|Thunderbolt Bridge" {
		t.Errorf("services: %q", got)
	}
	if got := parseGetDNSServers("There aren't any DNS Servers set on Wi-Fi.\n"); got != nil {
		t.Errorf("no manual DNS: %q", got)
	}
	if got := strings.Join(parseGetDNSServers("1.1.1.1\n8.8.8.8\n"), ","); got != "1.1.1.1,8.8.8.8" {
		t.Errorf("manual DNS: %q", got)
	}
	pkt := "op = BOOTREPLY\nyiaddr = 192.168.1.5\ndomain_name_server (ip_mult): {192.168.1.1, 198.51.100.53}\nend (none):\n"
	if got := strings.Join(parseIpconfigPacket(pkt), ","); got != "192.168.1.1,198.51.100.53" {
		t.Errorf("ipconfig getpacket: %q", got)
	}
	if got := strings.Join(parseResolvectlDNS("Link 2 (eth0): 10.0.0.2 10.0.0.3#dns.example 2001:db8::53\n"), ","); got != "10.0.0.2,10.0.0.3" {
		t.Errorf("resolvectl dns: %q", got)
	}
	if got := sshClientIP("203.0.113.9 51234 22"); got != "203.0.113.9" {
		t.Errorf("SSH_CLIENT: %q", got)
	}
	if got := sshClientIP(""); got != "" {
		t.Errorf("no SSH: %q", got)
	}
}

func TestTheRelayHostsComeFromTheCredentialCache(t *testing.T) {
	p := t.TempDir() + "/creds.json"
	writeFile(t, p, `{"version":2,"creds":[{"address":"203.0.113.50:19302","username":"u","password":"x"},{"address":"203.0.113.50:19302"},{"address":"203.0.113.51:3478"},{"address":"relay.example:3478"}]}`)
	if got := strings.Join(relayHostsFromCache(p), ","); got != "203.0.113.50,203.0.113.51" {
		t.Fatalf("relays = %q — each address once, names dropped", got)
	}
	if relayHostsFromCache(t.TempDir()+"/none.json") != nil {
		t.Fatal("a missing cache yields relays")
	}
}
