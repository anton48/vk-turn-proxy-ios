package main

// The SSH sessions read from each system's socket table. Sabotage seen red:
// the state ignored (a listener's zero peer taken); an OUTGOING ssh (remote
// port 22) taken for a session this host serves; /proc's byte order not
// reversed; a peer listed twice; /proc/net/tcp6 not read; an IPv4-mapped
// client kept as IPv6 (never pinned); an IPv6 host cut at its first colon or
// dot; -block-ipv6 not refused over an IPv6 session, or refused for a client
// on-link, link-local, without the flag or in split mode.

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestTheSSHSessionsAreReadFromTheSocketTable(t *testing.T) {
	// 203.0.113.9 is CB.00.71.09 — /proc writes it 097100CB.
	proc := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n" +
		"   1: 0501A8C0:0016 097100CB:D431 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n" +
		"   2: 0501A8C0:C350 0A7100CB:0016 01 00000000:00000000 00:00000000 00000000  1000        0 3 1\n" +
		"   3: 0501A8C0:0016 097100CB:D432 01 00000000:00000000 00:00000000 00000000     0        0 4 1\n" +
		"   4: 0501A8C0:0050 0B7100CB:D431 01 00000000:00000000 00:00000000 00000000     0        0 5 1\n"
	if got := strings.Join(parseProcNetTCP(proc), ","); got != "203.0.113.9" {
		t.Errorf("/proc/net/tcp: %q — the one client of the local port 22, once; not a listener, not an outgoing ssh, not port 80", got)
	}
	sockstat := "USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n" +
		"root     sshd       812   4  tcp4   192.0.2.5:22          203.0.113.9:51234\n" +
		"a48      ssh        900   3  tcp4   192.0.2.5:40000       198.51.100.7:22\n" +
		"root     sshd       813   4  tcp4   192.0.2.5:22          203.0.113.10:51000\n" +
		"root     sshd       814   4  tcp4   192.0.2.5:22          203.0.113.9:51300\n"
	if got := strings.Join(parseSockstat(sockstat), ","); got != "203.0.113.9,203.0.113.10" {
		t.Errorf("sockstat: %q", got)
	}
	netstat := "Active Internet connections (including servers)\n" +
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n" +
		"tcp4       0      0  192.168.1.5.22         203.0.113.9.51234      ESTABLISHED\n" +
		"tcp4       0      0  192.168.1.5.50000      198.51.100.7.22        ESTABLISHED\n" +
		"tcp4       0      0  192.168.1.5.22         203.0.113.11.51235     TIME_WAIT\n" +
		"tcp4       0      0  *.22                   *.*                    LISTEN\n"
	if got := strings.Join(parseNetstatDarwin(netstat), ","); got != "203.0.113.9" {
		t.Errorf("netstat: %q", got)
	}

	// IPv6: 2001:db8::9 is 20 01 0d b8 … 00 09 — /proc writes each 32-bit
	// word reversed: B80D0120 00000000 00000000 09000000. A dual-stack
	// socket's IPv4 client ::ffff:203.0.113.10 ends FFFF0000 0A7100CB.
	proc6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue\n" +
		"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000\n" +
		"   1: 0000000000000000FFFF00000501A8C0:0016 0000000000000000FFFF00000A7100CB:C001 01 00000000:00000000\n" +
		"   2: B80D0120000000000000000005000000:0016 B80D0120000000000000000009000000:C002 01 00000000:00000000\n" +
		"   3: B80D0120000000000000000005000000:C350 B80D0120000000000000000007000000:0016 01 00000000:00000000\n" +
		"   4: B80D0120000000000000000005000000:0016 B80D0120000000000000000008000000:C003 06 00000000:00000000\n"
	if got := strings.Join(parseProcNetTCP(proc6), ","); got != "203.0.113.10,2001:db8::9" {
		t.Errorf("/proc/net/tcp6: %q — the mapped IPv4 client as the IPv4 it is, the IPv6 one; not the listener, not an outgoing ssh, not TIME_WAIT", got)
	}
	tables := map[string]string{"/proc/net/tcp": proc, "/proc/net/tcp6": proc6}
	read := func(path string) ([]byte, error) {
		if c, ok := tables[path]; ok {
			return []byte(c), nil
		}
		return nil, errors.New("no such file")
	}
	if got := strings.Join(procPeers(read), ","); got != "203.0.113.9,203.0.113.10,2001:db8::9" {
		t.Errorf("both of /proc's tables: %q", got)
	}
	delete(tables, "/proc/net/tcp6")
	if got := strings.Join(procPeers(read), ","); got != "203.0.113.9" {
		t.Errorf("a host without IPv6 (no tcp6): %q", got)
	}
	sockstat6 := "USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n" +
		"root     sshd       815   5  tcp6   2001:db8::5:22        2001:db8::9:51234\n" +
		"root     sshd       816   5  tcp46  *:22                  *:*\n" +
		"a48      ssh        901   3  tcp6   2001:db8::5:40001     2001:db8::7:22\n" +
		"root     sshd       817   5  tcp6   fe80::5%em0:22        fe80::9%em0:51000\n"
	if got := strings.Join(parseSockstat(sockstat6), ","); got != "2001:db8::9,fe80::9" {
		t.Errorf("sockstat, IPv6: %q", got)
	}
	netstat6 := "tcp6       0      0  2001:db8::5.22         2001:db8::9.51234      ESTABLISHED\n" +
		"tcp46      0      0  *.22                   *.*                    LISTEN\n" +
		"tcp6       0      0  2001:db8::5.50001      2001:db8::7.22         ESTABLISHED\n" +
		"tcp6       0      0  fe80::5%en0.22         fe80::9%en0.51000      ESTABLISHED\n" +
		"tcp6       0      0  ::ffff:192.168.1.5.22  ::ffff:203.0.113.12.51236 ESTABLISHED\n"
	if got := strings.Join(parseNetstatDarwin(netstat6), ","); got != "2001:db8::9,fe80::9,203.0.113.12" {
		t.Errorf("netstat, IPv6: %q", got)
	}
}

func TestTheIPv6BlockRefusesToCutAnSSHSession(t *testing.T) {
	_, own, _ := net.ParseCIDR("2001:db8:1::/64")
	onlink := []*net.IPNet{own}
	v4, v6 := byFamily([]string{"203.0.113.9", "2001:db8::9", "::ffff:203.0.113.10", "not an address"})
	if strings.Join(v4, ",") != "203.0.113.9,203.0.113.10" || strings.Join(v6, ",") != "2001:db8::9" {
		t.Fatalf("byFamily: v4 %q, v6 %q — a mapped IPv4 is an IPv4 (pinned like any other)", v4, v6)
	}
	why := v6BlockRefusal(true, true, []string{"203.0.113.9", "2001:db8::9"}, onlink)
	if why == "" || !strings.Contains(why, "1 SSH session(s)") || !strings.Contains(why, "2001:db8::9") || !strings.Contains(why, "connect over IPv4") {
		t.Errorf("an SSH session over IPv6 and -block-ipv6: %q — want a refusal that names the session and says what to do", why)
	}
	for _, tc := range []struct {
		name          string
		block, defRte bool
		peers         []string
	}{
		{"IPv4 sessions only", true, true, []string{"203.0.113.9", "::ffff:203.0.113.10"}},
		{"a client on this host's own IPv6 network", true, true, []string{"2001:db8:1::7"}},
		{"a link-local client", true, true, []string{"fe80::9"}},
		{"no -block-ipv6", false, true, []string{"2001:db8::9"}},
		{"split mode (no default route: no IPv6 block either)", true, false, []string{"2001:db8::9"}},
	} {
		if why := v6BlockRefusal(tc.block, tc.defRte, tc.peers, onlink); why != "" {
			t.Errorf("%s: refused (%q) — nothing would be cut", tc.name, why)
		}
	}
}
