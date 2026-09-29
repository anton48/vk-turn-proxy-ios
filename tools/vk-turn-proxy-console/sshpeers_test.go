package main

// The SSH sessions read from each system's socket table. Sabotage seen red:
// the state ignored (a listener's zero peer taken); an OUTGOING ssh (remote
// port 22) taken for a session this host serves; /proc's byte order not
// reversed; a peer listed twice.

import (
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
}
