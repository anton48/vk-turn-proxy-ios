package main

// 2026-11-03, the user's review: since Go 1.24 a TCP listener on Linux is
// Multipath TCP when the kernel supports and allows it (net.mptcp.enabled),
// and the relay listened with net.Listen — an MPTCP listener takes MPTCP
// sessions in the kernel before anything of the relay's own (the request's
// checks, -peer, -max-allocs) can act. The relay's TCP listener is plain TCP,
// explicitly, whatever the sysctl says.

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	turn "github.com/pion/turn/v5"
)

// On a Linux with net.mptcp.enabled = 1 the old listener accepts an MPTCP
// session from an MPTCP-asking dialer and both ends report Multipath TCP;
// elsewhere (macOS, a Linux with it off) the kernel has no MPTCP to give and
// the scan below carries the property.
func TestTheRelaysTCPListenerIsPlainTCPNotMultipath(t *testing.T) {
	ln, err := listenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, ok := ln.(*net.TCPListener); !ok {
		t.Fatalf("listenTCP returned a %T, want a *net.TCPListener", ln)
	}
	var d net.Dialer
	d.SetMultipathTCP(true) // a client that asks for MPTCP: a plain-TCP listener makes it fall back
	done := make(chan net.Conn, 1)
	go func() {
		c, err := d.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Error(err)
			done <- nil
			return
		}
		done <- c
	}()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := <-done
	if c == nil {
		t.FailNow()
	}
	defer c.Close()
	for side, conn := range map[string]net.Conn{"the accepted side": s, "the dialled side": c} {
		tc, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("%s is a %T, want a *net.TCPConn", side, conn)
		}
		mp, err := tc.MultipathTCP()
		if err != nil {
			t.Fatal(err)
		}
		if mp {
			t.Errorf("%s is Multipath TCP — the relay's listener let the kernel take an MPTCP session", side)
		}
	}
}

// Every TCP listener of the relay is made by listenTCP, and listenTCP turns
// Multipath TCP off before it listens.
func TestEveryTCPListenerOfTheRelayIsMadeWithMultipathOff(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if os.IsNotExist(err) {
		t.Skip("the source is not here — a compiled test binary on a stand; the runtime test above carries the property there")
	}
	if err != nil {
		t.Fatal(err)
	}
	src := stripComments(string(b))
	if strings.Contains(src, `net.Listen("tcp"`) || strings.Contains(src, "net.ListenTCP(") {
		t.Error("main.go listens on TCP without listenTCP")
	}
	if got := strings.Count(src, "listenTCP(a)"); got != 1 {
		t.Errorf("main.go calls listenTCP(a) %d times, want 1 — the relay's one TCP listener per -listen", got)
	}
	i := strings.Index(src, "func listenTCP(")
	if i < 0 {
		t.Fatal("main.go has no listenTCP")
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j > 0 {
		body = body[:j]
	}
	off, listen := strings.Index(body, "SetMultipathTCP(false)"), strings.Index(body, ".Listen(")
	if off < 0 || listen < 0 || off > listen {
		t.Errorf("listenTCP does not turn Multipath TCP off before it listens (SetMultipathTCP(false) at %d, Listen at %d)", off, listen)
	}
}

func stripComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// The user's second finding (2026-11-03): the control listener was made plain
// TCP, but a TCP ALLOCATION (RFC 6062, REQUESTED-TRANSPORT 6) made the
// inherited generator open a second TCP listener in the relay port range
// through its own ListenConfig — Multipath TCP by Go 1.24's Linux default,
// which listenTCP's setting never reached (their stand: 3 of 3 with
// MultipathTCP true). The app's allocations are UDP; the relay refuses a TCP
// allocation outright, so no second listener exists to configure: the
// Allocate is answered with an error (not 486), the relay port stays closed,
// and the seat comes back.
func TestATCPAllocationIsRefusedAndOpensNoListener(t *testing.T) {
	cfg, err := parseConfig("127.0.0.1:0", "", "127.0.0.1", 1, "40300-40300", "vk-turn-relay", false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	if c, err := net.DialTimeout("tcp", "127.0.0.1:40300", 300*time.Millisecond); err == nil {
		c.Close()
		t.Skip("port 40300 is held by something else on this machine")
	}
	tcp, err := net.Dial("tcp", r.tcp[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	granted, code := rawAllocateWith(t, turn.NewSTUNConn(tcp), r.tcp[0], requestedTCP)
	if granted {
		t.Error("a TCP allocation was GRANTED — a second TCP listener in the relay port range, outside listenTCP")
	}
	if code == stun.CodeAllocQuotaReached {
		t.Errorf("a TCP allocation refused with 486 — want the relay's own refusal, not the quota's")
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:40300", 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("the relay port accepts TCP after the ask: the allocation's listener is open")
	}
	if held := waitHeld(r, 0); held != 0 {
		t.Errorf("after the refused TCP allocation: %d held, want 0 — the reservation leaked", held)
	}
}
