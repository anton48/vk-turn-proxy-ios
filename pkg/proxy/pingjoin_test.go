// SPDX-License-Identifier: GPL-3.0-only

package proxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// A session returns AFTER its ping goroutine has left (the gate's fixture
// race of 2026-11-03): the join cancels the session's context, waits for the
// goroutine's own end, and is bounded.
func TestASessionReturnsAfterItsPingGoroutineHasLeft(t *testing.T) {
	say := captureLog(t)
	p := &Proxy{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	left := make(chan time.Time, 1)
	go func() {
		defer close(done)
		<-ctx.Done()
		left <- time.Now()
	}()
	before := time.Now()
	if !p.joinPingLoop(cancel, done, 7, "") {
		t.Fatal("a goroutine that leaves on the cancel was not joined")
	}
	if ctx.Err() == nil {
		t.Fatal("the join did not cancel the session's context")
	}
	if at := <-left; at.Before(before) {
		t.Fatal("the goroutine left before the join")
	}
	if strings.Contains(say(), "WITHOUT its ping goroutine") {
		t.Fatal("a joined goroutine said as left behind")
	}
	// Bounded: a goroutine that does not leave is left behind after the
	// budget, said in the log.
	b := pingJoinBudget
	pingJoinBudget = 50 * time.Millisecond
	t.Cleanup(func() { pingJoinBudget = b })
	stuck := make(chan struct{})
	start := time.Now()
	res := make(chan bool, 1)
	go func() { res <- p.joinPingLoop(func() {}, stuck, 8, "SRTP ") }()
	select {
	case joined := <-res:
		if joined {
			t.Fatal("a goroutine that never leaves was reported joined")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the join did not return within two seconds of a 50-ms budget — not bounded")
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > time.Second {
		t.Fatalf("the bounded wait took %s", d)
	}
	if !strings.Contains(say(), "[conn 8] SRTP the session returns WITHOUT its ping goroutine") {
		t.Fatal("the session did not say it returned without its ping goroutine")
	}
}

// Both session kinds start their ping goroutine with a done channel it closes
// as it leaves, and defer the join right behind the start — before the
// defers registered earlier (the relay leg's join, the credential's release).
func TestBothSessionKindsJoinTheirPingGoroutine(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Skip("proxy.go not at hand")
	}
	code := string(src)
	for _, site := range []struct{ name, anchor string }{
		{"the DTLS session", "// Liveness-probe sender. Periodically writes a sentinel packet"},
		{"the SRTP session", "// Liveness-probe sender — ported from runDTLSSession"},
	} {
		at := strings.Index(code, site.anchor)
		if at < 0 {
			t.Fatalf("%s: the ping goroutine's comment not found", site.name)
		}
		body := code[at:]
		if end := strings.Index(body, "wg.Add(2)"); end > 0 {
			body = body[:end]
		}
		steps := []string{"pingDone := make(chan struct{})", "go func() {", "defer close(pingDone)", "ticker := time.NewTicker(probeInterval)", "}()", "defer p.joinPingLoop(connCancel, pingDone, connIdx,"}
		from := 0
		for _, step := range steps {
			i := strings.Index(body[from:], step)
			if i < 0 {
				t.Fatalf("%s: %q not found in order after the ping goroutine's start", site.name, step)
			}
			from += i + len(step)
		}
	}
	if n := strings.Count(code, "joinPingLoop("); n != 2 {
		t.Fatalf("joinPingLoop is called %d times in proxy.go, want 2 — one per session kind", n)
	}
}
