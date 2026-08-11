package proxy

import (
	"net"
	"os"
	"strings"
	"testing"
)

// An instrument that cannot see must say nothing, not say zero — a line of
// zeroes is quotable later as "measured, and the sockets were empty".
func TestSockStatsIsSilentWithNothingToSample(t *testing.T) {
	s := newSockStats()
	if got := s.summary(); got != "" {
		t.Fatalf("summary with no connections = %q, want empty", got)
	}
	// A nil receiver is the UDP-transport path: no registration ever happens.
	var nilS *sockStats
	if got := nilS.summary(); got != "" {
		t.Fatalf("nil summary = %q, want empty", got)
	}
	nilS.register(0, nil)
	nilS.unregister(0)
}

// register must ignore anything that is not a TCP connection, so the UDP
// transport needs no special case at the call site.
func TestOnlyTCPConnectionsAreRegistered(t *testing.T) {
	s := newSockStats()
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	defer uc.Close()
	s.register(0, uc.(net.Conn))
	s.register(-1, nil)
	if len(s.conns) != 0 {
		t.Fatalf("registered %d non-TCP connections, want 0", len(s.conns))
	}
}

// 🚨 THE RECONNECT TRAP. Retransmits are cumulative PER SOCKET, so a connection
// that drops and redials restarts its counter at zero. Subtracting the previous
// value would print a negative delta — "retransmits were undone" — which is the
// kind of number that gets quoted before it gets questioned.
func TestRetransmitDeltaSurvivesASocketReset(t *testing.T) {
	s := newSockStats()
	s.lastRtx[3] = 500

	// Same socket, counter advanced: a normal delta.
	if got := deltaFor(s, 3, 560); got != 60 {
		t.Fatalf("delta on a live socket = %d, want 60", got)
	}
	// Fresh socket on the same conn index: counter restarted below the old one.
	if got := deltaFor(s, 3, 7); got != 0 {
		t.Fatalf("delta across a reconnect = %d, want 0 — a reset must not "+
			"produce a negative or a wrapped-around delta", got)
	}
	// And the next interval measures from the NEW baseline, not the old one.
	if got := deltaFor(s, 3, 19); got != 12 {
		t.Fatalf("delta after the reset = %d, want 12", got)
	}
}

// deltaFor mirrors summary()'s accounting for one connection so the rule can be
// tested without a live socket.
func deltaFor(s *sockStats, idx int, cur uint64) uint64 {
	var d uint64
	if prev, seen := s.lastRtx[idx]; seen && cur >= prev {
		d = cur - prev
	}
	s.lastRtx[idx] = cur
	return d
}

// unregister must not leave the retransmit baseline behind: a later connection
// reusing the index would be measured against a stranger's counter.
func TestUnregisterClearsTheBaseline(t *testing.T) {
	s := newSockStats()
	s.lastRtx[2] = 900
	s.unregister(2)
	if _, ok := s.lastRtx[2]; ok {
		t.Fatal("unregister left the retransmit baseline for conn 2 behind")
	}
}

// 🚨 THE FIELD WHOSE DEFINITION IS THE TRAP. The iOS SDK documents
// tcpi_snd_sbbytes as "bytes in send socket buffer, INCLUDING in-flight data",
// so it is an upper bound on the queue rather than the queue. This test pins the
// warning to the source: if the caveat is ever dropped from the comment, the
// next reader will quote `sb` as queueing delay.
func TestTheInFlightCaveatIsDocumented(t *testing.T) {
	src, err := os.ReadFile("sockstats.go")
	if err != nil {
		t.Fatalf("read sockstats.go: %v", err)
	}
	for _, want := range []string{"IN-FLIGHT", "UPPER BOUND"} {
		if !strings.Contains(string(src), want) {
			t.Errorf("sockstats.go no longer says %q — `sb` will be read as the "+
				"queue when it also counts data already on the wire", want)
		}
	}
}

// 🎯 THE DECISIVE PAIRING. The question the window answers is not "is some
// connection throttled" but "is the connection that is BACKED UP the throttled
// one" — so the window must come from the same connection as the deepest buffer,
// never from a pool-wide minimum that could belong to an idle socket.
func TestWindowIsReportedForTheConnectionThatIsBackedUp(t *testing.T) {
	// The deepest buffer is the middle entry; the smallest window belongs to an
	// idle connection and must NOT be what gets reported.
	got := windowAtDeepestBuffer([]sbWnd{
		{sb: 1 << 10, wnd: 1 << 20},
		{sb: 128 << 10, wnd: 64 << 10}, // backed up, throttled — this one
		{sb: 0, wnd: 4 << 10},          // idle, tiny window — a decoy
	})
	if got != 64<<10 {
		t.Fatalf("window = %d, want %d — a pool-wide minimum would have reported "+
			"the idle connection's 4 KiB and invented a throttle that is not there",
			got, 64<<10)
	}

	if got := windowAtDeepestBuffer(nil); got != 0 {
		t.Fatalf("empty pool = %d, want 0", got)
	}
	// Ties resolve to the first, deterministically — no map iteration order.
	if got := windowAtDeepestBuffer([]sbWnd{{sb: 5, wnd: 111}, {sb: 5, wnd: 222}}); got != 111 {
		t.Fatalf("tie = %d, want the first (111)", got)
	}
}

// 🚨 THE GUARD THAT WAS MISSING, AND IT COST A DEVICE RUN. Build 233 registered
// the socket in runTURN and shipped. SRTP is the production transport and dials
// its TURN connection somewhere else entirely, so `sock=` appeared in exactly
// ZERO lines of the first run — the instrument compiled, tested green, and was
// never fed.
//
// The write-timing guard below existed and passed the whole time, because it
// guards the OTHER half. Guarding one half of a two-part wiring is how you get a
// green suite and an empty log.
func TestEveryTURNDialIsRegisteredForSampling(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	dials := 0
	for i, ln := range lines {
		// Both forms in use: d.DialContext(ctx, "tcp", turnAddr) and
		// dialer.Dial("tcp", turnAddr).
		if !strings.Contains(ln, `"tcp", turnAddr`) {
			continue
		}
		dials++
		registered := false
		for j := i; j < i+14 && j < len(lines); j++ {
			if strings.Contains(lines[j], "sockStats.register(") {
				registered = true
				break
			}
		}
		if !registered {
			t.Errorf("proxy.go:%d dials a TURN relay over TCP and never calls "+
				"sockStats.register — that transport's sockets are invisible, and "+
				"`sock=` will simply be absent from the log rather than wrong",
				i+1)
		}
	}
	if dials < 2 {
		t.Fatalf("found %d TCP dials to turnAddr, expected at least 2 (runTURN and "+
			"setupSRTPSession) — the scan is not finding them and this test is "+
			"passing vacuously", dials)
	}
}

// 🚨 EVERY WRITE MUST BE TIMED, and there are four places that can forget — the
// same shape as the sendCh dequeue guard. Validated by sabotage: drop one
// observe call and this names the line.
func TestEveryWriteIsTimed(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	sites := 0
	for i, ln := range lines {
		// The four transport writers, each pulling from sendCh above it.
		if !strings.Contains(ln, "w0 := time.Now()") {
			continue
		}
		sites++
		fed := false
		for j := i; j < i+4 && j < len(lines); j++ {
			if strings.Contains(lines[j], "p.writeWait.observe(w0.UnixNano()") {
				fed = true
				break
			}
		}
		if !fed {
			t.Errorf("proxy.go:%d starts a write clock that nothing reads", i+1)
		}
	}
	if sites < 4 {
		t.Fatalf("found %d timed writes, want at least 4 (DTLS, direct, WRAP-A, "+
			"SRTP) — that transport's time inside Write is invisible", sites)
	}
}
