//go:build darwin

package proxy

import (
	"net"
	"strings"
	"testing"
	"time"
)

// 🚨 THE TEST THAT MATTERS: does the getsockopt actually return anything?
// Everything else here is bookkeeping — this is the one that fails if
// TCP_CONNECTION_INFO is the wrong constant, the wrong level, or the struct is
// the wrong shape, and it fails on the Mac in a second rather than on the phone
// after an install.
func TestSampleTCPInfoReadsARealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	srv := <-accepted
	defer srv.Close()

	// Put real bytes through it so the kernel has counters to report.
	if _, err := c.Write(make([]byte, 64<<10)); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, ok := sampleTCPInfo(c.(*net.TCPConn))
	if !ok {
		t.Fatal("sampleTCPInfo returned no data for a live loopback socket — " +
			"the option number, the level, or the struct is wrong")
	}
	// Loopback: an established connection always has a non-zero MSS-scaled
	// window. Assert on something that cannot be zero by accident rather than on
	// a value that happens to be plausible.
	if info.cwnd == 0 {
		t.Errorf("cwnd = 0 on an established connection — the struct is probably "+
			"misaligned; got %+v", info)
	}
	// An established peer always advertises something. Zero here would mean the
	// field is misread, and a misread window is exactly the kind of number that
	// gets quoted as "the relay is throttling us".
	if info.sndWnd == 0 {
		t.Errorf("sndWnd = 0 on an established loopback connection — misaligned "+
			"or wrong field; got %+v", info)
	}
	// The socket buffer must have held something at some point during a 64 KiB
	// write, but by the time we sample, loopback may already have drained it —
	// so this is deliberately NOT asserted. Recording why, so nobody adds a
	// flaky assertion here later.
	t.Logf("loopback sample: sb=%d cwnd=%d srtt=%dms rtx=%d", info.sbBytes, info.cwnd, info.srttMs, info.rtxPkts)
}

// A closed socket must degrade to "no data", not to a zero-filled sample that
// would drag the pool's percentiles down.
func TestSampleTCPInfoOnAClosedSocketReportsNoData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := c.(*net.TCPConn)
	tc.Close()
	if _, ok := sampleTCPInfo(tc); ok {
		t.Fatal("a closed socket reported data — a dead connection would be " +
			"counted into the pool's percentiles")
	}
	if _, ok := sampleTCPInfo(nil); ok {
		t.Fatal("a nil connection reported data")
	}
}

// End to end through the registry: the summary must name every field a reader
// needs, and must count exactly the connections it sampled.
func TestSummaryOverRealSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { defer c.Close(); time.Sleep(200 * time.Millisecond) }()
		}
	}()

	s := newSockStats()
	for i := 0; i < 3; i++ {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Fatalf("dial %d: %v", i, derr)
		}
		defer c.Close()
		s.register(i, c)
	}
	out := s.summary()
	for _, want := range []string{"sock=3", "sb=", "cwnd=", "wnd=", "wscale=", "sbmax-wnd=", "srtt=", "rtx=+", "lossrec=", "reord="} {
		if !strings.Contains(out, want) {
			t.Errorf("summary %q is missing %q", out, want)
		}
	}
	// First interval: every baseline is being established, so the delta must be
	// zero rather than the sockets' whole lifetime count.
	if !strings.Contains(out, "rtx=+0") {
		t.Errorf("summary %q reports retransmits on the FIRST sample — the "+
			"baseline is being subtracted from nothing", out)
	}
	s.unregister(1)
	if out2 := s.summary(); !strings.Contains(out2, "sock=2") {
		t.Errorf("after unregister, summary = %q, want sock=2", out2)
	}
}
