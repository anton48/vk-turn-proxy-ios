package proxy

// Build 469 — a failed PING write is judged, never a silent exit (wakeprobe.go,
// pingWriteFailed). Up to 468 the probe goroutine of both session kinds ended on
// ANY error of its ping's write with a bare return, and the zombie detector,
// which lives in that goroutine, ended with it; the recv goroutine's read
// timeout is judged by the GLOBAL receive clock, so one live neighbour hid the
// dead connection, and its writer stayed in the shared send queue, where every
// uplink packet that reached it was lost. On an idle phone that was ≈ 40 × 5 s
// of a tunnel passing nothing behind a relay's loss (2026-11-02, Nov 2 §511).

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

func pingFailProxy() *Proxy {
	return &Proxy{credPool: &credPool{}, lastPongSeq: make([]atomic.Uint64, 1), lastPingSeq: make([]atomic.Uint64, 1), lastActiveProbeAt: make([]atomic.Int64, 1)}
}

// A ping's write that finds the connection GONE — a broken pipe, a reset, the
// kernel's own give-up, a closed socket — ends the session at once, in both
// session kinds, and says so.
func TestAPingWriteThatFindsTheConnectionGoneEndsTheSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		cause string
	}{
		// The cause is the errno's OWN words — the kernel's, not Darwin's: Linux
		// says "connection timed out" where Darwin says "operation timed out".
		{"EPIPE", syscall.EPIPE, syscall.EPIPE.Error()},
		{"EPIPE inside a net.OpError (what a socket write returns)", &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EPIPE)}, syscall.EPIPE.Error()},
		{"ECONNRESET", syscall.ECONNRESET, syscall.ECONNRESET.Error()},
		{"ECONNABORTED", syscall.ECONNABORTED, syscall.ECONNABORTED.Error()},
		{"ENOTCONN", syscall.ENOTCONN, syscall.ENOTCONN.Error()},
		{"ETIMEDOUT (the kernel's own give-up)", syscall.ETIMEDOUT, syscall.ETIMEDOUT.Error()},
		{"a closed socket", net.ErrClosed, "use of closed network connection"},
		{"a closed pipe", io.ErrClosedPipe, ""},
		{"pion/dtls's closed connection", dtls.ErrConnClosed, ""},
		{"the words alone (a library's own wrapping)", errors.New("write: broken pipe"), "broken pipe"},
	} {
		for _, label := range []string{"", "SRTP "} {
			t.Run(tc.name+"/"+strings.TrimSpace(label), func(t *testing.T) {
				logs := captureLog(t)
				p := pingFailProxy()
				cancelled := 0
				stop := p.pingWriteFailed(3, 7, label, tc.err, func() { cancelled++ })
				if !stop {
					t.Errorf("stop = false: the goroutine would go on probing a connection that is gone")
				}
				if cancelled != 1 {
					t.Errorf("connCancel called %d times, want 1: the session is not ended", cancelled)
				}
				out := logs()
				want := "[conn 3 on slot 7] " + label + "the ping's write found the connection gone ("
				if !strings.Contains(out, want) || !strings.Contains(out, "— the session ends") {
					t.Errorf("the log does not say the ping's write ended the session — want %q … %q, got %q", want, "— the session ends", out)
				}
				if tc.cause != "" && !strings.Contains(out, "("+tc.cause+")") {
					t.Errorf("the log names %q, want the cause (%s)", out, tc.cause)
				}
			})
		}
	}
}

// A ping's write that merely FAILS — its own deadline ran out, a moment's
// refusal, a route away for now — ends nothing: the goroutine goes on, the
// zombie detector in it stays alive to judge the connection by its pongs. Its
// own context's end is no verdict either, and no line.
func TestAPingWriteThatMerelyFailsKeepsTheDetectorAlive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		said  bool
		cause string
	}{
		{"the write's own deadline", os.ErrDeadlineExceeded, true, "i/o timeout"},
		{"the deadline inside a net.OpError", &net.OpError{Op: "write", Net: "udp", Err: os.ErrDeadlineExceeded}, true, "i/o timeout"},
		{"EAGAIN — a moment's refusal", syscall.EAGAIN, true, syscall.EAGAIN.Error()},
		{"ENOBUFS — a full UDP socket", syscall.ENOBUFS, true, syscall.ENOBUFS.Error()},
		{"EHOSTUNREACH — a route away for now, the path hook's business", syscall.EHOSTUNREACH, true, ""},
		{"ENETUNREACH", syscall.ENETUNREACH, true, ""},
		{"a plain error", errors.New("something else"), true, ""},
		{"the goroutine's own context cancelled", context.Canceled, false, ""},
		{"the goroutine's own context past its deadline", context.DeadlineExceeded, false, ""},
	} {
		for _, label := range []string{"", "SRTP "} {
			t.Run(tc.name+"/"+strings.TrimSpace(label), func(t *testing.T) {
				logs := captureLog(t)
				p := pingFailProxy()
				cancelled := 0
				stop := p.pingWriteFailed(3, 7, label, tc.err, func() { cancelled++ })
				if stop {
					t.Errorf("stop = true: the goroutine ends on an error that says nothing about the connection — the zombie detector dies with it")
				}
				if cancelled != 0 {
					t.Errorf("connCancel called %d times, want 0: a session ended on an error that is not the connection's", cancelled)
				}
				out := logs()
				if tc.said {
					want := "[conn 3] " + label + "the ping's write failed ("
					if !strings.Contains(out, want) || !strings.Contains(out, "— the probe goes on") {
						t.Errorf("the log does not say the probe goes on — want %q … %q, got %q", want, "— the probe goes on", out)
					}
					if tc.cause != "" && !strings.Contains(out, "("+tc.cause+")") {
						t.Errorf("the log names %q, want the cause (%s)", out, tc.cause)
					}
				} else if strings.Contains(out, "ping's write") {
					t.Errorf("a context's end is logged as a failed ping: %q", out)
				}
				if strings.Contains(out, "the session ends") {
					t.Errorf("the log says the session ends: %q", out)
				}
			})
		}
	}
}

// The log line names the CAUSE and never an address: a socket's error carries
// both ends of the connection.
func TestAFailedPingsLineNamesTheCauseAndNoAddress(t *testing.T) {
	src, _ := net.ResolveTCPAddr("tcp", "198.51.100.7:41000")
	dst, _ := net.ResolveTCPAddr("tcp", "203.0.113.9:3478")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"gone", &net.OpError{Op: "write", Net: "tcp", Source: src, Addr: dst, Err: os.NewSyscallError("write", syscall.EPIPE)}},
		{"merely failed", &net.OpError{Op: "write", Net: "tcp", Source: src, Addr: dst, Err: os.ErrDeadlineExceeded}},
		{"gone, by the words alone (a library's own wrapping without %w)", errors.New("write tcp " + src.String() + "->" + dst.String() + ": broken pipe")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)
			p := pingFailProxy()
			p.pingWriteFailed(0, 0, "", tc.err, func() {})
			out := logs()
			if !strings.Contains(out, "ping's write") {
				t.Fatalf("no line: %q", out)
			}
			for _, addr := range []string{"198.51.100.7", "203.0.113.9", "41000", "3478"} {
				if strings.Contains(out, addr) {
					t.Errorf("the line carries an address (%s): %q", addr, out)
				}
			}
		})
	}
}

// Both session kinds judge a failed ping — the tick's and the wake probe's —
// by the ONE rule, at every exit of the probe goroutine that an error can
// take; none of them returns bare any more.
func TestBothSessionKindsJudgeAFailedPingByTheOneRule(t *testing.T) {
	b, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.Join(strings.Fields(stripComments(string(b))), " ")
	for _, label := range []string{`""`, `"SRTP "`} {
		tick := `if err := p.tickPing(&seq, &lastPingAt, now, sendPing); err != nil { if p.pingWriteFailed(connIdx, credSlot, ` + label + `, err, connCancel) { return } }`
		if got := strings.Count(src, tick); got != 1 {
			t.Errorf("proxy.go holds %d × the tick's exit through the one rule for the %s session kind, want 1:\n%s", got, label, tick)
		}
		wake := `alive, probed, err := wake.serve(connCtx, connIdx, credSlot, ` + label + `, &seq, &lastPingAt, sendPing) if err != nil { if p.pingWriteFailed(connIdx, credSlot, ` + label + `, err, connCancel) { return } continue } if !alive { connCancel() return }`
		if got := strings.Count(src, wake); got != 1 {
			t.Errorf("proxy.go holds %d × the wake branch's exit through the one rule for the %s session kind, want 1:\n%s", got, label, wake)
		}
	}
	if got := strings.Count(src, "p.pingWriteFailed("); got != 4 {
		t.Errorf("proxy.go calls pingWriteFailed %d times, want 4 — the tick's and the wake's exit of each session kind", got)
	}
	w, err := os.ReadFile("wakeprobe.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(stripComments(string(w)), "func (p *Proxy) pingWriteFailed("); got != 1 {
		t.Errorf("wakeprobe.go defines pingWriteFailed %d times, want 1", got)
	}
}

// The review of 815137e: a wake probe whose FIRST write failed for a reason
// that is not the connection's (ENOBUFS, the write's own deadline) left the
// goroutine through `continue` — and the next turn met the probe's 30-s
// throttle (lastActiveProbeAt is stamped before the send): serve marked the
// wake served without a ping, and the wake was swallowed. A probe that did not
// finish is OWED: the wake stays pending, the throttle does not apply to it,
// and it is retried after a pause, not at once.
func TestAWakeProbeWhoseWriteFailedIsOwedAndRetriedAfterAPause(t *testing.T) {
	shrinkWakeProbe(t)
	r := wakeProbeRetry
	wakeProbeRetry = 40 * time.Millisecond
	t.Cleanup(func() { wakeProbeRetry = r })
	p := probeProxy()
	p.serverProbeable.Store(true)
	w := p.newWakeWatch()
	p.broadcastWake()
	var seq uint64
	var lastPingAt time.Time
	sent := 0
	send := func(s uint64, _ time.Time) error {
		sent++
		if sent == 1 {
			return syscall.ENOBUFS // a moment's refusal on the probe's first write
		}
		go func() { time.Sleep(time.Millisecond); p.notePongSeq(0, s) }()
		return nil
	}
	alive, probed, err := w.serve(context.Background(), 0, 0, "", &seq, &lastPingAt, send)
	if err == nil || !errors.Is(err, syscall.ENOBUFS) || !probed || !alive {
		t.Fatalf("the first serve: alive %v probed %v err %v, want the write's own error back, alive, probed", alive, probed, err)
	}
	if !w.pending() {
		t.Fatal("after the failed write the wake is not pending: nothing will probe it")
	}
	// The next turn of the goroutine serves the wake again: within the throttle
	// (the stamp is seconds old), yet the OWED probe is made — after the pause.
	t0 := time.Now()
	alive, probed, err = w.serve(context.Background(), 0, 0, "", &seq, &lastPingAt, send)
	if err != nil || !alive || !probed {
		t.Fatalf("the second serve: alive %v probed %v err %v, want the owed probe made", alive, probed, err)
	}
	if sent < 2 {
		t.Errorf("the owed probe sent nothing (sends %d): the throttle swallowed the wake", sent)
	}
	if waited := time.Since(t0); waited < wakeProbeRetry {
		t.Errorf("the owed probe was retried after %s, want a pause of at least %s", waited, wakeProbeRetry)
	}
	if w.pending() {
		t.Error("the wake is still pending after the owed probe's verdict")
	}
	// Served now: the next wake inside the throttle needs no probe (as before).
	p.broadcastWake()
	if _, probed, _ = w.serve(context.Background(), 0, 0, "", &seq, &lastPingAt, nil); probed || w.pending() {
		t.Errorf("probed %v pending %v, want a throttled wake served without a probe", probed, w.pending())
	}
}

// The goroutine's own context ending inside a probe owes nothing: the
// goroutine returns at its next turn, and a watch that outlived it would not
// probe on a cancelled context's account.
func TestAProbeEndedByItsOwnContextOwesNothing(t *testing.T) {
	shrinkWakeProbe(t)
	p := probeProxy()
	p.serverProbeable.Store(true)
	w := p.newWakeWatch()
	p.broadcastWake()
	ctx, cancel := context.WithCancel(context.Background())
	var seq uint64
	var lastPingAt time.Time
	// The probe has begun (its first ping written) when the context ends: the
	// error comes out of the probe's own wait, where an owed probe is decided.
	_, _, err := w.serve(ctx, 0, 0, "", &seq, &lastPingAt, func(uint64, time.Time) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want the context's", err)
	}
	if w.owed {
		t.Error("a probe ended by its own context is owed")
	}
}
