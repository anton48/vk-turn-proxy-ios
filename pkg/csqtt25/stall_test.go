package csqtt25

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// startGated starts a client on sockets whose writes can be parked or made to
// fail, with a write bound.
func startGated(t *testing.T, srv *fakeServer, workers int, bound time.Duration) (*Client, *dialer) {
	t.Helper()
	d := &dialer{server: srv.sock.LocalAddr(), dials: map[int]int{}, gated: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ClientConfig{Password: srv.password, Workers: workers, Keys: KeysWrap, Dial: d.dial, WriteBound: bound})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, g := range d.gates { // whatever happened, let every parked goroutine go
			g.Close()
		}
	})
	eventually(t, "every worker ready", func() bool { return c.Stats().Ready == workers })
	return c, d
}

// gate is the nth socket the dialer handed out (in the order of the dials).
func (d *dialer) gate(n int) *gateConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gates[n]
}

// sendFlowsUntil sends one packet each of flows 1, 2, 3 … until done says so,
// every send bounded by limit, and returns the errors the sends gave and how
// long the slowest took.
func sendFlowsUntil(t *testing.T, c *Client, limit time.Duration, done func() bool) (errs []error, slowest time.Duration) {
	t.Helper()
	for flow := 1; flow <= 200 && !done(); flow++ {
		var err error
		took := within(t, limit, "one Send", func() { err = c.Send(seqPkt(uint16(2000+flow), flow, 100)) })
		if took > slowest {
			slowest = took
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if !done() {
		t.Fatal("two hundred flows and the stream under test was never picked")
	}
	return errs, slowest
}

// 🚨 A relay that stops taking bytes costs the caller of Send the bound, ONCE:
// the write comes back as a stall, the stream is replaced, and the flows go on
// over the others. Without a bound that write — and with it every packet of
// the tunnel — waited until somebody noticed the stream.
func TestAStalledWriteCostsTheBoundOnceAndItsStreamIsReplaced(t *testing.T) {
	quickClocks(t)
	const bound = 150 * time.Millisecond
	srv := newFakeServer(t, "pw-stall")
	c, d := startGated(t, srv, 2, bound)
	d.gate(1).stuck.Store(true) // worker 2's relay takes no more bytes

	errs, slowest := sendFlowsUntil(t, c, 3*time.Second, func() bool { return c.Stats().WriteStalls > 0 })
	if len(errs) != 1 || !errors.Is(errs[0], os.ErrDeadlineExceeded) {
		t.Fatalf("the sends' errors: %v — want exactly one, the bound's own expiry", errs)
	}
	if slowest < bound || slowest > bound+500*time.Millisecond {
		t.Fatalf("the stalled Send took %s, want the bound (%s) and little more", slowest, bound)
	}
	eventually(t, "the stalled stream dialled again and ready", func() bool { return d.count(2) == 2 && c.Stats().Ready == 2 })
	st := c.Stats()
	if st.WriteStalls != 1 || st.DeadWrites != 0 || d.count(1) != 1 || len(errs) != 1 {
		t.Fatalf("write stalls %d (want 1), dead writes %d (want 0), dials of the healthy stream %d (want 1)", st.WriteStalls, st.DeadWrites, d.count(1))
	}
	// The stream's NEXT session is judged like its first: what said «this
	// socket is being closed	 of the old one says nothing of the new.
	d.gate(2).stuck.Store(true)
	sendFlowsUntil(t, c, 3*time.Second, func() bool { return c.Stats().WriteStalls > 1 })
	eventually(t, "the stream replaced a second time", func() bool { return d.count(2) == 3 })
	// The bound came off behind every write: the socket carries no deadline now.
	if g := d.gate(0); g.deadline.Load() != 0 || g.sets.Load() < 2 {
		t.Fatalf("the healthy stream's socket: deadline %d, set %d time(s) — want it set before each write and cleared behind it", g.deadline.Load(), g.sets.Load())
	}
}

// 🚨 A write that finds the connection gone ends its stream at once — whoever
// wrote. Before, the caller of Send got the error and the stream stayed
// ready: every packet handed to it failed until its own keepalive noticed,
// ten seconds later.
func TestAWriteThatFindsTheConnectionGoneEndsItsStream(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-gone")
	c, d := startGated(t, srv, 2, time.Second)
	gone := error(&net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EPIPE)})
	d.gate(1).fail.Store(&gone)

	errs, _ := sendFlowsUntil(t, c, 3*time.Second, func() bool { return c.Stats().DeadWrites > 0 })
	if len(errs) != 1 || !errors.Is(errs[0], syscall.EPIPE) {
		t.Fatalf("the sends' errors: %v — want exactly one, the socket's own", errs)
	}
	eventually(t, "the stream dialled again and ready", func() bool { return d.count(2) == 2 && c.Stats().Ready == 2 })
	if st := c.Stats(); st.DeadWrites != 1 || st.WriteStalls != 0 || d.count(1) != 1 {
		t.Fatalf("dead writes %d (want 1), write stalls %d (want 0), dials of the healthy stream %d (want 1)", st.DeadWrites, st.WriteStalls, d.count(1))
	}
}

// A moment's refusal is the caller's error and nothing more: the stream stays.
func TestAMomentsRefusalEndsNothing(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-refusal")
	c, d := startGated(t, srv, 2, time.Second)
	busy := error(&net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.ENOBUFS)})
	d.gate(1).fail.Store(&busy)
	refused := 0
	for flow := 1; flow <= 40; flow++ {
		if err := c.Send(seqPkt(uint16(3000+flow), flow, 100)); err != nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("forty flows and none picked the refusing stream")
	}
	d.gate(1).fail.Store(nil)
	time.Sleep(200 * time.Millisecond)
	if st := c.Stats(); st.Ready != 2 || st.DeadWrites != 0 || st.WriteStalls != 0 || d.count(2) != 1 {
		t.Fatalf("after %d refused writes: ready %d, dead writes %d, stalls %d, dials of that stream %d — want 2, 0, 0, 1", refused, st.Ready, st.DeadWrites, st.WriteStalls, d.count(2))
	}
}

// The verdict itself, error by error — and the stream is not ready from the
// very moment of it: the next packet must not be handed to it.
func TestTheVerdictOnAFailedWrite(t *testing.T) {
	op := func(e error) error { return &net.OpError{Op: "write", Net: "tcp", Err: e} }
	sys := func(e syscall.Errno) error { return op(os.NewSyscallError("write", e)) }
	for _, tc := range []struct {
		name    string
		err     error
		closing bool
		want    error // what the session is told to end with; nil: nothing
	}{
		{"the bound's expiry", op(os.ErrDeadlineExceeded), false, errStalled},
		{"a broken pipe", sys(syscall.EPIPE), false, errConnGone},
		{"a reset", sys(syscall.ECONNRESET), false, errConnGone},
		{"an abort", sys(syscall.ECONNABORTED), false, errConnGone},
		{"not connected", sys(syscall.ENOTCONN), false, errConnGone},
		// 🚫 The kernel's give-up answers Timeout() as the bound's expiry does: it is the connection gone, not a stall.
		{"the kernel's own give-up", sys(syscall.ETIMEDOUT), false, errConnGone},
		{"a closed socket", op(net.ErrClosed), false, errConnGone},
		{"a closed pipe", op(io.ErrClosedPipe), false, errConnGone},
		{"a moment's refusal", sys(syscall.ENOBUFS), false, nil},
		{"try again", sys(syscall.EAGAIN), false, nil},
		{"a route away for now", sys(syscall.EHOSTUNREACH), false, nil},
		{"some other error", errors.New("anything"), false, nil},
		{"the bound's expiry under the session's own close", op(os.ErrDeadlineExceeded), true, nil},
		{"a closed socket under the session's own close", op(net.ErrClosed), true, nil},
	} {
		c := &Client{cfg: ClientConfig{Logf: func(string, ...any) {}}}
		w := &worker{c: c, id: 1, kick: make(chan error, 1)}
		w.ready.Store(true)
		w.closing.Store(tc.closing)
		w.failedWrite(tc.err, time.Second)
		var told error
		select {
		case told = <-w.kick:
		default:
		}
		if told != tc.want {
			t.Errorf("%s: the session is told %v, want %v", tc.name, told, tc.want)
		}
		if ready := w.ready.Load(); ready != (tc.want == nil) {
			t.Errorf("%s: the stream is ready=%v right behind the verdict", tc.name, ready)
		}
		stalls, dead := c.writeStalls.Load(), c.deadWrites.Load()
		if (stalls == 1) != (tc.want == errStalled) || (dead == 1) != (tc.want == errConnGone) || stalls+dead > 1 {
			t.Errorf("%s: counted %d stall(s) and %d dead write(s)", tc.name, stalls, dead)
		}
	}
}

// The session's own close ends a parked write — and that is the close, not a
// stall and not a connection found gone.
func TestAWriteEndedByTheStopIsNotCounted(t *testing.T) {
	quickClocks(t)
	srv := newFakeServer(t, "pw-own-close")
	c, d := startGated(t, srv, 2, 30*time.Second) // a bound the stop comes long before
	for i := 0; i < 2; i++ {
		d.gate(i).stuck.Store(true)
	}
	for i := 0; i < 2; i++ { // a writer parked in each stream
		go func(i int) { _ = c.Send(seqPkt(uint16(100+i), i, 100)) }(i)
	}
	eventually(t, "a write parked in each stream", func() bool { return d.gate(0).parked.Load() > 0 && d.gate(1).parked.Load() > 0 })
	within(t, 4*time.Second, "Close with a write parked in every stream", c.Close)
	if st := c.Stats(); st.WriteStalls != 0 || st.DeadWrites != 0 {
		t.Fatalf("the stop ended two parked writes: counted %d stall(s) and %d dead write(s), want none — it was the close", st.WriteStalls, st.DeadWrites)
	}
}

// One control write of a stream is in flight at a time: an ask that finds the
// one before it still in its write is not queued behind it — behind a relay
// that takes nothing, one goroutine waits, not one per tick.
func TestOneControlWriteIsInFlightAtATime(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &gateConn{PacketConn: udp, released: make(chan struct{})}
	g.stuck.Store(true)
	wrap, _ := WrapKey("pw-one-write")
	cipher, err := NewCipher(WrapKeys(wrap).Client)
	if err != nil {
		t.Fatal(err)
	}
	wr, err := NewWrapper(cipher, ModeUnified)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{cfg: ClientConfig{Logf: func(string, ...any) {}}}
	w := &worker{c: c, id: 1, kick: make(chan error, 1), conn: g, peer: udp.LocalAddr(), wrapper: wr}
	c.wg.Add(1) // as the serve loop that calls say is counted
	for i := 0; i < 6; i++ {
		w.say([]byte(ReadyRequest))
		if i == 0 {
			eventually(t, "the first ask parked in the socket", func() bool { return g.parked.Load() == 1 })
		}
	}
	w.closing.Store(true)
	g.Close()
	c.wg.Done()
	within(t, 2*time.Second, "the writers' end", c.wg.Wait)
	if n := g.parked.Load(); n != 1 {
		t.Fatalf("%d writes reached the socket behind the parked one, want none: six asks, one write", n-1)
	}
}

// 🚨 The serve loop never waits in a socket: with one of its own writes — an
// ask — parked in the relay, it still hears a notice and ends its session.
// Written from the loop itself, the ask held the loop, and the stream could
// be told nothing until the write came back.
func TestTheServeLoopDoesNotWaitInAWrite(t *testing.T) {
	quickClocks(t)
	probeAfter, deafAfter = 100*time.Millisecond, 60*time.Second
	srv := newFakeServer(t, "pw-loop")
	c, d := startGated(t, srv, 2, 0) // no bound: a parked write stays parked
	srv.set(func() { srv.mute[2] = true })
	g := d.gate(1)
	g.stuck.Store(true)
	eventually(t, "worker 2's ask parked in its socket", func() bool { return g.parked.Load() > 0 })
	srv.repair(1, 1, 2) // the server asks for worker 2 again
	began := time.Now()
	eventually(t, "worker 2 dialled again on the server's word", func() bool { return d.count(2) == 2 })
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("worker 2 acted on the notice %s later — its loop was waiting in the write", took)
	}
	if st := c.Stats(); st.WriteStalls != 0 || st.DeadWrites != 0 {
		t.Fatalf("the parked ask was ended by the session's own close: counted %d stall(s), %d dead write(s)", st.WriteStalls, st.DeadWrites)
	}
}
