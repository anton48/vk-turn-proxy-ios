package proxy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// same reports whether two slices share a backing array. Comparing *byte is
// ordinary Go — no unsafe needed — and it is the only way to observe that a
// buffer came BACK from the pool rather than being freshly made.
func same(a, b []byte) bool {
	return len(a) > 0 && len(b) > 0 && &a[0] == &b[0]
}

// requirePoolRoundTrip fails if a Put immediately followed by a Get on this
// goroutine does not return the same buffer.
//
// 🚨 Without it every identity assertion below would pass VACUOUSLY the moment
// sync.Pool stopped round-tripping — a fresh buffer and a returned one are
// indistinguishable except by address. The property holds because Put fills the
// current P's private slot and Get checks it first; a GC between the two would
// break it, which is why this is checked rather than assumed.
func requirePoolRoundTrip(t *testing.T) {
	t.Helper()
	a := sendPktPoolGet(2048)
	sendPktPoolPut(a)
	b := sendPktPoolGet(2048)
	if !same(a, b) {
		t.Fatalf("sync.Pool did not round-trip on this runtime — the identity " +
			"assertions in this file cannot discriminate and would pass vacuously")
	}
	sendPktPoolPut(b)
}

// TestWritePacketReturnsTheBufferOnSuccess is the steady-state half of the
// ownership contract: dequeuing transfers ownership to writePacket, which hands
// the buffer back.
func TestWritePacketReturnsTheBufferOnSuccess(t *testing.T) {
	requirePoolRoundTrip(t)
	p := newWriterProxy(8, 1)

	if err := p.SendPacket(make([]byte, 1312)); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	item := <-p.sendCh

	if err := p.writePacket(item, 0, func(pkt []byte, _ time.Time) error {
		if len(pkt) != 1312 {
			t.Errorf("writer saw %d bytes, want 1312", len(pkt))
		}
		return nil
	}); err != nil {
		t.Fatalf("writePacket: %v", err)
	}

	if got := sendPktPoolGet(1312); !same(got, item.buf) {
		t.Fatal("writePacket did not return the buffer to the pool on success")
	}
}

// TestWritePacketReturnsTheBufferOnWriteError is the half the original patch's
// "Put after the socket write" would have missed.
//
// SABOTAGE SEEN TO FAIL: move the `defer sendPktPoolPut(item.buf)` below the
// `if err != nil { return err }` in writepacket.go. Compiles, the success test
// above still passes, and this one goes red.
func TestWritePacketReturnsTheBufferOnWriteError(t *testing.T) {
	requirePoolRoundTrip(t)
	p := newWriterProxy(8, 1)

	if err := p.SendPacket(make([]byte, 1312)); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	item := <-p.sendCh

	boom := errors.New("boom")
	if err := p.writePacket(item, 0, func([]byte, time.Time) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("writePacket err = %v, want boom", err)
	}

	if got := sendPktPoolGet(1312); !same(got, item.buf) {
		t.Fatal("a failed write must still return the buffer — the writer that " +
			"owned it is about to exit and nothing else can")
	}
}

// TestSendPacketReturnsTheBufferWhenItNeverEnqueues covers the one exit where
// SendPacket still owns the buffer: the send lost the race with ctx.Done, so it
// never reached the channel and no writePacket will ever see it.
func TestSendPacketReturnsTheBufferWhenItNeverEnqueues(t *testing.T) {
	requirePoolRoundTrip(t)
	p := newWriterProxy(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx

	// Fill the channel so the fast path cannot take it, then cancel so the slow
	// path selects ctx.Done.
	p.sendCh <- sendItem{buf: []byte{0}, at: time.Now().UnixNano()}
	cancel()

	marker := sendPktPoolGet(1312)
	sendPktPoolPut(marker)

	if err := p.SendPacket(make([]byte, 1312)); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendPacket err = %v, want context.Canceled", err)
	}
	if got := sendPktPoolGet(1312); !same(got, marker) {
		t.Fatal("SendPacket kept the buffer on the exit where it never enqueued")
	}
}

// TestExactlyTwoPutSitesExist is the guard the ownership contract needs.
//
// 🚨 The failure it exists to prevent is not a leak. A third Put — the obvious
// "fix the leak" edit in a writer loop's error branch, or a Put inside a write
// closure — hands ONE backing array to two of ~30 writer goroutines, which then
// copy different WireGuard records into it concurrently. On the wire that is
// corrupt uplink dropped by server1 as an auth failure, indistinguishable from
// the per-allocation loss already under investigation. `-race` does not see it,
// because no test drives two writers over a real pool.
//
// SABOTAGE SEEN TO FAIL: delete the defer in writepacket.go (the writepacket
// check goes red); add `sendPktPoolPut(item.buf)` to any writer loop in
// proxy.go (the count goes red).
func TestExactlyTwoPutSitesExist(t *testing.T) {
	countIn := func(path, needle string) int {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s — a scan over a missing file passes vacuously: %v", path, err)
		}
		// Strip the file's own prose: these names appear all over the ownership
		// comments, and this project has had scans redden on their own
		// documentation three times.
		var code strings.Builder
		for _, line := range strings.Split(string(src), "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			code.WriteString(line)
			code.WriteString("\n")
		}
		return strings.Count(code.String(), needle)
	}

	proxyPuts := countIn("proxy.go", "sendPktPoolPut(")
	writePuts := countIn("writepacket.go", "sendPktPoolPut(")

	// proxy.go holds the pool helper's own definition plus SendPacket's
	// never-enqueued exit; writepacket.go holds the one that matters.
	if proxyPuts != 2 {
		t.Errorf("proxy.go has %d sendPktPoolPut( occurrences, want 2 "+
			"(the func declaration and SendPacket's ctx.Done exit) — a Put in a "+
			"writer loop is a DOUBLE free of a live buffer, not a leak fix", proxyPuts)
	}
	if writePuts != 1 {
		t.Errorf("writepacket.go has %d sendPktPoolPut( occurrences, want exactly 1 "+
			"(the defer that gives writePacket ownership)", writePuts)
	}
	if gets := countIn("proxy.go", "sendPktPoolGet("); gets != 2 {
		t.Errorf("proxy.go has %d sendPktPoolGet( occurrences, want 2 (the func "+
			"declaration and SendPacket) — every Get needs an owner that Puts", gets)
	}
	// And the ownership must sit in writePacket rather than at a call site: the
	// four writer loops must not mention the pool at all.
	if countIn("writepacket.go", "sendPktPoolGet(") != 0 {
		t.Error("writepacket.go takes from the pool — it only ever RETURNS")
	}
}

// BenchmarkSendPacketThroughWritePacket prices the whole hand-off the pool
// exists for: SendPacket → sendCh → writePacket, with the buffer coming back.
//
// Run with -benchmem. Against `make([]byte, len(data))` this should fall from
// one full-size allocation per packet to the pool's fixed overhead; if it does
// not, the pool is not round-tripping and the change is not worth its
// invariant.
func BenchmarkSendPacketThroughWritePacket(b *testing.B) {
	p := newWriterProxy(1024, 1)
	data := make([]byte, 1312)
	noop := func([]byte, time.Time) error { return nil }

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.SendPacket(data); err != nil {
			b.Fatalf("SendPacket: %v", err)
		}
		if err := p.writePacket(<-p.sendCh, 0, noop); err != nil {
			b.Fatalf("writePacket: %v", err)
		}
	}
}
