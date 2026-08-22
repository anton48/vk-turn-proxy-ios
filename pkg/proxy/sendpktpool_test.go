package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// 🚨 WHY THESE TESTS MEASURE BYTES AND NOT ADDRESSES.
//
// The first version asserted that a buffer came back from the pool by comparing
// backing-array addresses, behind a precondition that Put-then-Get returns the
// same slice. `sync.Pool` promises neither LIFO nor identity: it is cleared on
// every GC and an object may be taken by any P. Under `-race -count=20` all
// three tests — and the precondition itself — failed on CORRECT production code.
//
// 🎯 The precondition existed to prevent a VACUOUS PASS, and it did exactly
// that. The mistake was depending on the property at all: trading a test that
// can pass wrongly for one that can FAIL wrongly is not an improvement, because
// a suite that reddens on correct code is one people learn to re-run until it
// goes green. *(User-caught 2026-08-21, by running `-race -count=20` — which I
// never did.)*
//
// What matters is not identity but REUSE, and reuse is visible in allocated
// bytes. The comparison is against a control measured in the SAME process: the
// race detector inflates the pooled path (~25 B/op becomes ~540) while leaving
// a plain allocation at 1408, so a fixed threshold would be build-mode
// dependent and a ratio to a live control is not.

// allocSink keeps the control allocation from being optimised away.
var allocSink []byte

// bytesPerOp is the steady-state allocation of f, in bytes per call. f runs once
// before the window so a cold pool's New() is not charged to steady state, and
// ReadMemStats stops the world, so TotalAlloc is exact.
func bytesPerOp(n int, f func()) uint64 {
	f()
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	for i := 0; i < n; i++ {
		f()
	}
	runtime.ReadMemStats(&m2)
	return (m2.TotalAlloc - m1.TotalAlloc) / uint64(n)
}

// onePacketAlloc is the control: what ONE packet-sized allocation costs in this
// process, in this build mode. A path that recycles must come in under it; a
// path that has stopped recycling cannot, because every Get then falls through
// to New(make([]byte, 2048)).
func onePacketAlloc(t *testing.T) uint64 {
	t.Helper()
	c := bytesPerOp(2000, func() { allocSink = make([]byte, 1312) })
	if c == 0 {
		t.Fatal("control measured 0 bytes/op — the allocation was optimised away, " +
			"and every comparison against it would pass vacuously")
	}
	return c
}

func assertRecycled(t *testing.T, what string, f func()) {
	t.Helper()
	control := onePacketAlloc(t)
	got := bytesPerOp(2000, f)
	if got >= control {
		t.Errorf("%s: %d bytes/op against a control of %d — the buffer is NOT returning "+
			"to the pool, so every Get falls through to New(make([]byte, 2048)) and this "+
			"path now allocates MORE than it did before pooling", what, got, control)
	}
	t.Logf("%s: %d bytes/op (one-packet control: %d)", what, got, control)
}

// TestTheBufferIsRecycledOnSuccess is the steady-state half of the ownership
// contract: dequeuing transfers ownership to writePacket, which hands it back.
func TestTheBufferIsRecycledOnSuccess(t *testing.T) {
	p := newWriterProxy(1024, 1)
	data := make([]byte, 1312)
	noop := func([]byte, time.Time) error { return nil }

	assertRecycled(t, "success path", func() {
		if err := p.SendPacket(data); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
		if err := p.writePacket(<-p.sendCh, 0, noop); err != nil {
			t.Fatalf("writePacket: %v", err)
		}
	})
}

// TestTheBufferIsRecycledOnWriteError is the half the original patch's "Put
// after the socket write" would have leaked: the writer that owned the buffer
// is about to exit, and nothing else can return it.
//
// SABOTAGE SEEN TO FAIL: move the `defer sendPktPoolPut(item.buf)` in
// writepacket.go below the `if err != nil { return err }`. Compiles, the
// success test above still passes, and this one goes red.
func TestTheBufferIsRecycledOnWriteError(t *testing.T) {
	p := newWriterProxy(1024, 1)
	data := make([]byte, 1312)
	boom := errors.New("boom")
	fail := func([]byte, time.Time) error { return boom }

	assertRecycled(t, "write-error path", func() {
		if err := p.SendPacket(data); err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
		if err := p.writePacket(<-p.sendCh, 0, fail); !errors.Is(err, boom) {
			t.Fatalf("writePacket err = %v, want boom", err)
		}
	})
}

// TestTheBufferIsRecycledWhenItNeverEnqueues covers the one exit where
// SendPacket still owns the buffer: the send lost to ctx.Done, so it never
// reached the channel and no writePacket will ever see it.
//
// SABOTAGE SEEN TO FAIL: delete the sendPktPoolPut on that branch in
// SendPacket. Nothing else can free it, so every iteration allocates anew.
func TestTheBufferIsRecycledWhenItNeverEnqueues(t *testing.T) {
	p := newWriterProxy(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	cancel()
	// Fill the channel so the non-blocking fast path cannot take the item and
	// the slow select is forced onto ctx.Done every time.
	p.sendCh <- sendItem{buf: []byte{0}, at: time.Now().UnixNano()}
	data := make([]byte, 1312)

	assertRecycled(t, "never-enqueued path", func() {
		if err := p.SendPacket(data); !errors.Is(err, context.Canceled) {
			t.Fatalf("SendPacket err = %v, want context.Canceled", err)
		}
	})
}

// TestExactlyTwoPutSitesExist is the guard the ownership contract needs, and it
// is static because the failure it prevents cannot be reached from a test.
//
// 🚨 A third Put is not a leak — it is a DOUBLE FREE of a live buffer. The
// tempting edit is "the write-error branch leaks, add a Put there": it does not
// leak (the defer covers it), and adding one hands ONE backing array to two of
// ~30 writer goroutines, which then copy different WireGuard records into it
// concurrently. On the wire that is corrupt uplink dropped by server1 as an
// auth failure — indistinguishable from the per-allocation loss already under
// investigation, and it would be blamed on the relay. `-race` cannot see it,
// because no test drives two writers over a real pool.
//
// SABOTAGE SEEN TO FAIL: add `sendPktPoolPut(item.buf)` to any writer loop in
// proxy.go, or delete the defer in writepacket.go.
func TestExactlyTwoPutSitesExist(t *testing.T) {
	// Strip `//` comments: this scan matches names that the ownership prose is
	// full of, and a source scan reddening on its own documentation has already
	// happened four times in this project.
	codeOf := func(path string) string {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s — a scan over a missing file passes vacuously: %v", path, err)
		}
		var code strings.Builder
		for _, line := range strings.Split(string(src), "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			code.WriteString(line)
			code.WriteString("\n")
		}
		return code.String()
	}
	countIn := func(path, needle string) int { return strings.Count(codeOf(path), needle) }

	if n := countIn("proxy.go", "sendPktPoolPut("); n != 2 {
		t.Errorf("proxy.go has %d sendPktPoolPut( occurrences, want 2 (the helper's own "+
			"declaration and SendPacket's never-enqueued exit) — a Put in a writer loop "+
			"is a double free of a LIVE buffer, not a leak fix", n)
	}
	if n := countIn("writepacket.go", "sendPktPoolPut("); n != 1 {
		t.Errorf("writepacket.go has %d sendPktPoolPut( occurrences, want exactly 1 "+
			"(the defer that gives writePacket ownership)", n)
	}
	if n := countIn("proxy.go", "sendPktPoolGet("); n != 2 {
		t.Errorf("proxy.go has %d sendPktPoolGet( occurrences, want 2 (the helper and "+
			"SendPacket) — every Get needs exactly one owner that Puts", n)
	}
	if countIn("writepacket.go", "sendPktPoolGet(") != 0 {
		t.Error("writepacket.go takes from the pool — it must only ever RETURN")
	}

	// 🚨 THE RELEASE MUST BE A `defer`, AND THIS IS THE CORRUPTION DIRECTION.
	// Counting the site says nothing about WHEN it runs: `sendPktPoolPut(item.buf)`
	// immediately before `write(item.buf, now)` keeps the count at one, recycles
	// the buffer exactly once, and passes every byte-based test above — while
	// handing the array to another Get whose writer memcpys into it WHILE a
	// transport is still reading it. A deferred call cannot run before the write,
	// so asserting the form is what rules the whole direction out.
	// *(Review-caught: no test in this file covered it.)*
	if !strings.Contains(codeOf("writepacket.go"), "defer sendPktPoolPut(item.buf)") {
		t.Error("writepacket.go's release is not `defer sendPktPoolPut(item.buf)` — a Put " +
			"that is not deferred can run BEFORE the transport has finished reading the " +
			"buffer, which is the one ordering that corrupts rather than leaks")
	}

	// 🚨 …AND THE CLAIM IS ABOUT THE WHOLE PACKAGE, so the scan must be too. The
	// pool's own comment says "exactly two Put sites in the tree"; counting only
	// two files would miss `sendPktPoolPut` added to uplinkpace.go or synth.go,
	// and misses `sendPktPool.Put(` — bypassing the helper — anywhere at all.
	// *(Review-caught: the check was narrower than the invariant it advertised.)*
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) < 10 {
		t.Fatalf("globbing pkg/proxy/*.go found %d files (err %v) — the sweep below "+
			"would pass vacuously", len(files), err)
	}
	swept := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		swept++
		code := codeOf(f)
		if n := strings.Count(code, "sendPktPool.Put("); n != expectedDirectPuts(f) {
			t.Errorf("%s has %d sendPktPool.Put( occurrences, want %d — the pool is "+
				"returned to through sendPktPoolPut, never directly", f, n, expectedDirectPuts(f))
		}
		if f == "proxy.go" || f == "writepacket.go" {
			continue
		}
		if n := strings.Count(code, "sendPktPoolPut("); n != 0 {
			t.Errorf("%s has %d sendPktPoolPut( occurrences — ownership lives in "+
				"SendPacket and writePacket ONLY, and a third site is a double free", f, n)
		}
	}
	if swept < 10 {
		t.Fatalf("swept only %d production files — the sweep is not finding the package", swept)
	}
}

// expectedDirectPuts: the helper's own body is the single legitimate
// sendPktPool.Put( in the package.
func expectedDirectPuts(file string) int {
	if file == "proxy.go" {
		return 1
	}
	return 0
}

// BenchmarkSendPacketThroughWritePacket prices the hand-off the pool exists for:
// SendPacket → sendCh → writePacket, with the buffer coming back. Run with
// -benchmem; against `make([]byte, len(data))` this is 1408 B/op → 24 B/op.
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
