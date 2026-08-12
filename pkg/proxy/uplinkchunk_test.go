package proxy

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newChunkProxy builds the minimum Proxy a writer needs: the queue, the two
// residence histograms writeChunk files into, and the per-conn TX counters.
// K is process-global (uplinkchunk.go), so a test that sets it must restore it
// or it leaks into every test that runs afterwards.
func newChunkProxy(t *testing.T, k int, queueCap, conns int) *Proxy {
	t.Helper()
	prev := uplinkChunkK.Load()
	t.Cleanup(func() { uplinkChunkK.Store(prev) })
	SetUplinkChunkK(k)
	return &Proxy{
		sendCh:      make(chan sendItem, queueCap),
		connTxBytes: make([]atomic.Int64, conns),
		lastTxAt:    make([]atomic.Int64, conns),
	}
}

func queue(p *Proxy, n int) {
	for i := 0; i < n; i++ {
		p.sendCh <- sendItem{buf: []byte{byte(i)}, at: time.Now().UnixNano()}
	}
}

// recorder is a `write` closure that remembers what it was handed.
func recorder(got *[]byte) func([]byte, time.Time) error {
	return func(pkt []byte, _ time.Time) error {
		*got = append(*got, pkt[0])
		return nil
	}
}

// K=1 must be the behaviour this tunnel has always had: one packet per grab,
// whatever else is queued. This is the control arm of every A/B run, so if it
// ever chunks, the experiment has no baseline.
func TestChunkOffTakesExactlyOnePacket(t *testing.T) {
	p := newChunkProxy(t, UplinkChunkOff, 8, 1)
	queue(p, 5)

	var got []byte
	if err := p.writeChunk(<-p.sendCh, 0, recorder(&got)); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("K=1 wrote %d packets, want exactly 1 (got %v)", len(got), got)
	}
	if left := len(p.sendCh); left != 4 {
		t.Fatalf("K=1 left %d packets queued, want 4 — it consumed more than it wrote", left)
	}
}

// The headline behaviour, and the one the sabotage below must be able to break:
// with K=3 and a deep queue, one grab carries three packets to ONE connection,
// in the producer's order. Order is the whole point — the packets are in
// WireGuard nonce sequence and keeping them so on one path is the mechanism.
func TestChunkTakesKPacketsInOrder(t *testing.T) {
	p := newChunkProxy(t, 3, 8, 1)
	queue(p, 5)

	var got []byte
	if err := p.writeChunk(<-p.sendCh, 0, recorder(&got)); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	if string(got) != string([]byte{0, 1, 2}) {
		t.Fatalf("chunk wrote %v, want [0 1 2] — K packets, FIFO", got)
	}
	if left := len(p.sendCh); left != 2 {
		t.Fatalf("%d packets left queued, want 2", left)
	}
}

// A chunk must never WAIT for packets to arrive. This is what separates it from
// the two refuted temporal levers (the server resequencer's hold timer, the
// client pacer's spacing): chunking chooses a PATH, never a MOMENT. If the drain
// ever blocks, it has become a latency mechanism and the whole argument for it
// collapses.
func TestChunkNeverWaitsForPackets(t *testing.T) {
	p := newChunkProxy(t, 8, 8, 1)
	queue(p, 2) // far fewer than K

	done := make(chan int, 1)
	go func() {
		var got []byte
		_ = p.writeChunk(<-p.sendCh, 0, recorder(&got))
		done <- len(got)
	}()

	select {
	case n := <-done:
		if n != 2 {
			t.Fatalf("wrote %d packets, want the 2 that were queued", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writeChunk blocked waiting for a packet — the drain must be non-blocking")
	}
}

// 🚨 THE DESIGN PROPERTY, and the reason the loop writes before it grabs.
//
// While a write is in progress, the packets this chunk has NOT yet taken must
// still be in sendCh, where another connection's writer can steal them. The
// alternative shape — grab K, then write K — would hold K-1 packets inside this
// goroutine, invisible to work-stealing, and a connection that stalls mid-chunk
// would strand them. That is the run-20 pathology (a packet committed to a
// stalled connection cannot be re-routed), and chunking must not deepen it.
func TestStalledWriteLeavesRemainingPacketsStealable(t *testing.T) {
	p := newChunkProxy(t, 8, 16, 1)
	queue(p, 6)

	inWrite := make(chan struct{})
	release := make(chan struct{})
	var wrote int32

	go func() {
		_ = p.writeChunk(<-p.sendCh, 0, func(pkt []byte, _ time.Time) error {
			if atomic.AddInt32(&wrote, 1) == 1 {
				close(inWrite) // first write has begun
				<-release      // ...and stalls here, as a full send buffer would
			}
			return nil
		})
	}()

	<-inWrite
	// The writer is blocked inside its FIRST write. Everything it has not
	// written must still be queued and therefore stealable.
	if left := len(p.sendCh); left != 5 {
		t.Fatalf("while a write is stalled, %d packets are queued; want 5 still stealable. "+
			"A lower number means the chunk pre-grabbed packets and stranded them in this goroutine.", left)
	}
	close(release)
}

// A failing write ends the chunk and surfaces the error, so the caller can tear
// the connection down exactly as it did before chunking existed.
func TestChunkStopsOnWriteError(t *testing.T) {
	p := newChunkProxy(t, 8, 8, 1)
	queue(p, 5)

	boom := errors.New("write failed")
	n := 0
	err := p.writeChunk(<-p.sendCh, 0, func(pkt []byte, _ time.Time) error {
		n++
		if n == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error surfaced", err)
	}
	if n != 2 {
		t.Fatalf("wrote %d packets, want 2 (stop at the failure)", n)
	}
}

// txConnIdx = -1 means "this site never accounted, do not start now". It is what
// keeps K=1 byte-for-byte identical at the DTLS / direct / WRAP-A sites.
func TestTxAccountingOnlyWhenTheSiteAsksForIt(t *testing.T) {
	withIdx := newChunkProxy(t, 4, 8, 2)
	queue(withIdx, 4)
	var got []byte
	_ = withIdx.writeChunk(<-withIdx.sendCh, 1, recorder(&got))
	if n := withIdx.connTxBytes[1].Load(); n != 4 {
		t.Fatalf("connTxBytes[1] = %d, want 4 (one byte per packet, all four counted)", n)
	}
	if withIdx.lastTxAt[1].Load() == 0 {
		t.Fatal("lastTxAt was not stamped for an accounting site")
	}

	noIdx := newChunkProxy(t, 4, 8, 2)
	queue(noIdx, 4)
	got = nil
	_ = noIdx.writeChunk(<-noIdx.sendCh, -1, recorder(&got))
	for i := range noIdx.connTxBytes {
		if n := noIdx.connTxBytes[i].Load(); n != 0 {
			t.Fatalf("connTxBytes[%d] = %d with txConnIdx=-1; want 0 — "+
				"writeChunk must not add accounting a call site never had", i, n)
		}
	}
}

// K=1 is the permanent default now that the experiment is closed, so the field
// must stay OUT of the log entirely: every chunk is trivially 1, and printing
// ` chunk=1.00/1 over=N` on every tick forever is noise, not a measurement. A
// deliberately raised K still reports.
func TestChunkStatsStaySilentWhenChunkingIsOff(t *testing.T) {
	off := newChunkProxy(t, UplinkChunkOff, 8, 1)
	queue(off, 5)
	var got []byte
	for i := 0; i < 3; i++ {
		_ = off.writeChunk(<-off.sendCh, 0, recorder(&got))
	}
	if s := off.chunkStats.summary(); s != "" {
		t.Fatalf("at K=1 the summary is %q, want \"\" — the default configuration must "+
			"not print a chunk field on every tick", s)
	}

	on := newChunkProxy(t, 4, 8, 1)
	queue(on, 5)
	got = nil
	_ = on.writeChunk(<-on.sendCh, 0, recorder(&got))
	if s := on.chunkStats.summary(); s == "" {
		t.Fatal("at K=4 the summary is empty — suppressing K=1 must not suppress a " +
			"deliberately raised K, or the knob becomes unmeasurable")
	}
}

// The instrument that decides whether a run tested anything at all.
func TestChunkStatsReportMeanMaxAndDenominator(t *testing.T) {
	var c chunkStats
	if s := c.summary(); s != "" {
		t.Fatalf("idle summary = %q, want \"\" — an idle tunnel must not print a row of zeroes", s)
	}
	c.observe(1)
	c.observe(3)
	c.observe(8)
	want := " chunk=4.00/8 over=3"
	if got := c.summary(); got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	// Read-and-reset: the next interval starts empty.
	if s := c.summary(); s != "" {
		t.Fatalf("summary did not reset the interval: %q", s)
	}
}

// A configured K that never materialises means the run measured nothing — the
// same trap as the pacer's "0 writes delayed". The stats must make that visible
// rather than let a shallow queue pass for a tested K.
func TestChunkStatsExposeAKThatNeverEngaged(t *testing.T) {
	p := newChunkProxy(t, 16, 8, 1)
	queue(p, 1) // K=16 configured, but only one packet ever available

	var got []byte
	_ = p.writeChunk(<-p.sendCh, 0, recorder(&got))
	if s := p.chunkStats.summary(); !strings.Contains(s, "chunk=1.00/1") {
		t.Fatalf("summary = %q, want it to show chunks of 1 so a null is readable as "+
			"'the knob never engaged' rather than 'chunking does not help'", s)
	}
}

// 🚨 THE LIVE PATH, and the reason K is a process global rather than a field
// read once at connect. A sweep applied through reconnects puts a ~107 s
// 30-connection ramp between every pair of arms, on a line that has moved
// 75 → 363 Mbit/s inside 70 minutes — the arms would then differ by drift as
// much as by K. This test asserts the property that makes the clean pairing
// possible: a K set between two writes is honoured by the SECOND one, with no
// reconnect and no new Proxy.
func TestKTakesEffectWithoutAReconnect(t *testing.T) {
	p := newChunkProxy(t, UplinkChunkOff, 32, 1)
	queue(p, 12)

	// Arm A: K=1, one packet per grab.
	var a []byte
	if err := p.writeChunk(<-p.sendCh, 0, recorder(&a)); err != nil {
		t.Fatalf("arm A: %v", err)
	}
	if len(a) != 1 {
		t.Fatalf("arm A wrote %d packets, want 1", len(a))
	}

	// The live switch — the same call the bridge's wgSetUplinkChunkK makes.
	SetUplinkChunkK(4)

	// Arm B: the very next chunk must already carry 4, on the SAME Proxy.
	var b []byte
	if err := p.writeChunk(<-p.sendCh, 0, recorder(&b)); err != nil {
		t.Fatalf("arm B: %v", err)
	}
	if len(b) != 4 {
		t.Fatalf("after SetUplinkChunkK(4) the next chunk carried %d packets, want 4 — "+
			"K is not being re-read on the hot path, so a sweep would need a reconnect "+
			"per arm and every comparison would straddle a 107 s ramp", len(b))
	}

	// And back down again, so the switch is not one-way.
	SetUplinkChunkK(UplinkChunkOff)
	var c []byte
	if err := p.writeChunk(<-p.sendCh, 0, recorder(&c)); err != nil {
		t.Fatalf("arm C: %v", err)
	}
	if len(c) != 1 {
		t.Fatalf("after returning K to 1 the next chunk carried %d packets, want 1", len(c))
	}
}

// The setter clamps, so a value that reached it from an imported backup or a
// malformed provider message cannot put an out-of-range K on the hot path.
func TestSetUplinkChunkKClampsWhatItStores(t *testing.T) {
	prev := uplinkChunkK.Load()
	t.Cleanup(func() { uplinkChunkK.Store(prev) })

	SetUplinkChunkK(0) // never configured
	if got := uplinkChunkK.Load(); got != int64(UplinkChunkOff) {
		t.Fatalf("SetUplinkChunkK(0) stored %d, want %d (unset must mean off)", got, UplinkChunkOff)
	}
	SetUplinkChunkK(1 << 20)
	if got := uplinkChunkK.Load(); got != int64(UplinkChunkMax) {
		t.Fatalf("SetUplinkChunkK(huge) stored %d, want %d", got, UplinkChunkMax)
	}
	SetUplinkChunkK(-7)
	if got := uplinkChunkK.Load(); got != int64(UplinkChunkOff) {
		t.Fatalf("SetUplinkChunkK(-7) stored %d, want %d", got, UplinkChunkOff)
	}
}

func TestClampUplinkChunkK(t *testing.T) {
	cases := map[int]int{
		0:                  UplinkChunkOff, // unset config
		-5:                 UplinkChunkOff,
		1:                  1,
		16:                 16,
		UplinkChunkMax:     UplinkChunkMax,
		UplinkChunkMax + 1: UplinkChunkMax,
		1 << 20:            UplinkChunkMax,
	}
	for in, want := range cases {
		if got := ClampUplinkChunkK(in); got != want {
			t.Errorf("ClampUplinkChunkK(%d) = %d, want %d", in, got, want)
		}
	}
}

// 🚨 SOURCE GUARD — every sendCh consumer must go through writeChunk.
//
// Build 233 shipped a socket sampler wired to one of two dial sites and printed
// nothing; build 234 fixed it. The same shape applies here: a writer left on the
// old one-packet path would silently opt its whole transport out of the
// experiment, and the log would look fine.
//
// The count is call sites MINUS the declaration, because
// `strings.Contains(src, "writeChunk(")` is satisfied by the function's own
// signature — that is exactly how a vacuous guard passed in build 232 with the
// call site deleted.
func TestEverySendChConsumerUsesWriteChunk(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	text := string(src)

	consumers := strings.Count(text, "<-p.sendCh:")
	if consumers != 4 {
		t.Fatalf("found %d `<-p.sendCh:` consumer sites in proxy.go, expected 4 "+
			"(DTLS, direct, WRAP-A, SRTP). If a transport was added, wire it through "+
			"writeChunk and update this guard.", consumers)
	}

	calls := strings.Count(text, "p.writeChunk(")
	if calls != consumers {
		t.Fatalf("%d sendCh consumers but %d p.writeChunk( calls — a writer is still on "+
			"the old one-packet path and is silently excluded from the experiment", consumers, calls)
	}

	// The helper itself must not be counted: it lives in uplinkchunk.go, so a
	// `p.writeChunk(` in proxy.go is always a call. Assert that, so this guard
	// cannot start passing for the wrong reason.
	if strings.Contains(text, "func (p *Proxy) writeChunk(") {
		t.Fatal("writeChunk is declared in proxy.go; this guard counts declarations as calls " +
			"and has become vacuous — move the declaration back to uplinkchunk.go")
	}
}
