package proxy

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These carry over from the chunking suite that was deleted with the lever. The
// properties they guard are older than chunking and outlive it: one packet per
// grab, the queue stays stealable while a write blocks, errors surface, and a
// call site that never accounted for TX bytes does not start.

func newWriterProxy(queueCap, conns int) *Proxy {
	return &Proxy{
		sendCh:      make(chan sendItem, queueCap),
		connTxBytes: make([]atomic.Int64, conns),
		lastTxAt:    make([]atomic.Int64, conns),
	}
}

func queuePackets(p *Proxy, n int) {
	for i := 0; i < n; i++ {
		p.sendCh <- sendItem{buf: []byte{byte(i)}, at: time.Now().UnixNano()}
	}
}

// ONE packet per grab, whatever else is queued. With the pacer live this is no
// longer only about reordering: every packet a writer sends must correspond to
// exactly one reservation, and a helper that drained a second packet would send
// it unmetered.
//
// SABOTAGE SEEN TO FAIL: restore the chunk drain (a `select` on p.sendCh that
// loops while packets are queued). Compiles; this test then sees 4 writes.
func TestWritePacketTakesExactlyOnePacket(t *testing.T) {
	p := newWriterProxy(8, 1)
	queuePackets(p, 4)

	var got []byte
	err := p.writePacket(<-p.sendCh, 0, func(pkt []byte, _ time.Time) error {
		got = append(got, pkt[0])
		return nil
	})
	if err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("wrote %v, want exactly the one packet handed in", got)
	}
	if left := len(p.sendCh); left != 3 {
		t.Fatalf("%d packets left queued, want 3 — the helper consumed more than it was given", left)
	}
}

// A writer blocked inside its write must not be holding anything else: packets
// it has not written have to stay on the shared queue where the other writers
// can steal them. This is the run-20 pathology, and the uplink pacer's
// reserve-before-dequeue rests on the same argument.
func TestAStalledWriteLeavesTheQueueStealable(t *testing.T) {
	p := newWriterProxy(16, 1)
	queuePackets(p, 6)

	inWrite := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_ = p.writePacket(<-p.sendCh, 0, func(pkt []byte, _ time.Time) error {
			close(inWrite)
			<-release
			return nil
		})
	}()

	<-inWrite
	if left := len(p.sendCh); left != 5 {
		t.Fatalf("while a write is stalled, %d packets are queued; want 5 still stealable", left)
	}
	close(release)
}

func TestWritePacketSurfacesTheWriteError(t *testing.T) {
	p := newWriterProxy(8, 1)
	queuePackets(p, 2)

	boom := errors.New("write failed")
	err := p.writePacket(<-p.sendCh, 0, func(pkt []byte, _ time.Time) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error surfaced so the caller tears the conn down", err)
	}
	if n := p.connTxBytes[0].Load(); n != 0 {
		t.Fatalf("a failed write counted %d TX bytes; nothing left the socket", n)
	}
}

// txConnIdx = -1 means "this site never accounted, do not start now".
func TestTxAccountingOnlyWhenTheSiteAsksForIt(t *testing.T) {
	withIdx := newWriterProxy(8, 2)
	queuePackets(withIdx, 1)
	_ = withIdx.writePacket(<-withIdx.sendCh, 1, func([]byte, time.Time) error { return nil })
	if n := withIdx.connTxBytes[1].Load(); n != 1 {
		t.Fatalf("connTxBytes[1] = %d, want 1", n)
	}
	if withIdx.lastTxAt[1].Load() == 0 {
		t.Fatal("lastTxAt was not stamped for an accounting site")
	}

	noIdx := newWriterProxy(8, 2)
	queuePackets(noIdx, 1)
	_ = noIdx.writePacket(<-noIdx.sendCh, -1, func([]byte, time.Time) error { return nil })
	for i := range noIdx.connTxBytes {
		if n := noIdx.connTxBytes[i].Load(); n != 0 {
			t.Fatalf("connTxBytes[%d] = %d with txConnIdx=-1; want 0", i, n)
		}
	}
}

// Every sendCh consumer goes through the one helper, or its transport is both
// unmetered by the pacer and invisible to the residence histograms.
//
// SABOTAGE SEEN TO FAIL: inline `writeOne(item.buf, time.Now())` at one site.
func TestEverySendChConsumerUsesWritePacket(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	text := string(src)

	consumers := strings.Count(text, "<-p.sendCh:")
	if consumers != 4 {
		t.Fatalf("found %d `<-p.sendCh:` consumer sites in proxy.go, expected 4 "+
			"(DTLS, direct, WRAP-A, SRTP). If a transport was added, wire it through "+
			"writePacket and update this guard.", consumers)
	}
	if calls := strings.Count(text, "p.writePacket("); calls != consumers {
		t.Fatalf("%d sendCh consumers but %d p.writePacket( calls — a writer is on its "+
			"own write path, so its packets are unpaced and unmeasured", consumers, calls)
	}
	if strings.Contains(text, "func (p *Proxy) writePacket(") {
		t.Fatal("writePacket is declared in proxy.go; this guard counts declarations as " +
			"calls and has become vacuous — keep the declaration in writepacket.go")
	}
}

// 🚨 THE CHUNKING MACHINERY MUST STAY GONE, and this is the guard that says so.
// It was removed because packets 2..K of a chunk were written after a SINGLE
// pace reservation — a bucket reporting ENGAGED while up to K−1 of every K
// packets passed it unmetered. Re-adding the drain without re-adding a
// reservation per packet would restore that silently, and the pacer's own
// `waited=` would look healthy throughout.
//
// SABOTAGE SEEN TO FAIL: reintroduce `uplinkChunkK` in this package, or the
// `uplink_chunk_k` field in the bridge's ProxyConfig.
func TestNoChunkingMachineryRemains(t *testing.T) {
	for _, f := range []string{"proxy.go", "writepacket.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		body := stripComments(string(src))
		for _, needle := range []string{"uplinkChunkK", "SetUplinkChunkK", "chunkStats"} {
			if strings.Contains(body, needle) {
				t.Errorf("%s still references %s — chunking cannot coexist with the "+
					"uplink pacer, which reserves once per dequeue", f, needle)
			}
		}
	}

	bridge, err := os.ReadFile("../../WireGuardBridge/bridge.go")
	if err != nil {
		t.Fatalf("read bridge.go: %v", err)
	}
	if strings.Contains(stripComments(string(bridge)), "uplink_chunk_k") {
		t.Error("the bridge still accepts uplink_chunk_k, so a backup could re-arm " +
			"chunking through a config the app no longer writes")
	}
}

// stripComments removes `//` comment text so a scan tests the CODE and not the
// prose about it — this file's own header names every symbol it forbids.
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
