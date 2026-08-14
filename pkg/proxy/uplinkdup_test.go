package proxy

import (
	"context"
	"testing"
	"time"
)

// armDup sets the mode for one test and restores the shipped value afterwards.
// The mode is process-global (uplinkChunkK's idiom, for the same reason), so
// without this one test's arm leaks into the next — which is exactly how the
// chunking tests were fixed in build 239.
func armDup(t *testing.T, mode int) {
	t.Helper()
	SetUplinkDupMode(mode)
	t.Cleanup(func() { SetUplinkDupMode(UplinkDupOff) })
}

func newDupProxy(t *testing.T, depth int) (*Proxy, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		ctx:     ctx,
		sendCh:  make(chan sendItem, depth),
		groupCh: [2]chan sendItem{make(chan sendItem, depth), make(chan sendItem, depth)},
	}
	t.Cleanup(cancel)
	return p, cancel
}

// wgData builds a WireGuard transport message of the given TOTAL length: type 4,
// 3 reserved, 4-byte receiver index, 8-byte counter, then ciphertext+tag.
func wgData(n int) []byte {
	b := make([]byte, n)
	b[0] = 4
	return b
}

// TestKeepalivesAndHandshakesNeverEnterAGroup is the guard on the property that
// keeps an arm from damaging the arm AFTER it: if control traffic followed bulk
// into one group, the connections excluded from that group would carry nothing
// for a whole arm and could be reaped as idle.
func TestKeepalivesAndHandshakesNeverEnterAGroup(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		bulk bool
	}{
		// A transport message with an empty payload is exactly 16 + 0 + 16 = 32
		// bytes. One byte more is a payload of one byte, i.e. real data.
		{"keepalive (32B, type 4)", wgData(32), false},
		{"smallest real data (33B)", wgData(33), true},
		{"typical data (1420B)", wgData(1420), true},
		{"handshake initiation (type 1)", func() []byte { b := make([]byte, 148); b[0] = 1; return b }(), false},
		{"handshake response (type 2)", func() []byte { b := make([]byte, 92); b[0] = 2; return b }(), false},
		{"cookie reply (type 3)", func() []byte { b := make([]byte, 64); b[0] = 3; return b }(), false},
		{"empty", []byte{}, false},
	}
	for _, c := range cases {
		if got := isUplinkBulk(c.pkt); got != c.bulk {
			t.Errorf("%s: isUplinkBulk = %v, want %v", c.name, got, c.bulk)
		}
	}
}

// TestOffModeNeverTouchesAGroupChannel is the control arm's guarantee: with the
// experiment off, the packet path is what it has always been. A control that is
// not byte-for-byte the shipped behaviour is not a control.
func TestOffModeNeverTouchesAGroupChannel(t *testing.T) {
	armDup(t, UplinkDupOff)
	p, _ := newDupProxy(t, 4)
	if err := p.SendPacket(wgData(1420)); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	if len(p.sendCh) != 1 {
		t.Fatalf("shared channel got %d packets, want 1", len(p.sendCh))
	}
	if len(p.groupCh[0])+len(p.groupCh[1]) != 0 {
		t.Fatalf("group channels got %d/%d packets, want none",
			len(p.groupCh[0]), len(p.groupCh[1]))
	}
	if n := p.txPackets.Load(); n != 1 {
		t.Fatalf("txPackets = %d, want 1", n)
	}
}

func TestSingleGroupSendsBulkToGroupZeroAndControlToShared(t *testing.T) {
	armDup(t, UplinkDupSingleGroup)
	p, _ := newDupProxy(t, 4)
	if err := p.SendPacket(wgData(1420)); err != nil { // bulk
		t.Fatalf("SendPacket(bulk): %v", err)
	}
	if err := p.SendPacket(wgData(32)); err != nil { // keepalive
		t.Fatalf("SendPacket(keepalive): %v", err)
	}
	if len(p.groupCh[0]) != 1 {
		t.Fatalf("group 0 got %d, want 1 (the bulk packet)", len(p.groupCh[0]))
	}
	if len(p.groupCh[1]) != 0 {
		t.Fatalf("group 1 got %d, want 0 — single-group mode must not duplicate", len(p.groupCh[1]))
	}
	if len(p.sendCh) != 1 {
		t.Fatalf("shared got %d, want 1 (the keepalive)", len(p.sendCh))
	}
	if n := p.dupStats.copies.Load(); n != 0 {
		t.Fatalf("copies = %d, want 0 in single-group mode", n)
	}
}

// TestDupSendsTwoINDEPENDENTCopies covers both halves of the treatment: two
// copies exist, and they do not share a backing array. A shared slice would be
// silent until a transport that frames or obfuscates IN PLACE (WRAP-A XORs) met
// it, and would then surface as a decrypt failure minutes later.
func TestDupSendsTwoIndependentCopies(t *testing.T) {
	armDup(t, UplinkDupBoth)
	p, _ := newDupProxy(t, 4)
	pkt := wgData(1420)
	pkt[100] = 0xAA
	if err := p.SendPacket(pkt); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	a := <-p.groupCh[0]
	b := <-p.groupCh[1]
	if a.buf[100] != 0xAA || b.buf[100] != 0xAA {
		t.Fatalf("copies do not carry the payload: %#x / %#x", a.buf[100], b.buf[100])
	}
	// 🚨 THE ALIAS THAT MATTERS IS THE CALLER'S, and an earlier version of this
	// test missed it: it mutated copy A and checked copy B, which passes even
	// when B aliases `data`, because A is always a fresh make+copy. wireguard-go
	// REUSES the buffer it hands to SendPacket, so an aliasing second copy would
	// be overwritten in flight — or, on a transport that frames in place
	// (WRAP-A XORs), corrupted after the fact.
	pkt[100] = 0xCC
	if a.buf[100] != 0xAA {
		t.Fatal("copy A aliases the CALLER's buffer — wireguard-go reuses it")
	}
	if b.buf[100] != 0xAA {
		t.Fatal("copy B aliases the CALLER's buffer — wireguard-go reuses it, so the " +
			"duplicate would carry whatever the next packet put there")
	}
	a.buf[100] = 0xBB
	if b.buf[100] != 0xAA {
		t.Fatal("the two copies SHARE a backing array — an in-place transport would corrupt both")
	}
	if n := p.dupStats.copies.Load(); n != 1 {
		t.Fatalf("copies = %d, want 1", n)
	}
	// The offered-traffic counters must count the packet ONCE. If the duplicate
	// were counted too, tx-pkt and tun-mbit would stop meaning "what WireGuard
	// handed us" and every historical number on that line would become
	// incomparable — including the wire/useful ratio this experiment turns on.
	if n := p.txPackets.Load(); n != 1 {
		t.Fatalf("txPackets = %d, want 1 — the duplicate is WIRE, not offered traffic", n)
	}
}

// TestTheSecondCopyIsDroppedRatherThanBlocking: a stalled half of the pool must
// not be able to throttle the whole uplink. The first copy still goes.
func TestTheSecondCopyIsDroppedRatherThanBlocking(t *testing.T) {
	armDup(t, UplinkDupBoth)
	p, _ := newDupProxy(t, 1)
	p.groupCh[1] <- sendItem{buf: []byte{1}} // group 1 is now full

	done := make(chan error, 1)
	go func() { done <- p.SendPacket(wgData(1420)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendPacket BLOCKED on the second copy — a full group must drop it, not stall the uplink")
	}
	if len(p.groupCh[0]) != 1 {
		t.Fatalf("group 0 got %d, want 1 — the first copy is never best-effort", len(p.groupCh[0]))
	}
	if n := p.dupStats.dropped.Load(); n != 1 {
		t.Fatalf("dropped = %d, want 1 — a silent drop is how an arm gets scored as another", n)
	}
}

// TestGroupsAreByParitySoAPartialPoolFeedsBoth is the ramp guard. With a
// low-half split, a pool that is only partly connected would put every live
// writer in group 0 and leave group 1 with no consumer, so the producer's second
// copy would have nobody to take it. Parity covers both groups for EVERY prefix.
func TestGroupsAreByParitySoAPartialPoolFeedsBoth(t *testing.T) {
	for live := 2; live <= 30; live++ {
		seen := [2]bool{}
		for i := 0; i < live; i++ {
			g := uplinkDupGroup(i)
			if g < 0 || g > 1 {
				t.Fatalf("conn %d mapped to group %d", i, g)
			}
			seen[g] = true
		}
		if !seen[0] || !seen[1] {
			t.Fatalf("with %d connections live, groups covered = %v — a partial pool must feed both", live, seen)
		}
	}
	if uplinkDupGroup(-1) != -1 {
		t.Fatal("a site with no connection identity must have no group")
	}
}

// TestAWriterParkedBEFOREAFlipStillServesItsGroup is the regression that carries
// the whole design.
//
// 🚨 The closed flow-paths lever shipped a writer that read its mode ONCE above
// a blocking select (build 254). After a flip, every parked writer still held
// the channel set it had parked under, so a queued packet was reachable only
// when some other packet on the SHARED channel happened to wake that exact
// writer — in practice a keepalive. It cost a day of wrong hypotheses and a
// 5-second connect stall. Here a writer's channel set is a function of connIdx
// alone, so this must hold with the writer parked before the mode ever changes.
func TestAWriterParkedBeforeAFlipStillServesItsGroup(t *testing.T) {
	armDup(t, UplinkDupOff)
	p, _ := newDupProxy(t, 4)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	got := make(chan sendItem, 1)
	go func() {
		// Parks under `off`, i.e. before the treatment exists.
		if item, ok := p.nextUplinkItem(done, 0); ok {
			got <- item
		}
	}()
	time.Sleep(100 * time.Millisecond) // let it block

	SetUplinkDupMode(UplinkDupBoth)
	if err := p.SendPacket(wgData(1420)); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a writer parked before the flip never saw its group queue — the build-254 defect is back")
	}
}

func TestNextUplinkItemTakesFromTheSharedChannelToo(t *testing.T) {
	armDup(t, UplinkDupBoth)
	p, _ := newDupProxy(t, 4)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	p.sendCh <- sendItem{buf: wgData(32)}
	item, ok := p.nextUplinkItem(done, 1)
	if !ok || len(item.buf) != 32 {
		t.Fatal("a writer must keep serving the shared channel in every mode — that is where keepalives are")
	}
}

func TestClampAndNamesFailClosed(t *testing.T) {
	for _, v := range []int{-1, 3, 99} {
		if got := ClampUplinkDupMode(v); got != UplinkDupOff {
			t.Fatalf("ClampUplinkDupMode(%d) = %d, want off — an experiment must fail CLOSED", v, got)
		}
	}
	// 🚨 These three spellings are a CONTRACT with UplinkDup.logName in Swift
	// and with the scorer that cuts arms out of the log. Build 257 renamed a
	// field on one side only and its own parser reported "a blind run" for a
	// session carrying 154 engaged ticks.
	want := map[int]string{UplinkDupOff: "off", UplinkDupSingleGroup: "g15", UplinkDupBoth: "dup"}
	for mode, name := range want {
		if got := UplinkDupModeName(mode); got != name {
			t.Fatalf("UplinkDupModeName(%d) = %q, want %q", mode, got, name)
		}
	}
}

// TestChunkingIsForcedOffWhileAnArmIsArmed: writeChunk's drain takes further
// packets from the SHARED channel, so a chunk started from a group queue would
// pull unrelated control traffic onto its connection and mix two experiments.
func TestChunkingIsForcedOffWhileAnArmIsArmed(t *testing.T) {
	SetUplinkChunkK(8)
	t.Cleanup(func() { SetUplinkChunkK(UplinkChunkOff) })
	armDup(t, UplinkDupBoth)

	p, _ := newDupProxy(t, 8)
	// Queue more than one packet on the shared channel: with K=8 honoured, the
	// first write would drain them into one chunk.
	for i := 0; i < 4; i++ {
		p.sendCh <- sendItem{buf: wgData(100), at: time.Now().UnixNano()}
	}
	first := <-p.sendCh
	written := 0
	if err := p.writeChunk(first, -1, func(pkt []byte, now time.Time) error {
		written++
		return nil
	}); err != nil {
		t.Fatalf("writeChunk: %v", err)
	}
	if written != 1 {
		t.Fatalf("writeChunk carried %d packets while an arm was armed, want 1 — chunking must be forced off", written)
	}
}
