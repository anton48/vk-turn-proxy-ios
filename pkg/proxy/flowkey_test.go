package proxy

import (
	"context"
	"testing"
)

// PR1 plumbing: SendPacketFlow accounts the inner-flow key so an on-device run
// can confirm the WireGuard patch delivers keys through real traffic, and the
// flow-agnostic SendPacket wrapper carries 0.
func TestSendPacketFlowAccountsTheKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Proxy{ctx: ctx, sendCh: make(chan sendItem, 8)}

	if err := p.SendPacketFlow([]byte{1, 2, 3}, 0x1234); err != nil {
		t.Fatal(err)
	}
	if err := p.SendPacketFlow([]byte{4, 5, 6}, 0x5678); err != nil {
		t.Fatal(err)
	}
	if err := p.SendPacketFlow([]byte{7}, 0); err != nil { // keepalive-style, no key
		t.Fatal(err)
	}
	if err := p.SendPacket([]byte{8}); err != nil { // wrapper → 0
		t.Fatal(err)
	}

	if got := p.flowKeyNonZero.Load(); got != 2 {
		t.Fatalf("flowKeyNonZero = %d, want 2", got)
	}
	if got := p.flowKeyTotal.Load(); got != 4 {
		t.Fatalf("flowKeyTotal = %d, want 4", got)
	}
}
