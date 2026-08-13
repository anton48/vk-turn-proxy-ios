package proxy

import (
	"testing"
)

// The trace must fire for a real flow, name the connection, and then go quiet —
// a diagnostic that logs every packet of a bulk transfer is one nobody can leave on.
func TestFlowTraceIsBudgeted(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	done := make(chan struct{})
	const key = 0xfeed
	for i := 0; i < flowTraceBudget+3; i++ {
		if !p.enqueueFlowPath(sendItem{buf: []byte{byte(i)}, flow: key}, key) {
			t.Fatalf("packet %d was not placed", i)
		}
		if _, ok := p.nextSendItem(done, int(p.flows.paths(key, 5).paths[0])); !ok {
			t.Fatal("writer got nothing")
		}
	}
	if left := p.flows.paths(key, 5).traceLeft.Load(); left > 0 {
		t.Fatalf("trace budget still %d after %d packets — it never fired", left, flowTraceBudget+3)
	}
	if left := p.flows.paths(key, 5).traceLeft.Load(); left < -10 {
		t.Fatalf("budget ran away to %d — the guard is not stopping the log", left)
	}
}
