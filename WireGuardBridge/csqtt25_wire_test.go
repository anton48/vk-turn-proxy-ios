package main

// The rhythm of a 2.5 client on the wire, in the log once a minute: how many
// datagrams its streams wrote and heard and the longest stretch without one
// (csqtt25.WireQuiet, the adapter's WireLine, the tick's second line).

import (
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/csqtt25"
)

const wireLineWant = "csqtt25: wire, the last 1m0s: 271 datagram(s) out, 93 in; the longest stretch without one 2.4s, 4 of 3s and more"

func wireEngine() *fakeEngine {
	fe := newFakeEngine()
	fe.quiet = csqtt25.WireQuiet{Span: 60*time.Second + 400*time.Millisecond, Out: 271, In: 93, Longest: 2449 * time.Millisecond, Quiet: 4}
	return fe
}

// The adapter words one take: the span to the second, the two counts, the
// longest stretch to a tenth of a second, the quiet ones against their floor.
func TestCsqtt25WireLineSaysTheMinutesRhythm(t *testing.T) {
	fe := wireEngine()
	a := &csqtt25Client{eng: fe}
	if got := a.WireLine(); got != wireLineWant {
		t.Fatalf("the wire line\n got %q\nwant %q", got, wireLineWant)
	}
	if n := fe.takes.Load(); n != 1 {
		t.Fatalf("one line took the measure %d times, want once: a take starts the next stretch", n)
	}
}

func wireLines(out *lockedLog) (ticks, wires int, texts []string) {
	for _, l := range out.lines() {
		if strings.Contains(l, "csqtt: pathstats tick: ") {
			ticks++
		}
		if i := strings.Index(l, "csqtt25: wire, "); i >= 0 {
			wires++
			texts = append(texts, l[i:])
		}
	}
	return
}

func tickEvery(t *testing.T, d time.Duration) *lockedLog {
	t.Helper()
	every := csqttStatsEvery
	csqttStatsEvery = d
	t.Cleanup(func() { csqttStatsEvery = every })
	out := &lockedLog{}
	prev := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(prev) })
	return out
}

// The tick says the wire line right behind its counters line, for a client
// that measures it — and it is the tick's ALONE: the path-event snapshot and
// the stop print the counters and take nothing, so every take is a tick's
// stretch.
func TestCsqttTickSaysTheWireLineOfAClientThatMeasuresIt(t *testing.T) {
	fe := wireEngine()
	installPairTun(t)
	out := tickEvery(t, 20*time.Millisecond)
	h, _ := start25(t, fe, "")
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	if rc := csqttAttachImpl(h, mine); rc != 1 {
		t.Fatalf("attach = %d", rc)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, n, _ := wireLines(out); n < 3 && time.Now().Before(deadline); _, n, _ = wireLines(out) {
		time.Sleep(5 * time.Millisecond)
	}
	csqttLogPathSnapshotImpl(h, "probe")
	csqttTurnOffImpl(h)
	ticks, wires, texts := wireLines(out)
	if wires < 3 {
		t.Fatalf("%d wire line(s) in the log behind %d tick(s), want one behind every tick (at least three by now)", wires, ticks)
	}
	if wires != ticks {
		t.Fatalf("%d wire line(s) for %d tick line(s): the wire line is the tick's second line, every time", wires, ticks)
	}
	for _, l := range texts {
		if l != wireLineWant {
			t.Fatalf("a wire line in the log\n got %q\nwant %q", l, wireLineWant)
		}
	}
	if n := int(fe.takes.Load()); n != wires {
		t.Fatalf("the measure was taken %d times for %d wire line(s): the snapshot and the stop take nothing", n, wires)
	}
	lines := out.lines()
	for i, l := range lines {
		if strings.Contains(l, "csqtt25: wire, ") && (i == 0 || !strings.Contains(lines[i-1], "csqtt: pathstats tick: ")) {
			t.Fatalf("a wire line stands behind something else than its tick's counters line (line %d)", i)
		}
	}
}

// A client that does not measure the wire (2.1.9's) gets no such line.
func TestCsqttTickSaysNoWireLineForAClientThatDoesNotMeasure(t *testing.T) {
	var mints atomic.Int32
	installFakePool(t, mintingFetch(&mints))
	installFakeDial(t, newFakeClient())
	installPairTun(t)
	csqttSeededSettle = 0
	out := tickEvery(t, 20*time.Millisecond)
	h := startCsqtt(t, "")
	if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
		t.Fatalf("WaitReady = %d", rc)
	}
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	if rc := csqttAttachImpl(h, mine); rc != 1 {
		t.Fatalf("attach = %d", rc)
	}
	deadline := time.Now().Add(3 * time.Second)
	for n, _, _ := wireLines(out); n < 3 && time.Now().Before(deadline); n, _, _ = wireLines(out) {
		time.Sleep(5 * time.Millisecond)
	}
	csqttTurnOffImpl(h)
	if ticks, wires, _ := wireLines(out); ticks < 3 || wires != 0 {
		t.Fatalf("%d tick(s) and %d wire line(s) for a client that does not measure the wire: want ticks and no wire line", ticks, wires)
	}
}
