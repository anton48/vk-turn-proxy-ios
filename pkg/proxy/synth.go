package proxy

import (
	"context"
	"encoding/binary"
	"log"
	"time"
)

// A PACED SYNTHETIC UPLINK, for one question and one question only.
//
// 🎯 THE QUESTION. As of 2026-08-10 the tunnel's upload sits at a shared ceiling
// of ~19 Mbit/s and every candidate on the NETWORK side is eliminated: the relay
// path carries 59.4 Mbit/s (`turn_srtp_test`, 30 allocations, same WiFi, same
// minute), delivery is 99.98%, each allocation runs at 21-30% of its policer,
// the outer TCP is gone on UDP with no change, and the bare phone does 100
// Mbit/s up. What has NEVER been separated is *the phone* from *what we built on
// it*, because the only synthetic we can run today runs on a Mac.
//
// THE SPLIT. This generator calls SendPacket in a paced loop, which is exactly
// where wireguard-go hands us an encrypted packet. So it exercises everything
// BELOW that point — sendCh, the N connection writers, SRTP framing, TURN, the
// relay — and bypasses everything above it: the TUN read path, wireguard-go's
// crypto, and the inner TCP.
//
//	ΣUP at server1 ≈ 50-60  ⇒ the ceiling is ABOVE SendPacket: WireGuard or the
//	                          inner TCP. Everything below is exonerated.
//	ΣUP at server1 ≈ 19     ⇒ the ceiling is AT OR BELOW SendPacket: our
//	                          transport, or the phone's socket layer.
//
// Either answer halves the remaining search space, which nothing measured so far
// has done.
//
// 🚨 READ THE RESULT AT THE SERVER, NOT HERE. This side can only report what it
// OFFERED. That is the same trap as the server's own DOWN counter, which counts
// after conn.Write and was published as throughput once already. The delivered
// figure is server1's `ΣUP` in conn-stats.
//
// ⚠️ RUN IT WITH `-uplink-reseq=0`. The packets carry a WireGuard transport
// header with a synthetic receiver index so server1's reorder.go measures their
// displacement for free — but a resequencer would then hold them, which both
// distorts this measurement and pollutes its own.
//
// ⚠️ AND KEEP THE PHONE OTHERWISE IDLE. This adds to the real uplink rather than
// replacing it; anything else the phone is doing lands in the same ΣUP.
const (
	// synthPktSize matches a real WireGuard transport packet at the shipped
	// 1280-byte inner MTU (1280 + 32 of WireGuard header and tag), so the byte
	// and packet accounting is directly comparable with the tunnel's own.
	synthPktSize = 1312

	// synthTick is the pacing granularity. Packets go out in bursts of
	// rate×tick because time.Sleep cannot resolve a single packet at these
	// rates — the same reason `turn_srtp_test` grew a -burst flag: sleep
	// granularity caps a naive loop near 900 pkt/s, well under what this has to
	// reach to answer anything.
	synthTick = 2 * time.Millisecond

	// synthIdx is the receiver index stamped into every synthetic packet. It is
	// deliberately not a plausible WireGuard index: server1 keys its reorder
	// statistics per index, so this keeps the synthetic stream in its own
	// bucket instead of corrupting the real one's.
	synthIdx = 0x5D17_0000

	// Guard rails, because this is remote-triggered by a config field and a
	// typo must not be able to run a phone's radio flat.
	synthMaxMbit = 200.0
	synthMaxSec  = 120

	// 🚨 HOW LONG TO WAIT FOR THE POOL, AND WHY IT IS NOT A NUMBER.
	//
	// The first version of this file used a flat 90 s, picked by eyeballing the
	// code. A 30-connection ramp takes **106.8 s by construction** — 200 ms
	// apart for the first ten, then 5 s apart for the rest — so the generator
	// gave up 17 seconds before the pool completed, logged a refusal, and cost
	// a device run. The device's own HEARTBEAT shows the ramp exactly: one more
	// conn every 5 s, 30 up at t+1m47s.
	//
	// So the wait is DERIVED from the same constants that build the ramp, via
	// expectedRampTime, plus slack for establishment. Never hardcode it again.
	synthPoolSlack = 45 * time.Second

	// What fraction of the pool is enough. Not 100%: at 27 of 30 the N-way
	// fan-out under test is entirely present, and refusing outright wastes a
	// device run for a 10% shortfall. Below this the run is genuinely
	// uninterpretable and is skipped.
	//
	// ⚠️ Whatever it runs with, the COUNT goes in both the START and DONE lines,
	// so a partial run can never be mistaken for a full one after the fact.
	synthMinPoolFrac = 0.9
)

// runUplinkSynthLoop is the one-shot generator. It returns as soon as the run
// finishes; it is not restarted for the life of the tunnel.
func (p *Proxy) runUplinkSynthLoop(ctx context.Context) {
	mbit := p.config.UplinkSynthMbit
	if mbit <= 0 {
		return
	}
	if mbit > synthMaxMbit {
		log.Printf("uplink-synth: %.1f Mbit/s requested, clamping to %.0f", mbit, synthMaxMbit)
		mbit = synthMaxMbit
	}
	secs := p.config.UplinkSynthSec
	if secs <= 0 {
		secs = 30
	}
	if secs > synthMaxSec {
		log.Printf("uplink-synth: %ds requested, clamping to %ds", secs, synthMaxSec)
		secs = synthMaxSec
	}

	want := int32(p.config.NumConns)
	if want <= 0 {
		want = 1
	}
	got, ok := p.waitForConns(ctx, want)
	if !ok {
		return
	}

	pktPerSec := mbit * 1e6 / 8 / synthPktSize
	burst := int(pktPerSec*synthTick.Seconds() + 0.999)
	if burst < 1 {
		burst = 1
	}
	log.Printf("uplink-synth: START — target %.1f Mbit/s for %ds over %d of %d conns "+
		"(%.0f pkt/s of %d B, bursts of %d every %s). 🚨 The number that matters "+
		"is ΣUP in server1's conn-stats, NOT this side's; run the server with "+
		"-uplink-reseq=0 and keep the phone otherwise idle.",
		mbit, secs, got, want, pktPerSec, synthPktSize, burst, synthTick)

	var sent, blocked int64
	buf := make([]byte, synthPktSize)
	buf[0] = 4 // WireGuard transport message
	binary.LittleEndian.PutUint32(buf[4:8], synthIdx)

	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	tick := time.NewTicker(synthTick)
	defer tick.Stop()
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if time.Now().After(deadline) {
			break
		}
		for i := 0; i < burst; i++ {
			// A sequential counter in WireGuard's own field, so server1's
			// reorder.go reports this stream's displacement with no changes.
			binary.LittleEndian.PutUint64(buf[8:16], uint64(sent))
			before := p.sendChBlockCount.Load()
			if err := p.SendPacket(buf); err != nil {
				log.Printf("uplink-synth: STOPPED after %d packets: %v", sent, err)
				return
			}
			if p.sendChBlockCount.Load() != before {
				blocked++
			}
			sent++
		}
	}
	elapsed := time.Since(start)
	offered := float64(sent) * synthPktSize * 8 / elapsed.Seconds() / 1e6
	log.Printf("uplink-synth: DONE — OFFERED %d packets, %.1f MiB, %.1f Mbit/s over %s "+
		"across %d of %d conns (%d sends blocked on sendCh). ⚠️ This is what we "+
		"offered, not what arrived: read ΣUP at server1 for the answer.",
		sent, float64(sent)*synthPktSize/(1<<20), offered, elapsed.Round(time.Millisecond),
		got, want, blocked)
}

// waitForConns blocks until the pool is usable. It returns the count it settled
// for and whether the run should happen at all.
//
// The deadline comes from expectedRampTime, not from a constant — see
// synthPoolSlack for what guessing it cost.
func (p *Proxy) waitForConns(ctx context.Context, want int32) (int32, bool) {
	need := int32(float64(want)*synthMinPoolFrac + 0.999)
	if need < 1 {
		need = 1
	}
	budget := expectedRampTime(int(want)) + synthPoolSlack
	deadline := time.Now().Add(budget)
	log.Printf("uplink-synth: waiting for %d of %d conns, up to %s "+
		"(the ramp itself takes %s by construction)",
		need, want, budget.Round(time.Second), expectedRampTime(int(want)).Round(time.Second))
	lastLog := time.Now()
	for {
		n := p.activeConns.Load()
		if n >= want {
			return n, true
		}
		if time.Now().After(deadline) {
			if n >= need {
				// ⚠️ Runs, but the count rides in every line from here on, so
				// the number can never be read later as if the pool were full.
				log.Printf("uplink-synth: %d of %d conns after %s — running anyway, "+
					"the fan-out under test is present; the count is in the START "+
					"and DONE lines", n, want, budget.Round(time.Second))
				return n, true
			}
			log.Printf("uplink-synth: only %d of %d conns after %s (needed %d) — NOT "+
				"running, a pool this partial produces a number that answers nothing",
				n, want, budget.Round(time.Second), need)
			return n, false
		}
		if time.Since(lastLog) >= 15*time.Second {
			log.Printf("uplink-synth: %d of %d conns, %s left", n, want,
				time.Until(deadline).Round(time.Second))
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return n, false
		case <-time.After(500 * time.Millisecond):
		}
	}
}
