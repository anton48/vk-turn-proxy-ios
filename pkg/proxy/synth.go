package proxy

import (
	"context"
	"encoding/binary"
	"log"
	"sync/atomic"
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

	// synthMaxArmSec stops an arm that was set and forgotten. The dose-response
	// this exists for uses arms of ~120 s, so ten minutes is far above any real
	// arm and far below "all night on a phone's radio". Every rate change
	// refreshes it.
	synthMaxArmSec = 10 * time.Minute

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

// synthTargetCentiMbit is the LIVE target rate, in hundredths of a Mbit/s.
// Zero means idle.
//
// 🚨 WHY THIS IS LIVE, AND IT IS A MEASUREMENT REQUIREMENT RATHER THAN A
// CONVENIENCE — the same reason `uplink_chunk_k` and `flow_paths_k` are live.
// The experiment this generator now exists for is a DOSE-RESPONSE: hold the
// pool at ~30%, ~60% and ~95% of the per-allocation knee and ask whether the
// loss measured by the server's counter space (`lost` / `cum-lost`) moves.
// Applying a level through a reconnect would put a ~107 s thirty-connection
// ramp between arms, on a line measured to move 75 → 363 Mbit/s inside 70
// minutes — so the arms would differ by drift as much as by level.
//
// 🎯 AND WHY A SYNTHETIC AT ALL, WHEN WE HAVE A TCP PROBE: TCP CANNOT HOLD A
// LEVEL. Its congestion control ramps until it meets something, which is why
// the per-connection load in `udptest6` wandered 28-101% of the knee inside one
// run. A paced generator is the only way to ask "what happens at 30% of the
// knee" and get an answer about 30% of the knee.
var synthTargetCentiMbit atomic.Int64

// synthArmDeadline is a safety stop: an arm set and forgotten must not run a
// phone's radio flat. UnixNano; refreshed on every rate change.
var synthArmDeadline atomic.Int64

// SetUplinkSynthMbit sets the live target rate and starts a fresh arm. 0 stops.
// Clamped, so a malformed message cannot run the radio flat.
//
// ⚠️ It does NOT wait for the pool: the loop does that once, at tunnel start.
// Setting a rate before the pool is up simply takes effect when it comes up.
func SetUplinkSynthMbit(mbit float64) {
	if mbit < 0 {
		mbit = 0
	}
	if mbit > synthMaxMbit {
		log.Printf("uplink-synth: %.1f Mbit/s requested, clamping to %.0f", mbit, synthMaxMbit)
		mbit = synthMaxMbit
	}
	synthTargetCentiMbit.Store(int64(mbit*100 + 0.5))
	synthArmDeadline.Store(time.Now().Add(synthMaxArmSec).UnixNano())
}

// synthTarget reads the live rate, honouring the safety deadline.
func synthTarget() float64 {
	c := synthTargetCentiMbit.Load()
	if c <= 0 {
		return 0
	}
	if d := synthArmDeadline.Load(); d > 0 && time.Now().UnixNano() > d {
		return 0
	}
	return float64(c) / 100
}

// runUplinkSynthLoop is the generator. It waits for the pool once and then runs
// for the life of the tunnel, following whatever rate is set live.
func (p *Proxy) runUplinkSynthLoop(ctx context.Context) {
	// The backup-JSON field still works and still means what it did: ONE arm at
	// that rate, bounded by UplinkSynthSec. Kept so every recorded run remains
	// reproducible from its own config.
	if m := p.config.UplinkSynthMbit; m > 0 {
		SetUplinkSynthMbit(m)
		secs := p.config.UplinkSynthSec
		if secs <= 0 {
			secs = 30
		}
		if secs > synthMaxSec {
			log.Printf("uplink-synth: %ds requested, clamping to %ds", secs, synthMaxSec)
			secs = synthMaxSec
		}
		synthArmDeadline.Store(time.Now().Add(time.Duration(secs) * time.Second).UnixNano())
	}

	// 🚨 The pool wait and the fine ticker are BOTH deferred to first use, so a
	// tunnel that never runs the generator neither logs about it nor keeps a
	// 2 ms timer alive on the phone's radio budget.
	idle := time.NewTicker(100 * time.Millisecond)
	defer idle.Stop()

	var (
		fine        *time.Ticker
		poolChecked bool
		conns       int32
		lastRate    float64
		buf         = make([]byte, synthPktSize)
		burst       int
		perTick     float64 // packets owed per tick at the current rate
		owed        float64 // fractional carry, so the long-run rate is exact
		armSent     int64
		armBlocked  int64
		armStart    time.Time
		seq         uint64
	)
	buf[0] = 4 // WireGuard transport message
	binary.LittleEndian.PutUint32(buf[4:8], synthIdx)

	stopArm := func(why string) {
		if fine == nil {
			return
		}
		fine.Stop()
		fine = nil
		el := time.Since(armStart)
		offered := float64(armSent) * synthPktSize * 8 / el.Seconds() / 1e6
		log.Printf("uplink-synth ARM-END (%s) — offered %d packets, %.1f MiB, "+
			"%.1f Mbit/s over %s across %d conns (%d sends blocked on sendCh). "+
			"⚠️ OFFERED, not delivered: the answer is ΣUP and `lost` in server1's conn-stats.",
			why, armSent, float64(armSent)*synthPktSize/(1<<20), offered,
			el.Round(time.Millisecond), conns, armBlocked)
		lastRate = 0
	}
	defer stopArm("tunnel stopping")

	for {
		if ctx.Err() != nil {
			return
		}
		rate := synthTarget()

		if rate <= 0 {
			if fine != nil {
				why := "rate set to 0"
				if synthTargetCentiMbit.Load() > 0 {
					why = "safety deadline"
				}
				stopArm(why)
			}
			select {
			case <-ctx.Done():
				return
			case <-idle.C:
			}
			continue
		}

		if !poolChecked {
			want := int32(p.config.NumConns)
			if want <= 0 {
				want = 1
			}
			got, ok := p.waitForConns(ctx, want)
			poolChecked = true
			if !ok {
				// waitForConns already said why. Disarm rather than spin.
				synthTargetCentiMbit.Store(0)
				continue
			}
			conns = got
		}

		if rate != lastRate {
			pktPerSec := rate * 1e6 / 8 / synthPktSize
			perTick = pktPerSec * synthTick.Seconds()
			owed = 0
			if fine != nil {
				stopArm("rate changed")
			}
			fine = time.NewTicker(synthTick)
			armSent, armBlocked, armStart = 0, 0, time.Now()
			lastRate = rate
			// 🎯 One greppable marker per arm, carrying everything needed to
			// score it later — the lesson of `flowab PLAN/ARM/RUNEND`, where an
			// arm boundary that lives only in the operator's memory is an arm
			// boundary that cannot be recovered from the log.
			log.Printf("uplink-synth ARM mbit=%.1f — %.0f pkt/s of %d B, %.2f per %s tick, "+
				"over %d conns. Run the server with -uplink-reseq=0 and keep the phone otherwise idle.",
				rate, pktPerSec, synthPktSize, perTick, synthTick, conns)
		}

		// 🚨 A FRACTIONAL ACCUMULATOR, NOT A ROUNDED BURST, AND THE TEST FOUND
		// OUT WHY. Rounding packets-per-tick UP overshoots badly at exactly the
		// arms this generator exists for: 12 Mbit/s wants 2.29 packets per 2 ms
		// tick and a rounded burst of 3 delivers 15.7 Mbit/s — 31% high, so a
		// "30% of the knee" arm would really sit at 39% and the dose-response
		// would be scored against levels it never ran at. Carrying the
		// remainder makes the long-run rate exact.
		owed += perTick
		burst = int(owed)
		owed -= float64(burst)
		if burst < 1 {
			// Nothing owed this tick at a very low rate; wait rather than
			// inventing a packet.
			select {
			case <-ctx.Done():
				return
			case <-fine.C:
			}
			continue
		}

		failed := false
		for i := 0; i < burst; i++ {
			// 🚨 `seq` is NEVER reset between arms, and that is load-bearing: it
			// is WireGuard's counter field, and server1 measures loss as span
			// minus arrivals over it. Restarting it at each arm would read as a
			// counter going backwards by millions and destroy the measurement
			// this generator now exists for.
			binary.LittleEndian.PutUint64(buf[8:16], seq)
			before := p.sendChBlockCount.Load()
			if err := p.SendPacketSynth(buf); err != nil {
				log.Printf("uplink-synth: STOPPED after %d packets in this arm: %v", armSent, err)
				stopArm("send error")
				synthTargetCentiMbit.Store(0)
				failed = true
				break
			}
			if p.sendChBlockCount.Load() != before {
				armBlocked++
			}
			seq++
			armSent++
		}
		if failed {
			// stopArm cleared the ticker; falling into the select below would
			// read fine.C on a nil *Ticker.
			continue
		}

		select {
		case <-ctx.Done():
			return
		case <-fine.C:
		}
	}
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
