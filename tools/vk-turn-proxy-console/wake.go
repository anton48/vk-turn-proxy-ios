// SPDX-License-Identifier: MIT

package main

// WireGuard after a sleep.
//
// wireguard-go reads a keypair's age with time.Since — Go's monotonic clock —
// and with the stock Go runtime that clock stands still while the machine
// sleeps (mach_absolute_time on macOS; Linux's CLOCK_MONOTONIC leaves suspend
// out too). The app never meets this: its bridge is built with a runtime
// patched to count sleep (WireGuardBridge/goruntime-boottime-over-monotonic.diff);
// the console's binaries are built with the toolchain as it ships.
//
// So after a sleep WireGuard takes its key for as young as it was when the
// lid closed and goes on sending with it, while the server — whose clock ran —
// has long expired it (180 s) and drops every packet in silence. It recovers
// only by its own rule "data sent, nothing heard for 15 s": the field,
// 2026-09-30 — asleep 12 minutes, every session back 2 s after the wake, the
// tunnel silent for 14.
//
// The monitor sees a sleep by the WALL clock (netmon.go). At a wake the
// console tells WireGuard what its clock cannot. The keys are dropped AT
// ONCE: from then on WireGuard handshakes before it sends anything, whenever
// that is. And the handshake is asked the moment a session can carry it: a
// wake usually ends in a forced reconnect of every session, an initiation
// sent into the dead ones is lost, and WireGuard's own next one is 5 s away.

import (
	"context"
	"log"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// wgPeer is what a wake needs of WireGuard — *device.Peer in production.
type wgPeer interface {
	ExpireCurrentKeypairs()
	SendHandshakeInitiation(isRetry bool) error
}

// rekey drops the keys and asks for a handshake. The expiry comes first and
// is not optional: it is also what lifts wireguard-go's limit of one
// initiation per 5 s — data that went out at the wake has usually asked for
// one already, into sessions that were dead.
func rekey(p wgPeer) error {
	p.ExpireCurrentKeypairs()
	return p.SendHandshakeInitiation(false)
}

// findPeer is the device's peer with this public key (base64, as the backup
// has it), or nil.
func findPeer(dev *device.Device, publicKey string) wgPeer {
	h, err := keyHex(publicKey)
	if err != nil || dev == nil {
		return nil
	}
	var pk device.NoisePublicKey
	if err := pk.FromHex(h); err != nil {
		return nil
	}
	p := dev.LookupPeer(pk)
	if p == nil {
		return nil // not a nil *device.Peer inside the interface
	}
	return p
}

const (
	// wakeKickTick: how often the wake's handshake is looked at.
	wakeKickTick = 100 * time.Millisecond
	// wakeKickSpacing: an initiation is given this long for its answer before
	// another is asked — the expiry that goes with a new one cuts the first off.
	wakeKickSpacing = 2 * time.Second
	// wakeKickGiveUp: WireGuard's own timers have long taken over by then.
	wakeKickGiveUp = 10 * time.Minute
)

// wakeKick decides, tick by tick after a wake, when WireGuard is asked to
// handshake — until a handshake made after the wake is seen.
type wakeKick struct {
	since  time.Time   // wall clock: a handshake after this moment is the wake's
	before proxy.Stats // the proxy as the wake found it, BEFORE its health check

	kicks    int
	lastKick time.Time
	base     int32 // sessions established when last looked: more means a new one is up
	started  bool
}

// step says whether to ask now, and whether the wake's work is over. now and
// lastHandshake are wall-clock readings.
func (k *wakeKick) step(now time.Time, s proxy.Stats, lastHandshake time.Time) (kick, done bool) {
	if !k.started {
		k.started, k.base = true, k.before.TotalConns
	}
	if lastHandshake.After(k.since) || now.Sub(k.since) > wakeKickGiveUp {
		return false, true
	}
	newSession := s.TotalConns > k.base
	if k.kicks == 0 {
		// The health check forced a reconnect: every session is being
		// rebuilt, and the first of them is what can carry the handshake.
		// Without one, the sessions are what they were — ask at once.
		if s.Reconnects != k.before.Reconnects && !newSession {
			return false, false
		}
	} else if !newSession || now.Sub(k.lastKick) < wakeKickSpacing {
		// Asked already: again only through a session that came up since
		// (the last one may have gone into a dead one), and not on the
		// heels of the previous ask.
		return false, false
	}
	k.kicks++
	k.lastKick, k.base = now, s.TotalConns
	return true, false
}

// rekeyAfterWake drops WireGuard's keys and runs one wake's handshake to its
// end. Called from the monitor's goroutine; a wake inside a wake replaces the
// earlier one.
func (c *console) rekeyAfterWake(before proxy.Stats, noticed time.Time) {
	if c.peer == nil || c.mctx == nil {
		// Never in a running console (attach keeps the peer, run the
		// context) — and if ever, said: a wake that tells WireGuard nothing
		// costs 15 s of silence that no line would explain.
		log.Printf("wireguard: the wake is NOT told to WireGuard — the console holds no peer to ask")
		return
	}
	if c.wakeStop != nil {
		c.wakeStop()
		c.wakeStop = nil
	}
	// The wake itself was up to one poll before it was noticed: a handshake
	// WireGuard made by itself in between is the wake's too — those keys are
	// new on both sides, and dropping them would only cost another.
	since := noticed.Add(-netPoll).Round(0)
	if readWG(c.dev).lastHandshake.After(since) {
		log.Printf("wireguard: it made a handshake by itself as the machine woke — its keys are new, nothing to ask")
		return
	}
	// The keys go AT ONCE, whatever can or cannot carry a handshake yet: from
	// here on WireGuard handshakes before it sends anything, whenever that
	// is. Left to the first ask, a wake into no network that outlasts
	// wakeKickGiveUp would end with the stale keys in place — and the
	// network's return would meet the 15 s of silence after all.
	c.peer.ExpireCurrentKeypairs()
	log.Printf("wireguard: its keys did not see the sleep — dropped; a new handshake is asked as soon as a session can carry it")
	ctx, stop := context.WithCancel(c.mctx)
	c.wakeStop = stop
	k := &wakeKick{since: since, before: before}
	go func() {
		defer stop()
		t := time.NewTicker(wakeKickTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			now := time.Now().Round(0)
			hs := readWG(c.dev).lastHandshake
			kick, done := k.step(now, c.p.GetStats(), hs)
			switch {
			case done && hs.After(k.since):
				after := hs.Sub(noticed.Round(0)).Round(100 * time.Millisecond)
				if after < 0 {
					after = 0
				}
				log.Printf("wireguard: handshake %s after the wake was noticed (asked %d time(s))", after, k.kicks)
				return
			case done:
				log.Printf("wireguard: no handshake since the wake (asked %d time(s)) — left to WireGuard: its keys are dropped, it handshakes before it sends", k.kicks)
				return
			case kick:
				if err := rekey(c.peer); err != nil {
					log.Printf("wireguard: handshake after the wake: %v", err)
				}
			}
		}
	}()
}
