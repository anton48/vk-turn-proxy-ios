package proxy

// CredPool — the app's credential pool as a standalone value.
//
// Stage-5 step 1 (2026-09-06): a second transport (csqtt, pkg/csqtt) must
// mint, share, pace and cache VK TURN credentials by the SAME policy the
// native transport does — one pool slot per ~10 connections (VK's quota is
// per (identity, relay), see connsPerSlot), the cold-start cap inside get(),
// the grower's fast-then-staggered fill, the on-disk cache, cookie auth and
// the TURN override — without that transport living inside Proxy. This file
// is ADDITIONS ONLY: Proxy keeps building its own pool exactly as before
// (NewProxy → newCredPool with p.fetchFreshCreds; growCredPool unchanged),
// and this wrapper reuses the same credPool type with an injected fetcher.
//
// What the wrapper's fetcher does NOT carry is the captcha: the WebView round
// trip keeps its tokens in Proxy fields, and every acquire here is
// non-blocking (get(…, false) / tryFill(…, false)), so a captcha fails the
// fetch with CaptchaRequiredError and the slot cools down — the transport
// reports "authentication required". No solver is wired on this path by
// design (a field that is never consulted would be a lie); stage-5 step D
// (csqtt as a Proxy session mode) brings the app's captcha flow by
// construction. ⚠️ Grow duplicates the state machine of Proxy.growCredPool
// so that proxy.go stays untouched; step D makes Proxy delegate here and
// deletes the copy.

import (
	"context"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// CredPoolConfig describes a standalone pool. NumConns sizes it exactly as
// proxy.Config.NumConns sizes Proxy's (poolSizeForNumConns); the rest mirror
// the same-named proxy.Config fields.
type CredPoolConfig struct {
	VKLink     string        // VK call invite link or bare link id, as proxy.Config.VKLink
	NumConns   int           // connections the pool must host; pool size = poolSizeForNumConns(NumConns)
	Cooldown   time.Duration // post-failure skip-fetch window per slot; <=0 → the pool's default (2 min)
	CachePath  string        // on-disk JSON cache (the app's creds-pool.json); empty disables persistence
	TurnServer string        // optional TURN host override applied to every fresh mint
	TurnPort   string        // optional TURN port override
	// Fetch replaces the standard VK fetcher (tests, or another minter). It
	// must return ("host:port", creds, nil) with creds.Addresses non-empty.
	Fetch func(allowCaptchaBlock bool, slot int) (string, *TURNCreds, error)
}

// CredPool wraps the package's credPool for use outside Proxy.
type CredPool struct {
	cp       *credPool
	numConns int
	linkID   string
	relayIP  atomic.Value    // string: first host of the last fresh mint
	pace     growPace        // set before Grow starts; tests shrink it
	ctx      context.Context // the pool's own lifetime: the saver, Grow; ended by Close
	cancel   context.CancelFunc
}

// CredPoolStats is the pool's state in the shape the app's Stats carries it
// (CredPoolFilled / WithCreds / Size / DistinctRelays) plus the saturation
// view used by the bootstrap watchdog.
type CredPoolStats struct {
	Available        int // fresh AND not saturated — what a NEW connection can use
	WithCreds        int // slots holding an unexpired cred (superset of Available)
	Size             int
	DistinctRelays   int
	Saturated        int
	SaturatedLongest time.Duration
}

// NewCredPool builds a standalone pool. The periodic cache saver (when
// CachePath is set) runs until Close or until ctx ends, and writes the cache
// once more on its way out.
func NewCredPool(ctx context.Context, cfg CredPoolConfig) *CredPool {
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &CredPool{numConns: cfg.NumConns, linkID: parseVKLinkID(cfg.VKLink), pace: defaultGrowPace, ctx: ctx, cancel: cancel}
	fetch := cfg.Fetch
	if fetch == nil {
		fetch = p.standardFetch(cfg)
	}
	p.cp = newCredPool(ctx, poolSizeForNumConns(cfg.NumConns), cfg.Cooldown, cfg.CachePath, fetch)
	return p
}

// Close is the transport's stop path: it writes the cache now (so the stop
// does not depend on the background saver's timing), then ends the pool's
// lifetime — the periodic saver and Grow both stop. Safe to call more than
// once; nothing is minted after it.
func (p *CredPool) Close() {
	if p.cp.cachePath != "" {
		p.cp.saveToDisk()
	}
	p.cancel()
}

// parseVKLinkID is Proxy.Start's link parsing: the id after "join/", cut at
// the first "/", "?" or "#".
func parseVKLinkID(link string) string {
	id := link
	if strings.Contains(id, "join/") {
		parts := strings.Split(id, "join/")
		id = parts[len(parts)-1]
	}
	if i := strings.IndexAny(id, "/?#"); i != -1 {
		id = id[:i]
	}
	return id
}

// standardFetch is Proxy.fetchFreshCreds without the captcha bookkeeping:
// cookie auth when enabled (package-level, shared with Proxy), otherwise the
// anonymous VK Calls path with no solver — a captcha surfaces as
// CaptchaRequiredError; then the TURN override, then the relay host is
// published.
func (p *CredPool) standardFetch(cfg CredPoolConfig) func(bool, int) (string, *TURNCreds, error) {
	return func(_ bool, slot int) (string, *TURNCreds, error) {
		var creds *TURNCreds
		if cookieAuthEnabled.Load() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			c, cerr := cookieCredForSlot(ctx, slot)
			cancel()
			if cerr != nil {
				if errors.Is(cerr, ErrCookieRejected) {
					setCookieAuthFatal(cerr.Error())
				}
				return "", nil, fmt.Errorf("cookie auth: %w", cerr)
			}
			clearCookieAuthFatal()
			creds = c
		} else {
			c, err := GetVKCreds(p.linkID, nil, "", "", 0, 0, "", "")
			if err != nil {
				return "", nil, fmt.Errorf("get VK creds: %w", err)
			}
			creds = c
		}
		addr, err := applyTURNOverride(creds, cfg.TurnServer, cfg.TurnPort)
		if err != nil {
			return "", nil, err
		}
		if host, _, herr := net.SplitHostPort(addr); herr == nil {
			p.relayIP.Store(host)
		}
		return addr, creds, nil
	}
}

// applyTURNOverride rewrites every VK-returned address with the optional
// host/port override — the fresh-fetch path only, exactly as Proxy does —
// and returns the primary address.
func applyTURNOverride(creds *TURNCreds, server, port string) (string, error) {
	if creds == nil || len(creds.Addresses) == 0 {
		return "", errors.New("VK returned no TURN address")
	}
	for i, vkAddr := range creds.Addresses {
		h, pport, err := net.SplitHostPort(vkAddr)
		if err != nil {
			return "", fmt.Errorf("parse TURN address %q: %w", vkAddr, err)
		}
		if server != "" {
			h = server
		}
		if port != "" {
			pport = port
		}
		creds.Addresses[i] = net.JoinHostPort(h, pport)
	}
	creds.Address = creds.Addresses[0]
	return creds.Addresses[0], nil
}

// Acquire hands connIdx a credential by the pool's policy: its own slot
// (connIdx/10) when that has quota room, any fresh slot otherwise, a fresh
// mint when allowed by the cold-start cap. The error cases ("paused for
// path-change settle", "cold-start cap … parking", "no slot available")
// are the pool's own; the caller parks on SlotAvailable() or a short timer
// and retries, as Proxy's connections do. Never blocks on a captcha.
func (p *CredPool) Acquire(connIdx int) (addr string, creds *TURNCreds, slot int, err error) {
	return p.cp.get(connIdx, false)
}

// Release returns a connection's hold on its slot (call when the allocation
// is gone).
func (p *CredPool) Release(slot int) { p.cp.release(slot) }

// MarkSaturated records a 486 (allocation quota reached) on the slot and
// returns the cooldown applied.
func (p *CredPool) MarkSaturated(slot int) time.Duration { return p.cp.markSaturated(slot) }

// RecordAuthError counts a 401/403 on the slot (pre-kill attribution).
func (p *CredPool) RecordAuthError(slot int) { p.cp.recordAuthError(slot) }

// Invalidate drops every cached credential (a wholesale re-fetch follows).
func (p *CredPool) Invalidate() { p.cp.invalidate() }

// OnPathChange is what Proxy.OnPathChange does to its pool: marks the slots
// in use so the next acquires spread, and pauses acquires briefly so a
// dual PathMonitor event does not grab fresh slots in the gap.
func (p *CredPool) OnPathChange() { p.cp.MarkInUseSlotsForPathChange() }

// ExtendPause lengthens the post-path-change acquire pause (a transition
// the caller knows is still in progress).
func (p *CredPool) ExtendPause(d time.Duration) { p.cp.ExtendPauseAcquireForTransition(d) }

// SlotAvailable is closed whenever the pool changes in a way that may let a
// parked acquire succeed; take a fresh channel after every wake.
func (p *CredPool) SlotAvailable() <-chan struct{} { return p.cp.slotAvailableChannel() }

// RelayIP is the host of the last fresh mint, falling back to the first host
// the pool holds — so it is NOT empty after a warm-cache start, which
// Proxy.TURNServerIP is (seen 2026-09-05: the console client pinned no relay
// and the tunnel swallowed its own relay sockets).
func (p *CredPool) RelayIP() string {
	if v := p.relayIP.Load(); v != nil {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	if hosts := p.RelayHosts(); len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}

// RelayHosts lists every distinct relay host the pool holds a credential for
// (cache included), sorted. Anonymously that is one host.
func (p *CredPool) RelayHosts() []string {
	p.cp.mu.Lock()
	seen := map[string]bool{}
	for i := range p.cp.pool {
		e := &p.cp.pool[i]
		if e.creds == nil || e.addr == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(e.addr); err == nil && h != "" {
			seen[h] = true
		}
	}
	p.cp.mu.Unlock()
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Stats is the pool's state as the app reports it.
func (p *CredPool) Stats() CredPoolStats {
	available, withCreds, size := p.cp.snapshotSize()
	saturated, _, longest := p.cp.saturationSnapshot()
	return CredPoolStats{
		Available: available, WithCreds: withCreds, Size: size,
		DistinctRelays: p.cp.distinctRelays(),
		Saturated:      saturated, SaturatedLongest: longest,
	}
}

// growPace is the grower's timing — Proxy.growCredPool's constants as a
// value, so a test can run the state machine in milliseconds on its own pool
// without touching package state. The production value is pinned by
// TestCredPoolGrowPaceIsPinned.
type growPace struct {
	fast, slow, staggerMin, staggerMax, bootstrap time.Duration
}

var defaultGrowPace = growPace{
	fast: 2 * time.Second, slow: 30 * time.Second,
	staggerMin: 120 * time.Second, staggerMax: 300 * time.Second,
	bootstrap: 2 * time.Minute,
}

// Grow runs the background fill loop for the pool's lifetime (Close ends
// it): it waits for `ready` (the transport's first live connection; nil =
// start now), then fills
// slots fast until ceil(NumConns/10) are usable — the cold-start target — and
// from then on adds one slot every 120–300 s so credential expiries stay
// spread. Fetches never block on a captcha. This is Proxy.growCredPool's
// state machine without the captcha-pending check (no captcha UI here).
func (p *CredPool) Grow(ready <-chan struct{}) {
	ctx := p.ctx
	if ready != nil {
		select {
		case <-ready:
		case <-time.After(p.pace.bootstrap):
			log.Printf("credpool-grow: transport not ready within %s, grower exiting", p.pace.bootstrap)
			return
		case <-ctx.Done():
			return
		}
	}
	coldStartSlots := (p.numConns + connsPerSlot - 1) / connsPerSlot
	if coldStartSlots < 1 {
		coldStartSlots = 1
	}
	coldStartMet := false
	interval := p.pace.fast
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		slot := p.cp.pickSlotToFill()
		if slot < 0 {
			interval = p.pace.slow
			continue
		}
		if !coldStartMet {
			if available, _, total := p.cp.snapshotSize(); available >= coldStartSlots {
				coldStartMet = true
				log.Printf("credpool-grow: cold-start target %d reached at pool %d/%d (no fill needed) — switching to maintenance", coldStartSlots, available, total)
			}
		}
		abortGuard := 0
		if !coldStartMet {
			abortGuard = coldStartSlots
		}
		success := p.cp.tryFill(slot, false, abortGuard)
		if !coldStartMet {
			if available, _, total := p.cp.snapshotSize(); available >= coldStartSlots {
				coldStartMet = true
				log.Printf("credpool-grow: cold-start target %d reached at pool %d/%d — switching to maintenance", coldStartSlots, available, total)
			}
		}
		if coldStartMet {
			interval = p.pace.staggerMin + time.Duration(mathrand.Int63n(int64(p.pace.staggerMax-p.pace.staggerMin)))
			if success {
				log.Printf("credpool-grow: maintenance fill succeeded, next fill in %v", interval.Round(time.Second))
			} else {
				log.Printf("credpool-grow: maintenance fill skipped/failed, next attempt in %v", interval.Round(time.Second))
			}
		} else {
			interval = p.pace.fast
		}
	}
}
