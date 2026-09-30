package main

// The stats line. Sabotage seen red: the sessions established since the start
// printed as the connections' total ("40/80"); the count of sessions dropped;
// the watchdog's restarts named "reconnects".

import (
	"strings"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

func TestTheStatsLineSaysConnectionsOutOfTheConfigured(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 22, 13, 0, time.UTC)
	// The field run after its path change: forty sessions up, eighty
	// established since the start, the watchdog never fired.
	s := proxy.Stats{ActiveConns: 40, TotalConns: 80, TxBytes: 400 << 10, RxBytes: 2900 << 10,
		CredPoolSize: 8, CredPoolWithCreds: 8, CredPoolDistinctRelays: 1, TurnRTTms: 236}
	line := statsLine(s, 40, now.Add(-7*time.Second), 9, now)
	for _, want := range []string{"conns 40/40 ·", "sessions 80 since start", "watchdog restarts 0", "pool 8/8 (relays 1)", "turn rtt 236 ms", "wg handshake 7s ago", "pins 9"} {
		if !strings.Contains(line, want) {
			t.Errorf("no %q in %q", want, line)
		}
	}
	for _, not := range []string{"40/80", " reconnects "} {
		if strings.Contains(line, not) {
			t.Errorf("%q in %q — the second number of conns is what was CONFIGURED; sessions since the start and the watchdog's restarts have names of their own", not, line)
		}
	}
	// Half of them down: the line says so against the configured forty.
	s.ActiveConns, s.Reconnects, s.CaptchaImageURL, s.CredPoolQuotaRefusals = 17, 2, "pending", 3
	line = statsLine(s, 40, time.Time{}, 0, now)
	for _, want := range []string{"conns 17/40 ·", "watchdog restarts 2", "wg handshake never", "captcha pending", "486 ×3"} {
		if !strings.Contains(line, want) {
			t.Errorf("no %q in %q", want, line)
		}
	}
}
