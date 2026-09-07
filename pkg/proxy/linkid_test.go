package proxy

import (
	"testing"
	"time"
)

// p.linkID is derived once, in NewProxy (parseVKLinkID, the pool's own parser), and never written afterwards:
// Start runs on the bootstrap goroutine while RefreshCaptchaURL reads the
// field on Swift's thread with nothing ordering the two (the review of
// 2026-09-06). Sabotage seen red: the derivation moved back into Start (the
// field is "" before Start).
func TestLinkIDIsFixedAtConstruction(t *testing.T) {
	for link, want := range map[string]string{
		"https://vk.ru/call/join/abc123?x=1":   "abc123",
		"https://vk.com/call/join/abc123/tail": "abc123",
		"https://vk.ru/call/join/abc123#frag":  "abc123",
		"bare-id":                              "bare-id",
		"":                                     "",
	} {
		if got := parseVKLinkID(link); got != want {
			t.Errorf("parseVKLinkID(%q) = %q, want %q", link, got, want)
		}
	}
	p := NewProxy(Config{VKLink: "https://vk.ru/call/join/abc123?x=1", PeerAddr: "127.0.0.1:1"})
	defer p.StopWithTimeout(time.Second)
	if p.linkID != "abc123" {
		t.Fatalf("linkID before Start = %q, want abc123 — it must not depend on Start", p.linkID)
	}
}
