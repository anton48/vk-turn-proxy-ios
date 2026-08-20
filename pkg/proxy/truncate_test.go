package proxy

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 🚨 THE LOG MUST NEVER CARRY AN INVALID BYTE, and this is the function that
// put one there. On 2026-08-20 a VK error response containing the name
// "Русл|ан" was cut at byte 300 INSIDE the "а" (0xD0 0xB0); the surviving 0xD0
// made the app's Logs screen read "(log is empty)" over an 829 072-byte file
// for the length of a VPN sweep, because the reader decoded strictly.
//
// The reader is lenient now — but that is the second line of defence, not a
// reason to keep emitting bad bytes: the same file is read by grep and by the
// python scorers, and each decides separately how badly one byte hurts.
func TestTruncateNeverCutsInsideARune(t *testing.T) {
	// Every cut point of a string whose runes are 1, 2 and 4 bytes wide, so
	// the loop lands inside a multi-byte sequence at most offsets rather than
	// by luck.
	s := "name=Руслан Алексеевич ✓ 🎯 ok"
	for n := 0; n <= len(s)+2; n++ {
		got := truncate(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("truncate(s, %d) produced invalid UTF-8: %q", n, got)
		}
		if len(got) > n+3 && len(s) > n {
			t.Fatalf("truncate(s, %d) = %d bytes — the cap must stay in BYTES, "+
				"a rune-count cap would let one line grow 4x", n, len(got))
		}
	}
}

// The exact shape that produced the bad byte: the cut lands one byte into a
// two-byte Cyrillic character. Reproduced from the real log, not invented —
// vpn.wifi.9.log offset 398903.
func TestTruncateReproducesTheFieldIncident(t *testing.T) {
	body := `{"key":"name","value":"` + strings.Repeat("x", 270) + `Руслан"}`
	got := truncate(body, 300)
	if !utf8.ValidString(got) {
		t.Fatalf("the recorded incident still produces invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("a truncated value must say so, got %q", got[len(got)-8:])
	}
	// It really was cut — otherwise the test passes for the wrong reason,
	// having exercised the short-string path.
	if len(got) >= len(body) {
		t.Fatalf("precondition failed: the fixture was not long enough to cut "+
			"(body %d bytes, result %d) — this test would then prove nothing",
			len(body), len(got))
	}
}

// ASCII behaviour is unchanged: the back-off must not shorten a cut that
// already lands on a boundary.
func TestTruncateLeavesASCIICutsWhereTheyWere(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello..." {
		t.Fatalf("got %q, want %q", got, "hello...")
	}
	if got := truncate("short", 99); got != "short" {
		t.Fatalf("a string under the cap must come back untouched, got %q", got)
	}
}
