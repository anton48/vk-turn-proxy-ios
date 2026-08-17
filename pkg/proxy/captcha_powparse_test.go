package proxy

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The fixture is the PoW <script> block of a captcha page VK actually served
// us on 2026-08-18 (bundle 1.1.1395), captured with VK_DUMP_POW_HTML and
// reduced to that block — the surrounding page carries a session_token and
// three JWTs, which must not enter the repository.
//
// 🚨 IT IS HERE BECAUSE A REGEX AGAINST AN OBFUSCATED PAGE CANNOT BE REVIEWED
// BY READING IT. Every live captcha page costs a real VK session, so without a
// fixture each iteration of this parser would burn one and rate-limit us for
// the privilege; with it the parser is checked offline against the exact bytes
// it has to match.
const powFixture = "testdata/captcha_pow_page_1_1_1395.html"

func loadPowFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(powFixture)
	if err != nil {
		t.Fatalf("read %s: %v", powFixture, err)
	}
	return string(b)
}

// The values are the ones the page hands its own script:
//
//	}("gMbKzMjN77r4NVrv",2,"pow_timeout"));
func TestParsePowPageObfuscated(t *testing.T) {
	p, err := parsePowPage(loadPowFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Input != "gMbKzMjN77r4NVrv" {
		t.Errorf("input = %q, want gMbKzMjN77r4NVrv", p.Input)
	}
	if p.Difficulty != 2 {
		t.Errorf("difficulty = %d, want 2", p.Difficulty)
	}
	if p.Prefix != "v2." {
		t.Errorf("prefix = %q, want v2.", p.Prefix)
	}
}

// 🚨 THE PREFIX MUST COME FROM THE PAGE, not from our constant. It is the one
// field VK bumps when the envelope changes shape, so a hardcoded value
// guarantees we send the OLD shape under the NEW name on the day it moves —
// which is exactly the failure this whole change is repairing.
//
// SABOTAGE SEEN TO FAIL: return powPrefixFallback unconditionally from
// parsePowPage. Compiles, and every other assertion here still passes.
func TestParsePowPageReadsPrefixFromThePage(t *testing.T) {
	html := strings.Replace(loadPowFixture(t),
		"window['captchaPowResult']='v2.'+", "window['captchaPowResult']='v3.'+", -1)
	p, err := parsePowPage(html)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Prefix != "v3." {
		t.Errorf("prefix = %q, want v3. — the page's value, not ours", p.Prefix)
	}
}

// The pre-obfuscation page must keep working: VK serves different pages to
// different identities, and a rollback on their side must not need a build on
// ours.
func TestParsePowPageLegacyStillParses(t *testing.T) {
	html := `<html><script>
window.captchaPowResult = "v2." + btoa(JSON.stringify({hash: hash, nonce: nonce}));
const powInput = "Pihj7tyAHFxdwm4t";
if (h.startsWith('0'.repeat(3))) {}
</script></html>`
	p, err := parsePowPage(html)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Input != "Pihj7tyAHFxdwm4t" || p.Difficulty != 3 || p.Prefix != "v2." {
		t.Errorf("legacy parse = %q/%d/%q", p.Input, p.Difficulty, p.Prefix)
	}
}

// A page with no PoW at all must FAIL rather than yield a plausible zero
// value: an empty input with difficulty 2 would "solve" instantly and we would
// present a proof of nothing.
func TestParsePowPageRefusesAPageWithoutPow(t *testing.T) {
	if _, err := parsePowPage(`<html><body><div id="spa_root"></div></body></html>`); err == nil {
		t.Fatal("expected an error when the page carries no PoW")
	}
}

// An unusable difficulty must be refused, not clamped: the solver would run to
// its 10M ceiling and the timeout would be reported as a failed solve, which
// reads as "VK rejected us" instead of "we could not read the page".
func TestParsePowPageRefusesAbsurdDifficulty(t *testing.T) {
	html := strings.Replace(loadPowFixture(t),
		`}("gMbKzMjN77r4NVrv",2,"pow_timeout"))`, `}("gMbKzMjN77r4NVrv",64,"pow_timeout"))`, 1)
	if _, err := parsePowPage(html); err == nil {
		t.Fatal("expected an error for a difficulty we cannot honour")
	}
}

// 🚨 THE ENVELOPE MUST CARRY THE TWO NEW FIELDS, in the page's own key order,
// with the empty values the page itself produces when its telemetry collector
// throws. The three-field form is what VK stopped accepting.
//
// SABOTAGE SEEN TO FAIL: drop `"telemetry":{},"tel_hash":""` from the payload.
func TestBuildPowResultShape(t *testing.T) {
	got := buildPowResult("v2.", "00ab", 7, 42)
	payload, ok := strings.CutPrefix(got, "v2.")
	if !ok {
		t.Fatalf("result = %q, want a v2. prefix", got)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload is not standard base64 with padding: %v", err)
	}
	want := `{"hash":"00ab","nonce":7,"duration_ms":42,"telemetry":{},"tel_hash":""}`
	if string(raw) != want {
		t.Errorf("payload =\n  %s\nwant\n  %s", raw, want)
	}
}

// The prefix threads through rather than being re-hardcoded at the last step.
func TestBuildPowResultUsesTheGivenPrefix(t *testing.T) {
	if got := buildPowResult("v3.", "00ab", 1, 1); !strings.HasPrefix(got, "v3.") {
		t.Errorf("result = %q, want the v3. prefix it was given", got)
	}
	if got := buildPowResult("", "00ab", 1, 1); !strings.HasPrefix(got, powPrefixFallback) {
		t.Errorf("empty prefix should fall back to %q, got %q", powPrefixFallback, got)
	}
}

// End to end on the real page: parse it, solve it, and check the digest the
// page's own condition would accept.
func TestSolvePoWAgainstTheRealPage(t *testing.T) {
	p, err := parsePowPage(loadPowFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hash, nonce := solvePoW(p.Input, p.Difficulty)
	if hash == "" {
		t.Fatal("no solution found for the page's own parameters")
	}
	if !strings.HasPrefix(hash, strings.Repeat("0", p.Difficulty)) {
		t.Errorf("hash %q does not satisfy difficulty %d", hash, p.Difficulty)
	}
	t.Logf("solved the captured page: nonce=%d hash=%s…", nonce, hash[:12])
}

// 🚨 A FAILED ATTEMPT MUST NOT BE COUNTED AS A VERDICT BY VK. When VK obfuscated
// the PoW script every attempt died at the parse with showType="" — our own zero
// value — and the old counter read that as "VK has no slider ready" and skipped
// the remaining attempt. The log then blamed VK for a defect that was ours, which
// is what made the failure look like an identity problem for hours.
//
// SABOTAGE SEEN TO FAIL: count every empty showType regardless of powErr, i.e.
// `if showType == "" { return consecutive + 1 }` as the first clause.
func TestEmptyShowHintIgnoresFailedAttempts(t *testing.T) {
	boom := os.ErrDeadlineExceeded

	if got := nextEmptyShowHint(boom, "", 0); got != 0 {
		t.Errorf("a FAILED attempt moved the counter to %d — it says nothing about VK", got)
	}
	if got := nextEmptyShowHint(boom, "", 1); got != 1 {
		t.Errorf("a failed attempt changed a standing count: %d, want 1 held", got)
	}
	if got := nextEmptyShowHint(nil, "", 1); got != 2 {
		t.Errorf("VK answering with no slider should count: %d, want 2", got)
	}
	if got := nextEmptyShowHint(nil, "slider", 5); got != 0 {
		t.Errorf("a named challenge should reset: %d, want 0", got)
	}
	if got := nextEmptyShowHint(boom, "slider", 5); got != 0 {
		t.Errorf("a named challenge resets even on a failed attempt: %d, want 0", got)
	}
}
