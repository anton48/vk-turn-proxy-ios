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

// legacyPowPage is the pre-obfuscation shape, from the 2026-07-31 capture
// recorded in the wire reference: three fields, and the SAME `v2.` prefix.
const legacyPowPage = `<html><script>
window.captchaPowResult = "v2." + btoa(JSON.stringify({hash: hash, nonce: nonce}));
const powInput = "Pihj7tyAHFxdwm4t";
if (h.startsWith('0'.repeat(3))) {}
</script></html>`

func loadPowFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(powFixture)
	if err != nil {
		t.Fatalf("read %s: %v", powFixture, err)
	}
	return string(b)
}

func decodePowPayload(t *testing.T, result, prefix string) string {
	t.Helper()
	payload, ok := strings.CutPrefix(result, prefix)
	if !ok {
		t.Fatalf("result = %q, want prefix %q", result, prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload is not standard base64 with padding: %v", err)
	}
	return string(raw)
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

// The pre-obfuscation page must keep parsing: VK serves different pages to
// different identities, and a rollback on their side must not need a build on
// ours.
func TestParsePowPageLegacyStillParses(t *testing.T) {
	p, err := parsePowPage(legacyPowPage)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Input != "Pihj7tyAHFxdwm4t" || p.Difficulty != 3 || p.Prefix != "v2." {
		t.Errorf("legacy parse = %q/%d/%q", p.Input, p.Difficulty, p.Prefix)
	}
}

// 🚨 THE TWO PAGES MUST BE CLASSIFIED DIFFERENTLY, or the shape choice below has
// nothing to act on. Detection is by the page's own script — the `tel_hash` KEY
// is wire format and an obfuscator cannot rename it.
//
// SABOTAGE SEEN TO FAIL: set Envelope = envelopeTelemetry5 unconditionally in
// parsePowPage.
func TestParsePowPageDetectsTheEnvelopeShape(t *testing.T) {
	p, err := parsePowPage(loadPowFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Envelope != envelopeTelemetry5 {
		t.Errorf("1.1.1395 classified as %s, want telemetry5", p.Envelope)
	}

	lp, err := parsePowPage(legacyPowPage)
	if err != nil {
		t.Fatalf("parse legacy: %v", err)
	}
	if lp.Envelope != envelopeLegacy3 {
		t.Errorf("legacy page classified as %s, want legacy3", lp.Envelope)
	}
}

// 🚨 ANSWER THE PAGE IN ITS OWN SHAPE — the correction that matters most here.
// BOTH pages call themselves `v2.`: bundle 1.1.1387 sent three fields, 1.1.1395
// sends five. So a parser that reads the legacy page and then emits five fields
// answers it in a shape its own script never produced — silently, and on exactly
// the identities VK still serves the old page to.
// *(User-caught. The comment this file used to carry, "VK bumps the prefix when
// the shape changes", is refuted by these two fixtures.)*
//
// SABOTAGE SEEN TO FAIL: make buildPowResult always emit the five-field body.
func TestBuildPowResultAnswersInThePagesOwnShape(t *testing.T) {
	five := buildPowResult(powPageParams{Prefix: "v2.", Envelope: envelopeTelemetry5}, "00ab", 7, 42)
	want5 := `{"hash":"00ab","nonce":7,"duration_ms":42,"telemetry":{},"tel_hash":""}`
	if got := decodePowPayload(t, five, "v2."); got != want5 {
		t.Errorf("telemetry5 payload =\n  %s\nwant\n  %s", got, want5)
	}

	three := buildPowResult(powPageParams{Prefix: "v2.", Envelope: envelopeLegacy3}, "00ab", 7, 42)
	want3 := `{"hash":"00ab","nonce":7,"duration_ms":42}`
	if got := decodePowPayload(t, three, "v2."); got != want3 {
		t.Errorf("legacy3 payload =\n  %s\nwant\n  %s — a three-field page must get three fields", got, want3)
	}
}

// 🚨 AN UNKNOWN PREFIX MUST BE REFUSED, NOT GUESSED AT. `v2.` has already
// carried two different shapes, so a NEW prefix tells us nothing about the
// schema — and a guessed body under a version VK just bumped is a silent wrong
// answer, where a refusal is one loud line and one build.
//
// SABOTAGE SEEN TO FAIL: drop the `p.Prefix != powPrefixFallback` guard.
func TestParsePowPageRefusesAnUnknownPrefix(t *testing.T) {
	html := strings.Replace(loadPowFixture(t),
		"window['captchaPowResult']='v2.'+", "window['captchaPowResult']='v3.'+", -1)
	if _, err := parsePowPage(html); err == nil {
		t.Fatal("expected a refusal for a prefix we have never seen")
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

// 🚨 A FAILED ATTEMPT MUST NOT BE COUNTED AS A VERDICT BY VK, and it must be
// REACHABLE for the rule to mean anything.
//
// The first version of this guard keyed on `powErr == nil`, which made it dead
// code: every non-success return of solveCaptchaPoW carries a non-nil error, so
// the incrementing branch could never run. The predicate was correct in
// isolation and unreachable in situ — and the test passed on a state the
// program cannot produce. *(User-caught.)*
//
// The stage is now explicit: `reached` is true only once VK has actually
// answered the check, whatever the outcome.
//
// SABOTAGE SEEN TO FAIL: count every empty showType regardless of `reached`.
func TestEmptyShowHintCountsOnlyWhatVKAnswered(t *testing.T) {
	// Never got to VK: transport, parse, or a page we could not read.
	if got := nextEmptyShowHint(false, "", 0); got != 0 {
		t.Errorf("an UNREACHED attempt moved the counter to %d — it says nothing about VK", got)
	}
	if got := nextEmptyShowHint(false, "", 1); got != 1 {
		t.Errorf("an unreached attempt changed a standing count: %d, want 1 held", got)
	}
	// VK answered, and answered "no challenge type": that is its verdict.
	if got := nextEmptyShowHint(true, "", 1); got != 2 {
		t.Errorf("VK answering with no slider should count: %d, want 2", got)
	}
	// VK named a challenge: the next attempt has a real chance.
	if got := nextEmptyShowHint(true, "slider", 5); got != 0 {
		t.Errorf("a named challenge should reset: %d, want 0", got)
	}
	if got := nextEmptyShowHint(false, "slider", 5); got != 0 {
		t.Errorf("a named challenge resets even on an unreached attempt: %d, want 0", got)
	}
}

// 🚨 AN UNREADABLE PREFIX IS NOT `v2.`. The unknown-prefix guard above only
// catches a prefix we READ; if the page moves the literal into a variable the
// regex misses, the default survives, and a v3-shaped exchange would go out
// labelled `v2.` — the same defect as reading `show_captcha_type=""` as VK's
// answer, an unread value silently becoming a plausible one. *(User-caught.)*
//
// The fixture keeps its IIFE and its telemetry; only the literal assignment is
// taken away, which is exactly the shape of the page being guarded against.
//
// SABOTAGE SEEN TO FAIL: drop the `p.Envelope == envelopeTelemetry5 &&
// !prefixRead` guard.
func TestParsePowPageRefusesAnUnreadablePrefixOnTheLiveShape(t *testing.T) {
	html := strings.Replace(loadPowFixture(t),
		"window['captchaPowResult']='v2.'+", "window['captchaPowResult']=_0xversion+", -1)
	if strings.Contains(html, "'v2.'") {
		t.Fatal("fixture still carries a readable prefix — the case is not being exercised")
	}
	if !rePowTelemetry.MatchString(html) {
		t.Fatal("telemetry marker was lost — this would refuse for the wrong reason")
	}
	if _, err := parsePowPage(html); err == nil {
		t.Fatal("expected a refusal: the prefix is unreadable on a telemetry-shaped page")
	}
}

// …and the legacy shape KEEPS its fallback: `v2.` is the only prefix that shape
// has ever carried, and that branch exists so a rollback by VK survives without
// a build of ours.
func TestParsePowPageKeepsTheFallbackOnTheLegacyShape(t *testing.T) {
	html := `<html><script>
window.captchaPowResult = version + btoa(JSON.stringify({hash: hash, nonce: nonce}));
const powInput = "Pihj7tyAHFxdwm4t";
if (h.startsWith('0'.repeat(3))) {}
</script></html>`
	p, err := parsePowPage(html)
	if err != nil {
		t.Fatalf("legacy page with an unreadable prefix should still parse: %v", err)
	}
	if p.Prefix != powPrefixFallback || p.Envelope != envelopeLegacy3 {
		t.Errorf("legacy parse = %q/%s, want %q/legacy3", p.Prefix, p.Envelope, powPrefixFallback)
	}
}
