package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
)

// vkAPIHost returns the FQDN used for all api.vk.* method calls
// (calls.getAnonymousToken, captchaNotRobot.*, etc).
//
// Default "api.vk.ru". Override via VK_API_HOST env var — used for
// the 2026-05-17 evening test that VK Calls iOS app appears to call
// `api.vk.me` (different FQDN, same backend IPs) and is not captcha-
// gated for anonymous join. Hypothesis: VK gates per-(FQDN, client_id),
// so just switching the host might let our existing VK iOS App credentials
// pass without captcha. See progress_summary_may_17_2026.md for context.
func vkAPIHost() string {
	if h := os.Getenv("VK_API_HOST"); h != "" {
		return h
	}
	return "api.vk.ru"
}

// credExpiryBuffer is the safety margin before a TURN cred's expiry timestamp
// at which we consider the cred no longer fresh and start refreshing. The
// expiry comes from VK's TURN REST API (draft-uberti-behave-turn-rest):
// the credentials Username is "<expiry_unix_timestamp>:<key_id>", with the
// timestamp being the moment after which VK's TURN server rejects the
// cred with error 401. We stop using the cred before that point so an
// in-flight TURN refresh (every ~5 min via pion) doesn't surprise us with
// a 401 mid-session, and we have enough headroom for the fresh-fetch path
// to finish (including a possible captcha solve, which can take many
// seconds on a hostile VK day).
//
// 30 min works out to ~7h 30m of usage on VK's typical 8h-validity creds —
// one fetch per cred-lifetime, no thrashing, plenty of margin if
// VK suddenly demands captcha during refresh.
const credExpiryBuffer = 30 * time.Minute

// parseCredExpiry extracts the expiry timestamp from a VK TURN cred Username.
// VK follows draft-uberti-behave-turn-rest: Username is
// "<unix_expiry_timestamp>:<key_id>". Returns (expiry, true) on parse success.
// On failure (malformed username) returns (zero, false) — caller should
// treat the slot as expired and refetch.
func parseCredExpiry(username string) (time.Time, bool) {
	idx := strings.IndexByte(username, ':')
	if idx <= 0 {
		return time.Time{}, false
	}
	ts, err := strconv.ParseInt(username[:idx], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(ts, 0), true
}

// vkCredentials holds a VK API client_id/client_secret pair.
type vkCredentials struct {
	ClientID     string
	ClientSecret string
}

// vkCredentialsList contains the VK app credentials for the legacy
// calls.getAnonymousToken rotation. Two client_id gives failover and spreads
// per-app rate-limiting / captcha frequency. Each minted anon session is a
// distinct cred (own ~10-allocation quota), so 2 client_id do NOT cap conns —
// the credpool mints many distinct creds by re-fetching.
//
// 2026-05-31 — full rework after the build-149 force-legacy on-device test
// minted 0 creds. Two findings, both harness-verified from our own IP (see
// 29.05.2026/proxy-turn-vk-android-1.2.2/go_client iptest_test.go MINT TEST):
//
//   1. Dropped 3 app_ids (52461373 VK_WEB_VKVIDEO, 52649896 VK_MVK_VKVIDEO,
//      51781872 VK_ID_AUTH): they return error_code 3 "Unknown method passed"
//      for calls.getAnonymousToken (method not exposed to those apps) — never
//      produced a cred, and the wasted attempts amplified VK's per-IP captcha
//      escalation (checkbox→slider→BOT).
//
//   2. Replaced our stale secrets. Our old secrets for 6287487
//      (QbYic1K3lEV5kTGiqlq2) and 7879029 (aR5NKGmm03GYrCiNKsaw) SOLVE the
//      captcha fine but then VK returns error_code 10 "Internal server error"
//      on the post-captcha getAnonymousToken MINT — the token1 they yield is
//      mint-invalid. amurcanov's secret for 6287487 (MuAxFaKDYDOICzGnEOhp) and
//      their 2nd app 8202606 BOTH mint a call token cleanly from the same
//      IP/method (verified 2026-05-31: MINT OK 2/2). So the method is NOT
//      sunset — our secrets were stale. Matched amurcanov's exact pair.
//      (7879029 dropped: no known-good secret; re-add if one is found.)
var vkCredentialsList = []vkCredentials{
	{ClientID: "6287487", ClientSecret: "MuAxFaKDYDOICzGnEOhp"}, // VK_WEB — amurcanov's current working secret
	{ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"}, // amurcanov's 2nd stable app_id
}

// CaptchaSolver is called when VK requires a captcha.
// It receives the captcha image URL and must return the user's answer.
// Returning an error aborts the credential fetch.
type CaptchaSolver func(imageURL string) (string, error)

// CaptchaRequiredError is returned when VK requires captcha and no solver is available.
type CaptchaRequiredError struct {
	ImageURL       string
	SID            string
	CaptchaTs      float64
	CaptchaAttempt float64
	Token1         string // step1 access_token — must be reused when retrying with captcha
	ClientID       string // VK app client_id — must be reused with savedToken1 (token1 is bound to this client_id)
	IsRateLimit    bool   // true when VK returned ERROR_LIMIT (PoW exhausted)
}

func (e *CaptchaRequiredError) Error() string {
	return fmt.Sprintf("captcha required: %s", e.ImageURL)
}

// TURNCreds holds TURN server credentials.
//
// Address vs Addresses: VK's vchat.joinConversationByLink response includes
// a turn_server.urls array — typically 2 endpoints on different /24 subnets
// (e.g. 91.231.135.146:19302 and 95.163.34.164:19302), confirmed by build
// 53 logging. Until then we took only urls[0]. We now parse all of them
// into Addresses for diagnostics and possible future failover. We do NOT
// rotate per-conn: iOS includeAllNetworks=true allows only one exempt
// host (NEVPNProtocol.serverAddress), and routing the second TURN
// endpoint through the tunnel collapses throughput to ~0.5 Mbps via
// recursive routing (observed in TunnelManager.swift:355 history).
// Address stays populated as Addresses[0] for back-compat with code that
// reads the singular field (cred caches, log strings, JSON marshaling).
type TURNCreds struct {
	Username  string
	Password  string
	Address   string   // host:port — primary address (= Addresses[0])
	Addresses []string // all VK-returned TURN endpoints, len >= 1
}

// isTransientNetworkError reports whether err looks like a transient network
// or DNS issue that may resolve itself within seconds. Empirically, on iOS
// the Network Extension's first DNS lookups right after startTunnel can fail
// with NXDOMAIN ("no such host") for the first ~30-100ms while the system
// resolver hasn't fully repointed at the physical Wi-Fi DNS yet — the same
// hostname resolves fine a second later. This predicate distinguishes those
// from genuine VK-side errors (HTTP 4xx/5xx, parse errors, etc.) so the
// retry loop in GetVKCreds only kicks in when retrying is plausibly useful.
func isTransientNetworkError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "network is unreachable") ||
		strings.Contains(s, "no route to host") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "connection reset")
}

// GetVKCreds fetches TURN credentials from VK using a call invite link ID.
// captchaSolver may be nil; if nil and captcha is required, an error is returned.
// solvedCaptchaSID/solvedCaptchaKey: if non-empty, are from a previous captcha solve.
// solvedCaptchaKey is the success_token from captchaNotRobot.check.
// solvedCaptchaTs/solvedCaptchaAttempt are from the original captcha error response.
// savedToken1: if non-empty, reuse this access_token from step1 instead of fetching a new one
// (the captcha is tied to the original step2 call which used this token1).
// savedClientID: if non-empty, restrict the call to the matching credentials entry
// (the saved token1 is bound to a specific client_id, so on a captcha-retry we MUST
// reuse the same client). When empty, the normal client_id rotation+shuffle applies.
func GetVKCreds(linkID string, captchaSolver CaptchaSolver, solvedCaptchaSID, solvedCaptchaKey string, solvedCaptchaTs, solvedCaptchaAttempt float64, savedToken1, savedClientID string) (*TURNCreds, error) {
	// Non-anonymous cookie (logged-in / "VKAuth") path. When the user enables
	// cookie auth in Settings, this is the ONLY path — there is NO fallback to
	// the anonymous VK Calls / legacy paths (the whole point is to keep working
	// when VK has disabled anonymous join, so falling back would defeat it). On
	// failure we return the error; a cookie REJECTION (ErrCookieRejected:
	// expired/invalid) is latched into the cookie-auth fatal state so the
	// extension can stop the tunnel with a clear "re-login" message instead of
	// spinning. Cookie auth never triggers captcha, so the savedToken1 /
	// solvedCaptcha* retry parameters never apply here. See creds_vkcookie.go.
	if cookieAuthEnabled.Load() {
		// Cookie (VKAuth) path. This entry (no slot) serves slot 0 — used by the
		// pre-bootstrap probe to seed slot 0. The pool's per-slot fetches go
		// through fetchFreshCreds -> cookieCredForSlot(slot) so each slot stably
		// holds a distinct (call, relay) bucket. Single-relay creds; NO captcha;
		// NO anonymous fallback.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		creds, err := cookieCredForSlot(ctx, 0)
		cancel()
		if err != nil {
			if errors.Is(err, ErrCookieRejected) {
				setCookieAuthFatal(err.Error())
			}
			return nil, fmt.Errorf("cookie auth: %w", err)
		}
		clearCookieAuthFatal()
		log.Printf("vk: success via cookie (logged-in) path (slot 0 seed)")
		return creds, nil
	}

	// VK Calls captcha-free path (added 2026-05-17 — see creds_vkcalls.go).
	//
	// Try this first on FRESH fetches only. Skip on captcha retry because:
	//   - savedToken1 is a login.vk.ru access_token bound to a vkCredentialsList
	//     client_id; VK Calls path uses a different VK Connect anonymous_token.
	//   - solvedCaptchaSID/Key are bound to a captchaNotRobot session that
	//     only exists on the legacy api.vk.ru/calls.getAnonymousToken path.
	// On any failure (including unexpected captcha gate appearing on the new
	// path), fall through to the legacy multi-client_id retry loop below.
	if savedToken1 == "" && solvedCaptchaSID == "" && savedClientID == "" {
		creds, err := getVKCredsViaVKCallsPath(linkID)
		if err == nil {
			log.Printf("vk: success via VK Calls captcha-free path")
			return creds, nil
		}
		log.Printf("vk: VK Calls path failed, falling back to legacy: %v", err)
	}

	// Outer retry loop guards against transient network/DNS errors at the very
	// start of an extension launch — see isTransientNetworkError. We only loop
	// if EVERY client_id failed with such an error in the same wave; as soon
	// as one client_id reaches VK and gets a real response (success, captcha,
	// or HTTP/parse error), the network is up and further retries are wasted.
	//
	// Budget: 12 attempts × 4s delay between waves = up to ~44s of waiting,
	// well within the wgWaitBootstrapReady 120s budget (which itself has to
	// cover captcha-solver time after DNS comes back). Empirically the iOS
	// resolver after an airplane-mode toggle can take 30-60s before login.vk.ru
	// resolves cleanly — a 21s budget (the previous 8×3s setting) was observed
	// to give up while DNS was still recovering. The wider window absorbs that
	// without forcing the user to manually retry Connect.
	const maxNetworkRetries = 12
	const retryDelay = 4 * time.Second

	// Build the credentials list to walk. Normally we shuffle the full list
	// for per-app rate-limiting reasons, but when retrying with a saved
	// captcha solution + saved token1 we MUST stick to the original
	// client_id (token1 is bound to it; trying with a different client_id
	// would make step2 reject the captcha).
	var baseCreds []vkCredentials
	if savedClientID != "" {
		for _, vc := range vkCredentialsList {
			if vc.ClientID == savedClientID {
				baseCreds = []vkCredentials{vc}
				log.Printf("vk: pinned to client_id=%s for captcha-retry", savedClientID)
				break
			}
		}
		if len(baseCreds) == 0 {
			return nil, fmt.Errorf("savedClientID %q not in vkCredentialsList", savedClientID)
		}
	}

	var lastErr error
	for retry := 0; retry < maxNetworkRetries; retry++ {
		var creds []vkCredentials
		if baseCreds != nil {
			// Pinned mode — single client_id, no shuffle.
			creds = baseCreds
		} else {
			// Rotate through client_id/client_secret pairs to reduce per-app rate limiting.
			// Shuffle the list so each connection attempt uses a different order.
			creds = make([]vkCredentials, len(vkCredentialsList))
			copy(creds, vkCredentialsList)
			// DIAGNOSTIC (standalone tools/captcha_test only): replace the
			// whole credential list with VK_TEST_CREDS="id:secret,id:secret"
			// to probe whether a different client_id/secret (e.g. another
			// fork's) changes VK's captcha type/verdict. Unset in production.
			if tc := os.Getenv("VK_TEST_CREDS"); tc != "" {
				var override []vkCredentials
				for _, pair := range strings.Split(tc, ",") {
					kv := strings.SplitN(strings.TrimSpace(pair), ":", 2)
					if len(kv) == 2 && kv[0] != "" && kv[1] != "" {
						override = append(override, vkCredentials{ClientID: kv[0], ClientSecret: kv[1]})
					}
				}
				if len(override) > 0 {
					creds = override
					log.Printf("vk: VK_TEST_CREDS override active — %d custom client_id(s)", len(override))
				}
			}
			// DIAGNOSTIC (2026-05-17 api.vk.me test): filter to one specific
			// client_id if VK_CLIENT_ID_ONLY env var is set. Used to isolate
			// which client_id is captcha-gated on api.vk.me. Remove after
			// experiment resolves.
			if only := os.Getenv("VK_CLIENT_ID_ONLY"); only != "" {
				filtered := creds[:0]
				for _, vc := range creds {
					if vc.ClientID == only {
						filtered = append(filtered, vc)
					}
				}
				creds = filtered
				if len(creds) == 0 {
					return nil, fmt.Errorf("VK_CLIENT_ID_ONLY=%q not in vkCredentialsList", only)
				}
				log.Printf("vk: VK_CLIENT_ID_ONLY filter active — using only client_id=%s", only)
			}
			mathrand.Shuffle(len(creds), func(i, j int) { creds[i], creds[j] = creds[j], creds[i] })
		}

		allTransient := true
		for credIdx, vc := range creds {
			log.Printf("vk: trying credentials %d/%d: client_id=%s", credIdx+1, len(creds), vc.ClientID)
			result, err := getVKCredsWithClientID(linkID, vc, captchaSolver, solvedCaptchaSID, solvedCaptchaKey, solvedCaptchaTs, solvedCaptchaAttempt, savedToken1)
			if err == nil {
				log.Printf("vk: success with client_id=%s", vc.ClientID)
				return result, nil
			}
			// If it's a CaptchaRequiredError (needs WebView), return immediately — don't try other client_ids
			if _, isCaptcha := err.(*CaptchaRequiredError); isCaptcha {
				return nil, err
			}
			log.Printf("vk: failed with client_id=%s: %v", vc.ClientID, err)
			lastErr = err
			if !isTransientNetworkError(err) {
				allTransient = false
			}
		}

		// At least one client_id got a non-transient response from VK — the
		// network is fine, the issue is on VK's side. No point in retrying.
		if !allTransient {
			break
		}

		if retry < maxNetworkRetries-1 {
			log.Printf("vk: all %d client_ids failed with transient network error, retrying in %s (network retry %d/%d)",
				len(creds), retryDelay, retry+1, maxNetworkRetries-1)
			time.Sleep(retryDelay)
		}
	}
	return nil, fmt.Errorf("all %d client_ids failed, last error: %w", len(vkCredentialsList), lastErr)
}

func getVKCredsWithClientID(linkID string, vc vkCredentials, captchaSolver CaptchaSolver, solvedCaptchaSID, solvedCaptchaKey string, solvedCaptchaTs, solvedCaptchaAttempt float64, savedToken1 string) (*TURNCreds, error) {
	// Phase 10 (build 105) session-unified identity:
	//
	// All bootstrap requests below (login.vk.ru, api.vk.ru, calls.okcdn.ru)
	// now go through the SAME bogdanfinn HttpClient (Phase 9 Safari TLS
	// profile + shared cookie jar) that captcha_pow.go's solveCaptchaPoW
	// uses. Phase 9 + UA were the captcha-solver-only ID; bootstrap kept
	// leaking uTLS Chrome + random Chrome UA. VK's 2026-05-15 detection
	// update started catching the mismatch as BOT.
	//
	// UA: captured Safari WKWebView UA from vk_profile.json (same one
	// that computed the captured browser_fp). Falls back to generic Safari
	// iOS for cold start (pre-first-WebView). Previously: randomUserAgent()
	// returned a random Chrome desktop UA every call — guaranteed identity
	// inconsistency across requests AND with the Safari TLS profile.
	ua := GetSessionUserAgent()
	name := generateName()
	escapedName := neturl.QueryEscape(name)
	log.Printf("vk: identity — name: %s, UA: %s (Phase 10 session-unified)", name, ua)

	// Per-fetch device_id. VK keys the anonymous call participant on
	// (device_id, link) — proven by the harness MINT TEST (2026-05-31): an
	// EMPTY device_id (our old behavior) made VK return the SAME anon token for
	// every fetch of a given client_id, so ALL credpool slots shared ONE
	// 10-allocation quota → 486 "Allocation Quota Reached" on every conn past
	// the first ~10 (the "stuck at 20/20" bug). A fresh UUID per fetch mints a
	// DISTINCT anon participant → distinct TURN cred → its own 10-quota, exactly
	// like the free path (creds_vkcalls.go threads device_id the same way).
	// Threaded into every VK-side call below (get_anonym_token, getCallPreview,
	// and all calls.getAnonymousToken variants). NOT the OK.ru anonymLogin
	// device_id (step 3 below) — that's a separate identity with its own uuid.
	//
	// On an external WebView captcha retry (solvedCaptchaSID set) this generates
	// a fresh device_id that won't match the success_token's original request;
	// VK rejects the stale token and the internal PoW loop re-solves a fresh
	// captcha against THIS device_id, so the fetch self-reconciles.
	deviceID := uuid.New().String()

	// Fresh HTTP client (fresh cookie jar) per fetch — the ACTUAL cure for the
	// 20/20 cap. VK keys the legacy calls.getAnonymousToken anon token on the
	// SESSION COOKIE (remixstid), not device_id; reusing the shared
	// GetSessionClient made every fetch return the SAME token → all credpool
	// slots shared ONE 10-allocation TURN quota → 486 past ~10 conns. A fresh
	// session per fetch = a distinct VK identity = a distinct cred with its own
	// quota (harness-proven 2026-05-31: shared jar → 1 token, fresh jar →
	// distinct). Used in doRequest below AND passed to solveCaptchaPoW so the
	// captcha is solved in the SAME session that issued it.
	fetchClient := newFreshSessionClient()

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := fetchClient // fresh per-fetch session (see fetchClient above) — NOT the shared singleton
		// fhttp.NewRequest (NOT std http.NewRequest) — bogdanfinn HttpClient
		// only accepts fhttp.Request. fhttp is bogdanfinn's fork of net/http
		// that integrates with their HTTP/2 implementation.
		req, err := fhttp.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		// Safari WKWebView header set — matches captcha_pow.go's vkReq
		// helper used for captchaNotRobot.*. Origin/Referer = id.vk.ru
		// because real Safari WebView captcha context loads from there;
		// VK API expects calls from that origin.
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Priority", "u=3, i")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-site")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpResp.Body.Close() }()

		// bogdanfinn auto-decompresses gzip; io.ReadAll yields plain bytes.
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, fmt.Errorf("unmarshal error: %w, body: %s", err, string(body))
		}
		return resp, nil
	}

	extractStr := func(resp map[string]interface{}, keys ...string) (string, error) {
		var cur interface{} = resp
		for _, k := range keys {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("expected map at key %q, got %T", k, cur)
			}
			cur = m[k]
		}
		s, ok := cur.(string)
		if !ok {
			return "", fmt.Errorf("expected string at end of path, got %T", cur)
		}
		return s, nil
	}

	// VK API version for the calls.* methods. Bumped 5.275 → 5.282 on 2026-06-24
	// (matching samosvalishe's working flow: const APIVersion = "5.282") as a
	// candidate fix for the post-captcha vchat.joinConversationByLink failure
	// (error.webrtc.auth.anonym_token.not_found) — the hypothesis is that a token
	// minted at the stale version isn't valid at join. Keep both calls.* in sync.
	step2URL := fmt.Sprintf("https://%s/method/calls.getAnonymousToken?v=5.282&client_id=%s", vkAPIHost(), vc.ClientID)

	// Step 1: get anonymous messages token
	// If savedToken1 is provided (captcha retry), reuse it instead of fetching a new one.
	var token1 string
	if savedToken1 != "" {
		token1 = savedToken1
		log.Printf("vk: reusing saved token1 for captcha retry")
	} else {
		data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s&device_id=%s", vc.ClientID, vc.ClientSecret, vc.ClientID, deviceID)
		resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
		if err != nil {
			return nil, fmt.Errorf("step1: %w", err)
		}
		token1, err = extractStr(resp, "data", "access_token")
		if err != nil {
			return nil, fmt.Errorf("step1 parse: %w", err)
		}
	}

	// Step 1.5: call getCallPreview (warms up the session, as in reference impl)
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&access_token=%s&device_id=%s", linkID, token1, deviceID)
	_, _ = doRequest(previewData, fmt.Sprintf("https://%s/method/calls.getCallPreview?v=5.282&client_id=%s", vkAPIHost(), vc.ClientID))

	// Step 2: get anonymous call token (with captcha retry)
	var token2 string
	var resp map[string]interface{}
	var err error
	step2Data := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&device_id=%s", linkID, escapedName, token1, deviceID)

	// buildCaptchaRetry builds the step2 body carrying a solved captcha. VK's
	// new error_code-14 format (2026-06-24) OMITS captcha_sid — it ships only
	// redirect_uri + session_token. So when sid is empty we send ONLY the
	// success_token and drop captcha_sid/captcha_key/ts/attempt (matching the
	// samosvalishe/cacggghp fix); an empty captcha_sid in the body confuses VK.
	buildCaptchaRetry := func(sid, successToken string, ts, attempt float64) string {
		if sid == "" {
			return fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&success_token=%s&device_id=%s",
				linkID, escapedName, token1, neturl.QueryEscape(successToken), deviceID)
		}
		return fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d&device_id=%s",
			linkID, escapedName, token1, sid, neturl.QueryEscape(successToken), ts, int(attempt), deviceID)
	}

	// If we have a pre-solved captcha (success_token), include it. Gate on the
	// success_token only — the new VK format has no captcha_sid to require.
	if solvedCaptchaKey != "" {
		log.Printf("vk: retrying step2 with success_token (%d chars), captcha_sid=%q", len(solvedCaptchaKey), solvedCaptchaSID)
		step2Data = buildCaptchaRetry(solvedCaptchaSID, solvedCaptchaKey, solvedCaptchaTs, solvedCaptchaAttempt)
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err = doRequest(step2Data, step2URL)
		if err != nil {
			return nil, fmt.Errorf("step2: %w", err)
		}

		// DIAGNOSTIC (2026-05-17 api.vk.me test): always dump step2 response
		// so we can see what api.vk.me returns differently from api.vk.ru.
		// Remove after the hypothesis is resolved.
		if respJSON, mErr := json.Marshal(resp); mErr == nil {
			log.Printf("vk: step2 response (host=%s, attempt=%d): %s", vkAPIHost(), attempt+1, string(respJSON))
		}

		// Check for captcha (VK error code 14)
		captchaSID, captchaImg, captchaTs, captchaAttempt := extractCaptcha(resp)
		// Gate on the captcha URL (redirect_uri), NOT captcha_sid: VK's new
		// error_code-14 format (2026-06-24) ships redirect_uri+session_token
		// with NO captcha_sid, so a sid-gate would skip the solver entirely.
		if captchaImg != "" {
			log.Printf("vk: captcha required (attempt %d), url: %s", attempt+1, captchaImg)

			// Try automatic PoW solver up to 3 times with fresh captcha sessions.
			const maxPoWRetries = 3
			powSolved := false
			currentImg := captchaImg
			currentSID := captchaSID
			currentTs := captchaTs
			currentAttempt := captchaAttempt
			var lastPowErr error
			// consecutiveEmptyShow tracks how many PoW attempts in a row came
			// back with show_captcha_type="" from the checkbox check — an
			// empirical signal that VK has no slider ready for this session.
			// After 2 such attempts in a row we short-circuit to WebView
			// instead of burning a third round-trip (saves ~3-5 seconds and
			// one captcha API call that just inflates VK's rate-limit bucket).
			consecutiveEmptyShow := 0

			for powTry := 1; powTry <= maxPoWRetries; powTry++ {
				log.Printf("vk: PoW attempt %d/%d", powTry, maxPoWRetries)
				powCtx, powCancel := context.WithTimeout(context.Background(), 30*time.Second)
				powToken, showType, powErr := solveCaptchaPoW(powCtx, fetchClient, currentImg, currentSID, ua)
				powCancel()
				lastPowErr = powErr

				if powErr == nil && powToken != "" {
					log.Printf("vk: PoW auto-solve succeeded on attempt %d (%d chars), retrying step2", powTry, len(powToken))
					step2Data = buildCaptchaRetry(currentSID, powToken, currentTs, currentAttempt)
					powSolved = true
					break
				}

				log.Printf("vk: PoW attempt %d/%d failed (show_captcha_type=%q): %v", powTry, maxPoWRetries, showType, powErr)

				// Track consecutive empty show_captcha_type — a non-empty
				// "slider" hint means VK is about to hand us an actual slider
				// (next attempt has a real chance); a persistently empty hint
				// means the slider isn't ready and retries are futile.
				if showType == "" {
					consecutiveEmptyShow++
				} else {
					consecutiveEmptyShow = 0
				}
				if consecutiveEmptyShow >= 2 {
					log.Printf("vk: %d consecutive attempts with show_captcha_type=\"\" — VK has no slider ready, skipping remaining attempts", consecutiveEmptyShow)
					break
				}

				if powTry < maxPoWRetries {
					freshData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&device_id=%s", linkID, escapedName, token1, deviceID)
					freshResp, freshErr := doRequest(freshData, step2URL)
					if freshErr != nil {
						log.Printf("vk: failed to get fresh captcha for PoW retry: %v", freshErr)
						break
					}
					fSID, fImg, fTs, fAttempt := extractCaptcha(freshResp)
					if fImg == "" {
						token2, err = extractStr(freshResp, "response", "token")
						if err == nil {
							powSolved = true
						}
						break
					}
					currentSID = fSID
					currentImg = fImg
					currentTs = fTs
					currentAttempt = fAttempt
					log.Printf("vk: got fresh captcha for PoW retry %d/%d", powTry+1, maxPoWRetries)
				}
			}

			if powSolved {
				continue
			}

			// All PoW attempts exhausted — surface CaptchaRequiredError so
			// the CALLER decides what to do. Depending on the caller the
			// error may end up (a) shown as a WebView to the user, or (b)
			// swallowed by credPool.get via fallback to another fresh
			// slot's cred. This function does not know which.
			isRateLimit := lastPowErr != nil && strings.Contains(lastPowErr.Error(), "ERROR_LIMIT")
			log.Printf("vk: all %d PoW attempts failed, returning CaptchaRequiredError to caller (rateLimit=%v)", maxPoWRetries, isRateLimit)

			// CRITICAL: PoW solver consumed the captchaNotRobot.* API calls on
			// the current session_token (`baseParams := "session_token=%s..."`
			// in captcha_pow.go uses the same token that's embedded in the
			// captcha page URL). If we hand currentImg/currentSID to a
			// WebView for user solve, VK responds ERROR_LIMIT to that WebView's
			// captchaNotRobot.check because the session is burned. Fetch ONE
			// MORE fresh captcha (untouched by PoW) for whoever consumes this
			// error — WebView or stats-derived UI.
			//
			// Without this fix, every WebView open produced ERROR_LIMIT
			// (audit of 27-28.04 logs: 22/22 captcha-view JS check responses
			// were ERROR_LIMIT, 0 success_tokens, 0 user-solved captchas).
			//
			// Note: VK captcha bundle (not_robot_captcha.js) does have
			// anti-bot tooling (sandbox iframe pure fetch check) but it's
			// for analytics instrumentation, not bot blocking. The actual
			// issue is purely session_token consumption.
			freshData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&device_id=%s", linkID, escapedName, token1, deviceID)
			if freshResp, freshErr := doRequest(freshData, step2URL); freshErr == nil {
				if fSID, fImg, fTs, fAttempt := extractCaptcha(freshResp); fImg != "" {
					log.Printf("vk: fetched untouched captcha for caller (was sid=%s, now sid=%s)", currentSID, fSID)
					currentSID = fSID
					currentImg = fImg
					currentTs = fTs
					currentAttempt = fAttempt
				}
			} else {
				log.Printf("vk: failed to fetch fresh captcha for caller (%v); returning burned one", freshErr)
			}

			if captchaSolver == nil {
				return nil, &CaptchaRequiredError{
					ImageURL:       currentImg,
					SID:            currentSID,
					CaptchaTs:      currentTs,
					CaptchaAttempt: currentAttempt,
					Token1:         token1,
					ClientID:       vc.ClientID,
					IsRateLimit:    isRateLimit,
				}
			}
			answer, err := captchaSolver(currentImg)
			if err != nil {
				return nil, fmt.Errorf("step2: captcha solver: %w", err)
			}
			log.Printf("vk: WebView captcha solver returned answer (%d chars), retrying", len(answer))
			step2Data = buildCaptchaRetry(currentSID, answer, currentTs, currentAttempt)
			continue
		}

		token2, err = extractStr(resp, "response", "token")
		if err != nil {
			return nil, fmt.Errorf("step2 parse: %w", err)
		}
		break
	}
	if token2 == "" {
		return nil, fmt.Errorf("step2: failed after 3 captcha attempts")
	}

	// Step 3: OK.ru anonymous login
	data := fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New())
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step3: %w", err)
	}
	token3, err := extractStr(resp, "session_key")
	if err != nil {
		return nil, fmt.Errorf("step3 parse: %w", err)
	}

	// Step 4: join conversation and get TURN creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", linkID, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("step4: %w", err)
	}

	// DIAGNOSTIC (2026-06-24): dump the raw okcdn join response so the standalone
	// tool (and on-device logs) show EXACTLY what calls.okcdn.ru returns for our
	// anonymToken — the wall is HERE (anonym_token.not_found), not the mint.
	// Mirrors the step2-response diagnostic above.
	if respJSON, mErr := json.Marshal(resp); mErr == nil {
		log.Printf("vk: step4 (okcdn vchat.joinConversationByLink) response: %s", string(respJSON))
	}

	user, err := extractStr(resp, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("step4 parse username: %w", err)
	}
	pass, err := extractStr(resp, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("step4 parse credential: %w", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("step4: turn_server not a map")
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok || len(urls) == 0 {
		return nil, fmt.Errorf("step4: turn_server.urls empty")
	}
	// VK's vchat.joinConversationByLink returns a turn_server.urls array —
	// confirmed in vpn.wifi.7.log (build 53) to contain 2 distinct endpoints
	// on different /24 subnets. Extract them all for downstream rotation
	// (proxy.resolveTURNAddr distributes conns round-robin).
	log.Printf("vk: turn_server.urls count=%d", len(urls))
	var addresses []string
	for i, u := range urls {
		s, ok := u.(string)
		if !ok {
			log.Printf("vk: turn_server.urls[%d]=<non-string %T> — skipping", i, u)
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		log.Printf("vk: turn_server.urls[%d]=%s", i, addr)
		addresses = append(addresses, addr)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("step4: no usable turn_server.urls (all non-string?)")
	}

	return &TURNCreds{
		Username:  user,
		Password:  pass,
		Address:   addresses[0],
		Addresses: addresses,
	}, nil
}

// --- credPool: per-conn TURN credential cache ---
//
// Ported from turnbridge's poolCreds:
//
//   Commit that introduced it:
//     https://github.com/nullcstring/turnbridge/commit/72cd1d4a8f04eec0e5e210388d415a84777cd2e6
//   Current version:
//     https://github.com/nullcstring/turnbridge/blob/main/wireguard-apple/Sources/WireGuardKitGo/turn_proxy.go
//     (function poolCreds, ~lines 602-647 at time of porting)
//
// Adaptations for this codebase:
// - Per-connection affinity: each conn has its own slot in the pool. When
//   a conn's cred goes stale (per-entry TTL), only that conn refetches,
//   leaving other conns' fresh creds untouched. This is the key property
//   that keeps the tunnel alive while one conn's refetch is stuck waiting
//   for the user to solve captcha.
// - Degraded-mode fallback: if a conn's own fetch fails (captcha or 403),
//   fall back to round-robin over ANY fresh entry so the conn can still
//   come back up using another conn's cred.
// - Per-entry TTL (each slot tracks its own ts) instead of turnbridge's
//   global "wipe when any entry is 10 min old". Entries refresh independently.

// credPoolEntry is one slot in the pool — either filled (creds != nil)
// or empty. Each slot tracks its own freshness and cooldown independently.
type credPoolEntry struct {
	addr  string
	creds *TURNCreds
	ts    time.Time // when this slot was last filled; zero for empty slots

	// cooldownUntil: if set and in the future, the slot is temporarily
	// "forbidden from fetching" because a previous fetch attempt failed
	// (typically CaptchaRequiredError). get() and the background grower
	// skip fetch for this slot until cooldownUntil passes — they fall
	// back to any fresh slot instead. This prevents one conn's persistent
	// captcha failures from pounding VK on every reconnect.
	cooldownUntil time.Time

	// fetching: a goroutine is currently doing a VK fetch to populate
	// this slot. Other goroutines (get / background grower) skip the
	// fetch path for this slot and fall back instead of duplicating work.
	fetching bool

	// active: number of conns currently using this slot's cred (i.e.
	// holding an active TURN allocation against it). VK enforces a strict
	// quota of 10 simultaneous allocations per cred set, so get() refuses
	// to hand out a cred whose active count is already 10 — even if the
	// slot is otherwise fresh — and the caller is steered to the next
	// available slot or to wait for one. The conn is responsible for
	// calling release() when the cred is no longer in use (typically when
	// the TURN session ends or the conn switches to a different slot).
	active int

	// availableAt is the earliest moment this slot's cred is safe to
	// hand out. Set by loadFromDisk when the on-disk lastUsedAt falls
	// within credSaturationCooldown of now: instead of dropping the
	// cred (forcing an expensive fresh VK fetch via PoW that can take
	// 10-30+ minutes when VK is hostile), we keep it in the pool but
	// mark it not-yet-usable until availableAt. entryIsFresh returns
	// false while now < availableAt, so get() Phase 1 ignores the slot
	// and pickSlotToFill skips it (background grower won't overwrite a
	// soon-available cred with a new fetch).
	//
	// Once availableAt passes (~10 min after the previous session's
	// last release), VK's lingering allocations have timed out
	// server-side and the cred is safe again. The slot becomes "fresh"
	// without any VK API call.
	//
	// Zero value means the cred is immediately usable (no pending
	// cooldown). Cleared on any successful fetch into this slot.
	availableAt time.Time

	// lastUsedAt is the most recent moment when this slot's `active`
	// count transitioned from >0 to 0 — i.e. the last conn to hold a
	// TURN allocation against this cred just released it. While `active`
	// is still >0 we don't update this field; saveToDisk substitutes
	// time.Now() in the persisted record so an in-flight session always
	// looks "active" to the next load even if no one called release()
	// yet (e.g. iOS jetsam'd the extension mid-session).
	//
	// Persisted to disk so loadFromDisk can decide per-entry whether
	// the cred is still potentially saturated by lingering VK-side
	// allocations: if (now - lastUsedAt) > ~10 min, all allocations
	// have timed out server-side and the cred is safe to reuse. If
	// lastUsedAt is the zero value (slot was filled by background
	// grower but no conn ever took it), the slot is safe regardless
	// of how recently the file was saved — this is the typical state
	// of the "+1 reserve" slot in the pool.
	lastUsedAt time.Time

	// saturatedUntil: VK-side quota saturation marker. When a runTURN
	// allocation fails with 486 Allocation Quota Reached, the cred is
	// marked as saturated by the proxy: VK still considers prior client-
	// side-killed allocations alive on this cred for the remainder of
	// their TURN lifetime (~600s default). Our local active count says 0
	// after we release them, but VK's count is still 10 → next Allocate
	// gets 486 immediately. Without this marker the proxy would loop on
	// the same cred forever; with it, get() Phase 1 skips saturated
	// slots and the conn falls through to Phase 2 (fetch a fresh cred
	// in another slot) or returns "no slot available" so the caller
	// backs off. Cleared automatically when the slot is replaced via
	// fresh fetch (since the new cred has a clean VK quota).
	saturatedUntil time.Time

	// saturationTimer fires broadcastSlotAvailable when saturatedUntil
	// passes, waking any conn currently parked in runConnection's
	// "no slot available" backoff so it can immediately retry on the
	// just-recovered slot. Without this, parked conns sleep through
	// their randomised 30s-3min dormancy regardless of when the
	// saturation actually expires — vpn.wifi.2.log on 2026-05-06
	// showed conn 0 idling 5 minutes past slot 0's expiry before its
	// next retry naturally fired. Set/Stopped+replaced by markSaturated;
	// nil for never-saturated slots and harmlessly-leaked-then-GC'd for
	// slots whose entry gets replaced before the timer fires.
	saturationTimer *time.Timer
}

// credCacheVersion is the on-disk JSON schema version. Loaders that find
// a different version log a warning and skip — caller falls through to
// fresh fetch as if no cache existed.
//
// Bumped to 2 on 2026-05-01: per-entry LastUsedAt added so loadFromDisk
// can decide saturation cooldown per-slot instead of per-file. The
// previous file-level cooldown was overly conservative — it skipped the
// whole cache (including the "+1 reserve" slot, which by design sits
// at active=0 and has zero VK-side allocations) whenever a recent
// session had touched ANY slot. Per-entry check loads the reserve and
// any other never-used / long-since-released slots while still
// skipping the genuinely saturated ones.
const credCacheVersion = 2

// credSaturationCooldown is the minimum gap from a slot's last release
// before we trust it on load. VK allows 10 concurrent TURN allocations
// per cred set with ~600s server-side lifetime. When a session ends,
// pion's Refresh(lifetime=0) over UDP is best-effort — VK frequently
// keeps the previous session's allocations live until they expire on
// their own. Loading a cred whose lastUsedAt is within that window
// would 486 every bootstrap allocation, and the extension can't
// recover before iOS kills it on startTunnel timeout.
//
// Slots with lastUsedAt == 0 (background-grower-filled but never used
// by any conn — typically the "+1 reserve" slot) are safe regardless
// of file age: VK has no allocations on them.
//
// vpn.wifi.9.log on 2026-05-01: reconnect 6 minutes after disconnect
// entered an infinite preparing → connecting → disconnecting loop
// because the only persisted slot (slot 0) was reused from cache and
// VK still had its 10 lingering allocations from the prior session.
const credSaturationCooldown = 10 * time.Minute

// credPeriodicSaveInterval keeps the on-disk file's per-slot
// lastUsedAt within ~1 minute of reality even when no fetch / invalidate
// events fire (steady state, no pool churn). Without this, an extension
// that ran cleanly for hours then got jetsam'd would leave the disk
// reflecting only the initial-startup save, with lastUsedAt frozen at
// "fetch time" — far enough in the past that the per-entry cooldown
// would mistakenly mark all slots as safe even though their
// allocations were still live until the kill moment.
const credPeriodicSaveInterval = 60 * time.Second

// vkSaturationCooldown is the SHORT cooldown applied when a slot's last
// in-use moment was long ago (no recent active allocations). The 486
// is most likely from VK-side residual session state which clears
// quickly, so a brief wait suffices. 3m chosen 2026-05-06 (commit
// f458389) over the original 10m to fix vpn.wifi.2.log's 14-min 0-conn
// window where parked conns slept past actual recovery time, and
// paired with markSaturated's broadcastSlotAvailable on expiry to wake
// them within milliseconds of cooldown end.
const vkSaturationCooldown = 3 * time.Minute

// vkActiveAllocationsCooldown is the LONG cooldown applied when 486
// hits a slot whose allocations were active very recently (lastUsedAt
// within `activeAllocationsWindow` ago). In that case the 486 isn't
// from cleared-up ghosts, it's because the slot's previous TURN
// allocations are STILL OCCUPYING VK's quota for their full ~600s
// lifetime. We must wait for them to actually expire server-side
// before retrying — otherwise we churn through the bootstrap retry
// budget hitting 486 every time.
//
// Demonstrated 2026-05-08 in vpn.wifi-lte-wifi.1.log: WiFi → LTE → office
// WiFi transition. 30 conns successfully allocated on LTE at
// 18:01:20-26; iOS killed those sockets ~13s later when the office
// WiFi appeared; bootstrap retried at 18:07:25-45 within the 10m
// window and got 486 again because VK still held the LTE-side
// allocations until ~18:11:30. Watchdog #1 fire was wasted; only
// watchdog #2 at 18:12:45 succeeded. With this cooldown the wasted
// retry burst would have been suppressed and watchdog #1 would have
// noticed slots still saturated, sparing the bootstrap budget.
//
// 11m = VK's worst-case 600s lifetime + ~1m safety so the retry burst
// after expiry doesn't race the last allocation's actual cleanup
// (token bucket, CGNAT mapping, etc).
const vkActiveAllocationsCooldown = 11 * time.Minute

// activeAllocationsWindow is the lastUsedAt threshold under which a 486
// is interpreted as "VK still holds our active allocations" (and dually,
// also the smart-pause threshold for marking a slot as having potentially
// live VK quota on path change).
//
// VK's TURN allocation lifetime is 600s from the LAST refresh, and pion
// refreshes every ~5min during a conn's life. So the latest allocation
// expiry timestamp is:
//
//   T_last_refresh + 600s, where T_last_refresh ∈ [T_conn_die - 5m, T_conn_die]
//
// Worst case (refresh fired just before death): T_conn_die + 600s = +10m.
// Our `lastUsedAt` is set when conn count drops to 0 (≈ T_conn_die for
// last conn in slot). So VK can hold a live allocation up to 10m past
// lastUsedAt in the worst case.
//
// Originally this window was 10m — exactly matching VK's lifetime with
// ZERO safety margin. Symptom (vpn.over24h.log 2026-05-13 15:26 outage):
// slots 3/4/5 had `lastUsedAt > 10m ago` so smart-pause skipped them at
// event 1, but pion's last refresh on those slots had been just before
// their lastUsedAt → VK allocations still alive ~1-2 min after our 10m
// threshold. 26 conns retried Allocate on slots 3/4/5 after smart-pause
// blocked 0/1/2, hit 486 (quota still occupied by previous-session
// allocations VK hadn't expired yet), markSaturated fired with reason
// "active-now, conns still hold slot". Cascade: all 12 slots saturated
// → 10-minute outage until cooldowns elapsed.
//
// 12m = 10m worst-case allocation lifetime + 2m buffer for VK processing
// + slot of conservatism. Cost: smart-pause may mark 1-2 extra slots per
// path change covering the 10-12m window. With pool=12 and typically
// only 3-6 slots active at any moment, this is acceptable.
const activeAllocationsWindow = 12 * time.Minute

// pauseAcquireAfterPathEvent is how long credPool.get() returns "paused"
// after each wgPathChanged call. iOS fires PathMonitor events in pairs
// on every physical interface swap (unsatisfied old-iface + satisfied
// new-iface) typically 130-365ms apart. Without this pause, conns dying
// from kernel error after the first event acquire fresh slots in the
// gap, then the second event's smart-pause catches those newly-active
// slots — burning 1 extra slot per transition (vpn.wifi-lte.0.log
// 2026-05-12 15:44:36-37: pool 6→2 instead of expected 6→3 on a single
// WiFi→LTE; slot 6 caught at the cellular-satisfied event because
// conns 27/22/23 had already migrated to it during the 356ms gap).
//
// 500ms covers typical iOS dual-event gap with margin. Pause is
// refreshed (extended) on each smart-pause call so longer event
// sequences keep the pool quiet through the whole transition. Conn
// retry loops see "credpool: paused for path-change settle" and back
// off, returning to acquire when the pause naturally expires.
const pauseAcquireAfterPathEvent = 500 * time.Millisecond

// cascadeDetectionWindow + cascadePauseDuration implement adaptive pause-
// acquire for multi-event path cascades (vs single iOS dual-event sequence).
//
// Single handover: one PathMonitor event (or iOS dual-event 130-365ms
// apart) → pauseAcquireAfterPathEvent (500ms) is enough.
//
// Multi-event cascade: WiFi → LTE → other-WiFi → LTE within ~30-60 seconds
// (e.g., walking past a known WiFi network while moving from indoor to
// outdoor coverage, or jittery cellular causing reconnect bouncing).
// Each event marks the slots holding active conns. Between events, conns
// redistribute onto OTHER fresh slots — the next event then marks those
// too. Result: pool wiped after 3-4 events.
//
// Observed multi-event cascades and their gaps:
//   2026-05-13 20:01-20:02 — gaps 46s, 27s
//   2026-05-14 19:43-19:45 — gaps 51s, 36s
//   2026-05-14 14:30      — gaps ~3s + ~3s (with iface=other in middle,
//                            handled by Variant B's 5s extended pause)
//
// On each path event we check `gap = now - lastPathEventAt`:
//
//   gap < 500ms                → iOS dual-event, normal pause refresh (500ms)
//   500ms ≤ gap < 90s           → CASCADE detected, set pause to 30s
//   gap ≥ 90s                  → isolated event, normal pause (500ms)
//
// 90s window comfortably covers observed real cascades with margin (typical
// gap 25-60s). 30s pause covers the time conns would otherwise redistribute
// onto fresh slots between events. After 30s of "no path event" we assume
// network has stabilized.
//
// Trade-off: zero impact on normal handovers (no preceding event in 90s
// window → regular 500ms). Only abnormal multi-event sequences pay the
// 30s acquire-block. Conn retry loops see "credpool: paused for path-
// change settle" and wait, then resume normally.
const cascadeDetectionWindow = 90 * time.Second
const cascadePauseDuration = 30 * time.Second

// credCacheFile is the JSON-on-disk shape persisted to App Group container.
// One file per pool. Contents are non-secret: VK TURN creds are session
// tokens with ~8h validity, sandbox-protected by App Group entitlement.
// Runtime state (saturatedUntil, cooldownUntil, active count, fetching)
// is intentionally excluded — those are per-process and shouldn't survive
// across launches.
type credCacheFile struct {
	Version int              `json:"version"`
	SavedAt int64            `json:"saved_at"`
	Creds   []credCacheEntry `json:"creds"`
}

type credCacheEntry struct {
	Slot     int    `json:"slot"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	// LastUsedAt is the most recent moment a conn was holding a TURN
	// allocation against this cred (Unix seconds, 0 = never used in
	// this session). Drives the per-entry saturation-cooldown check
	// in loadFromDisk. saveToDisk substitutes time.Now() for slots
	// that are currently active so a kill mid-session still records
	// "this slot was alive" rather than the last release time.
	LastUsedAt int64 `json:"last_used_at,omitempty"`
}

// credPool holds up to `size` independent TURN credential slots, one per
// connection index. Design:
//
//   - Lazy-first get(): callers prefer ANY fresh entry over blocking on a
//     VK fetch. Only when the pool has no fresh entry at all will a
//     caller invoke fetch inline.
//   - Per-slot cooldown: a failed fetch (captcha) puts that slot in
//     cooldown so subsequent get()s skip fetch and go straight to
//     fallback. After the cooldown expires the slot is eligible again.
//   - Background grower: a separate goroutine (see Proxy.growCredPool)
//     periodically picks an empty/stale slot and tries to fill it
//     without blocking any caller. That's how the pool grows to `size`
//     over time instead of at startup — which is what gave us the slow
//     ~100s serialized startup before.
//
// Thread safety: `mu` protects the pool slice and its entries. The VK
// fetch itself runs WITHOUT mu held (both get and tryFill drop the lock
// across the fetch call) so a long captcha solve on one slot cannot
// block fast-path get() calls on other conns' fresh slots.
type credPool struct {
	mu       sync.Mutex
	pool     []credPoolEntry // indexed by slot index; grown lazily up to size
	size     int             // pool capacity, derived from NumConns via poolSizeForNumConns
	cooldown time.Duration   // post-failure skip-fetch window (default 5m)

	// authErrors counts pion-reported 401/403 errors per slot since the
	// slot was last (re)filled. Reset to 0 on seedSlot, tryFill success,
	// and get's Phase 2 fetch success — i.e. anywhere a fresh cred lands
	// in the slot. Used by the pre-kill snapshot logging to attribute
	// mass kill events: if a slot has accumulated several auth errors
	// shortly before its conns die, the chain is "VK invalidated cred →
	// pion stops refreshing → allocation expires → conns silent → zombie
	// killer fires", and the cred should have been invalidated proactively.
	authErrors []atomic.Int64

	// freshLastTick records the entryIsFresh result per slot at the last
	// runPeriodicSave tick. logFreshTransitionsLocked compares current
	// against this snapshot and emits a log line for slots that flipped
	// out of fresh — these transitions are otherwise invisible because
	// entryIsFresh is a pure function whose result silently changes when
	// time.Now() crosses the credExpiryBuffer threshold relative to the
	// VK-encoded cred expiry. Without this log line, the UI's "available"
	// count drops without any explanation in the log stream (observed in
	// vpn.wifi-lte-wifi.1.log on 2026-05-12 — Pool went 8→7→6 over a
	// minute with zero markSaturated events because slots 9 and 11 were
	// crossing their 30m expiry-buffer thresholds silently).
	//
	// Kept under cp.mu like the rest of pool state.
	freshLastTick []bool

	// pauseAcquireUntil blocks credPool.get() with a "paused" error
	// while it's in the future. Set by MarkInUseSlotsForPathChange to
	// time.Now() + pauseAcquireAfterPathEvent on every path-change
	// event. Refreshed (extended) on each subsequent path event so a
	// dual-event iOS sequence (unsatisfied + satisfied within
	// 130-365ms) keeps the pool quiet through the whole transition.
	// See pauseAcquireAfterPathEvent comment for the full rationale.
	pauseAcquireUntil time.Time

	// pauseAcquireTimer fires broadcastSlotAvailable at pauseAcquireUntil
	// expiry so conns parked in runConnection's dormancy select wake up
	// the moment the pool unblocks, instead of sleeping out their full
	// dormantDuration. Without this, vpn.wifi-lte-wifi.1.log 2026-05-15
	// 13:03 cascade burned 4m20s waiting for the 5-min watchdog after
	// pauseAcquireUntil expired at +30s — every conn was sleeping in
	// dormancy with no signal that the credpool was ready.
	// (Re)armed by armPauseAcquireBroadcastLocked whenever pauseAcquire
	// Until is extended; idempotent (Stop+nil before re-arm).
	pauseAcquireTimer *time.Timer

	// lastPathEventAt is the timestamp of the most recent
	// MarkInUseSlotsForPathChange invocation. Used for adaptive cascade
	// detection: if a new path event fires within cascadeDetectionWindow
	// of this timestamp (and not within iOS dual-event range), we extend
	// pauseAcquireUntil by cascadePauseDuration instead of the default
	// 500ms — see cascadeDetectionWindow comment.
	lastPathEventAt time.Time

	// fetch is the underlying credential fetcher. It must do all the work
	// previously inlined in resolveTURNAddr: build solver + pending-captcha
	// params, call GetVKCreds, parse TURN host:port, publish turnServerIP.
	// Returns (address "host:port", creds, err). On CaptchaRequiredError
	// the pool may choose to fall back to an existing entry instead of
	// surfacing the error.
	fetch func(allowCaptchaBlock bool, slot int) (string, *TURNCreds, error)

	// cachePath is the on-disk JSON file that persists the pool across
	// extension launches. Empty disables persistence. The file lives in
	// the App Group container alongside vpn.log and is sandbox-protected
	// by the group entitlement. Contents (TURN session tokens, ~8h
	// validity) are not Keychain-grade sensitive.
	cachePath string

	// saveMu serializes disk writes. saveToDisk snapshots pool state under
	// cp.mu (briefly), then releases cp.mu and writes under saveMu — this
	// avoids holding cp.mu during the (potentially slow) filesystem write
	// while still preventing concurrent writers from racing on the .tmp
	// file before the atomic rename.
	saveMu sync.Mutex

	// slotAvailableCh is closed-and-replaced whenever a slot transitions
	// toward usable: a fresh cred is seeded/fetched into a slot
	// (seedSlot, tryFill, get's Phase 2 fetch), or a conn release lowers
	// active count below the per-slot cap (release). runConnection's
	// retry-after-failure select listens on this channel alongside its
	// fallback timeout, so a conn parked in "no slot available" backoff
	// — or even in the longer dormancy after 3 short failures — wakes
	// up within a few milliseconds of any pool-state change instead of
	// sleeping out its randomised delay.
	//
	// The "close on signal, swap in a new chan" pattern gives broadcast
	// semantics: every conn currently waiting on the channel reference
	// it captured wakes simultaneously when the old chan closes. A
	// buffered single-slot channel would only wake one waiter.
	//
	// Saturation expiry is also signalled here: markSaturated arms a
	// time.AfterFunc that calls broadcastSlotAvailable when the
	// saturation window passes, so a parked conn wakes within ms of
	// the slot becoming usable again instead of sleeping through its
	// randomised 30s-3min dormancy. (Before this, vpn.wifi.2.log on
	// 2026-05-06 showed conn 0 idling 5+ min past slot 0's 11:28
	// expiry before its own backoff naturally fired.)
	//
	// Reads/writes of the chan field are guarded by cp.mu; close itself
	// runs after unlock so close-while-locked stalls are impossible.
	slotAvailableCh chan struct{}
}

// poolSizeForNumConns derives the cred pool size from the configured
// number of tunnel connections.
//
// VK enforces a STRICT allocation quota of 10 simultaneous TURN
// allocations per cred set. This is not a refilling token bucket — once
// 10 allocations are in flight on a cred, the 11th attempt gets 486
// Allocation Quota Reached and stays 486 until one of the 10 active
// allocations is released (TTL expiry, network change invalidating the
// 5-tuple, or explicit close).
//
// Empirical confirmation in vpn.wifi.19.1.log:
//   - conns 0-9 used cred 0, established 23:42:39-41
//   - conns 11-15 came from cred 1 (a separate cred set fetched by the
//     pool's background grower 10+ minutes later); none of them succeeded
//     by retrying on cred 0, even after dozens of 486 attempts
//   - conn 10 also eventually landed on cred 1
//
// Earlier vpn.wifi.18.log showed the same pattern (conn 11+ used cred 3
// from background grower, not cred 0), but I misread the cred-suffix in
// the log line and concluded VK had a refilling per-cred bucket. That
// was wrong. The pool's previous formula (3 + (n-1)/20, committed in
// 260d8bc on this same misreading) is reverted here.
//
// Formula: ceil(n * 4 / 10) = ceil(n * 2 / 5). One cred per 10 conns
// (matches VK's hard quota) plus a 300% spare buffer for cascade
// recovery during network-path changes — survives up to 3 back-to-back
// transitions within one 10m30s smart-pause window.
//
// History — formula bumped twice in two days:
//
//   * 2026-05-10 build 70: ceil(n * 1.5 / 10) → ceil(n * 2.5 / 10).
//     The previous +50% buffer (3 working + 2 spare for typical N=30)
//     was empirically insufficient for rapid-flap saturation cascades.
//
//   * 2026-05-10 build 73: ceil(n * 2.5 / 10) → ceil(n * 4 / 10).
//     Build 72's smart-pause + pool=8 worked perfectly for SINGLE
//     transitions (vpn.wifi.3.log: WiFi→LTE recovery 7.5s, 0 quota
//     errors). But back-to-back transitions saturate disjoint slot
//     sets — vpn.wifi-lte-wifi.1.log on 2026-05-10 23:03 showed
//     LTE→WiFi (5 slots saturated) coming 6.5 min after WiFi→LTE
//     (5 slots saturated 10m30s) → ALL 8 slots locked, 4m09s outage
//     until first cohort's smart-pause expired. With pool=12 the
//     two transitions saturate 6 slots, leaving 6 fresh — survives.
//
// Why this works: VK's per-cred 486 quota is bound to allocation
// LIFETIME (server-side ~600s timer), not client actions — verified
// empirically 2026-05-10 with build 69's wgForceReconnect debug button
// (see evaluated_alternatives_pre_emptive_refresh.md). The only way
// to keep throughput during a path-cascade is to have enough fresh,
// never-used slots that VK has no allocations against.
//
// Capacity math for back-to-back transitions (N=30, ~3 active slots
// per phase): pool=12 absorbs 4 transitions before all-saturated;
// pool=8 absorbs 2 (overlapping into the 3rd-transition window).
// Three back-to-back transitions within ~10 min is rare enough that
// pool=12 covers practically all real-world scenarios.
//
// Examples (cred slots → max conns at 10/slot, of which N for live
//          conns, remainder are spare):
//   n=1..4   → 2 (clamped to 2 for refresh insurance)
//   n=5..7   → 4 (was 2 with old formula)
//   n=8..12  → 4-5
//   n=13..17 → 6-7
//   n=18..22 → 8-9
//   n=23..27 → 10-11
//   n=28..32 → 12 (typical NumConns=30: 3 for conns + 9 spare)
//   n=33..37 → 14
//   n=38..42 → 16-17
//   n=43..47 → 18-19
//   n=48..52 → 20 (typical NumConns=50: 5 for conns + 15 spare)
//
// Trade-off: each extra spare slot is one more cred VK needs to issue
// (PoW + slider, ~20-60 sec but happens in background after pre-bootstrap)
// and one more allocation-refresh pulse every ~5 min in steady state.
// Cold-start time is unaffected since pre-bootstrap fills only slot 0;
// the remaining slots fill asynchronously via background grower while
// the user is already browsing.
func poolSizeForNumConns(n int) int {
	if n <= 0 {
		n = 1
	}
	// ceil(n * 4 / 10) = ceil(n * 2 / 5) — integer math.
	size := (n*2 + 4) / 5
	if size < 2 {
		size = 2
	}
	return size
}

// newCredPool builds a pool sized to `size` conns with post-failure
// `cooldown` (the time a slot waits after a failed fetch before being
// eligible to retry). Per-entry freshness is derived from the cred's own
// VK-supplied expiry timestamp (encoded in Username), with a safety
// margin of credExpiryBuffer — see parseCredExpiry / isFreshLocked.
//
// seedSlot fills `slot` with externally-provided credentials. Used by
// NewProxy when the main app's pre-bootstrap captcha flow already obtained
// TURN creds via wgProbeVKCreds — we plant them in slot 0 so the first
// conn's get() returns them without any VK API call, avoiding the
// .connecting-window deadlock where a cold credPool would trigger another
// captcha request the main app can't service.
//
// If the slot already holds a fresh cred (e.g. loaded from disk on
// startup), the seed is ignored — the pre-existing cred is presumed
// equally valid and equally usable, so there's no point overwriting it.
// This is what makes "main app reads cache and uses cached cred as the
// pre-bootstrap seed" work cleanly: the cache-read in the app and the
// independent loadFromDisk in this pool both arrive at the same cred,
// and seedSlot recognizes that and no-ops.
func (cp *credPool) seedSlot(slot int, addr string, creds *TURNCreds) {
	cp.mu.Lock()
	if len(cp.pool) > slot && cp.isFreshLocked(slot) {
		cp.mu.Unlock()
		log.Printf("credpool: seed for slot %d ignored — slot already has a fresh cred (likely loaded from disk)", slot)
		return
	}
	for len(cp.pool) <= slot {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	// If the target slot already holds a pending cred (loaded from
	// disk, waiting on saturation cooldown) with a DIFFERENT cred set
	// than the seed, we'll move it aside instead of dropping it — it
	// might still become useful in 10 minutes. Slots vacated by the
	// dedup pass below are good targets for the relocation.
	var displaced *credPoolEntry
	if entry := cp.pool[slot]; entry.creds != nil && entry.creds.Username != creds.Username {
		copyEntry := entry
		displaced = &copyEntry
	}
	cp.pool[slot] = credPoolEntry{
		addr:  addr,
		creds: creds,
		ts:    time.Now(),
	}
	// Dedup: clear any OTHER slot holding the same VK cred set. This
	// happens when app-side reads creds-pool.json, picks an entry
	// (e.g. a never-used reserve slot) as the seed, and our own
	// loadFromDisk also loads that same entry into its original slot.
	// Without dedup the same cred ends up in two slots: pool count is
	// inflated, conns falling back to the duplicate slot compete for
	// the same VK 10-allocation quota, and background grower thinks
	// it has more cred sets than it really does.
	//
	// Username uniquely identifies a VK cred set per
	// draft-uberti-behave-turn-rest format (<expiry_unix>:<key_id>):
	// VK never reissues the same key_id+expiry tuple to a different
	// session, so equal usernames mean equal cred sets.
	duplicates := 0
	if creds != nil {
		for i := range cp.pool {
			if i == slot {
				continue
			}
			if cp.pool[i].creds != nil && cp.pool[i].creds.Username == creds.Username {
				cp.pool[i] = credPoolEntry{}
				duplicates++
			}
		}
	}
	// Relocate the pre-seed pending cred (if any) into the first now-
	// empty slot. We'd rather keep it pending and have it become
	// usable in 10 min than discard a perfectly good cred and pay
	// the VK PoW tax to refetch.
	relocatedTo := -1
	if displaced != nil {
		for i := range cp.pool {
			if cp.pool[i].creds == nil {
				cp.pool[i] = *displaced
				relocatedTo = i
				break
			}
		}
	}
	cp.mu.Unlock()
	if creds != nil {
		if exp, ok := parseCredExpiry(creds.Username); ok {
			log.Printf("credpool: seeded slot %d with externally-provided creds (addr=%s, expires in %s)",
				slot, addr, time.Until(exp).Round(time.Second))
		} else {
			log.Printf("credpool: seeded slot %d with externally-provided creds (addr=%s, malformed username — will refetch on first use)", slot, addr)
		}
		if duplicates > 0 {
			log.Printf("credpool: cleared %d duplicate slot(s) holding the same cred set as slot %d (disk-load + app-seed convergence)",
				duplicates, slot)
		}
		if relocatedTo >= 0 {
			log.Printf("credpool: relocated pre-seed pending cred from slot %d to slot %d (will become usable when its saturation cooldown expires)",
				slot, relocatedTo)
		} else if displaced != nil {
			log.Printf("credpool: pre-seed pending cred at slot %d had no empty slot to relocate to, dropped",
				slot)
		}
	}
	if creds != nil && slot >= 0 && slot < len(cp.authErrors) {
		// Fresh cred lands in this slot — reset the auth-error tally so
		// subsequent kill snapshots reflect only this cred's history.
		cp.authErrors[slot].Store(0)
	}
	cp.saveToDisk()
	// Wake any conn parked in "no slot available" backoff: a fresh seed
	// just placed a usable cred into the pool. Also covers the dedup-
	// relocate paths above — even if creds==nil (no-op seed), other
	// goroutines may benefit from a re-check.
	cp.broadcastSlotAvailable()
}

// recordAuthError increments the per-slot auth-error counter. Called from
// turnLogger.maybeFlagAuthError when pion logs a 401/403 from VK on this
// slot's allocation. Safe with slot==-1 (no-op).
func (cp *credPool) recordAuthError(slot int) {
	if slot < 0 || slot >= len(cp.authErrors) {
		return
	}
	cp.authErrors[slot].Add(1)
}

// authErrorCount returns the current accumulated auth-error count for the
// slot since it was last refilled. -1 for invalid slot.
func (cp *credPool) authErrorCount(slot int) int64 {
	if slot < 0 || slot >= len(cp.authErrors) {
		return -1
	}
	return cp.authErrors[slot].Load()
}

func newCredPool(ctx context.Context, size int, cooldown time.Duration, cachePath string, fetch func(bool, int) (string, *TURNCreds, error)) *credPool {
	if size < 1 {
		size = 1
	}
	if cooldown <= 0 {
		cooldown = 2 * time.Minute
	}
	cp := &credPool{
		size:      size,
		cooldown:  cooldown,
		cachePath: cachePath,
		fetch:     fetch,
		// Pre-size to `size` so later code (loadFromDisk, seedSlot,
		// the relocation loop in seedSlot, etc.) always sees the full
		// slot array with empty zero-entries in unused positions
		// rather than a truncated slice that hides real slots. Earlier
		// code grew the slice lazily with `for len(cp.pool) <= slot
		// { append... }`; that worked when callers always referenced
		// every slot eventually, but the seedSlot relocation loop had
		// no way to find an empty target slot if loadFromDisk only
		// populated slot 0 (cp.pool had len 1, so the loop saw only
		// the seed-target slot itself). Pre-sizing fixes that.
		pool:       make([]credPoolEntry, size),
		authErrors: make([]atomic.Int64, size),
		// Initial channel for the slot-available broadcast. Replaced
		// (and the old one closed) every time the pool changes in a
		// way that may unblock a parked conn — see broadcastSlotAvailable.
		slotAvailableCh: make(chan struct{}),
	}
	if cachePath != "" {
		cp.loadFromDisk()
		// Periodic-save goroutine keeps lastUsedAt fresh on disk so a
		// kill-mid-session leaves the file reflecting current activity.
		// See credPeriodicSaveInterval comment.
		go cp.runPeriodicSave(ctx)
	}
	log.Printf("credpool: initialized with %d slots (expiry-buffer=%s, cooldown=%s, cache=%q)", size, credExpiryBuffer, cp.cooldown, cachePath)
	return cp
}

// runPeriodicSave wakes every credPeriodicSaveInterval and re-snapshots
// the pool to disk. The snapshot stamps LastUsedAt = now for every
// currently-active slot so the on-disk view stays within ~1 minute of
// "what slots were last holding live VK allocations" even when no fetch
// or invalidate event fires (steady-state). Exits when ctx is cancelled.
func (cp *credPool) runPeriodicSave(ctx context.Context) {
	ticker := time.NewTicker(credPeriodicSaveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// Surface silent fresh→not-fresh transitions BEFORE saving.
			// Brief locked block; saveToDisk takes its own locks so we
			// release cp.mu first to avoid nesting.
			cp.mu.Lock()
			cp.logFreshTransitionsLocked()
			cp.mu.Unlock()
			cp.saveToDisk()
		case <-ctx.Done():
			// Final save on shutdown so any in-memory lastUsedAt
			// updates from release() since the last tick make it
			// to disk before the goroutine exits.
			cp.saveToDisk()
			return
		}
	}
}

// loadFromDisk populates the pool from cachePath (JSON written by a prior
// process). Skips entries whose username-encoded expiry has elapsed
// (with credExpiryBuffer margin), entries whose slot index exceeds the
// current pool size (handles users shrinking NumConns between launches),
// and the whole file on parse error or version mismatch — the pool just
// stays empty in those cases and the normal fetch path takes over.
//
// Called once from newCredPool before the proxy starts handing out conns,
// so no other goroutine is touching cp.pool yet — but we still take cp.mu
// for clarity and to satisfy isFreshLocked's lock-held precondition.
func (cp *credPool) loadFromDisk() {
	data, err := os.ReadFile(cp.cachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("credpool: load: read %s: %v", cp.cachePath, err)
		}
		return
	}
	var f credCacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("credpool: load: corrupt JSON in %s: %v — ignoring file", cp.cachePath, err)
		return
	}
	if f.Version != credCacheVersion {
		log.Printf("credpool: load: version %d != expected %d — ignoring file", f.Version, credCacheVersion)
		return
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := time.Now()
	loaded, skipped := 0, 0
	for _, entry := range f.Creds {
		if entry.Slot < 0 || entry.Slot >= cp.size {
			skipped++
			continue
		}
		creds := &TURNCreds{
			Username: entry.Username,
			Password: entry.Password,
			Address:  entry.Address,
		}
		exp, ok := parseCredExpiry(creds.Username)
		if !ok {
			log.Printf("credpool: load: slot %d malformed username, skipping", entry.Slot)
			skipped++
			continue
		}
		if exp.Sub(now) < credExpiryBuffer {
			log.Printf("credpool: load: slot %d expired or expiring within %s, skipping (expires in %s)",
				entry.Slot, credExpiryBuffer, time.Until(exp).Round(time.Second))
			skipped++
			continue
		}
		// Per-slot saturation. lastUsedAt == 0 means the slot was
		// filled but no conn ever took it (background-grower reserve
		// case) — VK has no allocations on this cred, immediately
		// usable. Otherwise compute when VK's lingering allocations
		// will have expired (lastUsedAt + credSaturationCooldown);
		// while now < availableAt the slot is loaded but PENDING,
		// not handed out to conns yet. This avoids the 486 cascade
		// (using cred while VK still has live allocations on it) WHILE
		// preserving a usable cred we'd otherwise discard — VK's PoW
		// fetch path takes 10-30+ min on hostile days, far longer than
		// the 10-min cooldown.
		var lastUsed, availableAt time.Time
		if entry.LastUsedAt > 0 {
			lastUsed = time.Unix(entry.LastUsedAt, 0)
			ready := lastUsed.Add(credSaturationCooldown)
			if now.Before(ready) {
				availableAt = ready
			}
		}
		for len(cp.pool) <= entry.Slot {
			cp.pool = append(cp.pool, credPoolEntry{})
		}
		cp.pool[entry.Slot] = credPoolEntry{
			addr:        entry.Address,
			creds:       creds,
			ts:          now,
			lastUsedAt:  lastUsed,
			availableAt: availableAt,
		}
		loaded++
		switch {
		case entry.LastUsedAt == 0:
			log.Printf("credpool: load: slot %d ready (addr=%s, expires in %s, never used in last session)",
				entry.Slot, entry.Address, time.Until(exp).Round(time.Second))
		case availableAt.IsZero():
			log.Printf("credpool: load: slot %d ready (addr=%s, expires in %s, last used %s ago — outside saturation window)",
				entry.Slot, entry.Address, time.Until(exp).Round(time.Second),
				now.Sub(lastUsed).Round(time.Second))
		default:
			log.Printf("credpool: load: slot %d pending (addr=%s, expires in %s, last used %s ago — usable in %s once VK allocations expire)",
				entry.Slot, entry.Address, time.Until(exp).Round(time.Second),
				now.Sub(lastUsed).Round(time.Second),
				availableAt.Sub(now).Round(time.Second))
		}
	}
	log.Printf("credpool: loaded %d slots from disk (%d skipped); file saved at %s",
		loaded, skipped, time.Unix(f.SavedAt, 0).Format(time.RFC3339))
}

// saveToDisk snapshots the pool's filled slots and writes them to
// cachePath via tmp+rename. Called from any code path that mutates
// pool[].creds: seedSlot (slot 0 from app), tryFill / get's fetch
// branches (background grower and inline fetch), invalidateEntry (after
// a 401/403 drops a slot — the next snapshot just won't include it).
//
// Snapshot is taken under cp.mu (brief), but the actual file write runs
// under saveMu only — we don't want to block credPool callers on disk
// I/O. Two concurrent fetches completing simultaneously will serialize
// here without trampling each other's .tmp file.
func (cp *credPool) saveToDisk() {
	if cp.cachePath == "" {
		return
	}

	now := time.Now()
	cp.mu.Lock()
	f := credCacheFile{
		Version: credCacheVersion,
		SavedAt: now.Unix(),
	}
	for slot, entry := range cp.pool {
		if entry.creds == nil {
			continue
		}
		// For active slots stamp LastUsedAt as "now" — the slot is
		// holding live VK allocations at this very moment, which is the
		// most recent ground truth we have. release() will update the
		// in-memory lastUsedAt when active drops to 0; until then the
		// in-memory value may be stale (e.g. zero for a slot that was
		// filled by background grower and is currently in active use).
		var lastUsed int64
		if entry.active > 0 {
			lastUsed = now.Unix()
		} else if !entry.lastUsedAt.IsZero() {
			lastUsed = entry.lastUsedAt.Unix()
		}
		f.Creds = append(f.Creds, credCacheEntry{
			Slot:       slot,
			Address:    entry.addr,
			Username:   entry.creds.Username,
			Password:   entry.creds.Password,
			LastUsedAt: lastUsed,
		})
	}
	cp.mu.Unlock()

	cp.saveMu.Lock()
	defer cp.saveMu.Unlock()

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Printf("credpool: save: marshal: %v", err)
		return
	}

	tmpPath := cp.cachePath + ".tmp"
	// Best-effort cleanup: remove any tmp file left from a prior crash.
	// Ignore errors — WriteFile below will fail loud if anything's
	// genuinely wrong with the directory.
	_ = os.Remove(tmpPath)
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		log.Printf("credpool: save: write %s: %v", tmpPath, err)
		return
	}
	if err := os.Rename(tmpPath, cp.cachePath); err != nil {
		log.Printf("credpool: save: rename %s -> %s: %v", tmpPath, cp.cachePath, err)
		_ = os.Remove(tmpPath)
		return
	}
	// Ensure the directory entry hits the disk too — on iOS App Group
	// containers the parent directory's metadata write isn't always
	// flushed by rename alone. Best-effort, log only.
	if dir, err := os.Open(filepath.Dir(cp.cachePath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	log.Printf("credpool: saved %d slots to disk", len(f.Creds))
}

// get returns (addr, creds, credSlot, err) for the given connIdx.
// credSlot identifies which pool slot's creds were ultimately used —
// may equal connIdx (own slot) or some other index (fallback).
// credSlot < 0 iff err != nil.
//
// Semantics, in priority order:
//  1. pool[connIdx] fresh → return it (no VK call).
//  2. Any other pool slot fresh → fallback to round-robin over fresh
//     slots (no VK call). This is the key change: we don't try to fetch
//     into pool[connIdx] when a working cred is already available, so
//     startup is fast and VK is not pressed for multiple captchas.
//  3. No fresh slot, and pool[connIdx] is on cooldown → surface an
//     error so the caller's reconnect loop can back off.
//  4. No fresh slot, no cooldown → inline fetch (releases mu during the
//     VK call). On success, fills pool[connIdx]. On failure, sets
//     cooldown on pool[connIdx] and re-checks for fresh fallback (some
//     other goroutine may have filled one while we were fetching).
// connsPerSlot is VK's hard quota of simultaneous TURN allocations on
// one cred set. Confirmed empirically: vpn.wifi.19.1.log showed conn
// 0-9 saturating cred 0, with conn 10+ ONLY succeeding on a separate
// cred set fetched into a different pool slot — even after 10+ minutes
// of retries on cred 0. So this is a strict cap, not a refilling
// bucket. The pool tracks per-slot active count and refuses to hand
// out a saturated slot's cred.
const connsPerSlot = 10

// pickAcquireSlotLocked picks the best slot for connIdx to acquire, or
// returns -1 if no slot is usable. Caller must hold cp.mu.
//
// Selection priority:
//  1. ownSlot if fresh + has capacity + not VK-saturated.
//  2. Among other fresh + capacity + non-saturated slots, the one with
//     the highest active count (compact-fill: consolidate conns onto
//     already-in-use slots so each path-change event marks fewer slots).
//  3. If no candidate has active>0 (all idle), the lowest-index idle
//     candidate — same order the prior implementation used.
//
// kind classifies the choice for the caller's log line: "own",
// "compact", or "fresh" (or "" if no slot found).
//
// logSkips=true emits per-slot "skipping (VK-saturated)" log lines for
// slots passed over due to active saturation cooldowns. Pass false on
// the post-fetch retry path to avoid duplicating log lines the initial
// scan already produced.
//
// Compact-fill rationale: MarkInUseSlotsForPathChange (smart-pause)
// marks EVERY slot with active>0 on each PathMonitor event. Spreading
// 30 conns across 7 slots costs 7 marks per event; clustering on the
// optimal 3 costs 3. Compact-fill keeps the spread near the floor of
// ceil(NumConns/connsPerSlot), so the pool survives more back-to-back
// cascades before all-saturated. See open_improvement_compact_fill in
// memory for the empirical context (build 87, 2026-05-14).
func (cp *credPool) pickAcquireSlotLocked(connIdx, ownSlot int, logSkips bool) (int, string) {
	now := time.Now()

	// Priority 1: ownSlot, unconditionally preferred when usable.
	if cp.isFreshLocked(ownSlot) && cp.pool[ownSlot].active < connsPerSlot {
		if now.Before(cp.pool[ownSlot].saturatedUntil) {
			if logSkips {
				log.Printf("credpool: conn %d skipping slot %d (VK-saturated for %s more)",
					connIdx, ownSlot, cp.pool[ownSlot].saturatedUntil.Sub(now).Round(time.Second))
			}
		} else {
			return ownSlot, "own"
		}
	}

	// Priority 2/3: scan other slots, picking max-active (compact-fill)
	// or the lowest-index idle slot when all candidates have active=0.
	bestSlot := -1
	bestActive := -1
	for i := 0; i < cp.size; i++ {
		if i == ownSlot {
			continue
		}
		if !cp.isFreshLocked(i) || cp.pool[i].active >= connsPerSlot {
			continue
		}
		if now.Before(cp.pool[i].saturatedUntil) {
			if logSkips {
				log.Printf("credpool: conn %d skipping slot %d (VK-saturated for %s more)",
					connIdx, i, cp.pool[i].saturatedUntil.Sub(now).Round(time.Second))
			}
			continue
		}
		// Strict > keeps the lowest-index slot when active counts tie
		// (iteration order is ascending).
		if cp.pool[i].active > bestActive {
			bestSlot = i
			bestActive = cp.pool[i].active
		}
	}
	if bestSlot < 0 {
		return -1, ""
	}
	if bestActive > 0 {
		return bestSlot, "compact"
	}
	return bestSlot, "fresh"
}

func (cp *credPool) get(connIdx int, allowCaptchaBlock bool) (string, *TURNCreds, int, error) {
	cp.mu.Lock()

	// Path-change pause: while pauseAcquireUntil is in the future, refuse
	// new acquires so conn-retry-loops don't grab fresh slots in the gap
	// between iOS's dual PathMonitor events. See pauseAcquireAfterPathEvent
	// constant for the rationale. Conns see this error in their retry
	// loop, back off briefly, and try again after the pause expires.
	if !cp.pauseAcquireUntil.IsZero() && time.Now().Before(cp.pauseAcquireUntil) {
		remaining := time.Until(cp.pauseAcquireUntil).Round(time.Millisecond)
		cp.mu.Unlock()
		return "", nil, -1, fmt.Errorf("credpool: paused for path-change settle, %s remaining", remaining)
	}

	// ownSlot is the slot this conn would prefer to live on, by
	// distributing N conns across ceil(N/10) cred sets — slot 0 hosts
	// conn 0-9, slot 1 hosts conn 10-19, etc. This is a preference,
	// not a strict binding: if ownSlot isn't ready (empty, on cooldown,
	// being fetched, or saturated), the conn happily uses any other
	// slot with quota room.
	ownSlot := connIdx / connsPerSlot
	if ownSlot < 0 {
		ownSlot = 0
	}
	if ownSlot >= cp.size {
		ownSlot = cp.size - 1
	}
	// Make pool[ownSlot] addressable.
	for len(cp.pool) <= ownSlot {
		cp.pool = append(cp.pool, credPoolEntry{})
	}

	// candidatesOrdered enumerates pool slots starting with ownSlot
	// (preference), then the others in index order. Used by Phase 2
	// (fetch-target picking) below. Phase 1's acquire path uses
	// pickAcquireSlotLocked instead — it implements compact-fill,
	// which candidatesOrdered cannot express on its own.
	candidatesOrdered := func() []int {
		out := make([]int, 0, cp.size)
		out = append(out, ownSlot)
		for i := 0; i < cp.size; i++ {
			if i != ownSlot {
				out = append(out, i)
			}
		}
		return out
	}

	// Phase 1: any fresh slot with quota room? Prefer ownSlot; when
	// ownSlot isn't usable, fall back via compact-fill (consolidate
	// onto already-active slots) instead of first-by-index. See
	// pickAcquireSlotLocked for the selection logic + rationale (each
	// path event marks fewer slots when conns cluster).
	if slot, kind := cp.pickAcquireSlotLocked(connIdx, ownSlot, true); slot >= 0 {
		cp.pool[slot].active++
		e := cp.pool[slot]
		cp.mu.Unlock()
		var tag string
		switch kind {
		case "own":
			tag = "own slot"
		case "compact":
			tag = "fallback compact-fill"
		default: // "fresh"
			tag = "fallback fresh slot"
		}
		log.Printf("credpool: conn %d acquired slot %d (%s, active=%d/%d, age %s)",
			connIdx, slot, tag, e.active, connsPerSlot, time.Since(e.ts).Round(time.Second))
		return e.addr, e.creds, slot, nil
	}

	// Phase 2 cold-start cap: don't let a COLD pool get over-fetched. When the
	// pool starts empty (fresh install, or after a Settings "reset creds") and
	// all NumConns race into get() at once with zero creds, only the first
	// ~ceil(NumConns/connsPerSlot) conns should fetch a cred; the rest must PARK
	// and SHARE those once they land (woken via slotAvailableCh /
	// broadcastSlotAvailable), instead of each grabbing its own empty reserve
	// slot. Without this cap every racing conn fetches into a distinct empty
	// slot → the whole pool is over-provisioned → many creds get allocated at a
	// burst rate → VK 486 "Allocation Quota Reached" → a self-perpetuating
	// saturation cascade that leaves the surplus conns permanently unable to
	// connect (observed 2026-05-30/31 after a reset-creds + forced-legacy test:
	// 30 conns cold-started empty → over-fetched 12 slots → stuck 20/20).
	//
	// "provisioned" = creds we already hold (usable, any saturation state) +
	// creds in flight (fetching). coldStartTarget ≈ ceil(NumConns/connsPerSlot),
	// recovered from the pool size (size = ceil(NumConns*4/10) ⇒ ceil(size/4)).
	// When provisioned already covers the target we have/will-have enough creds
	// to host every conn at quota, so a conn that found no usable slot in
	// Phase 1 parks: a slot opens up (a fetch completes, or a saturated slot's
	// cooldown expires → broadcastSlotAvailable) and the conn shares it via the
	// normal Phase-1 acquire on retry. This aligns conn-driven fetches with the
	// grower's existing cold-start target (growCredPool) — the grower still
	// fills reserve slots beyond the target, but slowly + staggered.
	{
		usable := cp.countWithUsableCredsLocked()
		inFlight := 0
		for i := range cp.pool {
			if cp.pool[i].fetching {
				inFlight++
			}
		}
		coldStartTarget := (cp.size + 3) / 4 // ceil(size/4) ≈ ceil(NumConns/connsPerSlot)
		if coldStartTarget < 1 {
			coldStartTarget = 1
		}
		if usable+inFlight >= coldStartTarget {
			cp.mu.Unlock()
			return "", nil, -1, fmt.Errorf("credpool: cold-start cap (%d usable+inflight >= %d target) — parking to share instead of over-fetching", usable+inFlight, coldStartTarget)
		}
	}

	// Phase 2: no usable fresh slot. Pick a fetch target — first
	// candidate that's not fresh AND not pending AND not on cooldown
	// AND not already being fetched. Prefer ownSlot here too. Skipping
	// fresh-saturated slots is critical: replacing the cred there
	// would orphan the 10 conns currently bound to it. Skipping
	// pending slots avoids overwriting a disk-loaded cred that's about
	// to become available on its own — a wasted VK fetch (and likely
	// captcha attempt) for no benefit.
	now := time.Now()
	target := -1
	for _, slot := range candidatesOrdered() {
		if cp.isFreshLocked(slot) {
			continue // saturated-fresh, must not be replaced
		}
		if entryIsPending(cp.pool[slot]) {
			continue // disk-loaded, waiting on saturation cooldown
		}
		if now.Before(cp.pool[slot].cooldownUntil) {
			continue
		}
		if cp.pool[slot].fetching {
			continue
		}
		target = slot
		break
	}

	if target == -1 {
		// Every slot is either saturated, on cooldown, or being fetched
		// by someone else. Return a descriptive error so the caller's
		// reconnect loop knows to back off and try again later.
		cp.mu.Unlock()
		return "", nil, -1, fmt.Errorf("credpool: no slot available (all saturated, cooling down, or fetching)")
	}
	cp.pool[target].fetching = true
	cp.mu.Unlock()

	// Inline fetch — runs WITHOUT mu so get() on other slots stays fast.
	addr, creds, fetchErr := cp.fetch(allowCaptchaBlock, target)

	cp.mu.Lock()
	cp.pool[target].fetching = false
	if fetchErr == nil {
		// Replacing an empty/stale slot — active was 0, now 1 (us).
		cp.pool[target] = credPoolEntry{addr: addr, creds: creds, ts: time.Now(), active: 1}
		filled := cp.countFreshLocked()
		cp.mu.Unlock()
		log.Printf("credpool: conn %d fetched fresh cred into slot %d (%d/%d slots filled)",
			connIdx, target, filled, cp.size)
		if target >= 0 && target < len(cp.authErrors) {
			cp.authErrors[target].Store(0)
		}
		cp.saveToDisk()
		// Inline fetch placed a fresh cred into a previously empty/
		// stale slot. The current conn took capacity 1/connsPerSlot;
		// the remaining connsPerSlot-1 slots of capacity are open for
		// other parked conns that lost the race for ownSlot.
		cp.broadcastSlotAvailable()
		return addr, creds, target, nil
	}

	// Fetch failed. Set cooldown on the target so we don't hammer it
	// every reconnect. Then check once more for a fresh-and-available
	// slot — background grower may have filled one while we were
	// blocked on VK.
	cp.pool[target].cooldownUntil = time.Now().Add(cp.cooldown)
	// Compact-fill applies here too: if the grower or another conn
	// filled a slot during our fetch window, prefer the most-active
	// one. logSkips=false because Phase 1's initial scan already
	// emitted any per-slot "VK-saturated" lines for these slots.
	if slot, kind := cp.pickAcquireSlotLocked(connIdx, ownSlot, false); slot >= 0 {
		cp.pool[slot].active++
		e := cp.pool[slot]
		cp.mu.Unlock()
		var tag string
		switch kind {
		case "own":
			tag = "own slot"
		case "compact":
			tag = "fallback compact-fill"
		default: // "fresh"
			tag = "fallback fresh slot"
		}
		log.Printf("credpool: conn %d fetch into slot %d failed (%v), falling back to slot %d (%s, active=%d/%d, age %s), cooldown %s",
			connIdx, target, fetchErr, slot, tag, e.active, connsPerSlot, time.Since(e.ts).Round(time.Second), cp.cooldown)
		return e.addr, e.creds, slot, nil
	}
	cp.mu.Unlock()
	log.Printf("credpool: conn %d fetch into slot %d failed and no fallback available: %v (cooldown %s)",
		connIdx, target, fetchErr, cp.cooldown)
	return "", nil, -1, fetchErr
}

// release decrements the active conn count on slot, signaling that the
// caller is no longer using its cred. Must be paired with a successful
// get() on the same slot. Idempotent for invalid slot indices (e.g. -1
// from a get() that errored out).
//
// When active drops to zero we stamp lastUsedAt with the current time —
// that's the latest moment we can be sure the slot was carrying live
// VK-side allocations. saveToDisk persists this so the next launch can
// decide per-slot whether enough time has passed for those allocations
// to have expired server-side (~10 min lifetime) before reusing the
// cred. See loadFromDisk's per-entry cooldown check.
func (cp *credPool) release(slot int) {
	if slot < 0 {
		return
	}
	cp.mu.Lock()
	if slot >= cp.size || slot >= len(cp.pool) {
		cp.mu.Unlock()
		return
	}
	// Decide whether this release will genuinely open a usable slot for
	// a parked conn. Three conditions must all hold; if any fails the
	// broadcast is a thundering-herd waste because get()'s Phase 1 would
	// skip the slot for the same reason that made the broadcast useless:
	//
	//   1. Slot was at the per-slot cap before this release. Otherwise
	//      it already had room and conns weren't blocked on it.
	//   2. entryIsFresh — slot's cred isn't expired/expiring/pending.
	//      Observed in vpn.wifi.5.log: slot 0's cred crossed the 30m
	//      expiry buffer ~4 min after startup; without this guard, every
	//      conn dying on that now-stale slot would wake 10 parked conns
	//      just to have them re-park (slot 0 not fresh → skipped).
	//   3. Not VK-saturated — get()'s Phase 1 explicitly skips saturated
	//      slots even when fresh and below cap.
	slotBecomesUsable := cp.pool[slot].active == connsPerSlot &&
		entryIsFresh(cp.pool[slot]) &&
		!time.Now().Before(cp.pool[slot].saturatedUntil)
	if cp.pool[slot].active > 0 {
		cp.pool[slot].active--
		if cp.pool[slot].active == 0 {
			cp.pool[slot].lastUsedAt = time.Now()
		}
	}
	cp.mu.Unlock()
	if slotBecomesUsable {
		cp.broadcastSlotAvailable()
	}
}

// markSaturated marks slot as VK-side quota-saturated until time.Now()+
// duration. Phase 1 of get() will skip the slot during this window even
// if it's otherwise fresh — the cred is fine, but VK still has lingering
// allocations from before that prevent us from acquiring new ones.
//
// Called by the proxy's reconnect path when runTURN fails with 486
// Allocation Quota Reached. The duration is typically vkSaturationCooldown
// (3m) — long enough to let most ghost allocations time out server-side,
// short enough to retry well within VK's full ~600s TURN lifetime. If
// we're still hitting 486 after the cooldown, the next failure re-marks.
//
// Schedules a timer that calls broadcastSlotAvailable on expiry so any
// conn currently parked in runConnection's dormancy select wakes up the
// instant the slot recovers, instead of sleeping through the rest of its
// randomised 30s-3min back-off (which observably wasted 5+ min in
// vpn.wifi.2.log on 2026-05-06). Re-arming a still-pending timer Stops
// the old one first; spurious fires from already-replaced entries are
// harmless (broadcastSlotAvailable tolerates them by design).
//
// saturationSnapshot returns (saturatedCount, totalSlots, longestCooldownRemaining).
// Used by bootstrap to log a single clear diagnostic when all retry attempts
// failed because the entire pool is in 486 cooldown — without this, the log
// shows N independent "[conn X] TURN allocate quota error" lines and the
// reader has to manually correlate them. Locks cp.mu briefly.
func (cp *credPool) saturationSnapshot() (saturated, total int, longest time.Duration) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	now := time.Now()
	total = cp.size
	for i := 0; i < cp.size && i < len(cp.pool); i++ {
		until := cp.pool[i].saturatedUntil
		if until.After(now) {
			saturated++
			remaining := until.Sub(now)
			if remaining > longest {
				longest = remaining
			}
		}
	}
	return
}

// Idempotent for invalid slot indices. Returns the chosen cooldown
// duration so the caller can log it; zero return means the slot index
// was invalid and nothing was marked.
//
// Cooldown is adaptive based on slot's current activity and lastUsedAt:
//   - If slot has active>0 right now (conns still holding it), or
//     lastUsedAt is within `activeAllocationsWindow`, VK's quota is
//     genuinely full of our allocations and we wait
//     `vkActiveAllocationsCooldown` (11m, matching VK's ~600s TURN
//     allocation lifetime + safety).
//   - Otherwise the 486 is most likely residual session state from
//     other clients on the same client_id (rare, but possible), and
//     the shorter `vkSaturationCooldown` (3m) suffices.
//
// Note vpn.wifi-lte-wifi.2.log (build 60) revealed the active>0 check
// matters: during a path change, conns die and IMMEDIATELY re-acquire
// the slot before active ever drops to 0. lastUsedAt may never have
// been set since cred fetch (it's only updated on active 10→0
// transitions), so a check based purely on lastUsedAt picked
// "ghost-likely" 3m for slots that genuinely had VK-side allocations
// in flight from milliseconds-ago use.
func (cp *credPool) markSaturated(slot int) time.Duration {
	if slot < 0 {
		return 0
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if slot >= cp.size || slot >= len(cp.pool) {
		return 0
	}

	entry := cp.pool[slot]
	age := time.Since(entry.lastUsedAt)
	hasRecentLastUsed := !entry.lastUsedAt.IsZero() && age < activeAllocationsWindow

	cooldown := vkSaturationCooldown
	reason := "ghost-likely (no active conns and lastUsedAt not in active window)"
	if entry.active > 0 {
		cooldown = vkActiveAllocationsCooldown
		reason = fmt.Sprintf("active-now (active=%d/%d, conns still hold slot)", entry.active, connsPerSlot)
	} else if hasRecentLastUsed {
		cooldown = vkActiveAllocationsCooldown
		reason = fmt.Sprintf("active-recent (lastUsedAt %s ago)", age.Round(time.Second))
	}

	cp.applySaturationLocked(slot, cooldown, reason)
	return cooldown
}

// applySaturationLocked is the inner state-mutation step shared by
// markSaturated (which computes a fixed cooldown from current slot
// state — 11m active or 3m ghost) and MarkInUseSlotsForPathChange
// (which computes a precise per-slot cooldown based on lastUsedAt +
// VK allocation lifetime). Caller MUST hold cp.mu.
func (cp *credPool) applySaturationLocked(slot int, cooldown time.Duration, reason string) {
	log.Printf("credpool: slot %d marked VK-saturated for %s — %s",
		slot, cooldown.Round(time.Second), reason)
	if cp.pool[slot].saturationTimer != nil {
		cp.pool[slot].saturationTimer.Stop()
	}
	cp.pool[slot].saturatedUntil = time.Now().Add(cooldown)
	cp.pool[slot].saturationTimer = time.AfterFunc(cooldown, cp.broadcastSlotAvailable)
}

// MarkInUseSlotsForPathChange is called from Swift's NWPathMonitor on every
// real (deduped) network-path transition. For each pool slot that VK
// almost-certainly still holds allocations for (active>0 OR lastUsedAt
// within activeAllocationsWindow), mark it saturated proactively — same
// effect as if a conn had just hit 486 on the slot, but without the wasted
// allocate attempt + retry burst.
//
// Why this helps: without this, after a path change we typically see
// ~3 conns hit 486 in series on each in-use slot (slot 0 → 486 → mark,
// slot 1 → 486 → mark, slot 2 → 486 → mark) over ~0.5-1 seconds before
// credPool routing realises which slots are dead. With pre-emptive
// marking, conn 0 immediately sees slots 0/1/2 saturated and goes to
// fresh reserve slots (3/4/5/...) — no 486 burst, no log spam, no
// CPU/network churn.
//
// Slots with active=0 AND lastUsedAt > 10m ago (or never used) are NOT
// marked — they're either ghost-likely-expired or fresh-never-used, and
// in both cases VK has no allocations against them. Marking them would
// waste 11 minutes of an otherwise-fine slot.
//
// Empirically confirmed VK-side timing: build 69's wgForceReconnect test
// showed 486 firing ~0.4-0.8s after Refresh(0) closes — VK quota release
// is timer-driven (600s lifetime), not client-driven. So the lastUsedAt
// + 600s window is a reliable predictor of when a slot is safe to reuse.
// See evaluated_alternatives_pre_emptive_refresh.md.
func (cp *credPool) MarkInUseSlotsForPathChange() {
	const vkAllocLifetime = 600 * time.Second
	// Safety buffer: clock skew + jitter in VK's quota-release task.
	// If a slot becomes usable a few seconds before this expires the
	// cost is just one wasted allocate attempt that hits 486 and
	// re-marks via the existing path — bounded harm.
	const safetyBuffer = 30 * time.Second
	// Minimum age of lastUsedAt for "active-recent" classification to
	// fire. Below this threshold the slot was just-released by a conn
	// that briefly touched it during the current path-cascade — kernel
	// error killed the socket within ~ms of acquire, so no TURN
	// allocate could have completed (round-trip ~50-200ms minimum,
	// plus VK processing). Without this guard, MarkInUseSlotsForPathChange
	// fires AFTER the conn-retry-loop has already done acquire→release
	// cycles on previously-active slots, marking them all active-recent
	// even though no real VK quota was committed.
	//
	// Observed in vpn.wifi.1.log on 2026-05-11 09:05:51: WiFi→LTE
	// transition fired 3 active-now markings (legitimate) PLUS 3
	// active-recent markings on slots whose lastUsedAt was 0s ago
	// (just-released by reconnect-cycle). Result: pool dropped 12→6
	// fresh instead of expected 12→9. Build 76 fix.
	const minRealUseAge = 2 * time.Second

	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := time.Now()
	// Track which slots got marked so the summary log line below can list
	// them explicitly. Defense in depth against losing a per-slot log line:
	// the per-slot lines emitted by applySaturationLocked carry full detail
	// (cooldown, active count, reason) and are normally what we read; the
	// list in the summary line is a backup so even if one per-slot line is
	// missing from the log for any reason, we can still tell which slots
	// were touched. Observed wifi-lte-wifi.1.log 2026-05-14 19:44:43:
	// `marked 3 in-use slots` summary count but only 2 per-slot lines (slot
	// 4's line missing). The actual slot 4 was demonstrably marked
	// (subsequent "skipping slot 4 (VK-saturated)" lines confirm) — only
	// the marking log itself was lost.
	markedSlots := make([]int, 0, cp.size)
	for slot := 0; slot < cp.size && slot < len(cp.pool); slot++ {
		e := cp.pool[slot]
		// Skip already-saturated (re-marking is no-op but spams logs)
		if !e.saturatedUntil.IsZero() && e.saturatedUntil.After(now) {
			continue
		}
		// Skip empty/never-filled slots (no creds, no VK state)
		if e.creds == nil {
			continue
		}

		// Skip slots already in load-from-disk pending state. availableAt
		// was set by loadFromDisk based on a PRIOR session's lastUsedAt
		// + credSaturationCooldown — VK's lingering allocations from
		// before this session are already correctly accounted for. Smart-
		// pause would re-mark these slots based on the same lastUsedAt,
		// only extending the wait by safetyBuffer (~30s) and confusing
		// the log. Trust the load-cooldown.
		//
		// Observed in vpn.wifi-lte-wifi.3.log on 2026-05-10 23:52: pool
		// loaded from disk had slots 8/9/11 with lastUsedAt 36s ago →
		// pending until 23:58:25 (load-cooldown). Smart-pause at 23:52:21
		// re-marked them saturated until 23:58:56 (~30s later than load-
		// cooldown's natural expiry). No real harm but no real benefit
		// either, and it makes the saturation count misleading.
		if !e.availableAt.IsZero() && e.availableAt.After(now) {
			continue
		}

		// Smart-pause anchor selection:
		//   active>0  → conns alive right now, refreshes every ~5m, so the
		//               latest allocation expires no later than now + 600s.
		//   active=0  → lastUsedAt is when active dropped to 0; VK still
		//               holds allocations for the remainder of 600s after
		//               last refresh, bounded above by lastUsedAt + 600s.
		var anchor time.Time
		var reason string
		if e.active > 0 {
			anchor = now
			reason = fmt.Sprintf("path-change active-now (active=%d/%d, smart-pause)", e.active, connsPerSlot)
		} else if !e.lastUsedAt.IsZero() &&
			now.Sub(e.lastUsedAt) > minRealUseAge &&
			now.Sub(e.lastUsedAt) < activeAllocationsWindow {
			anchor = e.lastUsedAt
			age := now.Sub(e.lastUsedAt).Round(time.Second)
			reason = fmt.Sprintf("path-change active-recent (lastUsedAt %s ago, smart-pause)", age)
		} else {
			// Ghost-likely-expired (lastUsedAt > 10m), never-used,
			// OR just-released-during-this-path-cascade (lastUsedAt
			// within minRealUseAge — see comment on that constant).
			continue
		}

		// remaining = (anchor + vkAllocLifetime + safetyBuffer) - now
		remaining := vkAllocLifetime - now.Sub(anchor) + safetyBuffer
		if remaining <= 0 {
			continue
		}

		cp.applySaturationLocked(slot, remaining, reason)
		markedSlots = append(markedSlots, slot)
	}

	if len(markedSlots) > 0 {
		log.Printf("credpool: path-change pre-emptive — marked %d in-use slots %v with smart-pause cooldowns", len(markedSlots), markedSlots)
	}

	// Adaptive pause-acquire selection. See cascadeDetectionWindow comment
	// for the full rationale.
	pauseDur := pauseAcquireAfterPathEvent // default 500ms
	if !cp.lastPathEventAt.IsZero() {
		gap := now.Sub(cp.lastPathEventAt)
		if gap >= pauseAcquireAfterPathEvent && gap < cascadeDetectionWindow {
			// Cascade detected — previous event was 500ms-90s ago,
			// not iOS dual-event (< 500ms) and not isolated (≥ 90s).
			// Extend pause to block conn redistribution until network
			// stabilises.
			pauseDur = cascadePauseDuration
			log.Printf("credpool: path-change cascade detected (gap %v from prev event) — extending pause to %v",
				gap.Round(time.Millisecond), cascadePauseDuration)
		}
	}
	deadline := now.Add(pauseDur)
	if deadline.After(cp.pauseAcquireUntil) {
		cp.pauseAcquireUntil = deadline
		cp.armPauseAcquireBroadcastLocked()
	}
	cp.lastPathEventAt = now
}

// armPauseAcquireBroadcastLocked (re)schedules a one-shot broadcast on
// slotAvailableCh for the current pauseAcquireUntil deadline. Caller must
// hold cp.mu.
//
// This is what wakes conns parked in runConnection's dormancy select
// (proxy.go:1606) at the moment the credpool unblocks. Without it, a conn
// that entered dormancy during a path-change cascade waits out its full
// random dormantDuration before retrying — even if pauseAcquireUntil
// expired earlier. Empirically surfaced by vpn.wifi-lte-wifi.1.log
// 2026-05-15 13:03 where 30 conns idled 4m20s after the 30s cascade pause
// expired, recovery only happening when the 5-min watchdog kicked in.
//
// Stops any previously-armed timer first so re-arming on extension (next
// path event arriving before the prior pause expired) doesn't double-fire
// or fire at the OLD deadline. Stop+nil is safe even if the old timer
// already fired — Stop returns false in that case, no panic.
//
// Spurious broadcasts are harmless by broadcastSlotAvailable's design:
// a conn that wakes only to find no usable slot just re-parks on the
// next channel.
func (cp *credPool) armPauseAcquireBroadcastLocked() {
	if cp.pauseAcquireTimer != nil {
		cp.pauseAcquireTimer.Stop()
		cp.pauseAcquireTimer = nil
	}
	delay := time.Until(cp.pauseAcquireUntil)
	if delay <= 0 {
		return
	}
	cp.pauseAcquireTimer = time.AfterFunc(delay, cp.broadcastSlotAvailable)
}

// ExtendPauseAcquireForTransition extends pauseAcquireUntil without marking
// any slots. Used for path events that signal "transition in progress, real
// network not yet stable" — specifically iOS PathMonitor satisfied events
// with iface=other (which empirically means our own TUN device becoming
// os-default during the brief window between physical interfaces).
//
// Motivation: vpn.over24h.log 2026-05-13 15:26 outage. Sequence was:
//   T+0     requiresConnection cellular (Event 1)
//   T+162ms satisfied iface=other os-default=192.168.102.4 (our TUN!)
//   T+3.3s  satisfied iface=cellular (Event 3 — real new path)
//
// MarkInUseSlotsForPathChange on Event 1 correctly marked 6 active slots
// and set pauseAcquireUntil = now + 500ms. By the time Event 2 fired
// (162ms after Event 1) the pause was still alive. But the 500ms pause
// expired before Event 3 (3.3s later), so 26 conns acquired fresh slots
// 0/1/2 during the gap, then those allocations dropped/failed/got 486 →
// pool-wide saturation cascade → 10-minute outage.
//
// The proper fix isn't to call MarkInUseSlotsForPathChange on the .other
// event — there are no NEW active slots to mark (the slots are the same
// ones marked at Event 1). Instead we just extend the pause to cover the
// transition window so conns DON'T acquire during the misleading recovery.
//
// Existing pause-set-via-MarkInUseSlots stays untouched. This function
// only extends. Idempotent and safe to call multiple times — uses max().
func (cp *credPool) ExtendPauseAcquireForTransition(d time.Duration) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	deadline := time.Now().Add(d)
	if deadline.After(cp.pauseAcquireUntil) {
		cp.pauseAcquireUntil = deadline
		cp.armPauseAcquireBroadcastLocked()
	}
}

// tryFill is called by the background grower (see Proxy.growCredPool) to
// fill one empty/stale slot without blocking any caller. Returns true if
// the slot ended up fresh as a result — either because we filled it, or
// because someone else had already filled it by the time we looked.
//
// Respects cooldown (skip) and in-flight fetches (skip). Like get(), it
// does NOT hold mu across the VK fetch.
//
// abortIfAvailableGTE (0 = disabled, >0 = enabled): if at any of the two
// checkpoints — pre-fetch (saves PoW time) or post-fetch (catches races
// during PoW) — cp.countAvailableLocked() returns >= this value, the fill
// is aborted. Pre-fetch abort releases the slot's `fetching` flag and
// returns false (no VK call made). Post-fetch abort discards already-
// fetched creds AND releases the flag.
//
// Used by the grower to bail when conn-driven fetches in get() race ahead
// and push the pool past the cold-start target during our 5-10s PoW wait.
// Without this, the grower systematically over-shoots cold-start by 1
// (observed vpn.wifi.5.log + wifi.6.log: pool 0 → 4 instead of 0 → 3 for
// NumConns=30 because conn 10 fetched slot 2 while grower was mid-PoW
// on slot 3).
func (cp *credPool) tryFill(slot int, allowCaptchaBlock bool, abortIfAvailableGTE int) bool {
	cp.mu.Lock()
	if slot < 0 || slot >= cp.size {
		cp.mu.Unlock()
		return false
	}
	for len(cp.pool) <= slot {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	if cp.isFreshLocked(slot) {
		cp.mu.Unlock()
		return true
	}
	// Defense in depth: pickSlotToFill already filters pending slots
	// for the background grower, but a direct tryFill caller (none in
	// the current code, but harmless future-proofing) shouldn't waste
	// a VK fetch on a slot that's about to become usable on its own.
	if entryIsPending(cp.pool[slot]) {
		cp.mu.Unlock()
		return true // pending counts as "filled" — the cred is there, just not yet usable
	}
	if time.Now().Before(cp.pool[slot].cooldownUntil) || cp.pool[slot].fetching {
		cp.mu.Unlock()
		return false
	}
	// Pre-fetch abort check (saves PoW). If conn-driven fetches in get()
	// have already pushed available past the cold-start target, this
	// fill is redundant.
	if abortIfAvailableGTE > 0 && cp.countAvailableLocked() >= abortIfAvailableGTE {
		cp.mu.Unlock()
		return false
	}
	cp.pool[slot].fetching = true
	cp.mu.Unlock()

	addr, creds, err := cp.fetch(allowCaptchaBlock, slot)

	cp.mu.Lock()
	cp.pool[slot].fetching = false
	if err == nil {
		// Post-fetch abort check (catches races during our 5-10s PoW
		// window). Discards fetched creds — they go to waste this round
		// but that's far cheaper than continuing to systematically
		// over-shoot the cold-start target by 1.
		if abortIfAvailableGTE > 0 && cp.countAvailableLocked() >= abortIfAvailableGTE {
			cp.mu.Unlock()
			return false
		}
		cp.pool[slot] = credPoolEntry{addr: addr, creds: creds, ts: time.Now()}
		filled := cp.countFreshLocked()
		cp.mu.Unlock()
		log.Printf("credpool: background filled slot %d (%d/%d slots filled)", slot, filled, cp.size)
		if slot >= 0 && slot < len(cp.authErrors) {
			cp.authErrors[slot].Store(0)
		}
		cp.saveToDisk()
		// Background grower just turned a non-fresh slot into a fresh
		// one. Wake conns parked after a cascade ForceReconnect — they
		// can now acquire the freshly-filled slot instead of waiting
		// out their randomised retry timer.
		cp.broadcastSlotAvailable()
		return true
	}
	cp.pool[slot].cooldownUntil = time.Now().Add(cp.cooldown)
	cp.mu.Unlock()
	log.Printf("credpool: background fill slot %d failed (%v), cooldown %s", slot, err, cp.cooldown)
	return false
}

// pickSlotToFill returns the index of a slot that is eligible for the
// background grower to attempt (empty or stale, not fetching, not on
// cooldown, not pending). Returns -1 if nothing to do right now.
//
// Pending slots (loaded from disk but waiting on saturation cooldown)
// are NOT picked: a fresh fetch would overwrite a cred that's about
// to become available on its own, wasting a VK API call (and risking
// captcha) for no benefit. Once the cooldown passes, the pending slot
// transitions to fresh and pickSlotToFill skips it as already-good.
func (cp *credPool) pickSlotToFill() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	now := time.Now()
	for i := 0; i < cp.size; i++ {
		e := cp.pool[i]
		if entryIsFresh(e) {
			continue // fresh (cred not yet near expiry)
		}
		if entryIsPending(e) {
			continue // loaded from disk, waiting on saturation cooldown
		}
		if e.fetching {
			continue
		}
		if now.Before(e.cooldownUntil) {
			continue
		}
		return i
	}
	return -1
}

// invalidate drops every entry so the next get() refetches. Used on
// explicit session resets (Pause/Resume/ForceReconnect) and on captcha
// probes that need to force a fresh VK session.
func (cp *credPool) invalidate() {
	cp.mu.Lock()
	n := 0
	for _, e := range cp.pool {
		if e.creds != nil {
			n++
		}
	}
	// Reset to pre-sized empty slice so subsequent ops (seedSlot
	// relocation, pickSlotToFill iteration) keep seeing the full
	// slot array; see newCredPool's pre-size comment.
	cp.pool = make([]credPoolEntry, cp.size)
	cp.mu.Unlock()
	if n > 0 {
		log.Printf("credpool: invalidated %d entries", n)
	}
}

// invalidateEntry drops one slot (by pool index, not necessarily a
// connIdx) so its cred is re-fetched on next need. Cooldown and
// fetching flags are cleared too.
//
// Callers should pass the slot that actually produced the bad cred —
// for conns that fell back via credPool.get fallback, that's the
// credSlot returned by get(), NOT the caller's connIdx.
//
// Persists the new pool state to disk so the next launch doesn't try
// to use this server-rejected cred (which would cost a 401 round-trip
// to discover the same thing). saveToDisk is a snapshot of current
// pool[].creds, so dropping the entry above is enough — no separate
// "delete from cache file" step.
func (cp *credPool) invalidateEntry(slot int) {
	if slot < 0 {
		return
	}
	cp.mu.Lock()
	dropped := slot < len(cp.pool) && cp.pool[slot].creds != nil
	if slot < len(cp.pool) {
		cp.pool[slot] = credPoolEntry{}
	}
	cp.mu.Unlock()
	if dropped {
		cp.saveToDisk()
	}
}

// broadcastSlotAvailable wakes every conn currently parked in
// runConnection's retry select on slotAvailableChannel(). Called from
// every pool mutation that can transition a slot toward usable: a fresh
// cred lands in a slot (seedSlot, tryFill success, get's Phase 2 fetch),
// a conn release frees per-slot capacity, or a saturation cooldown
// expires (via markSaturated's AfterFunc). The cooldown-expiry hook
// matters during 486-cascades: parked conns in their long randomised
// dormancy would otherwise miss the moment the slot becomes usable
// again and waste minutes sleeping past it.
//
// Implementation: close the current channel and swap in a new one. The
// close acts as a fan-out wake-up — all waiting conns observe the same
// closed channel and proceed simultaneously. A buffered single-slot
// channel would only wake one waiter, defeating the broadcast.
//
// Spurious calls are harmless: a conn that wakes up only to find no
// usable slot will fail get() again and re-park on the new channel.
func (cp *credPool) broadcastSlotAvailable() {
	cp.mu.Lock()
	oldCh := cp.slotAvailableCh
	cp.slotAvailableCh = make(chan struct{})
	cp.mu.Unlock()
	close(oldCh)
}

// slotAvailableChannel returns the channel a conn should select on to
// receive the next slot-available broadcast. Must be re-read after each
// wake-up since broadcastSlotAvailable replaces the field.
func (cp *credPool) slotAvailableChannel() <-chan struct{} {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.slotAvailableCh
}

// snapshotSize returns (freshCount, withCredsCount, totalCapacity) of
// the pool — used by the stats endpoint so the UI can display
// "fresh / with-creds / total". Takes the lock briefly; safe to call
// from any goroutine.
//
// fresh counts slots usable for NEW conn allocations (entryIsFresh).
// withCreds counts slots that physically hold a cred — including ones
// past their expiry buffer or in pending state — i.e. slots where
// existing conns may still be alive on a now-stale cred until their
// VK-side allocation lifetime runs out. The two diverge whenever a
// slot's username-encoded expiry is within 30 min: the slot drops out
// of "fresh" (UI shows lower number) while existing conns continue
// functioning until VK actually invalidates the allocation.
func (cp *credPool) snapshotSize() (available int, withUsableCreds int, size int) {
	cp.mu.Lock()
	// "Available" = fresh AND not currently saturated. The Stats UI
	// "Pool" first number used to count `fresh` (entryIsFresh) which
	// missed saturatedUntil — back-to-back path transitions on
	// build 72 (vpn.wifi-lte-wifi.1.log 2026-05-10 23:03) showed
	// "Pool 8/8/8" while ALL 8 slots were saturated for the next
	// 4 minutes. Switching to countAvailableLocked makes the UI
	// reflect actual usability.
	available = cp.countAvailableLocked()
	// "WithUsableCreds" = slots whose cred hasn't crossed the
	// expiry buffer. Replaces the prior countWithCredsLocked which
	// counted ANY cred regardless of expiry — misleading when
	// background grower stalls (PoW rate-limited) and slots hold
	// stale creds that can't be refreshed (vpn.wifi-lte-wifi.1.log
	// on 2026-05-12: UI showed "6/12/12" while 6 of those 12 slots
	// had expired creds the grower had been failing to refresh for
	// 26+ minutes). The middle number now matches the user's mental
	// model of "viable creds the pool can fall back on".
	withUsableCreds = cp.countWithUsableCredsLocked()
	size = cp.size
	cp.mu.Unlock()
	return
}

// distinctRelays counts the number of DISTINCT TURN relay addresses currently
// held across the pool's filled slots — i.e. how many independent
// (per-(userid,relay)≈10) quota buckets the conns are spread over. Surfaced as
// the 4th "Pool" stat: the whole point in cookie/VKAuth mode, and harmless/
// informative in anonymous mode.
func (cp *credPool) distinctRelays() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	seen := make(map[string]struct{})
	for i := range cp.pool {
		if cp.pool[i].creds != nil && cp.pool[i].addr != "" {
			seen[cp.pool[i].addr] = struct{}{}
		}
	}
	return len(seen)
}

// isFreshLocked assumes cp.mu is held. A slot is fresh iff it holds creds
// AND those creds will still be valid on VK's TURN server credExpiryBuffer
// from now (see parseCredExpiry for the expiry source).
func (cp *credPool) isFreshLocked(slot int) bool {
	if slot < 0 || slot >= len(cp.pool) {
		return false
	}
	return entryIsFresh(cp.pool[slot])
}

// entryIsFresh is the slot-agnostic version, used by isFreshLocked /
// countFreshLocked / pickSlotToFill on already-snapshotted entries.
//
// "Fresh" means the cred is usable RIGHT NOW: it has a valid VK-side
// expiry far enough in the future, and any saturation cooldown from
// a prior session has elapsed. Pending-but-loaded creds (creds != nil
// AND availableAt is in the future) are NOT fresh — get() will skip
// them so conns don't 486 against still-live allocations.
func entryIsFresh(e credPoolEntry) bool {
	if e.creds == nil {
		return false
	}
	exp, ok := parseCredExpiry(e.creds.Username)
	if !ok {
		// Malformed username — treat as already expired so the next
		// fetch path replaces it. Safer than trusting an unparseable
		// cred indefinitely.
		return false
	}
	if !time.Now().Add(credExpiryBuffer).Before(exp) {
		return false
	}
	if !e.availableAt.IsZero() && time.Now().Before(e.availableAt) {
		return false
	}
	return true
}

// entryIsAvailable reports whether the slot can hand out new TURN
// allocations RIGHT NOW: cred is fresh AND no active VK-side saturation
// cooldown. Used by the StatsView "available" count so the user sees the
// actual usable-slot count, not a misleading total when all slots are
// saturated. entryIsFresh alone does NOT check saturatedUntil — it was
// designed for cred-validity checks, not runtime usability.
//
// Example: build 72 on 2026-05-10 23:03 had pool=8 with all 8 slots
// holding fresh creds (entryIsFresh=true for all) but all 8 also marked
// VK-saturated by smart-pause. UI showed "Pool 8/8/8" misleadingly when
// reality was 0 usable. entryIsAvailable would have correctly reported 0.
func entryIsAvailable(e credPoolEntry) bool {
	if !entryIsFresh(e) {
		return false
	}
	if !e.saturatedUntil.IsZero() && time.Now().Before(e.saturatedUntil) {
		return false
	}
	return true
}

// entryIsPending reports whether the slot holds a cred that's
// load-from-disk-pending: present, with a valid expiry, but not yet
// past its saturation cooldown. pickSlotToFill uses this to leave
// pending slots alone — we'd rather wait ~10 min for the prior
// session's allocations to expire on VK's side than spend 10-30 min
// chasing a fresh cred through PoW on a hostile day. Once availableAt
// passes the slot transitions to fresh on its own.
func entryIsPending(e credPoolEntry) bool {
	if e.creds == nil {
		return false
	}
	if e.availableAt.IsZero() || !time.Now().Before(e.availableAt) {
		return false
	}
	exp, ok := parseCredExpiry(e.creds.Username)
	if !ok {
		return false
	}
	return time.Now().Add(credExpiryBuffer).Before(exp)
}

// countFreshLocked assumes cp.mu is held.
func (cp *credPool) countFreshLocked() int {
	n := 0
	for _, e := range cp.pool {
		if entryIsFresh(e) {
			n++
		}
	}
	return n
}

// countAvailableLocked assumes cp.mu is held. Same as countFreshLocked
// but ALSO excludes saturated slots — see entryIsAvailable. Used for the
// UI "available" count.
func (cp *credPool) countAvailableLocked() int {
	n := 0
	for _, e := range cp.pool {
		if entryIsAvailable(e) {
			n++
		}
	}
	return n
}

// countWithUsableCredsLocked assumes cp.mu is held. Counts slots whose
// cred has NOT crossed the credExpiryBuffer threshold — i.e. slots that
// will (or could) hand out new allocations once any current saturation
// or load-pending state passes. Excludes:
//   - empty slots (no cred)
//   - slots with expired / expiring-within-buffer creds (these are
//     effectively dead until background grower fetches a fresh cred)
//   - slots with unparseable cred username (treated as dead)
//
// Includes saturated and load-pending slots — those will recover on
// their own.
//
// Used by the StatsView "Pool" middle number so the user sees how many
// slots have a viable cred backing them, not just any cred. Replaces
// countWithCredsLocked usage in snapshotSize since 2026-05-12 build 82
// — the prior "any cred" semantic was misleading when background
// grower is stuck (e.g. PoW rate-limited) and slots hold stale creds
// that can't be refreshed.
func (cp *credPool) countWithUsableCredsLocked() int {
	n := 0
	now := time.Now()
	for _, e := range cp.pool {
		if e.creds == nil {
			continue
		}
		exp, ok := parseCredExpiry(e.creds.Username)
		if !ok {
			continue
		}
		if !now.Add(credExpiryBuffer).Before(exp) {
			continue // expired or expiring within buffer
		}
		n++
	}
	return n
}

// logFreshTransitionsLocked compares per-slot entryIsFresh against the
// snapshot stored in freshLastTick from the previous runPeriodicSave
// tick. For each slot that just transitioned fresh→not-fresh, emits a
// log line with the inferred reason. Then refreshes freshLastTick for
// the next tick. Caller MUST hold cp.mu.
//
// Reason inference (priority order):
//   - "cred removed" — entry has no creds (e.g. background grower
//     cleared the slot)
//   - "load-pending" — availableAt is in the future (load-cooldown)
//   - "unparseable cred expiry" — parseCredExpiry failed
//   - "expiring within Xm buffer" — cred expiry is closer than
//     credExpiryBuffer (typically 30 min)
//   - "unknown" — fallthrough, none of the above (shouldn't happen
//     in practice)
//
// Note: smart-pause / 486 saturation does NOT trigger this log line
// because entryIsFresh doesn't check saturatedUntil — only
// entryIsAvailable does. Saturation events have their own log line
// from markSaturated/applySaturationLocked.
func (cp *credPool) logFreshTransitionsLocked() {
	// Resize snapshot on first run or after pool growth. On first run
	// we just snapshot current state without logging — there's no
	// "transition" to report when we have no history.
	if len(cp.freshLastTick) != len(cp.pool) {
		cp.freshLastTick = make([]bool, len(cp.pool))
		for i := range cp.pool {
			cp.freshLastTick[i] = entryIsFresh(cp.pool[i])
		}
		return
	}
	now := time.Now()
	for slot := range cp.pool {
		wasFresh := cp.freshLastTick[slot]
		nowFresh := entryIsFresh(cp.pool[slot])
		if wasFresh && !nowFresh {
			e := cp.pool[slot]
			reason := "unknown"
			switch {
			case e.creds == nil:
				reason = "cred removed"
			case !e.availableAt.IsZero() && now.Before(e.availableAt):
				reason = fmt.Sprintf("moved to load-pending state (usable in %s)",
					time.Until(e.availableAt).Round(time.Second))
			default:
				if exp, ok := parseCredExpiry(e.creds.Username); !ok {
					reason = "unparseable cred expiry"
				} else if !now.Add(credExpiryBuffer).Before(exp) {
					remaining := time.Until(exp).Round(time.Second)
					reason = fmt.Sprintf("cred expiring within %s buffer (cred expires in %s)",
						credExpiryBuffer, remaining)
				}
			}
			log.Printf("credpool: slot %d transitioned out of fresh — %s", slot, reason)
		} else if !wasFresh && nowFresh {
			// Symmetric to the fresh→not-fresh branch: log when a slot
			// silently becomes fresh. Most common cause: load-from-disk
			// pending state elapsing (availableAt crossed). Also covers
			// cases where seedSlot / background-fill produced a fresh
			// cred between ticks (those paths log their own success
			// line, so this is mildly redundant for them — accepted as
			// "all transitions visible" beats "guess from absence").
			e := cp.pool[slot]
			reason := "unknown"
			switch {
			case e.creds == nil:
				reason = "creds appeared (race; check seedSlot/background fill log)"
			case !e.availableAt.IsZero() && !now.Before(e.availableAt):
				elapsed := now.Sub(e.availableAt).Round(time.Second)
				reason = fmt.Sprintf("load-cooldown elapsed (became usable %s ago)", elapsed)
			default:
				reason = "creds became valid (seeded or background-filled)"
			}
			log.Printf("credpool: slot %d transitioned to fresh — %s", slot, reason)
		}
		cp.freshLastTick[slot] = nowFresh
	}
}

// countWithCredsLocked assumes cp.mu is held. Counts slots that hold a
// non-nil cred pointer regardless of expiry — i.e. the same predicate
// saveToDisk uses to decide what to persist. The Stats UI shows this
// alongside the fresh count so the user can tell apart "cred is gone"
// from "cred is still in the slot but past its expiry buffer / pending /
// saturated" — those latter cases keep existing conns alive on the slot
// even though pickSlotToFill / get's Phase 1 won't grant new ones.
func (cp *credPool) countWithCredsLocked() int {
	n := 0
	for _, e := range cp.pool {
		if e.creds != nil {
			n++
		}
	}
	return n
}

// extractCaptcha checks if a VK API response contains error code 14 (captcha required).
// Returns captcha_sid, captcha URL, captcha_ts, and captcha_attempt.
// Prefers redirect_uri (new interactive captcha) over captcha_img (deprecated text captcha).
func extractCaptcha(resp map[string]interface{}) (sid, captchaURL string, captchaTs, captchaAttempt float64) {
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		return "", "", 0, 0
	}
	code, _ := errObj["error_code"].(float64)
	if int(code) != 14 {
		return "", "", 0, 0
	}

	// Log the full error for debugging
	if errJSON, err := json.Marshal(errObj); err == nil {
		log.Printf("vk: captcha error response: %s", string(errJSON))
	}

	// Prefer redirect_uri (new "I'm not a robot" captcha that works in browser)
	if uri, ok := errObj["redirect_uri"].(string); ok && uri != "" {
		captchaURL = uri
	} else {
		// Fallback to old captcha_img
		captchaURL, _ = errObj["captcha_img"].(string)
	}

	// captcha_sid can be string or number
	switch v := errObj["captcha_sid"].(type) {
	case string:
		sid = v
	case float64:
		sid = fmt.Sprintf("%.0f", v)
	}

	// Extract captcha_ts and captcha_attempt for success_token retry
	captchaTs, _ = errObj["captcha_ts"].(float64)
	captchaAttempt, _ = errObj["captcha_attempt"].(float64)
	if captchaAttempt == 0 {
		captchaAttempt = 1
	}

	return sid, captchaURL, captchaTs, captchaAttempt
}
