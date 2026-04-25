package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// vkCredentials holds a VK API client_id/client_secret pair.
type vkCredentials struct {
	ClientID     string
	ClientSecret string
}

// vkCredentialsList contains all known VK app credentials for rotation.
// Using multiple client_id reduces per-app rate limiting and captcha frequency.
var vkCredentialsList = []vkCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2"},  // VK_WEB_APP_ID
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw"},  // VK_MVK_APP_ID
	{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A"}, // VK_WEB_VKVIDEO_APP_ID
	{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC"}, // VK_MVK_VKVIDEO_APP_ID
	{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK"}, // VK_ID_AUTH_APP
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
	IsRateLimit    bool   // true when VK returned ERROR_LIMIT (PoW exhausted)
}

func (e *CaptchaRequiredError) Error() string {
	return fmt.Sprintf("captcha required: %s", e.ImageURL)
}

// TURNCreds holds TURN server credentials.
type TURNCreds struct {
	Username string
	Password string
	Address  string // host:port
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
func GetVKCreds(linkID string, captchaSolver CaptchaSolver, solvedCaptchaSID, solvedCaptchaKey string, solvedCaptchaTs, solvedCaptchaAttempt float64, savedToken1 string) (*TURNCreds, error) {
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

	var lastErr error
	for retry := 0; retry < maxNetworkRetries; retry++ {
		// Rotate through client_id/client_secret pairs to reduce per-app rate limiting.
		// Shuffle the list so each connection attempt uses a different order.
		creds := make([]vkCredentials, len(vkCredentialsList))
		copy(creds, vkCredentialsList)
		mathrand.Shuffle(len(creds), func(i, j int) { creds[i], creds[j] = creds[j], creds[i] })

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
	// Randomize identity for anti-detection: different UA and name per credential fetch.
	ua := randomUserAgent()
	name := generateName()
	escapedName := neturl.QueryEscape(name)
	log.Printf("vk: identity — name: %s, UA: %s", name, ua)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := newHTTPClient()
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("User-Agent", ua)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpResp.Body.Close() }()

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

	step2URL := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", vc.ClientID)

	// Step 1: get anonymous messages token
	// If savedToken1 is provided (captcha retry), reuse it instead of fetching a new one.
	var token1 string
	if savedToken1 != "" {
		token1 = savedToken1
		log.Printf("vk: reusing saved token1 for captcha retry")
	} else {
		data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", vc.ClientID, vc.ClientSecret, vc.ClientID)
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
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&access_token=%s", linkID, token1)
	_, _ = doRequest(previewData, fmt.Sprintf("https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=%s", vc.ClientID))

	// Step 2: get anonymous call token (with captcha retry)
	var token2 string
	var resp map[string]interface{}
	var err error
	step2Data := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", linkID, escapedName, token1)

	// If we have a pre-solved captcha (success_token from captchaNotRobot.check), include it.
	if solvedCaptchaSID != "" && solvedCaptchaKey != "" {
		log.Printf("vk: retrying step2 with success_token (%d chars), captcha_sid=%s", len(solvedCaptchaKey), solvedCaptchaSID)
		step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d",
			linkID, escapedName, token1, solvedCaptchaSID, neturl.QueryEscape(solvedCaptchaKey), solvedCaptchaTs, int(solvedCaptchaAttempt))
	}

	for attempt := 0; attempt < 3; attempt++ {
		resp, err = doRequest(step2Data, step2URL)
		if err != nil {
			return nil, fmt.Errorf("step2: %w", err)
		}

		// Check for captcha (VK error code 14)
		captchaSID, captchaImg, captchaTs, captchaAttempt := extractCaptcha(resp)
		if captchaSID != "" {
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
				powToken, showType, powErr := solveCaptchaPoW(powCtx, currentImg, currentSID, ua)
				powCancel()
				lastPowErr = powErr

				if powErr == nil && powToken != "" {
					log.Printf("vk: PoW auto-solve succeeded on attempt %d (%d chars), retrying step2", powTry, len(powToken))
					step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d",
						linkID, escapedName, token1, currentSID, neturl.QueryEscape(powToken), currentTs, int(currentAttempt))
					powSolved = true
					break
				}

				log.Printf("vk: PoW attempt %d/%d failed (show_captcha_type=%q): %v", powTry, maxPoWRetries, showType, powErr)

				// Only short-circuit to WebView when checkbox is provably
				// disabled for this session — i.e. VK returned status=ERROR at
				// least once, so `checkboxBurnedForSession` is set and the
				// error message includes "checkbox burned". In that case both
				// auto paths are dead and further retries are wasted work.
				//
				// For transient failures (status=BOT, ERROR_LIMIT, …) we DO
				// retry up to maxPoWRetries times with a fresh captcha URL —
				// the next captcha session often succeeds even when the
				// previous one was rejected.
				if powErr != nil && strings.Contains(powErr.Error(), "checkbox burned") {
					log.Printf("vk: checkbox disabled (ERROR) and slider failed, skipping remaining attempts")
					break
				}

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
					freshData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", linkID, escapedName, token1)
					freshResp, freshErr := doRequest(freshData, step2URL)
					if freshErr != nil {
						log.Printf("vk: failed to get fresh captcha for PoW retry: %v", freshErr)
						break
					}
					fSID, fImg, fTs, fAttempt := extractCaptcha(freshResp)
					if fSID == "" {
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

			if captchaSolver == nil {
				return nil, &CaptchaRequiredError{ImageURL: currentImg, SID: currentSID, CaptchaTs: currentTs, CaptchaAttempt: currentAttempt, Token1: token1, IsRateLimit: isRateLimit}
			}
			answer, err := captchaSolver(currentImg)
			if err != nil {
				return nil, fmt.Errorf("step2: captcha solver: %w", err)
			}
			log.Printf("vk: WebView captcha solver returned answer (%d chars), retrying", len(answer))
			step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d",
				linkID, escapedName, token1, currentSID, neturl.QueryEscape(answer), currentTs, int(currentAttempt))
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
	turnURL, ok := urls[0].(string)
	if !ok {
		return nil, fmt.Errorf("step4: turn_server.urls[0] not string")
	}

	clean := strings.Split(turnURL, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return &TURNCreds{
		Username: user,
		Password: pass,
		Address:  address,
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
	pool     []credPoolEntry // indexed by connIdx; grown lazily up to size
	idx      int             // round-robin cursor for fallback mode
	size     int             // pool capacity = Config.NumConns
	ttl      time.Duration   // per-entry freshness (default 10m)
	cooldown time.Duration   // post-failure skip-fetch window (default 5m)

	// fetch is the underlying credential fetcher. It must do all the work
	// previously inlined in resolveTURNAddr: build solver + pending-captcha
	// params, call GetVKCreds, parse TURN host:port, publish turnServerIP.
	// Returns (address "host:port", creds, err). On CaptchaRequiredError
	// the pool may choose to fall back to an existing entry instead of
	// surfacing the error.
	fetch func(allowCaptchaBlock bool) (string, *TURNCreds, error)
}

// poolSizeForNumConns derives the insurance pool size from the configured
// number of tunnel connections. The policy is max(2, ceil(n/3)):
//
//   - Scale with n so heavier-use setups get more independent creds.
//   - Keep the minimum at 2 so that the "mid-session captcha on one slot,
//     others keep the tunnel alive" behaviour always has something to
//     fall back to. With only 1 slot, a mid-session refetch that hits
//     captcha would have no fallback and surface as a user-facing
//     WebView — defeating the purpose of the pool.
//   - Staying below n (default=10 → pool=4) keeps background PoW /
//     VK-fetch pressure low: TTL-rotation touches each slot once per
//     TTL, so fewer slots = fewer periodic fetches.
//
// Examples: n=1..3 → 2, n=4..6 → 2, n=7..9 → 3, n=10..12 → 4,
//           n=13..15 → 5, n=30 → 10.
func poolSizeForNumConns(n int) int {
	if n <= 0 {
		n = 1
	}
	size := (n + 2) / 3 // integer ceiling of n/3
	if size < 2 {
		size = 2
	}
	return size
}

// newCredPool builds a pool sized to `size` conns with per-entry `ttl`.
// The post-failure cooldown is fixed at 5 minutes.
func newCredPool(size int, ttl time.Duration, fetch func(bool) (string, *TURNCreds, error)) *credPool {
	if size < 1 {
		size = 1
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	cp := &credPool{
		size:     size,
		ttl:      ttl,
		cooldown: 5 * time.Minute,
		fetch:    fetch,
	}
	log.Printf("credpool: initialized with %d slots (ttl=%s, cooldown=%s)", size, ttl, cp.cooldown)
	return cp
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
func (cp *credPool) get(connIdx int, allowCaptchaBlock bool) (string, *TURNCreds, int, error) {
	cp.mu.Lock()

	// Pool size may be smaller than NumConns (policy: max(2, ceil(n/3))),
	// so multiple conns beyond the pool size collapse onto the last slot
	// as their "own slot". Keep connIdx as-is for logs (so the actual
	// calling conn is visible) and derive a clamped `ownSlot` for the
	// pool indexing math.
	ownSlot := connIdx
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

	// 1. Own slot fresh?
	if cp.isFreshLocked(ownSlot) {
		e := cp.pool[ownSlot]
		cp.mu.Unlock()
		log.Printf("credpool: conn %d using cached cred from slot %d (age %s)",
			connIdx, ownSlot, time.Since(e.ts).Round(time.Second))
		return e.addr, e.creds, ownSlot, nil
	}

	// 2. Any other fresh slot — fallback without fetching.
	if pick, ok := cp.pickFreshFallbackLocked(); ok {
		e := cp.pool[pick]
		cp.mu.Unlock()
		log.Printf("credpool: conn %d using cred from slot %d (fallback, age %s)",
			connIdx, pick, time.Since(e.ts).Round(time.Second))
		return e.addr, e.creds, pick, nil
	}

	// 3. Own slot on cooldown and no fresh fallback — propagate so the
	//    caller's reconnect loop backs off instead of hammering us.
	now := time.Now()
	if now.Before(cp.pool[ownSlot].cooldownUntil) {
		until := cp.pool[ownSlot].cooldownUntil
		cp.mu.Unlock()
		return "", nil, -1, fmt.Errorf("credpool: slot %d on cooldown for %s and no fresh fallback",
			ownSlot, until.Sub(now).Round(time.Second))
	}

	// 4. Another goroutine is already fetching into this slot; don't
	//    duplicate work. Return an error so the caller retries (by then
	//    the other fetch may have filled the slot or a fallback).
	if cp.pool[ownSlot].fetching {
		cp.mu.Unlock()
		return "", nil, -1, fmt.Errorf("credpool: slot %d fetch already in progress", ownSlot)
	}
	cp.pool[ownSlot].fetching = true
	cp.mu.Unlock()

	// Inline fetch — runs WITHOUT mu so get() on other slots stays fast.
	addr, creds, fetchErr := cp.fetch(allowCaptchaBlock)

	cp.mu.Lock()
	cp.pool[ownSlot].fetching = false
	if fetchErr == nil {
		cp.pool[ownSlot] = credPoolEntry{addr: addr, creds: creds, ts: time.Now()}
		filled := cp.countFreshLocked()
		cp.mu.Unlock()
		log.Printf("credpool: conn %d fetched fresh cred into slot %d (%d/%d slots filled)",
			connIdx, ownSlot, filled, cp.size)
		return addr, creds, ownSlot, nil
	}

	// Fetch failed. Set cooldown so this slot doesn't get hammered on
	// every reconnect. Then check once more for a fresh fallback: the
	// background grower may have filled another slot while we waited.
	cp.pool[ownSlot].cooldownUntil = time.Now().Add(cp.cooldown)
	if pick, ok := cp.pickFreshFallbackLocked(); ok {
		e := cp.pool[pick]
		cp.mu.Unlock()
		log.Printf("credpool: conn %d fetch failed (%v), falling back to slot %d (age %s), cooldown %s",
			connIdx, fetchErr, pick, time.Since(e.ts).Round(time.Second), cp.cooldown)
		return e.addr, e.creds, pick, nil
	}
	cp.mu.Unlock()
	log.Printf("credpool: conn %d fetch failed and no fresh fallback: %v (cooldown %s)",
		connIdx, fetchErr, cp.cooldown)
	return "", nil, -1, fetchErr
}

// tryFill is called by the background grower (see Proxy.growCredPool) to
// fill one empty/stale slot without blocking any caller. Returns true if
// the slot ended up fresh as a result — either because we filled it, or
// because someone else had already filled it by the time we looked.
//
// Respects cooldown (skip) and in-flight fetches (skip). Like get(), it
// does NOT hold mu across the VK fetch.
func (cp *credPool) tryFill(slot int, allowCaptchaBlock bool) bool {
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
	if time.Now().Before(cp.pool[slot].cooldownUntil) || cp.pool[slot].fetching {
		cp.mu.Unlock()
		return false
	}
	cp.pool[slot].fetching = true
	cp.mu.Unlock()

	addr, creds, err := cp.fetch(allowCaptchaBlock)

	cp.mu.Lock()
	cp.pool[slot].fetching = false
	if err == nil {
		cp.pool[slot] = credPoolEntry{addr: addr, creds: creds, ts: time.Now()}
		filled := cp.countFreshLocked()
		cp.mu.Unlock()
		log.Printf("credpool: background filled slot %d (%d/%d slots filled)", slot, filled, cp.size)
		return true
	}
	cp.pool[slot].cooldownUntil = time.Now().Add(cp.cooldown)
	cp.mu.Unlock()
	log.Printf("credpool: background fill slot %d failed (%v), cooldown %s", slot, err, cp.cooldown)
	return false
}

// pickSlotToFill returns the index of a slot that is eligible for the
// background grower to attempt (empty or stale, not fetching, not on
// cooldown). Returns -1 if nothing to do right now.
func (cp *credPool) pickSlotToFill() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for len(cp.pool) < cp.size {
		cp.pool = append(cp.pool, credPoolEntry{})
	}
	now := time.Now()
	for i := 0; i < cp.size; i++ {
		e := cp.pool[i]
		if e.creds != nil && now.Sub(e.ts) < cp.ttl {
			continue // fresh
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
	n := len(cp.pool)
	cp.pool = nil
	cp.idx = 0
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
func (cp *credPool) invalidateEntry(slot int) {
	if slot < 0 {
		return
	}
	cp.mu.Lock()
	if slot < len(cp.pool) {
		cp.pool[slot] = credPoolEntry{}
	}
	cp.mu.Unlock()
}

// isFreshLocked assumes cp.mu is held.
func (cp *credPool) isFreshLocked(slot int) bool {
	if slot < 0 || slot >= len(cp.pool) {
		return false
	}
	e := cp.pool[slot]
	return e.creds != nil && time.Since(e.ts) < cp.ttl
}

// pickFreshFallbackLocked picks one fresh slot round-robin-style.
// Returns (slot, true) if any fresh slot exists; (-1, false) otherwise.
// Assumes cp.mu is held.
func (cp *credPool) pickFreshFallbackLocked() (int, bool) {
	fresh := cp.freshIndicesLocked()
	if len(fresh) == 0 {
		return -1, false
	}
	pick := fresh[cp.idx%len(fresh)]
	cp.idx++
	return pick, true
}

// countFreshLocked assumes cp.mu is held.
func (cp *credPool) countFreshLocked() int {
	n := 0
	for _, e := range cp.pool {
		if e.creds != nil && time.Since(e.ts) < cp.ttl {
			n++
		}
	}
	return n
}

// freshIndicesLocked assumes cp.mu is held. Returns indices of currently
// fresh entries in pool order.
func (cp *credPool) freshIndicesLocked() []int {
	out := make([]int, 0, len(cp.pool))
	for i, e := range cp.pool {
		if e.creds != nil && time.Since(e.ts) < cp.ttl {
			out = append(out, i)
		}
	}
	return out
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
