package proxy

// VK Calls captcha-free anon-join flow (discovered 2026-05-17).
//
// VK Calls iOS app uses an entirely different API path than VK iOS App /
// VK Messenger / our legacy bootstrap:
//
//   - host:       api.vk.me                      (not api.vk.ru / api.vk.com)
//   - client_id:  8093730  (VK Connect)          (not any of vkCredentialsList — those are VK iOS App / Video / ID-Auth variants)
//   - auth ep:    /method/auth.getAnonymToken    (not login.vk.ru/?act=get_anonym_token)
//   - param name: anonymous_token=               (not access_token=)
//   - api ver:    v=5.276                        (not v=5.275)
//   - call ep:    /method/messages.getAnonymCallToken  (not /method/calls.getAnonymousToken)
//
// VK gates anon flows per-(FQDN, API method, client_id). On 2026-05-15 VK
// added a captcha gate to calls.getAnonymousToken across all our client_ids
// — that's what broke our legacy flow. The messages.getAnonymCallToken path
// with VK Connect's public client_id (8093730 — no client_secret required)
// is captcha-free as of 2026-05-17.
//
// 🚨 EXPECT VK TO ADD A CAPTCHA GATE HERE EVENTUALLY (weeks-to-months).
// When that happens, the legacy captcha solver (captcha_pow.go) and WebView
// fallback in creds.go still cover the case via GetVKCreds's auto-fallback
// chain. Do NOT delete legacy code.
//
// Discovery methodology: anyipa.me decrypt of VK Calls IPA + PlayCover
// runtime + frida-trace NSURLSession hook captured one messages.getCallPreview
// request whose URL revealed `client_id=8093730` + `anonymous_token=` + `v=5.276`.
// Full details in memory file vk_calls_anon_flow_2026_05_17.md.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
)

const (
	// vkConnectClientID is VK Connect's public app_id (vk8093730:// URL scheme
	// in VK Calls Info.plist). Requires no client_secret. Returns anon tokens
	// with `app_id:8093730` claim that pass messages.getAnonymCallToken's gate
	// without captcha on api.vk.me (as of 2026-05-17).
	vkConnectClientID = "8093730"

	// vkCallsAPIHost is the FQDN VK Calls uses for VK API. Same backend IPs as
	// api.vk.com / api.vk.ru but VK gates per-FQDN — captcha rules differ.
	vkCallsAPIHost = "api.vk.me"

	// vkCallsAPIVersion matches what VK Calls iOS sends. Legacy flow uses 5.275.
	vkCallsAPIVersion = "5.276"
)

// getVKCredsViaVKCallsPath fetches TURN credentials using VK Calls iOS app's
// captcha-free flow. Returns CaptchaRequiredError if a captcha gate
// unexpectedly appears (caller should fall back to legacy path then).
// Returns generic error on any other failure (caller can also try legacy).
func getVKCredsViaVKCallsPath(linkID string) (*TURNCreds, error) {
	deviceID := uuid.New().String()
	name := generateName()
	ua := GetSessionUserAgent()
	linkURL := neturl.QueryEscape("https://vk.com/call/join/" + linkID)
	nameEnc := neturl.QueryEscape(name)

	log.Printf("vkcalls: identity — name: %s, device_id: %s, UA: %s", name, deviceID, ua)

	// doRequest issues a POST to the given URL with no body (all params in URL
	// per VK API convention). Returns parsed JSON response or error.
	doRequest := func(url string) (map[string]interface{}, error) {
		client := GetSessionClient()
		req, err := fhttp.NewRequest("POST", url, bytes.NewReader(nil))
		if err != nil {
			return nil, err
		}
		// Headers — minimal set matching what frida-trace captured from real
		// VK Calls. Notably absent: Origin, Referer (legacy flow sends these
		// because it imitates WebView; VK Calls is a native app).
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "en-GB,en;q=0.9")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpResp.Body.Close() }()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal: %w, body: %s", err, truncate(string(body), 200))
		}
		return resp, nil
	}

	// Step 1: get anonymous_token from VK Connect.
	// auth.getAnonymToken with client_id=8093730 returns:
	//   {response: {token: "anonym.<JWT>", expired_at: <epoch>}}
	step1URL := fmt.Sprintf(
		"https://%s/method/auth.getAnonymToken?v=%s&client_id=%s&link=%s&device_id=%s&anonymName=%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, vkConnectClientID,
		linkURL, deviceID, nameEnc,
	)
	resp1, err := doRequest(step1URL)
	if err != nil {
		return nil, fmt.Errorf("vkcalls step1 (auth.getAnonymToken): %w", err)
	}
	anonymToken, err := extractStrFromResp(resp1, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step1 parse: %w (resp: %v)", err, truncResp(resp1))
	}
	anonymTokenEnc := neturl.QueryEscape(anonymToken)
	log.Printf("vkcalls: step1 OK, anonymous_token (%d chars)", len(anonymToken))

	// Step 2: get call preview → user_id + secret JWT.
	step2URL := fmt.Sprintf(
		"https://%s/method/messages.getCallPreview?v=%s&anonymous_token=%s&device_id=%s&extended=1&fields=first_name,last_name,photo_200&lang=en&link=%s",
		vkCallsAPIHost, vkCallsAPIVersion, anonymTokenEnc, deviceID, linkURL,
	)
	resp2, err := doRequest(step2URL)
	if err != nil {
		return nil, fmt.Errorf("vkcalls step2 (messages.getCallPreview): %w", err)
	}
	if captchaSID, captchaImg, captchaTs, captchaAttempt := extractCaptcha(resp2); captchaSID != "" {
		log.Printf("vkcalls: step2 captcha gate APPEARED (sid=%s) — VK closed messages.getCallPreview", captchaSID)
		return nil, &CaptchaRequiredError{
			ImageURL: captchaImg, SID: captchaSID,
			CaptchaTs: captchaTs, CaptchaAttempt: captchaAttempt,
		}
	}
	userIDFloat, err := extractFloatFromResp(resp2, "response", "user_id")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step2 parse user_id: %w (resp: %v)", err, truncResp(resp2))
	}
	userIDStr := fmt.Sprintf("%.0f", userIDFloat)
	secret, err := extractStrFromResp(resp2, "response", "secret")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step2 parse secret: %w", err)
	}
	log.Printf("vkcalls: step2 OK, user_id=%s, secret (%d chars)", userIDStr, len(secret))

	// Step 3: getAnonymCallToken → OK anonymToken (32-char hex).
	// THIS IS THE GATE THAT FORCED-CAPTCHA'd our legacy client_ids.
	// VK Connect (8093730) passes here without captcha.
	step3URL := fmt.Sprintf(
		"https://%s/method/messages.getAnonymCallToken?v=%s&anonymous_token=%s&device_id=%s&link=%s&name=%s&user_id=%s&secret=%s&lang=en",
		vkCallsAPIHost, vkCallsAPIVersion, anonymTokenEnc, deviceID, linkURL,
		nameEnc, userIDStr, neturl.QueryEscape(secret),
	)
	resp3, err := doRequest(step3URL)
	if err != nil {
		return nil, fmt.Errorf("vkcalls step3 (messages.getAnonymCallToken): %w", err)
	}
	if captchaSID, captchaImg, captchaTs, captchaAttempt := extractCaptcha(resp3); captchaSID != "" {
		log.Printf("vkcalls: step3 captcha gate APPEARED (sid=%s) — VK closed messages.getAnonymCallToken path", captchaSID)
		return nil, &CaptchaRequiredError{
			ImageURL: captchaImg, SID: captchaSID,
			CaptchaTs: captchaTs, CaptchaAttempt: captchaAttempt,
		}
	}
	okAnonymToken, err := extractStrFromResp(resp3, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step3 parse: %w (resp: %v)", err, truncResp(resp3))
	}
	log.Printf("vkcalls: step3 OK, OK anonymToken (%d chars)", len(okAnonymToken))

	// Step 4: OK auth.anonymLogin → session_key.
	// IDENTICAL to legacy step 3 (creds.go:543) — same OK endpoint, same
	// session_data shape, same application_key.
	okDeviceID := uuid.New().String()
	step4URL := "https://calls.okcdn.ru/fb.do?session_data=" +
		neturl.QueryEscape(fmt.Sprintf(
			`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, okDeviceID,
		)) +
		"&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"
	resp4, err := doRequest(step4URL)
	if err != nil {
		return nil, fmt.Errorf("vkcalls step4 (auth.anonymLogin): %w", err)
	}
	sessionKey, err := extractStrFromResp(resp4, "session_key")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step4 parse: %w", err)
	}
	log.Printf("vkcalls: step4 OK, OK session_key (%d chars)", len(sessionKey))

	// Step 5: vchat.joinConversationByLink → TURN credentials.
	// IDENTICAL to legacy step 4 (creds.go:553) — same OK endpoint, same
	// param shape. Only difference: anonymToken comes from new step 3 path.
	step5URL := fmt.Sprintf(
		"https://calls.okcdn.ru/fb.do?joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		linkID, okAnonymToken, sessionKey,
	)
	resp5, err := doRequest(step5URL)
	if err != nil {
		return nil, fmt.Errorf("vkcalls step5 (vchat.joinConversationByLink): %w", err)
	}

	// Parse TURN creds — same shape as legacy flow.
	user, err := extractStrFromResp(resp5, "turn_server", "username")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step5 parse username: %w (resp: %v)", err, truncResp(resp5))
	}
	pass, err := extractStrFromResp(resp5, "turn_server", "credential")
	if err != nil {
		return nil, fmt.Errorf("vkcalls step5 parse credential: %w", err)
	}
	addresses := parseTURNAddressesFromResp(resp5)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("vkcalls step5: turn_server.urls empty")
	}

	log.Printf("vkcalls: SUCCESS — username=%s, addresses=%v", user, addresses)
	return &TURNCreds{
		Username:  user,
		Password:  pass,
		Address:   addresses[0],
		Addresses: addresses,
	}, nil
}

// --- Helpers (duplicated from getVKCredsWithClientID closures for isolation) ---

// extractStrFromResp walks resp[keys[0]][keys[1]]... and returns the leaf
// value as a string. Same logic as the closure-form extractStr in creds.go;
// duplicated here to keep creds_vkcalls.go fully self-contained.
func extractStrFromResp(resp map[string]interface{}, keys ...string) (string, error) {
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

// extractFloatFromResp same as extractStrFromResp but for numeric leaves.
// VK API returns user_id as a JSON number (large negative int for anon users)
// which JSON unmarshal yields as float64.
func extractFloatFromResp(resp map[string]interface{}, keys ...string) (float64, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return 0, fmt.Errorf("expected map at key %q, got %T", k, cur)
		}
		cur = m[k]
	}
	f, ok := cur.(float64)
	if !ok {
		return 0, fmt.Errorf("expected float64 at end of path, got %T", cur)
	}
	return f, nil
}

// parseTURNAddressesFromResp extracts host:port strings from
// response.turn_server.urls[]. Same parsing as legacy getVKCredsWithClientID
// (creds.go:573-593) — duplicated for isolation. Strips "turn:" / "turns:"
// prefix and ?query suffix.
func parseTURNAddressesFromResp(resp map[string]interface{}) []string {
	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok {
		return nil
	}
	var addrs []string
	for i, u := range urls {
		s, ok := u.(string)
		if !ok {
			log.Printf("vkcalls: turn_server.urls[%d]=<non-string %T> — skipping", i, u)
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		log.Printf("vkcalls: turn_server.urls[%d]=%s", i, addr)
		addrs = append(addrs, addr)
	}
	return addrs
}

// truncate trims s to at most n characters, appending "..." if shortened.
// Used for compact error messages from large JSON bodies.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// truncResp renders a map response as a short string for error messages
// without dumping the full payload (which can be many KB).
func truncResp(resp map[string]interface{}) string {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Sprintf("(unmarshallable: %v)", err)
	}
	return truncate(string(b), 300)
}
