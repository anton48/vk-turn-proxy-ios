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

// GetVKCreds fetches TURN credentials from VK using a call invite link ID.
// captchaSolver may be nil; if nil and captcha is required, an error is returned.
// solvedCaptchaSID/solvedCaptchaKey: if non-empty, are from a previous captcha solve.
// solvedCaptchaKey is the success_token from captchaNotRobot.check.
// solvedCaptchaTs/solvedCaptchaAttempt are from the original captcha error response.
// savedToken1: if non-empty, reuse this access_token from step1 instead of fetching a new one
// (the captcha is tied to the original step2 call which used this token1).
func GetVKCreds(linkID string, captchaSolver CaptchaSolver, solvedCaptchaSID, solvedCaptchaKey string, solvedCaptchaTs, solvedCaptchaAttempt float64, savedToken1 string) (*TURNCreds, error) {
	// Rotate through client_id/client_secret pairs to reduce per-app rate limiting.
	// Shuffle the list so each connection attempt uses a different order.
	creds := make([]vkCredentials, len(vkCredentialsList))
	copy(creds, vkCredentialsList)
	mathrand.Shuffle(len(creds), func(i, j int) { creds[i], creds[j] = creds[j], creds[i] })

	var lastErr error
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
	}
	return nil, fmt.Errorf("all %d client_ids failed, last error: %w", len(creds), lastErr)
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

			// All PoW attempts exhausted — fall back to WebView.
			// Return CaptchaRequiredError so the app can show WebView.
			// The app will request a FRESH captcha URL right before showing WebView
			// (the current URL may be stale if the app was in background).
			isRateLimit := lastPowErr != nil && strings.Contains(lastPowErr.Error(), "ERROR_LIMIT")
			log.Printf("vk: all %d PoW attempts failed, falling back to WebView (rateLimit=%v)", maxPoWRetries, isRateLimit)

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
