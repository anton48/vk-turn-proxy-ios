package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
	// Randomize identity for anti-detection: different UA and name per credential fetch.
	ua := randomUserAgent()
	name := generateName()
	escapedName := neturl.QueryEscape(name)
	log.Printf("vk: identity — name: %s, UA: %s", name, ua)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		}
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
		defer httpResp.Body.Close()

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

	// Step 1: get anonymous messages token
	// If savedToken1 is provided (captcha retry), reuse it instead of fetching a new one.
	// The captcha is tied to the step2 request that used this specific token1.
	var token1 string
	if savedToken1 != "" {
		token1 = savedToken1
		log.Printf("vk: reusing saved token1 for captcha retry")
	} else {
		data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
		resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
		if err != nil {
			return nil, fmt.Errorf("step1: %w", err)
		}
		token1, err = extractStr(resp, "data", "access_token")
		if err != nil {
			return nil, fmt.Errorf("step1 parse: %w", err)
		}
	}

	// Step 2: get anonymous call token (with captcha retry)
	var token2 string
	var resp map[string]interface{}
	var err error
	var data string
	step2URL := "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"
	step2Data := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", linkID, escapedName, token1)

	// If we have a pre-solved captcha (success_token from captchaNotRobot.check), include it.
	// Format matches https://github.com/cacggghp/vk-turn-proxy/pull/97
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

			// Try automatic PoW solver first (no user interaction needed).
			// This works even during phone sleep since it runs in the Network Extension.
			powCtx, powCancel := context.WithTimeout(context.Background(), 30*time.Second)
			powToken, powErr := solveCaptchaPoW(powCtx, captchaImg, captchaSID, ua)
			powCancel()

			if powErr == nil && powToken != "" {
				log.Printf("vk: PoW auto-solve succeeded (%d chars), retrying step2", len(powToken))
				step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d",
					linkID, escapedName, token1, captchaSID, neturl.QueryEscape(powToken), captchaTs, int(captchaAttempt))
				continue
			}

			// PoW failed — the session_token is burned (VK counts the failed attempt).
			// Do NOT try WebView with the same token — it will show "Attempt limit reached".
			// Instead, let the outer retry loop re-request step2 to get a fresh captcha.
			log.Printf("vk: PoW auto-solve failed: %v — requesting fresh captcha for WebView", powErr)

			// Re-request step2 WITHOUT captcha params to get a fresh captcha session
			step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", linkID, escapedName, token1)
			resp, err = doRequest(step2Data, step2URL)
			if err != nil {
				return nil, fmt.Errorf("step2 re-request: %w", err)
			}
			// Extract fresh captcha from the new response
			freshSID, freshImg, freshTs, freshAttempt := extractCaptcha(resp)
			if freshSID == "" {
				// No captcha this time — maybe VK accepted us?
				token2, err = extractStr(resp, "response", "token")
				if err != nil {
					return nil, fmt.Errorf("step2 parse after fresh: %w", err)
				}
				break
			}

			// Fall back to WebView with fresh captcha session
			if captchaSolver == nil {
				return nil, &CaptchaRequiredError{ImageURL: freshImg, SID: freshSID, CaptchaTs: freshTs, CaptchaAttempt: freshAttempt, Token1: token1}
			}
			answer, err := captchaSolver(freshImg)
			if err != nil {
				return nil, fmt.Errorf("step2: captcha solver: %w", err)
			}
			log.Printf("vk: WebView captcha solver returned answer (%d chars), retrying", len(answer))
			step2Data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%.3f&captcha_attempt=%d",
				linkID, escapedName, token1, freshSID, neturl.QueryEscape(answer), freshTs, int(freshAttempt))
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
	data = fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New())
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
