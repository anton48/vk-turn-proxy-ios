package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// captchaPowProfile stores the browser profile for the current PoW session.
var captchaPowProfile BrowserProfile

// randomHex generates a random hex string of n bytes (2n hex chars).
var _ = randomHex

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(mathrand.Intn(256))
		}
	}
	return hex.EncodeToString(b)
}

// newSessionClient creates an HTTP client with a shared cookie jar and Chrome TLS fingerprint.
func newSessionClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   20 * time.Second,
		Jar:       jar,
		Transport: newChromeTransport(),
	}
}

// newHTTPClient creates a fresh http.Client (no cookie jar) with Chrome TLS fingerprint.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: newChromeTransport(),
	}
}

// checkboxBurnedForSession is set the first time a checkbox-style
// captchaNotRobot.check returns status=ERROR, which is VK's explicit
// "this captcha type is disabled" signal. Once set, all subsequent
// solveCaptchaPoW calls in the current global session (Proxy instance)
// will skip the checkbox check entirely and jump straight to the slider.
//
// Other non-OK statuses (BOT, ERROR_LIMIT, etc.) are transient — they mean
// "try again later", not "this type is disabled" — so they do NOT burn the
// checkbox; the next solveCaptchaPoW call will still attempt the checkbox.
//
// Reset to false by NewProxy() at the start of every connect cycle.
var checkboxBurnedForSession atomic.Bool

// solveCaptchaPoW attempts to solve a VK "Not Robot" captcha automatically
// using proof-of-work, without any user interaction.
func solveCaptchaPoW(ctx context.Context, redirectURI, captchaSID, userAgent string) (string, error) {
	captchaPowProfile = profileForUA(userAgent)
	log.Printf("pow: attempting automatic captcha solve (UA: %s, platform: %s, Chrome/%d)",
		captchaPowProfile.UserAgent, captchaPowProfile.Platform, captchaPowProfile.ChromeVersion)

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	sessionToken := parsed.Query().Get("session_token")
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Single HTTP client with cookie jar for the entire captcha session.
	client := newSessionClient()
	defer client.CloseIdleConnections()

	// Random initial delay (1.5-2.5s) — HAR timing from real browser
	delay := time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// Step 1: Fetch captcha page and extract PoW parameters + cookies + slider settings
	powInput, difficulty, htmlSettings, err := fetchPoW(ctx, client, redirectURI)
	if err != nil {
		return "", fmt.Errorf("fetch PoW: %w", err)
	}
	log.Printf("pow: input=%s difficulty=%d htmlSettings=%v", powInput, difficulty, htmlSettings != nil)

	// Log cookies received from page load (for debugging)
	if parsedURL, e := url.Parse("https://id.vk.ru"); e == nil {
		cookies := client.Jar.Cookies(parsedURL)
		log.Printf("pow: received %d cookies from page load", len(cookies))
	}
	if parsedURL, e := url.Parse("https://vk.ru"); e == nil {
		cookies := client.Jar.Cookies(parsedURL)
		log.Printf("pow: received %d cookies from vk.ru domain", len(cookies))
	}

	// Step 2: Solve PoW (brute-force SHA-256)
	hash := solvePoW(powInput, difficulty)
	if hash == "" {
		return "", fmt.Errorf("PoW: no solution found within 10M iterations")
	}
	log.Printf("pow: solved hash=%s...%s", hash[:8], hash[len(hash)-8:])

	// Brief pause after PoW (simulate browser JS execution time)
	time.Sleep(time.Duration(200+mathrand.Intn(300)) * time.Millisecond)

	// Step 3: Call captchaNotRobot API sequence (using same client = same cookies)
	successToken, err := callCaptchaNotRobotAPI(ctx, client, sessionToken, hash, htmlSettings)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API: %w", err)
	}

	log.Printf("pow: success! token=%d chars", len(successToken))
	return successToken, nil
}

// fetchPoW fetches the captcha HTML page and extracts PoW parameters.
func fetchPoW(ctx context.Context, client *http.Client, redirectURI string) (powInput string, difficulty int, htmlSettings map[string]interface{}, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
	req.Header.Set("sec-ch-ua", captchaPowProfile.SecChUA())
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", captchaPowProfile.SecChUAPlatform())
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("DNT", "1")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	log.Printf("pow: fetchPoW HTTP status=%d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, nil, err
	}
	html := string(body)

	powRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	m := powRe.FindStringSubmatch(html)
	if len(m) < 2 {
		preview := html
		if len(preview) > 500 {
			preview = preview[:500]
		}
		log.Printf("pow: HTML preview: %s", preview)
		return "", 0, nil, fmt.Errorf("powInput not found in HTML (%d bytes)", len(html))
	}
	powInput = m[1]

	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	dm := diffRe.FindStringSubmatch(html)
	difficulty = 2
	if len(dm) >= 2 {
		if d, e := strconv.Atoi(dm[1]); e == nil {
			difficulty = d
		}
	}

	// Also extract captcha_settings from window.init (for slider solver)
	initRe := regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?\})\s*;\s*window\.lang`)
	if initMatch := initRe.FindStringSubmatch(html); len(initMatch) >= 2 {
		var initPayload map[string]interface{}
		if err := json.Unmarshal([]byte(initMatch[1]), &initPayload); err == nil {
			if data, ok := initPayload["data"].(map[string]interface{}); ok {
				htmlSettings = map[string]interface{}{"response": data}
				showType, _ := data["show_captcha_type"].(string)
				log.Printf("pow: HTML captcha settings found (show_captcha_type=%q)", showType)
			}
		}
	}

	return powInput, difficulty, htmlSettings, nil
}


// solvePoW brute-forces SHA-256(powInput + nonce) until the hash
// starts with `difficulty` leading zeros.
func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10_000_000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		h := sha256.Sum256([]byte(data))
		hexH := hex.EncodeToString(h[:])
		if strings.HasPrefix(hexH, target) {
			return hexH
		}
	}
	return ""
}

// callCaptchaNotRobotAPI performs the 4-step VK captchaNotRobot protocol.
// Adapted from the reference implementation in PR #105 — uses simplified
// sensor data (empty arrays) and longer timing delays.
func callCaptchaNotRobotAPI(ctx context.Context, client *http.Client, sessionToken, hash string, htmlSettings map[string]interface{}) (string, error) {
	vkReq := func(method, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("sec-ch-ua", captchaPowProfile.SecChUA())
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("sec-ch-ua-platform", captchaPowProfile.SecChUAPlatform())
		req.Header.Set("DNT", "1")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-GPC", "1")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP POST %s failed: %w", method, err)
		}
		defer func() { _ = httpResp.Body.Close() }()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		log.Printf("pow: %s response: %s", method, string(body[:min(300, len(body))]))

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}
		return resp, nil
	}

	domain := "vk.com"
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))

	// 1/4: settings
	log.Printf("pow: 1/4 captchaNotRobot.settings")
	settingsResp, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings: %w", err)
	}

	// Short delay after settings (100-200ms) — matches reference impl
	time.Sleep(time.Duration(100+mathrand.Intn(100)) * time.Millisecond)

	// 2/4: componentDone
	log.Printf("pow: 2/4 captchaNotRobot.componentDone")
	browserFp := fmt.Sprintf("%x%x", mathrand.Int63(), mathrand.Int63())

	// Simplified device data matching reference implementation
	deviceMap := map[string]interface{}{
		"screenWidth":             1920,
		"screenHeight":            1080,
		"screenAvailWidth":        1920,
		"screenAvailHeight":       1040,
		"innerWidth":              1903,
		"innerHeight":             969,
		"devicePixelRatio":        1,
		"language":                "en-US",
		"languages":               []string{"en-US", "en", "ru"},
		"webdriver":               false,
		"hardwareConcurrency":     8,
		"deviceMemory":            8,
		"connectionEffectiveType": "4g",
		"notificationsPermission": "default",
	}
	deviceBytes, _ := json.Marshal(deviceMap)

	componentData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
		browserFp, url.QueryEscape(string(deviceBytes)))

	_, err = vkReq("captchaNotRobot.componentDone", componentData)
	if err != nil {
		return "", fmt.Errorf("componentDone: %w", err)
	}

	// 3/4: check (checkbox-style)
	//
	// Checkbox captcha is probed at most ONCE per global session (per Proxy
	// instance). After the first time it fails, checkboxBurnedForSession is
	// set and all subsequent solveCaptchaPoW calls in this session jump
	// straight to the slider path, saving ~2-3 seconds of wait + HTTP per
	// captcha.
	if checkboxBurnedForSession.Load() {
		log.Printf("pow: 3/4 skipping checkbox check (burned earlier this session), going straight to slider")
	} else {
		// Longer pause before check (1950-3200ms) — matches reference HAR timing
		checkDelay := time.Duration(1950+mathrand.Intn(1250)) * time.Millisecond
		log.Printf("pow: waiting %s before check", checkDelay.Round(time.Millisecond))
		select {
		case <-time.After(checkDelay):
		case <-ctx.Done():
			return "", ctx.Err()
		}

		log.Printf("pow: 3/4 captchaNotRobot.check")

		// Simplified sensor data — empty arrays for most sensors,
		// minimal cursor path. Reference impl shows VK accepts this
		// and overly-detailed fake data may trigger detection.
		now := time.Now().UnixMilli()
		cursorData := []map[string]interface{}{
			{"x": 960, "y": 540, "t": now - 2000},
			{"x": 965, "y": 538, "t": now - 1500},
			{"x": 970, "y": 535, "t": now - 1000},
			{"x": 972, "y": 533, "t": now - 500},
			{"x": 975, "y": 530, "t": now},
		}
		cursorBytes, _ := json.Marshal(cursorData)

		// Downlink: small array with realistic values
		var downlink []float64
		baseSpeed := 8.0 + mathrand.Float64()*4.0
		for i := 0; i < 7; i++ {
			downlink = append(downlink, baseSpeed+mathrand.Float64()*0.5-0.25)
		}
		downlinkBytes, _ := json.Marshal(downlink)

		answer := base64.StdEncoding.EncodeToString([]byte("{}"))

		// Fixed debug_info hash — a real browser sends consistent value
		debugInfo := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

		checkData := baseParams + fmt.Sprintf(
			"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
				"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
			url.QueryEscape("[]"),
			url.QueryEscape("[]"),
			url.QueryEscape("[]"),
			url.QueryEscape(string(cursorBytes)),
			url.QueryEscape("[]"),
			url.QueryEscape("[]"),
			url.QueryEscape(string(downlinkBytes)),
			browserFp,
			hash,
			answer,
			debugInfo,
		)

		checkResp, err := vkReq("captchaNotRobot.check", checkData)
		if err != nil {
			return "", fmt.Errorf("check: %w", err)
		}

		respObj, ok := checkResp["response"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("check: invalid response: %v", checkResp)
		}
		status, _ := respObj["status"].(string)
		if status == "OK" {
			successToken, ok := respObj["success_token"].(string)
			if !ok || successToken == "" {
				return "", fmt.Errorf("check: no success_token in response")
			}
			time.Sleep(200 * time.Millisecond)
			log.Printf("pow: 4/4 captchaNotRobot.endSession")
			_, err = vkReq("captchaNotRobot.endSession", baseParams)
			if err != nil {
				log.Printf("pow: endSession failed (non-fatal): %v", err)
			}
			return successToken, nil
		}

		// Checkbox check failed. Only burn the checkbox path when VK explicitly
		// signals that this captcha type is unavailable (status=ERROR). Other
		// statuses like BOT or ERROR_LIMIT are transient ("try again later"),
		// so we keep the checkbox enabled for future solveCaptchaPoW calls in
		// this session. In both cases control falls through to the slider
		// solver below as an in-call fallback.
		showCaptchaType, _ := respObj["show_captcha_type"].(string)
		if status == "ERROR" {
			log.Printf("pow: checkbox returned status=ERROR (captcha type disabled) — burning checkbox for the rest of this session, falling through to slider (show_captcha_type=%s)", showCaptchaType)
			checkboxBurnedForSession.Store(true)
		} else {
			log.Printf("pow: checkbox transient failure (status=%s, show_captcha_type=%s) — falling through to slider; if all else fails, next solveCaptchaPoW call will attempt checkbox again", status, showCaptchaType)
		}
	}

	// Try slider solver regardless of show_captcha_type — VK may not always
	// include it in the check response, but getContent may still work
	// Merge settings from API response and HTML page (HTML has slider settings
	// that the API response doesn't include)
	mergedSettings := settingsResp
	if htmlSettings != nil {
		mergedSettings = htmlSettings
		log.Printf("pow: using HTML-extracted captcha settings for slider")
	}
	log.Printf("pow: attempting automatic slider solver...")
	sliderToken, sliderErr := solveSliderCaptcha(vkReq, baseParams, browserFp, hash, mergedSettings)
	if sliderErr == nil && sliderToken != "" {
		log.Printf("pow: slider solver succeeded!")
		time.Sleep(200 * time.Millisecond)
		log.Printf("pow: 4/4 captchaNotRobot.endSession")
		_, err = vkReq("captchaNotRobot.endSession", baseParams)
		if err != nil {
			log.Printf("pow: endSession failed (non-fatal): %v", err)
		}
		return sliderToken, nil
	}
	log.Printf("pow: slider solver failed: %v", sliderErr)

	if checkboxBurnedForSession.Load() {
		return "", fmt.Errorf("checkbox burned earlier this session, slider also failed: %v", sliderErr)
	}
	return "", fmt.Errorf("checkbox check failed and slider also failed: %v", sliderErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
