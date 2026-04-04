package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// captchaPowUA stores the User-Agent for the current PoW session.
// Set by solveCaptchaPoW() caller — must match the UA used for the VK API
// request that triggered the captcha (VK fingerprints UA mismatches).
var captchaPowUA string

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(mathrand.Intn(256))
		}
	}
	return hex.EncodeToString(b)
}

// newHTTPClient creates a fresh http.Client for each request.
// Uses standard Go TLS (same as TurnBridge and Android fork, both confirmed working).
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}
}

// solveCaptchaPoW attempts to solve a VK "Not Robot" captcha automatically
// using proof-of-work, without any user interaction.
func solveCaptchaPoW(ctx context.Context, redirectURI, captchaSID, userAgent string) (string, error) {
	// Use the same UA as the VK API request that triggered the captcha.
	// VK ties the captcha session to the original request's fingerprint —
	// using a different UA triggers BOT detection.
	captchaPowUA = userAgent
	log.Printf("pow: attempting automatic captcha solve (UA: %s)", captchaPowUA)

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	sessionToken := parsed.Query().Get("session_token")
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Random initial delay (1-2.5s) to look human-like
	delay := time.Duration(1000+mathrand.Intn(1500)) * time.Millisecond
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// Step 1: Fetch captcha page and extract PoW parameters
	powInput, difficulty, err := fetchPoW(ctx, redirectURI)
	if err != nil {
		return "", fmt.Errorf("fetch PoW: %w", err)
	}
	log.Printf("pow: input=%s difficulty=%d", powInput, difficulty)

	// Step 2: Solve PoW (brute-force SHA-256)
	hash := solvePoW(powInput, difficulty)
	if hash == "" {
		return "", fmt.Errorf("PoW: no solution found within 10M iterations")
	}
	log.Printf("pow: solved hash=%s...%s", hash[:8], hash[len(hash)-8:])

	// Brief pause after PoW (simulate browser JS execution time)
	time.Sleep(time.Duration(200+mathrand.Intn(300)) * time.Millisecond)

	// Step 3: Call captchaNotRobot API sequence
	successToken, err := callCaptchaNotRobotAPI(ctx, sessionToken, hash)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API: %w", err)
	}

	log.Printf("pow: success! token=%d chars", len(successToken))
	return successToken, nil
}

// fetchPoW fetches the captcha HTML page and extracts PoW parameters.
func fetchPoW(ctx context.Context, redirectURI string) (powInput string, difficulty int, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", captchaPowUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	client := newHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("pow: fetchPoW HTTP status=%d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	html := string(body)

	powRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	m := powRe.FindStringSubmatch(html)
	if len(m) < 2 {
		// Log first 500 chars of HTML for debugging
		preview := html
		if len(preview) > 500 {
			preview = preview[:500]
		}
		log.Printf("pow: HTML preview: %s", preview)
		return "", 0, fmt.Errorf("powInput not found in HTML (%d bytes)", len(html))
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

	return powInput, difficulty, nil
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
func callCaptchaNotRobotAPI(ctx context.Context, sessionToken, hash string) (string, error) {
	// Each API call uses a fresh http.Client (matching TurnBridge's behavior)
	vkReq := func(method, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", captchaPowUA)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("sec-ch-ua-platform", `"Linux"`)
		req.Header.Set("sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("DNT", "1")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-GPC", "1")

		client := newHTTPClient()
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP POST %s failed: %w", method, err)
		}
		defer httpResp.Body.Close()

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
	_, err := vkReq("captchaNotRobot.settings", baseParams)
	if err != nil {
		return "", fmt.Errorf("settings: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	// 2/4: componentDone — send fake desktop browser fingerprint
	log.Printf("pow: 2/4 captchaNotRobot.componentDone")
	browserFp := randomHex(16)

	resolutions := [][]int{{1920, 1080}, {1366, 768}, {1440, 900}, {1536, 864}, {2560, 1440}}
	res := resolutions[mathrand.Intn(len(resolutions))]
	screenW, screenH := res[0], res[1]

	cores := []int{4, 8, 12, 16}[mathrand.Intn(4)]
	ram := []int{4, 8, 16, 32}[mathrand.Intn(4)]

	deviceMap := map[string]interface{}{
		"screenWidth":             screenW,
		"screenHeight":            screenH,
		"screenAvailWidth":        screenW,
		"screenAvailHeight":       screenH - 40,
		"innerWidth":              screenW - mathrand.Intn(100),
		"innerHeight":             screenH - 100 - mathrand.Intn(50),
		"devicePixelRatio":        []float64{1, 1.25, 1.5, 2}[mathrand.Intn(4)],
		"language":                "en-US",
		"languages":               []string{"en-US", "en"},
		"webdriver":               false,
		"hardwareConcurrency":     cores,
		"deviceMemory":            ram,
		"connectionEffectiveType": "4g",
		"notificationsPermission": "denied",
	}
	deviceBytes, _ := json.Marshal(deviceMap)

	componentData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
		browserFp, url.QueryEscape(string(deviceBytes)))

	_, err = vkReq("captchaNotRobot.componentDone", componentData)
	if err != nil {
		return "", fmt.Errorf("componentDone: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	// 3/4: check — send PoW hash + fake telemetry
	log.Printf("pow: 3/4 captchaNotRobot.check")

	type Point struct {
		X int `json:"x"`
		Y int `json:"y"`
	}
	var cursor []Point
	cx, cy := screenW/2+mathrand.Intn(200)-100, screenH/2+mathrand.Intn(200)-100
	for i := 0; i < 4+mathrand.Intn(5); i++ {
		cursor = append(cursor, Point{X: cx, Y: cy})
		cx += mathrand.Intn(30) - 15
		cy += mathrand.Intn(30) - 15
	}
	cursorBytes, _ := json.Marshal(cursor)

	var downlink []float64
	baseSpeed := float64(mathrand.Intn(8) + 2)
	for i := 0; i < 16; i++ {
		downlink = append(downlink, baseSpeed)
	}
	downlinkBytes, _ := json.Marshal(downlink)

	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

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
		randomHex(32),
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
	if status != "OK" {
		return "", fmt.Errorf("check: status=%s response=%v", status, checkResp)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("check: no success_token in response")
	}

	time.Sleep(200 * time.Millisecond)

	// 4/4: endSession (non-fatal)
	log.Printf("pow: 4/4 captchaNotRobot.endSession")
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		log.Printf("pow: endSession failed (non-fatal): %v", err)
	}

	return successToken, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
