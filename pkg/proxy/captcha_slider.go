package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"log"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sliderCaptchaType     = "slider"
	defaultSliderAttempts = 4
)

// vkReqFunc is the type for the VK API request helper from callCaptchaNotRobotAPI.
type vkReqFunc func(method, postData string) (map[string]interface{}, error)

type sliderCaptchaContent struct {
	Image    image.Image
	Size     int    // grid NxN
	Steps    []int  // swap pairs
	Attempts int    // max submit attempts
}

type sliderCandidate struct {
	Index       int
	ActiveSteps []int
	Score       int64
}

// solveSliderCaptcha attempts to solve a VK slider captcha automatically.
// It fetches the scrambled image via captchaNotRobot.getContent, analyzes
// tile border continuity to find the correct permutation, and submits the answer.
func solveSliderCaptcha(
	vkReq vkReqFunc,
	baseParams string,
	browserFp string,
	hash string,
	settingsResp map[string]interface{},
) (string, error) {
	// Extract slider settings from the settings response
	sliderSettings := extractSliderSettings(settingsResp)

	log.Printf("slider: fetching captcha content (settings=%q)", sliderSettings)

	// Get scrambled image and swap instructions
	getContentData := baseParams
	if sliderSettings != "" {
		getContentData += "&captcha_settings=" + neturl.QueryEscape(sliderSettings)
	}

	resp, err := vkReq("captchaNotRobot.getContent", getContentData)
	if err != nil {
		return "", fmt.Errorf("slider getContent: %w", err)
	}

	content, err := parseSliderContent(resp)
	if err != nil {
		return "", fmt.Errorf("slider parse: %w", err)
	}

	log.Printf("slider: image=%dx%d grid=%d steps=%d attempts=%d",
		content.Image.Bounds().Dx(), content.Image.Bounds().Dy(),
		content.Size, len(content.Steps)/2, content.Attempts)

	// Rank candidate positions by pixel border continuity
	candidates, err := rankSliderCandidates(content.Image, content.Size, content.Steps)
	if err != nil {
		return "", fmt.Errorf("slider rank: %w", err)
	}

	maxTries := content.Attempts
	if maxTries > len(candidates) {
		maxTries = len(candidates)
	}

	log.Printf("slider: ranked %d positions, trying top %d", len(candidates), maxTries)

	// Try each candidate
	for i := 0; i < maxTries; i++ {
		c := candidates[i]
		log.Printf("slider: guess %d/%d position=%d score=%d", i+1, maxTries, c.Index, c.Score)

		answer, err := encodeSliderAnswer(c.ActiveSteps)
		if err != nil {
			return "", err
		}

		// Generate slider cursor (simulates drag from left to position)
		cursor := generateSliderCursor(c.Index, len(candidates))

		checkData := baseParams + fmt.Sprintf(
			"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
				"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
			neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
			neturl.QueryEscape(cursor),
			neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
			browserFp, hash, neturl.QueryEscape(answer),
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		)

		checkResp, err := vkReq("captchaNotRobot.check", checkData)
		if err != nil {
			return "", fmt.Errorf("slider check: %w", err)
		}

		respObj, ok := checkResp["response"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("slider check: invalid response")
		}

		status, _ := respObj["status"].(string)
		switch status {
		case "OK":
			successToken, _ := respObj["success_token"].(string)
			if successToken == "" {
				return "", fmt.Errorf("slider: success_token not found")
			}
			log.Printf("slider: solved! position=%d (attempt %d/%d)", c.Index, i+1, maxTries)
			return successToken, nil
		case "ERROR_LIMIT":
			return "", fmt.Errorf("slider: ERROR_LIMIT")
		default:
			log.Printf("slider: position=%d rejected (status=%s)", c.Index, status)
			time.Sleep(500 * time.Millisecond)
		}
	}

	return "", fmt.Errorf("slider: all %d guesses rejected", maxTries)
}

// extractSliderSettings extracts slider captcha_settings from settings API response.
func extractSliderSettings(settingsResp map[string]interface{}) string {
	if settingsResp == nil {
		return ""
	}
	respObj, ok := settingsResp["response"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Try to find captcha_settings for slider type
	raw := respObj["captcha_settings"]
	if raw == nil {
		return ""
	}

	// captcha_settings can be array or map
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			t, _ := m["type"].(string)
			if t == sliderCaptchaType {
				return normalizeSettings(m["settings"])
			}
		}
	case map[string]interface{}:
		if s, ok := v[sliderCaptchaType]; ok {
			return normalizeSettings(s)
		}
	case string:
		// Try JSON parse
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return ""
		}
		var items []interface{}
		if err := json.Unmarshal([]byte(trimmed), &items); err == nil {
			return extractSliderSettings(map[string]interface{}{
				"response": map[string]interface{}{"captcha_settings": items},
			})
		}
	}
	return ""
}

func normalizeSettings(raw interface{}) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

// parseSliderContent parses the getContent API response.
func parseSliderContent(resp map[string]interface{}) (*sliderCaptchaContent, error) {
	respObj, ok := resp["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response: %v", resp)
	}

	status, _ := respObj["status"].(string)
	if status != "OK" {
		return nil, fmt.Errorf("status: %s", status)
	}

	ext, _ := respObj["extension"].(string)
	ext = strings.ToLower(ext)
	if ext != "jpeg" && ext != "jpg" {
		return nil, fmt.Errorf("unsupported image format: %s", ext)
	}

	rawImage, _ := respObj["image"].(string)
	if rawImage == "" {
		return nil, fmt.Errorf("image missing")
	}

	rawSteps, ok := respObj["steps"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("steps missing")
	}

	steps, err := parseIntSlice(rawSteps)
	if err != nil {
		return nil, err
	}

	size, swaps, attempts, err := parseSliderSteps(steps)
	if err != nil {
		return nil, err
	}

	img, err := decodeSliderImage(rawImage)
	if err != nil {
		return nil, err
	}

	return &sliderCaptchaContent{
		Image:    img,
		Size:     size,
		Steps:    swaps,
		Attempts: attempts,
	}, nil
}

func parseIntSlice(raw []interface{}) ([]int, error) {
	values := make([]int, 0, len(raw))
	for _, item := range raw {
		switch v := item.(type) {
		case float64:
			values = append(values, int(v))
		case int:
			values = append(values, v)
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("invalid numeric: %v", item)
			}
			values = append(values, n)
		default:
			return nil, fmt.Errorf("invalid numeric: %v", item)
		}
	}
	return values, nil
}

func parseSliderSteps(steps []int) (int, []int, int, error) {
	if len(steps) < 3 {
		return 0, nil, 0, fmt.Errorf("steps too short: %d", len(steps))
	}

	size := steps[0]
	if size <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid grid size: %d", size)
	}

	remaining := append([]int(nil), steps[1:]...)
	attempts := defaultSliderAttempts
	if len(remaining)%2 != 0 {
		attempts = remaining[len(remaining)-1]
		remaining = remaining[:len(remaining)-1]
	}
	if attempts <= 0 {
		attempts = defaultSliderAttempts
	}
	if len(remaining) == 0 || len(remaining)%2 != 0 {
		return 0, nil, 0, fmt.Errorf("invalid swap payload")
	}

	return size, remaining, attempts, nil
}

func decodeSliderImage(rawImage string) (image.Image, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawImage)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	img, _, err := image.Decode(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("image decode: %w", err)
	}
	return img, nil
}

func encodeSliderAnswer(activeSteps []int) (string, error) {
	payload := struct {
		Value []int `json:"value"`
	}{Value: activeSteps}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// rankSliderCandidates analyzes each candidate permutation and ranks by
// pixel border continuity (lower score = better match = more likely correct).
func rankSliderCandidates(img image.Image, gridSize int, swaps []int) ([]sliderCandidate, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, fmt.Errorf("no candidates")
	}

	candidates := make([]sliderCandidate, 0, candidateCount)
	for idx := 1; idx <= candidateCount; idx++ {
		activeSteps := buildSliderActiveSteps(swaps, idx)
		mapping, err := buildSliderTileMapping(gridSize, activeSteps)
		if err != nil {
			return nil, err
		}

		rendered, err := renderSliderCandidate(img, gridSize, mapping)
		if err != nil {
			return nil, err
		}

		score := scoreRenderedSliderImage(rendered, gridSize)
		candidates = append(candidates, sliderCandidate{
			Index:       idx,
			ActiveSteps: activeSteps,
			Score:       score,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].Index < candidates[j].Index
		}
		return candidates[i].Score < candidates[j].Score
	})

	return candidates, nil
}

func buildSliderActiveSteps(swaps []int, candidateIndex int) []int {
	if candidateIndex <= 0 {
		return []int{}
	}
	end := candidateIndex * 2
	if end > len(swaps) {
		end = len(swaps)
	}
	return append([]int(nil), swaps[:end]...)
}

func buildSliderTileMapping(gridSize int, activeSteps []int) ([]int, error) {
	tileCount := gridSize * gridSize
	if tileCount <= 0 {
		return nil, fmt.Errorf("invalid tile count")
	}
	if len(activeSteps)%2 != 0 {
		return nil, fmt.Errorf("invalid steps length: %d", len(activeSteps))
	}

	mapping := make([]int, tileCount)
	for i := range mapping {
		mapping[i] = i
	}
	for idx := 0; idx < len(activeSteps); idx += 2 {
		l, r := activeSteps[idx], activeSteps[idx+1]
		if l < 0 || r < 0 || l >= tileCount || r >= tileCount {
			return nil, fmt.Errorf("step out of range: %d,%d", l, r)
		}
		mapping[l], mapping[r] = mapping[r], mapping[l]
	}
	return mapping, nil
}

func renderSliderCandidate(img image.Image, gridSize int, mapping []int) (*image.RGBA, error) {
	tileCount := gridSize * gridSize
	if len(mapping) != tileCount {
		return nil, fmt.Errorf("mapping length %d != %d", len(mapping), tileCount)
	}

	bounds := img.Bounds()
	rendered := image.NewRGBA(bounds)
	for dstIdx, srcIdx := range mapping {
		srcRect := sliderTileRect(bounds, gridSize, srcIdx)
		dstRect := sliderTileRect(bounds, gridSize, dstIdx)
		copyTile(rendered, dstRect, img, srcRect)
	}
	return rendered, nil
}

func scoreRenderedSliderImage(img image.Image, gridSize int) int64 {
	bounds := img.Bounds()
	var score int64

	// Horizontal borders (left tile right edge vs right tile left edge)
	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftRect := sliderTileRect(bounds, gridSize, row*gridSize+col)
			rightRect := sliderTileRect(bounds, gridSize, row*gridSize+col+1)
			height := leftRect.Dy()
			if h := rightRect.Dy(); h < height {
				height = h
			}
			for y := 0; y < height; y++ {
				score += pixelDiff(
					img.At(leftRect.Max.X-1, leftRect.Min.Y+y),
					img.At(rightRect.Min.X, rightRect.Min.Y+y),
				)
			}
		}
	}

	// Vertical borders (top tile bottom edge vs bottom tile top edge)
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topRect := sliderTileRect(bounds, gridSize, row*gridSize+col)
			bottomRect := sliderTileRect(bounds, gridSize, (row+1)*gridSize+col)
			width := topRect.Dx()
			if w := bottomRect.Dx(); w < width {
				width = w
			}
			for x := 0; x < width; x++ {
				score += pixelDiff(
					img.At(topRect.Min.X+x, topRect.Max.Y-1),
					img.At(bottomRect.Min.X+x, bottomRect.Min.Y),
				)
			}
		}
	}

	return score
}

func sliderTileRect(bounds image.Rectangle, gridSize, index int) image.Rectangle {
	row := index / gridSize
	col := index % gridSize
	x0 := bounds.Min.X + col*bounds.Dx()/gridSize
	x1 := bounds.Min.X + (col+1)*bounds.Dx()/gridSize
	y0 := bounds.Min.Y + row*bounds.Dy()/gridSize
	y1 := bounds.Min.Y + (row+1)*bounds.Dy()/gridSize
	return image.Rect(x0, y0, x1, y1)
}

func copyTile(dst *image.RGBA, dstRect image.Rectangle, src image.Image, srcRect image.Rectangle) {
	dw, dh := dstRect.Dx(), dstRect.Dy()
	sw, sh := srcRect.Dx(), srcRect.Dy()
	for y := 0; y < dh; y++ {
		sy := srcRect.Min.Y + y*sh/dh
		for x := 0; x < dw; x++ {
			sx := srcRect.Min.X + x*sw/dw
			dst.Set(dstRect.Min.X+x, dstRect.Min.Y+y, src.At(sx, sy))
		}
	}
}

func pixelDiff(a, b color.Color) int64 {
	ar, ag, ab, _ := a.RGBA()
	br, bg, bb, _ := b.RGBA()
	return absDiff(ar, br) + absDiff(ag, bg) + absDiff(ab, bb)
}

func absDiff(a, b uint32) int64 {
	if a > b {
		return int64(a - b)
	}
	return int64(b - a)
}

func generateSliderCursor(candidateIndex, candidateCount int) string {
	if candidateCount <= 0 {
		return "[]"
	}
	type point struct {
		X int   `json:"x"`
		Y int   `json:"y"`
		T int64 `json:"t"`
	}
	startX := 140
	endX := startX + 620*candidateIndex/candidateCount
	startY := 430
	startTime := time.Now().Add(-220 * time.Millisecond).UnixMilli()

	points := make([]point, 12)
	for i := 0; i < 12; i++ {
		points[i] = point{
			X: startX + (endX-startX)*i/11,
			Y: startY + (i%3 - 1),
			T: startTime + int64(i*18),
		}
	}
	data, _ := json.Marshal(points)
	return string(data)
}
