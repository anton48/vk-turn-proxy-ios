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
	"math"
	mathrand "math/rand"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sliderCaptchaType     = "slider"
	defaultSliderAttempts = 4
	// maxSliderGridSize bounds the grid dimension parsed from the untrusted VK
	// captcha response (steps[0]) — real VK sliders are ~3-6 tiles per side.
	// Without an upper bound a hostile response (e.g. steps[0]=50000) drives
	// make([]int, size*size) into a multi-GB allocation that jetsam-kills the
	// memory-constrained iOS Network Extension.
	maxSliderGridSize = 16
)

// vkReqFunc is the type for the VK API request helper from callCaptchaNotRobotAPI.
type vkReqFunc func(method, postData string) (map[string]interface{}, error)

type sliderCaptchaContent struct {
	Image    image.Image
	Size     int   // grid NxN
	Steps    []int // swap pairs
	Attempts int   // max submit attempts
}

type sliderCandidate struct {
	Index       int
	ActiveSteps []int
	Score       int64 // consensus rank (lower = better); for logging
}

// solveSliderCaptcha attempts to solve a VK slider captcha automatically.
// It fetches the scrambled image via captchaNotRobot.getContent, analyzes
// tile border continuity to find the correct permutation, and submits the answer.
//
// deviceParam is the URL-encoded device descriptor (matches whatever was
// sent in the prior componentDone — either generated default or captured
// from a real browser via vk_profile.json). Passed through unchanged to
// the re-issued componentDone before getContent.
func solveSliderCaptcha(
	vkReq vkReqFunc,
	baseParams string,
	browserFp string,
	deviceParam string,
	hash string,
	settingsResp map[string]interface{},
) (string, error) {
	// Re-issue captchaNotRobot.componentDone before getContent. Per
	// cacggghp PR #162 (commit 2bcb9e35, Moroka8): VK responds ERROR
	// to getContent without a fresh componentDone signal — VK is
	// waiting for the slider widget to announce it loaded. The earlier
	// componentDone call was for the checkbox path; slider needs its
	// own. Same browser_fp + device — those are session-scoped, not
	// per-widget. Failure here is non-fatal: try getContent anyway.
	componentDoneData := baseParams + "&browser_fp=" + browserFp + "&device=" + deviceParam + accessTokenSuffix
	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		log.Printf("slider: pre-getContent componentDone failed (non-fatal): %v", err)
	}

	// Extract slider settings from the settings response
	sliderSettings := extractSliderSettings(settingsResp)

	// Try getContent with captcha_settings, fall back to without if VK
	// returns ERROR. Per Moroka8: VK sometimes advertises show_type=
	// checkbox in settings but actually serves slider content, so the
	// captcha_settings string we extracted may not match. The unsettings'd
	// call uses VK's default, which works in those cases.
	resp, err := requestSliderContentWithFallback(vkReq, baseParams, sliderSettings)
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

	// Rank candidate permutations by the v2 3-metric consensus (luma seam +
	// RGB seam + text-band-weighted seam). Ported from amurcanov's
	// captcha_v2_slider.go rankSliderGuessesV2 (descends, like our old
	// solver, from Moroka8/cacggghp PR #162 but upgraded). Best = lowest
	// consensus rank.
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
		log.Printf("slider: guess %d/%d position=%d consensus=%d", i+1, maxTries, c.Index, c.Score)

		answer, err := encodeSliderAnswer(c.ActiveSteps)
		if err != nil {
			return "", err
		}

		// Human-like Bézier cursor path (v2). Simulates the drag with start
		// jitter → curved transit → approach → settle, vs our old 12-point
		// straight line. Ported from amurcanov buildSliderCursorV2.
		cursor := generateSliderCursor(c.Index, len(candidates))

		checkData := baseParams + fmt.Sprintf(
			"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
				"&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
			neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
			neturl.QueryEscape(cursor),
			neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
			browserFp, hash, neturl.QueryEscape(answer),
			// Hardcoded canonical debug_info constant — matches Safari
			// fallback (window.vk?.brlefapmjnpg || "a0ac4896..."). Same
			// rationale as captcha_pow.go check, applied to slider for
			// consistency. Phase 2 (build 93) fix extended here.
			"a0ac4896e9b899f78d905fd37c5adb2b768aa955eb7b2a7bcba6ee2a44a96daf",
		) + accessTokenSuffix

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

// requestSliderContentWithFallback calls captchaNotRobot.getContent first
// with the extracted captcha_settings string (if non-empty), then if the
// response status is not "OK", retries without captcha_settings. Per
// cacggghp PR #162 (commit 2bcb9e35, Moroka8): VK occasionally returns
// show_captcha_type=checkbox in /settings while actually serving slider
// content, so the captcha_settings extracted from /settings may not
// match what /getContent expects. Calling without captcha_settings lets
// VK pick its default which works in those cases.
//
// Returns the response from whichever call returned status=OK (or the
// last one tried), so the caller can pass it straight to parseSliderContent.
// On HTTP-layer error from vkReq, gives up immediately.
func requestSliderContentWithFallback(vkReq vkReqFunc, baseParams, sliderSettings string) (map[string]interface{}, error) {
	tryGetContent := func(withSettings bool) (map[string]interface{}, string, error) {
		data := baseParams
		if withSettings && sliderSettings != "" {
			data += "&captcha_settings=" + neturl.QueryEscape(sliderSettings)
		}
		data += accessTokenSuffix
		resp, err := vkReq("captchaNotRobot.getContent", data)
		if err != nil {
			return nil, "", err
		}
		respObj, ok := resp["response"].(map[string]interface{})
		if !ok {
			return resp, "", nil
		}
		status, _ := respObj["status"].(string)
		return resp, status, nil
	}

	if sliderSettings != "" {
		log.Printf("slider: getContent attempt 1 (with captcha_settings, %d chars)", len(sliderSettings))
		resp, status, err := tryGetContent(true)
		if err != nil {
			return nil, err
		}
		if status == "OK" {
			return resp, nil
		}
		log.Printf("slider: getContent with settings returned status=%q, retrying without", status)
	} else {
		log.Printf("slider: getContent attempt 1 (no captcha_settings extracted)")
	}

	resp, status, err := tryGetContent(false)
	if err != nil {
		return nil, err
	}
	if status != "OK" && status != "" {
		log.Printf("slider: getContent without settings also returned status=%q", status)
	}
	return resp, nil
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
	if size > maxSliderGridSize {
		return 0, nil, 0, fmt.Errorf("grid size too large: %d", size)
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

// rankSliderCandidates ranks each candidate permutation by a 3-metric
// consensus, ported from amurcanov's captcha_v2_slider.go rankSliderGuessesV2.
//
// Two-stage so the (more expensive) RGB+text metrics only run on the most
// promising candidates:
//   - Stage 1: luma seam-continuity for ALL candidates → luma rank.
//   - Stage 2: the top ≤12 by luma → RGB seam score + a text-band-weighted
//     seam score (a Gaussian bump around the 3 horizontal text stripes at
//     0.2/0.5/0.8 of image height, on the blue channel where VK's overlaid
//     text contrasts most) → RGB rank + text rank.
//   - Consensus rank = lumaRank + (rgbRank + textRank for stage-2, else
//     +candidateCount). Lower = better.
//
// Computed SEQUENTIALLY (amurcanov parallelizes stage 2 with a worker pool;
// we don't — the image is tiny and ≤12 candidates, and the iOS NetworkExtension
// is memory-constrained, so avoiding transient goroutines/channels is safer).
//
// Reuses our buildSliderActiveSteps / buildSliderTileMapping / sliderTileRect
// (byte-identical to amurcanov's activeSwapsForIndexV2 / applySliderSwapsV2 /
// sliderTileRect). The seam scorers sample the ORIGINAL image through the
// mapping on the fly (no per-candidate render), like amurcanov's v2.
func rankSliderCandidates(img image.Image, gridSize int, swaps []int) ([]sliderCandidate, error) {
	candidateCount := len(swaps) / 2
	if candidateCount == 0 {
		return nil, fmt.Errorf("no candidates")
	}

	type scored struct {
		index       int
		activeSteps []int
		luma        int64
		rgb         int64
		text        float64
		consensus   int
	}

	all := make([]scored, candidateCount)
	for idx := 1; idx <= candidateCount; idx++ {
		active := buildSliderActiveSteps(swaps, idx)
		mapping, err := buildSliderTileMapping(gridSize, active)
		if err != nil {
			return nil, err
		}
		all[idx-1] = scored{
			index:       idx,
			activeSteps: active,
			luma:        seamScoreLumaV2(img, gridSize, mapping),
		}
	}

	// Stage 1: luma rank over all candidates (lumaOrder holds positions in `all`).
	lumaOrder := make([]int, candidateCount)
	for i := range lumaOrder {
		lumaOrder[i] = i
	}
	sort.SliceStable(lumaOrder, func(i, j int) bool {
		a, b := all[lumaOrder[i]], all[lumaOrder[j]]
		if a.luma == b.luma {
			return a.index < b.index
		}
		return a.luma < b.luma
	})
	lumaRank := make(map[int]int, candidateCount)
	for rank, pos := range lumaOrder {
		lumaRank[all[pos].index] = rank
	}

	// Stage 2: top ≤12 by luma → RGB + text seam scores.
	stage2Count := candidateCount
	if stage2Count > 12 {
		stage2Count = 12
	}
	stage2Pos := make([]int, 0, stage2Count)
	stage2Set := make(map[int]bool, stage2Count)
	for i := 0; i < stage2Count; i++ {
		pos := lumaOrder[i]
		stage2Pos = append(stage2Pos, pos)
		stage2Set[all[pos].index] = true
		mapping, err := buildSliderTileMapping(gridSize, all[pos].activeSteps)
		if err != nil {
			return nil, err
		}
		all[pos].rgb, all[pos].text = seamScoreRGBTextV2(img, gridSize, mapping)
	}

	rgbOrder := append([]int(nil), stage2Pos...)
	sort.SliceStable(rgbOrder, func(i, j int) bool {
		a, b := all[rgbOrder[i]], all[rgbOrder[j]]
		if a.rgb == b.rgb {
			return a.index < b.index
		}
		return a.rgb < b.rgb
	})
	rgbRank := make(map[int]int, len(rgbOrder))
	for rank, pos := range rgbOrder {
		rgbRank[all[pos].index] = rank
	}

	textOrder := append([]int(nil), stage2Pos...)
	sort.SliceStable(textOrder, func(i, j int) bool {
		a, b := all[textOrder[i]], all[textOrder[j]]
		if a.text == b.text {
			return a.index < b.index
		}
		return a.text < b.text
	})
	textRank := make(map[int]int, len(textOrder))
	for rank, pos := range textOrder {
		textRank[all[pos].index] = rank
	}

	// Consensus rank.
	for i := range all {
		c := lumaRank[all[i].index]
		if stage2Set[all[i].index] {
			c += rgbRank[all[i].index] + textRank[all[i].index]
		} else {
			c += candidateCount
		}
		all[i].consensus = c
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].consensus != all[j].consensus {
			return all[i].consensus < all[j].consensus
		}
		if all[i].luma != all[j].luma {
			return all[i].luma < all[j].luma
		}
		return all[i].index < all[j].index
	})

	candidates := make([]sliderCandidate, candidateCount)
	for i, s := range all {
		candidates[i] = sliderCandidate{
			Index:       s.index,
			ActiveSteps: s.activeSteps,
			Score:       int64(s.consensus),
		}
	}
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
	if gridSize > maxSliderGridSize {
		return nil, fmt.Errorf("grid size too large: %d", gridSize)
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

func sliderTileRect(bounds image.Rectangle, gridSize, index int) image.Rectangle {
	row := index / gridSize
	col := index % gridSize
	x0 := bounds.Min.X + col*bounds.Dx()/gridSize
	x1 := bounds.Min.X + (col+1)*bounds.Dx()/gridSize
	y0 := bounds.Min.Y + row*bounds.Dy()/gridSize
	y1 := bounds.Min.Y + (row+1)*bounds.Dy()/gridSize
	return image.Rect(x0, y0, x1, y1)
}

// ── v2 seam scorers (ported from amurcanov captcha_v2_slider.go) ───────────

// seamScoreLumaV2 sums the luminance discontinuity across every horizontal
// and vertical tile seam, sampling the original image through `mapping`.
// Lower = tiles fit better = more likely the correct permutation.
func seamScoreLumaV2(img image.Image, gridSize int, mapping []int) int64 {
	bounds := img.Bounds()
	var score int64
	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			h := leftDst.Dy()
			if rightDst.Dy() < h {
				h = rightDst.Dy()
			}
			for y := 0; y < h; y++ {
				yy := leftDst.Min.Y + y
				a := sampleLumaMappedV2(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				b := sampleLumaMappedV2(img, rightDst, rightSrc, rightDst.Min.X, yy)
				score += int64(absIntV2(int(a) - int(b)))
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			w := topDst.Dx()
			if bottomDst.Dx() < w {
				w = bottomDst.Dx()
			}
			for x := 0; x < w; x++ {
				xx := topDst.Min.X + x
				a := sampleLumaMappedV2(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleLumaMappedV2(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				score += int64(absIntV2(int(a) - int(b)))
			}
		}
	}
	return score
}

// seamScoreRGBTextV2 returns (rgbScore, textScore). rgbScore is the full-RGB
// seam discontinuity; textScore is the blue-channel seam discontinuity weighted
// by a Gaussian bump around the 3 horizontal text stripes (0.2/0.5/0.8 of
// height) where VK's overlaid challenge text lives — so a permutation that
// aligns the text reads as a much better fit.
func seamScoreRGBTextV2(img image.Image, gridSize int, mapping []int) (int64, float64) {
	bounds := img.Bounds()
	height := float64(bounds.Dy())
	textCenters := []float64{
		float64(bounds.Min.Y) + 0.2*height,
		float64(bounds.Min.Y) + 0.5*height,
		float64(bounds.Min.Y) + 0.8*height,
	}
	sigma := height * 0.14
	if sigma < 1.0 {
		sigma = 1.0
	}
	weight := func(y int) float64 {
		yf := float64(y)
		best := absFloatV2(yf - textCenters[0])
		for i := 1; i < len(textCenters); i++ {
			d := absFloatV2(yf - textCenters[i])
			if d < best {
				best = d
			}
		}
		return 1 + 3*math.Exp(-(best*best)/(2*sigma*sigma))
	}

	var rgbScore int64
	var textScore float64
	for row := 0; row < gridSize; row++ {
		for col := 0; col < gridSize-1; col++ {
			leftIdx := row*gridSize + col
			rightIdx := leftIdx + 1
			leftDst := sliderTileRect(bounds, gridSize, leftIdx)
			rightDst := sliderTileRect(bounds, gridSize, rightIdx)
			leftSrc := sliderTileRect(bounds, gridSize, mapping[leftIdx])
			rightSrc := sliderTileRect(bounds, gridSize, mapping[rightIdx])
			h := leftDst.Dy()
			if rightDst.Dy() < h {
				h = rightDst.Dy()
			}
			for y := 0; y < h; y++ {
				yy := leftDst.Min.Y + y
				l := sampleColorMappedV2(img, leftDst, leftSrc, leftDst.Max.X-1, yy)
				r := sampleColorMappedV2(img, rightDst, rightSrc, rightDst.Min.X, yy)
				rgbScore += pixelDiff(l, r)
				_, _, lb, _ := l.RGBA()
				_, _, rb, _ := r.RGBA()
				textScore += weight(yy) * float64(absIntV2(int(lb>>8)-int(rb>>8)))
			}
		}
	}
	for row := 0; row < gridSize-1; row++ {
		for col := 0; col < gridSize; col++ {
			topIdx := row*gridSize + col
			bottomIdx := (row+1)*gridSize + col
			topDst := sliderTileRect(bounds, gridSize, topIdx)
			bottomDst := sliderTileRect(bounds, gridSize, bottomIdx)
			topSrc := sliderTileRect(bounds, gridSize, mapping[topIdx])
			bottomSrc := sliderTileRect(bounds, gridSize, mapping[bottomIdx])
			w := topDst.Dx()
			if bottomDst.Dx() < w {
				w = bottomDst.Dx()
			}
			for x := 0; x < w; x++ {
				xx := topDst.Min.X + x
				t := sampleColorMappedV2(img, topDst, topSrc, xx, topDst.Max.Y-1)
				b := sampleColorMappedV2(img, bottomDst, bottomSrc, xx, bottomDst.Min.Y)
				rgbScore += pixelDiff(t, b)
				_, _, tb, _ := t.RGBA()
				_, _, bb, _ := b.RGBA()
				textScore += 0.65 * float64(absIntV2(int(tb>>8)-int(bb>>8)))
			}
		}
	}
	return rgbScore, textScore
}

// sampleColorMappedV2 returns the original-image colour at the destination
// pixel (dstX,dstY) within dstRect, looked up through srcRect (i.e. the tile
// that `mapping` places at this destination). Avoids rendering a full
// candidate image per permutation.
func sampleColorMappedV2(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) color.Color {
	dx := dstRect.Dx()
	if dx < 1 {
		dx = 1
	}
	dy := dstRect.Dy()
	if dy < 1 {
		dy = 1
	}
	sx := srcRect.Min.X + (dstX-dstRect.Min.X)*srcRect.Dx()/dx
	sy := srcRect.Min.Y + (dstY-dstRect.Min.Y)*srcRect.Dy()/dy
	return img.At(sx, sy)
}

func sampleLumaMappedV2(img image.Image, dstRect image.Rectangle, srcRect image.Rectangle, dstX int, dstY int) uint8 {
	c := sampleColorMappedV2(img, dstRect, srcRect, dstX, dstY)
	r, g, b, _ := c.RGBA()
	y := (299*(r>>8) + 587*(g>>8) + 114*(b>>8)) / 1000
	return uint8(y)
}

// pixelDiff is the 8-bit absolute RGB difference of two colours (amurcanov v2
// scale). Used by the seam scorers.
func pixelDiff(a, b color.Color) int64 {
	ar, ag, ab, _ := a.RGBA()
	br, bg, bb, _ := b.RGBA()
	dr := int64(ar>>8) - int64(br>>8)
	dg := int64(ag>>8) - int64(bg>>8)
	db := int64(ab>>8) - int64(bb>>8)
	if dr < 0 {
		dr = -dr
	}
	if dg < 0 {
		dg = -dg
	}
	if db < 0 {
		db = -db
	}
	return dr + dg + db
}

func absFloatV2(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func absIntV2(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// generateSliderCursor builds a human-like Bézier drag path, ported from
// amurcanov buildSliderCursorV2 (start jitter → curved transit → approach →
// settle, with per-point randomisation). Replaces our old 12-point straight
// line. Returns a JSON array of {x,y} points. Coordinates are amurcanov's
// empirical slider-widget pixels — proven to be accepted by VK; if a future
// slider-mode test shows cursor-plausibility rejections we can rescale.
func generateSliderCursor(candidateIndex, candidateCount int) string {
	if candidateCount <= 0 {
		return "[]"
	}
	if candidateIndex < 1 {
		candidateIndex = 1
	}
	if candidateIndex > candidateCount {
		candidateIndex = candidateCount
	}

	type cursorPoint struct {
		X int `json:"x"`
		Y int `json:"y"`
	}

	startX := 570 + mathrand.Intn(40)
	startY := 875 + mathrand.Intn(30)

	denom := candidateCount - 1
	if denom < 1 {
		denom = 1
	}
	baseTargetX := 734 + (937-734)*(candidateIndex-1)/denom
	targetX := baseTargetX + mathrand.Intn(10) - 5
	targetY := 655 + mathrand.Intn(14)

	points := make([]cursorPoint, 0, 28)

	for i := 0; i < 1+mathrand.Intn(3); i++ {
		points = append(points, cursorPoint{
			X: startX + mathrand.Intn(5) - 2,
			Y: startY + mathrand.Intn(5) - 2,
		})
	}

	transitSteps := 2 + mathrand.Intn(3)
	arcOffX := mathrand.Intn(60) - 30
	arcOffY := -(mathrand.Intn(30) + 10)
	for i := 1; i <= transitSteps; i++ {
		t := float64(i) / float64(transitSteps+1)
		cx := float64(startX+targetX)/2 + float64(arcOffX)
		cy := float64(startY+targetY)/2 + float64(arcOffY)
		bx := (1-t)*(1-t)*float64(startX) + 2*t*(1-t)*cx + t*t*float64(targetX)
		by := (1-t)*(1-t)*float64(startY) + 2*t*(1-t)*cy + t*t*float64(targetY)
		jitter := int((1-t)*8) + 2
		points = append(points, cursorPoint{
			X: int(math.Round(bx)) + mathrand.Intn(jitter*2+1) - jitter,
			Y: int(math.Round(by)) + mathrand.Intn(jitter*2+1) - jitter,
		})
	}

	approachSteps := 4 + mathrand.Intn(4)
	prev := points[len(points)-1]
	for i := 1; i <= approachSteps; i++ {
		t := float64(i) / float64(approachSteps)
		ax := prev.X + int(math.Round(t*float64(targetX-prev.X))) + mathrand.Intn(5) - 2
		ay := prev.Y + int(math.Round(t*float64(targetY-prev.Y))) + mathrand.Intn(5) - 2
		points = append(points, cursorPoint{X: ax, Y: ay})
	}

	settleCount := 3 + mathrand.Intn(5)
	for i := 0; i < settleCount; i++ {
		points = append(points, cursorPoint{
			X: targetX + mathrand.Intn(7) - 3,
			Y: targetY + mathrand.Intn(7) - 3,
		})
	}

	data, err := json.Marshal(points)
	if err != nil {
		return "[]"
	}
	return string(data)
}
