package proxy

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	tls_client "github.com/bogdanfinn/tls-client"
)

// vkGlobalBlockFixture is a `window.vk = {…}` block in the shape the BFF captcha
// page prints (keys as on the live page of 2026-09-07; values synthetic). The
// UUID's key is obfuscated and changes per bundle build, so the parser must
// find the value by SHAPE — and only inside the block: the page also carries
// `window.lang = {…}` (a translation table) and, in this fixture, a stray UUID
// in a later script that must never be mistaken for debug_info. The statsMeta
// hash deliberately contains braces inside a string literal.
const vkGlobalBlockFixture = `
window.vk = {
    apiConfigDomains: {"apiDomain":"api.vk.ru","connectDomain":"id.vk.ru","domain":"vk.ru","loginDomain":"login.vk.ru"},
    webToken: null,
    stDomain: "https://st.vk.ru/vkid/vkid-bff",
    qzxwvutsrqpo: "11111111-2222-4333-8444-555555555555",
    pe: {"frontend.vkid.bff_captcha_rollout":1},
    cfg: {},
    toggles: {},
    lang: 3,
    statsMeta: {"platform":"","st":false,"id":0,"time":1787154550,"hash":"ab}{cd"},
    isOldBrowserVersion: false
};
window.lang = {"vkconnect_not_robot_captcha_audio_lang":"en"};
`

// The stray UUID sits in another object under a `key: "…"` of exactly the
// shape the parser matches, so only the block boundary keeps it out.
const strayUUIDScript = `<script>window.other = { zzz: "99999999-8888-4777-8666-555555555554" };</script>`

func TestParseVKGlobalReadsTheDebugInfoUUIDAndLang(t *testing.T) {
	page := "<html><script>" + vkGlobalBlockFixture + "</script>" + strayUUIDScript + "</html>"
	uuid, lang := parseVKGlobal(page)
	if uuid != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("debug_info = %q, want the block's UUID", uuid)
	}
	if lang != "3" {
		t.Fatalf("lang = %q, want %q (the block's own `lang: 3`, not window.lang)", lang, "3")
	}
}

// A UUID that appears BEFORE the block must not be taken: the search is the
// block's, not the page's. A page without the block yields nothing at all.
func TestParseVKGlobalSearchesOnlyTheBlock(t *testing.T) {
	page := "<html>" + strayUUIDScript + "<script>" + vkGlobalBlockFixture + "</script></html>"
	uuid, lang := parseVKGlobal(page)
	if uuid != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("debug_info = %q, want the block's UUID, never the stray one before it", uuid)
	}
	if lang != "3" {
		t.Fatalf("lang = %q, want %q", lang, "3")
	}
	if u, l := parseVKGlobal("<html>" + strayUUIDScript + "</html>"); u != "" || l != "" {
		t.Fatalf("a page without window.vk yielded uuid=%q lang=%q, want nothing", u, l)
	}
}

// parsePowPage carries the two values alongside the PoW; the monolith page of
// the 1.1.1395 fixture has no window.vk and reads empty.
func TestParsePowPageCarriesTheVKGlobalValues(t *testing.T) {
	fixture := loadPowFixture(t)
	p, err := parsePowPage(fixture)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.DebugInfo != "" || p.Lang != "" {
		t.Fatalf("monolith fixture: uuid=%q lang=%q, want both empty", p.DebugInfo, p.Lang)
	}
	p, err = parsePowPage("<script>" + vkGlobalBlockFixture + "</script>" + fixture)
	if err != nil {
		t.Fatalf("parse with window.vk: %v", err)
	}
	if p.DebugInfo != "11111111-2222-4333-8444-555555555555" || p.Lang != "3" {
		t.Fatalf("uuid=%q lang=%q, want the block's values", p.DebugInfo, p.Lang)
	}
	if p.Input != "gMbKzMjN77r4NVrv" {
		t.Fatalf("the PoW parse changed: input=%q", p.Input)
	}
}

// The widget's transport serialises the method params in insertion order and
// appends the empty access_token last. An unreadable lang is `window.vk.lang || 0`.
func TestInitSessionBodyIsTheWidgetsFieldOrder(t *testing.T) {
	if got, want := initSessionBody("T0K", "vk.com", "3"), "session_token=T0K&domain=vk.com&lang=3&access_token="; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got, want := initSessionBody("T0K", "vk.com", ""), "session_token=T0K&domain=vk.com&lang=0&access_token="; got != want {
		t.Fatalf("empty lang: body = %q, want %q", got, want)
	}
}

// initSession's content_settings become the slider's captcha_settings: on the
// BFF branch the widget sends settings_key, falling back to settings.
func TestInitSessionSettingsFeedTheSliderPath(t *testing.T) {
	resp := map[string]interface{}{"response": map[string]interface{}{
		"show_captcha_type": "slider",
		"captcha_id":        "c1",
		"content_settings": []interface{}{
			map[string]interface{}{"type": "sound", "settings": "s-old", "settings_key": "S-KEY"},
			map[string]interface{}{"type": "slider", "settings": "old-settings", "settings_key": "SLIDER-KEY"},
		},
	}}
	s, showType := initSessionSettings(resp)
	if showType != "slider" {
		t.Fatalf("show_captcha_type = %q, want slider", showType)
	}
	if got := extractSliderSettings(s); got != "SLIDER-KEY" {
		t.Fatalf("slider captcha_settings = %q, want the settings_key", got)
	}

	noKey := map[string]interface{}{"response": map[string]interface{}{
		"show_captcha_type": "checkbox",
		"content_settings": []interface{}{
			map[string]interface{}{"type": "slider", "settings": "old-settings"},
		},
	}}
	s, showType = initSessionSettings(noKey)
	if showType != "checkbox" || extractSliderSettings(s) != "old-settings" {
		t.Fatalf("without settings_key: show=%q settings=%q, want checkbox / old-settings", showType, extractSliderSettings(s))
	}

	if s, _ := initSessionSettings(map[string]interface{}{"error": map[string]interface{}{"error_code": 100}}); s != nil {
		t.Fatalf("an error answer produced settings %v, want nil", s)
	}
}

// The check body keeps its 2026-08-21 shape by default and drops exactly the
// two connection arrays under the arm — nothing else moves.
func TestBuildCheckBodyDropsTheConnectionArraysOnlyWhenAsked(t *testing.T) {
	base := "session_token=T&domain=vk.com&adFp=A"
	with := buildCheckBody(base, "FP", "v2.a+b/c=", "e30=", "DBG", true)
	want := base + "&accelerometer=%5B%5D&gyroscope=%5B%5D&motion=%5B%5D&cursor=%5B%5D&taps=%5B%5D" +
		"&connectionRtt=%5B%5D&connectionDownlink=%5B%5D" +
		"&browser_fp=FP&hash=v2.a%2Bb%2Fc%3D&answer=e30%3D&debug_info=DBG&access_token="
	if with != want {
		t.Fatalf("with conn fields:\n got %q\nwant %q", with, want)
	}
	without := buildCheckBody(base, "FP", "v2.a+b/c=", "e30=", "DBG", false)
	if strings.Contains(without, "connection") {
		t.Fatalf("the arm left a connection field in: %q", without)
	}
	if got, want := without, strings.Replace(want, "&connectionRtt=%5B%5D&connectionDownlink=%5B%5D", "", 1); got != want {
		t.Fatalf("without conn fields:\n got %q\nwant %q", got, want)
	}
}

// recordingVK answers every captchaNotRobot.* call with a valid empty response
// except `settings`, which it answers with non-JSON so the sequence stops right
// there: the test is about what precedes settings, not about the solve.
type recordingVK struct {
	mu     sync.Mutex
	paths  []string
	bodies map[string]string
}

func (r *recordingVK) handler(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.paths = append(r.paths, req.URL.Path)
	r.bodies[req.URL.Path] = string(body)
	r.mu.Unlock()
	if strings.HasSuffix(req.URL.Path, "captchaNotRobot.settings") {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>stop here</html>"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"response":{"show_captcha_type":"checkbox","captcha_id":"c1"}}`))
}

func runAPISequence(t *testing.T) *recordingVK {
	t.Helper()
	f := newFakeVK(t)
	useFakeVK(t, f)
	rec := &recordingVK{bodies: map[string]string{}}
	f.srv.Config.Handler = http.HandlerFunc(rec.handler)
	client, err := newVKSessionClient(tls_client.NewCookieJar())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	_, _, _, err = callCaptchaNotRobotAPI(context.Background(), client, "T0K", "vk.com", "v2.hash", "adfp", "DBG", "3", nil)
	if err == nil || !strings.Contains(err.Error(), "settings:") {
		t.Fatalf("the sequence was meant to stop at settings, err = %v", err)
	}
	return rec
}

// By default the sequence opens the session first — initSession, then
// settings — with the widget's body; VK_INIT_SESSION=0 (the negative control
// of 2026-09-07, which VK answers BOT with no slider) makes settings the first
// call, as before that day.
func TestInitSessionOpensTheSessionBeforeSettingsByDefault(t *testing.T) {
	t.Setenv("VK_INIT_SESSION", "")
	rec := runAPISequence(t)
	want := []string{"/method/captchaNotRobot.initSession", "/method/captchaNotRobot.settings"}
	if strings.Join(rec.paths, " ") != strings.Join(want, " ") {
		t.Fatalf("calls = %v, want %v", rec.paths, want)
	}
	if got, want := rec.bodies["/method/captchaNotRobot.initSession"], "session_token=T0K&domain=vk.com&lang=3&access_token="; got != want {
		t.Fatalf("initSession body = %q, want %q", got, want)
	}
}

func TestInitSessionCanBeSwitchedOff(t *testing.T) {
	t.Setenv("VK_INIT_SESSION", "0")
	rec := runAPISequence(t)
	if len(rec.paths) != 1 || !strings.HasSuffix(rec.paths[0], "captchaNotRobot.settings") {
		t.Fatalf("calls = %v, want settings alone", rec.paths)
	}
}

// The three switches default to the live widget's shape (2026-09-07) and each
// flips on its own variable — the arms of tools/captcha_test need no build.
func TestExperimentSwitchesDefaultToTheLiveWidgetsShape(t *testing.T) {
	for _, v := range []string{"VK_INIT_SESSION", "VK_DEBUG_INFO_PAGE", "VK_CHECK_CONN_FIELDS"} {
		t.Setenv(v, "")
	}
	if !initSessionEnabled() || !debugInfoFromPage() || checkConnFieldsEnabled() {
		t.Fatalf("defaults: initSession=%v debugInfoFromPage=%v connFields=%v, want true/true/false",
			initSessionEnabled(), debugInfoFromPage(), checkConnFieldsEnabled())
	}
	t.Setenv("VK_INIT_SESSION", "0")
	t.Setenv("VK_DEBUG_INFO_PAGE", "0")
	t.Setenv("VK_CHECK_CONN_FIELDS", "1")
	if initSessionEnabled() || debugInfoFromPage() || !checkConnFieldsEnabled() {
		t.Fatalf("flipped: initSession=%v debugInfoFromPage=%v connFields=%v, want false/false/true",
			initSessionEnabled(), debugInfoFromPage(), checkConnFieldsEnabled())
	}
}

// bffPowFixture is the page VK served ya1 on 2026-09-07 (arm A0's second
// attempt), reduced to its window.vk and PoW script blocks — the first live
// BFF page in the repository. The UUID is that page load's; the next load of
// the same session printed a different one.
const bffPowFixture = "testdata/captcha_pow_page_bff_2026_09_07.html"

func TestParsePowPageReadsTheLiveBFFPage(t *testing.T) {
	b, err := os.ReadFile(bffPowFixture)
	if err != nil {
		t.Fatalf("read %s: %v", bffPowFixture, err)
	}
	p, err := parsePowPage(string(b))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Input != "eIFSl36uRID80B9I" || p.Difficulty != 2 || p.Envelope != envelopeTelemetry5 || p.Prefix != "v2." {
		t.Fatalf("pow = %+v, want input eIFSl36uRID80B9I / difficulty 2 / telemetry5 / v2.", p)
	}
	if p.DebugInfo != "e2208979-74eb-40bb-8a00-90091dca8ac0" {
		t.Fatalf("debug_info = %q, want the page's window.vk UUID", p.DebugInfo)
	}
	if p.Lang != "3" {
		t.Fatalf("lang = %q, want 3", p.Lang)
	}
}
