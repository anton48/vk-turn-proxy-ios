package proxy

import (
	"compress/flate"
	"compress/gzip"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
	"github.com/klauspost/compress/zstd"
)

// captchaPowProfile stores the browser profile for the current PoW session.
var captchaPowProfile BrowserProfile

// VKBrowserProfile is a captured-from-real-browser fingerprint reused in
// the auto-PoW solver to evade VK's bot detection. The Swift main app's
// CaptchaWKWebView intercepts captchaNotRobot.componentDone request bodies
// (where a real browser sends VK its computed device + browser_fp) and
// persists them to App Group vk_profile.json. Subsequent solveCaptchaPoW
// calls — in either main app or extension process — load this file and
// substitute the captured values for the generated ones, dramatically
// improving the auto-solve success rate (observed 6% with generated
// browser_fp, vpn.wifi.0.log 2026-05-08; expected to climb sharply with
// real captured values per Moroka8 PR #162 commit b9642c6).
//
// The captured Device is the form-encoded value from VK's request body
// (already URL-encoded JSON); BrowserFp is the encoded fingerprint
// string. Both go directly into our outgoing componentDone/check
// requests without re-encoding.
type VKBrowserProfile struct {
	Device    string  `json:"device"`
	BrowserFp string  `json:"browser_fp"`
	UserAgent string  `json:"user_agent"`
	// CapturedAt is unix seconds with sub-second fraction. Stored as
	// float64 because Swift writes TimeInterval (Double) and Go's
	// json.Unmarshal won't coerce a float into int64. Match Swift's
	// type to keep the round-trip lossless.
	CapturedAt float64 `json:"captured_at"`
}

// vkProfilePath holds the App Group container path to vk_profile.json.
// Set via SetVKProfilePath from bridge.go's wgSetLogFilePath. Read by
// loadSavedVKProfile on every solveCaptchaPoW call (no caching — the
// file is small, reading once per captcha attempt is negligible, and
// cache invalidation gets messy).
var vkProfilePath atomic.Value // string

// SetVKProfilePath records where vk_profile.json lives in the App Group
// container. Empty string disables loading (loadSavedVKProfile returns
// nil silently). Called once during bridge init for both main app and
// extension processes.
func SetVKProfilePath(p string) {
	vkProfilePath.Store(p)
}

// loadSavedVKProfile returns the captured profile if the file exists
// and parses cleanly, or nil otherwise. Missing file / parse error /
// empty fields all yield nil — caller falls back to generated values.
// Logs the load decision so production logs show whether the captured
// profile is being used on each PoW attempt.
func loadSavedVKProfile() *VKBrowserProfile {
	v := vkProfilePath.Load()
	if v == nil {
		return nil
	}
	path, _ := v.(string)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// ENOENT is normal (no captured profile yet); other errors
		// suggest something wrong with App Group container access.
		if !os.IsNotExist(err) {
			log.Printf("pow: vk_profile.json read failed: %v", err)
		}
		return nil
	}
	var p VKBrowserProfile
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("pow: vk_profile.json parse failed: %v", err)
		return nil
	}
	if p.BrowserFp == "" || p.Device == "" {
		log.Printf("pow: vk_profile.json missing required fields (device=%dc, browser_fp=%dc)",
			len(p.Device), len(p.BrowserFp))
		return nil
	}
	return &p
}

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

// ── VK_DESKTOP_CHROME diagnostic mode ──────────────────────────────────────
//
// When env VK_DESKTOP_CHROME=1 is set, the captcha session presents a
// FULLY-CONSISTENT DESKTOP CHROME 146 identity instead of the production
// iPhone-Safari identity. Every axis is flipped together so VK sees one
// coherent browser:
//
//   - TLS:          bogdanfinn profiles.Chrome_146 (real Chrome JA3)
//   - User-Agent:   Chrome 146 on Windows
//   - sec-ch-ua*:   Chromium/Google Chrome v146, mobile=?0, platform=Windows
//   - device blob:  1920x1080 desktop (amurcanov's known-working value)
//   - browser_fp:   RANDOM (NOT the captured iPhone fp)
//   - debug_info:   dynamic (unchanged — already version-scraped)
//
// Rationale: empirically (2026-05-30, captcha-probe.{mac,msk,www,meg}.log)
// our iPhone-Safari presentation gets checkbox->BOT + getContent->ERROR on
// all 4 IPs and even with amurcanov's exact creds, while amurcanov's Android
// fork — which presents this exact desktop-Chrome identity (profiles.Chrome_146
// + desktop UA + sec-ch-ua, see go_client/{profiles,captcha_v2}.go) — gets VK
// to serve a SOLVABLE Go-slider. This mode lets tools/captcha_test reproduce
// amurcanov's presentation to test whether browser identity is the
// discriminator. Production iOS (env unset) is unchanged.
var (
	desktopChromeOnce sync.Once
	desktopChromeProf *BrowserProfile
)

// desktopChromeProfile returns a pinned, process-stable desktop Chrome 146
// (Windows) profile when VK_DESKTOP_CHROME=1, else nil. Singleton so the TLS
// client, UA, and sec-ch-ua headers all agree on one identity for the whole
// process.
func desktopChromeProfile() *BrowserProfile {
	desktopChromeOnce.Do(func() {
		if os.Getenv("VK_DESKTOP_CHROME") != "1" {
			return
		}
		desktopChromeProf = &BrowserProfile{
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
			Platform:      "Windows",
			ChromeVersion: 146,
		}
		log.Printf("pow: VK_DESKTOP_CHROME=1 — captcha session presents DESKTOP CHROME 146 (TLS Chrome_146 + sec-ch-ua + 1920x1080 device + random browser_fp), NOT iPhone Safari")
	})
	return desktopChromeProf
}

// desktopChromeDeviceJSON is the device descriptor sent in componentDone when
// in desktop-Chrome mode — byte-identical to amurcanov's known-working
// captchaV2DeviceInfo (go_client/captcha_v2.go:31).
const desktopChromeDeviceJSON = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1080,"innerWidth":1920,"innerHeight":951,"devicePixelRatio":1,"language":"en-US","languages":["en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"denied"}`

// chromeCaptchaHeaderOrder is the EXACT HTTP/2 header order amurcanov pins on
// every captchaNotRobot.* request (go_client/captcha_v2.go captchaV2HeaderOrder).
// 2026-05-30 A/B proof: this header ORDER is the single discriminator — with it,
// VK returns checkbox status=OK; without it, status=BOT (Origin .com/.ru and
// adFp empty/populated are irrelevant). VK fingerprints the header sequence;
// bogdanfinn's default (uncontrolled) order is what flagged us as BOT for weeks.
// Set via req.Header[fhttp.HeaderOrderKey]; headers we send that aren't listed
// (e.g. DNT) trail — same as amurcanov, tolerated by VK.
var chromeCaptchaHeaderOrder = []string{
	"host",
	"content-length",
	"sec-ch-ua-platform",
	"accept-language",
	"sec-ch-ua",
	"content-type",
	"sec-ch-ua-mobile",
	"user-agent",
	"accept",
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"priority",
}

// chromeCaptchaPHeaderOrder is the HTTP/2 pseudo-header order (Chrome).
var chromeCaptchaPHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}

// safariCaptchaHeaderOrder is the AUTHORITATIVE HTTP/2 header order real Safari
// WKWebView sends on captchaNotRobot.* POSTs, extracted via mitmdump from the
// 2026-05-17 capture of our app's WORKING WebView solve (VK accepted it with
// status=OK). Pinned on EVERY captchaNotRobot.* POST (production default, see
// vkReq) — this header ORDER was THE captcha discriminator: bogdanfinn's
// uncontrolled default order didn't match real Safari, so VK flagged us BOT
// since 2026-05-15. NOTE: real Safari sends NO Cache-Control/Pragma here (build
// 85 added them by mistake), so vkReq also drops them. Pseudo-header order is
// left to the Safari_IOS_26_0 profile default (already correct).
var safariCaptchaHeaderOrder = []string{
	"accept",
	"content-type",
	"sec-fetch-site",
	"origin",
	"sec-fetch-mode",
	"user-agent",
	"referer",
	"sec-fetch-dest",
	"content-length",
	"accept-language",
	"priority",
	"accept-encoding",
	"cookie",
}

// applyChromeHints adds desktop-Chrome Client-Hint headers (sec-ch-ua*),
// en-US Accept-Language, and DNT to a captcha-session request when
// VK_DESKTOP_CHROME=1. No-op in the production Safari path (Safari does not
// send sec-ch-ua). Mirrors amurcanov's applyBrowserProfileFhttp. Call AFTER
// the per-request inline Header.Set block so it overrides Accept-Language.
func applyChromeHints(req *fhttp.Request) {
	p := desktopChromeProfile()
	if p == nil {
		return
	}
	req.Header.Set("sec-ch-ua", p.SecChUA())
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", p.SecChUAPlatform())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

// customSafariIOS26Profile returns a captcha session profile with a
// hand-crafted TLS ClientHello matching real Safari iOS 26 byte-for-byte,
// extracted from pcap captured 2026-05-16 (captcha-capture.pcap, frame 32,
// real Safari WKWebView handshake to api.vk.ru).
//
// Why we don't just use profiles.Safari_IOS_26_0 directly: bogdanfinn's
// built-in profile (v1.14.0) has three concrete divergences from real
// Safari iOS 26 that we observed on wire:
//
//   1. CipherSuites: 21 vs 16. Real Safari iOS 26 sends NO 3DES suites
//      (Apple removed years ago); bogdanfinn includes TLS_..._3DES_EDE_CBC_SHA.
//      Order also differs: real Safari = AES_128_GCM first, bogdanfinn =
//      AES_256_GCM first.
//
//   2. SupportedCurves: 5 vs 4. Bogdanfinn adds CurveP521 (secp521r1);
//      real Safari doesn't have it.
//
//   3. Extension order: FIXED in bogdanfinn (same JA3 across all
//      connections); RANDOMIZED in real Safari (different JA3 every
//      connection due to GREASE + per-connection shuffle).
//
//   4. Missing extensions: bogdanfinn lacks encrypted_client_hello
//      (65037), application_settings (17613 ALPS), session_ticket (35).
//      Real Safari iOS 17+ sends all three.
//
// VK detection likely catches all of these — most damning is #3: 24
// consecutive Go-solver connections with identical JA3 vs Safari rotating
// JA3 each connection is an obvious bot signal.
//
// HTTP/2 settings (settings, settingsOrder, pseudoHeaderOrder, connection
// flow, header priority) are taken from profiles.Safari_IOS_26_0 — they
// match our captured Safari iOS 26 HTTP/2 frames and don't need fixing.
//
// Built with RandomExtensionOrder=true to mimic Safari's per-connection
// shuffling. utls handles the actual randomization internally.
// buildCustomSafariIOS26Spec returns a uTLS ClientHelloSpec matching the
// REAL Safari WKWebView TLS fingerprint as observed empirically in pcap
// captures from the user's iPhone (captcha-capture.3.pcap, 2026-05-16).
//
// Phase 9 correction: builds 99-103 (Phase 7-8) targeted a fingerprint
// that an earlier pcap-analysis sub-agent CLAIMED was real Safari iOS 26
// (16 ciphers, RandomExtensionOrder=true, ECH+ALPS+session_ticket, no
// secp521r1). That analysis turned out to be hallucinated. Verified
// 2026-05-16 by direct tshark inspection: real Safari WKWebView TLS
// handshakes (8 ClientHellos with cipher_suites_length=28 bytes in the
// pcap) consistently show 14 ciphers, FIXED extension order (single JA3
// across all conns), NO ECH/ALPS/session_ticket, WITH secp521r1, and a
// 10-entry signature_algorithms list including duplicated 0x0805 and
// legacy 0x0201 (rsa_pkcs1_sha1).
//
// Phase 8 was therefore chasing a fictional fingerprint — VK BOT was
// guaranteed regardless of any further refinement of the wrong target.
// Phase 9 below is byte-accurate to actual current Safari behavior on
// this device.
//
// Reference: extension order from pcap WebView ClientHello:
//   GREASE, server_name (0), extended_master_secret (23),
//   renegotiation_info (65281), supported_groups (10),
//   ec_point_formats (11), ALPN (16), status_request (5),
//   signature_algorithms (13), signed_certificate_timestamp (18),
//   key_share (51), psk_key_exchange_modes (45),
//   supported_versions (43), compress_certificate (27), GREASE
//
// If Phase 9 still triggers BOT on VK while WebView solve succeeds on
// the same IP within the same minute, detection is provably NOT at
// TLS/HTTP layer — likely WKWebView-specific attestation (App Attest,
// WebKit network identity) or JS execution result.
func buildCustomSafariIOS26Spec() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			// TLS 1.3: AES_256_GCM first (real Safari iOS 26 order).
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			// ECDHE_*_*GCM block. Order from pcap:
			// c02c (ECDSA AES_256), c030 (RSA AES_256), c02b (ECDSA AES_128),
			// cca9 (ECDSA CHACHA), c02f (RSA AES_128), cca8 (RSA CHACHA).
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			// ECDHE CBC fallbacks: c00a/c009 (ECDSA), c014/c013 (RSA).
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			// NO RSA bulk ciphers (009c/009d/002f/0035) — real Safari
			// iOS 26 does not send these despite older Apple devices
			// did. Phase 8 incorrectly added them.
			// NO 3DES — Apple removed years ago.
		},
		CompressionMethods: []uint8{utls.CompressionNone},
		// Extensions in EXACT pcap order — RandomExtensionOrder=false
		// in customSafariIOS26Profile so utls preserves this slice order.
		Extensions: []utls.TLSExtension{
			// 1. GREASE
			&utls.UtlsGREASEExtension{},
			// 2. server_name (0) — SNI
			&utls.SNIExtension{},
			// 3. extended_master_secret (23)
			&utls.ExtendedMasterSecretExtension{},
			// 4. renegotiation_info (65281)
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// 5. supported_groups (10) — 6 entries with secp521r1.
			//    Phase 8 incorrectly omitted secp521r1.
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			// 6. ec_point_formats (11)
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			// 7. ALPN (16)
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			// 8. status_request (5) — OCSP
			&utls.StatusRequestExtension{},
			// 9. signature_algorithms (13) — 10 entries with a DUPLICATED
			//    PSSWithSHA384 (0x0805 twice) and legacy PKCS1WithSHA1
			//    (0x0201). Both unusual; both empirically present in
			//    Safari iOS 26 pcap. Order from pcap.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, // 0x0403
				utls.PSSWithSHA256,          // 0x0804
				utls.PKCS1WithSHA256,        // 0x0401
				utls.ECDSAWithP384AndSHA384, // 0x0503
				utls.PSSWithSHA384,          // 0x0805
				utls.PSSWithSHA384,          // 0x0805 — duplicate, intentional, matches pcap
				utls.PKCS1WithSHA384,        // 0x0501
				utls.PSSWithSHA512,          // 0x0806
				utls.PKCS1WithSHA512,        // 0x0601
				utls.PKCS1WithSHA1,          // 0x0201 — legacy, intentional, matches pcap
			}},
			// 10. signed_certificate_timestamp (18)
			&utls.SCTExtension{},
			// 11. key_share (51) — GREASE + X25519MLKEM768 + x25519.
			//     pcap shows total len=1263 → 4(GREASE+len)+1(GREASE data)
			//     + 4(MLKEM768 hdr)+1216(MLKEM768 key) + 4(x25519 hdr)
			//     +32(x25519 key) = 1265-2 (outer len) = 1263. Match.
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			// 12. psk_key_exchange_modes (45)
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// 13. supported_versions (43) — GREASE, TLS1.3, TLS1.2
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			// 14. compress_certificate (27) — brotli only
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			// 15. GREASE
			&utls.UtlsGREASEExtension{},
			// NO ECH (65037), NO ALPS (17613), NO session_ticket (35).
			// Phase 8 added all three based on hallucinated agent
			// analysis; real Safari iOS 26 sends none of them.
		},
	}, nil
}

// customSafariIOS26Profile wraps buildCustomSafariIOS26Spec into a bogdanfinn
// ClientProfile, reusing HTTP/2 settings from profiles.Safari_IOS_26_0 (they
// already matched our captured Safari iOS 26 HTTP/2 frames byte-for-byte and
// don't need overriding — only ClientHello did).
//
// Phase 9 (build 104): RandomExtensionOrder set to FALSE. Real Safari sends
// IDENTICAL extension order across every connection (verified by single JA3
// hash 8527da8b8a640065e72ec6b6f99764f3 across 8 WebView ClientHellos in
// the same pcap). Earlier Phase 8 had this set to true based on the
// hallucinated "Safari randomizes JA3" claim.
func customSafariIOS26Profile() profiles.ClientProfile {
	helloID := utls.ClientHelloID{
		Client:               "Safari_iOS_26_custom",
		RandomExtensionOrder: false, // FIXED — matches real Safari empirically
		Version:              "2.0", // Phase 9: byte-accurate from pcap, no longer hallucinated
		Seed:                 nil,
		SpecFactory:          buildCustomSafariIOS26Spec,
	}
	base := profiles.Safari_IOS_26_0
	return profiles.NewClientProfile(
		helloID,
		base.GetSettings(),
		base.GetSettingsOrder(),
		base.GetPseudoHeaderOrder(),
		base.GetConnectionFlow(),
		base.GetPriorities(),
		base.GetHeaderPriority(),
		base.GetStreamID(),
		base.GetAllowHTTP(),
		base.GetHttp3Settings(),
		base.GetHttp3SettingsOrder(),
		base.GetHttp3PriorityParam(),
		base.GetHttp3PseudoHeaderOrder(),
		base.GetHttp3SendGreaseFrames(),
	)
}

// newSessionClient creates a captcha session client via bogdanfinn/tls-client
// using customSafariIOS26Profile (our own byte-accurate Safari iOS 26
// ClientHello extracted from real WKWebView pcap 2026-05-16).
//
// Phase 7 (build 99-100) used profiles.Safari_IOS_26_0 from bogdanfinn but
// pcap analysis showed bogdanfinn's profile diverges from real Safari iOS
// 26 on cipher list, supported_groups, missing ECH/ALPS/session_ticket,
// and fixed-vs-randomized extension order. Phase 8 uses our custom spec
// matching capture exactly. See customSafariIOS26Profile for the
// extracted differences.
//
// HTTP/2 settings + connection flow remain from bogdanfinn's
// Safari_IOS_26_0 — those matched our capture and don't need overriding.
//
// Other call sites (creds.go / proxy.go) keep their stdlib *http.Client
// + uTLS Chrome transport unchanged — those flows have Chrome UA and
// Chrome JA3, which is internally consistent.
// Phase 10 (build 105): SESSION-UNIFIED FINGERPRINT.
//
// Previously each captcha solver attempt created a fresh bogdanfinn HttpClient
// (Phase 9 Safari profile + fresh cookie jar) while creds.go bootstrap requests
// used a SEPARATE std http.Client with uTLS Chrome transport + random Chrome UA.
//
// pcap analysis 2026-05-16 (captcha-capture.4.pcap) proved:
//   - bootstrap requests to api.vk.ru: 16 ciphers, RANDOM JA3 per conn (uTLS Chrome)
//   - captcha requests to api.vk.ru: 14 ciphers, FIXED JA3 8527da8b... (Phase 9 Safari)
//   - SAME session_token spans both → VK sees impossible fingerprint switch → BOT
//
// VK's 2026-05-15 detection update likely added session-level fingerprint
// consistency checking. Real Safari WKWebView uses ONE TLS profile + ONE UA
// for all requests in a session. Phase 10 makes us match.
//
// Singleton bogdanfinn HttpClient — created once per process, shared across
// creds.go bootstrap + captcha_pow.go solver. Cookies accumulate naturally
// like a real browser session. ALL VK API requests (login.vk.ru, api.vk.ru,
// calls.okcdn.ru, id.vk.ru) flow through THIS one client.
var (
	sessionClientOnce sync.Once
	sessionClient     tls_client.HttpClient
)

// vkDiagDialer returns a net.Dialer whose Control hook logs the exact remote
// address the bogdanfinn session client is about to connect to, with the
// address family exposed via network ("tcp4" vs "tcp6"). DIAGNOSTIC (build
// 167): pairs with the main app's pre-call interface dump so a
// "connect: can't assign requested address" (EADDRNOTAVAIL) failure can be tied
// to the address that was actually requested — i.e. confirm whether we dialed
// an IPv4 literal while the device had no usable IPv4 source. Only Control is
// set; newDirectDialer overwrites Timeout with the client's WithTimeoutSeconds.
func vkDiagDialer() net.Dialer {
	return net.Dialer{
		Control: func(network, address string, _ syscall.RawConn) error {
			log.Printf("vk-dial: requesting %s %s", network, address)
			return nil
		},
	}
}

// GetSessionClient returns the singleton bogdanfinn HttpClient configured with
// Phase 9 Safari iOS 26 TLS profile + persistent cookie jar. Same instance
// returned across the whole process lifetime — cookies and connection state
// persist. Exported (capitalized) so creds.go and proxy.go can call it.
func GetSessionClient() tls_client.HttpClient {
	sessionClientOnce.Do(func() {
		var clientProfile profiles.ClientProfile
		if desktopChromeProfile() != nil {
			// VK_DESKTOP_CHROME diagnostic: real Chrome 146 JA3 to match the
			// desktop UA + sec-ch-ua (same profile amurcanov uses).
			clientProfile = profiles.Chrome_146
			log.Printf("pow: TLS profile=Chrome_146 (bogdanfinn built-in) — VK_DESKTOP_CHROME diagnostic mode")
		} else {
			// Phase 9 spec diagnostic — confirms what TLS bytes we send.
			// Phase 10 expected: ciphers=14 extensions=15 random_ext_order=false.
			clientProfile = customSafariIOS26Profile()
			spec, err := buildCustomSafariIOS26Spec()
			if err != nil {
				log.Printf("pow: TLS profile spec build ERROR: %v", err)
			} else {
				log.Printf("pow: TLS profile=Safari_iOS_26_custom ciphers=%d extensions=%d random_ext_order=false (Phase 9 spec, Phase 10 session-unified across bootstrap+captcha)",
					len(spec.CipherSuites), len(spec.Extensions))
			}
		}

		jar := tls_client.NewCookieJar()
		options := []tls_client.HttpClientOption{
			tls_client.WithTimeoutSeconds(20),
			tls_client.WithClientProfile(clientProfile),
			tls_client.WithCookieJar(jar),
			tls_client.WithDialer(vkDiagDialer()), // DIAGNOSTIC (build 167): log requested dial addr+family
		}
		client, cerr := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
		if cerr != nil {
			log.Printf("pow: ERROR creating bogdanfinn session client: %v", cerr)
			return
		}
		sessionClient = client
	})
	return sessionClient
}

// GetSessionUserAgent returns the User-Agent string ALL VK API requests in
// this process should use. Returns the captured Safari WKWebView UA from
// vk_profile.json when available (the same UA that computed the captured
// browser_fp). Falls back to a generic recent Safari iOS UA when no profile
// has been captured yet (cold start before first WebView solve).
//
// Phase 10: replaces creds.go's randomUserAgent() — random Chrome UAs were
// inconsistent with the Safari TLS profile and with the captured browser_fp.
func GetSessionUserAgent() string {
	if p := desktopChromeProfile(); p != nil {
		return p.UserAgent
	}
	if saved := loadSavedVKProfile(); saved != nil && saved.UserAgent != "" {
		return saved.UserAgent
	}
	// Fallback for cold start (pre-first-WebView): generic recent Safari iOS.
	// Matches the Phase 9 TLS family at least; browser_fp will also be
	// generated (not captured) until WebView completes.
	return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
}

// newSessionClient is the legacy name for backwards compatibility. New code
// should call GetSessionClient directly.
func newSessionClient() tls_client.HttpClient {
	return GetSessionClient()
}

// newFreshSessionClient builds a NEW bogdanfinn HttpClient with a FRESH cookie
// jar each call (NOT the GetSessionClient singleton), same Safari iOS 26 TLS
// profile (or Chrome_146 in VK_DESKTOP_CHROME mode).
//
// The legacy cred fetch (creds.go getVKCredsWithClientID) uses ONE per fetch:
// VK keys the legacy calls.getAnonymousToken anon-call token on the SESSION
// COOKIE (remixstid), NOT on device_id — so reusing the shared singleton made
// every fetch return the SAME token → all credpool slots shared ONE
// 10-allocation TURN quota → 486 "Allocation Quota Reached" past ~10 conns
// (the "stuck at 20/20" bug). Harness-proven 2026-05-31: shared jar → 1
// identical token across fetches; fresh jar → distinct tokens. The free path
// (creds_vkcalls.go) does NOT need this — its identity is the per-fetch
// device-bound anonymous_token JWT, immune to the shared cookie.
func newFreshSessionClient() tls_client.HttpClient {
	var clientProfile profiles.ClientProfile
	if desktopChromeProfile() != nil {
		clientProfile = profiles.Chrome_146
	} else {
		clientProfile = customSafariIOS26Profile()
	}
	client, cerr := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithTimeoutSeconds(20),
		tls_client.WithClientProfile(clientProfile),
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithDialer(vkDiagDialer()), // DIAGNOSTIC (build 167): log requested dial addr+family
	)
	if cerr != nil {
		log.Printf("pow: ERROR creating fresh session client: %v — falling back to singleton", cerr)
		return GetSessionClient()
	}
	return client
}

// newHTTPClient creates a fresh http.Client (no cookie jar) with Chrome TLS fingerprint.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: newChromeTransport(),
	}
}

// solveCaptchaPoW attempts to solve a VK "Not Robot" captcha automatically
// using proof-of-work, without any user interaction.
//
// Returns (successToken, lastShowCaptchaType, err). lastShowCaptchaType is the
// last known hint from VK about what captcha type should be presented to the
// user — either from the API `captchaNotRobot.check` response or (when the
// checkbox check is skipped) from the HTML page's window.init payload. The
// caller (creds.go) uses it as a signal for retry/backoff decisions.
func solveCaptchaPoW(ctx context.Context, client tls_client.HttpClient, redirectURI, captchaSID, userAgent string) (string, string, error) {
	captchaPowProfile = profileForUA(userAgent)
	if p := desktopChromeProfile(); p != nil {
		// VK_DESKTOP_CHROME diagnostic: pin the entire identity to Chrome 146
		// and ignore any captured iPhone Safari profile (its UA/fp/device are
		// suppressed below in componentDone too).
		captchaPowProfile = *p
	} else if saved := loadSavedVKProfile(); saved != nil && saved.UserAgent != "" {
		// If we have a captured browser profile (from WKWebView capture saved
		// to vk_profile.json), override the UA derived from the input userAgent
		// param. The captured UA is the one VK saw when computing the captured
		// browser_fp; sending a mismatched UA to validate that fp triggers BOT.
		// Before this override (2026-05-11) we sent UA=Chrome desktop while the
		// captured browser_fp was computed for Safari iOS Mobile — guaranteed
		// fingerprint inconsistency on every check.
		captchaPowProfile.UserAgent = saved.UserAgent
	}
	log.Printf("pow: attempting automatic captcha solve (UA: %s, platform: %s, Chrome/%d)",
		captchaPowProfile.UserAgent, captchaPowProfile.Platform, captchaPowProfile.ChromeVersion)

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return "", "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	sessionToken := parsed.Query().Get("session_token")
	if sessionToken == "" {
		return "", "", fmt.Errorf("no session_token in redirect_uri")
	}

	// The HTTP client (with its cookie jar) is passed in by the caller so the
	// captcha session shares cookies with the getAnonymousToken request that
	// issued this captcha. The legacy cred fetch passes a FRESH per-fetch client
	// (newFreshSessionClient) so each fetch is a distinct VK session.
	// (bogdanfinn HttpClient has no CloseIdleConnections; profile pool is reused via package-level state)

	// Random initial delay (1.5-2.5s) — HAR timing from real browser
	delay := time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return "", "", ctx.Err()
	}

	// Step 1: Fetch captcha page and extract PoW parameters + cookies + slider settings + JS bundle URL.
	// This GETs the redirect_uri (typically id.vk.ru/not_robot_captcha?session_token=...)
	// and accumulates session cookies (remixlang/remixstid/remixstlid) in the jar.
	// These cookies are required for subsequent captchaNotRobot.* calls.
	powInput, difficulty, scriptURL, htmlSettings, err := fetchPoW(ctx, client, redirectURI)
	if err != nil {
		return "", "", fmt.Errorf("fetch PoW: %w", err)
	}
	log.Printf("pow: input=%s difficulty=%d htmlSettings=%v scriptURL=%s", powInput, difficulty, htmlSettings != nil, scriptURL)

	// Phase 6: Pull the version-specific debug_info constant from the
	// captcha JS bundle. Falls back to hardcoded value if the bundle URL
	// wasn't extracted or if regex doesn't match the JS contents. Cache
	// is keyed on full scriptURL (versioned path) so VK rotating the
	// constant via a JS bump auto-invalidates.
	debugInfo := fetchAndCacheDebugInfo(ctx, client, scriptURL)

	// Log cookies received from page load (for debugging) — bogdanfinn API
	if parsedURL, e := url.Parse("https://id.vk.ru"); e == nil {
		cookies := client.GetCookies(parsedURL)
		log.Printf("pow: received %d cookies from page load", len(cookies))
	}
	if parsedURL, e := url.Parse("https://vk.ru"); e == nil {
		cookies := client.GetCookies(parsedURL)
		log.Printf("pow: received %d cookies from vk.ru domain", len(cookies))
	}

	// Phase 11 (build 106): Replicate real Safari WebView preflight sequence
	// captured 2026-05-17 via mitmproxy. See vk_captcha_mitm_capture_2026_05_17.md.
	// Real WebView between fetchPoW (step 1, id.vk.ru/not_robot_captcha GET)
	// and first captchaNotRobot.* POST does:
	//   a. GET ad.mail.ru/static/sync-loader.js (JS bundle, generates adFp)
	//   b. POST privacy-cs.mail.ru/fp/?id=<adFp> with browser fingerprint JSON
	//   c. POST sdk-api.apptracer.ru/api/crash/trackSession (analytics SDK)
	// All errors non-fatal — these are pure traffic-shape parity replays,
	// not load-bearing for VK's protocol. captchaNotRobot.* proceeds either
	// way; if Phase 11 hypothesis is right (VK checks for tracking-endpoint
	// presence), having these means status=OK; if wrong, doesn't make worse.
	fetchMailRuSyncLoader(ctx, client)

	adFp := getSessionAdFp()
	log.Printf("pow: using session adFp=%s for this PoW solve", adFp)

	registerAdFpWithMailRu(ctx, client, adFp)
	fetchAppTracerSession(ctx, client)

	// Step 2: Solve PoW (brute-force SHA-256)
	hash := solvePoW(powInput, difficulty)
	if hash == "" {
		return "", "", fmt.Errorf("PoW: no solution found within 10M iterations")
	}
	log.Printf("pow: solved hash=%s...%s", hash[:8], hash[len(hash)-8:])

	// Brief pause after PoW (simulate browser JS execution time)
	time.Sleep(time.Duration(200+mathrand.Intn(300)) * time.Millisecond)

	// Step 3: Call captchaNotRobot API sequence (using same client = same cookies)
	successToken, showType, err := callCaptchaNotRobotAPI(ctx, client, sessionToken, hash, adFp, debugInfo, htmlSettings)
	if err != nil {
		return "", showType, fmt.Errorf("captchaNotRobot API: %w", err)
	}

	log.Printf("pow: success! token=%d chars", len(successToken))
	return successToken, showType, nil
}

// debugInfoCache maps captcha-script URL → extracted debug_info hex
// constant. Per Moroka8/vk-turn-proxy commit 21cf9fa: the constant is
// versioned (path includes vkid/<version>/not_robot_captcha.js), VK
// rotates it when bumping the captcha JS bundle. Caching by full URL
// auto-invalidates on version change.
var debugInfoCache sync.Map

// debugInfoRegex extracts the constant fallback from the captcha JS:
//
//	debug_info: (window.vk?.brlefapmjnpg) || "a0ac4896...64hex..."
//
// or older: debug_info: "a0ac4896..."
//
// Captures the 64-hex string. If the JS structure changes the fallback
// extraction fails and we use the hardcoded constant from build 93 as
// last resort.
var debugInfoRegex = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)

// captchaJSRegex finds the not_robot_captcha.js script URL embedded in
// the captcha HTML page so we can fetch it and extract debug_info.
var captchaJSRegex = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)

// hardcodedDebugInfo is the build-93 fallback constant captured from
// Safari WKWebView 2026-05-15. Used when dynamic extraction fails.
const hardcodedDebugInfo = "a0ac4896e9b899f78d905fd37c5adb2b768aa955eb7b2a7bcba6ee2a44a96daf"

// fetchAndCacheDebugInfo GETs the captcha JS bundle, extracts the
// debug_info constant via debugInfoRegex, caches by script URL, and
// returns the extracted value. Returns hardcodedDebugInfo on any
// failure (regex miss, HTTP error, parse error) — the captcha attempt
// will still be made with the previously-canonical value rather than
// failing outright.
//
// Phase 6 of the 2026-05-15 PoW regression investigation: ports
// dynamic extraction from Moroka8 captcha v2. If VK rotates the
// constant in a future JS version (bumping the vkid/X.Y.Z path), we
// pick it up automatically; build 93's hardcoded value would have
// become stale.
func fetchAndCacheDebugInfo(ctx context.Context, client tls_client.HttpClient, scriptURL string) string {
	if scriptURL == "" {
		return hardcodedDebugInfo
	}
	if cached, ok := debugInfoCache.Load(scriptURL); ok {
		return cached.(string)
	}
	req, err := fhttp.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		log.Printf("pow: debug_info fetch req-build failed (%v) — falling back to hardcoded constant", err)
		return hardcodedDebugInfo
	}
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "text/javascript,*/*")
	req.Header.Set("Accept-Encoding", safariAcceptEncoding)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	applyChromeHints(req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pow: debug_info fetch failed (%v) — falling back to hardcoded constant", err)
		return hardcodedDebugInfo
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body) // bogdanfinn auto-decompresses gzip
	if err != nil {
		log.Printf("pow: debug_info read body failed (%v) — falling back to hardcoded constant", err)
		return hardcodedDebugInfo
	}
	m := debugInfoRegex.FindSubmatch(body)
	if len(m) < 2 {
		log.Printf("pow: debug_info regex no match in JS (%d bytes) — falling back to hardcoded constant", len(body))
		return hardcodedDebugInfo
	}
	value := string(m[1])
	debugInfoCache.Store(scriptURL, value)
	log.Printf("pow: debug_info extracted from %s = %s (cached)", scriptURL, value)
	return value
}

// fetchPoW fetches the captcha HTML page and extracts PoW parameters.
// scriptURL is the captcha JS bundle URL (e.g. https://static.vk.ru/vkid/
// 1.1.1331/not_robot_captcha.js), used by fetchAndCacheDebugInfo to
// extract the version-specific debug_info constant. Empty if extraction
// fails (caller falls back to hardcodedDebugInfo).
func fetchPoW(ctx context.Context, client tls_client.HttpClient, redirectURI string) (powInput string, difficulty int, scriptURL string, htmlSettings map[string]interface{}, err error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, "", nil, err
	}
	// Headers calibrated for Safari iOS 17 mobile (see vkReq for full
	// rationale). For the document GET we keep navigate-mode Sec-Fetch
	// triplet plus Upgrade-Insecure-Requests. Removed: sec-ch-ua* (Chrome
	// only), DNT (Safari dropped). Changed: Accept stripped of Chrome-specific
	// image format preferences (Safari sends a simpler Accept), Accept-Language
	// → en-GB matching captured device.language.
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", safariAcceptEncoding)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	applyChromeHints(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	log.Printf("pow: fetchPoW HTTP status=%d", resp.StatusCode)

	body, err := io.ReadAll(resp.Body) // bogdanfinn auto-decompresses gzip
	if err != nil {
		return "", 0, "", nil, fmt.Errorf("read body (Content-Encoding=%q): %w",
			resp.Header.Get("Content-Encoding"), err)
	}
	// Phase 3 diagnostic: log cookies the jar received from the page GET.
	// Real Safari accumulates remixlang/remixstid/remixstlid here and
	// replays them on subsequent api.vk.ru POSTs. Verify our jar does the
	// same — if it shows zero cookies after the page GET, that's a strong
	// signal the missing cookies are part of the BOT detection.
	logCookiesForURL(client, "https://api.vk.ru", "fetchPoW post-GET (api.vk.ru)")
	logCookiesForURL(client, "https://id.vk.ru", "fetchPoW post-GET (id.vk.ru)")
	html := string(body)

	powRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	m := powRe.FindStringSubmatch(html)
	if len(m) < 2 {
		preview := html
		if len(preview) > 500 {
			preview = preview[:500]
		}
		log.Printf("pow: HTML preview: %s", preview)
		return "", 0, "", nil, fmt.Errorf("powInput not found in HTML (%d bytes)", len(html))
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

	// Extract captcha JS bundle URL — used by fetchAndCacheDebugInfo to
	// pull the version-specific debug_info constant. The URL contains a
	// vkid/<version>/ path component that auto-invalidates our cache when
	// VK bumps the captcha bundle.
	if m := captchaJSRegex.FindStringSubmatch(html); len(m) >= 2 {
		scriptURL = m[1]
		log.Printf("pow: captcha script URL %s", scriptURL)
	} else {
		log.Printf("pow: captcha script URL not found in HTML — debug_info will use hardcoded fallback")
	}

	return powInput, difficulty, scriptURL, htmlSettings, nil
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

// readDecompressedBody decodes an HTTP response body based on the given
// Content-Encoding string. Decoupled from http.Response / fhttp.Response
// types so it works with either (Phase 7 introduced fhttp via
// bogdanfinn/tls-client; std net/http still used in non-captcha paths).
//
// Needed because when we set Accept-Encoding manually (gzip, deflate,
// br, zstd — to match Safari's HTTP fingerprint), neither std nor
// bogdanfinn transports auto-decompress reliably; we have to handle it.
//
// brotli + zstd come from indirect deps already in go.sum (used by
// klauspost/compress and andybalholm/brotli transitively).
func readDecompressedBody(body io.Reader, encoding string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	var reader io.Reader
	switch enc {
	case "", "identity":
		reader = body
	case "gzip":
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("gzip decoder init: %w", err)
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	case "deflate":
		zr := flate.NewReader(body)
		defer func() { _ = zr.Close() }()
		reader = zr
	case "br":
		// brotli.Reader has no Close (just an io.Reader).
		reader = brotli.NewReader(body)
	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("zstd decoder init: %w", err)
		}
		defer zr.Close()
		reader = zr
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding: %q", enc)
	}
	return io.ReadAll(reader)
}

// safariAcceptEncoding matches what Safari iOS 17 sends literally.
// Set as a request header — see readDecompressedBody for the rationale.
const safariAcceptEncoding = "gzip, deflate, br, zstd"

// accessTokenSuffix is the Safari-canonical trailing form field on every
// captchaNotRobot.* body — an empty `access_token=` at the very end.
// Real Safari sends this after all per-method fields (sensors, browser_fp,
// hash, debug_info, etc.). Pre-build-94 we put `access_token=` 4th
// (right after adFp), giving same content but different byte order — a
// possible fingerprint difference. See callCaptchaNotRobotAPI for the
// position-by-position comparison with Safari capture 2026-05-15.
const accessTokenSuffix = "&access_token="

// logCookiesForURL logs the names of cookies that the bogdanfinn captcha
// session client would send to the given URL. Used for diagnostic
// visibility into whether the captcha session jar correctly accumulates
// + replays VK cookies (real Safari sends remixlang/remixstid/remixstlid;
// we should too after the initial id.vk.ru GET in fetchPoW). Phase 3
// diagnostic, updated for tls_client.HttpClient in Phase 7.
//
// tls_client.HttpClient.GetCookies(url) returns the cookies the jar
// holds for that URL — same semantics as net/http CookieJar.Cookies.
func logCookiesForURL(client tls_client.HttpClient, rawURL, label string) {
	if client == nil {
		log.Printf("pow: %s captcha session client is nil", label)
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("pow: %s cookie URL parse failed: %v", label, err)
		return
	}
	cookies := client.GetCookies(u)
	if len(cookies) == 0 {
		log.Printf("pow: %s NO cookies in jar for %s", label, u.Host)
		return
	}
	names := make([]string, len(cookies))
	for i, c := range cookies {
		names[i] = c.Name
	}
	log.Printf("pow: %s sending %d cookies to %s: %v", label, len(cookies), u.Host, names)
}

// genAdFp produces a 21-char base64url string used as the `adFp` form field
// in captchaNotRobot.check. Empirically (Safari WKWebView capture via Web
// Inspector, 2026-05-11) sync-loader.js from ad.mail.ru generates this
// client-side as a random tracking ID — VK validates only its presence and
// format, not its value (no cross-domain handshake with mail.ru). Until
// 2026-05-11 we sent `adFp=` empty in the POST body, which after VK tightened
// bot heuristics dropped PoW success from 88% (build 64 era) to 6% across
// 49+ attempts on two distinct captured fps. 16 random bytes → 22 base64url
// chars → truncated to 21 to match the empirically observed length.
func genAdFp() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) > 21 {
		s = s[:21]
	}
	return s
}

var (
	sessionAdFpVal  string
	sessionAdFpOnce sync.Once
)

// 5-minute captcha solver throttle was introduced in builds 106 (per-process)
// and 107 (cross-process via App Group shared file) to protect VK's per-IP
// rate-limit budget from credPool grower retry-storms. Removed in build 108
// after empirical verification proved the underlying HTTP-layer mimicry
// approach (Phase 11) is dead — Mac and FreeBSD VPS standalone runs of the
// same Go solver code BOTH returned BOT, conclusively ruling out iOS
// environment / per-IP reputation / TLS layer / HTTP-layer differences as
// the detection axis. Detection requires JS execution context the Go solver
// structurally cannot provide. With Go solver expected to fail every time
// regardless, throttle no longer adds value — it would just delay the
// recognized-failure handoff to WebView fallback. Throttle (per-IP pacing
// for actually-working solver) would belong in a future server-side
// headless-browser captcha-solver service, not in the legacy Go solver.

// getSessionAdFp returns a process-stable adFp value, generated once on
// first call and reused for every subsequent solveCaptchaPoW. Mimics
// real Safari's window.rb_sync.id, which is generated by sync-loader.js
// and persisted in cookie + localStorage for the lifetime of the page
// (and across page reloads while the cookie is alive).
//
// Pre-build-91 we generated a fresh random per solveCaptchaPoW, meaning
// each of the 3 PoW retries (in creds.go) sent a different adFp. Real
// Safari sends the SAME adFp across all attempts within the same browser
// session — and across multiple captcha sessions, since rb_sync persists.
// The inconsistency was a candidate BOT signal during the 2026-05-15
// PoW regression investigation (Phase 1; see open question in chat
// session 76000841 for empirical context). NOT proven to be the cause —
// this is a hypothesis fix, will be evaluated empirically.
//
// Process-scoped (not user-scoped) deliberately: persisting to disk
// (vk_profile.json) would be more Safari-like but the value is opaque
// and we have no evidence it matters across process restarts. Easy to
// promote later if data warrants.
func getSessionAdFp() string {
	sessionAdFpOnce.Do(func() {
		sessionAdFpVal = genAdFp()
		log.Printf("pow: initialized session adFp=%s (process-stable; reused for all subsequent PoW solves)", sessionAdFpVal)
	})
	return sessionAdFpVal
}

// fetchMailRuSyncLoader downloads ad.mail.ru/static/sync-loader.js — the JS
// bundle that real Safari WKWebView loads while rendering the VK captcha
// page. sync-loader.js is responsible for generating adFp client-side. We
// don't execute the JS (no V8 in Go process) but loading it matches real
// WebView's network footprint exactly (see vk_captcha_mitm_capture_2026_05_17.md
// step 2). Errors non-fatal.
//
// Phase 11 (build 106). Added based on mitmproxy capture of our app's
// WebView captcha solve session that VK accepted with status=OK.
func fetchMailRuSyncLoader(ctx context.Context, client tls_client.HttpClient) {
	syncURL := "https://ad.mail.ru/static/sync-loader.js"
	req, err := fhttp.NewRequestWithContext(ctx, "GET", syncURL, nil)
	if err != nil {
		log.Printf("pow: fetchMailRuSyncLoader skipped (req-build: %v)", err)
		return
	}
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", safariAcceptEncoding)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Origin", "https://id.vk.ru")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	applyChromeHints(req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pow: fetchMailRuSyncLoader failed (non-fatal): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	n, _ := io.Copy(io.Discard, resp.Body)
	log.Printf("pow: mail.ru sync-loader loaded (status=%d, %d bytes)", resp.StatusCode, n)
}

// registerAdFpWithMailRu does the privacy-cs.mail.ru/fp/?id=<adFp> POST
// that real WebView does to register the adFp with mail.ru's fingerprint
// store. Empirically VK does NOT validate adFp against mail.ru DB (verified
// twice in prior sessions — random adFp works fine in captchaNotRobot.*),
// but this POST is harmless traffic-shape parity with real WebView and may
// influence some other detection heuristic.
//
// Body matches captured WebView format byte-for-byte:
// {"script":{"v":"v4.0.3","b_id":"152552442"},"navigator":{...},"screen":{...},"sendReason":1}
//
// plugins_hash and properties_hash are hardcoded from captured WebView —
// they're likely deterministic per Safari version + plugin set, but we
// don't verify; copying captured values is safest. screen.* is hardcoded
// from captured WebView (iPhone 375x667 → mobile values). userAgent is
// inserted dynamically from captchaPowProfile.
//
// Phase 11 (build 106) — replaces previous fetchAdFpPing (a GET that
// matched older Safari capture but the proper call is POST with body).
func registerAdFpWithMailRu(ctx context.Context, client tls_client.HttpClient, adFp string) {
	// Captured body shape from 2026-05-17 WebView mitm (iPhone 375x667).
	// In desktop-Chrome diagnostic mode, swap the mobile screen + en-GB for a
	// 1920x1080 desktop screen + en-US so this stays consistent with the
	// Chrome identity (this POST is non-load-bearing — VK does not validate
	// adFp against mail.ru — but keep it coherent anyway).
	navLang := "en-GB (en-GB)"
	screenRes := "667;375"
	if desktopChromeProfile() != nil {
		navLang = "en-US (en-US)"
		screenRes = "1080;1920"
	}
	body := fmt.Sprintf(
		`{"script":{"v":"v4.0.3","b_id":"152552442"},`+
			`"navigator":{"language":"%s","plugins_hash":"f8a4506236a7ac2d7ac1251468bbdc2b","properties_hash":"f34e97527ec40c1deeb748830014d230","userAgent":"%s"},`+
			`"screen":{"availableScreenResolution":"%s","screenResolution":"%s"},`+
			`"sendReason":1}`,
		navLang, captchaPowProfile.UserAgent, screenRes, screenRes)

	fpURL := "https://privacy-cs.mail.ru/fp/?id=" + adFp
	req, err := fhttp.NewRequestWithContext(ctx, "POST", fpURL, strings.NewReader(body))
	if err != nil {
		log.Printf("pow: registerAdFpWithMailRu skipped (req-build: %v)", err)
		return
	}
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", safariAcceptEncoding)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Origin", "https://id.vk.ru")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	applyChromeHints(req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pow: registerAdFpWithMailRu failed (non-fatal): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	log.Printf("pow: adFp registered with mail.ru (status=%d, id=%s)", resp.StatusCode, adFp)
}

// fetchAppTracerSession POSTs sdk-api.apptracer.ru/api/crash/trackSession
// that real WebView calls. Apptracer is a Russian app analytics SDK that VK
// embeds in the captcha page for crash + performance telemetry. We don't
// care about analytics — we replicate the call for traffic-shape parity
// with real WebView session footprint. Errors non-fatal.
//
// crashToken is per-deployment app key registered with apptracer when the
// captcha page is built. Hardcoded from captured WebView 2026-05-17
// (build 106 used a random token and got HTTP 400 — apptracer rejects
// unregistered tokens). VK doesn't validate apptracer responses, but
// returning 200 vs 400 means our session shows up in apptracer's logs
// the way real WebView's does — better traffic-shape parity.
//
// deviceId and sessionUuid are UUIDs. We generate UUID-shaped random strings
// from 16 random bytes formatted as 8-4-4-4-12 hex.
//
// Phase 11 (build 106). Hardcoded crashToken added build 107.
const apptracerCrashToken = "91nhGGlf9xzaH5OUO6PxuvR31DAUnL8xtNoULeuCFrK0"

func fetchAppTracerSession(ctx context.Context, client tls_client.HttpClient) {
	deviceID := randomUUIDish()
	sessionUUID := randomUUIDish()
	crashToken := apptracerCrashToken

	body := fmt.Sprintf(
		`{"versionName":"1.1.1331","versionCode":"0","deviceId":"%s",`+
			`"sessions":[{"sessionUuid":"%s","versionName":"1.1.1331","versionCode":"0","status":"RUNNING","environment":"production"}]}`,
		deviceID, sessionUUID)

	trackURL := "https://sdk-api.apptracer.ru/api/crash/trackSession?crashToken=" + crashToken + "&sdkVersion=2.6.3"
	req, err := fhttp.NewRequestWithContext(ctx, "POST", trackURL, strings.NewReader(body))
	if err != nil {
		log.Printf("pow: fetchAppTracerSession skipped (req-build: %v)", err)
		return
	}
	req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", safariAcceptEncoding)
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	req.Header.Set("Origin", "https://id.vk.ru")
	req.Header.Set("Referer", "https://id.vk.ru/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	applyChromeHints(req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pow: fetchAppTracerSession failed (non-fatal): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	log.Printf("pow: apptracer session tracked (status=%d, deviceID=%s)", resp.StatusCode, deviceID)
}

// randomUUIDish produces a UUID-shaped string (8-4-4-4-12 hex) from 16
// random bytes. Not RFC 4122 UUID (no version bits set), just shape-match
// for fields that expect UUID format. Apptracer doesn't validate UUID
// structure, only string shape.
func randomUUIDish() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// callCaptchaNotRobotAPI performs the 4-step VK captchaNotRobot protocol.
// Adapted from the reference implementation in PR #105 — uses simplified
// sensor data (empty arrays) and longer timing delays.
//
// Returns (successToken, lastShowCaptchaType, err). See solveCaptchaPoW for
// the meaning of lastShowCaptchaType.
func callCaptchaNotRobotAPI(ctx context.Context, client tls_client.HttpClient, sessionToken, hash, adFp, debugInfo string, htmlSettings map[string]interface{}) (string, string, error) {
	vkReq := func(method, postData string) (map[string]interface{}, error) {
		reqURL := "https://" + vkAPIHost() + "/method/" + method + "?v=5.131"
		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		// Headers calibrated against real Safari iOS 17 WKWebView capture
		// (Web Inspector → Network → captchaNotRobot.check, 2026-05-11).
		// Removed: sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform (Chrome
		// Client Hints — Safari does NOT send them and our captured browser_fp
		// was computed for Safari mobile, so sending Chrome hints with Safari
		// UA was a double mismatch). Removed: DNT (Safari dropped years ago),
		// Sec-GPC (Brave/Firefox-only signal). Changed: Accept-Language to
		// en-GB matching captured device.language. Added: Cache-Control,
		// Pragma, Priority — all present in Safari capture.
		req.Header.Set("User-Agent", captchaPowProfile.UserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", safariAcceptEncoding)
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
		applyChromeHints(req)
		if desktopChromeProfile() != nil {
			// THE FIX (2026-05-30): VK fingerprints the HTTP/2 header ORDER on
			// captchaNotRobot.* and flags our default (uncontrolled bogdanfinn
			// order) as BOT. amurcanov pins Chrome's order and gets checkbox
			// status=OK on the SAME IP/creds where we got BOT — proven by A/B
			// in their own code (only the header-order axis flips the verdict).
			// Match it: pin the order + drop the Safari-only Cache-Control/
			// Pragma so our header SET fits the order list, and use Priority
			// u=1,i. Gated on desktop-Chrome (the order list assumes the
			// sec-ch-ua* headers we only send in that mode).
			req.Header.Del("Cache-Control")
			req.Header.Del("Pragma")
			req.Header.Set("Priority", "u=1, i")
			req.Header[fhttp.HeaderOrderKey] = chromeCaptchaHeaderOrder
			req.Header[fhttp.PHeaderOrderKey] = chromeCaptchaPHeaderOrder
		} else {
			// PRODUCTION FIX (2026-05-30): pin real Safari WKWebView header
			// order + drop the spurious Cache-Control/Pragma (real Safari sends
			// neither on captchaNotRobot.* per the 2026-05-17 mitm). The HTTP/2
			// header ORDER was THE captcha discriminator: bogdanfinn's
			// uncontrolled default order ≠ real Safari, so VK flagged us BOT
			// since the 2026-05-15 update. With the order pinned,
			// captchaNotRobot.check returns status=OK — verified on multiple IPs
			// with BOTH captured and generated browser_fp. Keeps the full Safari
			// identity (TLS/UA/captured profile/adFp/preflight) consistent with
			// the WKWebView manual-solve fallback.
			req.Header.Del("Cache-Control")
			req.Header.Del("Pragma")
			req.Header[fhttp.HeaderOrderKey] = safariCaptchaHeaderOrder
		}

		// Phase 3 diagnostic: surface what cookies we're sending to VK.
		// Real Safari sends remixlang/remixstid/remixstlid on every
		// captchaNotRobot.* call; we should too after fetchPoW (which
		// GETs id.vk.ru/not_robot_captcha and should accumulate
		// Set-Cookie headers in the shared jar).
		logCookiesForURL(client, reqURL, method)

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP POST %s failed: %w", method, err)
		}
		defer func() { _ = httpResp.Body.Close() }()

		body, err := io.ReadAll(httpResp.Body) // bogdanfinn auto-decompresses gzip
		if err != nil {
			return nil, fmt.Errorf("read body (Content-Encoding=%q): %w",
				httpResp.Header.Get("Content-Encoding"), err)
		}

		log.Printf("pow: %s response: %s", method, string(body[:min(300, len(body))]))

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}
		return resp, nil
	}

	domain := "vk.com"
	// Phase 11 (build 106): adFp LIFECYCLE matches captured WebView 2026-05-17.
	// Real WebView sends adFp=EMPTY on captchaNotRobot.settings (because
	// sync-loader.js hasn't generated it yet at that point in the page
	// lifecycle), then adFp=<value> on componentDone/check/endSession (after
	// sync-loader.js completes).
	//
	// Pre-Phase 11 we sent adFp value on all 4 calls — that was a deviation
	// from real WebView pattern that may have been a BOT signal.
	//
	// Body order: session_token & domain & adFp first, then per-method
	// fields (sensors / browser_fp / hash / answer / debug_info), then
	// access_token LAST. Matches Safari capture order byte-for-byte.
	baseParamsEmptyAdFp := fmt.Sprintf("session_token=%s&domain=%s&adFp=",
		url.QueryEscape(sessionToken), url.QueryEscape(domain))
	baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=%s",
		url.QueryEscape(sessionToken), url.QueryEscape(domain), url.QueryEscape(adFp))

	// Extract HTML-level show_captcha_type hint. VK embeds a `window.init.data`
	// payload in the captcha page that announces which challenge type VK plans
	// to render. Empirically:
	//   - "slider"   : VK is in slider-only mode (checkbox disabled). Every
	//                  subsequent captchaNotRobot.check returns status=ERROR.
	//                  Skipping the check saves ~3 seconds (2.5s artificial
	//                  delay + HTTP round-trip) on every solveCaptchaPoW call.
	//   - "checkbox" : normal mode, checkbox may succeed — proceed as usual.
	htmlShowType := ""
	if htmlSettings != nil {
		if resp, ok := htmlSettings["response"].(map[string]interface{}); ok {
			if s, ok := resp["show_captcha_type"].(string); ok {
				htmlShowType = s
			}
		}
	}
	// lastShowType is what we return to the caller as the last known
	// show_captcha_type signal. Seeded from the HTML hint; overwritten by the
	// API check response if we make one.
	lastShowType := htmlShowType

	// 1/4: settings
	//
	// Phase 5 (build 97) skipped this and componentDone on the
	// hypothesis that Safari WKWebView capture's Web Inspector showed
	// only check + endSession. EMPIRICALLY DISPROVED — BOT rate
	// stayed at 100% (vpn.wifi.8.log). Reverted in build 98.
	// Cross-check with Moroka8/vk-turn-proxy commit 21cf9fa shows
	// they DO call settings + componentDone — Safari's Inspector
	// likely missed them due to caching or filter, not absence.
	log.Printf("pow: 1/4 captchaNotRobot.settings (adFp=EMPTY per Phase 11 WebView lifecycle)")
	settingsResp, err := vkReq("captchaNotRobot.settings", baseParamsEmptyAdFp+accessTokenSuffix)
	if err != nil {
		return "", lastShowType, fmt.Errorf("settings: %w", err)
	}

	// Short delay after settings (100-200ms) — matches reference impl
	time.Sleep(time.Duration(100+mathrand.Intn(100)) * time.Millisecond)

	// 2/4: componentDone
	log.Printf("pow: 2/4 captchaNotRobot.componentDone")

	// Default: generated browser_fp + canned device descriptor. VK's
	// anti-bot scoring catches this pattern almost every time
	// (status=BOT on .check, see vpn.wifi.0.log analysis 2026-05-08
	// where 62/66 fresh fetches got BOT). If we have a captured real
	// browser profile from a prior manual solve in CaptchaWKWebView,
	// use those values instead — they pass VK's check because they
	// were originally produced and accepted by VK's own JS.
	browserFp := fmt.Sprintf("%x%x", mathrand.Int63(), mathrand.Int63())

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
	deviceParam := url.QueryEscape(string(deviceBytes))

	if desktopChromeProfile() != nil {
		// VK_DESKTOP_CHROME diagnostic: keep the RANDOM browser_fp generated
		// above and send the desktop 1920x1080 device blob (amurcanov's exact
		// known-working value). Do NOT load the captured iPhone profile — its
		// Safari fp/device would contradict the Chrome TLS+UA+sec-ch-ua.
		deviceParam = url.QueryEscape(desktopChromeDeviceJSON)
		log.Printf("pow: desktop-Chrome mode — random browser_fp=%s (len=%d) + 1920x1080 device (captured iPhone profile ignored)",
			browserFp[:min(8, len(browserFp))], len(browserFp))
	} else if saved := loadSavedVKProfile(); saved != nil {
		ageDays := (float64(time.Now().Unix()) - saved.CapturedAt) / 86400.0
		log.Printf("pow: using captured browser profile (browser_fp=%dc, device=%dc, captured %.1f days ago)",
			len(saved.BrowserFp), len(saved.Device), ageDays)
		browserFp = saved.BrowserFp
		// saved.Device is the raw value from the captured request body,
		// which was already URL-encoded form-data. Pass through as-is —
		// re-encoding would double-escape the JSON braces and quotes.
		deviceParam = saved.Device
	} else {
		log.Printf("pow: no captured browser profile, using generated browser_fp+device")
	}

	componentData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, deviceParam) + accessTokenSuffix

	if _, err := vkReq("captchaNotRobot.componentDone", componentData); err != nil {
		return "", lastShowType, fmt.Errorf("componentDone: %w", err)
	}

	// 3/4: check (checkbox-style).
	//
	// We always attempt the checkbox check regardless of past responses.
	// Empirically VK's status=ERROR is transient ("captcha type unavailable
	// right now") rather than permanent — a previous version cached a
	// session-wide "burned" flag on the first ERROR and skipped checkbox
	// forever, but that wedged the pool grower whenever VK returned a
	// single ERROR (slider also fails ~100% in our environment, so once
	// burned, every subsequent solveCaptchaPoW returned an error and the
	// pool decayed to empty). Now we just retry the checkbox each call;
	// if it returns ERROR/BOT/ERROR_LIMIT we still fall through to the
	// slider attempt within the same call.
	{
		// Longer pause before check (1950-3200ms) — matches reference HAR timing
		checkDelay := time.Duration(1950+mathrand.Intn(1250)) * time.Millisecond
		log.Printf("pow: waiting %s before check", checkDelay.Round(time.Millisecond))
		select {
		case <-time.After(checkDelay):
		case <-ctx.Done():
			return "", lastShowType, ctx.Err()
		}

		log.Printf("pow: 3/4 captchaNotRobot.check")

		// Sensor arrays empty across the board — confirmed by Safari
		// WKWebView capture 2026-05-15 (captchaNotRobot.check.curl).
		// Real Safari sends `cursor=[]` and `connectionDownlink=[]`,
		// not fake-but-realistic data we used to send. The fake data
		// (5 cursor positions + 7 downlink floats) was a try-too-hard
		// mistake from build 85 era — real iOS Safari just sends []
		// for checkbox-style captcha (sensor data is only relevant
		// for slider variant). Sending fake values gave VK an extra
		// signal to detect us; reverting matches Safari exactly.
		cursorBytes := []byte("[]")
		downlinkBytes := []byte("[]")

		answer := base64.StdEncoding.EncodeToString([]byte("{}"))

		// debug_info — passed in from solveCaptchaPoW.
		// fetchAndCacheDebugInfo extracts the version-specific constant
		// from not_robot_captcha.js dynamically (Phase 6 of 2026-05-15
		// PoW regression investigation, ported from Moroka8 v2 solver).
		// Falls back to the canonical "a0ac4896..." constant on any
		// extraction failure. See callCaptchaNotRobotAPI sig + Phase 2
		// commentary in build 93 for the original hardcoded reasoning.

		// Phase 11.1 (build 107): URL-encode `answer` value. Captured
		// WebView sends `answer=e30%3D` (encoded `=`); pre-build-107 we
		// sent `answer=e30=` (raw `=`). Functionally same param value,
		// but byte-different on wire — possibly a fingerprint signal.
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
			url.QueryEscape(answer),
			debugInfo,
		) + accessTokenSuffix

		checkResp, err := vkReq("captchaNotRobot.check", checkData)
		if err != nil {
			return "", lastShowType, fmt.Errorf("check: %w", err)
		}

		respObj, ok := checkResp["response"].(map[string]interface{})
		if !ok {
			return "", lastShowType, fmt.Errorf("check: invalid response: %v", checkResp)
		}
		status, _ := respObj["status"].(string)
		showCaptchaType, _ := respObj["show_captcha_type"].(string)
		// Overwrite the HTML-seeded hint with VK's explicit API response.
		lastShowType = showCaptchaType

		if status == "OK" {
			successToken, ok := respObj["success_token"].(string)
			if !ok || successToken == "" {
				return "", lastShowType, fmt.Errorf("check: no success_token in response")
			}
			time.Sleep(200 * time.Millisecond)
			log.Printf("pow: 4/4 captchaNotRobot.endSession")
			_, err = vkReq("captchaNotRobot.endSession", baseParams+accessTokenSuffix)
			if err != nil {
				log.Printf("pow: endSession failed (non-fatal): %v", err)
			}
			return successToken, lastShowType, nil
		}

		// Checkbox check failed. ALL non-OK statuses are treated as transient
		// — a future solveCaptchaPoW call will retry the checkbox. Falls
		// through to the slider attempt below as an in-call fallback.
		log.Printf("pow: checkbox failure (status=%s, show_captcha_type=%s) — falling through to slider; next solveCaptchaPoW call will retry checkbox", status, showCaptchaType)
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
	sliderToken, sliderErr := solveSliderCaptcha(vkReq, baseParams, browserFp, deviceParam, hash, mergedSettings)
	if sliderErr == nil && sliderToken != "" {
		log.Printf("pow: slider solver succeeded!")
		time.Sleep(200 * time.Millisecond)
		log.Printf("pow: 4/4 captchaNotRobot.endSession")
		if _, esErr := vkReq("captchaNotRobot.endSession", baseParams+accessTokenSuffix); esErr != nil {
			log.Printf("pow: endSession failed (non-fatal): %v", esErr)
		}
		return sliderToken, lastShowType, nil
	}
	log.Printf("pow: slider solver failed: %v", sliderErr)
	return "", lastShowType, fmt.Errorf("checkbox check failed and slider also failed: %v", sliderErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
