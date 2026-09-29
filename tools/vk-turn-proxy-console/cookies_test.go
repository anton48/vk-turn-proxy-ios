package main

// The VK login from cookies.txt: the app's two cookies and nothing else, the
// HttpOnly marker read as a marker, an expired pair refused, no value ever in
// an error. Sabotage seen red: "#HttpOnly_" read as a comment; the domain rule
// loosened (a remixsid of another site taken); the expiry ignored; the header
// in another order or with a third cookie.

import (
	"strings"
	"testing"
	"time"
)

const cookiesTxt = "# Netscape HTTP Cookie File\n" +
	"# https://curl.se/docs/http-cookies.html\n" +
	"\n" +
	"#HttpOnly_.vk.com\tTRUE\t/\tTRUE\t1893456000\tremixsid\tSIDVALUE\n" +
	"#HttpOnly_.login.vk.com\tTRUE\t/\tTRUE\t1861920000\tp\tPVALUE\n" +
	".vk.com\tTRUE\t/\tFALSE\t1893456000\tremixlang\t0\n" +
	".example.org\tTRUE\t/\tFALSE\t1893456000\tremixsid\tFOREIGN\n"

func TestTheAppsTwoCookiesComeOutOfCookiesTxt(t *testing.T) {
	cs, err := parseNetscapeCookies(strings.NewReader(cookiesTxt))
	if err != nil {
		t.Fatal(err)
	}
	h, exp, err := vkCookieHeader(cs, time.Unix(1790000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if h != "remixsid=SIDVALUE; p=PVALUE" {
		t.Fatalf("header = %q, want the app's pair, remixsid first, nothing else", h)
	}
	if !exp.Equal(time.Unix(1861920000, 0)) {
		t.Fatalf("expiry = %v, want the pair's earlier one", exp)
	}
}

func TestTheVKRUDomainsCountToo(t *testing.T) {
	txt := "#HttpOnly_.vk.ru\tTRUE\t/\tTRUE\t0\tremixsid\tS\n#HttpOnly_login.vk.ru\tFALSE\t/\tTRUE\t0\tp\tP\n"
	cs, err := parseNetscapeCookies(strings.NewReader(txt))
	if err != nil {
		t.Fatal(err)
	}
	if h, _, err := vkCookieHeader(cs, time.Now()); err != nil || h != "remixsid=S; p=P" {
		t.Fatalf("vk.ru pair: %q, %v", h, err)
	}
}

func TestAnExpiredOrMissingCookieIsRefusedWithoutItsValue(t *testing.T) {
	now := time.Unix(1790000000, 0)
	expired := "#HttpOnly_.vk.com\tTRUE\t/\tTRUE\t1700000000\tremixsid\tOLDSID\n#HttpOnly_.login.vk.com\tTRUE\t/\tTRUE\t1893456000\tp\tPVALUE\n"
	cs, _ := parseNetscapeCookies(strings.NewReader(expired))
	_, _, err := vkCookieHeader(cs, now)
	if err == nil || !strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "OLDSID") {
		t.Fatalf("expired remixsid: %v", err)
	}
	noP := "#HttpOnly_.vk.com\tTRUE\t/\tTRUE\t1893456000\tremixsid\tSID\n"
	cs, _ = parseNetscapeCookies(strings.NewReader(noP))
	if _, _, err := vkCookieHeader(cs, now); err == nil || !strings.Contains(err.Error(), "no p cookie") {
		t.Fatalf("no p: %v", err)
	}
	foreign := ".example.org\tTRUE\t/\tFALSE\t1893456000\tremixsid\tX\n.login.example.org\tTRUE\t/\tFALSE\t1893456000\tp\tY\n"
	cs, _ = parseNetscapeCookies(strings.NewReader(foreign))
	if _, _, err := vkCookieHeader(cs, now); err == nil {
		t.Fatal("another site's remixsid / p accepted")
	}
}

func TestAMalformedLineIsReportedByNumberOnly(t *testing.T) {
	_, err := parseNetscapeCookies(strings.NewReader("# header\n.vk.com TRUE / TRUE 1893456000 remixsid SECRETSID\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "SECRETSID") {
		t.Fatalf("err = %v, want the line number and no value", err)
	}
}

func TestTheLongestLivedCookieOfEachIsTaken(t *testing.T) {
	txt := "#HttpOnly_.vk.com\tTRUE\t/\tTRUE\t1800000000\tremixsid\tSHORT\n" +
		"#HttpOnly_.vk.ru\tTRUE\t/\tTRUE\t1893456000\tremixsid\tLONG\n" +
		"#HttpOnly_.login.vk.com\tTRUE\t/\tTRUE\t1893456000\tp\tP\n"
	cs, _ := parseNetscapeCookies(strings.NewReader(txt))
	if h, _, _ := vkCookieHeader(cs, time.Unix(1790000000, 0)); h != "remixsid=LONG; p=P" {
		t.Fatalf("header = %q, want the remixsid that lives longest", h)
	}
}
