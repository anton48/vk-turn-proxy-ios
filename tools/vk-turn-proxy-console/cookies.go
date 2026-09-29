// SPDX-License-Identifier: MIT

package main

// -vk-cookie-file: a VK login exported from a browser as Netscape cookies.txt
// (the format curl and the "cookies.txt" browser extensions write) turns on the
// authenticated (VKAuth) mode — the console's analogue of the app's VK login
// WebView, which the console has none of.
//
// The app sends VK exactly two cookies, "remixsid=…; p=…" (VKAuthWebView.swift):
// remixsid of .vk.com or .vk.ru, p of .login.vk.com or .login.vk.ru. The file
// may hold a browser's whole jar; only those two are taken, the freshest of
// each. 🚫 Nothing of a cookie's value is ever printed — not in an error, not
// for a malformed line.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type fileCookie struct {
	domain, name, value string
	expires             time.Time // zero: a session cookie
}

// parseNetscapeCookies reads the seven tab-separated fields of each line:
// domain, subdomains flag, path, secure flag, expiry (unix seconds, 0 = session),
// name, value. "#HttpOnly_" before a domain is curl's marker for an HttpOnly
// cookie, not a comment — VK's auth cookies are HttpOnly.
func parseNetscapeCookies(r io.Reader) ([]fileCookie, error) {
	var out []fileCookie
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "#HttpOnly_") {
			line = strings.TrimPrefix(line, "#HttpOnly_")
		} else if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			return nil, fmt.Errorf("line %d: %d tab-separated fields, a Netscape cookie line has 7", n, len(f))
		}
		c := fileCookie{domain: strings.ToLower(f[0]), name: f[5], value: f[6]}
		exp, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: the expiry field is not a number", n)
		}
		if exp > 0 {
			c.expires = time.Unix(exp, 0)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// domainUnder: the cookie's domain is suffix itself or one of its subdomains.
func domainUnder(domain, suffix string) bool {
	d := strings.TrimPrefix(domain, ".")
	return d == suffix || strings.HasSuffix(d, "."+suffix)
}

// vkCookieHeader picks remixsid (.vk.com / .vk.ru) and p (.login.vk.com /
// .login.vk.ru), unexpired, the one that lives longest of each, and returns
// the app's header with the pair's earlier expiry (zero if both are session
// cookies).
func vkCookieHeader(cookies []fileCookie, now time.Time) (string, time.Time, error) {
	pick := func(name string, suffixes ...string) (*fileCookie, error) {
		var best *fileCookie
		expired := false
		for i := range cookies {
			c := &cookies[i]
			if c.name != name || c.value == "" {
				continue
			}
			under := false
			for _, s := range suffixes {
				if domainUnder(c.domain, s) {
					under = true
				}
			}
			if !under {
				continue
			}
			if !c.expires.IsZero() && !c.expires.After(now) {
				expired = true
				continue
			}
			if best == nil || (!best.expires.IsZero() && (c.expires.IsZero() || c.expires.After(best.expires))) {
				best = c
			}
		}
		if best == nil {
			if expired {
				return nil, fmt.Errorf("the %s cookie in the file has expired — log in to VK again and export the cookies anew", name)
			}
			return nil, fmt.Errorf("no %s cookie of %s in the file", name, strings.Join(suffixes, " / "))
		}
		return best, nil
	}
	sid, err := pick("remixsid", "vk.com", "vk.ru")
	if err != nil {
		return "", time.Time{}, err
	}
	p, err := pick("p", "login.vk.com", "login.vk.ru")
	if err != nil {
		return "", time.Time{}, err
	}
	if strings.ContainsAny(sid.value+p.value, ";\r\n") {
		return "", time.Time{}, errors.New("a cookie value holds a separator — the file is damaged")
	}
	exp := sid.expires
	if exp.IsZero() || (!p.expires.IsZero() && p.expires.Before(exp)) {
		exp = p.expires
	}
	return "remixsid=" + sid.value + "; p=" + p.value, exp, nil
}
