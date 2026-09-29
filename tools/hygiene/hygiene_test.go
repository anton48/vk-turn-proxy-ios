// SPDX-License-Identifier: MIT

package hygiene

// THE TREE CARRIES NO REAL ADDRESS (2026-09-28, the user's finding). The stands'
// DNS names had been cleaned out of the doc comments on 2026-09-08 (f912cad) —
// and the same comments, the examples of the tools and the fixtures of the tests
// still named the stands, the server and the relays by IP. A name and an address
// are one class: a reader of the public repository learns where the
// infrastructure lives.
//
// The rule: every IPv4 or IPv6 literal in a tracked text file must be one the
// tree may carry —
//
//   - the unspecified, loopback and broadcast addresses;
//   - a private (RFC 1918), link-local or carrier-grade-NAT (100.64.0.0/10) network;
//   - multicast and the reserved space above it;
//   - a DOCUMENTATION range: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
//     (RFC 5737) and 2001:db8::/32 (RFC 3849) — what an example or a fixture
//     names a host by;
//   - a public resolver everyone knows (1.1.1.1, 8.8.8.8, 9.9.9.9, Yandex's
//     77.88.8.8 and their kin), which the tools and the app's defaults point at;
//   - a browser version that merely LOOKS like an address (Chrome/146.0.0.0 in a
//     User-Agent — four numbers behind a "Name/");
//   - a NETWORK of /8 or wider — 0.0.0.0/1 and 128.0.0.0/1, the two halves of
//     the address space a tunnel's routes take (the console client, 09-29): a
//     prefix that wide names no host. A /24 or a /32 still does.
//
// A literal is a dotted quad, or three octets and a format verb — "203.0.113.%d"
// in a fixture that mints one host per slot names the /24 as surely as a quad
// does. Anything else is a real host, and the test names it with its file and
// line.
//
// What is read: `git ls-files` — what the repository publishes, never what
// happens to lie in the working tree (the local, gitignored scripts carry a
// machine's own paths and are nobody's business). third_party/ is skipped: the
// vendored fork is pinned byte for byte against upstream by its own guard, and
// upstream's fixtures are upstream's.
//
// Seen red on the tree of 2026-09-28 before the addresses were replaced, and
// red again under a sabotage that puts one public address back into a comment —
// with a full stop behind it, since the user's finding of the same evening.

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestTheTreeCarriesNoRealAddress(t *testing.T) {
	root := moduleRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files in %s: %v — the guard reads what the repository TRACKS; run it inside the checkout", root, err)
	}
	var bad []string
	files := 0
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" || strings.HasPrefix(rel, "third_party/") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) { // tracked, deleted in the working tree — nothing published from it
				continue
			}
			t.Fatal(err)
		}
		if looksBinary(data) {
			continue
		}
		files++
		for i, line := range strings.Split(string(data), "\n") {
			for _, lit := range addressLiterals(line) {
				if !allowedAddress(lit) {
					bad = append(bad, fmt.Sprintf("%s:%d: %s", rel, i+1, lit.text))
				}
			}
		}
	}
	if files == 0 {
		t.Fatal("no tracked text file read — the walk is broken, not the tree clean")
	}
	if len(bad) > 0 {
		t.Fatalf("%d real address(es) in the tree — a stand, a server, a relay or a device named by IP. Name it by a placeholder (<server-ip>:<port>) or by a documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) instead:\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// The guard sees what it is built to see: a public address in any file, a
// documentation address and a browser version in none.
func TestTheRuleTellsARealAddressFromWhatTheTreeMayCarry(t *testing.T) {
	// The negative cases are built at run time: a real-looking address must not
	// stand in this file either — the tree's guard reads it too.
	host := net.IPv4(93, 184, 216, 34).String()
	bench := net.IPv4(198, 18, 0, 1).String()
	v6 := net.IP{0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}.String()
	prefix := strings.TrimSuffix(net.IPv4(95, 163, 34, 0).String(), "0") // "N.N.N." — a real /24, three octets
	for text, want := range map[string]bool{
		"the relay at 203.0.113.10:19302 answered":                          true,
		"dial 198.51.100.7:56000":                                           true,
		"the doc example 192.0.2.1":                                         true,
		"resolver 1.1.1.1 and 77.88.8.8":                                    true,
		"listen 0.0.0.0:9000 / 127.0.0.1:53":                                true,
		"the tunnel 10.66.67.4/24, the LAN 192.168.0.7":                     true,
		"link-local 169.254.1.1, carrier 100.64.0.1, mask 255.255.255.0":    true,
		"Chrome/146.0.0.0 Safari/537.36":                                    true,
		"an IPv6 example 2001:db8::1 and the resolver 2606:4700:4700::1111": true,
		"a version v1.2.3.4 and a longer 1.2.3.4.5 are no addresses":        true,
		"a host " + host + " in a comment":                                  false,
		"a relay at " + bench + ":19302":                                    false,
		"a fixture minting " + prefix + "%d:19302 per slot":                 false,
		"a doc fixture minting 203.0.113.%d:19302 per slot":                 true,
		"the server address is " + host + ".":                               false,
		"in parentheses (" + host + "), then a comma " + host + ",":         false,
		"an IPv6 at the end of a sentence: " + v6 + ".":                     false,
		"an IPv6 before the colon of a sentence " + v6 + ": and on":         false,
		"a fifth component 1.2.3.4.5 and 5.1.2.3.4 are no addresses":        true,
		"a documentation address at the end of a sentence: 203.0.113.10.":   true,
		"a server at [" + v6 + "]:443":                                      false,
		"the halves 0.0.0.0/1 and 128.0.0.0/1 into the tunnel":              true,
		"a real network named by a narrow prefix " + host + "/24":           false,
		"a real host named as a /32: " + host + "/32":                       false,
		"a real host with a port-like slash " + host + "/16bits":            false,
	} {
		got := true
		for _, lit := range addressLiterals(text) {
			if !allowedAddress(lit) {
				got = false
			}
		}
		if got != want {
			t.Errorf("%q: allowed %v, want %v", text, got, want)
		}
	}
}

type literal struct {
	ip     net.IP
	text   string
	before string // the line up to the literal
	after  string // the line after it
}

var (
	v4Pattern = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	// three octets and a format verb: "203.0.113.%d" in a fixture that mints one host per slot
	v4Format  = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.%d`)
	v6Pattern = regexp.MustCompile(`[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	// Chrome/146.0.0.0, Version/17.4.1.2 — a product's version, not a host.
	versionPrefix = regexp.MustCompile(`[A-Za-z]+/$`)
	// "/1" … "/8" right behind the literal: a network that wide names no host.
	widePrefix = regexp.MustCompile(`^/[0-8]\b`)
	docV4      = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
	resolvers  = map[string]bool{
		"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true, "9.9.9.9": true, "149.112.112.112": true,
		"77.88.8.8": true, "77.88.8.1": true, "77.88.8.88": true, "77.88.8.2": true,
		"208.67.222.222": true, "208.67.220.220": true,
		"2606:4700:4700::1111": true, "2606:4700:4700::1001": true,
		"2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
	}
)

func addressLiterals(line string) []literal {
	var out []literal
	for _, m := range v4Pattern.FindAllStringIndex(line, -1) {
		if joinedBefore(line, m[0]) || joinedAfter(line, m[1]) {
			continue // v1.2.3.4, 1.2.3.4.5, an identifier's tail — never the full stop of a sentence
		}
		ip := net.ParseIP(line[m[0]:m[1]])
		if ip == nil {
			continue // an octet above 255: a version like 146.0.7680.116
		}
		out = append(out, literal{ip: ip, text: line[m[0]:m[1]], before: line[:m[0]], after: line[m[1]:]})
	}
	for _, m := range v4Format.FindAllStringIndex(line, -1) {
		if joinedBefore(line, m[0]) {
			continue
		}
		ip := net.ParseIP(strings.TrimSuffix(line[m[0]:m[1]], "%d") + "0")
		if ip == nil {
			continue
		}
		out = append(out, literal{ip: ip, text: line[m[0]:m[1]], before: line[:m[0]]})
	}
	for _, m := range v6Pattern.FindAllStringIndex(line, -1) {
		if joinedBefore(line, m[0]) || joinedAfter(line, m[1]) {
			continue
		}
		text := line[m[0]:m[1]]
		ip := net.ParseIP(text)
		if ip == nil && strings.HasSuffix(text, ":") {
			// "2001:db8::1: and then" — the pattern takes the sentence's colon for an
			// empty group; the address is what stands before it.
			text = strings.TrimSuffix(text, ":")
			ip = net.ParseIP(text)
		}
		if ip == nil || ip.To4() != nil || ip[0]&0xe0 != 0x20 {
			continue // not an address, or not global unicast (fe80::, ::1, ff02::)
		}
		out = append(out, literal{ip: ip, text: text, before: line[:m[0]]})
	}
	return out
}

// joinedBefore / joinedAfter: is the literal part of a longer token? A letter,
// a digit or an underscore joins it (v1.2.3.4, an identifier's tail); a DOT
// joins it only with a digit on its other side — the fifth component of
// 1.2.3.4.5 — and is otherwise punctuation: an address before the full stop of
// a sentence («… lives at 203.0.113.10.») is an address. The first cut took
// every dot for a continuation and let exactly that through — the user's
// finding of 2026-09-28, shown on a temporary copy of the tree: a Markdown
// line with a public address and a full stop passed, the same line without
// the full stop did not.
func joinedBefore(s string, start int) bool {
	if start == 0 {
		return false
	}
	c := s[start-1]
	if c == '.' {
		return start >= 2 && isDigit(s[start-2])
	}
	return isWordChar(c)
}

func joinedAfter(s string, end int) bool {
	if end >= len(s) {
		return false
	}
	c := s[end]
	if c == '.' {
		return end+1 < len(s) && isDigit(s[end+1])
	}
	return isWordChar(c)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isWordChar(c byte) bool {
	return c == '_' || isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func allowedAddress(l literal) bool {
	if resolvers[l.ip.String()] {
		return true
	}
	if v4 := l.ip.To4(); v4 != nil {
		if v4.IsUnspecified() || v4.IsLoopback() || v4.Equal(net.IPv4bcast) || v4.IsPrivate() ||
			v4.IsLinkLocalUnicast() || v4[0] >= 224 || (v4[0] == 100 && v4[1]&0xC0 == 64) {
			return true
		}
		for _, cidr := range docV4 {
			if _, n, _ := net.ParseCIDR(cidr); n.Contains(v4) {
				return true
			}
		}
		return versionPrefix.MatchString(l.before) || widePrefix.MatchString(l.after)
	}
	_, doc6, _ := net.ParseCIDR("2001:db8::/32")
	return doc6.Contains(l.ip)
}

func looksBinary(data []byte) bool {
	if len(data) > 8000 {
		data = data[:8000]
	}
	return bytes.IndexByte(data, 0) >= 0
}

func moduleRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller information")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("%s is not the module root: %v", root, err)
	}
	return root
}
