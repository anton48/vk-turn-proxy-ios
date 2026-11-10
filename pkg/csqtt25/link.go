package csqtt25

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// The 2.5 connection link: csqtt:// + base64url( IV(12) ‖ AES-256-GCM ) of
// the 2.1.9 query string. The key is the SHA-256 of a seed the app carries —
// obfuscation, not secrecy.
const linkKeySeed = "csqtt-chiper-key"

// Link is a decoded connection link.
type Link struct {
	Host     string
	Port     int
	Password string
	Hashes   []string // bare VK call hashes, when the link carries them
	Token    string   // a VK access token, when the link carries one
}

func linkAEAD() (cipher.AEAD, [32]byte, error) {
	key := sha256.Sum256([]byte(linkKeySeed))
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, key, err
	}
	g, err := cipher.NewGCM(b)
	return g, key, err
}

func decodeBase64Any(s string) ([]byte, error) {
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(strings.TrimSpace(s))
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("csqtt25: the link is not base64")
}

// IsEncryptedLink reports whether raw has the 2.5 form: a csqtt:// link
// whose body decrypts. A plain connect?… or pass@host:port link is 2.1.9's.
func IsEncryptedLink(raw string) bool {
	_, err := DecodeLink(raw)
	return err == nil
}

// DecodeLink decrypts and parses a 2.5 link.
func DecodeLink(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 8 || !strings.EqualFold(raw[:8], "csqtt://") {
		return Link{}, errors.New("csqtt25: not a csqtt:// link")
	}
	blob, err := decodeBase64Any(raw[8:])
	if err != nil {
		return Link{}, err
	}
	g, _, err := linkAEAD()
	if err != nil {
		return Link{}, err
	}
	if len(blob) < 12+g.Overhead() {
		return Link{}, errors.New("csqtt25: the link is too short")
	}
	plain, err := g.Open(nil, blob[:12], blob[12:], nil)
	if err != nil {
		return Link{}, errors.New("csqtt25: the link does not decrypt (a 2.1.9 link, or damaged)")
	}
	return parseLinkQuery(string(plain))
}

// EncodeLink is DecodeLink's inverse (the IV is taken from the plaintext, as
// the reference app does, so a link is stable).
func EncodeLink(l Link) (string, error) {
	// A field is percent-escaped, a space as %20: in this query a '+' is the
	// separator of the hashes and never a space.
	esc := func(v string) string { return strings.ReplaceAll(url.QueryEscape(v), "+", "%20") }
	q := []string{"v=2", "host=" + esc(l.Host), "peer=" + strconv.Itoa(l.Port), "password=" + esc(l.Password)}
	if len(l.Hashes) > 0 {
		hashes := make([]string, len(l.Hashes))
		for i, h := range l.Hashes {
			hashes[i] = esc(h)
		}
		q = append(q, "hashes="+strings.Join(hashes, "+"))
	} else if l.Token != "" {
		q = append(q, "token="+esc(l.Token))
	}
	plain := []byte("connect?" + strings.Join(q, "&"))
	g, key, err := linkAEAD()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write(plain)
	iv := mac.Sum(nil)[:12]
	return "csqtt://" + base64.RawURLEncoding.EncodeToString(append(iv, g.Seal(nil, iv, plain, nil)...)), nil
}

func parseLinkQuery(plain string) (Link, error) {
	q := plain
	if i := strings.Index(q, "?"); i >= 0 {
		q = q[i+1:]
	}
	fields := map[string]string{}
	for _, kv := range strings.Split(q, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// '+' separates hashes; it is not a space here.
		dec, err := url.QueryUnescape(strings.ReplaceAll(v, "+", "%2B"))
		if err != nil {
			return Link{}, errors.New("csqtt25: a link field does not decode")
		}
		fields[k] = dec
	}
	if fields["v"] != "2" || fields["host"] == "" {
		return Link{}, errors.New("csqtt25: the link has no v=2 host")
	}
	port, err := strconv.Atoi(fields["peer"])
	if err != nil || port < 1 || port > 65535 {
		return Link{}, errors.New("csqtt25: the link has no valid peer port")
	}
	l := Link{Host: fields["host"], Port: port, Password: strings.TrimSpace(fields["password"]), Token: strings.TrimSpace(fields["token"])}
	if h := fields["hashes"]; h != "" {
		l.Hashes = strings.Split(h, "+")
	}
	return l, nil
}
