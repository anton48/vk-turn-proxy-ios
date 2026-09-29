// SPDX-License-Identifier: MIT

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// uapiConfig is TunnelManager.buildUAPIConfig in Go: hex keys, the peer address
// as the endpoint (TURNBind ignores it — the proxy carries every packet), the
// one peer taking everything, the app's keepalive.
func uapiConfig(privB64, pubB64, pskB64, endpoint string, keepalive int) (string, error) {
	priv, err := keyHex(privB64)
	if err != nil {
		return "", fmt.Errorf("privateKey %w", err)
	}
	pub, err := keyHex(pubB64)
	if err != nil {
		return "", fmt.Errorf("peerPublicKey %w", err)
	}
	if strings.ContainsAny(endpoint, "\n\r=") {
		return "", fmt.Errorf("peerAddress holds a control character")
	}
	lines := []string{
		"private_key=" + priv,
		"replace_peers=true",
		"public_key=" + pub,
		"endpoint=" + endpoint,
	}
	if keepalive > 0 {
		lines = append(lines, "persistent_keepalive_interval="+strconv.Itoa(keepalive))
	}
	lines = append(lines, "allowed_ip=0.0.0.0/0")
	if pskB64 != "" {
		psk, err := keyHex(pskB64)
		if err != nil {
			return "", fmt.Errorf("presharedKey %w", err)
		}
		lines = append(lines, "preshared_key="+psk)
	}
	return strings.Join(lines, "\n"), nil
}

// keyHex turns a base64 WireGuard key into UAPI's hex; the error never
// carries the key.
func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("is not base64")
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("is %d bytes, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
