// SPDX-License-Identifier: MIT

package main

// The console's config is the iOS app's FULL BACKUP (Backup & Restore →
// Export Full Backup…), unchanged: vk-turn-proxy-console.json in the working
// directory, or -config <path>. One file carries the servers, the call links
// and the global settings; what the console does not use is left alone.
//
// 🚫 What it deliberately does NOT read:
//   - turn_pool — the app's cached TURN credentials. The console keeps its
//     own cache (-cred-cache): an identity used by the phone and the console at
//     once would share one allocation quota, and the two pools would evict
//     each other's seats.
//   - vk_profile — the phone WebView's captured browser fingerprint. The
//     console's captcha solver generates its own: one fingerprint on two
//     devices would link them at VK.
//
// The server: -server <name>, or the FIRST server of the native SRTP mode
// (useSrtp and no other transport); a named server of another mode is an
// error — the console carries the native mode only. Absent keys take the
// app's defaults (ServerProfile.swift), the way the app itself decodes them.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type backupFile struct {
	Version  int            `json:"version"`
	Type     string         `json:"type"`
	Settings backupSettings `json:"settings"`
}

type backupSettings struct {
	VKLink             string         `json:"vkLink"`
	Servers            []backupServer `json:"servers"`
	ActiveServer       *string        `json:"activeServer"`
	VKAuth             *bool          `json:"vkAuth"`
	UplinkPaceKiB      *int           `json:"uplinkPaceKiB"`
	TunnelMTU          *int           `json:"tunnelMTU"`
	ForceLegacyCaptcha *bool          `json:"forceLegacyCaptcha"`

	// The single-server fields of backups made before servers existed; the
	// app turns them into one server on import, and so does the console.
	backupServer
}

type backupServer struct {
	ServerName              string  `json:"serverName"`
	PrivateKey              *string `json:"privateKey"`
	PeerPublicKey           *string `json:"peerPublicKey"`
	PresharedKey            *string `json:"presharedKey"`
	TunnelAddress           *string `json:"tunnelAddress"`
	PeerAddress             *string `json:"peerAddress"`
	DNSServers              *string `json:"dnsServers"`
	NumConnections          *int    `json:"numConnections"`
	CredPoolCooldownSeconds *int    `json:"credPoolCooldownSeconds"`
	TurnServerOverride      *string `json:"turnServerOverride"`
	UseUDP                  *bool   `json:"useUDP"`
	UseSrtp                 *bool   `json:"useSrtp"`
	UseWrap                 *bool   `json:"useWrap"`
	UseWrapA                *bool   `json:"useWrapA"`
	UseWrapS                *bool   `json:"useWrapS"`
	UseCsqtt                *bool   `json:"useCsqtt"`
}

// server is a backup server with the app's defaults applied.
type server struct {
	Name                                    string
	PrivateKey, PeerPublicKey, PresharedKey string
	TunnelAddress, PeerAddress, DNSServers  string
	NumConnections                          int
	CredPoolCooldownSeconds                 int
	TurnServerOverride                      string
	UseUDP                                  bool
	UseSrtp, UseWrap, UseWrapA, UseWrapS    bool
	UseCsqtt                                bool
}

// The app's defaults for a key a server does not carry (ServerProfile.swift).
const (
	defaultTunnelAddress = "192.168.102.3/24"
	defaultDNSServers    = "1.1.1.1"
	defaultNumConns      = 30
	defaultCooldownSec   = 150
)

func strOr(p *string, d string) string {
	if p == nil {
		return d
	}
	return *p
}

func intOr(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

func boolOr(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

func (b backupServer) withDefaults() server {
	return server{
		Name:                    b.ServerName,
		PrivateKey:              strOr(b.PrivateKey, ""),
		PeerPublicKey:           strOr(b.PeerPublicKey, ""),
		PresharedKey:            strOr(b.PresharedKey, ""),
		TunnelAddress:           strOr(b.TunnelAddress, defaultTunnelAddress),
		PeerAddress:             strOr(b.PeerAddress, ""),
		DNSServers:              strOr(b.DNSServers, defaultDNSServers),
		NumConnections:          intOr(b.NumConnections, defaultNumConns),
		CredPoolCooldownSeconds: intOr(b.CredPoolCooldownSeconds, defaultCooldownSec),
		TurnServerOverride:      strOr(b.TurnServerOverride, ""),
		UseUDP:                  boolOr(b.UseUDP, false),
		UseSrtp:                 boolOr(b.UseSrtp, true),
		UseWrap:                 boolOr(b.UseWrap, false),
		UseWrapA:                boolOr(b.UseWrapA, false),
		UseWrapS:                boolOr(b.UseWrapS, false),
		UseCsqtt:                boolOr(b.UseCsqtt, false),
	}
}

// mode is the app's label for the server's transport (ServerProfile.modeLabel).
func (s server) mode() string {
	switch {
	case s.UseCsqtt:
		return "csqtt"
	case s.UseWrapS:
		return "SRTP-WRAP-S"
	case s.UseWrapA:
		return "SRTP-WRAP-A"
	case s.UseSrtp:
		return "SRTP"
	case s.UseWrap:
		return "SRTP+WRAP"
	}
	return "Legacy (DTLS+WG)"
}

// native reports the one mode the console carries.
func (s server) native() bool {
	return s.UseSrtp && !s.UseWrap && !s.UseWrapA && !s.UseWrapS && !s.UseCsqtt
}

func loadBackup(path string) (*backupFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b backupFile
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s is not the app's backup: %v", path, err)
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("%s: backup version %d, the console reads version 1", path, b.Version)
	}
	return &b, nil
}

// servers lists the backup's servers in order, defaults applied. A backup
// from before servers existed yields its one legacy server.
func (b *backupFile) servers() []server {
	var out []server
	for _, s := range b.Settings.Servers {
		out = append(out, s.withDefaults())
	}
	if len(out) == 0 && b.Settings.backupServer.PrivateKey != nil {
		legacy := b.Settings.backupServer.withDefaults()
		legacy.Name = "Server1"
		out = append(out, legacy)
	}
	return out
}

// selectServer picks -server's name, or the first native SRTP server.
func selectServer(list []server, name string) (server, error) {
	if len(list) == 0 {
		return server{}, errors.New("the backup holds no servers")
	}
	if name != "" {
		match := -1
		for i, s := range list {
			if s.Name == name {
				match = i
				break
			}
		}
		if match < 0 { // a unique case-insensitive match, for a name typed in a shell
			for i, s := range list {
				if strings.EqualFold(s.Name, name) {
					if match >= 0 {
						return server{}, fmt.Errorf("-server %q matches more than one server by case; give the exact name", name)
					}
					match = i
				}
			}
		}
		if match < 0 {
			return server{}, fmt.Errorf("no server named %q in the backup (servers: %s)", name, serverNames(list))
		}
		if s := list[match]; !s.native() {
			return server{}, fmt.Errorf("server %q is %s; the console carries the native SRTP mode only", s.Name, s.mode())
		}
		return list[match], nil
	}
	for _, s := range list {
		if s.native() {
			return s, nil
		}
	}
	return server{}, fmt.Errorf("the backup has no server of the native SRTP mode (servers: %s)", serverNames(list))
}

func serverNames(list []server) string {
	var parts []string
	for _, s := range list {
		parts = append(parts, fmt.Sprintf("%q %s", s.Name, s.mode()))
	}
	return strings.Join(parts, ", ")
}

// settings is what the console runs with: the server, the backup's globals
// and the command line's overrides.
type settings struct {
	ServerName                              string
	PrivateKey, PeerPublicKey, PresharedKey string // base64, never logged
	TunnelAddress                           string // IPv4 CIDR
	PeerAddress                             string // host:port — the TURN peer, our server's SRTP listener
	DNSServers                              []string
	NumConns                                int
	CredPoolCooldown                        time.Duration
	TurnServer, TurnPort                    string
	UseUDP                                  bool
	VKLinks                                 []string // [0] mints anonymously; all of them in cookie mode
	VKAuth                                  bool
	UplinkPaceKiB                           int
	MTU                                     int
	ForceLegacyCaptcha                      bool
}

// The tunnel MTU rule of the app (TunnelMTU.swift): 0 is automatic = 1280,
// anything else clamped to 1000…1400.
const (
	mtuStandard = 1280
	mtuMinimum  = 1000
	mtuMaximum  = 1400
)

func resolveMTU(stored int) int {
	if stored == 0 {
		return mtuStandard
	}
	return min(max(stored, mtuMinimum), mtuMaximum)
}

// splitLinks is the app's reading of vkLink: one link per line, blanks dropped.
func splitLinks(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// splitDNS is WireGuardConfText.splitDNS: commas and whitespace separate; the
// IP literals are the servers (search domains have no place here).
func splitDNS(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if net.ParseIP(f) != nil {
			out = append(out, f)
		}
	}
	return out
}

// parseTurnOverride is TunnelManager.parseTurnOverride: "host:port" or nothing.
func parseTurnOverride(raw string) (host, port string, ok bool) {
	t := strings.TrimSpace(raw)
	i := strings.LastIndex(t, ":")
	if t == "" || i <= 0 || i == len(t)-1 {
		return "", "", false
	}
	host, port = t[:i], t[i+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false
	}
	return host, port, true
}

func buildSettings(b *backupFile, s server) settings {
	st := settings{
		ServerName:         s.Name,
		PrivateKey:         strings.TrimSpace(s.PrivateKey),
		PeerPublicKey:      strings.TrimSpace(s.PeerPublicKey),
		PresharedKey:       strings.TrimSpace(s.PresharedKey),
		TunnelAddress:      strings.TrimSpace(s.TunnelAddress),
		PeerAddress:        strings.TrimSpace(s.PeerAddress),
		DNSServers:         splitDNS(s.DNSServers),
		NumConns:           s.NumConnections,
		CredPoolCooldown:   time.Duration(s.CredPoolCooldownSeconds) * time.Second,
		UseUDP:             s.UseUDP,
		VKLinks:            splitLinks(b.Settings.VKLink),
		VKAuth:             boolOr(b.Settings.VKAuth, false),
		UplinkPaceKiB:      intOr(b.Settings.UplinkPaceKiB, 0),
		MTU:                resolveMTU(intOr(b.Settings.TunnelMTU, 0)),
		ForceLegacyCaptcha: boolOr(b.Settings.ForceLegacyCaptcha, false),
	}
	if h, p, ok := parseTurnOverride(s.TurnServerOverride); ok {
		st.TurnServer, st.TurnPort = h, p
	}
	return st
}

// maxConns is the console's ceiling; the app's 60 is Swift's (ServerEditView,
// TunnelManager) and the Go side has none. Above ~60 on one relay host the
// open N=60 blackhole may bite — «проверим на практике».
const maxConns = 120

// validate checks what a start needs, naming the field and never its value.
func (st settings) validate() error {
	for _, k := range []struct{ name, v string }{{"privateKey", st.PrivateKey}, {"peerPublicKey", st.PeerPublicKey}} {
		if err := checkKey(k.v); err != nil {
			return fmt.Errorf("server %q: %s %v", st.ServerName, k.name, err)
		}
	}
	if st.PresharedKey != "" {
		if err := checkKey(st.PresharedKey); err != nil {
			return fmt.Errorf("server %q: presharedKey %v", st.ServerName, err)
		}
	}
	ip, _, err := net.ParseCIDR(st.TunnelAddress)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("server %q: tunnelAddress is not an IPv4 address with a prefix (a /24 in the app)", st.ServerName)
	}
	if _, _, err := net.SplitHostPort(st.PeerAddress); err != nil || st.PeerAddress == "" {
		return fmt.Errorf("server %q: peerAddress is not host:port", st.ServerName)
	}
	if st.NumConns < 1 || st.NumConns > maxConns {
		return fmt.Errorf("%d connections: the console carries 1…%d", st.NumConns, maxConns)
	}
	if len(st.VKLinks) == 0 {
		return errors.New("the backup has no VK call link (settings.vkLink) — the credentials are minted from it")
	}
	return nil
}

func checkKey(b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errors.New("is not base64")
	}
	if len(raw) != 32 {
		return fmt.Errorf("is %d bytes, a WireGuard key is 32", len(raw))
	}
	return nil
}

// poolSize is the console's credential pool: (1 + R) × ceil(N/10) identities.
// ceil(N/10) seat the N connections (ten allocations per identity and relay);
// R more sets are the reserve. A path change cools EVERY identity in use for
// 10m30s — their allocations may live on at the relay — so a reserve that
// rides one change is a full set, not one spare (the user's point, 09-29): one
// spare seats ten of thirty and leaves the rest waiting for mints. R = 1 by
// default; the app's four identities per ten connections is R = 3.
func poolSize(conns, reserve int) int {
	return (1 + reserve) * ((conns + 9) / 10)
}

// configReadableByOthers reports a config file group or others can read: it
// holds the WireGuard private key.
func configReadableByOthers(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm()&0o077 != 0
}
