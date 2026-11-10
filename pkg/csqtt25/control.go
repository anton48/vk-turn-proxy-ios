package csqtt25

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The control plane: plaintext strings inside the wrapper.
const (
	ReadyRequest         = "READY"
	ReadyOK              = "READY_OK"
	NoConfigResponse     = "NOCONF"
	DisconnectedResponse = "OK:disconnected"

	// MaxWorkers is the most streams a session may have; the server agrees
	// to at least MinWorkers.
	MaxWorkers = 100
	MinWorkers = 3
)

var (
	panelRestartNotice = []byte("\xffCSQTT_PANEL_RESTART_V1\x00\x91\x7d\x03\xa8")
	streamRepairPrefix = []byte("\xffCSQTT_STREAM_REPAIR_V1")
	streamAlivePrefix  = []byte("\xffCSQTT_STREAM_ALIVE_V1")
	pathEchoPrefix     = []byte("\xffCSQTT_PATH_ECHO_V1")

	// IdleKeepalive is what an idle stream sends every ten seconds.
	IdleKeepalive = []byte{0xff, 0xff, 0xff, 0xff}
)

// ConfigRequest is GETCONF: no device id and no revision — the password is
// the identity.
func ConfigRequest(localPort, password string, generation uint64, salt string, workerID, desiredCount int) string {
	desired := ""
	if desiredCount > 0 {
		desired = strconv.Itoa(desiredCount)
	}
	return fmt.Sprintf("GETCONF:%s|%s|%d|%s|%d|%s", localPort, password, generation, salt, workerID, desired)
}

// WorkersRequest asks the server how many streams it agrees to.
func WorkersRequest(password string, desiredCount int) string {
	return fmt.Sprintf("GETWORKERS:%s|%d", password, desiredCount)
}

// DisconnectRequest ends the requester's own epoch.
func DisconnectRequest(password, salt string) string {
	return "DISCONNECT:" + password + "|" + salt
}

// ConfigResponse is a parsed TUNCONF.
type ConfigResponse struct {
	TunnelIP string
	DNS      string
	Port     string
	Stream   string // "stream-v1"
	Workers  int    // the agreed stream count; 0 when the server did not say
	Raw      string
}

// DeniedError is a DENIED:<reason>.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return "csqtt25: denied: " + e.Reason }

// Fatal reports whether asking again with the same password is pointless.
func (e *DeniedError) Fatal() bool {
	switch e.Reason {
	case "wrong_password", "expired", "deactivated", "protocol_mismatch":
		return true
	}
	return false
}

// ErrNoConfig is NOCONF.
var ErrNoConfig = errors.New("csqtt25: the server has no configuration for this password")

// IsConfigResponse reports whether p answers a GETCONF.
func IsConfigResponse(p []byte) bool {
	return bytes.HasPrefix(p, []byte("TUNCONF:")) || bytes.Equal(p, []byte(NoConfigResponse)) || bytes.HasPrefix(p, []byte("DENIED:"))
}

// ParseConfigResponse parses the answer to a GETCONF.
func ParseConfigResponse(p []byte) (ConfigResponse, error) {
	s := string(p)
	if s == NoConfigResponse {
		return ConfigResponse{}, ErrNoConfig
	}
	if r, ok := strings.CutPrefix(s, "DENIED:"); ok {
		return ConfigResponse{}, &DeniedError{Reason: r}
	}
	rest, ok := strings.CutPrefix(s, "TUNCONF:")
	if !ok {
		return ConfigResponse{}, errors.New("csqtt25: not a GETCONF answer")
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 || parts[0] == "" {
		return ConfigResponse{}, errors.New("csqtt25: short TUNCONF")
	}
	c := ConfigResponse{TunnelIP: parts[0], DNS: parts[1], Raw: s}
	for i, part := range parts[2:] {
		switch {
		case strings.HasPrefix(part, "stream-"):
			c.Stream = part
		case strings.HasPrefix(part, "workers="):
			if n, err := strconv.Atoi(strings.TrimPrefix(part, "workers=")); err == nil {
				c.Workers = n
			}
		case i == 0:
			c.Port = part
		}
	}
	return c, nil
}

// ParseWorkers parses TUNWORKERS:<agreed>:<server limit> (limit 0 = none)
// and the older WORKERS:<n>.
func ParseWorkers(p []byte) (agreed, limit int, ok bool) {
	s := string(p)
	if r, found := strings.CutPrefix(s, "TUNWORKERS:"); found {
		a, l, _ := strings.Cut(r, ":")
		agreed, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil {
			return 0, 0, false
		}
		limit, _ := strconv.Atoi(strings.TrimSpace(l))
		return agreed, limit, true
	}
	if r, found := strings.CutPrefix(s, "WORKERS:"); found {
		n, err := strconv.Atoi(strings.TrimSpace(r))
		if err != nil {
			return 0, 0, false
		}
		return n, n, true
	}
	return 0, 0, false
}

// IsIdleKeepalive is the server's own rule for a keepalive.
func IsIdleKeepalive(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	if len(p) >= 4 && len(p) <= 9 && p[0] == 0xff {
		return true
	}
	for _, b := range p {
		if b != 0xff {
			return false
		}
	}
	return true
}

// IsControl reports whether a plaintext is a control message and must never
// reach the TUN.
func IsControl(p []byte) bool {
	if bytes.Equal(p, panelRestartNotice) {
		return true
	}
	for _, prefix := range [][]byte{
		[]byte("TUNCONF:"), []byte(NoConfigResponse), []byte("DENIED:"), []byte(ReadyOK), []byte(DisconnectedResponse),
		[]byte("ROUTING:"), []byte("TUNWORKERS:"), []byte("WORKERS:"),
		streamRepairPrefix, streamAlivePrefix, pathEchoPrefix,
	} {
		if bytes.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// ControlName names a control message for a log line, without its content.
func ControlName(p []byte) string {
	switch {
	case bytes.Equal(p, panelRestartNotice):
		return "PANEL_RESTART"
	case bytes.HasPrefix(p, streamRepairPrefix):
		return "STREAM_REPAIR"
	case bytes.HasPrefix(p, streamAlivePrefix):
		return "STREAM_ALIVE"
	case bytes.HasPrefix(p, pathEchoPrefix):
		return "PATH_ECHO"
	case IsIdleKeepalive(p):
		return "KEEPALIVE"
	}
	for _, name := range []string{"TUNCONF", "NOCONF", "DENIED", "READY_OK", "OK:disconnected", "ROUTING", "TUNWORKERS", "WORKERS"} {
		if bytes.HasPrefix(p, []byte(name)) {
			return name
		}
	}
	return ""
}
