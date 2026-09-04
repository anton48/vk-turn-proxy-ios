// SPDX-License-Identifier: MIT

package csqtt

// The control plane: short plaintext strings exchanged inside the obfuscation
// before and beside the IP traffic. Nothing here is length-framed; a datagram
// is one message, classified by its prefix.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Wire revisions. WireRevision requests CQF1 data frames (stream-v2); the
// legacy one is accepted by the server and yields an unframed data plane,
// which is a useful knob while debugging the framing itself.
const (
	WireRevision       = "CSQTT-WIRE-3"
	LegacyWireRevision = "CSQTT-WIRE-2"

	// MaxWorkers is the server's ceiling on worker_id and desired_count.
	MaxWorkers = 126

	// ReadyRequest is sent once after TUNCONF; ReadyOK is the reply. The
	// server also sets the tunnel up on the first data packet, so this is
	// a courtesy that makes the log readable, not a gate.
	ReadyRequest = "READY"
	ReadyOK      = "READY_OK"

	NoConfigResponse     = "NOCONF"
	DisconnectedResponse = "OK:disconnected"
)

// Server-originated control prefixes.
var (
	PanelRestartNotice = []byte("\xffCSQTT_PANEL_RESTART_V1\x00\x91\x7d\x03\xa8")
	StreamRepairPrefix = []byte("\xffCSQTT_STREAM_REPAIR_V1")
	StreamAlivePrefix  = []byte("\xffCSQTT_STREAM_ALIVE_V1")

	// IdleKeepalive is a payload the server classifies as a keepalive and
	// never forwards to the TUN: all bytes 0xff.
	IdleKeepalive = bytes.Repeat([]byte{0xff}, 16)
)

// ConfigRequest builds the GETCONF line. localPort is only echoed back by
// the server; desiredCount 0 leaves that field empty (the server then does
// not run stream repair for this device).
func ConfigRequest(localPort, deviceID, password string, generation uint64, salt string, workerID, desiredCount int, revision string) string {
	desired := ""
	if desiredCount > 0 {
		desired = strconv.Itoa(desiredCount)
	}
	return fmt.Sprintf("GETCONF:%s|%s|%s|%d|%s|%d|%s|%s",
		localPort, deviceID, password, generation, salt, workerID, desired, revision)
}

// DisconnectRequest asks the server to drop every session of this
// (device, salt) pair; the reply is DisconnectedResponse.
func DisconnectRequest(deviceID, salt string) string {
	return "DISCONNECT:" + deviceID + "|" + salt
}

// ConfigResponse is a parsed TUNCONF. StreamRevision is "stream-v2" when the
// server frames its TCP downlink and expects framed uplink; "stream-v1" or
// empty means an unframed data plane.
type ConfigResponse struct {
	TunnelIP       string
	DNS            string // one address, or two comma-separated
	LocalPort      string // our own localPort echoed back; unused
	StreamRevision string
	Raw            string
}

// FramesData reports whether the data plane carries CQF1 frames.
func (c ConfigResponse) FramesData() bool {
	return c.StreamRevision == "stream-v2"
}

// DeniedError is a DENIED:<reason> reply. Every reason is fatal for this
// (password, device) — retrying the same request cannot succeed.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return "csqtt: denied: " + e.Reason }

// ErrNoConfig is the NOCONF reply: the password is accepted but the server
// has no address for this device (its pool is exhausted).
var ErrNoConfig = errors.New("csqtt: server has no configuration for this device")

// ParseConfigResponse interprets a reply to GETCONF.
func ParseConfigResponse(payload []byte) (ConfigResponse, error) {
	s := string(payload)
	if s == NoConfigResponse {
		return ConfigResponse{}, ErrNoConfig
	}
	if reason, ok := strings.CutPrefix(s, "DENIED:"); ok {
		return ConfigResponse{}, &DeniedError{Reason: reason}
	}
	body, ok := strings.CutPrefix(s, "TUNCONF:")
	if !ok {
		return ConfigResponse{}, fmt.Errorf("csqtt: unexpected GETCONF reply %q", truncate(s))
	}
	parts := strings.Split(body, ":")
	if len(parts) < 2 || parts[0] == "" {
		return ConfigResponse{}, fmt.Errorf("csqtt: malformed TUNCONF %q", truncate(s))
	}
	c := ConfigResponse{TunnelIP: parts[0], DNS: parts[1], Raw: s}
	if len(parts) > 2 {
		c.LocalPort = parts[2]
	}
	if len(parts) > 3 {
		c.StreamRevision = parts[3]
	}
	return c, nil
}

// IsConfigResponse is what the GETCONF wait accepts; everything else
// arriving meanwhile is ignored (a stray data packet, READY_OK from an
// earlier incarnation).
func IsConfigResponse(p []byte) bool {
	return bytes.HasPrefix(p, []byte("TUNCONF:")) ||
		bytes.Equal(p, []byte(NoConfigResponse)) ||
		bytes.HasPrefix(p, []byte("DENIED:"))
}

// IsControl reports whether an inbound plaintext is a control message that
// must never be written to the TUN.
func IsControl(p []byte) bool {
	if IsPanelRestart(p) {
		return true
	}
	return IsConfigResponse(p) ||
		bytes.Equal(p, []byte(ReadyOK)) ||
		bytes.Equal(p, []byte(DisconnectedResponse)) ||
		bytes.HasPrefix(p, StreamRepairPrefix) ||
		bytes.HasPrefix(p, StreamAlivePrefix)
}

// IsPanelRestart is an exact match: the server is about to restart.
func IsPanelRestart(p []byte) bool { return bytes.Equal(p, PanelRestartNotice) }

// IsIdleKeepalive mirrors the server's own classifier, so the client can
// drop the same things the server would.
func IsIdleKeepalive(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	if p[0] != 0xff {
		return false
	}
	if len(p) >= 4 && len(p) <= 9 {
		return true
	}
	for _, b := range p {
		if b != 0xff {
			return false
		}
	}
	return true
}

// StreamCommand is a REPAIR (restart these workers) or ALIVE (these workers
// are seen) notice. Sequence is the server's monotonic counter for dedup.
type StreamCommand struct {
	Sequence     uint64
	DesiredCount uint16
	WorkerIDs    []uint16
}

// ParseStreamRepair decodes a REPAIR notice; ok is false for anything else
// or for a malformed one.
func ParseStreamRepair(p []byte) (StreamCommand, bool) { return parseStream(p, StreamRepairPrefix) }

// ParseStreamAlive decodes an ALIVE notice.
func ParseStreamAlive(p []byte) (StreamCommand, bool) { return parseStream(p, StreamAlivePrefix) }

func parseStream(p, prefix []byte) (StreamCommand, bool) {
	rest, ok := bytes.CutPrefix(p, prefix)
	if !ok || len(rest) < 11 {
		return StreamCommand{}, false
	}
	seq := binary.BigEndian.Uint64(rest[0:8])
	desired := binary.BigEndian.Uint16(rest[8:10])
	count := int(rest[10])
	ids := rest[11:]
	if seq == 0 || desired == 0 || desired > MaxWorkers || len(ids) != count*2 || count == 0 {
		return StreamCommand{}, false
	}
	cmd := StreamCommand{Sequence: seq, DesiredCount: desired, WorkerIDs: make([]uint16, 0, count)}
	for i := 0; i < count; i++ {
		id := binary.BigEndian.Uint16(ids[i*2 : i*2+2])
		if id == 0 || id > desired {
			return StreamCommand{}, false
		}
		cmd.WorkerIDs = append(cmd.WorkerIDs, id)
	}
	return cmd, true
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
