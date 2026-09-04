// SPDX-License-Identifier: MIT

package csqtt

import (
	"encoding/binary"
	"errors"
	"testing"
)

// The GETCONF line is compared against the server's own contract strings
// (reference_csqtt_protocol_v3.md §4).
func TestConfigRequestMatchesServerContract(t *testing.T) {
	got := ConfigRequest("9000", "device", "password", 7, "salt", 4, 0, WireRevision)
	if want := "GETCONF:9000|device|password|7|salt|4||CSQTT-WIRE-3"; got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	got = ConfigRequest("9000", "device", "password", 7, "salt", 4, 36, WireRevision)
	if want := "GETCONF:9000|device|password|7|salt|4|36|CSQTT-WIRE-3"; got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	if got := DisconnectRequest("dev", "salt"); got != "DISCONNECT:dev|salt" {
		t.Fatalf("disconnect %q", got)
	}
}

func TestParseConfigResponse(t *testing.T) {
	c, err := ParseConfigResponse([]byte("TUNCONF:10.66.66.2:1.1.1.1"))
	if err != nil || c.TunnelIP != "10.66.66.2" || c.DNS != "1.1.1.1" || c.FramesData() {
		t.Fatalf("legacy TUNCONF: %+v %v", c, err)
	}
	c, err = ParseConfigResponse([]byte("TUNCONF:10.66.67.3:77.88.8.8,77.88.8.1:9000:stream-v2"))
	if err != nil || c.TunnelIP != "10.66.67.3" || c.DNS != "77.88.8.8,77.88.8.1" || c.LocalPort != "9000" || !c.FramesData() {
		t.Fatalf("v2 TUNCONF: %+v %v", c, err)
	}
	c, err = ParseConfigResponse([]byte("TUNCONF:10.66.67.3:1.1.1.1:9000:stream-v1"))
	if err != nil || c.FramesData() {
		t.Fatalf("stream-v1 must not frame data: %+v %v", c, err)
	}
	if _, err := ParseConfigResponse([]byte("NOCONF")); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("NOCONF: %v", err)
	}
	var denied *DeniedError
	if _, err := ParseConfigResponse([]byte("DENIED:wrong_password")); !errors.As(err, &denied) || denied.Reason != "wrong_password" {
		t.Fatalf("DENIED: %v", err)
	}
	if _, err := ParseConfigResponse([]byte("READY_OK")); err == nil {
		t.Fatal("READY_OK is not a config response")
	}
	if _, err := ParseConfigResponse([]byte("TUNCONF:")); err == nil {
		t.Fatal("empty TUNCONF accepted")
	}
}

func TestControlClassifiers(t *testing.T) {
	for _, p := range [][]byte{
		[]byte("TUNCONF:10.66.67.3:1.1.1.1"), []byte("NOCONF"), []byte("DENIED:expired"),
		[]byte("READY_OK"), []byte("OK:disconnected"), PanelRestartNotice,
		StreamRepairPrefix, StreamAlivePrefix,
	} {
		if !IsControl(p) {
			t.Fatalf("%q must be control", p)
		}
	}
	if IsControl([]byte{0x45, 0, 0, 20}) {
		t.Fatal("an IP packet classified as control")
	}
	if !IsConfigResponse([]byte("DENIED:expired")) || IsConfigResponse([]byte("READY_OK")) || IsConfigResponse([]byte{0x45, 0, 0, 20}) {
		t.Fatal("IsConfigResponse boundary")
	}
	if !IsPanelRestart(PanelRestartNotice) || IsPanelRestart([]byte("CSQTT_PANEL_RESTART_V1")) {
		t.Fatal("panel restart must be an exact match")
	}
	m := append([]byte(nil), PanelRestartNotice...)
	m[1] ^= 1
	if IsPanelRestart(m) {
		t.Fatal("a modified notice matched")
	}
}

// Mirrors the server's own keepalive classifier vectors.
func TestIsIdleKeepalive(t *testing.T) {
	for _, yes := range [][]byte{
		IdleKeepalive, {0xff, 0x11, 0x22, 0x33}, {0xff, 1, 2, 3, 4, 5, 6, 7, 8}, {0xff},
	} {
		if !IsIdleKeepalive(yes) {
			t.Fatalf("%x must be a keepalive", yes)
		}
	}
	for _, no := range [][]byte{
		nil, {0xff, 1, 2}, {0x45, 0, 0, 20}, {0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	} {
		if IsIdleKeepalive(no) {
			t.Fatalf("%x must not be a keepalive", no)
		}
	}
}

func TestParseStreamCommands(t *testing.T) {
	payload := append([]byte(nil), StreamRepairPrefix...)
	payload = binary.BigEndian.AppendUint64(payload, 9)
	payload = binary.BigEndian.AppendUint16(payload, 36)
	payload = append(payload, 2)
	payload = binary.BigEndian.AppendUint16(payload, 14)
	payload = binary.BigEndian.AppendUint16(payload, 28)

	cmd, ok := ParseStreamRepair(payload)
	if !ok || cmd.Sequence != 9 || cmd.DesiredCount != 36 || len(cmd.WorkerIDs) != 2 || cmd.WorkerIDs[0] != 14 || cmd.WorkerIDs[1] != 28 {
		t.Fatalf("repair: ok=%v %+v", ok, cmd)
	}
	if _, ok := ParseStreamAlive(payload); ok {
		t.Fatal("a REPAIR parsed as ALIVE")
	}
	bad := append([]byte(nil), payload...)
	bad[len(StreamRepairPrefix)+10] = 0 // count 0 with ids present
	if _, ok := ParseStreamRepair(bad); ok {
		t.Fatal("count/length disagreement accepted")
	}
	bad = append([]byte(nil), payload...)
	binary.BigEndian.PutUint16(bad[len(bad)-2:], 37) // id above desired
	if _, ok := ParseStreamRepair(bad); ok {
		t.Fatal("worker id above desired accepted")
	}
	bad = append([]byte(nil), payload...)
	binary.BigEndian.PutUint64(bad[len(StreamRepairPrefix):], 0) // sequence 0
	if _, ok := ParseStreamRepair(bad); ok {
		t.Fatal("sequence 0 accepted")
	}
}
