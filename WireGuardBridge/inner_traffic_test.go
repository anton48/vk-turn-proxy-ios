package main

// The inner traffic line's wiring in the bridge (pkg/proxy/innertraffic.go has
// the counter and its own tests): the profile's switch reaches the process on
// both start paths, the csqtt pumps show the counter every packet they move,
// and the native device is wrapped before wireguard-go gets it.

import (
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
)

// The csqtt path, end to end on the host: a packet up and a packet down, with
// the switch on in the config, are each counted once; with the switch absent
// the start turns the line off and nothing is counted.
func TestCsqttPumpsShowTheirPacketsToTheInnerTrafficLine(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		on          bool
	}{
		{"on", `,"inner_traffic_log":true`, true},
		{"absent", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The other state first: the start itself must set the one asked for.
			proxy.SetInnerTrafficLog(!tc.on)
			defer proxy.SetInnerTrafficLog(false)
			var mints atomic.Int32
			installFakePool(t, mintingFetch(&mints))
			fc := newFakeClient()
			installFakeDial(t, fc)
			installPairTun(t)
			csqttSeededSettle = 0

			h := startCsqtt(t, tc.extra)
			if _, _, on := proxy.InnerTrafficCounts(); on != tc.on {
				t.Fatalf("after the start the line is on=%v, the config asks for %v", on, tc.on)
			}
			if rc := csqttWaitReadyImpl(h, 3000*time.Millisecond); rc != 1 {
				t.Fatalf("not ready: %d", rc)
			}
			mine, theirs := socketPair(t)
			defer unix.Close(theirs)
			defer unix.Close(mine)
			if rc := csqttAttachImpl(h, mine); rc != 1 {
				t.Fatalf("attach: %d", rc)
			}
			up := ipv4Packet("up")
			if _, err := unix.Write(theirs, append([]byte{0, 0, 0, unix.AF_INET}, up...)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-fc.up:
			case <-time.After(2 * time.Second):
				t.Fatal("the packet did not cross TUN → client")
			}
			fc.down <- ipv4Packet("down")
			unix.SetNonblock(theirs, false)
			if err := unix.SetsockoptTimeval(theirs, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
				t.Fatal(err)
			}
			if n, err := unix.Read(theirs, make([]byte, 4096)); err != nil || n < 4 {
				t.Fatalf("the packet did not cross client → TUN: n=%d err=%v", n, err)
			}
			want := uint64(0)
			if tc.on {
				want = 1
			}
			if out, in, _ := proxy.InnerTrafficCounts(); out != want || in != want {
				t.Fatalf("counted %d out / %d in, want %d / %d", out, in, want, want)
			}
		})
	}
}

// Both configs carry the switch under one key, and a config without it is off.
func TestBothStartPathsReadTheInnerTrafficSwitch(t *testing.T) {
	var native ProxyConfig
	var cs csqttConfig
	if err := json.Unmarshal([]byte(`{"inner_traffic_log":true}`), &native); err != nil || !native.InnerTrafficLog {
		t.Fatalf("the native config did not read inner_traffic_log: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"inner_traffic_log":true}`), &cs); err != nil || !cs.InnerTrafficLog {
		t.Fatalf("the csqtt config did not read inner_traffic_log: %v", err)
	}
	native, cs = ProxyConfig{}, csqttConfig{}
	_ = json.Unmarshal([]byte(`{}`), &native)
	_ = json.Unmarshal([]byte(`{}`), &cs)
	if native.InnerTrafficLog || cs.InnerTrafficLog {
		t.Fatal("a config without the key must leave the line off")
	}
}

// The native path's wiring cannot be run on the host (it needs the whole
// WireGuard attach), so its three places are pinned in the source: the start
// applies the config's switch, the device is wrapped between its opening and
// wireguard-go's NewDevice, and the live export reaches the same switch.
func TestTheNativePathIsWiredToTheInnerTrafficLine(t *testing.T) {
	b, err := os.ReadFile("bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	within := func(from, to string) string {
		i := strings.Index(src, from)
		if i < 0 {
			t.Fatalf("bridge.go has no %q", from)
		}
		j := strings.Index(src[i:], to)
		if j < 0 {
			t.Fatalf("bridge.go has no %q behind %q", to, from)
		}
		return src[i : i+j]
	}
	if !strings.Contains(within("func wgStartVKBootstrap(", "\n}\n"), "proxy.SetInnerTrafficLog(pcfg.InnerTrafficLog)") {
		t.Error("the native start does not apply the config's inner_traffic_log")
	}
	if !strings.Contains(within("tunDev, err := wgOpenTun(dupFd)", "device.NewDevice(tunDev,"), "tunDev = proxy.WrapTUNForInner(tunDev)") {
		t.Error("the native device is not wrapped for the inner traffic line before wireguard-go gets it")
	}
	if !strings.Contains(within("//export wgSetInnerTrafficLog\n", "\n}\n"), "proxy.SetInnerTrafficLog(enabled != 0)") {
		t.Error("wgSetInnerTrafficLog does not reach the switch")
	}
}
