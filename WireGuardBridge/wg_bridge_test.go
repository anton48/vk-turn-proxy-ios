//go:build ios

package main

// The native bridge's tunnelEntry.device: written by wgAttachWireGuard under
// tunnelsMu, read by wgTurnOff / wgSetConfig / wgGetConfig — bare, until the
// accessor and these checks existed (the review of 2026-09-06). And the
// window csqtt_bridge.go closed in build 364, one transport over: a stop
// between the attach's pre-check and its install left a WireGuard device on
// a stopped tunnel that nobody closes. The attach runs for REAL here —
// wireguard-go's Device over a socketpair "tun" and a plain UDP bind — so
// the ownership is exercised, not modelled.

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeWGTun is a tun.Device over one end of a socketpair: one read = one
// packet; the offset is honoured and nothing else is interpreted.
type fakeWGTun struct {
	f      *os.File
	events chan tun.Event
	once   sync.Once
	closed atomic.Bool
}

func (d *fakeWGTun) File() *os.File { return d.f }
func (d *fakeWGTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.f.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (d *fakeWGTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if _, err := d.f.Write(b[offset:]); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
func (d *fakeWGTun) MTU() (int, error)        { return 1280, nil }
func (d *fakeWGTun) Name() (string, error)    { return "fake-wg", nil }
func (d *fakeWGTun) Events() <-chan tun.Event { return d.events }
func (d *fakeWGTun) BatchSize() int           { return 1 }
func (d *fakeWGTun) Close() error {
	d.closed.Store(true)
	d.once.Do(func() { close(d.events) })
	return d.f.Close()
}

// installWGFakes swaps the attach's two seams: the tun over the dup'd fd
// becomes a fakeWGTun (recorded in `opened`), the bind a plain UDP bind.
func installWGFakes(t *testing.T) (opened *atomic.Pointer[fakeWGTun]) {
	t.Helper()
	opened = &atomic.Pointer[fakeWGTun]{}
	prevTun, prevBind := wgOpenTun, wgNewBind
	wgOpenTun = func(dupFd int) (tun.Device, error) {
		// The dup arrives NON-BLOCKING from the attach itself (production's
		// shape — wireguard-go's CreateTUNFromFile sets nothing); the seam
		// sets nothing either, so a blocking dup shows here: device.Close
		// waits for a read that never ends and the ownership test times out.
		d := &fakeWGTun{f: os.NewFile(uintptr(dupFd), "pair"), events: make(chan tun.Event, 4)}
		opened.Store(d)
		return d, nil
	}
	wgNewBind = func(*proxy.Proxy) conn.Bind { return conn.NewDefaultBind() }
	t.Cleanup(func() { wgOpenTun, wgNewBind = prevTun, prevBind })
	return opened
}

// registerWGEntry puts a proxy-less entry in the registry, as
// wgStartVKBootstrap would; TurnOff on it stops nothing but the device.
func registerWGEntry(t *testing.T) int32 {
	t.Helper()
	tunnelsMu.Lock()
	id := nextID
	nextID++
	tunnels[id] = &tunnelEntry{}
	tunnelsMu.Unlock()
	t.Cleanup(func() { wgTurnOffImpl(id) })
	return id
}

// A WireGuard config wireguard-go accepts; the key is a test pattern.
var testWGConfig = "private_key=" + strings.Repeat("01", 32) + "\n"

// A stop that lands between the attach's device coming up and its install:
// wgTurnOff removed the entry and read no device, so the attach must find
// the entry gone and close the device it built — the check-and-set under
// tunnelsMu against TurnOff's unregister-then-read. Sabotage seen red: the
// registration check dropped from the install (attach answers 1, the device
// stays open on a stopped tunnel).
func TestWGAttachBesideTheStopInstallsNoDevice(t *testing.T) {
	opened := installWGFakes(t)
	hold, atHook := make(chan struct{}), make(chan struct{})
	prevHook := wgAfterAttachUp
	wgAfterAttachUp = func() { close(atHook); <-hold }
	defer func() { wgAfterAttachUp = prevHook }()
	id := registerWGEntry(t)
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	defer unix.Close(mine)
	defer wgTurnOffImpl(id) // runs before the descriptor closes above (LIFO)

	rc := make(chan int32, 1)
	go func() { rc <- wgAttachWireGuardImpl(id, testWGConfig, mine) }()
	select {
	case <-atHook: // the device is up and not yet installed
	case <-time.After(5 * time.Second):
		t.Fatal("the attach never reached the hook")
	}
	wgTurnOffImpl(id) // unregisters, reads no device, returns
	t0 := time.Now()
	close(hold) // the attach goes on to its install
	select {
	case got := <-rc:
		if got != -7 {
			t.Fatalf("attach beside the stop answered %d, want -7 (stopped) — a device was installed on a stopped tunnel", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attach did not return — device.Close waits for a TUN reader that never wakes (a blocking dup?)")
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Fatalf("the -7 teardown took %s — the TUN reader did not wake on Close", took)
	}
	waitFor(t, "the attach to close the device it could not install", func() bool { return opened.Load().closed.Load() })
	if fdIsOpen(mine) == false {
		t.Fatal("the caller's descriptor was closed — the attach must only close its dup")
	}
}

// The other exports read the device only through deviceNow — under
// tunnelsMu, the lock the attach installs under. -race is the check, one
// goroutine per reader (a locked read in a goroutine orders its later bare
// reads; see csqtt_bridge_test.go). Probabilistic; the scan below is the
// deterministic guard.
func TestWGDeviceReadersDoNotRaceTheAttach(t *testing.T) {
	installWGFakes(t)
	id := registerWGEntry(t)
	mine, theirs := socketPair(t)
	defer unix.Close(theirs)
	defer unix.Close(mine)
	defer wgTurnOffImpl(id) // the device closes before its descriptor (LIFO)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for _, read := range []func(){
		func() { _ = wgGetConfigImpl(id) },
		func() { _ = wgSetConfigImpl(id, "") },
	} {
		readers.Add(1)
		go func(read func()) {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				read()
			}
		}(read)
	}
	time.Sleep(20 * time.Millisecond)
	if rc := wgAttachWireGuardImpl(id, testWGConfig, mine); rc != 1 {
		t.Fatalf("attach: %d", rc)
	}
	time.Sleep(30 * time.Millisecond)
	close(stop)
	readers.Wait()
	if wgGetConfigImpl(id) == "" {
		t.Fatal("the attached device answers no config")
	}
}

// Every access to tunnelEntry.device / .bind in bridge.go sits under
// tunnelsMu — the Lock precedes it in the same function with no Unlock
// between (a deferred Unlock keeps the section open to the function's
// end). Pinned by spelling, because -race sees a bare read only when it is
// unordered in its goroutine. Sabotage seen red: wgGetConfigImpl reading
// entry.device directly.
func TestWGDeviceFieldAccessesSitUnderTheLock(t *testing.T) {
	src, err := os.ReadFile("bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	field := regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\.(device|bind)\b`)
	funcLine := regexp.MustCompile(`^func (?:\([^)]*\) )?([A-Za-z0-9_]+)\(`)
	locked, deferred := false, false
	current := ""
	seen := map[string]int{}
	for i, line := range strings.Split(string(src), "\n") {
		if m := funcLine.FindStringSubmatch(line); m != nil {
			current, locked, deferred = m[1], false, false
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, "tunnelsMu.Lock()") {
			locked = true
		}
		if field.MatchString(trimmed) && !strings.Contains(trimmed, "func (e *tunnelEntry)") {
			if !locked {
				t.Errorf("bridge.go:%d touches the device/bind field outside tunnelsMu (in %s): %q", i+1, current, trimmed)
			}
			seen[current]++
		}
		if strings.Contains(trimmed, "tunnelsMu.Unlock()") {
			if strings.HasPrefix(trimmed, "defer ") {
				deferred = true
			} else if !deferred {
				locked = false
			}
		}
	}
	for _, fn := range []string{"deviceNow", "wgAttachWireGuardImpl", "wgTurnOffImpl"} {
		if seen[fn] == 0 {
			t.Errorf("no locked device/bind access found in %s — the scan is looking at the wrong tree", fn)
		}
	}
}
