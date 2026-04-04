package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <os/log.h>

// Set GODEBUG=asyncpreemptoff=1 BEFORE Go runtime initializes.
// This prevents "fatal error: non-Go code disabled sigaltstack"
// on iOS Network Extensions where sigaltstack is disabled on some threads.
__attribute__((constructor))
static void disable_async_preempt(void) {
	setenv("GODEBUG", "asyncpreemptoff=1", 1);
}

// Logging callback type matching wireguard-apple convention
typedef void(*logger_fn_t)(int level, const char *msg);
static void callLogger(void *fn, int level, const char *msg) {
	((logger_fn_t)fn)(level, msg);
}

// Write Go log messages to os_log (visible in Console.app)
static void go_os_log(const char *msg) {
	os_log_t log = os_log_create("com.vkturnproxy.tunnel", "go");
	os_log(log, "%{public}s", msg);
}
*/
import "C"

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"github.com/cacggghp/vk-turn-proxy/pkg/turnbind"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// tunnelEntry holds a running tunnel's state.
type tunnelEntry struct {
	device *device.Device
	proxy  *proxy.Proxy
	bind   *turnbind.TURNBind
}

var (
	tunnels   = make(map[int32]*tunnelEntry)
	tunnelsMu sync.Mutex
	nextID    int32 = 1
)

// ProxyConfig is the JSON config passed from Swift.
type ProxyConfig struct {
	VKLink     string `json:"vk_link"`
	PeerAddr   string `json:"peer_addr"`
	TurnServer string `json:"turn_server,omitempty"`
	TurnPort   string `json:"turn_port,omitempty"`
	UseDTLS    bool   `json:"use_dtls"`
	UseUDP     bool   `json:"use_udp"`
	NumConns   int    `json:"num_conns,omitempty"`
}

//export wgTurnOnWithTURN
func wgTurnOnWithTURN(settings *C.char, tunFd C.int32_t, proxyConfigJSON *C.char) C.int32_t {
	goSettings := C.GoString(settings)
	goProxyJSON := C.GoString(proxyConfigJSON)

	var pcfg ProxyConfig
	if err := json.Unmarshal([]byte(goProxyJSON), &pcfg); err != nil {
		log.Printf("wgTurnOnWithTURN: invalid proxy config: %s", err)
		return -1
	}
	if pcfg.NumConns <= 0 {
		pcfg.NumConns = 1
	}

	// Create proxy
	p := proxy.NewProxy(proxy.Config{
		PeerAddr:   pcfg.PeerAddr,
		TurnServer: pcfg.TurnServer,
		TurnPort:   pcfg.TurnPort,
		VKLink:     pcfg.VKLink,
		UseDTLS:    pcfg.UseDTLS,
		UseUDP:     pcfg.UseUDP,
		NumConns:   pcfg.NumConns,
	})

	// Create TURN bind
	bind := turnbind.NewTURNBind(p)

	// Create TUN device from file descriptor
	dupFd, err := dupFD(int(tunFd))
	if err != nil {
		log.Printf("wgTurnOnWithTURN: dup fd failed: %s", err)
		return -2
	}
	tunFile := os.NewFile(uintptr(dupFd), "/dev/tun")
	tunDev, err := tun.CreateTUNFromFile(tunFile, 0)
	if err != nil {
		tunFile.Close()
		log.Printf("wgTurnOnWithTURN: CreateTUNFromFile failed: %s", err)
		return -5
	}

	// Create WireGuard device with our custom bind
	logger := device.NewLogger(device.LogLevelVerbose, "(wireguard-turn) ")
	dev := device.NewDevice(tunDev, bind, logger)

	// Apply UAPI configuration
	if err := dev.IpcSet(goSettings); err != nil {
		log.Printf("wgTurnOnWithTURN: IpcSet: %s", err)
		dev.Close()
		return -3
	}

	if err := dev.Up(); err != nil {
		log.Printf("wgTurnOnWithTURN: Up: %s", err)
		dev.Close()
		return -4
	}

	tunnelsMu.Lock()
	id := nextID
	nextID++
	tunnels[id] = &tunnelEntry{
		device: dev,
		proxy:  p,
		bind:   bind,
	}
	tunnelsMu.Unlock()

	log.Printf("wgTurnOnWithTURN: tunnel %d started", id)
	return C.int32_t(id)
}

//export wgTurnOff
func wgTurnOff(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	delete(tunnels, id)
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	entry.device.Close()
	log.Printf("wgTurnOff: tunnel %d stopped", id)
}

//export wgSetConfig
func wgSetConfig(tunnelHandle C.int32_t, settings *C.char) C.int64_t {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return -1
	}

	goSettings := C.GoString(settings)
	if err := entry.device.IpcSet(goSettings); err != nil {
		log.Printf("wgSetConfig: %s", err)
		return -2
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("")
	}

	settings, err := entry.device.IpcGet()
	if err != nil {
		return C.CString("")
	}
	return C.CString(settings)
}

//export wgGetTURNServerIP
func wgGetTURNServerIP(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("")
	}
	return C.CString(entry.proxy.TURNServerIP())
}

//export wgGetStats
func wgGetStats(tunnelHandle C.int32_t) *C.char {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return C.CString("{}")
	}

	stats := entry.proxy.GetStats()
	data, err := json.Marshal(stats)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(data))
}

//export wgPause
func wgPause(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	log.Printf("wgPause: pausing tunnel %d", id)
	entry.proxy.Pause()
}

//export wgResume
func wgResume(tunnelHandle C.int32_t) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	log.Printf("wgResume: resuming tunnel %d", id)
	entry.proxy.Resume()
}

//export wgSolveCaptcha
func wgSolveCaptcha(tunnelHandle C.int32_t, answer *C.char) {
	id := int32(tunnelHandle)
	tunnelsMu.Lock()
	entry, ok := tunnels[id]
	tunnelsMu.Unlock()

	if !ok {
		return
	}

	goAnswer := C.GoString(answer)
	log.Printf("wgSolveCaptcha: tunnel %d, answer length=%d", id, len(goAnswer))
	entry.proxy.SolveCaptcha(goAnswer)
}

//export wgVersion
func wgVersion() *C.char {
	return C.CString("0.1.0-turn")
}

//export wgSetLogger
func wgSetLogger(loggerFn unsafe.Pointer) {
	if loggerFn == nil {
		return
	}
	log.SetOutput(&clogWriter{fn: loggerFn})
}

type clogWriter struct {
	fn unsafe.Pointer
}

func (w *clogWriter) Write(p []byte) (int, error) {
	msg := C.CString(string(p))
	defer C.free(unsafe.Pointer(msg))
	C.callLogger(w.fn, 0, msg)
	return len(p), nil
}

func dupFD(fd int) (int, error) {
	return unix.Dup(fd)
}

// osLogWriter writes Go log output to os_log (visible in Console.app).
type osLogWriter struct{}

func (osLogWriter) Write(p []byte) (int, error) {
	msg := C.CString(strings.TrimRight(string(p), "\n"))
	defer C.free(unsafe.Pointer(msg))
	C.go_os_log(msg)
	return len(p), nil
}

func init() {
	// Belt-and-suspenders: also set via Go in case C constructor didn't run first
	os.Setenv("GODEBUG", "asyncpreemptoff=1")
	// Route all Go logs to os_log so they show in Console.app
	log.SetOutput(osLogWriter{})
	log.SetFlags(log.Ltime | log.Lmicroseconds)
}

func main() {}
