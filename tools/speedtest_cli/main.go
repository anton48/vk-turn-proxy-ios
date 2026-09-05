// SPDX-License-Identifier: MIT

// tools/speedtest_cli — the app's own speed-test engine (pkg/speedtest over the
// vendored speedtest-go fork) as a console command, so a run from the FreeBSD
// stand is the SAME instrument as the phone's in-app test: HTTP/1.1 (threads =
// TCP flows), no adaptive upload controller, research window with a discarded
// warm-up, confirmed bytes over the measured window. The stock speedtest-go CLI
// is a different instrument (HTTP/2 multiplexes its workers onto few
// connections), which is why its upload through an N-allocation tunnel cannot
// be compared with the app's.
//
//	go build -o /root/speedtest_cli ./tools/speedtest_cli
//	/root/speedtest_cli -server 51387 -threads 32 -duration 30
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cacggghp/vk-turn-proxy/pkg/speedtest"
)

func main() {
	server := flag.String("server", "", "Ookla server id to pin (empty = automatic, chosen from the APPARENT IP)")
	threads := flag.Int("threads", 32, "TCP flows per direction (1..32)")
	direction := flag.String("direction", "both", "download | upload | both")
	duration := flag.Int("duration", 30, "measured window in seconds (research mode discards a warm-up before it)")
	research := flag.Bool("research", true, "research mode: warm-up discarded, fixed window, raw figure primary")
	debug := flag.Bool("debug", false, "engine debug logging (worker counts, URLs)")
	jsonOut := flag.String("json", "", "also write the final snapshot as JSON to this file")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := speedtest.Config{ServerID: *server, Threads: *threads, Direction: *direction, DurationSec: *duration, Research: *research, Debug: *debug}
	if err := speedtest.Start(cfg); err != nil {
		log.Fatalf("start: %v", err)
	}
	log.Printf("started: server=%q threads=%d direction=%s duration=%ds research=%v", *server, *threads, *direction, *duration, *research)
	last := ""
	var snap speedtest.Progress
	for {
		snap = speedtest.Snapshot()
		if s := snap.State + "/" + snap.Stage; s != last {
			log.Printf("state %s · %s", s, snap.Mode)
			last = s
		}
		if snap.State == "done" || snap.State == "error" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if snap.State == "error" {
		log.Fatalf("error: %s", snap.Err)
	}
	log.Printf("server [%s] %s · ookla sees %s (%s) · ping %.1f ms · %s", snap.ServerID, snap.ServerStr, snap.OoklaSeesIP, snap.OoklaSeesISP, snap.PingMs, snap.Engine)
	phase("DOWNLOAD", snap.Down, snap.Threads)
	phase("UPLOAD", snap.Up, snap.Threads)
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(snap, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			log.Printf("json: %v", err)
		}
	}
	b, _ := json.Marshal(snap)
	fmt.Println(string(b))
}

// phase prints one direction the way the app logs it: the raw figure (confirmed
// bytes over the measured window) first, the engine's estimator second.
func phase(name string, p *speedtest.Phase, threads int) {
	if p == nil {
		return
	}
	log.Printf("%s raw=%.1f engine=%.1f Mbit/s actual=%.1fs window=%.1fs warmup=%.1fs bytes=%.1fMB threads=%d",
		name, p.RawMbps, p.LibraryMbps, p.ActualSec, p.WindowSec, p.WarmupSec, float64(p.Bytes)/1e6, threads)
}
