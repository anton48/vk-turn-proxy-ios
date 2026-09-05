// SPDX-License-Identifier: MIT

// tools/udpreorder — a UDP probe that measures what iperf3 cannot: TRUE loss
// (by the set of sequence numbers that arrived, not by gaps), duplicates, and
// the REORDERING a path introduces, as a distribution of how far and how LATE
// each out-of-order datagram arrived. The lateness is what a jitter buffer or
// a reassembler must absorb; the extent in positions is what QUIC's loss
// detection sees (kPacketThreshold = 3).
//
//	receiver:  udpreorder -recv 10.66.67.1:5300 [-json out.json]
//	sender:    udpreorder -send 10.66.67.1:5300 -b 5M -l 1200 -t 15
//
// Every datagram carries: magic, run id, sequence, planned total, send time.
// The sender finishes with a burst of FIN datagrams; the receiver reports
// when it sees a FIN and nothing more arrives for 2 s, or on -idle timeout.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	hdrLen  = 4 + 4 + 8 + 8 + 8
	magic   = 0x55445230 // "UDR0"
	finSeq  = math.MaxUint64
	finRuns = 8
)

func main() {
	recv := flag.String("recv", "", "receiver: listen on ip:port")
	send := flag.String("send", "", "sender: destination ip:port")
	rate := flag.String("b", "5M", "sender: bit rate (e.g. 500K, 5M, 20M)")
	size := flag.Int("l", 1200, "sender: datagram payload size in bytes")
	dur := flag.Duration("t", 15*time.Second, "sender: duration")
	idle := flag.Duration("idle", 2*time.Second, "receiver: report after this much silence following a FIN")
	maxWait := flag.Duration("max-wait", 120*time.Second, "receiver: give up waiting for a run after this long")
	jsonOut := flag.String("json", "", "receiver: also write the report as JSON to this file")
	label := flag.String("label", "", "receiver: label for the report")
	swapEvery := flag.Int("swap-every", 0, "sender SELF-TEST: send every Nth pair swapped (k+1 before k) so the receiver must report a known reorder")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	switch {
	case *recv != "":
		runReceiver(*recv, *idle, *maxWait, *jsonOut, *label)
	case *send != "":
		runSender(*send, parseRate(*rate), *size, *dur, *swapEvery)
	default:
		fmt.Fprintln(os.Stderr, "one of -recv or -send is required")
		os.Exit(64)
	}
}

func parseRate(s string) float64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "G"):
		mult, s = 1e9, s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		mult, s = 1e6, s[:len(s)-1]
	case strings.HasSuffix(s, "K"):
		mult, s = 1e3, s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 {
		log.Fatalf("bad rate %q", s)
	}
	return v * mult
}

// ─── sender ───────────────────────────────────────────────────────────────

func runSender(dst string, bps float64, size int, dur time.Duration, swapEvery int) {
	if size < hdrLen {
		size = hdrLen
	}
	conn, err := net.Dial("udp4", dst)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	interval := time.Duration(float64(size*8) / bps * 1e9)
	total := uint64(dur / interval)
	if total == 0 {
		total = 1
	}
	run := uint32(time.Now().UnixNano())
	log.Printf("send %d × %d B to %s at %.2f Mbit/s (interval %s, %s)", total, size, dst, bps/1e6, interval, dur)
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], magic)
	binary.BigEndian.PutUint32(buf[4:8], run)
	binary.BigEndian.PutUint64(buf[16:24], total)
	for i := hdrLen; i < size; i++ {
		buf[i] = byte(i)
	}
	start := time.Now()
	next := start
	sent := uint64(0)
	order := make([]uint64, 0, total)
	for seq := uint64(0); seq < total; seq++ {
		order = append(order, seq)
	}
	if swapEvery > 0 {
		for i := 0; i+1 < len(order); i += swapEvery {
			order[i], order[i+1] = order[i+1], order[i]
		}
	}
	for _, seq := range order {
		now := time.Now()
		if now.Before(next) {
			time.Sleep(next.Sub(now))
			now = time.Now()
		}
		next = next.Add(interval)
		binary.BigEndian.PutUint64(buf[8:16], seq)
		binary.BigEndian.PutUint64(buf[24:32], uint64(now.UnixNano()))
		if _, err := conn.Write(buf); err != nil {
			log.Printf("write: %v", err)
			continue
		}
		sent++
	}
	elapsed := time.Since(start)
	binary.BigEndian.PutUint64(buf[8:16], finSeq)
	for i := 0; i < finRuns; i++ {
		binary.BigEndian.PutUint64(buf[24:32], uint64(time.Now().UnixNano()))
		_, _ = conn.Write(buf[:hdrLen])
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("done: sent %d/%d in %s (%.2f Mbit/s offered)", sent, total, elapsed.Round(time.Millisecond),
		float64(sent*uint64(size)*8)/elapsed.Seconds()/1e6)
}

// ─── receiver ─────────────────────────────────────────────────────────────

type report struct {
	Label        string  `json:"label"`
	Run          uint32  `json:"run"`
	Planned      uint64  `json:"planned"`
	Received     uint64  `json:"received"` // distinct sequence numbers
	Duplicates   uint64  `json:"duplicates"`
	Lost         uint64  `json:"lost"` // planned − distinct
	LostPct      float64 `json:"lost_pct"`
	OutOfOrder   uint64  `json:"out_of_order"` // arrived with a higher sequence already seen
	OutOfOrderPc float64 `json:"out_of_order_pct"`
	Seconds      float64 `json:"seconds"`
	RateMbit     float64 `json:"rate_mbit"`
	// Reorder extent in positions (RFC 4737-style: maxSeq − seq at arrival),
	// over out-of-order datagrams only.
	ExtentP50 float64 `json:"extent_p50"`
	ExtentP90 float64 `json:"extent_p90"`
	ExtentP99 float64 `json:"extent_p99"`
	ExtentMax uint64  `json:"extent_max"`
	// Share of ALL received datagrams that arrived after ≥3 higher ones —
	// what QUIC's packet-threshold loss detection would have declared lost.
	QUICThreshold3Pct float64 `json:"quic_threshold3_pct"`
	// Lateness in ms: time since the first HIGHER-numbered datagram arrived,
	// i.e. how long a buffer had to hold the gap open for this one.
	LateP50   float64 `json:"late_ms_p50"`
	LateP90   float64 `json:"late_ms_p90"`
	LateP99   float64 `json:"late_ms_p99"`
	LateMax   float64 `json:"late_ms_max"`
	Late20Pct float64 `json:"late_gt20ms_pct_of_all"` // of ALL received
	Late40Pct float64 `json:"late_gt40ms_pct_of_all"`
	Late80Pct float64 `json:"late_gt80ms_pct_of_all"`
	// Inter-arrival jitter (RFC 3550-style running estimate) at the end, ms.
	JitterMs float64 `json:"jitter_ms"`
}

func runReceiver(listen string, idle, maxWait time.Duration, jsonOut, label string) {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(4 << 20)
	log.Printf("listening on %s", conn.LocalAddr())

	var (
		run                           uint32
		planned                       uint64
		seen                          []bool
		pendingSince                  []int64 // unix nanos when the gap for seq opened; 0 = never
		maxSeq                        = int64(-1)
		received                      uint64
		dups                          uint64
		ooo                           uint64
		extents                       []uint64
		lates                         []float64
		late20, late40, late80, quic3 uint64
		first, last                   time.Time
		gotFIN                        bool
		jitter                        float64
		prevTransit                   int64
		haveTransit                   bool
	)
	buf := make([]byte, 65536)
	deadline := time.Now().Add(maxWait)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		now := time.Now()
		if err != nil {
			if gotFIN && now.Sub(last) >= idle {
				break
			}
			if !gotFIN && received > 0 && now.Sub(last) >= 10*time.Second {
				log.Printf("no FIN and 10 s of silence — reporting what arrived")
				break
			}
			if now.After(deadline) {
				log.Printf("max-wait reached")
				break
			}
			continue
		}
		if n < hdrLen || binary.BigEndian.Uint32(buf[0:4]) != magic {
			continue
		}
		r := binary.BigEndian.Uint32(buf[4:8])
		seq := binary.BigEndian.Uint64(buf[8:16])
		total := binary.BigEndian.Uint64(buf[16:24])
		sendNs := int64(binary.BigEndian.Uint64(buf[24:32]))
		if run == 0 {
			run, planned = r, total
			seen = make([]bool, planned)
			pendingSince = make([]int64, planned)
			log.Printf("run %08x: %d datagrams planned", run, planned)
		}
		if r != run {
			continue // a stale run's tail
		}
		if seq == finSeq {
			if !gotFIN {
				log.Printf("FIN seen; waiting %s of silence", idle)
			}
			gotFIN = true
			last = now
			continue
		}
		if seq >= planned {
			continue
		}
		last = now
		if first.IsZero() {
			first = now
		}
		// RFC 3550 jitter on send/arrival transit (clocks unsynchronised; only differences matter).
		transit := now.UnixNano() - sendNs
		if haveTransit {
			d := float64(transit-prevTransit) / 1e6
			if d < 0 {
				d = -d
			}
			jitter += (d - jitter) / 16
		}
		prevTransit, haveTransit = transit, true

		if seen[seq] {
			dups++
			continue
		}
		seen[seq] = true
		received++
		s := int64(seq)
		if s > maxSeq {
			// Every sequence skipped between maxSeq and s is now a gap that opened at `now`.
			for k := maxSeq + 1; k < s; k++ {
				if pendingSince[k] == 0 {
					pendingSince[k] = now.UnixNano()
				}
			}
			maxSeq = s
			continue
		}
		// Out of order: a higher sequence was already here.
		ooo++
		extent := uint64(maxSeq - s)
		extents = append(extents, extent)
		if extent >= 3 {
			quic3++
		}
		lateMs := float64(now.UnixNano()-pendingSince[seq]) / 1e6
		lates = append(lates, lateMs)
		if lateMs > 20 {
			late20++
		}
		if lateMs > 40 {
			late40++
		}
		if lateMs > 80 {
			late80++
		}
	}

	rep := report{Label: label, Run: run, Planned: planned, Received: received, Duplicates: dups}
	if planned > received {
		rep.Lost = planned - received
	}
	if planned > 0 {
		rep.LostPct = 100 * float64(rep.Lost) / float64(planned)
	}
	rep.OutOfOrder = ooo
	if received > 0 {
		rep.OutOfOrderPc = 100 * float64(ooo) / float64(received)
		rep.QUICThreshold3Pct = 100 * float64(quic3) / float64(received)
		rep.Late20Pct = 100 * float64(late20) / float64(received)
		rep.Late40Pct = 100 * float64(late40) / float64(received)
		rep.Late80Pct = 100 * float64(late80) / float64(received)
	}
	if !first.IsZero() {
		rep.Seconds = last.Sub(first).Seconds()
	}
	if rep.Seconds > 0 {
		rep.RateMbit = float64(received) * float64(hdrLen) * 8 / rep.Seconds / 1e6 // header-only lower bound; payload size unknown to the receiver
	}
	if len(extents) > 0 {
		sort.Slice(extents, func(i, j int) bool { return extents[i] < extents[j] })
		rep.ExtentP50 = float64(extents[len(extents)*50/100])
		rep.ExtentP90 = float64(extents[len(extents)*90/100])
		rep.ExtentP99 = float64(extents[min(len(extents)*99/100, len(extents)-1)])
		rep.ExtentMax = extents[len(extents)-1]
	}
	if len(lates) > 0 {
		sort.Float64s(lates)
		rep.LateP50 = lates[len(lates)*50/100]
		rep.LateP90 = lates[len(lates)*90/100]
		rep.LateP99 = lates[min(len(lates)*99/100, len(lates)-1)]
		rep.LateMax = lates[len(lates)-1]
	}
	rep.JitterMs = jitter

	fmt.Printf("%-20s planned=%d received=%d lost=%d (%.3f%%) dups=%d | ooo=%d (%.1f%%) extent p50/p90/p99/max=%.0f/%.0f/%.0f/%d quic3=%.1f%% | late ms p50/p90/p99/max=%.1f/%.1f/%.1f/%.1f >20/>40/>80ms=%.1f/%.1f/%.1f%% | jitter=%.1fms %.1fs\n",
		label, rep.Planned, rep.Received, rep.Lost, rep.LostPct, rep.Duplicates, rep.OutOfOrder, rep.OutOfOrderPc,
		rep.ExtentP50, rep.ExtentP90, rep.ExtentP99, rep.ExtentMax, rep.QUICThreshold3Pct,
		rep.LateP50, rep.LateP90, rep.LateP99, rep.LateMax, rep.Late20Pct, rep.Late40Pct, rep.Late80Pct, rep.JitterMs, rep.Seconds)
	if jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(jsonOut, b, 0o644); err != nil {
			log.Printf("json: %v", err)
		}
	}
}
