// SPDX-License-Identifier: MIT

// tools/h3get — download a URL over HTTP/3 (QUIC) and over HTTP/1.1/2 (TCP)
// and report goodput and time to first byte. Its purpose is one question:
// how does QUIC fare through a tunnel that reorders and duplicates UDP.
//
// Separate module on purpose: quic-go stays out of the app's go.mod.
//
//	go build -o /tmp/h3get . && /tmp/h3get -url https://speed.cloudflare.com/__down?bytes=20000000 -h3 -h2
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	url := flag.String("url", "https://speed.cloudflare.com/__down?bytes=20000000", "URL to download")
	useH3 := flag.Bool("h3", true, "run the HTTP/3 download")
	useH2 := flag.Bool("h2", true, "run the HTTP/1.1/2 download over TCP")
	timeout := flag.Duration("timeout", 90*time.Second, "per-download timeout")
	repeat := flag.Int("n", 1, "repeat each download this many times")
	label := flag.String("label", "", "label for the output lines")
	flag.Parse()
	log.SetFlags(log.Ltime)

	for i := 0; i < *repeat; i++ {
		if *useH3 {
			report(*label, "h3", fetchH3(*url, *timeout))
		}
		if *useH2 {
			report(*label, "tcp", fetchTCP(*url, *timeout))
		}
	}
}

type result struct {
	bytes   int64
	ttfb    time.Duration
	total   time.Duration
	proto   string
	err     error
	remote  string
	details string
}

func report(label, kind string, r result) {
	if r.err != nil {
		fmt.Printf("%-14s %-4s ERROR after %s: %v\n", label, kind, r.total.Round(time.Millisecond), r.err)
		return
	}
	mbit := float64(r.bytes*8) / r.total.Seconds() / 1e6
	fmt.Printf("%-14s %-4s %-8s %8.1f MB in %6.2fs = %6.1f Mbit/s  ttfb %4d ms  %s %s\n",
		label, kind, r.proto, float64(r.bytes)/1e6, r.total.Seconds(), mbit, r.ttfb.Milliseconds(), r.remote, r.details)
}

func fetchH3(url string, timeout time.Duration) result {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second},
	}
	defer tr.Close()
	return fetch(&http.Client{Transport: tr}, url, timeout)
}

func fetchTCP(url string, timeout time.Duration) result {
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext:       (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
	}
	defer tr.CloseIdleConnections()
	return fetch(&http.Client{Transport: tr}, url, timeout)
}

func fetch(client *http.Client, url string, timeout time.Duration) result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t0 := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result{err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return result{err: err, total: time.Since(t0)}
	}
	defer resp.Body.Close()
	ttfb := time.Since(t0)
	n, err := io.Copy(io.Discard, resp.Body)
	total := time.Since(t0)
	if err != nil {
		return result{bytes: n, ttfb: ttfb, total: total, proto: resp.Proto, err: fmt.Errorf("body: %w", err)}
	}
	return result{bytes: n, ttfb: ttfb, total: total, proto: resp.Proto, details: fmt.Sprintf("status %d", resp.StatusCode)}
}

var _ = os.Exit
