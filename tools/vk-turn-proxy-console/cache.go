// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"net"
	"os"
)

// relayHostsFromCache reads the relay hosts out of the console's credential
// cache (the proxy's creds-pool.json shape: {"creds":[{"address":"host:port"}]})
// — only the addresses: they are pinned before the first dial.
func relayHostsFromCache(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cache struct {
		Creds []struct {
			Address string `json:"address"`
		} `json:"creds"`
	}
	if err := json.Unmarshal(b, &cache); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var hosts []string
	for _, c := range cache.Creds {
		h, _, err := net.SplitHostPort(c.Address)
		if err != nil || seen[h] || net.ParseIP(h) == nil {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}

// 🚫 The console never writes this file. A slot the previous run used in its
// last ten minutes loads as PENDING — the pool's own rule, the app's: the
// relay may still hold its allocations — and the restart takes the slots that
// are ready, mints into the empty ones, or waits. (For a day the console
// cleared those stamps after a clean end or a crash over TCP. The premise
// held only for the identities in use at the end, and only when the close or
// the deallocate had reached the relay — which nothing here can know: the
// identities a path change had orphaned, a stop with the network gone, and
// over UDP every unanswered deallocate. The user's decision, 2026-09-30: as
// in the app. A stand that restarts often removes the cache file instead.)
