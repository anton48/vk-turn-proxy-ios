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
