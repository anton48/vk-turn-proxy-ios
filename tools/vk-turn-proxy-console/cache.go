// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
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

// A cached identity the previous run used in its last ten minutes loads as
// PENDING (pkg/proxy's credSaturationCooldown): its allocations may still hold
// seats at the relay, and a 486 benches the slot for eleven minutes. With the
// console's one reserve set every slot may be such a slot, and a restart then
// waits up to ten minutes for nothing (the stand, 2026-09-29). Whether the
// seats were freed is known here:
//   - the previous run ended CLEANLY (no state file left): every session was
//     torn down — a deallocate sent, and over TCP the connection closed — and
//     the relay frees a seat 1.0 s after a deallocate and at once on a TCP
//     close (measured, Sep 21 §269);
//   - it CRASHED over TCP: the kernel closed its connections, which frees the
//     seats as a close does (unless the network was down right then — a 486
//     is the pool's ordinary business);
//   - it crashed over UDP: nothing told the relay; the allocations live until
//     they expire — the pending state is right, and stays.

// trustCachedIdentities: the previous run's seats are free (see above).
func trustCachedIdentities(prev *stateDoc) bool {
	return prev == nil || prev.Transport == "tcp"
}

// forgetLastUse clears last_used_at in the console's credential cache (its
// own file, never the app's) and returns how many identities it touched. Every
// other field is kept as it is — a number as it was written: the file is the
// pool's format, and an int64 passed through a float64 would come back changed.
func forgetLastUse(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return 0
	}
	creds, _ := doc["creds"].([]any)
	n := 0
	for _, c := range creds {
		if m, ok := c.(map[string]any); ok {
			if v, ok := m["last_used_at"].(json.Number); ok && positive(v) {
				delete(m, "last_used_at")
				n++
			}
		}
	}
	if n == 0 {
		return 0
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return 0
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return 0
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0
	}
	return n
}

// positive: a JSON integer above zero.
func positive(v json.Number) bool {
	t, err := v.Int64()
	return err == nil && t > 0
}
