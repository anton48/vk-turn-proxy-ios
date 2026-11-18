package proxy

import "net"

// SeedCreds builds the credential the app's pre-bootstrap probe hands the
// pool as its seed (credPool.seedSlot): the relay the probe names (address)
// and, when the app passes them, EVERY relay VK returned with the credential
// (addresses) — address first, each once, an entry that is not host:port
// dropped.
//
// Until 2026-11-18 the seed named ONE relay: the probe's answer carried
// turn_address alone, and the pool learnt the others only from a disk twin of
// the same credential (seedSlot). On a cold cache — no file, a fresh install,
// a reset — the pool then held one slot with one relay, and a relay that
// answers TURN and does not forward left the bootstrap nothing to move to: a
// phone, four attempts on one address, the bootstrap's timeout.
//
// With no addresses the result is what it always was — Address alone,
// Addresses nil: a cached seed's twin still supplies them.
func SeedCreds(address, username, password string, addresses []string) *TURNCreds {
	c := &TURNCreds{Username: username, Password: password, Address: address}
	var named []string
	for _, a := range addresses {
		if _, _, err := net.SplitHostPort(a); err == nil {
			named = append(named, a)
		}
	}
	if len(named) > 0 {
		c.Addresses = dedupeAddrs(append([]string{address}, named...))
	}
	return c
}
