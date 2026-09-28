// SPDX-License-Identifier: MIT

// Package hygiene holds the guards over what this repository PUBLISHES: nothing
// tracked here names a real host. The tests read the tree the way a reader of
// the public repository would — every tracked text file — and fail on the first
// address that belongs to a stand, a server, a relay or a device.
package hygiene
