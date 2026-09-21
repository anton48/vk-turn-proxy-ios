# Adaptive CSQTT transport

These options affect **CSQTT only**, not the other VPN backends. Existing
profiles keep their manual UDP/TCP choice. No server or wire-format changes
are required. The features are opt-in until tested on physical iPhones.

## Automatic UDP / TCP

Enable **Automatic UDP / TCP** in the server editor. Turn it off to return
to the profile's original manual setting. The option survives profile save,
backup and restore; old backups default to off.

New sessions start with UDP. A connectivity failure penalizes that transport
for 30 seconds; a subsequent attempt can use TCP. Allocation and GETCONF share
an eight-second startup budget. Credential acquisition and the existing
credential-pool cooldowns remain outside that budget. TURN authentication and
quota refusals remain credential-pool errors, not reasons to immediately open
another allocation. Existing restart backoff is retained.

When workers naturally start, the policy samples the other available transport.
It compares GETCONF completion latency, including retransmissions, and requires
a 25% improvement to change preference. Samples older than two minutes can be
refreshed on subsequent session starts. Healthy sessions are not interrupted
to benchmark; this is **not** a continuous throughput competition or a promise
to select the fastest transport under sustained load. Path changes reset the
policy; results from an old network cannot update the new network's policy.

Worker stats include the selected transport. A silent server, including a
wrong password, can still prevent both transports from connecting. Switching
transport cannot bypass a server refusal or the provider's allocation quota.

## Device acceptance checks

Before making this default, compare manual UDP, manual TCP and automatic mode
on the same iPhone/server/network: startup time, upload/download goodput,
loaded p95 latency, reconnect time, memory and energy. Include blocked UDP,
silent TURN, Wi-Fi/cellular transitions and sleep/wake. Tests with a local
fake server establish policy/lifecycle correctness, not real-carrier speed or
resistance to traffic filtering.
