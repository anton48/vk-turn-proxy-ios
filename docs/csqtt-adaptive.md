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

## Adaptive connection scheduling

Enable **Adaptive connection scheduling** in the CSQTT server editor. Each
worker gets a bounded asynchronous write queue (32 packets and 64 KiB,
including its in-flight write). A blocked relay no longer blocks the TUN
writer from handing packets to other relays. Queue-full fallback happens
only before acceptance; a failed write is never replayed speculatively.
Packets are copied into owned buffers and tagged with the allocation epoch;
queued packets from an old allocation cannot leak into its replacement.

Chunk scheduling weights local write time per KiB (EWMA), queued bytes and
recent write errors. Slow workers receive up to eight times shorter chunks,
with at least one packet per turn for recovery. The original maximum chunk
size is unchanged, avoiding larger bursts into the relay's policer. Small,
medium and bulk classes retain separate cursors. Stale write measurements
expire after 30 seconds. Worker stats expose queue bytes and write cost;
QueueDrops counts outbound queue saturation, stale packets and write errors.

These are **local backpressure signals**, not end-to-end RTT, delivery rate
or a packet-loss estimate. An uncongested UDP socket can look fast even when
the remote relay drops traffic. Existing liveness detection still handles
unresponsive workers. No extra measurement packets or new wire messages are
introduced. On a congested pool, bounded queues intentionally drop packets
instead of allowing unlimited memory growth. Async acceptance does not mean
the server has received the packet.

## Device acceptance checks

Before making this default, compare manual UDP, manual TCP and automatic mode
on the same iPhone/server/network: startup time, upload/download goodput,
loaded p95 latency, reconnect time, memory and energy. Include blocked UDP,
silent TURN, Wi-Fi/cellular transitions and sleep/wake. Tests with a local
fake server establish policy/lifecycle correctness, not real-carrier speed or
resistance to traffic filtering.
