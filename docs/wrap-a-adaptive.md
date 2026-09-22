# Adaptive SRTP-WRAP-A transport

This change affects **SRTP-WRAP-A only**. It does not change the WRAP-A wire
format, GETCONF request or server requirements. Existing profiles retain their
manual UDP/TCP setting. The new option is experimental and defaults to off.

## Automatic UDP / TCP

Enable **Automatic UDP / TCP** in the WRAP-A server editor. New sessions are
evaluated by the time required for the complete TURN allocation, DTLS handshake
and GETCONF exchange. With more than one connection, the initial pool samples
both transports concurrently. A 25% margin and an EWMA prevent normal relay
jitter from repeatedly changing the preference. Samples can be refreshed after
two minutes without interrupting a healthy session.

Connectivity failures put the affected transport on a 30-second cooldown.
TURN authentication failures, allocation quota errors, GETCONF `DENIED` and
`NOCONF` do not select another transport: those conditions are not repaired by
opening another socket. The whole bootstrap has a 30-second bound. Network path
changes clear all samples and ignore late results from the previous path.

The user's **Use UDP transport to TURN** value is the initial preference and
remains the exact behavior when automatic mode is disabled.

## Stability and diagnostics

A failed WRAP-A keepalive now cancels the connection so the existing session
supervisor can rebuild it. Previously that goroutine stopped silently while the
session could remain present until another timeout noticed it.

WRAP-A writes now identify their connection in the existing TX counters. This
does not change scheduling: the shared send queue already provides natural
work stealing because a connection blocked in `Write` cannot dequeue another
packet. The counters make per-connection throughput and last-transmit time
accurate for diagnostics and later measurement-driven tuning.

## Acceptance checks

Before enabling automatic mode by default, compare manual TCP, manual UDP and
automatic mode on the same physical iPhone, server and network. Record startup
time, goodput, loaded p95 latency, reconnect time, energy and memory. Include
blocked UDP, silent TURN, quota refusal, wrong password, Wi-Fi/cellular changes
and sleep/wake. Unit tests and an unsigned iOS build establish implementation
correctness, not carrier performance or resistance to traffic classification.
