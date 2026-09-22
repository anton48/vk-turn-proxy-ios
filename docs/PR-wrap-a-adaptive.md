# PR: Adaptive UDP/TCP selection and recovery for SRTP-WRAP-A

## Title

Add opt-in adaptive UDP/TCP selection for SRTP-WRAP-A

## Description

Adds an optional **Automatic UDP / TCP** setting to SRTP-WRAP-A profiles.
New sessions compare the complete TURN + DTLS + GETCONF startup rather than a
socket dial alone. Connectivity failures temporarily select the other
transport, while quota, authentication and GETCONF refusals keep their existing
error handling. Network changes discard samples from the previous path.

The setting defaults to off. Manual UDP/TCP behavior, the WRAP-A wire format
and server compatibility are unchanged. Healthy sessions are not interrupted
for measurement.

The same change also makes a failed WRAP-A keepalive restart its session and
adds the connection index to existing TX accounting. This makes recovery and
per-connection diagnostics consistent with the other transports.

Tests cover initial exploration, hysteresis, cooldown, path reset, stale
results and refusal classification. Go race tests, Swift checks, the iOS bridge
build and an unsigned application build pass. Physical-device performance and
energy measurements are still required before considering a default-on change.

## Branch

`codex/wrap-a-adaptive`

The branch is based directly on upstream commit
`6c41641dd6fc200a568ef565cf9d202dc4ccf907`; it does not include the CSQTT
commits prepared separately.
