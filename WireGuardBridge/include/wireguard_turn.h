#ifndef WIREGUARD_TURN_H
#define WIREGUARD_TURN_H

#include <stdint.h>

/// Start a WireGuard tunnel with TURN proxy (legacy single-call flow).
/// Retained for backward compatibility; new callers should use the split
/// flow (wgStartVKBootstrap + wgWaitBootstrapReady + wgAttachWireGuard) so
/// Swift can defer setTunnelNetworkSettings until VK bootstrap is ready.
/// @param settings UAPI configuration string (key=value\n format)
/// @param tunFd File descriptor of the TUN device
/// @param proxyConfigJSON JSON string with proxy configuration
/// @return Tunnel handle (>0 on success), negative on error:
///   -1: invalid proxy config JSON
///   -2: failed to create TUN device
///   -3: failed to apply WireGuard config
///   -4: failed to bring up device
int32_t wgTurnOnWithTURN(const char *settings, int32_t tunFd, const char *proxyConfigJSON);

/// Start VK bootstrap (API call, TURN allocation, DTLS handshake) in a
/// background goroutine. Does NOT create a TUN device yet. Returns a tunnel
/// handle that can be passed to wgWaitBootstrapReady / wgGetTURNServerIP /
/// wgAttachWireGuard.
/// @param proxyConfigJSON JSON string with proxy configuration
/// @return Tunnel handle (>0), or -1 on invalid config JSON
int32_t wgStartVKBootstrap(const char *proxyConfigJSON);

/// Wait for VK bootstrap to report ready (first conn has a live DTLS+TURN
/// session). Blocks up to timeoutMs. Safe to call multiple times on the
/// same handle; the internal signal is replayed so subsequent callers see
/// the same outcome.
/// @param tunnelHandle Handle from wgStartVKBootstrap
/// @param timeoutMs Deadline for readiness in milliseconds (e.g. 120000)
/// @return  1 on ready, 0 on timeout, -1 on fatal error / unknown handle
int32_t wgWaitBootstrapReady(int32_t tunnelHandle, int32_t timeoutMs);

/// Attach a WireGuard device to a tunnel whose proxy is already running.
/// Creates the TUN from tunFd, wires it via TURNBind to the proxy, applies
/// the UAPI config, and brings the device up. Call this AFTER
/// setTunnelNetworkSettings has returned and you have the real tunFd.
/// @param tunnelHandle Handle from wgStartVKBootstrap
/// @param wgConfigSettings UAPI configuration string
/// @param tunFd File descriptor of the TUN device
/// @return  1 on success, negative on error:
///   -1: unknown handle
///   -2: device already attached
///   -3: failed to duplicate tunFd
///   -4: failed to create TUN device
///   -5: failed to apply WireGuard config
///   -6: failed to bring up device
int32_t wgAttachWireGuard(int32_t tunnelHandle, const char *wgConfigSettings, int32_t tunFd);

/// Stop a tunnel. Accepts handles from either wgTurnOnWithTURN or
/// wgStartVKBootstrap; it tears down a WG device if one was attached and
/// stops the underlying proxy in either case.
/// @param tunnelHandle Handle returned by wgTurnOnWithTURN or wgStartVKBootstrap
void wgTurnOff(int32_t tunnelHandle);

/// Update WireGuard configuration.
/// @return 0 on success, negative on error
int64_t wgSetConfig(int32_t tunnelHandle, const char *settings);

/// Get current WireGuard configuration (UAPI format).
/// @return Configuration string (caller must free)
const char *wgGetConfig(int32_t tunnelHandle);

/// Get the TURN server IP discovered after connecting.
/// @return IP address string (caller must free), empty if not yet connected
const char *wgGetTURNServerIP(int32_t tunnelHandle);

/// WRAP-A (SRTP-WRAP-A mode): block up to timeoutMs for amurcanov's server to
/// mint our WireGuard config via GETCONF, then return it as JSON:
///   {"private_key_hex","peer_public_key_hex","address","dns","mtu",
///    "keepalive_sec","uapi"}
/// "uapi" is ready to pass to wgAttachWireGuard; address/dns/mtu feed the
/// NEPacketTunnelNetworkSettings. Call AFTER wgWaitBootstrapReady returns 1
/// when use_wrap_a is set. Returns "" (caller must free) on timeout/error or
/// when the tunnel is not in WRAP-A mode.
/// @return JSON string (caller must free)
const char *wgWaitWrapAProvision(int32_t tunnelHandle, int32_t timeoutMs);

/// Get tunnel statistics as JSON.
/// @return JSON string (caller must free), empty "{}" if tunnel not found
const char *wgGetStats(int32_t tunnelHandle);

/// Pause all proxy connections (call from sleep()).
void wgPause(int32_t tunnelHandle);

/// Resume proxy connections (call from wake()).
void wgResume(int32_t tunnelHandle);

/// Run a fast-path health check on the tunnel (call from wake()).
/// If any pion permission/binding errors have accumulated, forces an
/// immediate reconnect so the user doesn't hit a silently-degraded tunnel
/// right after unlocking the phone.
void wgWakeHealthCheck(int32_t tunnelHandle);

/// Emit one pathstats log line on demand. Called by Swift's NWPathMonitor
/// pathUpdateHandler so transient interfaces (e.g. cellular briefly
/// visited during a wifi-cellular-wifi handover) appear in the pathstats
/// stream — the periodic 60s ticker can miss sub-minute transitions.
/// @param label Free-form short string appended to "pathstats <label>"
///              in the log line; usually the new path description.
void wgLogPathSnapshot(int32_t tunnelHandle, const char *label);

/// Pre-emptive saturation marking on iOS network-path change. Called from
/// Swift's NWPathMonitor pathUpdateHandler after dedup. For each pool
/// slot with active>0 OR lastUsedAt within ~10 min, marks the slot
/// VK-saturated immediately instead of waiting for the next allocate
/// attempt to hit 486. Cheap, no-op for slots that aren't in use.
/// See Proxy.OnPathChange / credPool.MarkInUseSlotsForPathChange.
void wgPathChanged(int32_t tunnelHandle);

/// Pause-only path event handler for iOS satisfied events with iface=other
/// (recursive-routing fallback through our own TUN — typically observed
/// during the gap between physical interface changes). Extends the
/// pause-acquire window so conns don't grab fresh slots during this
/// misleading "recovery" state. Does NOT trigger smart-pause re-marking.
/// See Proxy.OnPathTransition / credPool.ExtendPauseAcquireForTransition.
void wgPathInTransition(int32_t tunnelHandle);

/// Provide captcha answer to unblock pending credential fetch.
void wgSolveCaptcha(int32_t tunnelHandle, const char *answer);

/// Refresh captcha URL by making a fresh VK API request.
/// Call this right before showing WebView to ensure the URL is not stale.
/// @return Fresh captcha redirect_uri (caller must free), empty string on failure
const char *wgRefreshCaptchaURL(int32_t tunnelHandle);

/// Set the path to the shared log file (App Group container).
/// Go log output will be appended to this file in addition to os_log.
void wgSetLogFilePath(const char *path);

/// Set timezone offset in seconds (e.g. 10800 for UTC+3).
/// Go runtime on iOS has no tzdata, so this aligns Go log timestamps with local time.
void wgSetTimezoneOffset(int offsetSeconds);

/// Set the cookie ("VKAuth") cred-path state for this process. Call BEFORE
/// wgProbeVKCreds (main app) or wgStartVKBootstrap (extension) when the user
/// has enabled VKAuth: read the harvested logged-in cookie from the shared
/// Keychain and pass it here. The cookie is passed out-of-band (NOT in the
/// ProxyConfig JSON) so it never persists in the VPN providerConfiguration.
/// @param enabled 1 = cookie path ONLY (no anonymous fallback); 0 = anonymous
/// @param cookie  Raw Cookie header ("remixsid=…; p=…"); "" when disabling
/// @param links_json JSON array of call links — the cookie pool spreads conns
///        across each call's relays (~10 per relay). "" / "[]" = none.
void wgSetVKCookieAuth(int32_t enabled, const char *cookie, const char *links_json);

/// Set the force-legacy-captcha diagnostic flag (Settings › Advanced ›
/// Diagnostics) for THIS process. Call BEFORE wgProbeVKCreds in the main app.
/// The extension does not need it — it gets the same value through
/// ProxyConfig.force_legacy_captcha.
///
/// Separate entry point because the flag is process-global and the app and the
/// extension are different processes: before build 213 only the extension
/// honoured it, so the pre-bootstrap probe still used the captcha-free path and
/// the setting looked like it worked only sometimes.
/// @param enabled 1 = skip the captcha-free VK Calls path; 0 = normal
void wgSetForceLegacyCaptcha(int32_t enabled);

/// Force the 1s memstats cadence (Settings > Advanced > Diagnostics) in THIS
/// process, taking effect on a tunnel that is already connected.
///
/// The same value arrives in ProxyConfig.memstats_fast_ticks at the next start;
/// this entry point exists because the case worth supporting is deciding
/// mid-session that the next few minutes deserve 1s resolution, and applying
/// that through a reconnect would re-ramp 30 connections over ~107s and record
/// the ramp instead of the thing being measured.
///
/// Only the extension runs the memstats loop, so unlike wgSetForceLegacyCaptcha
/// there is nothing for the main app to call.
/// @param enabled 1 = 1s ticks; 0 = the normal 10s cadence
void wgSetMemstatsFastTicks(int32_t enabled);

// Uplink chunking K, applied live (no reconnect). See bridge.go.
void wgSetUplinkChunkK(int32_t k);

/// Returns the current cookie ("VKAuth") fatal-auth message, or "" if none.
/// The extension polls this after bootstrap (cookie mode only) — a non-empty
/// value means the saved cookie was rejected/expired in the background, so the
/// extension stops the tunnel with a clear message. Caller must free().
const char *wgGetAuthError(void);

/// Probe VK credentials in the main-app process before startVPNTunnel,
/// to pre-solve any captcha while the main app still has full network
/// access (Step 4's deferred-tunnel-settings architecture cuts off
/// main-app network the moment startVPNTunnel runs, leaving the WebView
/// captcha flow no path to VK).
/// @param linkID VK call invite link ID (last path component of vk_link)
/// @param vkHostIPsJSON Hostname→[]IP map (JSON), pre-resolved by main app
/// @param savedSID Captcha SID from previous round, "" on first call
/// @param savedKey success_token from user's WebView solve, "" on first
/// @param savedToken1 step1 access_token from previous round, "" on first
/// @param savedClientID VK client_id pinned for retry (must match savedToken1)
/// @param savedTs captcha_ts from previous round, 0 on first
/// @param savedAttempt captcha_attempt from previous round, 0 on first
/// @return JSON string (caller must free()):
///   {"status":"ok",       "turn_address":"...","turn_username":"...",
///                         "turn_password":"..."}
///   {"status":"captcha",  "captcha_url":"...","sid":"...","ts":...,
///                         "attempt":...,"token1":"...","client_id":"...",
///                         "is_rate_limit":false}
///   {"status":"error",    "message":"..."}
const char *wgProbeVKCreds(const char *linkID, const char *vkHostIPsJSON,
                           const char *savedSID, const char *savedKey,
                           const char *savedToken1, const char *savedClientID,
                           double savedTs, double savedAttempt);

/// Get library version.
/// @return Version string
const char *wgVersion(void);

/// Set logging callback.
typedef void (*logger_fn_t)(int level, const char *msg);
void wgSetLogger(logger_fn_t fn);

#endif /* WIREGUARD_TURN_H */
