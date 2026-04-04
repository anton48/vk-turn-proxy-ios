#ifndef WIREGUARD_TURN_H
#define WIREGUARD_TURN_H

#include <stdint.h>

/// Start a WireGuard tunnel with TURN proxy.
/// @param settings UAPI configuration string (key=value\n format)
/// @param tunFd File descriptor of the TUN device
/// @param proxyConfigJSON JSON string with proxy configuration
/// @return Tunnel handle (>0 on success), negative on error:
///   -1: invalid proxy config JSON
///   -2: failed to create TUN device
///   -3: failed to apply WireGuard config
///   -4: failed to bring up device
int32_t wgTurnOnWithTURN(const char *settings, int32_t tunFd, const char *proxyConfigJSON);

/// Stop a tunnel.
/// @param tunnelHandle Handle returned by wgTurnOnWithTURN
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

/// Get tunnel statistics as JSON.
/// @return JSON string (caller must free), empty "{}" if tunnel not found
const char *wgGetStats(int32_t tunnelHandle);

/// Pause all proxy connections (call from sleep()).
void wgPause(int32_t tunnelHandle);

/// Resume proxy connections (call from wake()).
void wgResume(int32_t tunnelHandle);

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

/// Get library version.
/// @return Version string
const char *wgVersion(void);

/// Set logging callback.
typedef void (*logger_fn_t)(int level, const char *msg);
void wgSetLogger(logger_fn_t fn);

#endif /* WIREGUARD_TURN_H */
