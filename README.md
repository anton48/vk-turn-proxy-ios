# VK TURN Proxy — iOS

iOS client for [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) — a WireGuard VPN tunnel that routes traffic through VK's TURN infrastructure.

## Features

- Native iOS app with Network Extension (PacketTunnelProvider)
- Go-based WireGuard + DTLS/TURN proxy compiled as XCFramework
- Automatic VK Smart Captcha solving (SHA-256 Proof-of-Work)
- WebView fallback for captcha when PoW is rejected
- Self-healing tunnel: survives iOS sleep/wake, WiFi↔LTE handoff
- Watchdog-based dead tunnel detection (no reliance on iOS `sleep()`/`wake()` callbacks)
- Staggered reconnection to avoid TURN Allocation Quota errors
- Randomized identity (User-Agent + Russian names) per credential fetch

## Project Structure

```
VKTurnProxy/          # iOS app (SwiftUI) + PacketTunnel extension
WireGuardBridge/      # Go → C bridge, builds XCFramework via Makefile
pkg/proxy/            # Go proxy: DTLS+TURN tunnel, VK creds, PoW captcha solver
go.mod, go.sum        # Go module dependencies
```

## Building

### Prerequisites

- Xcode 15+
- Go 1.21+ (via Homebrew: `brew install go`)
- Apple Developer account with Network Extension entitlement

### Steps

1. Build the Go XCFramework:
   ```bash
   cd WireGuardBridge
   make xcframework
   ```

2. Open `VKTurnProxy/VKTurnProxy.xcodeproj` in Xcode.

3. Set your development team and bundle identifiers.

4. Build and run on a physical iOS device (simulator won't work for Network Extension).

## Configuration

In the app's Settings screen, configure:

- **WireGuard Config** — standard WireGuard config (Interface + Peer)
- **VK Link** — VK call invite link (e.g., `https://vk.com/call/join/...`)
- **Proxy Config** — JSON with `peer_addr`, connection count, DTLS/UDP options

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by [cacggghp](https://github.com/cacggghp).

## License

MIT
