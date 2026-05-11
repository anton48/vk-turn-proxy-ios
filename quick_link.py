#!/usr/bin/env python3
"""quick_link.py — generate a 1-Click vkturnproxy:// connection-link URL.

The output is a single `vkturnproxy://import?data=<base64>` string ready
to AirDrop / message / paste onto an iPhone running VK Turn Proxy. Tapping
the link launches the app, shows a confirm alert with the deployment
fingerprint, and applies the settings on confirm. The same payload also
works pasted bare on the iPhone clipboard (Settings → Backup & Restore →
"Import from Connection Link").

Two ways to feed it:

    1. Edit the CONFIG dict below in-place with your deployment values
       and run with no args:

           python3 quick_link.py

    2. Pass a JSON file (same shape as CONFIG) as argv[1] — useful when
       managing multiple deployments via files in a private repo or
       password manager:

           python3 quick_link.py my-deployment.json

Required fields (the link is rejected by the iOS parser if any are
missing or empty):

    privateKey       — WG client private key (base64)
    peerPublicKey    — WG server public key  (base64)
    presharedKey     — WG preshared key      (base64)
    tunnelAddress    — e.g. "192.168.102.3/24"
    allowedIPs       — e.g. "0.0.0.0/0"
    vkLink           — https://vk.me/join/<token>
    peerAddress      — e.g. "1.2.3.4:51820" (the WG server, not the TURN)
    useDTLS          — true unless you specifically run a no-DTLS server
    useWrap          — true if your server runs the WRAP layer (recommended)
    wrapKeyHex       — 64 hex chars matching server's -wrap-key (or "" if useWrap=false)

Optional fields (omitted from the link if left empty / commented out):

    dnsServers       — e.g. "1.1.1.1"; if absent, importer keeps its current value
    numConnections   — int 1..50; if absent, importer keeps its current value
                       (default 30 in the iOS app)

What this DOES NOT include and never should:

    creds-pool.json    — TURN credentials are device-specific (PoW is keyed
                          to the WebView fingerprint at solve time). They
                          rebuild automatically on first connect.
    vk_profile.json    — captured browser fingerprint, also device-specific.

If you need to migrate a complete app state (settings + cached creds +
captured profile) between two of YOUR devices, use the Full Backup
Export/Import flow in the app instead.
"""

import base64
import json
import sys

# Edit these to your deployment values, then run the script.
CONFIG = {
    # ----- required -----
    "privateKey":     "REPLACE_ME",
    "peerPublicKey":  "REPLACE_ME",
    "presharedKey":   "REPLACE_ME",
    "tunnelAddress":  "192.168.102.3/24",
    "allowedIPs":     "0.0.0.0/0",
    "vkLink":         "REPLACE_ME",         # https://vk.me/join/...
    "peerAddress":    "REPLACE_ME",         # ip:port of the WG server
    "useDTLS":        True,
    "useWrap":        True,
    "wrapKeyHex":     "REPLACE_ME",         # 64 hex chars

    # ----- optional (delete keys to omit them from the link) -----
    "dnsServers":     "1.1.1.1",
    "numConnections": 30,
}

REQUIRED = (
    "privateKey", "peerPublicKey", "presharedKey",
    "tunnelAddress", "allowedIPs",
    "vkLink", "peerAddress",
    "useDTLS", "useWrap", "wrapKeyHex",
)

# Schema version must match BackupManager.supportedConfigVersion in the
# iOS app. Bump on the Swift side first, then mirror here.
SCHEMA_VERSION = 1


def load_config(argv):
    if len(argv) > 1:
        path = argv[1]
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("settings", data)
    return CONFIG


def validate(settings):
    missing = []
    for key in REQUIRED:
        val = settings.get(key)
        # useDTLS / useWrap can be False; explicit None / "" / "REPLACE_ME"
        # is the failure case for everything else.
        if key in ("useDTLS", "useWrap"):
            if val is None:
                missing.append(key)
        else:
            if val in (None, "", "REPLACE_ME"):
                missing.append(key)
    if missing:
        raise SystemExit(
            f"ERROR: missing or placeholder required fields: {', '.join(missing)}\n"
            f"Edit the CONFIG dict at the top of quick_link.py (or your input "
            f"JSON) and rerun."
        )
    if settings.get("useWrap") and len(settings.get("wrapKeyHex", "")) != 64:
        raise SystemExit(
            "ERROR: useWrap=True but wrapKeyHex is not 64 hex chars (32 bytes). "
            "Generate one with: openssl rand -hex 32"
        )


def build_link(settings):
    payload = {
        "version": SCHEMA_VERSION,
        "type": "connection",
        "settings": settings,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    # url-safe base64 without padding — iOS parser tolerates either
    # variant, this just avoids "=" / "+" / "/" needing escaping in URLs.
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"vkturnproxy://import?data={b64}"


def main():
    settings = load_config(sys.argv)
    validate(settings)
    print(build_link(settings))


if __name__ == "__main__":
    main()
