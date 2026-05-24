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
    tunnelAddress    — e.g. "192.168.102.3/24"
    allowedIPs       — e.g. "0.0.0.0/0"
    vkLink           — https://vk.me/join/<token>
    peerAddress      — e.g. "1.2.3.4:51820" (the WG server, not the TURN)

Optional fields (delete or comment out the CONFIG key to omit them from
the link — leaving an empty string still gets sent through and overwrites
the importer's current value with empty):

    presharedKey     — WG preshared key (base64). Made Optional in iOS build
                       134 — WireGuard PSK is itself optional in the protocol
                       (deployments without PSK use the all-zeros key). If
                       absent from the link, the importer keeps its current
                       PSK setting. If the receiving device has never had a
                       PSK and the deployment doesn't use one, omit this key
                       entirely. The script rejects literal "REPLACE_ME" so
                       you can't accidentally embed the placeholder.
    dnsServers       — e.g. "1.1.1.1"; if absent, importer keeps its current value
    numConnections   — int 1..50; if absent, importer keeps its current value
                       (default 30 in the iOS app)
    useDTLS          — bool. Made Optional in iOS build 129 (UI toggle had
                       been removed in build 127). Default true on the iOS
                       side — omit unless you specifically need to force
                       the no-DTLS direct-mode for debugging.
    useWrap          — bool. Made Optional in iOS build 129 (UI toggle had
                       been removed in build 115). WRAP is largely deprecated
                       since VK changed shape policy 2026-05-18; only set if
                       your peerAddress points at a -wrap-enabled server and
                       you have a matching wrapKeyHex below. Default false
                       on the iOS side.
    wrapKeyHex       — 64 hex chars matching server's -wrap-key. Only meaningful
                       when useWrap=true. Made Optional in iOS build 129.
    useSrtp          — bool, added 2026-05-20 (iOS build 115+). True means
                       client uses the DTLS+SRTP transport that bypasses VK's
                       per-allocation shape policy — server must run with the
                       -srtp flag (anton48/vk-turn-proxy add-server-srtp-layer
                       branch), typically on a separate port from the legacy
                       DTLS listener. If absent, importer keeps current value
                       (default false). Note: useSrtp=true overrides useDTLS
                       in the iOS dispatcher (SRTP path wins).
    useUDP           — bool, added 2026-05-22 (iOS build 128). False (default)
                       = TCP-control transport from client to TURN relay,
                       which bypasses VK's per-cred allocation-rate throttle
                       (introduced 2026-05-18). True = UDP-control, only useful
                       if your network blocks/throttles TCP to the relay and
                       you'd rather take VK's allocation-rate hit. If absent,
                       importer keeps current value (default false / TCP).

Compat note: links generated against iOS build 128 or earlier MUST include
useDTLS, useWrap, and wrapKeyHex (iOS Codable rejects the link otherwise).
Build 129+ accepts their absence. Similarly, builds 133 or earlier require
presharedKey; build 134+ accepts its absence. quick_link.py keeps these
fields in CONFIG with safe defaults so links work with both eras — only
delete them from CONFIG if you know all importers are on the corresponding
build (129+ for useDTLS/useWrap/wrapKeyHex, 134+ for presharedKey).

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
    "tunnelAddress":  "192.168.102.3/24",
    "allowedIPs":     "0.0.0.0/0",
    "vkLink":         "REPLACE_ME",         # https://vk.me/join/...
    "peerAddress":    "REPLACE_ME",         # ip:port of the WG server

    # ----- optional (delete keys to omit them from the link) -----
    # presharedKey was required before iOS build 134. Kept in CONFIG with
    # the REPLACE_ME placeholder so links generated against builds 133 and
    # earlier still include a non-empty value (those builds reject missing
    # presharedKey). If the receiving devices are all on 134+ AND the
    # deployment doesn't use a WG preshared key, delete the line entirely.
    # validate() rejects literal "REPLACE_ME" so accidental retention of
    # the placeholder fails loudly.
    "presharedKey":   "REPLACE_ME",
    "dnsServers":     "1.1.1.1",
    "numConnections": 30,
    # useDTLS / useWrap / wrapKeyHex were required before iOS build 129
    # (they corresponded to UI toggles that have since been removed —
    # useDTLS in build 127, useWrap in build 115). Kept in CONFIG with
    # safe defaults so links work against both build-128-and-earlier
    # (which require these fields) and build-129+ (which accept their
    # absence). Delete them only if you know every importer is on 129+.
    "useDTLS":        True,                 # default; legacy DTLS+WG fallback
    "useWrap":        False,                # WRAP largely defunct since 2026-05-18
    "wrapKeyHex":     "",                   # 64 hex chars, only if useWrap=True
    # useSrtp / useUDP: see docstring at top for semantics. Both default
    # false (safe for users on the legacy DTLS+WG path). Set useSrtp=true
    # only if the peerAddress points at a -srtp-enabled server. Set
    # useUDP=true only if your network requires UDP-control transport.
    "useSrtp":        False,
    "useUDP":         False,
}

REQUIRED = (
    "privateKey", "peerPublicKey",
    "tunnelAddress", "allowedIPs",
    "vkLink", "peerAddress",
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
        if val in (None, "", "REPLACE_ME"):
            missing.append(key)
    if missing:
        raise SystemExit(
            f"ERROR: missing or placeholder required fields: {', '.join(missing)}\n"
            f"Edit the CONFIG dict at the top of quick_link.py (or your input "
            f"JSON) and rerun."
        )
    # Reject literal "REPLACE_ME" left in any optional field — would
    # otherwise silently embed the placeholder string into the link and
    # overwrite the importer's UserDefaults with garbage. The most likely
    # offender is presharedKey, which moved from required to optional in
    # build 134 but still defaults to "REPLACE_ME" in CONFIG so links
    # generated for pre-134 importers (where presharedKey is required)
    # keep working.
    placeholders = [k for k, v in settings.items() if v == "REPLACE_ME"]
    if placeholders:
        raise SystemExit(
            f"ERROR: optional field(s) still set to placeholder REPLACE_ME: "
            f"{', '.join(placeholders)}\n"
            f"Either set them to real values or delete the line from CONFIG "
            f"(optional fields can be omitted entirely — the importer will "
            f"keep its current setting for the corresponding key)."
        )
    # wrapKeyHex sanity-check kept only when useWrap is explicitly true —
    # both fields are now optional, but if the admin set useWrap=true they
    # almost certainly want the key validated too.
    if settings.get("useWrap") and len(settings.get("wrapKeyHex", "") or "") != 64:
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
