#!/usr/bin/env python3
"""quick_link.py — generate a 1-Click vkturnproxy:// connection-link URL.

The output is a single `vkturnproxy://import?data=<base64>` string ready
to AirDrop / message / paste onto an iPhone running VK Turn Proxy. Tapping
the link launches the app, shows a confirm alert with the deployment
fingerprint, and applies the settings on confirm. The same payload also
works pasted bare on the iPhone clipboard (Settings → Backup & Restore →
"Import from Connection Link").

Three ways to feed it:

    1. Edit the CONFIG dict below in-place with your deployment values
       and run with no args:

           python3 quick_link.py

    2. Pass a JSON file as argv[1] — useful when managing multiple
       deployments via files in a private repo or password manager. Two
       shapes are accepted:

         - the CONFIG shape (bare, or wrapped in {"settings": {...}}),
         - a Full Backup exported by app build 179+, whose settings carry
           a named-server array. The ACTIVE server is used by default:

           python3 quick_link.py my-deployment.json
           python3 quick_link.py vkturnproxy-backup.json
           python3 quick_link.py vkturnproxy-backup.json --server Server2

       In a 179+ backup vkLink is global (shared by all servers), so it is
       merged into the chosen server automatically.

    3. Provision a NEW client: generate a fresh WireGuard keypair, override
       CONFIG["privateKey"] with it, and print BOTH the link (carrying the new
       private key) AND the matching server-side [Peer] block (new public key,
       AllowedIPs = <tunnelAddress IP>/32, + PresharedKey if set in CONFIG):

           python3 quick_link.py -gen-peer-key

       An optional second arg "ip/mask" overrides CONFIG["tunnelAddress"]
       (use a distinct tunnel IP per client):

           python3 quick_link.py -gen-peer-key 192.168.102.11/24

       peerPublicKey / vkLink / peerAddress still come from CONFIG — the server
       side is fixed; only the client keypair + tunnel IP vary per client.

Required fields (the link is rejected by the iOS parser if any are
missing or empty):

    privateKey       — WG client private key (base64)
    peerPublicKey    — WG server public key  (base64)
    tunnelAddress    — e.g. "192.168.102.3/24"
    vkLink           — https://vk.me/join/<token>
    peerAddress      — e.g. "1.2.3.4:51820" (the WG server, not the TURN)

allowedIPs is NOT emitted (removed 2026-06-11). The iOS app pins the
WireGuard peer allowed_ip to 0.0.0.0/0 — under includeAllNetworks=true that
is the only correct value (a narrower one blackholes traffic, never splits),
and the Settings field was removed in build 160. New links omit it and the
importer keeps the device default 0.0.0.0/0. OLD links that still carry
allowedIPs are still accepted + applied (ConnectionSettings.allowedIPs stays
Optional on the iOS side).

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
    useWrapA         — bool, added 2026-06-03 (iOS SRTP-WRAP-A mode). True =
                       connect to amurcanov's proxy-turn-vk-android server. The
                       server provisions WireGuard via GETCONF, so a WRAP-A
                       link carries NO WG keys — DELETE privateKey /
                       peerPublicKey / tunnelAddress / allowedIPs from CONFIG
                       (they're Optional on the iOS side as of this build).
                       Only vkLink, peerAddress (the amurcanov server host:port)
                       and wrapAPassword are required. If absent, importer keeps
                       its current value (default false).
    wrapAPassword    — string. The amurcanov shared secret (obfuscation key +
                       GETCONF auth). Required when useWrapA=True.
    turnServerOverride — optional "IP:port" (added 2026-06-08). Forces fresh
                       conns onto this TURN relay instead of VK's returned
                       address; disk-cached creds keep their stored address.
                       Omit / leave empty to use whatever VK returns.

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
import os
import sys

# Edit these to your deployment values, then run the script.
CONFIG = {
    # ----- required -----
    "privateKey":     "REPLACE_ME",
    "peerPublicKey":  "REPLACE_ME",
    "tunnelAddress":  "192.168.102.3/24",
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
    # Name of the server this link creates on the importing device (app build
    # 179+, which stores a set of named servers instead of one configuration).
    # Importing ADDS a server under this name and makes it active; existing
    # servers are kept. Delete the line to let the app assign "ServerN".
    # Older builds ignore the field.
    "serverName":     "Server1",
    # useDTLS / useWrap / wrapKeyHex were required before iOS build 129
    # (they corresponded to UI toggles that have since been removed —
    # useDTLS in build 127, useWrap in build 115). Kept in CONFIG with
    # safe defaults so links work against both build-128-and-earlier
    # (which require these fields) and build-129+ (which accept their
    # absence). Delete them only if you know every importer is on 129+.
    "useDTLS":        True,                 # default; legacy DTLS+WG fallback
    "useWrap":        False,                # WRAP largely defunct since 2026-05-18
    "wrapKeyHex":     "",                   # 64 hex chars, only if useWrap=True
    # useSrtp defaults True — SRTP is the app's production transport (the
    # server must run with -srtp). After the build-159 fix the mode triple is
    # applied authoritatively on import, so a plain link with useSrtp/useWrap/
    # useWrapA all false would land the device in LEGACY mode; defaulting
    # useSrtp=True keeps a default link on the SRTP path. Set useSrtp=false only
    # for a legacy DTLS+WG server. (useUDP below stays false — TCP-control
    # bypasses VK's per-cred allocation-rate throttle; set true only if your
    # network needs UDP-control transport.)
    "useSrtp":        True,
    "useUDP":         False,
    # useWrapA is emitted EXPLICITLY (not omitted) so the link fully defines the
    # server mode. Omitting it caused an import bug (2026-06-10): a non-WRAP-A
    # link could NOT switch a device OUT of SRTP-WRAP-A — the importer left the
    # stale useWrapA=true, which wins the (useWrapA > useSrtp > useWrap) mode
    # precedence and kept the device in the wrong mode. Keep this present.
    "useWrapA":       False,
    # ----- SRTP-WRAP-A (amurcanov interop) -----
    # To target amurcanov's proxy-turn-vk-android server: set useWrapA above to
    # True, uncomment wrapAPassword below (real value), and DELETE the WireGuard
    # fields above (privateKey / peerPublicKey / tunnelAddress / allowedIPs) —
    # the server provisions WireGuard via GETCONF, so a WRAP-A link carries no WG
    # keys. peerAddress must be the amurcanov server's host:port. Only vkLink +
    # peerAddress + wrapAPassword are required in this mode.
    # "wrapAPassword":  "REPLACE_ME",
    # ----- SRTP-WRAP-S (samosvalishe/free-turn-proxy interop) -----
    # To target a free-turn-proxy server: set useWrapS=True, KEEP the WireGuard
    # fields above (unlike WRAP-A the user's own WG keys are used), set wrapKeyHex
    # to the server's -obf-key (64 hex), pick obfProfile to match the server's
    # -obf-profile, and set clientID (the server's -clients-file allowlist id; any
    # value if the server runs no allowlist). Emitted explicitly like useWrapA so
    # the link fully defines the mode.
    "useWrapS":       False,
    "obfProfile":     "rtpopus",            # rtpopus | rtpopus2 | rtpopus3
    "clientID":       "",                   # free-turn-proxy Client-ID
    # ----- TURN server override (optional) -----
    # Force fresh conns onto a specific TURN relay instead of whatever VK
    # returns (disk-cached creds keep their stored address). Uncomment + set
    # to IP:port. Omitted / empty = use VK's relays.
    # "turnServerOverride": "1.2.3.4:19302",
}

REQUIRED = (
    "privateKey", "peerPublicKey",
    "tunnelAddress",
    "vkLink", "peerAddress",
)

# SRTP-WRAP-A (amurcanov interop) links carry NO WireGuard keys — the server
# provisions them via GETCONF. Only the password + server address + vkLink are
# required. Selected when CONFIG sets useWrapA=True.
REQUIRED_WRAPA = (
    "wrapAPassword", "vkLink", "peerAddress",
)

# Schema version must match BackupManager.supportedConfigVersion in the
# iOS app. Bump on the Swift side first, then mirror here.
SCHEMA_VERSION = 1


def load_config(argv):
    """Resolve the settings dict a link is built from.

    Accepts three input shapes:
      * no file argument                  → the CONFIG dict above;
      * CONFIG-shaped JSON                → used as-is (also unwraps
                                            {"settings": {...}});
      * Full Backup from app build 179+   → settings.servers[] holds the named
                                            servers; pick the active one (or
                                            --server <name>) and merge in the
                                            GLOBAL vkLink, which no longer lives
                                            inside a server.
    """
    path = None
    want_server = None
    args = argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--server", "-server"):
            if i + 1 >= len(args):
                raise SystemExit("ERROR: --server needs a server name")
            want_server = args[i + 1]
            i += 2
            continue
        if path is None:
            path = args[i]
        i += 1

    if path is None:
        if want_server:
            raise SystemExit("ERROR: --server only applies to a backup file argument")
        return CONFIG

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    settings = data.get("settings", data)

    servers = settings.get("servers")
    if isinstance(servers, list) and servers:
        names = [s.get("serverName", "") for s in servers]
        if want_server:
            chosen = next((s for s in servers if s.get("serverName") == want_server), None)
            if chosen is None:
                raise SystemExit(
                    f"ERROR: no server named {want_server!r} in {path}\n"
                    f"Available: {', '.join(n for n in names if n)}"
                )
        else:
            active = settings.get("activeServer")
            chosen = next((s for s in servers if s.get("serverName") == active), None)
            if chosen is None:
                chosen = servers[0]
        merged = dict(chosen)
        # vkLink is GLOBAL in the 179+ backup (shared by every server) but is a
        # required field of a connection link, so fold it back in here.
        if "vkLink" in settings:
            merged["vkLink"] = settings["vkLink"]
        return merged

    if want_server:
        raise SystemExit(
            f"ERROR: --server given but {path} has no servers[] "
            f"(it is a pre-179 backup or a plain CONFIG file)"
        )
    return settings


def validate(settings):
    # WRAP-A links carry no WG keys (server-provisioned via GETCONF), so
    # validate the smaller required set when useWrapA is on.
    required = REQUIRED_WRAPA if settings.get("useWrapA") else REQUIRED
    missing = []
    for key in required:
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
    if settings.get("useWrapS"):
        if len(settings.get("wrapKeyHex", "") or "") != 64:
            raise SystemExit(
                "ERROR: useWrapS=True but wrapKeyHex is not 64 hex chars (32 bytes). "
                "It must match the free-turn-proxy server's -obf-key."
            )
        if settings.get("obfProfile") not in ("rtpopus", "rtpopus2", "rtpopus3"):
            raise SystemExit(
                "ERROR: useWrapS=True requires obfProfile in "
                "rtpopus|rtpopus2|rtpopus3 (match the server's -obf-profile)."
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


# ─── WireGuard keypair generation (for the -gen-peer-key mode) ──────────────
# Pure-Python X25519 (RFC 7748) so the script stays dependency-free. Produces
# the same base64 keys as `wg genkey` / `wg pubkey`.

def _x25519(k_int, u_int):
    P = 2 ** 255 - 19
    x1 = u_int
    x2, z2, x3, z3, swap = 1, 0, u_int, 1, 0
    for t in reversed(range(255)):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = x1 * (DA - CB) ** 2 % P
        x2 = AA * BB % P
        z2 = E * (AA + 121665 * E) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, P - 2, P) % P


def gen_wg_keypair():
    """Return (privateKey_b64, publicKey_b64) — a fresh WireGuard X25519 pair,
    base64-encoded exactly like `wg genkey` / `wg pubkey`."""
    priv = bytearray(os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    pub = _x25519(int.from_bytes(priv, "little"), 9).to_bytes(32, "little")
    return base64.b64encode(bytes(priv)).decode(), base64.b64encode(pub).decode()


def peer_section(settings, public_key_b64):
    """The server-side [Peer] block matching the freshly-generated client key:
    AllowedIPs = <tunnelAddress IP>/32, PublicKey = <generated pub>, plus a
    PresharedKey line if one is set in CONFIG."""
    ip = settings.get("tunnelAddress", "").split("/")[0].strip()
    lines = ["[Peer]", f"AllowedIPs = {ip}/32", f"PublicKey = {public_key_b64}"]
    psk = settings.get("presharedKey", "")
    if psk and psk != "REPLACE_ME":
        lines.append(f"PresharedKey = {psk}")
    return "\n".join(lines)


def main():
    argv = sys.argv
    # -gen-peer-key: generate a fresh WireGuard client keypair, override
    # CONFIG["privateKey"] with it (even if already filled), optionally override
    # tunnelAddress from a second "ip/mask" arg, then emit the link AND the
    # matching server-side [Peer] block (with the generated public key).
    if len(argv) > 1 and argv[1] == "-gen-peer-key":
        settings = dict(CONFIG)
        priv_b64, pub_b64 = gen_wg_keypair()
        settings["privateKey"] = priv_b64
        if len(argv) > 2:
            settings["tunnelAddress"] = argv[2]
        validate(settings)
        print(build_link(settings))
        print()
        print(peer_section(settings, pub_b64))
        return
    settings = load_config(argv)
    validate(settings)
    print(build_link(settings))


if __name__ == "__main__":
    main()
