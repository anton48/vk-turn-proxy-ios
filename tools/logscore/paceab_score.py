#!/usr/bin/env python3
"""Score the uplink-pacer A/B: group B's REAL loss, per arm, from the capture.

    ./paceab_score.py <pcap> <client-log> [--offset-hours 2]

🚨 WHY THIS EXISTS AND WHY IT IS WRITTEN BEFORE THE RUN.

Group B carries the REAL stream, and its WireGuard keypair ROTATES every ~2
minutes — so the server's `by-idx` entries appear and vanish between dumps and a
difference across an arm boundary yields NEGATIVE spans (-4850 and -208066 were
printed in `16.08.2026/tcptest1`). `cum-lost` therefore CANNOT score this run.
Only the synthetic's index is fixed by construction, and the synthetic is on
group A, where it serves as the cross-talk control.

⇒ The one honest source of B's loss is the capture: the OUTER RTP sequence,
which the client stamps immediately before the write to the underlay, so a gap
means the packet left the phone and never reached server1.

A scorer written AFTER a run gets tuned to that run's data. This one is written
first, and it is version-controlled beside the code it scores.

🚨 HOW LOSS IS COUNTED, AND IT IS NOT "COUNT THE FORWARD JUMPS". `rtpgaps.py`
tracks only the last sequence number, so a REORDERED packet is charged twice —
once as a gap on the forward jump, once as a `reorder` on the way back — and
`missing` comes out overstated. That was harmless in the split run because
reordering measured exactly 0; under a pacer it is not safe to assume.

This counts the way the WireGuard-nonce counter does, which is the semantics
this project already trusts:

    expected = max(seq) - min(seq) + 1     (the SPAN, after unwrapping)
    received = distinct sequence numbers actually seen
    missing  = expected - received

Immune to reordering by construction, and `by-idx [idx:L/N]`'s N is the same
quantity — so the two instruments stay comparable.

⚠️ The 16-bit sequence wraps every 65536 packets ≈ 9 minutes per allocation at
this load, i.e. inside a run though rarely inside an arm. It is unwrapped per
SSRC before anything else.
"""
import struct, sys, re, datetime
from collections import defaultdict

if len(sys.argv) < 3:
    sys.exit(__doc__)
PCAP, LOG = sys.argv[1], sys.argv[2]
OFFSET_H = 2.0
if "--offset-hours" in sys.argv:
    OFFSET_H = float(sys.argv[sys.argv.index("--offset-hours") + 1])
# 🚨 THE RUNNER IS PART OF THE CONTRACT, NOT A LABEL. Without this the utility
# happily scored an old EIGHT-ARM `splitab` log, printed its table and exited 0 —
# a different experiment, silently rendered as this one. `--runner splitab` is
# kept only so the commissioning regression can still be re-run.
# *(User-caught, 2026-08-16, before the run.)*
RUNNER = "paceab"
if "--runner" in sys.argv:
    RUNNER = sys.argv[sys.argv.index("--runner") + 1]
STRICT = RUNNER == "paceab"
DSTPORT = 56001


def die(msg):
    sys.exit("🚨 REFUSING TO SCORE: " + msg)


# ---- 1. conn -> relay port, straight from the client's own allocation lines.
port2conn = {}
for line in open(LOG, errors="replace"):
    m = re.search(r"\[conn (\d+)\] TURN relay allocated: [\d.]+:(\d+)", line)
    if m:
        port2conn[int(m.group(2))] = int(m.group(1))
if not port2conn:
    die("no `[conn N] TURN relay allocated:` lines — wrong log?")
nconn = max(port2conn.values()) + 1
half = nconn // 2
groupA = {p for p, c in port2conn.items() if c < half}
groupB = {p for p, c in port2conn.items() if c >= half}

# ---- 2. the run must be THIS run, and it must have finished.
text = open(LOG, errors="replace").read()
if re.search(rf"{RUNNER} ABORTED", text):
    die(f"the log contains `{RUNNER} ABORTED` — the run voided itself and nothing in it "
        "is comparable across the break.")
if not re.search(rf"{RUNNER} DONE state=done", text):
    die(f"no `{RUNNER} DONE state=done` — the run did not finish, so its last arm is "
        "truncated and its palindrome is incomplete.")

off = datetime.timedelta(hours=OFFSET_H)
marks = []
for line in open(LOG, errors="replace"):
    m = re.search(rf"\[([\d-]+ [\d:.]+)\] {RUNNER} (ARM|ARMEND) a=(\d+)/(\d+) mode=(\w+)", line)
    if m:
        t = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f") + off
        marks.append((m.group(2), int(m.group(3)), m.group(5), t))
if not marks:
    die(f"no `{RUNNER} ARM/ARMEND` markers — wrong log, or the run never declared an arm?")

arms = {}
for i in range(0, len(marks) - 1, 2):
    a, b = marks[i], marks[i + 1]
    if a[0] != "ARM" or b[0] != "ARMEND" or a[1] != b[1]:
        die(f"unpaired markers around arm {a[1]} — refusing to guess.")
    if a[1] in arms:
        # 🚨 Two runs in one log would otherwise OVERWRITE each other arm by arm
        # and produce a table that looks perfectly normal.
        die(f"arm {a[1]} appears twice — this log holds more than one {RUNNER} run. "
            "Split it, or the arms silently overwrite each other.")
    arms[a[1]] = (a[2], a[3].timestamp(), b[3].timestamp())

if STRICT:
    want = ["unpaced", "paced", "paced", "unpaced"]
    got = [arms[k][0] for k in sorted(arms)]
    if got != want:
        die(f"arms are {got}, and this scorer only reads {want}. A different sequence is a "
            "different experiment.")
    # 🚨 EVERY PACED ARM MUST CARRY ITS OWN ENGAGEMENT VERDICT. The per-tick
    # `pace=` field covers ten seconds and cannot speak for an arm; `PACE-ARMEND`
    # is the arm's own accumulator, printed once when the pacer is turned off.
    verdicts = re.findall(r"PACE-ARMEND gen=(\d+) .*?waited=(\d+)\(", text)
    npaced = sum(1 for k in arms if arms[k][0] == "paced")
    if len(verdicts) < npaced:
        die(f"{len(verdicts)} PACE-ARMEND lines for {npaced} paced arms — an arm without its "
            "own engagement verdict cannot be scored, because a per-tick zero is a quiet "
            "interval and not a verdict.")
    inert = [g for g, w in verdicts if int(w) == 0]
    if inert:
        die(f"PACE-ARMEND generation(s) {inert} report waited=0 — the bucket never emptied, "
            "so those arms tested NOTHING. Lower the BURST before the rate: the losses are "
            "block-shaped, i.e. a depth.")

# ---- 3. one streaming pass; only the first 64 B of each frame is read.
f = open(PCAP, "rb")
magic = f.read(4)
if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    endian, nano = "<", magic[0] == 0x4d
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    endian, nano = ">", magic[3] == 0x4d
else:
    sys.exit("not a pcap: %r" % magic)
f.read(20)
ph = struct.Struct(endian + "IIII")

# per (arm, ssrc): the unwrapped sequence numbers seen
seen = defaultdict(set)
port_of = {}                       # ssrc -> srcport (SSRC is per allocation)
hi = {}                            # ssrc -> unwrap epoch
prevseq = {}                       # ssrc -> last raw seq
dups = defaultdict(int)
reord = defaultdict(int)
maxseen = {}                       # (arm, ssrc) -> highest unwrapped seq so far
rtp_total = pcap_first = pcap_last = 0

while True:
    hdr = f.read(16)
    if len(hdr) < 16:
        break
    ts_s, ts_frac, incl, orig = ph.unpack(hdr)
    take = min(incl, 64)
    buf = f.read(take)
    if incl > take:
        f.seek(incl - take, 1)
    if len(buf) < 42 or buf[12:14] != b"\x08\x00":
        continue
    ihl = (buf[14] & 0x0F) * 4
    if buf[14 + 9] != 17:
        continue
    uoff = 14 + ihl
    if len(buf) < uoff + 20:
        continue
    sport, dport = struct.unpack(">HH", buf[uoff:uoff + 4])
    if dport != DSTPORT:
        continue
    p = uoff + 8
    if (buf[p] & 0xC0) != 0x80:
        continue
    rtp_total += 1
    ts = ts_s + (ts_frac / 1e9 if nano else ts_frac / 1e6)
    pcap_first = pcap_first or ts
    pcap_last = ts
    seq = struct.unpack(">H", buf[p + 2:p + 4])[0]
    ssrc = struct.unpack(">I", buf[p + 8:p + 12])[0]
    port_of.setdefault(ssrc, sport)

    # 16-bit unwrap, per SSRC. A step of more than half the space backwards is a
    # wrap forwards; more than half forwards is a late packet from before one.
    pv = prevseq.get(ssrc)
    if pv is None:
        hi[ssrc] = 0
    else:
        if seq < pv and (pv - seq) > 32768:
            hi[ssrc] += 65536
        elif seq > pv and (seq - pv) > 32768:
            hi[ssrc] -= 65536
    prevseq[ssrc] = seq
    u = hi[ssrc] + seq

    arm = None
    for k, (mode, s, e) in arms.items():
        if s <= ts <= e:
            arm = k
            break
    if arm is None:
        continue
    key = (arm, ssrc)
    if u in seen[key]:
        dups[key] += 1
    else:
        # Reordering, counted the only way span-minus-distinct allows: a
        # sequence arriving after a HIGHER one has already been seen.
        hiq = maxseen.get(key)
        if hiq is not None and u < hiq:
            reord[key] += 1
        maxseen[key] = u if hiq is None else max(hiq, u)
    seen[key].add(u)

# ---- 4. report.
if pcap_first == 0:
    sys.exit("no RTP to :%d in the capture" % DSTPORT)
span_ok = pcap_first <= min(a[1] for a in arms.values()) and pcap_last >= max(a[2] for a in arms.values())
print(f"# pcap RTP={rtp_total} span={datetime.datetime.fromtimestamp(pcap_first)} "
      f"→ {datetime.datetime.fromtimestamp(pcap_last)}  conns={nconn} "
      f"groupA={len(groupA)} groupB={len(groupB)} offset={OFFSET_H}h")
if not span_ok:
    print("# 🚨 THE CAPTURE DOES NOT COVER EVERY ARM — check --offset-hours before reading anything below")

hdr = f"{'arm':<4}{'mode':<10}{'grp':<4}{'allocs':>7}{'expected':>11}{'received':>10}{'missing':>9}{'loss':>9}{'reord':>7}{'dup':>6}"
print(hdr)
print("-" * len(hdr))
for k in sorted(arms):
    mode, s, e = arms[k]
    for gname, ports in (("A", groupA), ("B", groupB)):
        exp = rec = mis = dp = ro = 0
        allocs = 0
        for (arm, ssrc), got in seen.items():
            if arm != k or port_of.get(ssrc) not in ports:
                continue
            allocs += 1
            lo, hiq = min(got), max(got)
            exp += hiq - lo + 1
            rec += len(got)
            dp += dups[(arm, ssrc)]
            ro += reord[(arm, ssrc)]
        mis = exp - rec
        share = f"{100*mis/exp:.4f}%" if exp else "—"
        print(f"{k:<4}{mode:<10}{gname:<4}{allocs:>7}{exp:>11}{rec:>10}{mis:>9}{share:>9}{ro:>7}{dp:>6}")

print("\n🎯 THE COMPARISON IS GROUP B, PACED ARMS AGAINST UNPACED ONES.")
print("   Group A is the CROSS-TALK CONTROL and must not move; it is the synthetic,")
print("   whose own cum-lost at index 5d170000 is the second, independent reading of it.")
print("🚨 Read `pace=` in the client log FIRST: waited=0 means the bucket never emptied")
print("   and the arm tested nothing, whatever the numbers above say.")
