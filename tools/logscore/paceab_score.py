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
OFF_S = OFFSET_H * 3600.0   # client clock → pcap clock, applied ONLY to the pcap


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

# 🚨 TWO CLOCKS, AND ONLY ONE OF THEM NEEDS THE OFFSET. The Swift `ARM/ARMEND`
# markers and the Go `[Go] PACE-ARMEND` lines are both written by the PHONE, on
# the same device clock. The pcap is written by the SERVER. So arm windows are
# kept in CLIENT time — which is what the verdicts are compared against — and the
# offset is added only when those windows are used to select packets.
# ⚠️ The first version shifted the markers at parse time and then compared the
# unshifted verdicts against them, so both verdicts fell two hours outside their
# own arms and a perfectly good run would have been refused.
# *(User-caught, 2026-08-16, on the run itself.)*
off = datetime.timedelta(hours=OFFSET_H)
marks = []
for line in open(LOG, errors="replace"):
    m = re.search(rf"\[([\d-]+ [\d:.]+)\] {RUNNER} (ARM|ARMEND) a=(\d+)/(\d+) mode=(\w+)(.*)", line)
    if m:
        t = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
        # 🚨 WHAT THE ARM ASKED FOR, taken from the runner's OWN declaration
        # rather than from a constant copied into this scorer. The `pace=` clause
        # is the only place the request is written down; comparing it against the
        # verdict's `rate=`/`burst=` is what makes the label mean something.
        # (Copying `paceKiB` here instead would be the day's own repeated defect:
        # a second copy of something that already has an owner.)
        asked = None
        if m.group(2) == "ARM":
            pm = re.search(r"pace=(\d+)KiB/s burst (\d+)KiB", m.group(6))
            if pm:
                asked = (int(pm.group(1)), int(pm.group(2)))
            elif not re.search(r"pace=off", m.group(6)):
                die(f"arm {m.group(3)}: the ARM marker carries no readable `pace=` clause, so "
                    "what this arm ASKED FOR is unknown and its verdict cannot be checked "
                    f"against it. The runner's marker format changed.\n    {line.strip()}")
        marks.append((m.group(2), int(m.group(3)), m.group(5), t, int(m.group(4)), asked))
if not marks:
    die(f"no `{RUNNER} ARM/ARMEND` markers — wrong log, or the run never declared an arm?")

# 🚨 EXACTLY EIGHT MARKERS. The old loop stepped in pairs and SILENTLY DROPPED a
# trailing odd one — so a complete first run followed by a single `ARM` of a
# second passed as a normal first run. *(User-caught, 2026-08-16.)*
if STRICT and len(marks) != 8:
    die(f"{len(marks)} ARM/ARMEND markers, expected exactly 8 (four arms). An odd count "
        "means a second run started in this log; a different even count means a different "
        "experiment.")
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
    arms[a[1]] = (a[2], a[3].timestamp(), b[3].timestamp(), a[4], b[3], a[5])
    # client-clock seconds; +OFFSET only when selecting from the pcap
    # 🚨 THE LABEL AND THE COMMAND MUST AGREE. `mode=unpaced` with a `pace=` rate,
    # or a paced label with `pace=off`, means the runner named an arm one thing
    # and asked for another — and every later check would be run against the
    # wrong expectation.
    if (a[2] == "unpaced") != (a[5] is None):
        die(f"arm {a[1]} is labelled '{a[2]}' but its ARM marker asked for "
            f"{'pace=off' if a[5] is None else str(a[5])} — the label and the command disagree, "
            "so neither can be trusted.")

if STRICT:
    if sorted(arms) != [1, 2, 3, 4]:
        die(f"arm numbers are {sorted(arms)}, expected 1..4.")
    denoms = {arms[k][3] for k in arms}
    if denoms != {4}:
        die(f"arms declare denominators {sorted(denoms)}, expected /4 everywhere — this log "
            "is from a plan with a different number of arms.")
    # 🚨 THE SEQUENCE IS PART OF THE CONTRACT, and there are two of them now: the
    # first pacer A/B (`unpaced·paced·paced·unpaced`, which asked whether a bucket
    # helps at all) and the burst sweep (`burst16·burst2·burst2·burst16`, which
    # asks what the residual floor is made of). Both are mirrored palindromes of
    # four; anything else is a different experiment.
    got = [arms[k][0] for k in sorted(arms)]
    KNOWN = [["unpaced", "paced", "paced", "unpaced"],
             ["burst16", "burst2", "burst2", "burst16"]]
    if got not in KNOWN:
        die(f"arms are {got}, and this scorer reads only {KNOWN}. A different sequence is a "
            "different experiment; add it here deliberately rather than letting it through.")
    if got == KNOWN[1]:
        print("# 🚨 BURST SWEEP: every arm is PACED and there is NO unpaced control in these "
              "minutes. `burst16` vs `burst2` is the whole measurement — the 0.85% unpaced "
              "baseline is a PRIOR from another session and must not be differenced against "
              "these arms.")
    # 🚨 EVERY PACED ARM MUST CARRY ITS OWN ENGAGEMENT VERDICT. The per-tick
    # `pace=` field covers ten seconds and cannot speak for an arm; `PACE-ARMEND`
    # is the arm's own accumulator, printed once when the pacer is turned off.
    # 🚨 EXACTLY TWO VERDICTS, EACH IN ITS OWN ARM'S GAP. Counting them is not
    # enough: two lines from one arm and none from the other would pass a
    # >= check, and a verdict that landed anywhere in the run would pass a bare
    # count. Each must fall between its paced arm's ARMEND and the next ARM.
    # The `[Go]` prefix carries its own clock, already on the pcap's timeline.
    # 🚨 AND THE VERDICT'S `rate=`/`burst=` ARE READ, NOT SKIPPED. Taking only
    # `waited` accepts a sweep labelled 16·2·2·16 whose four buckets all actually
    # ran at 16 — a perfect null that reads as "depth does not matter". The
    # setting reaches the extension over a FIRE-AND-FORGET provider message
    # (`sendProviderMessage`, `try?`, no completion checked), so "the runner asked"
    # and "the tunnel applied" are two different facts and only the verdict knows
    # the second. *(User-caught, 2026-08-16.)*
    # ⚠️ Detect the line LOOSELY and parse its fields STRICTLY, so a Go format
    # change says "I found the verdict and could not read it" instead of "there
    # are no verdicts" — the second would be blamed on the run.
    vlines = []
    for line in open(LOG, errors="replace"):
        if "PACE-ARMEND gen=" not in line:
            continue
        fm = re.search(r"rate=(\d+)KiB burst=(\d+)KiB", line)
        if not fm:
            die("a PACE-ARMEND verdict carries no readable `rate=…KiB burst=…KiB` — the Go "
                "format changed, and without those fields this scorer cannot tell whether the "
                f"arm ran at the depth it was labelled with.\n    {line.strip()}")
        m = re.match(r"\[Go\] (\d\d):(\d\d):(\d\d)\.(\d+).*?waited=(\d+)\(", line)
        if not m:
            die("a PACE-ARMEND verdict has no `[Go] HH:MM:SS` stamp or no `waited=` — it cannot "
                f"be bound to an arm.\n    {line.strip()}")
        # `[Go]` carries a time of day and no date. Pick the date that puts it
        # nearest the run — a run can straddle midnight, and guessing the
        # first marker's date would then be a day out.
        tod = datetime.time(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            int(m.group(4)[:6].ljust(6, "0")))
        base = marks[0][3]
        cand = [datetime.datetime.combine(base.date() + datetime.timedelta(days=d), tod)
                for d in (-1, 0, 1)]
        t = min(cand, key=lambda c: abs((c - base).total_seconds()))
        vlines.append((t.timestamp(), int(m.group(5)), line.strip(),
                       (int(fm.group(1)), int(fm.group(2)))))
    # Every arm whose bucket is armed needs its own verdict — in the burst sweep
    # that is all four, not two.
    paced = [k for k in sorted(arms) if arms[k][0] != "unpaced"]
    if len(vlines) != len(paced):
        die(f"{len(vlines)} PACE-ARMEND lines for {len(paced)} paced arms — expected exactly "
            "one per paced arm. An arm without its own verdict cannot be scored, because a "
            "per-tick zero is a quiet interval and not a verdict.")
    # 🚨 An instrument that can misjudge should name its own likeliest failure.
    # Verdicts that exist but bind to NOTHING is the signature of a clock
    # mismatch in this scorer, not of a bad run — it is exactly the defect that
    # shipped here once.
    bound = sum(1 for v in vlines
                if any(arms[k][2] - 2 <= v[0] <= (arms[k + 1][1] if (k + 1) in arms
                                                  else arms[k][2] + 3600) + 2
                       for k in paced))
    if vlines and bound == 0:
        die(f"{len(vlines)} PACE-ARMEND lines exist but NONE falls inside a paced arm's gap. "
            "That is almost certainly a clock mismatch in this scorer rather than a bad run: "
            "`[Go]` lines and `ARM` markers are both PHONE time and must be compared without "
            "the pcap offset. Check before blaming the run.")
    for k in paced:
        end = arms[k][2]
        nxt = arms[k + 1][1] if (k + 1) in arms else end + 3600
        owned = [v for v in vlines if end - 2 <= v[0] <= nxt + 2]
        if len(owned) != 1:
            die(f"arm {k} (paced) has {len(owned)} PACE-ARMEND lines in its own gap — the "
                "verdict must be the one printed when THAT arm's pacer was turned off, not "
                "a line from somewhere else in the run.")
        if owned[0][1] == 0:
            die(f"arm {k}: PACE-ARMEND reports waited=0 — the bucket never emptied, so this "
                "arm tested NOTHING. Lower the BURST before the rate: the losses are "
                f"block-shaped, i.e. a depth.\n    {owned[0][2]}")
        # 🚨 THE ARM RAN AT THE DEPTH ITS LABEL CLAIMS — asked (ARM marker) against
        # applied (the verdict). Without this the sweep's labels are decoration:
        # `burst16·burst2·burst2·burst16` would be accepted with all four buckets
        # at 16, and the answer would read as "depth does not matter".
        want, got = arms[k][5], owned[0][3]
        if want != got:
            die(f"arm {k} is labelled '{arms[k][0]}' and its ARM marker asked for "
                f"{want[0]}KiB/s burst {want[1]}KiB, but its verdict reports "
                f"{got[0]}KiB/s burst {got[1]}KiB — THE ARM DID NOT RUN AT THE SETTING IT IS "
                "NAMED AFTER. The pace setting reaches the extension over a fire-and-forget "
                "provider message, so a send that never lands leaves the PREVIOUS arm's bucket "
                "in place and the arm runs under a label it never had.\n    "
                f"{owned[0][2]}")

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
    for k, (mode, s, e, _dn, _te, _ask) in arms.items():
        if s + OFF_S <= ts <= e + OFF_S:
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
span_ok = (pcap_first <= min(a[1] for a in arms.values()) + OFF_S
           and pcap_last >= max(a[2] for a in arms.values()) + OFF_S)
print(f"# pcap RTP={rtp_total} span={datetime.datetime.fromtimestamp(pcap_first)} "
      f"→ {datetime.datetime.fromtimestamp(pcap_last)}  conns={nconn} "
      f"groupA={len(groupA)} groupB={len(groupB)} offset={OFFSET_H}h")
if not span_ok:
    die("the capture does not cover every arm — check --offset-hours. Printing a table over "
        "a partial capture is how a missing tail reads as a clean arm.")

hdr = f"{'arm':<4}{'mode':<10}{'grp':<4}{'allocs':>7}{'expected':>11}{'received':>10}{'missing':>9}{'loss':>9}{'reord':>7}{'dup':>6}"
print(hdr)
print("-" * len(hdr))
for k in sorted(arms):
    mode, s, e = arms[k][0], arms[k][1], arms[k][2]
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

# 🚨 THE CLOSING HINT NAMES THIS RUN'S OWN COMPARISON. It used to say "paced
# against unpaced" and "both verdicts" unconditionally — written for the first
# A/B and left standing when the burst sweep arrived, where every arm is paced,
# there are FOUR verdicts and no unpaced arm exists. The reader takes the
# comparison from this line, so a stale one renames the experiment.
_paced = [k for k in sorted(arms) if arms[k][0] != "unpaced"]
_sweep = len(_paced) == len(arms)
print("\n🎯 THE COMPARISON IS GROUP B, " + ("BURST16 ARMS AGAINST BURST2 ONES — every arm is"
      "\n   PACED and there is NO unpaced control in these minutes, so the 0.85% baseline is a"
      "\n   PRIOR from another session and must not be differenced against these arms."
      if _sweep else "PACED ARMS AGAINST UNPACED ONES."))
print("   Group A is the CROSS-TALK CONTROL and must not move; it is the synthetic,")
print("   whose own cum-lost at index 5d170000 is the second, independent reading of it.")
print(f"🚨 The engagement verdict is `PACE-ARMEND`, one per paced arm ({len(_paced)} here) — NOT")
print("   the per-tick `pace=` field, which covers ten seconds and cannot speak for an arm.")
print("   This scorer refused to print anything unless every paced arm has its own verdict,")
print("   in its own gap, engaged, AND REPORTING THE RATE AND BURST ITS LABEL CLAIMS.")
