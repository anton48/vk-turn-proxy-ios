# Measurement method revisions

`EngineVersion` carries two numbers, and they answer different questions:

```
speedtest-go v1.7.11+fork.5 / vkturn-method.5
                        │                 │
                        │                 └── THIS file: how the wrapper measures
                        └── ../../third_party/speedtest-go/FORK.md: what we
                            changed inside the engine
```

🚨 **THE FORK REVISION ALONE WAS NOT ENOUGH, and four builds proved it.** Builds
315 through 318 all reported `+vkturn.5` because the fork did not move — while
the wrapper changed what "8 threads" means, what the connection count counts,
and whether a phase was primed at all. Results from those builds cannot go in
one series, and the label said they could.

⇒ **Bump the number below whenever a change alters what a number MEANS**: the
load offered, the window it is averaged over, the connections it runs on, or the
conditions under which a figure is published. Do not bump it for wording, UI, or
tests. `TestEngineVersionNamesEveryMethodRevision` fails if the constant and the
sections here disagree.

⚠️ **A revision boundary is not a "this got better" marker — it is a "do not
compare across this line" marker.** That is why the reasons below are written as
what was WRONG with the numbers before it.

---

## Method 1 — the original wrapper

Two figures per phase (the engine's blended estimator and confirmed bytes over
elapsed), the endpoint's 307 resolved before measuring, upload backlog and
confirmation ratio reported, a warm-up discarded in research mode.

## Method 2 — threads become flows, and a stopped run stops being a result

**Before this, `Threads` did not mean TCP connections.** The engine's transport
allowed HTTP/2 and the measured URL is https after the redirect is resolved, so
N workers multiplexed onto one connection — measured as 8 workers on 1
connection. Any comparison across thread counts before this measured nothing
about flow count.

Also from this revision: a cancelled phase is an error rather than a published
result; the warm-up and the measurement window are measured separately and both
shipped, so the reported rate and the reported duration cannot contradict each
other; a direction that did not run is omitted instead of being sent as zeros;
and the config is validated, so an unknown direction no longer measures nothing
and reports success.

## Method 3 — the connection count counts USE, not presence

**Before this, the count included connections the measurement never touched.**
Discovery — user info, the server list, and the list's concurrent ping of every
server — shared one transport with the measurement and left its pool full.
Measured: 7 idle discovery sockets plus 1 multiplexed HTTP/2 socket reported "8
of 8 threads" and raised no warning.

Discovery now runs on its own transport and is finished before the measurement
starts, and a connection is counted at its first byte in the phase.

## Method 4 — every phase is primed, and priming reports

**Before this, only the download phase was primed, and only by accident** — the
latency ping happened to leave a connection pooled. The upload phase started
cold, and a phase that starts cold cannot detect HTTP/2 at all: Go dials once
per concurrent request from an empty pool, so it reads N connections whatever
the protocol.

Priming now runs before every phase and reports whether the pool is actually
warm; a phase that could not be primed disclaims its own connection figure
instead of presenting it. Idle sockets are released when a run or a list fetch
finishes.

## Method 5 — priming asks for something the server serves

**Before this, priming made things WORSE than not priming.** It fetched the
measurement URL, and the real endpoint answers that with `404 Not Found` and
`Connection: Close` — over the connection the ping had already pooled, which the
server then closed. So priming emptied the pool. On a device the download phase
went from 7 dials to 8 and both phases printed the cold-pool disclaimer.

It now asks for `latency.txt`, derived exactly the way the engine derives its own
ping URL.

## Method 6 — `confirmed` is upload-only, and the tail of a phase is not refusal

**Before this the confirmation figure was wrong in both directions.**

*Download published `confirmed=100.0%`.* A GET's bytes are counted as they
arrive, so there is no pushed-but-unaccepted quantity at all and the ratio was
1.0 by construction — which reads as *the server accepted everything* when it
means *this field does not apply*. Sixteen download lines in
`20.08/vpn.wifi.6.log` carry it. The `Phase` doc comment had said UPLOAD ONLY the
whole time; the code did not.

*Upload warned about refused bytes that were nothing of the kind.* When the
capture time expires, every worker is mid-chunk; those requests are cancelled and
their bytes land in the backlog, so the tail is `threads × one chunk`
(`ulSizes[4]`, 999 490 B). That is the entire backlog ever measured here —
3.5/7.3/13.2/29.5 MB at 4/8/16/32 threads against ceilings of 4.0/8.0/16.0/32.0 —
so *"only 94% of uploaded bytes were confirmed by the server"* fired on every
32-thread run and was false every time. At a fixed rate the tail grows with the
thread count while the window's bytes do not, so **the warning was a function of
the knob, not of the path**.

The ratio is still reported for upload — it is a fact, and a ratio of 0.0 against
45.8 MB of backlog is what identified the Frankfurt 307 endpoint. What changed is
that the VERDICT is gated on backlog the cancellation tail cannot explain, and
`backlog_tail_bytes` now travels with the phase so the line can qualify its own
number.

*And zero was unrepresentable.* Presence was inferred from `ConfirmedRatio > 0`,
so the one endpoint this field exists for — Frankfurt's 307 host, which confirms
NOTHING — came out as exactly 0.000 and was therefore treated as *not measured*:
it printed on no line, showed on no screen and warned nowhere. `ConfirmedKnown`
now carries presence, and the ratio carries only the value. ⚠️ This is a
REPORTING fix, not a measurement one — no figure changes, a hidden one appears —
so it is part of Method 6 rather than a revision of its own.

⇒ **Do not compare a `confirmed` figure across this line**: before Method 6 a
download's is meaningless and an upload's warning is thread-count noise.

## Method 7 — the measurement window closes on its own timer

**Before this, research mode's "fixed window" was not fixed.** The wrapper read
its end timestamp and its byte counter after the engine's phase function
returned — and that returns only once every blocked worker has unwound. So the
unwinding was measured too.

Seen across two palindromes on 2026-08-20 (`20.08/speedtest0`), which are
designed around their arms being the same length:

```
30 allocations · T4   window 33.6s and 34.1s   (asked for 30)
30 allocations · T32  window 31.7s
60 allocations · T32  window 33.1s and 32.8s
60 allocations · T16  window 35.0s
```

The rate stayed arithmetically honest — bytes divided by the window it actually
used — which is exactly why nothing looked wrong. What was broken is
comparability: two arms of different lengths are not the same experiment, and a
palindrome cannot separate drift from treatment when its arms differ by 17%.

The window is now closed by its own timer at `warm-up + requested`, and both the
byte counter and the timestamp are taken THERE. What happens afterwards is
reported as **`cleanup_sec`** — which also makes it the first measurement of how
long the engine takes to stop.

⇒ **Do not compare a research-mode figure across this line.** Before Method 7 an
arm's window is whatever its workers allowed; after it, the window is the one
that was asked for. ⚠️ The 60-allocation T16 and T32 means from
`20.08/speedtest0` are indicative for that reason, not final.

## Method 8 — the window's boundary stops racing the engine, and the last field changes scope

**Method 7's window could silently not happen.** The wrapper's close sample and
the engine's own stop were armed for the SAME instant — `SetCaptureTime` was
`warm-up + requested`, and the close timer fired at the same moment — so which
one ran first was the scheduler's business. Worse, the timer was armed *after*
the warm-up sample returned, so it inherited that timer's scheduling delay and
was biased to lose. A lost sample fell back to the phase's own end: the
pre-Method-7 variable window, wearing a fixed window's label, in silence.

⇒ the engine is now given `warm-up + requested + 2s`, so the window closes while
it is still pushing; both boundaries are absolute, anchored on the phase start;
and a window that was asked for and NOT closed says so in a warning instead of
falling back quietly.

**And `consistent` / `implied_sec` were still the phase's.** Every other
qualifying figure had moved to the window — raw, window bytes, backlog, confirmed
— while the consistency check compared the engine's rate against the whole
phase's bytes over the whole phase's duration, cleanup included. A reader doing
the arithmetic the line invites uses the window figures printed on it, so a
CORRECT research line could fail its own check. Both are computed from the window
now. *(Same defect as the phase-scoped confirmed ratio in Method 6, one field
along; the third time this scope has had to be chased.)*

**Wording, because the sampling point moved.** At the cutoff the outstanding
bytes are exactly that — outstanding. Some are confirmed during the cleanup that
follows, so nothing may call them *cancelled*, *refused* or *never confirmed*;
the log, the screen and the warning all say *held in flight at the cutoff* /
*had been confirmed when the window closed*.

⇒ **Do not compare a research figure from Method 7 with one from Method 8**: a
Method 7 run cannot be known to have enforced its window.
