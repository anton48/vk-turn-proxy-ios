# Vendored fork of `showwin/speedtest-go` v1.7.11

Upstream: https://github.com/showwin/speedtest-go — **MIT**, see `LICENSE`
(kept verbatim; MIT inside our GPL-3 tree, like the Pion sources).

Only the `speedtest/` library package is vendored. Upstream's module root is a
CLI and would drag kingpin/ysmrr/colorable/isatty/runewidth/term in with it; the
library needs nothing outside the standard library.

## The one deliberate change: adaptive upload concurrency is DISABLED

`speedtest/data_manager.go` no longer starts `adaptUploadWorkers()`.

**Why.** Upstream 1.7.11 turned `-t`/`MaxConnections` from a worker COUNT into a
CEILING for a controller that re-evaluates every second and cuts workers when the
confirmed rate drops 15% below its best. Observed directly on 2026-08-20,
`-t 16` against server 35692 with debug on:

```
Upload workers: 16/16
Upload workers: 14/16  (confirmed: 90.88 MB/s)
Upload workers:  6/16  (confirmed: 33.01 MB/s)
Upload workers:  3/16  (confirmed: 15.99 MB/s)
Upload workers:  2/16  (confirmed: 10.99 MB/s)
Upload workers:  1/16  (confirmed:  6.00 MB/s)
```

Sixteen workers collapse to one in five seconds, and the collapse is
self-reinforcing: each cut lowers the rate, which justifies the next cut. On a
15-second test an arm never recovers. With the controller disabled the same run
prints one line — `Upload workers: 16/16` — and holds it.

**The reason we remove it is not that it is slow — it is that it makes the knob
lie.** We expose this number to users as "Threads". A control that silently means
"at most this many, for a while" is a defect of the interface whatever its effect
on throughput, and it makes a fixed-`t` comparison meaningless.

⚠️ What we deliberately KEEP from 1.7.11 is its confirmed-byte accounting: upload
bytes count only after the server's response, so redirected or rejected requests
no longer inflate the total the way they did in 1.7.10.

## Re-applying after an upstream bump

Find `adaptUploadWorkers` in `speedtest/data_manager.go`. Upstream starts it with:

```go
if td.TestType == typeUpload && td.maxWorkers > 1 {
    go td.adaptUploadWorkers()
}
```

Replace the body with `_ = td.adaptUploadWorkers` (keeping the reference so the
function does not become unused) and re-check that a debug run prints a single
`Upload workers: N/N` line.

## Third divergence: `SetEarlyStop(bool)` — added, default unchanged

Upstream ends a phase as soon as the rate has been stable (CV < 3%) for a third
of its 5 s window, with a floor of `minSteps = 2 × windowSize`. In practice
**every phase ends at ~10 s whatever capture time was asked for** — a requested
15 s produced an actual 10.1 s in seven runs out of seven on 2026-08-19, and
again on the 20th.

For "how fast is my line right now" that is a feature and it stays ON by default.
For a COMPARISON it is fatal: a fixed measurement window is exactly what makes
runs at different thread counts comparable, and it cannot be had while the engine
decides for itself when it has seen enough. Research mode calls
`SetEarlyStop(false)`; measured effect, same server and laptop:

```
early stop ON   actual 10.1 s   (15 s requested)
early stop OFF  actual 20.0 s   (5 s warm-up + 15 s window, as asked)
```

Re-apply after an upstream bump: the guard is `&& !td.manager.noEarlyStop` at the
`td.welford.Update(...)` call site in `rateCapture()`, plus the field, the setter
and the `Manager` interface entry. `fork_guard_test.go` fails if it goes missing.
