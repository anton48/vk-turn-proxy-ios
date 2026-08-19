# Vendored fork of `showwin/speedtest-go` v1.7.11

Upstream: https://github.com/showwin/speedtest-go — **MIT**, see `LICENSE`
(kept verbatim; MIT inside our GPL-3 tree, like the Pion sources).

Only the `speedtest/` library package is vendored. Upstream's module root is a
CLI and would drag kingpin/ysmrr/colorable/isatty/runewidth/term in with it; the
library needs nothing outside the standard library.

**THREE deliberate divergences**, each with its own re-apply recipe below, all
three guarded by `speedtest/fork_guard_test.go` (a source scan — see the note in
that file for why a value-based test cannot catch two of them):

1. the adaptive upload controller is not started;
2. upstream's `runtime.NumCPU()` clamp on the initial upload worker count is
   removed — **this one only becomes visible once (1) is done**;
3. `SetEarlyStop(bool)` is added.

## Divergence 1: adaptive upload concurrency is DISABLED

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

### Re-applying after an upstream bump

Find `adaptUploadWorkers` in `speedtest/data_manager.go`. Upstream starts it with:

```go
if td.TestType == typeUpload && td.maxWorkers > 1 {
    go td.adaptUploadWorkers()
}
```

Replace the body with `_ = td.adaptUploadWorkers` (keeping the reference so the
function does not become unused) and re-check that a debug run prints a single
`Upload workers: N/N` line.

## Divergence 2: the `runtime.NumCPU()` clamp on the initial worker count is REMOVED

`speedtest/data_manager.go`, in `TestDirection.Start`. Upstream clamps the
INITIAL upload worker count to the core count whenever `uploadMaxWorkers <= 8`:

```go
td.maxWorkers = int32(workerLimit)
initialWorkers := td.maxWorkers
if td.TestType == typeUpload {
    if td.manager.uploadMaxWorkers <= 8 {
        initialWorkers = int32(runtime.NumCPU())
        if initialWorkers > td.maxWorkers {
            initialWorkers = td.maxWorkers
        }
    }
}
atomic.StoreInt32(&td.activeWorkers, initialWorkers)
```

**Why it must go once divergence 1 is applied.** Upstream's design is *start
low, let the controller grow back*; the clamp is the low start. With the
controller gone the clamp is **permanent**, and it is not a general throttle —
`SetNThread(n)` for `n >= 1` sets `nThread` and `uploadMaxWorkers` **both** to
`n`, so the precondition `uploadMaxWorkers <= 8` means exactly *the user asked
for eight threads or fewer*. On a 6-core phone the Threads ladder we expose
becomes:

```
requested   1   2   4   8   16   32
actual      1   2   4   6   16   32
                        ^^^ silently
```

So `8` under-delivers while `16` is honoured, the step from 8 to 16 is ×2.7
rather than ×2, and a sweep across the ladder compares two different regimes
without saying so. That is the same defect as divergence 1 — **the knob lies** —
not a throughput argument.

🚨 **It is invisible on the machine we develop on.** The clamp is
`min(NumCPU, workerLimit)` with `workerLimit <= 8` as its own precondition, so on
any host with 8 or more cores it is the identity. No value-based test can catch
it here; that is why the guard is a source scan.

**The default is unchanged**, which is worth checking rather than assuming: with
`SetNThread` never called (or called with `n < 1`) the manager holds
`nThread = NumCPU`, `uploadMaxWorkers = 8`, so `workerLimit = min(NumCPU, 8)` and
the clamp would return that same value.

### Re-applying after an upstream bump

Delete the `if td.TestType == typeUpload { ... }` block quoted above, leaving:

```go
td.maxWorkers = int32(workerLimit)
initialWorkers := td.maxWorkers
atomic.StoreInt32(&td.activeWorkers, initialWorkers)
```

Keep the `// FORK:` comment above it. The guard scans `TestDirection.Start` for
`runtime.NumCPU()` **with comments stripped**, so the explanation may name the
call without reddening the check. Verify with a debug upload run at `-t 8` on a
host with fewer than 8 cores: it must print `Upload workers: 8/8`.

## Divergence 3: `SetEarlyStop(bool)` — added, default unchanged

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

### Re-applying after an upstream bump

The guard is `&& !td.manager.noEarlyStop` at the
`td.welford.Update(...)` call site in `rateCapture()`, plus the field, the setter
and the `Manager` interface entry. `fork_guard_test.go` fails if it goes missing.
