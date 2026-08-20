# Vendored fork of `showwin/speedtest-go` v1.7.11

Upstream: https://github.com/showwin/speedtest-go — **MIT**, see `LICENSE`
(kept verbatim; MIT inside our GPL-3 tree, like the Pion sources).

Only the `speedtest/` library package is vendored. Upstream's module root is a
CLI and would drag kingpin/ysmrr/colorable/isatty/runewidth/term in with it; the
library needs nothing outside the standard library.

**FIVE deliberate divergences**, each with its own re-apply recipe below:

| # | divergence | guarded by |
|---|---|---|
| 1 | the adaptive upload controller is not started | source scan |
| 2 | upstream's `runtime.NumCPU()` clamp on the initial worker count is removed — **only visible once (1) is done** | source scan |
| 3 | `SetEarlyStop(bool)` is added | source scan |
| 4 | `New()` gets its OWN `*http.Client` instead of `http.DefaultClient` | **value test** |
| 5 | a cancelled context ENDS the phase | **value test, through the call sites** |

1-3 cannot be caught by their values on the machine we test on, which is why they
are source scans; 4 and 5 can, and are — a scan for them would be ceremony.
🚨 **A scan can only find a token somebody thought to name, so it cannot see a
divergence nobody documented.** That is what
`TestForkDivergesFromUpstreamExactlyHere` is for: it diffs this tree against
pristine upstream in the module cache and compares the result to **`FORK.patch`**
— a generated golden file that IS this fork, in full, 187 lines.

That file is the only check on CONTENT. Counting changed files, hunks or lines
each miss something: hunks merge an adjacent edit into a neighbour, and the same
number of changed lines can be a completely different set of lines. Both were
measured, not assumed. Regenerate it — after documenting the change here —
with:

```
cd third_party/speedtest-go && UPDATE_FORK_PATCH=1 go test ./speedtest/ -run TestForkDiverges
```

and READ the result before committing: it is the whole divergence in one place.

**Where to run it** — the fork is a separate module, so `go test ./...` from the
repo root does NOT reach it:

```
cd third_party/speedtest-go && go test ./speedtest/ -race
```

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

## Divergence 4: `New()` gets its OWN `*http.Client`

`speedtest/speedtest.go`. Upstream:

```go
s := &Speedtest{
    doer:    http.DefaultClient,
    Manager: NewDataManager(),
}
s.NewUserConfig(&UserConfig{UserAgent: DefaultUserAgent})   // ends: s.doer.Transport = s
```

**Why.** `NewUserConfig` finishes with `s.doer.Transport = s`, so with the shared
default **every construction re-points the transport of every existing
instance** — and merely importing the package hijacks the process's
`http.DefaultClient`, because `var defaultClient = New()` runs at init. Measured
before the fix:

```
AT-INIT  http.DefaultClient.Transport = *speedtest.Speedtest   (from the package's own init)
a.doer == b.doer            true    two instances share one *http.Client
a.doer.Transport == b       true    constructing b rewired a
```

That is not theoretical here: this app fetches the SERVER LIST while a
measurement is running, so the second `New()` lands mid-phase.

🚨 **`WithDoer` does not save you, and fails in a way that looks like it worked.**
The default config is applied *before* the option loop, so the global is already
rewired; and the private client is then left with **`Transport == nil`**, silently
falling back to `http.DefaultTransport` — losing the dialer, the User-Agent and
whatever HTTP/2 setting the caller configured:

```
WithDoer alone          -> mine.Transport=false   DefaultClient polluted=true
WithDoer+WithUserConfig -> mine.Transport=true    DefaultClient polluted=true
```

### Re-applying after an upstream bump

Change the literal back to `doer: &http.Client{}` and keep the `// FORK:` comment.
`http.DefaultClient` is `&Client{}`, so `Timeout`/`CheckRedirect`/`Jar` are
identical and the change is behaviour-preserving by construction.
Guard: `fork_doer_test.go` — three assertions, seen red under *restore
`http.DefaultClient`* (all three) and under *delete `s.doer.Transport = s`*
(exactly one).

## Divergence 5: a cancelled context ENDS the phase

`speedtest/data_manager.go` (`TestDirection.Start` takes a `ctx` and watches it)
and the four `Start` call sites in `speedtest/request.go` (`:60`, `:95`, `:123`,
`:154`), plus two in `fork_workers_test.go`.

**Why.** Upstream ends a phase only through `td.closeFunc`, fired by the
`captureTime` timer or by the early-stop path. Nothing watched the caller's
context, and `runWorker` loops on `td.manager.running` — so after a cancel the
requests failed instantly on the dead context and the workers looped again at
once. Measured on this fork before the fix: **cancel at 0.70 s, the phase still
returned at 4.00 s** of a 4 s capture, with only 2 of 9186 requests reaching the
server after the cancel. A download+upload run burned **two** full capture times,
up to ~40 s in research mode, at up to 32 threads, in the app.

🚨 **`closeFunc` is the SINGLE shutdown path.** It is `sync.Once`-wrapped and also
drains and closes `stopCapture` (ending the `rateCapture` goroutine) and calls
`cancel()`. Three owners now funnel through it — the capture timer, the early-stop
path, and this watcher — which is exactly what makes them composable. Ending a
phase by any other route (setting `running`, closing `stopCapture`) breaks the
double-send invariant.

⚠️ `running` is **manager-wide**, not per-direction, so the watcher is a per-phase
guard clearing a manager-scoped flag. That is safe only because download and
upload are serial. The pre-existing capture timer has the identical scope
mismatch; anything proposing concurrent directions on one `DataManager` must
revisit both.

**Considered and rejected**, so nobody re-proposes it: a new file exporting
`StopPhase()` for the wrapper to call, avoiding the signature change. Reading
`td.closeFunc` from a foreign goroutine is an unsynchronised read of a field
written after `rateCapture` starts — a real `-race` hit — and it would be opt-in
at the call site, which is the failure mode being fixed.

### Re-applying after an upstream bump

1. `func (td *TestDirection) Start(ctx context.Context, cancel context.CancelFunc, mainRequestHandlerIndex int)`.
2. Immediately **after** the `td.closeFunc = func(){…}` assignment and before
   `time.AfterFunc`, insert the watcher:

```go
stopWatch := make(chan struct{})
defer close(stopWatch)
go func() {
    select {
    case <-ctx.Done():
        td.closeFunc()
    case <-stopWatch:
    }
}()
```

🚨 **Position is load-bearing**: spawning it any earlier races the `td.closeFunc`
assignment against `rateCapture`, which already reads that field.
`defer close(stopWatch)` runs after `wg.Wait()`, so the watcher cannot outlive the
phase even if a future caller passes the parent context.

3. Pass `_context` — the context the handlers use — at all four `request.go` call
   sites. A signature change rather than a setter is deliberate: omission is a
   **compile error** at every site, where a forgotten setter would silently
   restore the spin.

Guard: `fork_cancel_test.go`, which enters through `downloadTestContext` /
`uploadTestContext` with an injected request func and no network (0.2 s).
🚨 **A test that calls `Start` directly is GREEN while the defect is live** —
verified by putting `context.Background()` back at `request.go:123`: the direct
test passed, this one failed on `download` and passed on `upload`.
