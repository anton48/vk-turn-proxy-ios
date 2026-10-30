# Vendored fork of `pion/turn` v5.0.2

Upstream: https://github.com/pion/turn — **MIT**, see `LICENSE` (kept verbatim;
MIT inside our GPL-3 tree, like the other Pion sources).

The whole module is vendored (every file, examples and tests included), so
that `tools/turn-relay`'s `go.mod` can `replace github.com/pion/turn/v5` with
this tree. The app and the console keep using pristine upstream from the
module cache: this fork is for the relay tool ONLY.

**ONE deliberate divergence**, guarded by `FORK.patch`:

| # | divergence | file |
|---|---|---|
| 1 | the request's MESSAGE-INTEGRITY is not checked (`authenticateRequest`) | `internal/server/util.go` |

Why: the relay stands in the TURN override list of a client that signs its
requests with the credentials VK issued — a password this server cannot know
(issue #105: the user's own relay first, VK's relays after it; the issue's
author runs the same patch). The `AuthHandler` still names the user and hands
a key for the responses, which the pion client never verifies; the nonce is
still validated. What keeps the relay from being an open one is the
`PermissionHandler` (the peers allowed) and the `QuotaHandler` (the
allocations), set by `tools/turn-relay`.

Re-apply recipe (after an upstream bump): in `internal/server/util.go`,
`authenticateRequest`, replace the `stun.MessageIntegrity(ourKey).Check(…)`
block (the failed-auth event and the 400) with `_ = ourKey` and the comment
above it; keep `genAuthEvent(…, true)`. Then regenerate `FORK.patch`:

    cd third_party/pion-turn && UPDATE_FORK_PATCH=1 go test . -run TestForkDiverges

Upstream's own tests still run in the gate (`tools/test.sh`) except
`TestServerVNet/AuthEventHandlerFailure`, which waits for the auth-failure
event a bad signature raised — the fork raises none (the test panics on its
closed channel instead of failing), and `TestConnectRequest`, an environment
flake (it dials 127.0.0.1:5000 expecting a refusal; a Mac's AirPlay receiver
answers there).

`TestForkDivergesFromUpstreamExactlyHere` (`fork_upstream_diff_test.go`) diffs
this tree against pristine upstream in the module cache and compares the
result with `FORK.patch` — the fork, in full. It FATALS when upstream is not
in the cache (`go mod download github.com/pion/turn/v5@v5.0.2`).
