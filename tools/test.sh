#!/usr/bin/env bash
# Run EVERY test suite in this repository.
#
#   ./tools/test.sh
#
# 🚨 WHY THIS FILE EXISTS. The suites live in three places that no single command
# reaches:
#
#   1. pkg/... and the rest of the root module   — `go test ./...`
#   2. third_party/speedtest-go                  — a SEPARATE module behind a
#      `replace`, so the root `./...` does not see it. Its fork guards had never
#      been run by anything except a human typing the command.
#   3. tools/swiftcheck                          — a compiled Swift harness.
#
# Recording three commands in three files is the same defect as a harness that is
# green, sabotage-validated and not in the repo: a recorded way to run something
# that does not run. One entry point, and it is the one release.sh calls.
set -uo pipefail
cd "$(dirname "$0")/.."

RACE=${RACE:-1}
fail=0
run() {
    echo
    echo "══ $1"
    shift
    if "$@"; then
        echo "   PASS"
    else
        echo "   FAIL"
        fail=1
    fi
}

goflags=(-count=1)
[ "$RACE" = "1" ] && goflags+=(-race)

# 🚨 MAKE THE MACHINE READY, DO NOT ASSUME IT IS. The fork's
# TestForkDivergesFromUpstreamExactlyHere diffs the vendored tree against
# PRISTINE upstream, which it reads from the module cache. On a clean checkout
# that cache is cold and the test t.Fatals -- correctly, because a guard that
# SKIPS itself when its input is missing is green on every machine nobody set
# up. Fetching it here is what makes this script self-sufficient.
#
# The `@version` form fetches real upstream despite the `replace` in go.mod that
# points the module at ./third_party/speedtest-go -- which is exactly the point:
# the guard needs the original to compare against. Checksum-verified against the
# public sumdb (this repo's go.sum has no showwin entry, again because of the
# replace).
UPSTREAM=github.com/showwin/speedtest-go@v1.7.11
echo "== fetching pristine $UPSTREAM for the fork's upstream-diff guard"
if go mod download "$UPSTREAM"; then
    echo "   ready"
else
    echo "   FAIL: could not fetch $UPSTREAM -- the fork's divergence guard cannot run" >&2
    fail=1
fi

run "root module — go test ${goflags[*]} ./..." \
    go test "${goflags[@]}" ./...

# 🚨 The fork's guards include TestForkDivergesFromUpstreamExactlyHere, which
# needs pristine upstream in the module cache. It FATALS rather than skipping if
# it is cold — a guard that skips itself is a guard that is green everywhere it
# has not been set up.
run "vendored fork — separate module, not reached by the root ./..." \
    env -C third_party/speedtest-go go test "${goflags[@]}" ./speedtest/

run "swiftcheck — Swift value types and source scans" \
    ./tools/swiftcheck/run.sh

echo
if [ "$fail" = 0 ]; then
    echo "all suites passed"
    exit 0
fi
echo "SUITES FAILED"
exit 1
