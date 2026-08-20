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
