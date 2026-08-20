#!/usr/bin/env bash
# Run the swiftcheck harness.
#
#   ./tools/swiftcheck/run.sh
#
# 🚨 THE FILE LIST LIVES HERE AND NOWHERE ELSE. It used to live in a comment at
# the top of main.swift, and a section that added one source silently broke the
# documented command while the harness itself was fine. A recorded way to run
# something that does not run is the same family of defect as a harness that is
# green, sabotage-validated, and not in the repo.
#
# Run from anywhere; exits non-zero on any failed check.
set -euo pipefail
cd "$(dirname "$0")/../.."
S=VKTurnProxy/VKTurnProxy

# 🚨 EVERY INPUT — AND THIS SCRIPT — MUST BE TRACKED BY GIT. On this branch the
# whole `tools/` tree was untracked, so a fresh clone would have had the
# instructions and not the harness, and no local run could notice: the files are
# right there in the working copy. Checking here means the NEXT file added to this
# directory is caught the first time anyone runs the harness.
# *(The same trap cost this project three separate files on flow-local-path.)*
require_tracked() {
    local missing=()
    for f in "$@"; do
        git ls-files --error-unmatch "$f" >/dev/null 2>&1 || missing+=("$f")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "FAIL: not tracked by git, so a fresh clone cannot run this:" >&2
        printf '  %s\n' "${missing[@]}" >&2
        echo "git add them and commit." >&2
        exit 1
    fi
}

SOURCES=(
    tools/swiftcheck/main.swift
    "$S/UplinkPace.swift"
    "$S/UplinkPaceSync.swift"
    "$S/UplinkSynth.swift"
    "$S/DirectRouteSync.swift"
    "$S/SpeedTestPath.swift"
    "$S/SpeedTestRunConfig.swift"
    "$S/SpeedTestServerList.swift"
    "$S/SpeedTestWire.swift"
    "$S/SpeedTestLog.swift"
    "$S/SharedLogger.swift"
    "$S/AppEntitlements.swift"
)

require_tracked "$0" "${SOURCES[@]}"

OUT="$(mktemp -d)/swiftcheck"
swiftc -o "$OUT" "${SOURCES[@]}"
exec "$OUT"
