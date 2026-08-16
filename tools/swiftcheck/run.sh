#!/usr/bin/env bash
# Run the swiftcheck harness.
#
# 🚨 THE FILE LIST LIVES HERE AND NOWHERE ELSE. It used to live in a comment at the
# top of main.swift, and section 11 added UplinkPace — which pulls in SharedLogger,
# which pulls in AppEntitlements — so the documented command stopped compiling while
# the harness itself was fine. A recorded way to run something that does not run is
# the same family as the harness that was green, sabotage-validated, and NOT IN THE
# REPO. One copy, and it is executable, so it cannot drift silently.
#
#   ./tools/swiftcheck/run.sh
#
# Run from the repository root. Exits non-zero on any failed check.
set -euo pipefail
cd "$(dirname "$0")/../.."
S=VKTurnProxy/VKTurnProxy

# 🚨 EVERY INPUT — AND THIS SCRIPT — MUST BE TRACKED. `tools/.gitignore` is a
# blanket `*` with re-includes, and it has now silently dropped three things that
# belong in the repo: the harness itself, the log scorers, and this runner. The
# failure mode is a fresh clone where the test simply is not there, which no local
# run can notice. Checking here means the NEXT file added to this directory is
# caught the first time anyone runs the harness, not a month later.
# *(User-caught three times; made structural 2026-08-16.)*
require_tracked() {
    local missing=()
    for f in "$@"; do
        git ls-files --error-unmatch "$f" >/dev/null 2>&1 || missing+=("$f")
    done
    if [ ${#missing[@]} -ne 0 ]; then
        echo "FAIL: not tracked by git, so a fresh clone cannot run this:" >&2
        printf '  %s\n' "${missing[@]}" >&2
        echo "Fix tools/.gitignore (it is a blanket '*' with re-includes) and commit them." >&2
        exit 1
    fi
}
OUT="$(mktemp -d)/swiftcheck"
require_tracked "$0" tools/swiftcheck/main.swift

swiftc -o "$OUT" \
    tools/swiftcheck/main.swift \
    "$S/UplinkChunk.swift" \
    "$S/ProbeDuration.swift" \
    "$S/LoadWitness.swift" \
    "$S/LoadProgress.swift" \
    "$S/DiagnosticRunLock.swift" \
    "$S/UplinkPace.swift" \
    "$S/SharedLogger.swift" \
    "$S/AppEntitlements.swift"
exec "$OUT"
