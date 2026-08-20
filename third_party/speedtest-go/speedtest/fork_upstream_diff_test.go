package speedtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// upstreamVersion is the release this fork is taken from. FORK.md's title says
// the same thing; if you bump one, bump both.
const upstreamVersion = "v1.7.11"

// What ../FORK.md documents. Every entry here is a divergence with a re-apply
// recipe in that file.
var (
	wantChangedFiles = []string{"data_manager.go", "request.go", "speedtest.go"}
	wantAddedFiles   = []string{
		"fork_cancel_test.go",
		"fork_doer_test.go",
		"fork_guard_test.go",
		"fork_upstream_diff_test.go",
		"fork_workers_test.go",
	}
)

// TestForkDivergesFromUpstreamExactlyHere is the guard the source scans cannot be.
//
// 🚨 A SCAN CAN ONLY FIND A TOKEN SOMEBODY THOUGHT TO NAME. It is blind to the
// divergence that actually loses methodology: one nobody documented. This test
// diffs the vendored tree against pristine upstream and fails on ANY file that
// differs beyond the list above — so a change smuggled into vendored code is
// caught even though no scan, and no reviewer, was looking for it.
//
// It costs ~0.02 s and needs no network once the module cache is warm.
//
// Arms seen RED before being committed, each on its own sabotage:
//   - append a line to server.go            -> "UNDOCUMENTED divergence ... [server.go]"
//   - add an unlisted zz_unlisted.go        -> "added ... without being listed"
//   - copy upstream's speedtest.go over ours-> "claims a divergence ... but they are IDENTICAL"
//
// The fourth arm (an upstream file DELETED) is deliberately not sabotage-tested:
// removing any upstream .go file breaks compilation before this test can run, so
// the compiler is that arm's guard. The check stays for the case where a deleted
// file happens to compile.
func TestForkDivergesFromUpstreamExactlyHere(t *testing.T) {
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	upstream := filepath.Join(strings.TrimSpace(string(out)),
		"github.com/showwin/speedtest-go@"+upstreamVersion, "speedtest")

	// 🚨 FATAL, NEVER SKIP. A guard that skips itself when its input is missing
	// is a guard that is green on every machine that has not run one command.
	if _, err := os.Stat(upstream); err != nil {
		t.Fatalf("pristine upstream not in the module cache (%v).\n"+
			"Populate it with:\n"+
			"    go mod download github.com/showwin/speedtest-go@%s\n"+
			"(it is checksum-verified against the public sumdb; this repo's go.sum has no\n"+
			"showwin entry because of the `replace` in ../../WireGuardBridge/go.mod)",
			err, upstreamVersion)
	}

	changed, added, removed := diffTrees(t, upstream, ".")

	if d := difference(changed, wantChangedFiles); len(d) > 0 {
		t.Errorf("UNDOCUMENTED divergence — these files differ from upstream %s and are not in "+
			"../FORK.md: %v\nEither revert them, or add a Divergence section with a re-apply recipe "+
			"and list the file here.", upstreamVersion, d)
	}
	if d := difference(wantChangedFiles, changed); len(d) > 0 {
		t.Errorf("../FORK.md claims a divergence in %v but they are IDENTICAL to upstream — "+
			"the fork was lost (an upstream bump overwrote it?) or FORK.md is stale", d)
	}
	if d := difference(added, wantAddedFiles); len(d) > 0 {
		t.Errorf("files added to the vendored tree without being listed here: %v", d)
	}
	if len(removed) > 0 {
		t.Errorf("upstream files DELETED from the vendored tree: %v — the fork is not a "+
			"superset of upstream any more", removed)
	}
}

// diffTrees compares two flat directories of .go files.
func diffTrees(t *testing.T, upstream, ours string) (changed, added, removed []string) {
	t.Helper()
	up := goFiles(t, upstream)
	mine := goFiles(t, ours)
	for name, sum := range mine {
		if upSum, ok := up[name]; !ok {
			added = append(added, name)
		} else if upSum != sum {
			changed = append(changed, name)
		}
	}
	for name := range up {
		if _, ok := mine[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func goFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(b)
	}
	if len(out) == 0 {
		t.Fatalf("no .go files under %s — the anchor is wrong and every check below would be vacuous", dir)
	}
	return out
}

func difference(a, b []string) (only []string) {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			only = append(only, x)
		}
	}
	return
}
