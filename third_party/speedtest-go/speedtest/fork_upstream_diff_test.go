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
//
// 🚨 THE SIZE OF EACH DIVERGENCE IS PART OF THE CONTRACT, NOT DECORATION.
// Listing only the FILE SET lets any further edit hide inside a file that is
// already permitted — and data_manager.go is permitted, so a second change there
// would pass unnoticed.
//
// 🚫 IT COUNTS CHANGED LINES, NOT HUNKS, AND THAT WAS MEASURED THE HARD WAY: a
// hunk count is blind to an edit ADJACENT to an existing divergence, because
// diff merges it into the neighbouring hunk. Sabotaged with one comment line
// added above `func (td *TestDirection) Start(` — still 7 hunks, still green.
// Changed lines catch it; hunks are kept only in the failure message, where they
// help locate the change.
//
// The counts are MEASURED: `diff -u <upstream> <ours> | grep -cE '^[-+]([^-+]|$)'`.
// They are meant to be brittle. A change that moves one is a change somebody has
// to acknowledge in FORK.md.
var (
	wantChangedFiles = map[string]int{
		"data_manager.go": 76, // divergences 1, 2, 3, 5
		"request.go":      8,  // divergence 5's four Start call sites
		"speedtest.go":    11, // divergence 4
	}
	wantAddedFiles = []string{
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
//   - one extra line inside data_manager.go -> "diverges ... in 77 changed lines, want 76"
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

	wantNames := make([]string, 0, len(wantChangedFiles))
	for name := range wantChangedFiles {
		wantNames = append(wantNames, name)
	}
	sort.Strings(wantNames)

	if d := difference(changed, wantNames); len(d) > 0 {
		t.Errorf("UNDOCUMENTED divergence — these files differ from upstream %s and are not in "+
			"../FORK.md: %v\nEither revert them, or add a Divergence section with a re-apply recipe "+
			"and list the file here.", upstreamVersion, d)
	}
	if d := difference(wantNames, changed); len(d) > 0 {
		t.Errorf("../FORK.md claims a divergence in %v but they are IDENTICAL to upstream — "+
			"the fork was lost (an upstream bump overwrote it?) or FORK.md is stale", d)
	}

	// And within each permitted file, the SIZE of the divergence.
	for _, name := range changed {
		want, ok := wantChangedFiles[name]
		if !ok {
			continue // already reported above
		}
		lines, hunks := diffSize(t, filepath.Join(upstream, name), name)
		if lines != want {
			t.Errorf("%s diverges from upstream in %d changed lines across %d hunks, want %d — "+
				"an edit was made inside a file that was already permitted to differ, which the "+
				"file set alone cannot see. If it is deliberate, document it in ../FORK.md and "+
				"update the count here.", name, lines, hunks, want)
		}
	}
	if d := difference(added, wantAddedFiles); len(d) > 0 {
		t.Errorf("files added to the vendored tree without being listed here: %v", d)
	}
	if len(removed) > 0 {
		t.Errorf("upstream files DELETED from the vendored tree: %v — the fork is not a "+
			"superset of upstream any more", removed)
	}
}

// diffSize returns the number of changed lines and of hunks between two files.
//
// It shells out to diff(1) rather than reimplementing an LCS: the numbers have to
// mean what a human gets from `diff -u`, and a hand-rolled approximation that
// disagrees with the tool is worse than no check. diff exits 1 when the files
// differ, which is the expected case here.
func diffSize(t *testing.T, upstreamPath, ourPath string) (lines, hunks int) {
	t.Helper()
	out, err := exec.Command("diff", "-u", upstreamPath, ourPath).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("diff -u %s %s: %v", upstreamPath, ourPath, err)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "@@"):
			hunks++
		case strings.HasPrefix(line, "---"), strings.HasPrefix(line, "+++"):
			// file headers, not content
		case strings.HasPrefix(line, "-"), strings.HasPrefix(line, "+"):
			lines++
		}
	}
	return lines, hunks
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
