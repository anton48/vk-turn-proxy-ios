package turn

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// upstreamVersion is the release this fork is taken from. FORK.md's title says
// the same thing; if you bump one, bump both.
const upstreamVersion = "v5.0.2"

// What FORK.md documents: the files with a divergence. WHAT changed inside
// them is pinned by the golden patch (forkPatchFile) — a count is no check on
// content (see third_party/speedtest-go, where this guard comes from).
var (
	wantChangedFiles = []string{"internal/server/util.go"}
	wantAddedFiles   = []string{"fork_upstream_diff_test.go"}
)

// TestForkDivergesFromUpstreamExactlyHere diffs the vendored tree against
// pristine upstream in the module cache and fails on ANY .go file that differs
// beyond the list above, and on any difference inside those files beyond
// FORK.patch. 🚨 FATAL, NEVER SKIP, when upstream is not in the cache.
func TestForkDivergesFromUpstreamExactlyHere(t *testing.T) {
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	upstream := filepath.Join(strings.TrimSpace(string(out)), "github.com/pion/turn/v5@"+upstreamVersion)
	if _, err := os.Stat(upstream); err != nil {
		t.Fatalf("pristine upstream not in the module cache (%v).\nPopulate it with:\n    go mod download github.com/pion/turn/v5@%s", err, upstreamVersion)
	}
	changed, added, removed := diffTrees(t, upstream, ".")
	if d := difference(changed, wantChangedFiles); len(d) > 0 {
		t.Errorf("UNDOCUMENTED divergence — these files differ from upstream %s and are not in FORK.md: %v", upstreamVersion, d)
	}
	if d := difference(wantChangedFiles, changed); len(d) > 0 {
		t.Errorf("FORK.md claims a divergence in %v but they are IDENTICAL to upstream — the fork was lost or FORK.md is stale", d)
	}
	got := forkPatch(t, upstream, changed)
	if os.Getenv("UPDATE_FORK_PATCH") != "" {
		if err := os.WriteFile(forkPatchFile, []byte(got), 0o644); err != nil {
			t.Fatalf("write %s: %v", forkPatchFile, err)
		}
		t.Logf("regenerated %s — READ IT before committing; it is the fork, in full", forkPatchFile)
		return
	}
	want, err := os.ReadFile(forkPatchFile)
	if err != nil {
		t.Fatalf("read %s: %v\n%s", forkPatchFile, err, regenHint)
	}
	if got != string(want) {
		t.Errorf("THE FORK'S CONTENT CHANGED — %s no longer matches the tree.\n%s\n\nfirst difference:\n%s", forkPatchFile, regenHint, firstDifference(string(want), got))
	}
	if d := difference(added, wantAddedFiles); len(d) > 0 {
		t.Errorf("files added to the vendored tree without being listed here: %v", d)
	}
	if len(removed) > 0 {
		t.Errorf("upstream files DELETED from the vendored tree: %v — the fork is not a superset of upstream any more", removed)
	}
}

const forkPatchFile = "FORK.patch"

const regenHint = "regenerate with:\n    cd third_party/pion-turn && UPDATE_FORK_PATCH=1 go test . -run TestForkDiverges"

// forkPatch builds the normalised patch for the whole fork: `diff -u` per
// changed file, the `---`/`+++` header lines dropped (absolute paths, times).
func forkPatch(t *testing.T, upstream string, changed []string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range changed {
		fmt.Fprintf(&b, "=== %s ===\n", name)
		out := runDiff(t, filepath.Join(upstream, name), name)
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
				continue
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func firstDifference(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("  line %d\n    golden: %q\n    tree:   %q", i+1, wl, gl)
		}
	}
	return "  (no line differs — a trailing-newline difference)"
}

// runDiff returns `diff -u` output; diff exits 1 when the files differ.
func runDiff(t *testing.T, upstreamPath, ourPath string) string {
	t.Helper()
	out, err := exec.Command("diff", "-u", upstreamPath, ourPath).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("diff -u %s %s: %v", upstreamPath, ourPath, err)
		}
	}
	return string(out)
}

// diffTrees compares every .go file of two module trees, by relative path.
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
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no .go files under %s — the anchor is wrong and every check would be vacuous", dir)
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
