package proxy

import (
	"strings"
	"testing"
	"time"
)

// armCover switches the assignment mode for one test and restores it after: the
// globals are shared, so without this one test's mode leaks into the next.
func armCover(t *testing.T, on bool) {
	t.Helper()
	prev := flowPathsCover.Load()
	t.Cleanup(func() { flowPathsCover.Store(prev) })
	SetFlowPathsCover(on)
}

func distinctPaths(t *flowTable, keys []uint64, k int) int {
	seen := map[int32]bool{}
	for _, key := range keys {
		for _, p := range t.paths(key, k).paths {
			seen[p] = true
		}
	}
	return len(seen)
}

// 🎯 THE CLAIM THE WHOLE DESIGN RESTS ON: at the SAME k, sets built to complement
// each other cover far more of the pool than independent random ones.
//
// This is the arithmetic that chose greedy cover over adaptive k: with F flows of
// k paths each, independent sets leave a path unused with probability
// ((N-k)/N)^F, so F=4 at k=8 reaches only ~21 of 30 — the "raise k and hope"
// route pays full locality and still starves a third of the pool. A cover reaches
// every path as long as F*k >= N.
func TestCoverReachesTheWholePoolWhereRandomDoesNot(t *testing.T) {
	keys := []uint64{0x1111, 0x2222, 0x3333, 0x4444} // F=4, the speedtest corner
	const k, n = 8, 30

	armCover(t, false)
	randDistinct := distinctPaths(newFlowTable(n), keys, k)

	armCover(t, true)
	coverDistinct := distinctPaths(newFlowTable(n), keys, k)

	if coverDistinct != n {
		t.Fatalf("cover reached %d of %d paths with F*k = %d >= N — a greedy cover "+
			"must use every path before it reuses one", coverDistinct, n, len(keys)*k)
	}
	if randDistinct >= n-3 {
		t.Fatalf("random assignment reached %d of %d, so this test is not comparing "+
			"anything — the arithmetic says ~21", randDistinct, n)
	}
	t.Logf("F=%d k=%d: cover %d/%d vs random %d/%d", len(keys), k, coverDistinct, n, randDistinct, n)
}

// Distinctness is not cosmetic under cover either: k copies of one index is k=1
// wearing a costume, and k=1 is the measured -79%.
func TestCoverSetsAreDistinct(t *testing.T) {
	armCover(t, true)
	tbl := newFlowTable(30)
	for key := uint64(1); key < 200; key++ {
		for k := FlowPathsMin; k <= FlowPathsMax; k++ {
			seen := map[int32]bool{}
			for _, p := range tbl.paths(key*1000+uint64(k), k).paths {
				if seen[p] {
					t.Fatalf("k=%d: duplicate path %d", k, p)
				}
				seen[p] = true
			}
		}
	}
}

// 🚨 THE COUNTS MUST BE RELEASED ON BOTH EXITS. If they are not, every path looks
// equally loaded within minutes and the greedy cover silently degenerates into a
// fixed round-robin by index — the same coverage it was built to fix, with no
// symptom in the log.
func TestCoverReleasesOnReassignAndEviction(t *testing.T) {
	armCover(t, true)
	tbl := newFlowTable(30)

	sum := func() int32 {
		tbl.mu.Lock()
		defer tbl.mu.Unlock()
		var s int32
		for _, c := range tbl.assign {
			s += c
		}
		return s
	}

	tbl.paths(0xabc, 3)
	if got := sum(); got != 3 {
		t.Fatalf("after one k=3 flow the pool holds %d assignments, want 3", got)
	}
	// A live k change re-assigns: the old width must be given back first.
	tbl.paths(0xabc, 8)
	if got := sum(); got != 8 {
		t.Fatalf("after raising the same flow to k=8 the pool holds %d, want 8 — the "+
			"old set was not released, so this flow is charged twice", got)
	}

	// And eviction: age everything past the TTL and sweep.
	tbl.paths(0xdef, 5)
	tbl.mu.Lock()
	tbl.evictLocked(time.Now().Add(2 * flowPathsIdleTTL).UnixNano())
	tbl.mu.Unlock()
	if got := sum(); got != 0 {
		t.Fatalf("after evicting every flow the pool still holds %d assignments — the "+
			"counts drift up and the cover degenerates into round-robin", got)
	}
}

// Flipping the mode must re-assign, or a run measures a mixture of both and the
// result cannot be attributed to either.
func TestModeFlipReassignsTheFlow(t *testing.T) {
	armCover(t, true)
	tbl := newFlowTable(30)
	before := append([]int32(nil), tbl.paths(0x5150, 5).paths...)

	armCover(t, false)
	after := tbl.paths(0x5150, 5).paths

	same := len(before) == len(after)
	if same {
		for i := range before {
			if before[i] != after[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("the flow kept its cover-built set after the mode was switched off — " +
			"a run could then be half one assignment and half the other")
	}
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	for i, c := range tbl.assign {
		if c != 0 {
			t.Fatalf("path %d still holds %d cover assignments after the flow left "+
				"cover mode", i, c)
		}
	}
}

// The memstats field must name the mode, or two sessions' numbers are compared
// without anything in the log saying they were produced by different assignments.
func TestSummaryNamesTheAssignmentMode(t *testing.T) {
	armFlowPaths(t, 5)
	p, cancel := newFlowProxy(t, 30)
	defer cancel()
	p.flowPathStats.pref.Add(1)

	armCover(t, false)
	if s := p.flowPathStats.summary(p.flows); !strings.Contains(s, "k=5/rand") {
		t.Fatalf("summary = %q, want it to carry k=5/rand", s)
	}
	p.flowPathStats.pref.Add(1)
	armCover(t, true)
	if s := p.flowPathStats.summary(p.flows); !strings.Contains(s, "k=5/cover") {
		t.Fatalf("summary = %q, want it to carry k=5/cover", s)
	}
}
