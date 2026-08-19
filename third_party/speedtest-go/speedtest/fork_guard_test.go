package speedtest

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// None of the THREE fork changes (see ../FORK.md) can be guarded by their
// VALUES, and finding that out cost two vacuous tests on 2026-08-20:
//
//   - restoring the adaptive controller changes nothing in a unit test, because
//     with no confirmed bytes flowing its `delta <= 0` branch continues and it
//     never cuts;
//   - restoring upstream's NumCPU clamp changes nothing on a host with 8 or more
//     cores, because the clamp is min(NumCPU, maxWorkers) and maxWorkers <= 8 is
//     its own precondition. It is invisible on this laptop and bites on a
//     6-core phone — the machine that cannot run this test;
//   - restoring early stop shows up only as a DURATION, which needs a real
//     network phase (~10 s against ~20 s) — not something a unit test may hold.
//
// So the guard is a source scan, which is host-independent and targets exactly
// what a future upstream bump would put back. All three assertions were seen RED
// under the edits they name before being committed.
func TestForkChangesAreStillApplied(t *testing.T) {
	src, err := os.ReadFile("data_manager.go")
	if err != nil {
		t.Fatalf("read data_manager.go: %v", err)
	}
	// Strip // comments first. Without this the scan reads PROSE: the very
	// comment explaining why the clamp was removed contains "runtime.NumCPU()"
	// and reddened the check on a clean tree. Build 298 learned this in the main
	// repo; it is the same mistake one directory over.
	body := regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(string(src), "")

	if strings.Contains(body, "go td.adaptUploadWorkers()") {
		t.Error("the adaptive upload controller is started again — see ../FORK.md; " +
			"with it, the thread count is a ceiling for a controller that cut 16 workers to 1 in five seconds")
	}

	start := strings.Index(body, "func (td *TestDirection) Start(")
	if start < 0 {
		t.Fatal("TestDirection.Start not found — the scan below is meaningless, fix the anchor")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not delimit TestDirection.Start")
	}
	if !strings.Contains(body, "&& !td.manager.noEarlyStop") {
		t.Error("the early-stop guard is gone — see ../FORK.md; without it every phase ends at " +
			"its ~10 s floor whatever capture time was asked for, and research mode cannot hold a fixed window")
	}

	if strings.Contains(body[start:start+1+end], "runtime.NumCPU()") {
		t.Error("Start() consults runtime.NumCPU() again — upstream's clamp on the INITIAL upload " +
			"worker count is back; with the adaptive controller removed it is permanent, so Threads=8 " +
			"would run fewer workers forever on a phone with fewer cores while Threads=16 ran 16")
	}
}
