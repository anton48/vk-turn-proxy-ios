package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 🚨 `include/wireguard_turn.h` IS HAND-MAINTAINED, and forgetting to declare a
// new `//export` there has cost this project three separate incidents: the
// xcframework builds, the header ships without the symbol, and Swift cannot see
// it. The compiler catches it eventually — at the app build, minutes later, in a
// different repo directory, with an error that names Swift rather than this file.
//
// This test moves that failure to where the omission is made.
//
// SABOTAGE SEEN TO FAIL: delete the `void wgSetUplinkChunkK(int32_t k);` line
// from include/wireguard_turn.h. Compiles; this test then names it.
func TestEveryExportIsDeclaredInTheHandMaintainedHeader(t *testing.T) {
	header, err := os.ReadFile(filepath.Join("include", "wireguard_turn.h"))
	if err != nil {
		t.Fatalf("reading the header: %v", err)
	}
	h := string(header)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	re := regexp.MustCompile(`(?m)^//export\s+(\w+)`)

	var missing []string
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			name := m[1]
			seen++
			// The declaration is matched with its opening parenthesis, so a
			// symbol that appears only inside a COMMENT in the header does not
			// count as declared — a comment is exactly what a half-done removal
			// leaves behind.
			if !strings.Contains(h, name+"(") {
				missing = append(missing, name+" (in "+f+")")
			}
		}
	}

	if seen == 0 {
		t.Fatal("no //export directives found at all — this test has stopped testing anything")
	}
	if len(missing) > 0 {
		t.Fatalf("these //export symbols are not declared in include/wireguard_turn.h, "+
			"so Swift cannot see them:\n  %s", strings.Join(missing, "\n  "))
	}
}
