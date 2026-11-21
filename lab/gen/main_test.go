package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesAndChecks(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	// An empty directory is fully out of date.
	stale, err := run(dir, true, &out)
	if err != nil || stale == 0 {
		t.Fatalf("check of an empty directory: stale=%d err=%v", stale, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
		t.Fatal("check mode must not write")
	}
	if _, err := run(dir, false, &out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docker-compose.yml", "generated/states.sh", "ground-truth/t0.json", "ground-truth/t1.json", "ground-truth/t2.json",
		"ground-truth/changes-t0-t1.json", "ground-truth/changes-t1-t2.json", "labsim/hosts/kiosk-1.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not written", name)
		}
	}
	out.Reset()
	stale, err = run(dir, true, &out)
	if err != nil || stale != 0 {
		t.Fatalf("after a write nothing may be stale: stale=%d err=%v\n%s", stale, err, out.String())
	}
	if !strings.Contains(out.String(), "hosts in t0") {
		t.Fatalf("summary line missing: %q", out.String())
	}
}
