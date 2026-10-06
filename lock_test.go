package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLockRefuses(t *testing.T) {
	old := lockFile
	lockFile = filepath.Join(t.TempDir(), "lock")
	defer func() { lockFile = old }()

	if got := lockRefuses("run", nil); got != "" {
		t.Fatalf("unlocked agent refused run: %q", got)
	}
	if err := os.WriteFile(lockFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"run", "write_file", "rollback", "job_start", "site_cli", "xfer_allow", "db_restore", "images_convert"} {
		if got := lockRefuses(op, nil); got == "" {
			t.Errorf("locked agent ran %s", op)
		}
	}
	for op := range readOps {
		if got := lockRefuses(op, nil); got != "" {
			t.Errorf("locked agent refused the read %s: %q", op, got)
		}
	}
	if got := lockRefuses("db_query", json.RawMessage(`{"read_only":true}`)); got != "" {
		t.Errorf("read-only query refused: %q", got)
	}
	if got := lockRefuses("db_query", json.RawMessage(`{"read_only":false}`)); got == "" {
		t.Error("writing query ran on a locked agent")
	}
	if got := lockRefuses("db_query", json.RawMessage(`{}`)); got == "" {
		t.Error("query without read_only ran on a locked agent")
	}
}
