package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A root agent refuses a path that goes through another user's symlink, and follows
// root's own. Needs root to make a symlink owned by someone else; skipped otherwise.
func TestForeignLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a symlink")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(dir, "own")
	if err := os.Symlink(target, own); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(dir, "theirs")
	if err := os.Symlink(target, theirs); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(theirs, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := foreignLink(filepath.Join(own, "f")); err != nil {
		t.Errorf("root's own link refused: %v", err)
	}
	if err := foreignLink(filepath.Join(target, "f")); err != nil {
		t.Errorf("plain path refused: %v", err)
	}
	if err := foreignLink(filepath.Join(theirs, "f")); err == nil {
		t.Error("another user's link in the path was followed")
	}
	if err := foreignLink(filepath.Join(theirs, "new", "deeper")); err == nil {
		t.Error("another user's link followed by missing parts was followed")
	}
	if err := foreignLink(filepath.Join(dir, "missing", "f")); err != nil {
		t.Errorf("a missing path refused: %v", err)
	}
}
