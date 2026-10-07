package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvePath(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "real", "sub"), 0o755)
	os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	real := resolvePath(filepath.Join(dir, "real", "sub", "file"))
	for _, p := range []string{dir + "//real/sub/file", dir + "/real/./sub/file", dir + "/real/x/../sub/file", dir + "/link/sub/file", dir + "/link/sub/../sub/file"} {
		if got := resolvePath(p); got != real {
			t.Errorf("resolvePath(%q) = %q, want %q", p, got, real)
		}
	}
}

func TestProtectedPath(t *testing.T) {
	for _, p := range []string{
		"/etc/askyourstack/agent.json", "/etc//askyourstack/agent.json", "/etc/./askyourstack/agent.json", "/etc/x/../askyourstack/agent.json",
		"/etc/sudowhizzy/agent.json", "/etc/askyourstack", "/usr/local/bin/askyourstack-agent", "/usr/local/bin/askyourstack-agent.prev",
		"/etc/systemd/system/askyourstack-agent.service", "/etc/systemd/system/sudowhizzy-agent.service",
	} {
		if !protectedPath(p) {
			t.Errorf("%s should be protected", p)
		}
	}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/var/www/site/index.php", "/etc/askyourstackx/y", "/home/u/.config/other/agent.json"} {
		if protectedPath(p) {
			t.Errorf("%s should not be protected", p)
		}
	}
	dir := t.TempDir()
	os.Symlink("/etc/askyourstack", filepath.Join(dir, "innocent"))
	if !protectedPath(filepath.Join(dir, "innocent", "agent.json")) {
		t.Error("a symlink into the agent folder should be protected")
	}
}

func TestWriteFileThroughAndRefusals(t *testing.T) {
	dir := t.TempDir()
	backupDir = filepath.Join(dir, "backups")
	target := filepath.Join(dir, "a.conf")
	os.WriteFile(target, []byte("old"), 0o640)
	os.Symlink(target, filepath.Join(dir, "a.link"))
	raw, _ := json.Marshal(map[string]string{"path": filepath.Join(dir, "a.link"), "content": "new"})
	if _, err := writeFile(raw); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new" {
		t.Errorf("write through the symlink: target holds %q", b)
	}
	if fi, _ := os.Lstat(filepath.Join(dir, "a.link")); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a file")
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %o", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".sw-write-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	raw, _ = json.Marshal(map[string]string{"path": "/etc//askyourstack/agent.json", "content": "x"})
	if _, err := writeFile(raw); err == nil || !strings.Contains(err.Error(), "agent's own") {
		t.Errorf("writing the agent's config should be refused, got %v", err)
	}
	raw, _ = json.Marshal(map[string]string{"path": "/etc/./askyourstack/agent.json"})
	if _, err := readFile(raw); err == nil || !strings.Contains(err.Error(), "agent's own") {
		t.Errorf("reading the agent's config should be refused, got %v", err)
	}
}

func TestInternalIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"} {
		if !internalIP(net.ParseIP(s)) {
			t.Errorf("%s should be internal", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2.28.7.108", "2a01:4f8:c17:32fe::1", "1.1.1.1"} {
		if internalIP(net.ParseIP(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}
