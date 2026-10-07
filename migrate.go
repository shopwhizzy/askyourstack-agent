package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The agent was renamed from sudowhizzy-agent to askyourstack-agent on 2026-10-07.
// An agent that finds itself installed under the old name moves itself over, once,
// at startup: binary, configuration and state folders, and the systemd unit or the
// crontab line that keeps it running. Each old path is left as a symlink to the new
// one, so running background jobs, forced SSH commands from migration links, old
// instructions in the docs and the hub's blocked-path rule keep working.
const (
	agentName = "askyourstack-agent"
	oldName   = "sudowhizzy-agent"
)

var migrated = false // set when this process just moved the install: main() reloads its paths

func migrate() {
	if privileged {
		migrateRoot()
	} else {
		migrateUser()
	}
}

// moveDir renames old to new and leaves old as a symlink to new. Nothing happens when
// old is already a symlink or missing, or when new already exists as its own folder.
func moveDir(old, new string) {
	fi, err := os.Lstat(old)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return
	}
	if _, err := os.Lstat(new); err == nil {
		return
	}
	if err := os.Rename(old, new); err != nil {
		fmt.Fprintln(os.Stderr, "rename:", err)
		return
	}
	os.Symlink(new, old)
	migrated = true
}

// moveBinary copies the running binary to new and replaces old with a symlink to it.
func moveBinary(old, new string) {
	fi, err := os.Lstat(old)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	src, err := os.Open(self)
	if err != nil {
		return
	}
	defer src.Close()
	tmp := new + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmp)
		return
	}
	dst.Close()
	if err := os.Rename(tmp, new); err != nil {
		os.Remove(tmp)
		return
	}
	os.Remove(old) // the running process keeps its open image
	os.Symlink(new, old)
	os.Remove(old + ".prev")
	migrated = true
}

func sysctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// switchUnit replaces the unit that runs this process with one of the new name.
// It writes the new unit, starts it, and only when it is active removes the old one
// and exits this process with the code systemd takes as "do not restart". If the new
// unit does not come up, everything is put back and this process carries on.
func switchUnit(user bool, unitDir, newBin string) {
	oldUnit := filepath.Join(unitDir, oldName+".service")
	newUnit := filepath.Join(unitDir, agentName+".service")
	if _, err := os.Lstat(oldUnit); err != nil {
		return // not kept running by this unit
	}
	if fi, err := os.Lstat(oldUnit); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return // already the alias of the new unit
	}
	// Only the process that systemd started under the OLD unit does the switch. The one it
	// starts under the new unit sees the same files for a moment and must not repeat it.
	if cg, err := os.ReadFile("/proc/self/cgroup"); err != nil || !strings.Contains(string(cg), oldName+".service") {
		return
	}
	wanted := "multi-user.target"
	desc := "AskYourStack agent"
	if user {
		wanted = "default.target"
		desc = "AskYourStack agent (user)"
	}
	unit := fmt.Sprintf("[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=%s\nRestart=always\nRestartSec=5\n# 3 = the hub revoked this server; stay stopped.\nRestartPreventExitStatus=3\n\n[Install]\nWantedBy=%s\n", desc, newBin, wanted)
	if err := os.WriteFile(newUnit, []byte(unit), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "unit:", err)
		return
	}
	var pre []string
	if user {
		pre = []string{"--user"}
	}
	run := func(args ...string) error { return sysctl(append(append([]string{}, pre...), args...)...) }
	undo := func(why error) {
		fmt.Fprintln(os.Stderr, "rename: keeping the old unit:", why)
		run("stop", agentName)
		run("disable", agentName)
		os.Remove(newUnit)
		run("daemon-reload")
	}
	if err := run("daemon-reload"); err != nil {
		undo(err)
		return
	}
	if err := run("enable", agentName); err != nil {
		undo(err)
		return
	}
	if err := run("start", "--no-block", agentName); err != nil {
		undo(err)
		return
	}
	active := false
	for i := 0; i < 20 && !active; i++ {
		time.Sleep(500 * time.Millisecond)
		out, _ := exec.Command("systemctl", append(append([]string{}, pre...), "is-active", agentName)...).Output()
		active = strings.TrimSpace(string(out)) == "active"
	}
	if !active {
		undo(fmt.Errorf("%s did not become active", agentName))
		return
	}
	// The new unit runs. Retire the old one: no restart of this process, the old name an alias.
	run("disable", "--no-reload", oldName)
	os.Remove(oldUnit)
	os.Symlink(agentName+".service", oldUnit)
	run("daemon-reload")
	fmt.Fprintln(os.Stderr, "renamed: now running as", agentName)
	os.Exit(exitRevoked)
}

func migrateRoot() {
	moveBinary("/usr/local/bin/"+oldName, "/usr/local/bin/"+agentName)
	moveDir("/etc/sudowhizzy", "/etc/askyourstack")
	moveDir("/var/lib/sudowhizzy", "/var/lib/askyourstack")
	switchUnit(false, "/etc/systemd/system", "/usr/local/bin/"+agentName)
}

func migrateUser() {
	bin := filepath.Join(agentHome, ".local", "bin")
	moveBinary(filepath.Join(bin, oldName), filepath.Join(bin, agentName))
	moveDir(filepath.Join(agentHome, ".config", "sudowhizzy"), filepath.Join(agentHome, ".config", "askyourstack"))
	moveDir(filepath.Join(agentHome, ".local", "share", "sudowhizzy"), filepath.Join(agentHome, ".local", "share", "askyourstack"))
	// A crontab watchdog: point its lines at the new paths. The lock it holds is the same
	// file through the symlink, and this process exits so the next tick starts the new one.
	if out, err := exec.Command("crontab", "-l").Output(); err == nil && strings.Contains(string(out), "# "+oldName) {
		lines := strings.Split(string(out), "\n")
		for i, l := range lines {
			if strings.HasSuffix(strings.TrimSpace(l), "# "+oldName) {
				l = strings.ReplaceAll(l, "/.config/sudowhizzy/", "/.config/askyourstack/")
				l = strings.ReplaceAll(l, "/.local/bin/"+oldName, "/.local/bin/"+agentName)
				lines[i] = strings.TrimSuffix(l, "# "+oldName) + "# " + agentName
			}
		}
		cmd := exec.Command("crontab", "-")
		cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
		if err := cmd.Run(); err == nil {
			fmt.Fprintln(os.Stderr, "renamed: crontab now starts", agentName, "; exiting for the next tick")
			os.Exit(0)
		}
	}
	switchUnit(true, filepath.Join(agentHome, ".config", "systemd", "user"), filepath.Join(bin, agentName))
}
